//! 下载端点的传输层压缩。
//!
//! 只影响线上字节:入库正文与 Ed25519 签名仍针对**原文**,gzip 在响应阶段
//! 才加上,客户端(curl `--compressed`、reqwest 的 gzip feature)解压后再校验,
//! 因此签名语义与老客户端兼容性都不变。

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::http::header;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::{watch, Semaphore};

/// 小正文压缩收益抵不过 gzip 头与 CPU,直接原文。
const MIN_COMPRESS: usize = 64 * 1024;
/// 一个 hub 同时分发的制品只有个位数;上限防住版本堆积时的内存膨胀。
const MAX_ENTRIES: usize = 4;

/// 内容哈希 → gzip 块。压缩一次约 2.6s(37 MiB 二进制),不能每请求重做。
static CACHE: Mutex<Option<HashMap<[u8; 8], Entry>>> = Mutex::new(None);

/// singleflight:key → 正在进行的那次压缩。发送者被 drop(成功、失败、甚至
/// 客户端断开取消 future)时,等待者的 `changed()` 返回并重查缓存或接力。
static INFLIGHT: Mutex<Option<HashMap<[u8; 8], watch::Sender<()>>>> = Mutex::new(None);

/// 同时进行的压缩上限:冷缓存风暴下匿名下载不能占满 blocking 池的 CPU。
static COMPRESS_SEMAPHORE: Semaphore = Semaphore::const_new(2);

/// 实际执行的 gzip 次数,仅供单测断言 singleflight 语义。
#[cfg(test)]
static COMPRESS_RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct Entry {
    bytes: Bytes,
    /// 最近一次命中时刻,用于 LRU 淘汰。
    used: std::time::Instant,
}

/// 客户端是否接受 gzip(`Accept-Encoding: gzip`、`gzip;q=1.0`、`br, zstd, gzip`)。
pub(crate) fn accepts_gzip(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    raw.split(',').any(|token| {
        let token = token.trim();
        let coding = token.split_once(';').map_or(token, |c| c.0).trim();
        // q≤0(含 q=0、q=0.000)显式拒绝该编码。
        let rejected = token.split(';').skip(1).any(|p| {
            matches!(p.trim().strip_prefix("q="), Some(v) if v.trim().parse::<f32>().is_ok_and(|q| q <= 0.0))
        });
        !rejected && coding.eq_ignore_ascii_case("gzip")
    })
}

/// 按需用 gzip 编码下载正文;失败时退回原文(下载可用性优先于体积)。
pub(crate) async fn encode(raw: Vec<u8>, content_type: &'static str, gzip: bool) -> Response {
    if raw.len() < MIN_COMPRESS {
        // 小正文只有原文一种表示:永不压缩,无需 Vary。
        return plain(raw, content_type, false);
    }
    // 达到阈值后同一 URL 有 gzip/原文两种表示,愿意与不愿意的客户端拿到的
    // 字节不同:两种响应都必须带 Vary: Accept-Encoding,共享缓存才不会
    // 把 gzip 表示塞给不认识的客户端(或反过来)。
    if !gzip {
        return plain(raw, content_type, true);
    }
    let key = fingerprint(&raw);
    if let Some(hit) = cached(&key) {
        return compressed(hit, content_type);
    }
    match compress_shared(key, raw).await {
        Ok(deflated) => compressed(deflated, content_type),
        // 回退原文同样要 Vary:该正文对愿意的客户端本应是 gzip 表示。
        Err(raw) => plain(raw, content_type, true),
    }
}

/// 冷缓存去重(singleflight):同一正文只有一个请求真正压缩,其余订阅
/// 完成信号后复用其缓存块;并发压缩总数再受信号量约束。
async fn compress_shared(key: [u8; 8], raw: Vec<u8>) -> Result<Bytes, Vec<u8>> {
    enum Slot {
        Wait(watch::Receiver<()>),
        Lead(LeaderGuard),
    }
    loop {
        // 每轮先查缓存:领导者的完成信号到达时(成功)块已入库,等待者
        // 在此直接命中,不会接力发起第二次压缩。
        if let Some(hit) = cached(&key) {
            return Ok(hit);
        }
        let slot = {
            let mut guard = inflight_lock();
            let map = guard.get_or_insert_with(HashMap::new);
            match map.get(&key) {
                // 订阅与登记在同一把锁内完成,领导者的完成信号不会丢:
                // 即便它此刻已结束,changed() 也会立即返回进入重查。
                Some(tx) => Slot::Wait(tx.subscribe()),
                None => {
                    // A leader may have populated the cache since the unlocked check.
                    if let Some(hit) = cached(&key) {
                        return Ok(hit);
                    }
                    let (tx, _rx) = watch::channel(());
                    map.insert(key, tx.clone());
                    Slot::Lead(LeaderGuard { key, tx })
                }
            }
        };
        let mut rx = match slot {
            Slot::Wait(rx) => rx,
            Slot::Lead(guard) => return lead(guard, raw).await,
        };
        if let Some(hit) = cached(&key) {
            return Ok(hit);
        }
        let _ = rx.changed().await;
    }
}

async fn lead(guard: LeaderGuard, raw: Vec<u8>) -> Result<Bytes, Vec<u8>> {
    // 压缩是 CPU 密集同步操作,放到 blocking 池,别占住 worker 线程;
    // 许可证覆盖整段压缩耗时,把同时在压的大包个数限在 2。
    let permit = COMPRESS_SEMAPHORE
        .acquire()
        .await
        .expect("compress semaphore is never closed");
    // Queued leaders must not hold an extra full-sized fallback copy.
    let for_gzip = raw.clone();
    let attempt = tokio::task::spawn_blocking(move || {
        let _bound = permit;
        #[cfg(test)]
        COMPRESS_RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        gzip_bytes(&for_gzip)
    })
    .await;
    match attempt {
        Ok(Ok(deflated)) => {
            let deflated = Bytes::from(deflated);
            // 先入库再 drop guard:等待者醒来时缓存必已就绪。
            insert(guard.key, deflated.clone());
            Ok(deflated)
        }
        Ok(Err(e)) => {
            tracing::warn!("gzip download body failed: {e}");
            Err(raw)
        }
        Err(e) => {
            tracing::warn!("gzip download body task panicked: {e}");
            Err(raw)
        }
    }
}

/// 领导者登记项的卸载器:压缩完成、失败、乃至请求 future 被取消,都要把
/// inflight 条目摘掉,否则后来者会永远等一个不会来的信号。
struct LeaderGuard {
    key: [u8; 8],
    tx: watch::Sender<()>,
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        let mut guard = inflight_lock();
        if let Some(map) = guard.as_mut() {
            // 只摘自己登记的那条:失败后等待者可能已接力登记了新条目。
            if map.get(&self.key).is_some_and(|tx| tx.same_channel(&self.tx)) {
                map.remove(&self.key);
            }
        }
    }
}

fn inflight_lock() -> std::sync::MutexGuard<'static, Option<HashMap<[u8; 8], watch::Sender<()>>>> {
    INFLIGHT.lock().unwrap_or_else(|e| e.into_inner())
}

fn fingerprint(raw: &[u8]) -> [u8; 8] {
    let full = Sha256::digest(raw);
    let mut key = [0u8; 8];
    key.copy_from_slice(&full[..8]);
    // 长度并入指纹:同一秒内重复上传等长包时也不会命中旧块。
    for (i, b) in key.iter_mut().enumerate() {
        *b ^= (raw.len() as u64).to_le_bytes()[i];
    }
    key
}

fn cached(key: &[u8; 8]) -> Option<Bytes> {
    let mut guard = lock();
    let table = guard.get_or_insert_with(HashMap::new);
    let hit = table.get_mut(key)?;
    hit.used = std::time::Instant::now();
    Some(hit.bytes.clone())
}

fn insert(key: [u8; 8], bytes: Bytes) {
    let mut guard = lock();
    let table = guard.get_or_insert_with(HashMap::new);
    if table.len() >= MAX_ENTRIES && !table.contains_key(&key) {
        let oldest = table
            .iter()
            .min_by_key(|(_, e)| e.used)
            .map(|(k, _)| *k);
        if let Some(k) = oldest {
            table.remove(&k);
        }
    }
    table.insert(
        key,
        Entry {
            bytes,
            used: std::time::Instant::now(),
        },
    );
}

/// 中毒的锁仍指向同一张表:缓存丢失可以重建,不能因此让下载 500。
fn lock() -> std::sync::MutexGuard<'static, Option<HashMap<[u8; 8], Entry>>> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

fn gzip_bytes(raw: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::with_capacity(raw.len() / 3), Compression::new(9));
    enc.write_all(raw).map_err(|e| format!("gzip: {e}"))?;
    enc.finish().map_err(|e| format!("gzip finish: {e}"))
}

/// negotiable:该正文对愿意的客户端会以 gzip 表示,原文响应也必须声明 Vary,
/// 否则共享缓存会把原文发给声明了 gzip 的客户端。
fn plain(body: Vec<u8>, content_type: &'static str, negotiable: bool) -> Response {
    if !negotiable {
        return (
            axum::http::StatusCode::OK,
            [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
            body,
        )
            .into_response();
    }
    (
        axum::http::StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::VARY, HeaderValue::from_static("Accept-Encoding")),
        ],
        body,
    )
        .into_response()
}

fn compressed(body: Bytes, content_type: &'static str) -> Response {
    // Vary 必须给:同一 URL 现在有两种表示。
    (
        axum::http::StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            ),
            (header::VARY, HeaderValue::from_static("Accept-Encoding")),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn hdr(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn accept_encoding_parsing_follows_curl_and_reqwest() {
        assert!(accepts_gzip(&hdr("gzip")));
        assert!(accepts_gzip(&hdr("GZIP")));
        assert!(accepts_gzip(&hdr("zstd, br, gzip, deflate")));
        assert!(accepts_gzip(&hdr("gzip;q=1.0")));
        // curl --compressed 的实际发头(版本不同后缀不同)。
        assert!(accepts_gzip(&hdr("gzip, deflate, br, zstd")));
        assert!(!accepts_gzip(&hdr("gzip;q=0")));
        assert!(!accepts_gzip(&hdr("gzip;q=0.000, br")));
        assert!(!accepts_gzip(&hdr("br, deflate")));
        assert!(!accepts_gzip(&HeaderMap::new()));
        assert!(!accepts_gzip(&hdr("x-gzip-not")));
    }

    #[tokio::test]
    async fn gzip_body_round_trips_to_the_exact_original_bytes() {
        // 必须跨过 MIN_COMPRESS 且不可压缩性接近真实二进制。
        let raw: Vec<u8> = (0..200_000).map(|i| (i * 7 + i / 313) as u8).collect();
        let deflated = Bytes::from(gzip_bytes(&raw).unwrap());
        assert!(deflated.len() * 4 < raw.len(), "gzipped {} bytes", deflated.len());
        insert(fingerprint(&raw), deflated.clone());
        assert_eq!(cached(&fingerprint(&raw)).unwrap(), deflated, "cache must hit");

        let resp = encode(raw.clone(), "application/octet-stream", true).await;
        assert_eq!(
            resp.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert_eq!(resp.headers().get(header::VARY).unwrap(), "Accept-Encoding");
        let body = axum::body::to_bytes(resp.into_body(), 1 << 24).await.unwrap();
        assert_eq!(body.len(), deflated.len());

        let mut out = Vec::new();
        GzDecoder::new(&deflated[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, raw, "签名针对原文,解压必须逐字节还原");
    }

    #[tokio::test]
    async fn small_and_unwilling_clients_get_the_plain_body() {
        let raw = vec![7u8; 1024];
        let resp = encode(raw.clone(), "application/octet-stream", true).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
        // 小正文永不压缩:只有一种表示,不需要 Vary。
        assert!(resp.headers().get(header::VARY).is_none());
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&body[..], &raw[..]);

        // 达到阈值的正文对不愿意 gzip 的客户端返回原文,但必须声明 Vary:
        // 同一 URL 还有 gzip 表示,共享缓存不能混用。
        let big: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let resp = encode(big.clone(), "application/octet-stream", false).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(resp.headers().get(header::VARY).unwrap(), "Accept-Encoding");
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&body[..], &big[..]);
    }

    /// 冷缓存并发去重:同一正文的 N 个并发未命中只允许压缩一次,且所有
    /// 请求拿到同一 gzip 块。内容生成器与其它测试互不相同 → 指纹必不相同,
    /// 不依赖全局缓存里其它测试的残留,也不会被它们干扰。
    #[tokio::test]
    async fn concurrent_cold_misses_share_one_compression() {
        use std::sync::atomic::Ordering::SeqCst;

        let raw: Vec<u8> = (0..80_000).map(|i| (i * 31 + 7) as u8).collect();
        let before = COMPRESS_RUNS.load(SeqCst);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let raw = raw.clone();
            tasks.push(tokio::spawn(encode(raw, "application/octet-stream", true)));
        }
        let mut wires = Vec::new();
        for t in tasks {
            let resp = t.await.unwrap();
            assert_eq!(resp.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
            assert_eq!(resp.headers().get(header::VARY).unwrap(), "Accept-Encoding");
            wires.push(axum::body::to_bytes(resp.into_body(), 1 << 24).await.unwrap());
        }
        assert!(
            wires.iter().all(|w| *w == wires[0]),
            "同一正文的所有请求必须拿到同一 gzip 块"
        );
        assert_eq!(
            COMPRESS_RUNS.load(SeqCst) - before,
            1,
            "并发冷缓存只允许压缩一次(singleflight)"
        );
        let mut out = Vec::new();
        GzDecoder::new(&wires[0][..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, raw, "签名针对原文,解压必须逐字节还原");
    }

    #[test]
    fn cache_is_bounded_and_evicts_oldest() {
        for i in 0..(MAX_ENTRIES + 4) {
            insert([i as u8; 8], Bytes::from(vec![i as u8; 16]));
        }
        let guard = lock();
        assert_eq!(guard.as_ref().unwrap().len(), MAX_ENTRIES);
    }
}
