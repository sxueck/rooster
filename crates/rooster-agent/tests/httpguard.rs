//! http-guard 反向代理集成测试:
//! 80/443 反代与转发头注入、80→443 跳转、ACME HTTP-01 优先应答、
//! WAF 模式与规则排除、限速 429 与持续超限升级 Ban、可信代理链下的
//! Geo 拒绝、TLS 终止、TLS 透传 + PROXY v1、body_limit 只截检测不截
//! 转发、WebSocket 升级隧道。全部走 127.0.0.1,端口随机分配。
//!
//! 注:dev 依赖的 reqwest 未启用 TLS feature(见 Cargo.toml
//! `default-features = false, features = ["json"]`),因此 https 客户端
//! 不用 reqwest,而是直接用 tokio-rustls + 「信任任意证书」的测试
//! verifier(与 src/httpguard/tlsconf.rs 中上游客户端同一做法),
//! 效果等价于 reqwest 的 danger_accept_invalid_certs;SNI 与连接地址
//! 分离等价于 resolve 覆盖。

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rooster_agent::httpguard::{
    HttpGuardRuntime, HttpGuardSettings, InspectCtx, InspectVerdict, RequestInspector,
};
use rooster_config::schema::{GeoRule, OnExceed, RateLimitRule, SiteWafConfig};
use rooster_config::{ProxyProtocol, Site, SiteTls, TlsMode, WafMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 测试专用 HTTP 客户端:禁用环境代理。
///
/// 本机若设有 http_proxy/https_proxy(常见的代理/抓包工具),reqwest 默认会
/// 读环境变量,把 127.0.0.1 的测试请求也丢进代理 —— `no_proxy` 里的
/// `127.*` 通配符 reqwest 并不识别,于是所有反代测试拿到代理返回的空 body
/// 502。测试连的是回环,必须显式绕开代理。
fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().expect("client")
}

const TIMEOUT: Duration = Duration::from_secs(5);
/// GeoIP 测试库(DB-IP country lite,随仓库提供)。
const GEOIP_DB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/dbip-country-lite.mmdb");

// ---------------------------------------------------------------------------
// 辅助

/// 预留一个空闲端口(bind :0 后立即释放)。极小概率与并发用例竞争,
/// 失败时测试会以 bind error 暴露,可重跑(与 forward 测试同思路)。
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn listen_on(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// 每 100ms 轮询断言,10s 内必须满足,否则 panic 并附描述。
async fn wait_until(desc: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not met within 10s: {desc}");
}

/// 最小站点配置:明文上游、passthrough TLS、无 WAF / 限速 / geo。
fn site(id: &str, names: &[&str], upstream: &str) -> Site {
    Site {
        id: id.to_string(),
        server_names: names.iter().map(|s| s.to_string()).collect(),
        tls: SiteTls::default(),
        upstream: upstream.to_string(),
        waf: None,
        rate_limit: vec![],
        geo: None,
        proxy_protocol: None,
        ja4_deny: vec![],
        redirect_https: None,
    }
}

/// 从 runtime.stats() 取指定站点条目。
fn stat_for<'a>(stats: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    stats
        .iter()
        .find(|s| s["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("no stats entry for site {id}"))
}

fn stat_u64(rt: &HttpGuardRuntime, id: &str, field: &str) -> u64 {
    stat_for(&rt.stats(), id)[field].as_u64().unwrap_or_else(|| panic!("field {field}"))
}

// ---------------------------------------------------------------------------
// echo 上游:JSON 回显请求的方法 / URI / Host / 转发头 / body。

#[derive(Clone)]
struct EchoService {
    hits: Arc<AtomicU64>,
}

impl Service<Request<Incoming>> for EchoService {
    type Response = Response<Full<bytes::Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let hits = self.hits.clone();
        Box::pin(async move {
            hits.fetch_add(1, Ordering::Relaxed);
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.expect("collect body").to_bytes();
            let hdr = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            };
            // 同名多值头全部拼回来(B4 断言用):cookie / x-multi 逐值逗号连接。
            let join_all = |name: &str| -> String {
                parts
                    .headers
                    .get_all(name)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let json = serde_json::json!({
                "method": parts.method.as_str(),
                "uri": parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"),
                "host": hdr("host"),
                "xff": hdr("x-forwarded-for"),
                "real_ip": hdr("x-real-ip"),
                "proto": hdr("x-forwarded-proto"),
                "cookies": join_all("cookie"),
                "x_multi": join_all("x-multi"),
                "body": String::from_utf8_lossy(&bytes),
                "body_len": bytes.len(),
            });
            Ok(Response::new(Full::new(bytes::Bytes::from(json.to_string()))))
        })
    }
}

/// 起 echo 上游,返回 (地址, 命中计数)。
async fn echo_upstream() -> (SocketAddr, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind echo upstream");
    let addr = l.local_addr().expect("upstream addr");
    let hits = Arc::new(AtomicU64::new(0));
    let hits2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = l.accept().await else { return };
            let svc = EchoService { hits: hits2.clone() };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (addr, hits)
}

// ---------------------------------------------------------------------------
// WAF inspector mock(Mutex / atomic 控制,记录调用与 body 长度)

struct MockInspector {
    blocked: AtomicBool,
    hits: Mutex<Vec<(u32, String)>>,
    severities: Mutex<Vec<u8>>,
    body_lens: Mutex<Vec<usize>>,
    calls: AtomicU64,
}

impl MockInspector {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            blocked: AtomicBool::new(false),
            hits: Mutex::new(vec![]),
            severities: Mutex::new(vec![]),
            body_lens: Mutex::new(vec![]),
            calls: AtomicU64::new(0),
        })
    }

    fn set_verdict(&self, blocked: bool, hits: Vec<(u32, String)>) {
        self.set_verdict_sev(blocked, hits, vec![]);
    }

    /// 带严重度权重的判定(rooster-waf:CRITICAL=5/ERROR=4/WARNING=3/NOTICE=2)。
    fn set_verdict_sev(&self, blocked: bool, hits: Vec<(u32, String)>, severities: Vec<u8>) {
        self.blocked.store(blocked, Ordering::SeqCst);
        *self.hits.lock().unwrap() = hits;
        *self.severities.lock().unwrap() = severities;
    }

    fn body_lens(&self) -> Vec<usize> {
        self.body_lens.lock().unwrap().clone()
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RequestInspector for MockInspector {
    fn inspect(&self, ctx: InspectCtx<'_>) -> InspectVerdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.body_lens.lock().unwrap().push(ctx.body.len());
        let hits = self.hits.lock().unwrap().clone();
        InspectVerdict {
            blocked: self.blocked.load(Ordering::SeqCst),
            score: hits.len() as u32,
            hit_severities: self.severities.lock().unwrap().clone(),
            hits,
        }
    }
}

// ---------------------------------------------------------------------------
// TLS 客户端(信任任意证书,测试专用)

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

fn danger_client_config() -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    // 固定 http/1.1,配合下面的手写 HTTP/1.1 请求。
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// TLS 连接(指定 SNI)→ 写原始 HTTP/1.1 请求(Connection: close)→
/// 读尽响应字节。等价于 reqwest danger + resolve 覆盖的用法。
async fn tls_roundtrip(addr: SocketAddr, sni: &str, request: &[u8]) -> Vec<u8> {
    let connector = tokio_rustls::TlsConnector::from(danger_client_config());
    let tcp = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("tcp connect within 5s")
        .expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .expect("valid sni name");
    let mut tls = tokio::time::timeout(TIMEOUT, connector.connect(name, tcp))
        .await
        .expect("tls within 5s")
        .expect("tls handshake ok");
    tls.write_all(request).await.expect("write request");
    let mut out = Vec::new();
    tokio::time::timeout(TIMEOUT, tls.read_to_end(&mut out))
        .await
        .expect("read response within 5s")
        .expect("read response");
    out
}

/// TLS 连接(指定 SNI)→ 写请求 → 按 Content-Length 精确读响应。
/// 透传模式是裸 TCP 隧道,没有连接关闭语义,不能读到 EOF。
async fn tls_request_exact(addr: SocketAddr, sni: &str, request: &[u8]) -> (String, Vec<u8>) {
    let connector = tokio_rustls::TlsConnector::from(danger_client_config());
    let tcp = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("tcp connect within 5s")
        .expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).expect("valid sni name");
    let mut tls = tokio::time::timeout(TIMEOUT, connector.connect(name, tcp))
        .await
        .expect("tls within 5s")
        .expect("tls handshake ok");
    tls.write_all(request).await.expect("write request");
    let head = read_until_suffix(&mut tls, b"\r\n\r\n", 8192).await;
    let head_str = String::from_utf8_lossy(&head).to_string();
    let cl = head_str
        .to_lowercase()
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body = if cl > 0 {
        read_exact_t(&mut tls, cl).await
    } else {
        Vec::new()
    };
    (head_str, body)
}

/// 把原始 HTTP 响应切成 (head, body)。head 里的 Content-Length 由
/// 上游 Full body 保证存在,这里只需找 \r\n\r\n。
fn split_http_response(raw: &[u8]) -> (String, Vec<u8>) {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head terminator \\r\\n\\r\\n");
    (
        String::from_utf8_lossy(&raw[..pos]).to_string(),
        raw[pos + 4..].to_vec(),
    )
}

/// 读到出现 suffix 为止(字节粒度),5s 超时。
async fn read_until_suffix<S: AsyncReadExt + Unpin>(s: &mut S, suffix: &[u8], max: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        tokio::time::timeout(TIMEOUT, s.read_exact(&mut byte))
            .await
            .expect("read within 5s")
            .expect("read ok");
        buf.push(byte[0]);
        if buf.ends_with(suffix) {
            return buf;
        }
        assert!(buf.len() < max, "read_until_suffix exceeded {max} bytes");
    }
}

async fn read_exact_t<S: AsyncReadExt + Unpin>(s: &mut S, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut out))
        .await
        .expect("read within 5s")
        .expect("read ok");
    out
}

/// rcgen 自签证书(localhost)。
fn self_signed() -> rcgen::CertifiedKey {
    rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen self-signed")
}

// ---------------------------------------------------------------------------
// 1. 80 端口反代:转发头 + body 往返

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_proxy_headers() {
    let (up, _hits) = echo_upstream().await;
    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![site("hdr", &["hdr.test"], &format!("http://{up}"))],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    let client = client();
    let resp = tokio::time::timeout(TIMEOUT, client
        .post(format!("http://127.0.0.1:{port}/echo?x=1"))
        .header("host", "hdr.test")
        .body("hello-body-123")
        .send())
        .await
        .expect("request within 5s")
        .expect("request ok");
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.expect("body text");
    let json: serde_json::Value = serde_json::from_str(&text).expect("echo json");

    // 上游收到注入的转发头;无入站 XFF 时 XFF/X-Real-IP 均为 TCP peer。
    assert_eq!(json["method"], "POST");
    assert_eq!(json["uri"], "/echo?x=1");
    assert_eq!(json["host"], "hdr.test");
    assert_eq!(json["proto"], "http", "X-Forwarded-Proto must be http");
    assert_eq!(json["xff"], "127.0.0.1", "X-Forwarded-For must be client ip");
    assert_eq!(json["real_ip"], "127.0.0.1", "X-Real-IP must be client ip");
    // body 经 80 监听完整往返。
    assert_eq!(json["body"], "hello-body-123");
    assert_eq!(json["body_len"], 14);

    wait_until("site stats recorded", || stat_u64(&rt, "hdr", "requests") >= 1).await;
    rt.shutdown().await;
}

// ---------------------------------------------------------------------------
// 2. redirect_https:80 → 443 的 301

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redirect_80_to_443() {
    let (up, hits) = echo_upstream().await;
    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    let mut s = site("redir", &["redir.test"], &format!("http://{up}"));
    s.redirect_https = Some(true);
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![s],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    // 不跟随重定向,直接断言 301 + Location(Host 去端口)。
    let client = reqwest::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = tokio::time::timeout(TIMEOUT, client
        .get(format!("http://127.0.0.1:{port}/path?q=1"))
        .header("host", "redir.test")
        .send())
        .await
        .expect("request within 5s")
        .expect("request ok");
    assert_eq!(resp.status(), 301, "redirect_https site must 301 on :80");
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("https://redir.test/path?q=1"),
        "Location must be https + original path_and_query"
    );
    // 跳转在代理之前短路,上游不应被触碰。
    assert_eq!(hits.load(Ordering::Relaxed), 0, "upstream must not be hit");
}

// ---------------------------------------------------------------------------
// 3. ACME HTTP-01:80 端口优先应答,不经上游

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acme_challenge() {
    // 上游指向必然拒绝连接的端口:若被反代会得到 502 而非 200。
    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![site("acme", &["acme.test"], "http://127.0.0.1:1")],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;
    rt.set_challenge("tok123".to_string(), "keyauth-xyz".to_string());

    let client = client();
    let resp = tokio::time::timeout(TIMEOUT, client
        .get(format!("http://127.0.0.1:{port}/.well-known/acme-challenge/tok123"))
        .header("host", "acme.test")
        .send())
        .await
        .expect("request within 5s")
        .expect("request ok");
    assert_eq!(resp.status(), 200, "registered token must be answered on :80");
    let body = resp.text().await.expect("key auth body");
    assert_eq!(body, "keyauth-xyz", "body must be the key authorization");

    // 未注册 token → 404,同样不触碰上游。
    let resp = tokio::time::timeout(TIMEOUT, client
        .get(format!("http://127.0.0.1:{port}/.well-known/acme-challenge/unknown"))
        .header("host", "acme.test")
        .send())
        .await
        .expect("unknown token request within 5s")
        .expect("unknown token request ok");
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// 4. WAF 模式:block 拦截 / detect 只记录 / 排除列表抵消拦截

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waf_modes_and_exclusions() {
    let (up, hits) = echo_upstream().await;
    let mock = MockInspector::new();
    let rt = HttpGuardRuntime::new(Some(mock.clone()));
    let port = free_port();

    let apply_mode = |mode: WafMode, exclusions: Vec<u32>| {
        let mut s = site("wafs", &["waf.test"], &format!("http://{up}"));
        s.waf = Some(SiteWafConfig { mode, exclusions });
        HttpGuardSettings {
            listen_http: Some(listen_on(port)),
            listen_https: None,
            sites: vec![s],
            trusted_proxies: vec![],
            geoip_db: None,
            body_limit: 0,
            ban_hook: None,
        }
    };

    // (a) block 模式 + blocked 判定 → 403。
    // 注意:每阶段用全新 client —— 已建立连接按建立时的配置快照服务
    // (热重载语义),连接复用会让新配置不生效。
    rt.apply(apply_mode(WafMode::Block, vec![])).await;
    mock.set_verdict(true, vec![(1, "sqli-match".to_string())]);
    let resp = tokio::time::timeout(TIMEOUT, client()
        .post(format!("http://127.0.0.1:{port}/search"))
        .header("host", "waf.test")
        .body("id=1' OR '1'='1")
        .send())
        .await
        .expect("block request within 5s")
        .expect("block request ok");
    assert_eq!(resp.status(), 403, "block mode + blocked verdict must 403");
    assert_eq!(mock.calls(), 1, "inspector must be called");
    assert_eq!(hits.load(Ordering::Relaxed), 0, "blocked request must not reach upstream");

    // (b) detect 模式,同一判定 → 放行(命中只记录)。
    rt.apply(apply_mode(WafMode::Detect, vec![])).await;
    let resp = tokio::time::timeout(TIMEOUT, client()
        .post(format!("http://127.0.0.1:{port}/search"))
        .header("host", "waf.test")
        .body("id=1' OR '1'='1")
        .send())
        .await
        .expect("detect request within 5s")
        .expect("detect request ok");
    assert_eq!(resp.status(), 200, "detect mode must not block");
    assert_eq!(mock.calls(), 2, "inspector still runs in detect mode");
    assert_eq!(hits.load(Ordering::Relaxed), 1, "detect request reaches upstream");

    // (c) block 模式 + 命中全部在 exclusions → 本地过滤后放行。
    rt.apply(apply_mode(WafMode::Block, vec![1])).await;
    let resp = tokio::time::timeout(TIMEOUT, client()
        .post(format!("http://127.0.0.1:{port}/search"))
        .header("host", "waf.test")
        .body("id=1' OR '1'='1")
        .send())
        .await
        .expect("exclusion request within 5s")
        .expect("exclusion request ok");
    assert_eq!(resp.status(), 200, "fully-excluded hits must not block");
    assert_eq!(mock.calls(), 3);
    assert_eq!(hits.load(Ordering::Relaxed), 2, "excluded request reaches upstream");
}

/// 拦截必须上报 Event::Block(带严重度级别名),否则 hub
/// 侧联动封禁永远没有数据源;detect 模式必须对全队静默。
#[tokio::test]
async fn waf_block_reports_block_event_with_severity() {
    let (up, _hits) = echo_upstream().await;
    let mock = MockInspector::new();
    let rt = HttpGuardRuntime::new(Some(mock.clone()));
    let events: Arc<Mutex<Vec<rooster_proto::Event>>> = Arc::new(Mutex::new(vec![]));
    {
        let events = events.clone();
        rt.set_event_sink(Arc::new(move |ev| events.lock().unwrap().push(ev)));
    }
    let port = free_port();
    let mut s = site("wafev", &["wafev.test"], &format!("http://{up}"));
    s.waf = Some(SiteWafConfig {
        mode: WafMode::Block,
        exclusions: vec![],
    });
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        sites: vec![s],
        ..Default::default()
    })
    .await;

    mock.set_verdict_sev(true, vec![(942100, "sqli".to_string())], vec![5]);
    let resp = client()
        .post(format!("http://127.0.0.1:{port}/x"))
        .header("host", "wafev.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "block mode must 403");
    wait_until("block event reported to the sink", || {
        !events.lock().unwrap().is_empty()
    })
    .await;
    match events.lock().unwrap().remove(0) {
        rooster_proto::Event::Block {
            ip,
            rule_id,
            site,
            severity,
            path,
            hits,
            score,
        } => {
            assert_eq!(site, "wafev", "事件站点必须是 cfg.id");
            assert_eq!(rule_id, "942100");
            assert_eq!(severity.as_deref(), Some("CRITICAL"), "严重度用大写正名");
            assert_eq!(ip, "127.0.0.1", "事件 IP 必须是解析后的客户端地址");
            assert_eq!(path.as_deref(), Some("/x"), "事件必须带被攻击路径");
            assert_eq!(hits, vec![942100u32], "事件必须带全部命中规则");
            assert!(score.is_some(), "事件必须带累计异常评分");
        }
        other => panic!("expected Block event, got {other:?}"),
    }

    // detect 模式:同一判定只记录,不拦不上报。
    let mut d = site("wafdet", &["wafdet.test"], &format!("http://{up}"));
    d.waf = Some(SiteWafConfig {
        mode: WafMode::Detect,
        exclusions: vec![],
    });
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        sites: vec![d],
        ..Default::default()
    })
    .await;
    let resp = client()
        .post(format!("http://127.0.0.1:{port}/x"))
        .header("host", "wafdet.test")
        .body("id=1' OR '1'='1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "detect mode must not block");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        events.lock().unwrap().is_empty(),
        "detect mode must not emit Block events"
    );
}

// ---------------------------------------------------------------------------
// 5. 限速 reject:3/second burst 0,第 4 笔 429

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_reject_429() {
    let (up, _hits) = echo_upstream().await;
    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    let mut s = site("rl", &["rl.test"], &format!("http://{up}"));
    s.rate_limit = vec![RateLimitRule {
        key: "ip".to_string(),
        rate: "3/second".to_string(),
        burst: 0,
        on_exceed: OnExceed::Reject,
        ban_after: None,
    }];
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![s],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    let client = client();
    for i in 1..=4 {
        let resp = tokio::time::timeout(TIMEOUT, client
            .get(format!("http://127.0.0.1:{port}/burst"))
            .header("host", "rl.test")
            .send())
            .await
            .expect("request within 5s")
            .expect("request ok");
        if i <= 3 {
            assert_eq!(resp.status(), 200, "request #{i} within 3/second must pass");
        } else {
            assert_eq!(resp.status(), 429, "4th rapid request must be rate limited");
        }
    }
}

// ---------------------------------------------------------------------------
// 6. 限速 ban 升级:持续超限触发 ban_hook,其后请求继续被拒

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_ban_escalation() {
    let (up, _hits) = echo_upstream().await;
    let port = free_port();
    let bans: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let bans2 = bans.clone();
    let hook: Arc<dyn Fn(&str, Duration) + Send + Sync> =
        Arc::new(move |ip, _ttl| bans2.lock().unwrap().push(ip.to_string()));
    let rt = HttpGuardRuntime::new(None);
    let mut s = site("ban", &["ban.test"], &format!("http://{up}"));
    s.rate_limit = vec![RateLimitRule {
        key: "ip".to_string(),
        rate: "2/second".to_string(),
        burst: 0,
        on_exceed: OnExceed::Ban,
        ban_after: Some(Duration::from_millis(50)),
    }];
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![s],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: Some(hook),
    })
    .await;

    let client = client();
    let get = |i: usize| {
        let client = client.clone();
        let url = format!("http://127.0.0.1:{port}/n{i}");
        async move {
            tokio::time::timeout(TIMEOUT, client
                .get(url)
                .header("host", "ban.test")
                .send())
                .await
                .expect("request within 5s")
                .expect("request ok")
                .status()
        }
    };
    assert_eq!(get(1).await, 200);
    assert_eq!(get(2).await, 200);
    // 第 3 笔:首次超限 → 429(记录超限起点)。
    assert_eq!(get(3).await, 429, "3rd request beyond 2/second must 429");
    // 持续超限 ≥ ban_after(50ms)后再次超限 → 升级 Ban,触发 ban_hook。
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(get(4).await, 429, "sustained exceed still rejected");
    wait_until("ban_hook fired", || {
        bans.lock().unwrap().iter().any(|ip| ip == "127.0.0.1")
    })
    .await;
    // Ban 生效期间(TTL 内)继续 429。
    assert_eq!(get(5).await, 429, "banned ip must stay rejected");
}

// ---------------------------------------------------------------------------
// 7. 可信代理 + Geo 拒绝:XFF 里的真实 IP 参与国家判定

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn geo_deny_via_trusted_proxy() {
    let db = std::path::PathBuf::from(GEOIP_DB);
    assert!(
        db.exists(),
        "geoip db missing at {} — 仓库应包含 tests/data/dbip-country-lite.mmdb",
        db.display()
    );
    let reader = maxminddb::Reader::open_readfile(&db).expect("open geoip db");
    let country_of = |ip_str: &str| -> Option<String> {
        let c: maxminddb::geoip2::Country = reader
            .lookup(ip_str.parse().expect("valid ip"))
            .ok()?;
        c.country
            .and_then(|x| x.iso_code)
            .or_else(|| c.registered_country.and_then(|x| x.iso_code))
            .map(|s| s.to_string())
    };
    let c_us = country_of("8.8.8.8")
        .unwrap_or_else(|| panic!("geoip db must resolve 8.8.8.8 (expected US)"));
    let c_other = country_of("114.114.114.114")
        .unwrap_or_else(|| panic!("geoip db must resolve 114.114.114.114 (expected CN)"));

    let (up, _hits) = echo_upstream().await;
    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    let mut s = site("geo", &["geo.test"], &format!("http://{up}"));
    s.geo = Some(GeoRule {
        deny: vec![c_us.clone()],
        allow: vec![],
    });
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![s],
        // peer 127.0.0.1 可信 → 从 XFF 取真实 IP。
        trusted_proxies: vec!["127.0.0.1/32".to_string()],
        geoip_db: Some(db),
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    let client = client();
    // XFF = 8.8.8.8(国家在 deny 列表)→ 403。
    let resp = tokio::time::timeout(TIMEOUT, client
        .get(format!("http://127.0.0.1:{port}/"))
        .header("host", "geo.test")
        .header("x-forwarded-for", "8.8.8.8")
        .send())
        .await
        .expect("deny request within 5s")
        .expect("deny request ok");
    assert_eq!(
        resp.status(),
        403,
        "XFF {c_us} ip must be denied (country {c_us} in deny list)"
    );

    // 另一个国家的 IP → 放行;两库值相同(异常数据)时跳过该半段。
    if c_us != c_other {
        let resp = tokio::time::timeout(TIMEOUT, client
            .get(format!("http://127.0.0.1:{port}/"))
            .header("host", "geo.test")
            .header("x-forwarded-for", "114.114.114.114")
            .send())
            .await
            .expect("allow request within 5s")
            .expect("allow request ok");
        assert_eq!(
            resp.status(),
            200,
            "XFF 114.114.114.114 (country {c_other}, not in deny [{c_us}]) must pass"
        );
    } else {
        eprintln!("skip allow-half: 8.8.8.8 and 114.114.114.114 both resolve to {c_us}");
    }
}

// ---------------------------------------------------------------------------
// 8. TLS 终止:rustls 服务端证书,X-Forwarded-Proto: https

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_terminate() {
    let (up, _hits) = echo_upstream().await;
    let ck = self_signed();
    let port = free_port();
    let cert_path = std::env::temp_dir().join(format!("rooster-hg-{port}-cert.pem"));
    let key_path = std::env::temp_dir().join(format!("rooster-hg-{port}-key.pem"));
    std::fs::write(&cert_path, ck.cert.pem()).expect("write cert pem");
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).expect("write key pem");

    let rt = HttpGuardRuntime::new(None);
    let mut s = site("term", &["localhost"], &format!("http://{up}"));
    s.tls = SiteTls {
        mode: TlsMode::Terminate,
        acme: false,
        cert: Some(cert_path),
        key: Some(key_path),
        skip_verify: false,
    };
    rt.apply(HttpGuardSettings {
        listen_http: None,
        listen_https: Some(listen_on(port)),
        sites: vec![s],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    let body = "tls-terminate-body";
    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let raw = tls_roundtrip(listen_on(port), "localhost", req.as_bytes()).await;
    let (head, resp_body) = split_http_response(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "unexpected head: {head}");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("echo json over tls");
    assert_eq!(json["proto"], "https", "X-Forwarded-Proto must be https");
    assert_eq!(json["xff"], "127.0.0.1");
    assert_eq!(json["real_ip"], "127.0.0.1");
    assert_eq!(json["body"], body, "body must round-trip through terminate mode");
    assert_eq!(json["body_len"], body.len());
}

// ---------------------------------------------------------------------------
// 9. TLS 透传 + PROXY v1:上游先收 v1 头再做 TLS,字节原样双向

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_passthrough_proxy_v1() {
    // 上游:读 PROXY v1 行 → 断言 → TLS accept → 应答一个 HTTP 请求。
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind tls upstream");
    let up = l.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut tcp, _) = l.accept().await.expect("upstream accept");
        let line = read_until_suffix(&mut tcp, b"\r\n", 108).await;
        let line = String::from_utf8(line).expect("ascii proxy line");
        assert!(line.starts_with("PROXY "), "upstream must first get a PROXY line: {line:?}");
        assert!(line.contains("127.0.0.1"), "proxy line must carry client ip: {line:?}");

        let ck = self_signed();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .expect("upstream server cert");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let mut tls = acceptor.accept(tcp).await.expect("upstream tls accept");

        let req = read_until_suffix(&mut tls, b"\r\n\r\n", 8192).await;
        let req = String::from_utf8_lossy(&req).to_string();
        assert!(req.starts_with("GET /pt "), "request must survive passthrough: {req:?}");
        assert!(req.to_lowercase().contains("host: localhost"), "Host must be forwarded");

        let body = "passthrough-ok!";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tls.write_all(resp.as_bytes()).await.expect("upstream write");
        // 排空到客户端关闭,保证拷贝循环两侧都能自然结束。
        let mut sink = Vec::new();
        let _ = tls.read_to_end(&mut sink).await;
    });

    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    let mut s = site("pt", &["localhost"], &format!("{up}"));
    s.tls.mode = TlsMode::Passthrough;
    s.proxy_protocol = Some(ProxyProtocol::V1);
    rt.apply(HttpGuardSettings {
        listen_http: None,
        listen_https: Some(listen_on(port)),
        sites: vec![s],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    let req = "GET /pt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let (head, body) = tls_request_exact(listen_on(port), "localhost", req.as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "unexpected head: {head}");
    assert_eq!(body, b"passthrough-ok!", "payload must flow through the tunnel");

    // 透传统计:连接数与双向字节。
    wait_until("passthrough stats", || {
        stat_u64(&rt, "pt", "conns_passthrough") >= 1
            && stat_u64(&rt, "pt", "bytes_in") > 0
            && stat_u64(&rt, "pt", "bytes_out") > 0
    })
    .await;
    rt.shutdown().await;
}

// ---------------------------------------------------------------------------
// 10. body_limit 只截检测:inspector 只见前 16 字节,上游收全量

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_limit_forwarded_full() {
    let (up, _hits) = echo_upstream().await;
    let mock = MockInspector::new();
    let rt = HttpGuardRuntime::new(Some(mock.clone()));
    let port = free_port();
    let mut s = site("bl", &["bl.test"], &format!("http://{up}"));
    // detect 模式:走缓冲路径但不拦截。
    s.waf = Some(SiteWafConfig { mode: WafMode::Detect, exclusions: vec![] });
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![s],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 16,
        ban_hook: None,
    })
    .await;

    let payload = "A".repeat(100);
    let client = client();
    let resp = tokio::time::timeout(TIMEOUT, client
        .post(format!("http://127.0.0.1:{port}/upload"))
        .header("host", "bl.test")
        .body(payload.clone())
        .send())
        .await
        .expect("request within 5s")
        .expect("request ok");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = serde_json::from_str(&resp.text().await.expect("body")).expect("json");

    // inspector 只看到前 body_limit = 16 字节。
    wait_until("inspector called", || !mock.body_lens().is_empty()).await;
    let lens = mock.body_lens();
    assert_eq!(lens, vec![16], "inspector must see exactly the first 16 bytes");
    // 上游收到完整 100 字节并原样 echo 回客户端。
    assert_eq!(json["body_len"], 100, "upstream must receive the full body");
    assert_eq!(json["body"], payload, "client must receive the full echo");
}

// ---------------------------------------------------------------------------
// 11. WebSocket 升级隧道:101 + 双向裸字节

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_upgrade() {
    // 上游:裸 TCP 读升级请求 → 101 + payload → 保持连接到客户端关闭。
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind ws upstream");
    let up = l.local_addr().expect("ws upstream addr");
    tokio::spawn(async move {
        let (mut tcp, _) = l.accept().await.expect("ws upstream accept");
        let head = read_until_suffix(&mut tcp, b"\r\n\r\n", 8192).await;
        let head = String::from_utf8_lossy(&head).to_lowercase();
        assert!(head.contains("get /ws"), "upgrade request must arrive: {head:?}");
        assert!(
            head.contains("upgrade: websocket"),
            "Upgrade headers must be forwarded: {head:?}"
        );
        let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                    \r\n";
        tcp.write_all(resp.as_bytes()).await.expect("write 101");
        tcp.write_all(b"ws-payload-from-upstream").await.expect("write payload");
        // 排空,隧道两侧随客户端关闭自然结束。
        let mut sink = Vec::new();
        let _ = tcp.read_to_end(&mut sink).await;
    });

    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        listen_https: None,
        sites: vec![site("ws", &["ws.test"], &format!("http://{up}"))],
        trusted_proxies: vec![],
        geoip_db: None,
        body_limit: 0,
        ban_hook: None,
    })
    .await;

    // 裸 TCP 客户端发起升级请求(80 监听)。
    let mut c = TcpStream::connect(listen_on(port)).await.expect("connect");
    let req = "GET /ws HTTP/1.1\r\n\
               Host: ws.test\r\n\
               Connection: Upgrade\r\n\
               Upgrade: websocket\r\n\
               Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
               Sec-WebSocket-Version: 13\r\n\
               \r\n";
    c.write_all(req.as_bytes()).await.expect("write upgrade request");

    let head = read_until_suffix(&mut c, b"\r\n\r\n", 8192).await;
    let head_str = String::from_utf8_lossy(&head).to_string();
    assert!(
        head_str.to_lowercase().starts_with("http/1.1 101"),
        "client must receive 101, got: {head_str:?}"
    );
    assert!(
        head_str.to_lowercase().contains("upgrade: websocket"),
        "101 must keep the Upgrade header: {head_str:?}"
    );
    // 101 之后隧道里的首段 payload。
    let payload = read_exact_t(&mut c, b"ws-payload-from-upstream".len()).await;
    assert_eq!(payload, b"ws-payload-from-upstream", "tunnel payload must reach client");
}

// ---------------------------------------------------------------------------
// 12. B4:重复请求头不得被 wasm 头回写塌缩

/// 明文 HTTP/1.1 请求(Connection: close)→ 读尽响应 → 解析 echo JSON。
/// 用裸 TCP 客户端是为了精确发送同名多值头。
async fn raw_http_json(addr: SocketAddr, request: &[u8]) -> serde_json::Value {
    let mut c = TcpStream::connect(addr).await.expect("connect");
    c.write_all(request).await.expect("write request");
    let mut raw = Vec::new();
    tokio::time::timeout(TIMEOUT, c.read_to_end(&mut raw))
        .await
        .expect("response within 5s")
        .expect("read response");
    let (_, body) = split_http_response(&raw);
    serde_json::from_slice(&body).expect("echo json")
}

/// B4 回归:wasm 运行时已注入但零插件加载时,插件头视角的回写绝不能
/// 碰请求 —— 两个 cookie 头必须原样到达上游(旧实现在这条路径上把
/// 多值头塌缩成一个值);完全不注入 wasm 时行为必须一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wasm_zero_plugins_keeps_duplicate_headers_b4() {
    let (up, _hits) = echo_upstream().await;
    let settings = |port: u16| HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        sites: vec![site("mv", &["mv.test"], &format!("http://{up}"))],
        ..Default::default()
    };
    let req = b"GET /echo HTTP/1.1\r\nHost: mv.test\r\ncookie: a=1\r\ncookie: b=2\r\nConnection: close\r\n\r\n";

    // (a) 运行时在、插件为零:曾把两个 cookie 塌成一个。
    let port = free_port();
    let rt = HttpGuardRuntime::new(None);
    rt.set_wasm(Arc::new(rooster_agent::wasmrt::WasmRuntime::new()));
    rt.apply(settings(port)).await;
    let with_rt = raw_http_json(listen_on(port), req).await;
    assert_eq!(with_rt["cookies"], "a=1,b=2", "多值 cookie 必须完整到达上游");

    // (b) 完全不注入 wasm:行为必须一致。
    let port2 = free_port();
    let rt2 = HttpGuardRuntime::new(None);
    rt2.apply(settings(port2)).await;
    let plain = raw_http_json(listen_on(port2), req).await;
    assert_eq!(plain["cookies"], "a=1,b=2");
    assert_eq!(with_rt["cookies"], plain["cookies"], "注入空 wasm 运行时不得改变请求");
}

/// B4 回归:插件 rooster_set_header 的契约是「同名整体替换」—— 被
/// 设置的名字塌缩为单值,无关的多值名字(cookie)保持多值不误伤。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wasm_set_header_replaces_only_its_own_name_b4() {
    const SET_HEADER_WAT: &str = r#"
(module
  (import "env" "rooster_set_header" (func $set_h (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"n\":1}")
  (data (i32.const 16) "x-multi")
  (data (i32.const 32) "replaced")
  (func (export "rooster_manifest_ptr") (result i32) (i32.const 0))
  (func (export "rooster_manifest_len") (result i32) (i32.const 7))
  (func (export "on_http_request_headers") (result i32)
    (drop (call $set_h (i32.const 16) (i32.const 7) (i32.const 32) (i32.const 8)))
    (i32.const 0))
)
"#;
    let (up, _hits) = echo_upstream().await;
    let port = free_port();
    let wasm = rooster_agent::wasmrt::WasmRuntime::new();
    let file = std::env::temp_dir().join(format!("rooster-hg-sethdr-{}.wat", std::process::id()));
    std::fs::write(&file, SET_HEADER_WAT).unwrap();
    wasm.reconfigure(
        &[rooster_config::WasmPlugin {
            id: "sethdr".to_string(),
            file: file.clone(),
            hooks: vec!["on_http_request_headers".to_string()],
            sites: vec![],
            limits: None,
            on_error: None,
            config: None,
        }],
        |_| Some(file.clone()),
    );
    assert_eq!(
        wasm.plugin_status("sethdr"),
        "loaded",
        "{:?}",
        wasm.load_errors.lock().unwrap()
    );

    let rt = HttpGuardRuntime::new(None);
    rt.set_wasm(Arc::new(wasm));
    rt.apply(HttpGuardSettings {
        listen_http: Some(listen_on(port)),
        sites: vec![site("mvs", &["mvs.test"], &format!("http://{up}"))],
        ..Default::default()
    })
    .await;

    let req = b"GET /echo HTTP/1.1\r\nHost: mvs.test\r\nx-multi: v1\r\nx-multi: v2\r\ncookie: a=1\r\ncookie: b=2\r\nConnection: close\r\n\r\n";
    let j = raw_http_json(listen_on(port), req).await;
    assert_eq!(j["x_multi"], "replaced", "set_header 必须同名整体替换为单值");
    assert_eq!(j["cookies"], "a=1,b=2", "无关的多值名字不得被塌缩");
}
