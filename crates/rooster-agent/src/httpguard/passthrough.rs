//! 透传模式数据面:L4 规则 + PROXY protocol + 双向拷贝。
//!
//! 443 监听任务已经把 ClientHello 缓冲在 [`PeekStream`] 里并完成
//! SNI / JA4 解析;这里做 L4 检查(全部不通过即直接断开,不给响应):
//! 1. Geo(真实 IP = TCP peer;解密前拿不到 XFF);
//! 2. `ja4-deny` 命中 → drop;
//! 3. `rate-limit` 中 key 为 `ip` 的规则在 accept 时点执行令牌桶,
//!    超限 drop(`reject` / `ban` 同样直接断开,Ban 额外触发 ban_hook)。
//! 通过后:连上游(裸 `host:port` 或 `http(s)://` 均按 TCP 连),
//! 按需先写 PROXY protocol v1/v2 头,随后把缓冲的 ClientHello 原样
//! 重放并进入双向拷贝(带字节计数,计入站点统计)。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::clienthello::ClientHelloInfo;
use super::peek::PeekStream;
use super::settings::{Effective, SiteRt};
use super::throttle::RateDecision;
use crate::forward::proxy_proto;

/// 上游连接超时:与终止模式 [`super::httpsrv`] 的 connect 超时保持一致,
/// 否则黑洞上游会让每条已 accept 的连接占用到 OS TCP 超时。
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 连接生命周期守卫:进入时加 active,任何路径退出都减。
struct ConnGuard {
    site: Arc<SiteRt>,
}

impl ConnGuard {
    fn new(site: &Arc<SiteRt>) -> Self {
        site.stats.active.fetch_add(1, Ordering::Relaxed);
        Self { site: site.clone() }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.site.stats.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// JA4 指纹命中黑名单即拒绝。指纹缺失(解析失败)不误伤。
pub(crate) fn ja4_denied(deny: &[String], ja4: &Option<String>) -> bool {
    match ja4 {
        Some(j) => deny.iter().any(|d| d == j),
        None => false,
    }
}

/// 处理一条透传连接。
pub(crate) async fn handle(
    eff: Arc<Effective>,
    site: Arc<SiteRt>,
    hello: Option<ClientHelloInfo>,
    client: PeekStream<TcpStream>,
    peer: SocketAddr,
) {
    let _guard = ConnGuard::new(&site);
    let ip = peer.ip();

    // L4:Geo。
    if let Some(rule) = site.cfg.geo.as_ref() {
        if !super::geo::allowed(rule, eff.geo.as_deref(), ip) {
            site.stats.blocked.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(site = %site.cfg.id, ip = %ip, "passthrough dropped by geo rule");
            return;
        }
    }

    // L4:JA4 黑名单。
    if ja4_denied(&site.cfg.ja4_deny, &hello.as_ref().and_then(|h| h.ja4.clone())) {
        site.stats.blocked.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(site = %site.cfg.id, ip = %ip, "passthrough dropped by ja4 deny list");
        return;
    }

    // L4:仅 key=ip 的限速规则(透传模式下没有路径 / 头可用)。
    let ip_rules: Vec<_> = site.rates.iter().filter(|r| r.is_ip_key()).cloned().collect();
    if !ip_rules.is_empty() {
        let decision = site
            .limiter
            .lock()
            .unwrap()
            .check(&ip_rules, ip, "", &[]);
        match decision {
            RateDecision::Allow => {}
            RateDecision::Reject => {
                site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(site = %site.cfg.id, ip = %ip, "passthrough dropped by rate limit");
                return;
            }
            RateDecision::Ban => {
                site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                fire_ban(&eff, &site, ip);
                tracing::warn!(site = %site.cfg.id, ip = %ip, "passthrough dropped: rate limit escalated to ban");
                return;
            }
        }
    }

    // 连接上游并可选发送 PROXY 头。
    let up = site.upstream.clone();
    let connected = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect((up.host.as_str(), up.port)),
    )
    .await;
    let mut upstream = match connected {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(site = %site.cfg.id, upstream = %up.authority(), error = %e, "passthrough upstream connect failed");
            return;
        }
        Err(_) => {
            tracing::warn!(site = %site.cfg.id, upstream = %up.authority(), timeout_s = UPSTREAM_CONNECT_TIMEOUT.as_secs(), "passthrough upstream connect timed out");
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    let local = client.inner().local_addr().ok();
    let header = match local {
        Some(l) => proxy_proto::encode(site.cfg.proxy_protocol, peer, l),
        None => Vec::new(),
    };
    if !header.is_empty() {
        if let Err(e) = upstream.write_all(&header).await {
            tracing::debug!(site = %site.cfg.id, error = %e, "passthrough proxy-protocol write failed");
            return;
        }
    }
    site.stats.conns_passthrough.fetch_add(1, Ordering::Relaxed);
    if let Some(h) = hello.as_ref() {
        if let Some(j) = &h.ja4 {
            tracing::debug!(site = %site.cfg.id, ip = %ip, ja4 = %j, "passthrough established");
        }
    }

    // 双向拷贝(带计数)。client 侧先消费 PeekStream 里缓冲的 ClientHello。
    let bytes_in = site.stats.bytes_in.clone();
    let bytes_out = site.stats.bytes_out.clone();
    let (mut cr, mut cw) = tokio::io::split(client);
    // into_split 拆出所有权半边:spawn 的拷贝任务要求 'static,
    // 借用式 split() 的半边拿不出函数体。
    let (mut ur, mut uw) = upstream.into_split();
    let a = tokio::spawn(async move {
        let n = copy_count(&mut cr, &mut uw, &bytes_in).await;
        let _ = uw.shutdown().await;
        n
    });
    let b = tokio::spawn(async move {
        let n = copy_count(&mut ur, &mut cw, &bytes_out).await;
        let _ = cw.shutdown().await;
        n
    });
    let _ = tokio::join!(a, b);
}

async fn copy_count<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    counter: &Arc<std::sync::atomic::AtomicU64>,
) -> io::Result<u64> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(total)
}

/// 触发 ban_hook(封禁管理由主会话的封禁管理器执行,FR-N 系列)。
pub(crate) fn fire_ban(eff: &Effective, site: &SiteRt, ip: IpAddr) {
    if let Some(hook) = eff.ban_hook.as_ref() {
        hook(&ip.to_string(), Duration::from_secs(600));
    } else {
        tracing::debug!(site = %site.cfg.id, ip = %ip, "rate limit ban without ban_hook configured");
    }
}
