//! UDP 数据面。
//!
//! 每条规则一个 task、一个监听 socket;按「客户端地址」维护会话:
//! 每个会话单独 bind 一个上游 socket,`Arc<UdpSocket>` 在会话表(客户端→
//! 上游发送)与会话读端任务(上游→客户端回包)之间共享——tokio 的
//! `recv_from` / `send_to` 均取 `&self`,无锁并发安全,也无需额外通道,
//! 不存在无界队列增长。空闲超过 `udp_idle_timeout`(默认 60s)的会话由
//! sweeper 回收。
//!
//! PROXY protocol 不适用于 UDP:该规范(HAProxy 文档)只定义了面向连接 /
//! 首包前置的语义,主流实现也仅在 TCP(及 QUIC 扩展)上发送;UDP 无连接、
//! 无标准头位置,客户端也无法协商,因此这里既不发送也不解析(仅对
//! TCP 生效)。ACL / 限速以数据报源地址为准。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use super::dns::DnsCache;
use super::limit;
use super::RuleState;

struct UdpSession {
    /// 会话上游 socket:主循环向目标发送,读端任务接收回包。
    upstream: Arc<UdpSocket>,
    last_seen: Instant,
    /// 读端任务句柄;会话回收时 abort。
    reader: tokio::task::JoinHandle<()>,
    client: SocketAddr,
}

/// 会话表:Drop 时(含任务被 abort)清空全部会话并归零计数,
/// 保证热重载删除规则后 udp_sessions 立即反映真实状态。
struct SessionMap {
    state: Arc<RuleState>,
    map: HashMap<SocketAddr, UdpSession>,
}

impl Drop for SessionMap {
    fn drop(&mut self) {
        for (_, s) in self.map.drain() {
            s.reader.abort();
        }
        self.state.udp_sessions.store(0, Ordering::SeqCst);
    }
}

pub(crate) async fn run(state: Arc<RuleState>, dns: Arc<DnsCache>, socket: UdpSocket) {
    let idle_timeout = state.cfg.udp_idle_timeout;
    // sweeper 周期:idle/4,钳在 [100ms, 1s]。
    let sweep_every = idle_timeout
        .checked_div(4)
        .filter(|d| !d.is_zero())
        .unwrap_or(Duration::from_millis(100))
        .clamp(Duration::from_millis(100), Duration::from_secs(1));
    let mut ticker = tokio::time::interval(sweep_every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sessions = SessionMap {
        state: state.clone(),
        map: HashMap::new(),
    };
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65_535];

    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                match r {
                    Ok((n, from)) => {
                        handle_inbound(&mut sessions, &dns, &socket, &buf[..n], from).await
                    }
                    Err(e) => {
                        tracing::debug!(rule = %state.id, error = %e, "udp recv error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            _ = ticker.tick() => {
                reap_idle(&mut sessions, idle_timeout);
            }
        }
    }
}

async fn handle_inbound(
    sessions: &mut SessionMap,
    dns: &Arc<DnsCache>,
    listen: &Arc<UdpSocket>,
    data: &[u8],
    from: SocketAddr,
) {
    let state = sessions.state.clone();
    let cfg = state.cfg.clone();

    // ACL 按数据报源地址(UDP 无 PROXY 头,见模块注释)。
    if !limit::acl_allows(&cfg.acl, from.ip()) {
        tracing::debug!(rule = %state.id, ip = %from.ip(), "udp datagram denied by acl");
        return;
    }

    // 每个数据报都解析一次(命中 TTL 缓存时零开销),
    // 域名换址后无需等会话过期。
    let target = match dns.resolve(&cfg.target_host, cfg.target_port, false).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                rule = %state.id, target = %cfg.target_host,
                error = %e, "udp target resolve failed"
            );
            return;
        }
    };
    let Some(target_addr) = target.first().copied() else {
        return;
    };

    if !sessions.map.contains_key(&from) {
        // 会话创建视作一次「连接」,走限速与每 IP 并发上限。
        if let Err(reason) = state.limiter.lock().unwrap().try_acquire(&from.ip()) {
            tracing::info!(
                rule = %state.id, ip = %from.ip(),
                reason = reason.as_str(),
                "udp session denied by limits"
            );
            return;
        }
        match create_session(sessions, from, target_addr, listen).await {
            Ok(()) => {
                state.udp_sessions.fetch_add(1, Ordering::Relaxed);
                state.conns_total.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(rule = %state.id, error = %e, "udp session setup failed");
                state.limiter.lock().unwrap().release(&from.ip());
                return;
            }
        }
    }

    if let Some(sess) = sessions.map.get_mut(&from) {
        sess.last_seen = Instant::now();
        match sess.upstream.send_to(data, target_addr).await {
            Ok(_) => {
                state.bytes_in.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            Err(e) => tracing::debug!(rule = %state.id, error = %e, "udp forward send failed"),
        }
    }
}

async fn create_session(
    sessions: &mut SessionMap,
    client: SocketAddr,
    target: SocketAddr,
    listen: &Arc<UdpSocket>,
) -> std::io::Result<()> {
    // 上游 socket 与目标同族 bind 任意本地端口。
    let bind_any: SocketAddr = match target {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    };
    let upstream = Arc::new(UdpSocket::bind(bind_any).await?);
    let reader = tokio::spawn(upstream_reader(
        upstream.clone(),
        client,
        listen.clone(),
        sessions.state.clone(),
    ));
    sessions.map.insert(
        client,
        UdpSession {
            upstream,
            last_seen: Instant::now(),
            reader,
            client,
        },
    );
    Ok(())
}

/// 会话读端:上游回包直接经监听 socket 回给客户端(源地址必须与客户端
/// 发往的转发地址一致,否则客户端会丢弃),并累加 bytes_out。
async fn upstream_reader(
    up: Arc<UdpSocket>,
    client: SocketAddr,
    listen: Arc<UdpSocket>,
    state: Arc<RuleState>,
) {
    let mut buf = vec![0u8; 65_535];
    loop {
        match up.recv_from(&mut buf).await {
            Ok((n, _)) => {
                if listen.send_to(&buf[..n], client).await.is_ok() {
                    state.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            Err(_) => break,
        }
    }
}

/// 回收空闲超时的会话。
fn reap_idle(sessions: &mut SessionMap, idle_timeout: Duration) {
    let now = Instant::now();
    let state = sessions.state.clone();
    sessions.map.retain(|_, sess| {
        if now.duration_since(sess.last_seen) > idle_timeout {
            sess.reader.abort();
            state.udp_sessions.fetch_sub(1, Ordering::Relaxed);
            state.limiter.lock().unwrap().release(&sess.client.ip());
            false
        } else {
            true
        }
    });
}
