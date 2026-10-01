//! TCP 数据面:accept 循环 + 单连接处理。
//!
//! 每个连接一个独立 tokio task(持有 `Arc<RuleState>`),accept 任务
//! 被热重载 abort 不会影响它们。字节计数通过包装流实现,
//! `copy_bidirectional` 两侧读 / 写各自累加到规则的 AtomicU64 上。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use rooster_config::ProxyProtocol;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use super::dns::{self, DnsCache};
use super::limit;
use super::proxy_proto;
use super::{L4Plugins, RuleState};

pub(crate) async fn accept_loop(
    state: Arc<RuleState>,
    dns: Arc<DnsCache>,
    listener: TcpListener,
    plugins: Arc<L4Plugins>,
) {
    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                let state = state.clone();
                let dns = dns.clone();
                let plugins = plugins.clone();
                tokio::spawn(async move {
                    handle_conn(state, dns, client, peer, plugins).await;
                });
            }
            Err(e) => {
                // 常见为 EMFILE:稍等再试,避免忙转。
                tracing::debug!(rule = %state.id, error = %e, "tcp accept error");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// 连接占位守卫:连接任务任何路径退出时都释放并发名额并扣减 active。
struct ConnGuard {
    state: Arc<RuleState>,
    ip: std::net::IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.state.conns_active.fetch_sub(1, Ordering::Relaxed);
        self.state.limiter.lock().unwrap().release(&self.ip);
    }
}

async fn handle_conn(
    state: Arc<RuleState>,
    dns: Arc<DnsCache>,
    mut client: TcpStream,
    peer: SocketAddr,
    plugins: Arc<L4Plugins>,
) {
    let cfg = state.cfg.clone();

    // 先读客户端 PROXY 头(如有),得到真实源地址与 payload 前缀。
    let (real_src, leftover) = if cfg.accept_proxy_protocol {
        match proxy_proto::read_header(&mut client, peer).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(rule = %state.id, error = %e, "malformed PROXY header, dropping");
                return;
            }
        }
    } else {
        (peer, Vec::new())
    };

    // B6:on_l4_accept WASM 插件(真实源地址解析后、ACL 前):
    // Deny 拒绝连接;Ban 走封禁钩子(与 http-guard fire_ban 同参 600s)。
    if let Some(wasm) = plugins.wasm.as_ref() {
        for v in wasm.on_l4_accept(&state.id, real_src) {
            match v {
                crate::wasmrt::Verdict::Continue => {}
                crate::wasmrt::Verdict::Deny => {
                    tracing::info!(
                        rule = %state.id,
                        ip = %real_src.ip(),
                        "connection denied by wasm on_l4_accept plugin"
                    );
                    return;
                }
                crate::wasmrt::Verdict::Ban => {
                    tracing::warn!(
                        rule = %state.id,
                        ip = %real_src.ip(),
                        "on_l4_accept escalated to ban"
                    );
                    if let Some(hook) = plugins.ban_hook.as_ref() {
                        hook(&real_src.ip().to_string(), std::time::Duration::from_secs(600));
                    }
                    return;
                }
            }
        }
    }

    // ACL 以真实源地址判定。
    if !limit::acl_allows(&cfg.acl, real_src.ip()) {
        tracing::info!(rule = %state.id, ip = %real_src.ip(), "connection denied by acl");
        return;
    }
    // 每 IP 滑窗速率 + 并发上限。
    if let Err(reason) = state.limiter.lock().unwrap().try_acquire(&real_src.ip()) {
        tracing::info!(
            rule = %state.id, ip = %real_src.ip(),
            reason = reason.as_str(),
            "connection denied by limits"
        );
        return;
    }

    // 连接上游(缓存 + 全失败强刷一次)。
    let mut upstream = match dns::connect_upstream(&dns, &cfg.target_host, cfg.target_port).await {
        Ok(u) => u,
        Err(e) => {
            // 连接失败:只记日志,不计数、不占名额。
            tracing::warn!(
                rule = %state.id,
                target = %cfg.target_host,
                port = cfg.target_port,
                error = %e,
                "upstream connect failed"
            );
            state.limiter.lock().unwrap().release(&real_src.ip());
            return;
        }
    };

    state.conns_total.fetch_add(1, Ordering::Relaxed);
    state.conns_active.fetch_add(1, Ordering::Relaxed);
    let _guard = ConnGuard {
        state: state.clone(),
        ip: real_src.ip(),
    };

    // 向上游发送 PROXY 头。目的地址取 accepted socket 的本端地址
    //(即监听地址);失败直接放弃该连接。
    if cfg.proxy_protocol != ProxyProtocol::None {
        let dst = client.local_addr().unwrap_or(state.snapshot.listen);
        let header = match cfg.proxy_protocol {
            ProxyProtocol::V1 => proxy_proto::encode_v1(real_src, dst),
            ProxyProtocol::V2 => proxy_proto::encode_v2(real_src, dst),
            ProxyProtocol::None => unreachable!(),
        };
        if let Err(e) = upstream.write_all(&header).await {
            tracing::warn!(rule = %state.id, error = %e, "failed to send PROXY header");
            return;
        }
    }

    // 双向转发,包装流做实时字节计数。
    // client 侧:读 = bytes_in(客户端→上游),写 = bytes_out。
    // upstream 侧:读 = bytes_out,写 = bytes_in。
    let mut client_io = CountIo::new(
        Prefixed::new(client, leftover),
        state.bytes_in.clone(),
        state.bytes_out.clone(),
    );
    let mut upstream_io = CountIo::new(
        upstream,
        state.bytes_out.clone(),
        state.bytes_in.clone(),
    );
    let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
}

// ---------------------------------------------------------------------------
// 计数与前缀流适配器

/// 计数包装:读 / 写各累加到一个 AtomicU64。
struct CountIo<S> {
    inner: S,
    /// 从 inner 读到的字节数计入。
    read_ctr: Arc<AtomicU64>,
    /// 向 inner 写出的字节数计入。
    write_ctr: Arc<AtomicU64>,
}

impl<S> CountIo<S> {
    fn new(inner: S, read_ctr: Arc<AtomicU64>, write_ctr: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            read_ctr,
            write_ctr,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len().saturating_sub(before);
                if n > 0 {
                    self.read_ctr.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    self.write_ctr.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 前缀流:PROXY 头解析时多读出的 payload 字节先于底层流输出。
/// 保证「头 + payload 一次发出」的场景不丢数据。
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.capacity());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
