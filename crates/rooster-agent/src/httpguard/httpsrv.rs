//! HTTP 数据面。
//!
//! - 80 端口:hyper(auto h1/h2c)按 Host 路由;ACME HTTP-01 challenge
//!   优先应答;`redirect_https` 站点 301;默认反向代理到上游。
//! - 443 终止模式:rustls 握手后同样走 [`handle_site_request`],
//!   支持 HTTP/1.1、HTTP/2 与 WebSocket 升级(101 隧道)。
//! - 上游连接:每请求建立一条 HTTP/1.1 连接(实现选择,无连接池;
//!   `https://` 上游接受任意证书,见 `tlsconf`)。
//! - WAF:请求体前 `body_limit` 字节缓冲后交给 inspector;超出部分打
//!   标记直接透传,上游收到完整请求体。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, HOST, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::http1;
use hyper::service::Service;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto;
use rooster_config::WafMode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::settings::{Effective, SiteRt};
use super::throttle::RateDecision;
use super::Shared;

/// 响应 / 上游请求体统一类型。
type B = BoxBody<Bytes, io::Error>;

/// hyper 错误并入 io::Error(统一 BoxBody 的错误类型)。
fn hyper_err_to_io(e: hyper::Error) -> io::Error {
    io::Error::other(e)
}

fn io_err(e: impl Into<io::Error>) -> io::Error {
    e.into()
}

fn full(body: Bytes) -> Response<B> {
    Response::new(
        Full::new(body)
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed(),
    )
}

fn text(status: StatusCode, msg: &str) -> Response<B> {
    let mut resp = full(Bytes::copy_from_slice(msg.as_bytes()));
    *resp.status_mut() = status;
    resp
}

// ---------------------------------------------------------------------------
// body 适配器

/// 「已缓冲前缀 + 未读余量」组成的转发体:WAF 只窥探前缀,余量
/// (含被截断帧的剩余部分)原样续传,上游拿到完整请求体。
struct DelayedBody<Rest: Body<Data = Bytes> + Unpin> {
    pending: VecDeque<Bytes>,
    rest: Option<Rest>,
}

impl<Rest: Body<Data = Bytes> + Unpin> Body for DelayedBody<Rest> {
    type Data = Bytes;
    type Error = Rest::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        while let Some(front) = self.pending.front_mut() {
            if front.is_empty() {
                self.pending.pop_front();
                continue;
            }
            let chunk = std::mem::take(front);
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        match self.rest.as_mut() {
            Some(rest) => Pin::new(rest).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_empty()
            && self
                .rest
                .as_ref()
                .map(|r| r.is_end_stream())
                .unwrap_or(true)
    }
}

/// 空闲超时体(slow-loris `body-idle-timeout` 的流式段):两帧之间
/// 空闲超过 `idle` 即以错误终止上传。覆盖 WAF 关闭(完全不缓冲)与
/// 检测缓冲之后的余量转发两条路径 —— 旧实现只在缓冲阶段设超时,其余
/// 段可以永久涓流。实现:成功产出帧时重置定时器;Pending 时轮询定时
/// 器,定时器到点会唤醒上层任务,因此即使客户端一字不发也会被切断。
struct IdleTimeoutBody {
    inner: B,
    idle: Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Body for IdleTimeoutBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 有帧 = 有进展:重置空闲计时(错误/结束不重置,交上层)。
                this.sleep = Some(Box::pin(tokio::time::sleep(this.idle)));
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(other) => Poll::Ready(other),
            Poll::Pending => {
                let sleep = this
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.idle)));
                match std::future::Future::poll(sleep.as_mut(), cx) {
                    Poll::Ready(()) => Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body idle timeout",
                    )))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

/// 字节计数体:Data 字节数累加到站点统计(HTTP 模式的 bytes_in /
/// bytes_out,透传模式由拷贝循环计数)。`cap` 为 Some 时同时充当
/// 请求体硬上限:累计字节超过 cap 立即以错误终止流(hardening.body-cap;
/// 无 Content-Length 的分块上传只有这里能拦)。
struct CountingBody<Inner: Body<Data = Bytes> + Unpin> {
    inner: Inner,
    counter: Arc<std::sync::atomic::AtomicU64>,
    cap: Option<u64>,
    seen: u64,
}

impl<Inner: Body<Data = Bytes> + Unpin> Body for CountingBody<Inner>
where
    Inner::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = data.len() as u64;
                    this.counter.fetch_add(n, Ordering::Relaxed);
                    this.seen += n;
                    if this.cap.is_some_and(|c| this.seen > c) {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "request body over hardening.body-cap",
                        ))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(io::Error::other(
                e,
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

// ---------------------------------------------------------------------------
// 上游 IO(明文 TCP 或 TLS 的统一形态)

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

struct BoxedIo(Box<dyn AsyncReadWrite + Unpin>);

impl hyper::rt::Read for BoxedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match Pin::new(&mut self.0).poll_read(cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for BoxedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncRead for BoxedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

async fn connect_upstream(tls: bool, host: &str, port: u16, skip_verify: bool) -> io::Result<BoxedIo> {
    let tcp = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream connect timeout",
            ))
        }
    };
    let _ = tcp.set_nodelay(true);
    if !tls {
        return Ok(BoxedIo(Box::new(tcp)));
    }
    // https 上游:默认校验证书链与 hostname(见 tlsconf 模块注释)。
    let connector = TlsConnector::from(super::tlsconf::upstream_client_config(skip_verify));
    let name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad sni: {e}")))?,
    };
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(name, tcp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream tls timeout"))??;
    Ok(BoxedIo(Box::new(tls_stream)))
}

// ---------------------------------------------------------------------------
// 服务(80 端口:Host 路由)

/// 80 端口连接服务:每次请求按 Host 重新路由。
pub(crate) struct PlainService {
    pub(crate) shared: Arc<Shared>,
    pub(crate) eff: Arc<Effective>,
    pub(crate) peer: SocketAddr,
}

impl Service<Request<Incoming>> for PlainService {
    type Response = Response<B>;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Response<B>, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let shared = self.shared.clone();
        let eff = self.eff.clone();
        let peer = self.peer;
        Box::pin(async move { Ok(route_plain(shared, eff, peer, req).await) })
    }
}

async fn route_plain(
    shared: Arc<Shared>,
    eff: Arc<Effective>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<B> {
    // Host 路由(去端口、小写比较);无匹配回退第一个站点,
    // 没有任何站点时 404。
    let host = request_host(req.headers(), req.uri()).map(|h| strip_port(&h));
    let Some(site) = eff.route(host.as_deref()) else {
        return text(StatusCode::NOT_FOUND, "no site configured\n");
    };
    site.stats.requests.fetch_add(1, Ordering::Relaxed);

    // ACME HTTP-01 在一切站点逻辑之前应答(80 端口)。
    let path = req.uri().path().to_string();
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        if token.is_empty() || token.contains('/') {
            return text(StatusCode::NOT_FOUND, "not found\n");
        }
        let key_auth = shared.challenges.lock().unwrap().get(token).cloned();
        return match key_auth {
            Some(k) => {
                tracing::info!(token = %token, "acme http-01 challenge answered");
                let mut resp = full(Bytes::from(k));
                resp.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain"),
                );
                resp
            }
            None => text(StatusCode::NOT_FOUND, "not found\n"),
        };
    }

    // 站点开关控制 80 → 443 跳转(v1 默认关闭)。
    if site.cfg.redirect_https.unwrap_or(false) {
        let host = host.unwrap_or_default();
        let target = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let mut resp = full(Bytes::new());
        *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
        if let Ok(loc) = HeaderValue::from_str(&format!("https://{host}{target}")) {
            resp.headers_mut().insert(http::header::LOCATION, loc);
        }
        return resp;
    }

    handle_site_request(
        shared,
        eff.clone(),
        site,
        real_ip_of(&eff, req.headers(), peer),
        req,
        peer,
        "http",
    )
    .await
}

/// 可信代理链下的真实 IP(与 handle_site_request 旧内联逻辑同源)。
fn real_ip_of(eff: &Effective, headers: &HeaderMap, peer: SocketAddr) -> std::net::IpAddr {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    super::realip::real_ip(peer.ip(), xff.as_deref(), &eff.trusted_proxies)
}

// ---------------------------------------------------------------------------
// 服务(443 终止模式)

/// 终止模式连接服务:站点已由 SNI 决定,整条连接固定。
pub(crate) struct TlsService {
    pub(crate) shared: Arc<Shared>,
    pub(crate) eff: Arc<Effective>,
    pub(crate) site: Arc<SiteRt>,
    pub(crate) peer: SocketAddr,
}

impl Service<Request<Incoming>> for TlsService {
    type Response = Response<B>;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Response<B>, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let shared = self.shared.clone();
        let eff = self.eff.clone();
        let site = self.site.clone();
        let peer = self.peer;
        Box::pin(async move {
            site.stats.requests.fetch_add(1, Ordering::Relaxed);
            let ip = real_ip_of(&eff, req.headers(), peer);
            Ok(handle_site_request(shared, eff, site, ip, req, peer, "https").await)
        })
    }
}

// ---------------------------------------------------------------------------
// 站点请求处理核心

/// 请求的目标主机名(已去端口)。
///
/// HTTP/2 不含 `host` 头,h2 crate 只把 `:authority` 放进 `req.uri()`
/// (h2 `server.rs`),因此必须回退到 authority,否则 h2c 客户端会被
/// 路由到 `sites.first()`。
fn request_host(headers: &HeaderMap, uri: &http::Uri) -> Option<String> {
    if let Some(v) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
        return Some(v.to_string());
    }
    uri.authority().map(|a| a.as_str().to_string())
}

/// Host 头去掉端口(`[::1]:8080` / `a.b:80` → 地址本体)。
fn strip_port(host: &str) -> String {
    if host.starts_with('[') {
        if let Some((h, _)) = host.split_once(']') {
            return h[1..].to_string();
        }
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => host.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_site_request(
    shared: Arc<Shared>,
    eff: Arc<Effective>,
    site: Arc<SiteRt>,
    ip: std::net::IpAddr,
    mut req: Request<Incoming>,
    _peer: SocketAddr,
    proto: &'static str,
) -> Response<B> {
    // WebSocket 升级探测。
    let is_ws = wants_websocket(req.headers());
    // 先取 OnUpgrade;返回 101 后由隧道任务等待。
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Geo 规则。
    if let Some(rule) = site.cfg.geo.as_ref() {
        if !super::geo::allowed(rule, eff.geo.as_deref(), ip) {
            site.stats.blocked.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(site = %site.cfg.id, ip = %ip, "request blocked by geo rule");
            return text(StatusCode::FORBIDDEN, "blocked by geo rule\n");
        }
    }

    // 速率限制。
    let path = req.uri().path().to_string();
    if !site.rates.is_empty() {
        let headers = header_pairs(req.headers());
        let decision = site
            .limiter
            .lock()
            .unwrap()
            .check(&site.rates, ip, &path, &headers);
        match decision {
            RateDecision::Allow => {}
            RateDecision::Reject => {
                site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(site = %site.cfg.id, ip = %ip, path = %path, "request rejected by rate limit");
                return text(StatusCode::TOO_MANY_REQUESTS, "rate limited\n");
            }
            RateDecision::Ban => {
                site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                super::passthrough::fire_ban(&eff, &site, ip);
                tracing::warn!(site = %site.cfg.id, ip = %ip, path = %path, "rate limit escalated to ban");
                return text(StatusCode::TOO_MANY_REQUESTS, "rate limited\n");
            }
        }
    }

    // on_http_request_headers WASM 插件(在限速之后、
    // WAF/转发之前;插件可改写请求头)。
    if let Some(wasm) = shared.wasm.read().unwrap().as_ref() {
        // B4:插件可见视角 = UTF-8 键值对;只有插件真的改了内容才回写,
        // 否则一字不动(运行时注入但零插件时不能碰请求)。回写按名字
        // 重建(先删该名字全部值再按序 append),多值头不塌缩;两个视角
        // 都没出现的名字(如非 UTF-8 值被丢弃者)原样保留不误删。
        let original = header_pairs(req.headers());
        let mut headers = original.clone();
        let verdicts = wasm.on_http_request_headers(&site.cfg.id, &mut headers);
        if headers != original {
            let mut names: Vec<&str> = Vec::new();
            for (name, _) in original.iter().chain(headers.iter()) {
                if !names.contains(&name.as_str()) {
                    names.push(name.as_str());
                }
            }
            for name in &names {
                if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
                    req.headers_mut().remove(&hn);
                }
            }
            for (name, value) in &headers {
                let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) else { continue; };
                if let Ok(hv) = HeaderValue::from_str(value) {
                    req.headers_mut().append(hn, hv);
                }
            }
        }
        for v in verdicts {
            match v {
                crate::wasmrt::Verdict::Continue => {}
                crate::wasmrt::Verdict::Deny => {
                    site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(site = %site.cfg.id, ip = %ip, "request denied by wasm plugin");
                    return text(StatusCode::FORBIDDEN, "blocked by wasm plugin\n");
                }
                crate::wasmrt::Verdict::Ban => {
                    site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                    super::passthrough::fire_ban(&eff, &site, ip);
                    return text(StatusCode::FORBIDDEN, "blocked by wasm plugin\n");
                }
            }
        }
    }

    // WAF。off → 完全跳过(连请求体都不缓冲);
    // detect/block → 缓冲前 body_limit 字节交给 inspector,超出部分
    // 打标记继续转发(不因超限失败请求)。
    let waf_mode = site.waf_mode();
    // hardening.body-cap:声明式 Content-Length 直接 413(不占上游连接);
    // 分块/无长度上传由 CountingBody 在流式路径上拦截。
    if let (Some(cap), Some(cl)) = (site.body_cap, req.headers().get(CONTENT_LENGTH)) {
        let declared = cl.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok());
        if matches!(declared, Some(n) if n > cap) {
            tracing::debug!(
                site = %site.cfg.id, ip = %ip, cap,
                "request body over hardening.body-cap; rejected with 413"
            );
            return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
        }
    }
    let (parts, rest_body) = req.into_parts();
    let mut buffered: Vec<u8> = Vec::new();
    let mut leftover: Option<Bytes> = None;
    let mut truncated = false;
    let mut rest_body = rest_body;
    if waf_mode != WafMode::Off {
        // When the hard cap is smaller than the WAF buffer, reject excess bytes
        // before inspection instead of allocating the full inspection buffer.
        let cap_u64 = site.body_cap.unwrap_or(u64::MAX);
        let inspect_limit = (eff.body_limit as u64).min(cap_u64) as usize;
        let count_through = cap_u64 < eff.body_limit as u64;
        let mut seen: u64 = 0;
        loop {
            if buffered.len() >= inspect_limit && !count_through {
                break;
            }
            let frame = match eff.body_idle {
                Some(idle) => match tokio::time::timeout(idle, rest_body.frame()).await {
                    Ok(f) => f,
                    Err(_) => {
                        tracing::debug!(site = %site.cfg.id, ip = %ip, "request body stalled; 408");
                        return text(StatusCode::REQUEST_TIMEOUT, "request body timeout\n");
                    }
                },
                None => rest_body.frame().await,
            };
            match frame {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        seen += data.len() as u64;
                        if seen > cap_u64 {
                            tracing::debug!(
                                site = %site.cfg.id, ip = %ip, cap = cap_u64,
                                "chunked request body over hardening.body-cap; rejected with 413"
                            );
                            return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
                        }
                        if buffered.len() < inspect_limit {
                            let room = inspect_limit - buffered.len();
                            if data.len() <= room {
                                buffered.extend_from_slice(&data);
                            } else {
                                let mut head = data;
                                let tail = head.split_off(room);
                                buffered.extend_from_slice(&head);
                                leftover = Some(tail);
                                truncated = true;
                            }
                        }
                    }
                }
                Some(Err(_)) | None => break,
            }
        }
        if truncated {
            tracing::debug!(
                site = %site.cfg.id,
                limit = eff.body_limit,
                "request body exceeded waf body limit; forwarding remainder uninspected"
            );
        }
    }

    if let Some(inspector) = shared.inspector.read().unwrap().as_ref() {
        if waf_mode != WafMode::Off {
            let headers = header_pairs(&parts.headers);
            let cookies = cookie_pairs(&parts.headers);
            let uri_str = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| parts.uri.path().to_string());
            let verdict = inspector.inspect(super::InspectCtx {
                method: parts.method.as_str(),
                uri: &uri_str,
                headers: &headers,
                cookies: &cookies,
                body: &buffered,
            });
            let exclusions = site
                .cfg
                .waf
                .as_ref()
                .map(|w| w.exclusions.as_slice())
                .unwrap_or(&[]);
            // B5:过滤时保住与命中对齐的严重度(事件上报用)。
            let mut hits: Vec<(u32, String)> = Vec::new();
            let mut hit_sevs: Vec<u8> = Vec::new();
            for (i, (id, msg)) in verdict.hits.iter().enumerate() {
                if exclusions.contains(id) {
                    continue;
                }
                hits.push((*id, msg.clone()));
                hit_sevs.push(verdict.hit_severities.get(i).copied().unwrap_or(0));
            }
            if verdict.blocked || !verdict.hits.is_empty() {
                tracing::warn!(
                    site = %site.cfg.id,
                    ip = %ip,
                    mode = ?waf_mode,
                    hits = ?verdict.hits,
                    filtered_hits = ?hits,
                    score = verdict.score,
                    "waf verdict"
                );
            }
            // 判定:inspector 已按阈值给出 blocked;本地再按站点排除列表
            // 过滤——inspector 未报命中(或全部命中都被排除)时不拦截,
            // 让主会话桥接无需感知 exclusions 也能得到一致行为。
            let blocked = verdict.blocked && (verdict.hits.is_empty() || !hits.is_empty());
            if waf_mode == WafMode::Block && blocked {
                site.stats.blocked.fetch_add(1, Ordering::Relaxed);
                // 拦截必须上报 Block 事件,否则 hub 侧
                // 按事件联动的封禁策略永远没有数据源。ip 用真实客户端 IP
                // (XFF 可信解析结果),与限速/封禁路径同源;detect 模式
                // 不进这里(对全队静默),off 模式根本不做检测。
                let (rule_id, severity) = top_hit(&hits, &hit_sevs);
                let event = rooster_proto::Event::Block {
                    ip: ip.to_string(),
                    rule_id,
                    site: site.cfg.id.clone(),
                    severity,
                    path: Some(parts.uri.path().to_string()),
                    hits: hits.iter().map(|(id, _)| *id).collect(),
                    score: Some(verdict.score),
                };
                let sink = shared.event_sink.read().unwrap().clone();
                match sink {
                    Some(sink) => sink(event),
                    None => tracing::debug!(
                        site = %site.cfg.id,
                        "waf block without event sink; event not reported"
                    ),
                }
                return text(StatusCode::FORBIDDEN, "blocked by waf\n");
            }
            // detect 模式只记录(上方 warn),继续转发。
        }
    }

    // 构造上游请求(转发头)。join 规则见 settings::Upstream::join。
    let up = &site.upstream;
    let skip_verify = site.cfg.tls.skip_verify;
    let joined = up.join(
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/"),
    );
    let uri = match joined.parse::<http::Uri>() {
        // origin-form(path+query)即可:连接已指向该上游;绝对形式会让
        // HTTP/1.1 升级请求写出 absolute-form 请求行并被 hyper 客户端拒绝。
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(site = %site.cfg.id, error = %e, "upstream uri build failed");
            return text(StatusCode::BAD_GATEWAY, "bad upstream\n");
        }
    };

    let mut up_req_builder = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .version(Version::HTTP_11);
    for (name, value) in parts.headers.iter() {
        // HOST 除外:下方统一改写后单独设置,避免双 Host 头
        // (RFC 9110 不允许,上游会 400)。
        if name != HOST && !is_hop_by_hop(name, is_ws) {
            up_req_builder = up_req_builder.header(name.clone(), value.clone());
        }
    }
    let ip_str = ip.to_string();
    let xff_value = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|existing| format!("{existing}, {ip_str}"))
        .unwrap_or_else(|| ip_str.clone());
    // h2 请求没有 host 头,回退到原始 authority,否则上游收到的是
    // 上游地址而非客户端请求的域名(按域名做虚拟主机的后端会串站)。
    let original_host = request_host(&parts.headers, &parts.uri)
        .and_then(|h| HeaderValue::from_str(&h).ok());
    let host_value = original_host.unwrap_or_else(|| {
        HeaderValue::from_str(&up.authority()).unwrap_or(HeaderValue::from_static("upstream"))
    });
    up_req_builder = up_req_builder
        .header(
            "x-forwarded-for",
            HeaderValue::from_str(&xff_value)
                .unwrap_or(HeaderValue::from_static("unknown")),
        )
        .header(
            "x-real-ip",
            HeaderValue::from_str(&ip_str).unwrap_or(HeaderValue::from_static("unknown")),
        )
        .header("x-forwarded-proto", HeaderValue::from_static(proto))
        .header(HOST, host_value);

    let up_body: B = if is_ws {
        Empty::<Bytes>::new()
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed()
    } else {
        let mut pending = VecDeque::new();
        if !buffered.is_empty() {
            pending.push_back(Bytes::from(buffered.clone()));
        }
        if let Some(lo) = leftover.take() {
            pending.push_back(lo);
        }
        let delayed = DelayedBody {
            pending,
            rest: Some(rest_body),
        }
        .map_err(hyper_err_to_io)
        .boxed();
        match eff.body_idle {
            // WAF-off and post-inspection uploads must retain the same idle bound.
            Some(idle) => IdleTimeoutBody {
                inner: delayed,
                idle,
                sleep: None,
            }
            .boxed(),
            None => delayed,
        }
    };
    // 请求体计数;cap = 本站点生效的 body-cap(仅 client→upstream 方向)。
    let up_body = CountingBody {
        inner: up_body,
        counter: site.stats.bytes_in.clone(),
        cap: site.body_cap,
        seen: 0,
    };

    let up_req = match up_req_builder.body(up_body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(site = %site.cfg.id, error = %e, "upstream request build failed");
            return text(StatusCode::BAD_GATEWAY, "bad upstream\n");
        }
    };

    // 连上游 + HTTP/1.1 握手(每请求一条连接,无连接池)。
    let io_stream = match connect_upstream(up.tls, &up.host, up.port, skip_verify).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(site = %site.cfg.id, upstream = %up.authority(), error = %e, "upstream connect failed");
            return text(StatusCode::BAD_GATEWAY, "upstream unreachable\n");
        }
    };
    let (mut sender, conn) = match http1::handshake(io_stream).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(site = %site.cfg.id, error = %e, "upstream handshake failed");
            return text(StatusCode::BAD_GATEWAY, "upstream handshake failed\n");
        }
    };
    tokio::spawn(async move {
        // WebSocket 升级必须用 with_upgrades 包装 Connection:否则 101 响应
        // 不携带 OnUpgrade 扩展,hyper::upgrade::on 返回 ManualUpgrade。
        let _ = conn.with_upgrades().await;
    });

    let mut up_resp = match sender.send_request(up_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(site = %site.cfg.id, error = %e, "upstream request failed");
            return text(StatusCode::BAD_GATEWAY, "upstream failed\n");
        }
    };

    // WebSocket:上游 101 → 透传 101 并建立双向隧道。
    let ws_tunnel = is_ws && up_resp.status() == StatusCode::SWITCHING_PROTOCOLS;
    let up_upgrade = if ws_tunnel {
        Some(hyper::upgrade::on(&mut up_resp))
    } else {
        None
    };

    let (mut up_parts, resp_body) = up_resp.into_parts();
    up_parts.version = Version::HTTP_11;
    let counting = CountingBody {
        inner: resp_body,
        counter: site.stats.bytes_out.clone(),
        cap: None,
        seen: 0,
    }
    .boxed();

    for name in collect_hop_by_hop(&up_parts.headers, ws_tunnel) {
        up_parts.headers.remove(&name);
    }
    let resp = Response::from_parts(up_parts, counting);

    if let Some(up_upgrade) = up_upgrade {
        let site2 = site.clone();
        tokio::spawn(async move {
            match tokio::join!(client_upgrade, up_upgrade) {
                (Ok(client_io), Ok(up_io)) => {
                    tunnel_websocket(client_io, up_io, site2).await;
                }
                (a, b) => {
                    tracing::debug!(
                        client_err = ?a.err(),
                        upstream_err = ?b.err(),
                        "websocket upgrade failed"
                    );
                }
            }
        });
    }

    resp
}

/// WebSocket 隧道:升级后的两个裸流做双向拷贝并计数。
async fn tunnel_websocket(
    client: hyper::upgrade::Upgraded,
    upstream: hyper::upgrade::Upgraded,
    site: Arc<SiteRt>,
) {
    // hyper 的 Upgraded 实现 hyper::rt::Read/Write;TokioIo 适配为 tokio trait。
    let client = hyper_util::rt::TokioIo::new(client);
    let upstream = hyper_util::rt::TokioIo::new(upstream);
    let bytes_in = site.stats.bytes_in.clone();
    let bytes_out = site.stats.bytes_out.clone();
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let a = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if uw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        let _ = uw.shutdown().await;
    });
    let b = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match ur.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        let _ = cw.shutdown().await;
    });
    let _ = tokio::join!(a, b);
}

/// 需要剔除的逐跳头;`keep_upgrade` 为 WebSocket 升级保留 Connection/Upgrade。
fn collect_hop_by_hop(headers: &HeaderMap, keep_upgrade: bool) -> Vec<HeaderName> {
    headers
        .keys()
        .filter(|name| {
            if keep_upgrade && (*name == CONNECTION || *name == UPGRADE) {
                return false;
            }
            matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
            )
        })
        .cloned()
        .collect()
}

fn is_hop_by_hop(name: &HeaderName, keep_upgrade: bool) -> bool {
    if keep_upgrade && (name == CONNECTION || name == UPGRADE) {
        return false;
    }
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn wants_websocket(headers: &HeaderMap) -> bool {
    let conn_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")));
    let up_ws = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    conn_upgrade && up_ws
}

/// B5:取命中里严重度最高的一条(同分取先出现),映射为 Block 事件的
/// rule_id 与 severity 名;无命中 Hit(纯异常评分阈值阻断)时用固定
/// rule-id,severity 退化为 None(等价旧帧语义)。
fn top_hit(hits: &[(u32, String)], sevs: &[u8]) -> (String, Option<String>) {
    let mut best: Option<(usize, u8)> = None;
    for (i, s) in sevs.iter().enumerate() {
        match best {
            Some((_, bs)) if *s <= bs => {}
            _ => best = Some((i, *s)),
        }
    }
    match best {
        Some((i, s)) => (hits[i].0.to_string(), severity_name(s).map(str::to_string)),
        None => ("anomaly-threshold".to_string(), None),
    }
}

/// rooster-waf 严重度权重 → 级别名(parser:CRITICAL=5/ERROR=4/
/// WARNING=3/NOTICE=2);未知权重 → None。hub 按名字大小写不敏感比较,
/// 这里给全大写正名。
fn severity_name(sev: u8) -> Option<&'static str> {
    match sev {
        5 => Some("CRITICAL"),
        4 => Some("ERROR"),
        3 => Some("WARNING"),
        2 => Some("NOTICE"),
        _ => None,
    }
}

/// 小写键值对(http crate 的 HeaderName 本身即小写)。
fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect()
}

/// 从 Cookie 头解析 k=v 对。
fn cookie_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for value in headers.get_all(http::header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.split_once('=') {
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 连接服务入口(由监听任务调用)

/// 80 端口明文连接。
pub(crate) async fn serve_plain(
    shared: Arc<Shared>,
    eff: Arc<Effective>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    let svc = PlainService {
        shared,
        eff: eff.clone(),
        peer,
    };
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // slow-loris:请求头读取超时(h2 自带流级超时语义,此项只作用于 h1)。
    // timer 必须一并提供:hyper 在配置了 header_read_timeout 而没有
    // timer 时直接 panic(整条连接被 panic 关闭),TokioTimer 是标配配套。
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(eff.header_timeout);
    let io = hyper_util::rt::TokioIo::new(stream);
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        tracing::debug!(peer = %peer, error = %e, "http connection error");
    }
}

/// 443 终止模式连接(TLS 流)。
pub(crate) async fn serve_tls(
    shared: Arc<Shared>,
    eff: Arc<Effective>,
    site: Arc<SiteRt>,
    stream: tokio_rustls::server::TlsStream<super::peek::PeekStream<TcpStream>>,
    peer: SocketAddr,
) {
    let svc = TlsService {
        shared,
        eff: eff.clone(),
        site,
        peer,
    };
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(eff.header_timeout);
    let io = hyper_util::rt::TokioIo::new(stream);
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        tracing::debug!(peer = %peer, error = %e, "tls connection error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri_with_authority(a: &str) -> http::Uri {
        format!("http://{a}/x").parse().unwrap()
    }

    /// 回归(F1):HTTP/2 请求没有 `host` 头,h2 crate 只把 `:authority` 放进
    /// `req.uri()`。旧实现只读 `host` 头,h2c 客户端因此被路由到
    /// `sites.first()`——无论它请求的是哪个域名。
    #[test]
    fn host_resolution_falls_back_to_authority() {
        // h2 形状:无 host 头,authority 在 URI 里。
        let h2_req = http::Request::builder()
            .uri(uri_with_authority("a.test:443"))
            .body(())
            .unwrap();
        assert_eq!(
            request_host(h2_req.headers(), h2_req.uri()).as_deref(),
            Some("a.test:443")
        );
        assert_eq!(strip_port("a.test:443"), "a.test");
    }

    /// HTTP/1.1 形状:host 头优先,URI 的 authority 不应覆盖它。
    #[test]
    fn host_header_wins_over_authority() {
        let req = http::Request::builder()
            .uri(uri_with_authority("from-uri"))
            .header(HOST, "from-header")
            .body(())
            .unwrap();
        assert_eq!(
            request_host(req.headers(), req.uri()).as_deref(),
            Some("from-header")
        );
    }

    /// h2c prior-knowledge 场景:uri 带方括号 IPv6 authority 时去端口后
    /// 应得到地址本体(方括号一并去掉,与 HTTP/1.1 路径一致)。
    #[test]
    fn host_resolution_handles_ipv6_authority() {
        let uri: http::Uri = "http://[2001:db8::1]:8080/x".parse().unwrap();
        let h = request_host(&HeaderMap::new(), &uri).unwrap();
        assert_eq!(strip_port(&h), "2001:db8::1");
    }
}
