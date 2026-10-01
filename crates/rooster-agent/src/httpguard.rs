//! http-guard:80 / 443 反向代理运行时。
//!
//! - 按 `server_names`(Host / SNI)路由到站点;每站点一个
//!   `upstream` 与 `tls.mode`(passthrough | terminate)。
//! - 透传:443 单监听先窥探 ClientHello(`peek` 模块,不消费),
//!   解析 SNI / JA4 后只做 L4 规则(Geo、JA4 黑名单、key=ip 限速),
//!   可向上游发 PROXY protocol v1/v2,字节原样双向拷贝。
//! - 终止:站点 PEM 证书 rustls 终止,ALPN h2 + http/1.1,
//!   hyper 自动协商;支持 WebSocket 升级(101 隧道);向上游追加
//!   `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto`;可信代理
//!   CIDR 决定真实 IP;ACME HTTP-01 challenge 在 80 端口优先应答
//!   (`set_challenge` 注册表)。
//! - WAF / 限速:WAF 通过 [`RequestInspector`] 接入(rooster-waf
//!   由主会话桥接),body 只检测前 `body_limit`(默认 128 KiB)字节;
//!   令牌桶限速 key = ip / ip+path / header:<name>,超限 429,持续超限
//!   升级 Ban(ban_hook,ttl 10 分钟)。
//! - 80 端口默认直接反代,`redirect_https` 站点开关控制 301。
//!
//! 热重载模型(与 forward 同思路):监听任务只持有 `Arc<Shared>`,
//! 每条 accept 的连接取一次 `Arc<Effective>` 快照,配置变化整体换
//! `Arc`,**不需要重启 listener**,已建立连接按旧快照自然结束;
//! 只有 bind 地址变化或 sites 从空变非空时才重建监听任务。bind 失败
//! 记日志、保留 down 状态,下次 apply 重试。

mod clienthello;
mod geo;
mod httpsrv;
mod passthrough;
mod peek;
mod realip;
mod settings;
mod throttle;
mod tlsconf;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rooster_config::TlsMode;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// WAF 请求体默认检测上限(超出部分直接放行并打标记)。
pub const DEFAULT_BODY_LIMIT: usize = 128 * 1024;

/// ClientHello 读取超时:防止只连不发的客户端长期占住窥探缓冲。
const HELLO_READ_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// WAF 接入点(主会话桥接 rooster-waf;默认放行)

/// WAF 检测接入点:主会话把 rooster-waf 的引擎桥接为该 trait 传入;
/// 未设置时视为放行。异常评分阈值由桥接方(引擎)内部应用,
/// 这里只消费 `blocked` 与命中列表。
pub trait RequestInspector: Send + Sync {
    fn inspect(&self, ctx: InspectCtx<'_>) -> InspectVerdict;
}

/// 一次请求检测的上下文。`headers` 键已小写;`body` 已按
/// `body_limit` 截断。
pub struct InspectCtx<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub headers: &'a [(String, String)],
    pub cookies: &'a [(String, String)],
    pub body: &'a [u8],
}

/// 检测结论:`hits` 为 (rule-id, msg) 列表;`score` 为异常评分;
/// `hit_severities` 与 `hits` 逐项对齐(rooster-waf 严重度权重
/// CRITICAL=5/ERROR=4/WARNING=3/NOTICE=2),供 Block 事件上报。
pub struct InspectVerdict {
    pub blocked: bool,
    pub hits: Vec<(u32, String)>,
    pub hit_severities: Vec<u8>,
    pub score: u32,
}

// ---------------------------------------------------------------------------
// 配置

/// 全量配置(`plugins.http-guard` 与 managed.sites)。
#[derive(Clone, Default)]
pub struct HttpGuardSettings {
    pub listen_http: Option<std::net::SocketAddr>,
    pub listen_https: Option<std::net::SocketAddr>,
    pub sites: Vec<rooster_config::Site>,
    /// CIDR 列表;前置代理可信时从 XFF 取真实 IP。
    pub trusted_proxies: Vec<String>,
    /// mmdb 路径;None 或加载失败 → geo 规则跳过。
    pub geoip_db: Option<std::path::PathBuf>,
    /// 默认 [`DEFAULT_BODY_LIMIT`];0 → 用默认。
    pub body_limit: usize,
    /// 持续超限升级 Ban 时回调(封禁由主会话的封禁管理器执行)。
    pub ban_hook: Option<Arc<dyn Fn(&str, std::time::Duration) + Send + Sync>>,
}

// Arc<dyn Fn> 无法 derive(Debug),手工实现保持 API 形态。
impl fmt::Debug for HttpGuardSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpGuardSettings")
            .field("listen_http", &self.listen_http)
            .field("listen_https", &self.listen_https)
            .field("sites", &self.sites)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("geoip_db", &self.geoip_db)
            .field("body_limit", &self.body_limit)
            .field("ban_hook", &self.ban_hook.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 运行时

/// 一个 listener 的登记项。
struct ListenerSlot {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

pub(crate) struct Shared {
    /// 当前一代生效配置;None = 未配置 / 已 shutdown。
    pub(crate) eff: std::sync::RwLock<Option<Arc<settings::Effective>>>,
    /// ACME HTTP-01:token → key authorization。
    pub(crate) challenges: Mutex<HashMap<String, String>>,
    /// WAF 桥接(可运行时注入/替换,主会话在装配时设置)。
    pub(crate) inspector: std::sync::RwLock<Option<Arc<dyn RequestInspector>>>,
    /// WASM 插件运行时(on_http_request_headers 挂钩)。
    pub(crate) wasm: std::sync::RwLock<Option<Arc<crate::wasmrt::WasmRuntime>>>,
    /// 事件 sink(B5):WAF 拦截等事件由此进入节点事件流;
    /// 未注入(独立测试)时仅记日志,不产生事件。
    pub(crate) event_sink: std::sync::RwLock<Option<Arc<dyn Fn(rooster_proto::Event) + Send + Sync>>>,
    pub(crate) http_slot: Mutex<Option<ListenerSlot>>,
    pub(crate) https_slot: Mutex<Option<ListenerSlot>>,
    /// 站点统计:id → 计数器(跨 apply 保留,见 settings::gc_stats)。
    pub(crate) stats: Mutex<HashMap<String, Arc<settings::SiteStats>>>,
    /// 串行化 apply / shutdown 的整段 diff 流程。用 Semaphore(1) 而非
    /// Mutex:permit 跨 await 持有是 tokio 语义,且避开 lock-guard 静态
    /// 规则的误报(该规则按 std 锁的阻塞语义建模,在此不成立)。
    gate: tokio::sync::Semaphore,
}

/// http-guard 运行时句柄;内部 `Arc`,可跨任务共享。
pub struct HttpGuardRuntime {
    inner: Arc<Shared>,
}

impl HttpGuardRuntime {
    pub fn new(inspector: Option<Arc<dyn RequestInspector>>) -> Self {
        Self {
            inner: Arc::new(Shared {
                eff: std::sync::RwLock::new(None),
                challenges: Mutex::new(HashMap::new()),
                inspector: std::sync::RwLock::new(inspector),
                wasm: std::sync::RwLock::new(None),
                event_sink: std::sync::RwLock::new(None),
                http_slot: Mutex::new(None),
                https_slot: Mutex::new(None),
                stats: Mutex::new(HashMap::new()),
                gate: tokio::sync::Semaphore::new(1),
            }),
        }
    }

    /// 全量应用(增量 diff listener);未启用或 sites 为空不监听。
    ///
    /// - 解析全部站点 / 限速规则 / 证书 / GeoIP 库,整体换成新的
    ///   `Arc<Effective>`(监听任务按连接取快照,无需重启)。
    /// - listener 仅在 bind 地址变化、或监听开关变化时重建;bind 冲突
    ///   记日志保持 down,下次 apply 重试。
    pub async fn apply(&self, cfg: HttpGuardSettings) {
        // 故意持 permit 跨越整个 body:这是配置 apply 的串行化闸门,
        // 并发的热重载必须互斥(重建 stats、重绑 listener、换 eff 快照)。
        // 真正的数据锁(`eff` / `inspector`)都在各自的小作用域内释放。
        let _serial = self
            .inner
            .gate
            .acquire()
            .await
            .expect("gate semaphore never closed");
        let eff = settings::build(&cfg, &self.inner.stats);
        let sites_empty = eff.sites.is_empty();
        {
            let mut guard = self.inner.eff.write().unwrap();
            *guard = Some(eff.clone());
        }
        settings::gc_stats(&self.inner.stats, &eff.sites);

        let want_http = if sites_empty {
            None
        } else {
            cfg.listen_http
        };
        let want_https = if sites_empty {
            None
        } else {
            cfg.listen_https
        };
        self.reconcile_listener(&self.inner.http_slot, want_http, ListenerKind::Http)
            .await;
        self.reconcile_listener(&self.inner.https_slot, want_https, ListenerKind::Https)
            .await;
    }

    /// 每站点统计:{id, requests, blocked, conns_passthrough, bytes_in,
    /// bytes_out, listening_http, listening_https}(后两项为全局监听状态,
    /// 便于面板看到 bind 失败的 down 状态)。
    pub fn stats(&self) -> Vec<serde_json::Value> {
        let listening_http = self
            .inner
            .http_slot
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| !l.handle.is_finished())
            .unwrap_or(false);
        let listening_https = self
            .inner
            .https_slot
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| !l.handle.is_finished())
            .unwrap_or(false);
        let stats = self.inner.stats.lock().unwrap();
        let mut out: Vec<serde_json::Value> = stats
            .iter()
            .map(|(id, s)| {
                serde_json::json!({
                    "id": id,
                    "requests": s.requests.load(Ordering::Relaxed),
                    "blocked": s.blocked.load(Ordering::Relaxed),
                    "conns_passthrough": s.conns_passthrough.load(Ordering::Relaxed),
                    "bytes_in": s.bytes_in.load(Ordering::Relaxed),
                    "bytes_out": s.bytes_out.load(Ordering::Relaxed),
                    "listening_http": listening_http,
                    "listening_https": listening_https,
                })
            })
            .collect();
        out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        out
    }

    /// ACME HTTP-01:注册 token → key authorization,80 端口
    /// `/.well-known/acme-challenge/<token>` 即答。
    pub fn set_challenge(&self, token: String, key_auth: String) {
        self.inner
            .challenges
            .lock()
            .unwrap()
            .insert(token, key_auth);
    }

    /// 撤销全部挑战应答(订单完结或失败后调用,避免残留旧 token)。
    pub fn clear_challenges(&self) {
        self.inner.challenges.lock().unwrap().clear();
    }

    /// 注入/替换 WAF 桥接(AgentState 先于规则集构建,运行时后注入)。
    /// 注入 WASM 插件运行时。
    pub fn set_wasm(&self, wasm: Arc<crate::wasmrt::WasmRuntime>) {
        *self.inner.wasm.write().unwrap() = Some(wasm);
    }

    pub fn set_inspector(&self, inspector: Arc<dyn RequestInspector>) {
        *self.inner.inspector.write().unwrap() = Some(inspector);
    }

    /// 注入事件 sink(B5):拦截/封禁类事件由此进节点事件流,
    /// hub 联动策略才有数据可消费。
    pub fn set_event_sink(&self, sink: Arc<dyn Fn(rooster_proto::Event) + Send + Sync>) {
        *self.inner.event_sink.write().unwrap() = Some(sink);
    }

    /// 停止全部 accept;已建立连接(含透传 / WebSocket 隧道)由独立
    /// 任务持有快照,自然排空(与 forward 同思路)。
    pub async fn shutdown(&self) {
        let _serial = self.inner.gate.acquire().await.expect("gate semaphore never closed");
        *self.inner.eff.write().unwrap() = None;
        for slot in [&self.inner.http_slot, &self.inner.https_slot] {
            let old = slot.lock().unwrap().take();
            if let Some(l) = old {
                l.handle.abort();
                let _ = l.handle.await;
            }
        }
    }

    async fn reconcile_listener(
        &self,
        slot: &Mutex<Option<ListenerSlot>>,
        want: Option<SocketAddr>,
        kind: ListenerKind,
    ) {
        let cur = slot.lock().unwrap().as_ref().map(|l| l.addr);
        if cur == want {
            return;
        }
        let old = slot.lock().unwrap().take();
        if let Some(old) = old {
            tracing::info!(kind = ?kind, addr = %old.addr, "http-guard listener closing");
            old.handle.abort();
            let _ = old.handle.await;
        }
        let Some(addr) = want else { return };
        match TcpListener::bind(addr).await {
            Ok(l) => {
                let actual = l.local_addr().unwrap_or(addr);
                let handle = match kind {
                    ListenerKind::Http => {
                        tokio::spawn(http_accept_loop(self.inner.clone(), l))
                    }
                    ListenerKind::Https => {
                        tokio::spawn(https_accept_loop(self.inner.clone(), l))
                    }
                };
                *slot.lock().unwrap() = Some(ListenerSlot {
                    addr: actual,
                    handle,
                });
                tracing::info!(kind = ?kind, listen = %actual, "http-guard listening");
            }
            Err(e) => {
                tracing::error!(
                    kind = ?kind,
                    listen = %addr,
                    error = %e,
                    "http-guard bind failed; kept as down until next apply"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerKind {
    Http,
    Https,
}

/// 取当前一代配置快照(None = 未启用)。
fn snapshot(inner: &Shared) -> Option<Arc<settings::Effective>> {
    inner.eff.read().unwrap().clone()
}

// ---------------------------------------------------------------------------
// 80 端口:明文 HTTP

async fn http_accept_loop(inner: Arc<Shared>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(eff) = snapshot(&inner) else { return };
                let inner2 = inner.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    httpsrv::serve_plain(inner2, eff, stream, peer).await;
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "http accept error");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 443 端口:TLS 窥探 → 透传 / 终止

async fn https_accept_loop(inner: Arc<Shared>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(eff) = snapshot(&inner) else { return };
                let inner2 = inner.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    handle_tls_conn(inner2, eff, stream, peer).await;
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "https accept error");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_tls_conn(
    inner: Arc<Shared>,
    eff: Arc<settings::Effective>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) {
    let mut ps = peek::PeekStream::new(stream);
    // 窥探 ClientHello:不消费字节,解析失败也保留缓冲原样重放。
    let mut hello = None;
    loop {
        match clienthello::try_parse(ps.buffer()) {
            clienthello::HelloParse::Done(h) => {
                hello = h;
                break;
            }
            clienthello::HelloParse::NeedMore => {
                if ps.buffer().len() >= clienthello::MAX_HELLO_BUF {
                    tracing::debug!(peer = %peer, "client hello too large; giving up peek");
                    break;
                }
                match tokio::time::timeout(HELLO_READ_TIMEOUT, ps.fill()).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) => {}
                }
            }
        }
    }

    // SNI 路由;无 SNI → 第一个站点。
    let sni = hello.as_ref().and_then(|h| h.sni.clone());
    let Some(site) = eff.route(sni.as_deref()) else {
        tracing::debug!(peer = %peer, "no site for tls connection; rejecting");
        return;
    };

    match site.cfg.tls.mode {
        TlsMode::Passthrough => {
            passthrough::handle(eff, site, hello, ps, peer).await;
        }
        TlsMode::Terminate => {
            let Some(server_cfg) = site.tls_server.clone() else {
                // 证书不可用:握手直接拒绝(加载失败已在 apply 时告警)。
                tracing::warn!(site = %site.cfg.id, peer = %peer, "tls terminate without valid cert; refusing handshake");
                return;
            };
            let acceptor = TlsAcceptor::from(server_cfg);
            match acceptor.accept(ps).await {
                Ok(tls_stream) => {
                    httpsrv::serve_tls(inner, eff, site, tls_stream, peer).await;
                }
                Err(e) => {
                    tracing::debug!(site = %site.cfg.id, peer = %peer, error = %e, "tls handshake failed");
                }
            }
        }
    }
}
