//! 端口转发运行时。
//!
//! - TCP / UDP / tcp+udp 双向转发,`listen → target`,target 的
//!   host 可以是域名,按 TTL 缓存并在过期后重新解析(见 [`dns::DnsCache`])。
//! - UDP 按「客户端地址」维护会话,空闲超时可配(默认 60s),
//!   超时会话由 sweeper 回收(见 [`udp`])。
//! - 向上游发送 PROXY protocol v1/v2,或接收前置 LB 发来的
//!   PROXY 头并以头部中的真实源地址做 ACL / 限速(见 [`proxy_proto`])。
//! - 每条规则可挂 CIDR ACL、每 IP 连接速率滑窗与并发上限(见 [`limit`])。
//! - 每条规则的字节数 / 连接数 / 当前并发实时统计([`ForwardStats`])。
//! - 规则增、删、改热生效:只 abort 对应规则的 accept 任务,
//!   已建立的连接由独立任务持有 `Arc<RuleState>` 自然结束,统计保留到排空。
//!
//! 并发模型:registry 用 std `Mutex` 做短临界区(不跨 await);
//! `apply`/`shutdown` 的整个 diff → 停旧 → bind 新流程由 `apply_lock`
//! (tokio Mutex)串行化;每个 accept 循环、每个 TCP 连接、每个 UDP 会话
//! 读端都是独立 tokio task,accept 循环本身即有界,不存在无界 channel。

mod dns;
mod limit;
pub(crate) mod proxy_proto;
mod tcp;
mod udp;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rooster_config::{ForwardProto, ForwardRule, ProxyProtocol};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

/// on_l4_accept 插件面(B6):start_rule 时快照一次,数据面零锁消费;
/// 未注入(无插件/测试)时 accept 路径完全不付费。
pub(crate) struct L4Plugins {
    pub(crate) wasm: Option<Arc<crate::wasmrt::WasmRuntime>>,
    /// Ban 复用的封禁钩子(与 http-guard ban_hook 同一执行面)。
    pub(crate) ban_hook:
        Option<Arc<dyn Fn(&str, Duration) + Send + Sync>>,
}

impl Clone for L4Plugins {
    fn clone(&self) -> Self {
        Self {
            wasm: self.wasm.clone(),
            ban_hook: self.ban_hook.clone(),
        }
    }
}

/// 每条规则的运行时状态:计数器 + 限流器 + accept 任务句柄。
/// 连接任务持有 `Arc<RuleState>`,规则被删除 / 替换后依然存活,
/// 直到连接自然结束。
pub(crate) struct RuleState {
    pub(crate) id: String,
    /// 规则的规范化快照(含解析后的 target / ACL),用于热重载 diff。
    pub(crate) snapshot: RuleSnapshot,
    /// 数据面配置(连接任务实际使用的一份)。
    pub(crate) cfg: RuleCfg,
    pub(crate) listening: AtomicBool,
    /// 已从 registry 摘除(删除或被新版本替换),等待连接排空。
    pub(crate) retired: AtomicBool,
    pub(crate) conns_total: AtomicU64Wrapper,
    pub(crate) conns_active: AtomicU64Wrapper,
    /// UDP 当前会话数(TcpUdp 规则与 TCP 并发分开统计)。
    pub(crate) udp_sessions: AtomicU64Wrapper,
    /// 客户端 → 上游字节数。
    pub(crate) bytes_in: Arc<AtomicU64Wrapper>,
    /// 上游 → 客户端字节数。
    pub(crate) bytes_out: Arc<AtomicU64Wrapper>,
    /// 每 IP 滑窗限速 + 并发计数(TCP 连接与 UDP 会话共用)。
    pub(crate) limiter: Mutex<limit::PerIpLimiter>,
    /// 本规则的 accept 任务(TCP 一个,UDP 一个,TcpUdp 两个)。
    pub(crate) accept_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// 统一用 `Arc<AtomicU64>` 便于计数适配器(tcp 模块)只持计数器不持规则。
pub(crate) type AtomicU64Wrapper = std::sync::atomic::AtomicU64;

/// 数据面配置:从 `ForwardRule` 解析出的可直接使用的形式。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RuleCfg {
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    /// 发往上游的 PROXY protocol。
    pub(crate) proxy_protocol: ProxyProtocol,
    /// 接收客户端 PROXY 头并以真实源地址做 ACL / 限速。
    pub(crate) accept_proxy_protocol: bool,
    /// 空列表表示放行所有。
    pub(crate) acl: Vec<ipnet::IpNet>,
    /// 默认 60s。
    pub(crate) udp_idle_timeout: Duration,
}

/// 规则规范化快照:任一字段变化都视为「修改」,需要重建 listener。
/// `ForwardRule` 未实现 `PartialEq`,这里逐字段比较(等价于比较序列化值)。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RuleSnapshot {
    pub(crate) proto: ForwardProto,
    pub(crate) listen: SocketAddr,
    pub(crate) cfg: RuleCfg,
    pub(crate) conn_rate: Option<(u32, Duration)>,
    pub(crate) max_conns_per_ip: Option<u32>,
}

impl RuleSnapshot {
    /// 解析 `host:port`(支持 IPv6 `[::1]:53` 括号形式)。
    fn parse_target(target: &str) -> Result<(String, u16), String> {
        let s = target.trim();
        if let Some(rest) = s.strip_prefix('[') {
            // IPv6 字面量必须带括号
            let (host, tail) = rest
                .split_once(']')
                .ok_or_else(|| format!("unterminated IPv6 bracket in target {target:?}"))?;
            let port = tail
                .strip_prefix(':')
                .ok_or_else(|| format!("missing port in target {target:?}"))?
                .parse::<u16>()
                .map_err(|_| format!("bad port in target {target:?}"))?;
            Ok((host.to_string(), port))
        } else {
            let (host, port) = s
                .rsplit_once(':')
                .ok_or_else(|| format!("missing port in target {target:?}"))?;
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("bad port in target {target:?}"))?;
            if host.is_empty() {
                return Err(format!("empty host in target {target:?}"));
            }
            Ok((host.to_string(), port))
        }
    }

    fn from_rule(rule: &ForwardRule) -> Result<Self, String> {
        let (target_host, target_port) = Self::parse_target(&rule.target)?;
        let mut acl = Vec::new();
        if let Some(a) = rule.acl.as_ref() {
            for cidr in &a.allow {
                let net: ipnet::IpNet = cidr
                    .parse()
                    .map_err(|_| format!("invalid acl cidr {cidr:?}"))?;
                acl.push(net);
            }
        }
        let conn_rate = rule
            .limits
            .as_ref()
            .and_then(|l| l.conn_rate.as_deref())
            .and_then(limit::parse_rate);
        let max_conns_per_ip = rule.limits.as_ref().and_then(|l| l.max_conns_per_ip);
        Ok(Self {
            proto: rule.proto,
            listen: rule.listen,
            cfg: RuleCfg {
                target_host,
                target_port,
                proxy_protocol: rule.proxy_protocol,
                accept_proxy_protocol: rule.accept_proxy_protocol.unwrap_or(false),
                acl,
                udp_idle_timeout: rule.udp_idle_timeout.unwrap_or(DEFAULT_UDP_IDLE),
            },
            conn_rate,
            max_conns_per_ip,
        })
    }
}

/// UDP 会话默认空闲超时。
const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

impl RuleState {
    fn new(id: String, snapshot: RuleSnapshot) -> Self {
        let limiter = Mutex::new(limit::PerIpLimiter::new(
            snapshot.conn_rate,
            snapshot.max_conns_per_ip,
        ));
        Self {
            id,
            cfg: snapshot.cfg.clone(),
            snapshot,
            listening: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            conns_total: Default::default(),
            conns_active: Default::default(),
            udp_sessions: Default::default(),
            bytes_in: Arc::new(Default::default()),
            bytes_out: Arc::new(Default::default()),
            limiter,
            accept_handles: Mutex::new(Vec::new()),
        }
    }

    /// 停止 accept(abort 并等待任务退出,确保监听 socket 已关闭),
    /// 不触碰任何连接任务。
    async fn stop_accept(&self) {
        self.retired.store(true, Ordering::SeqCst);
        self.listening.store(false, Ordering::SeqCst);
        let handles: Vec<_> = self.accept_handles.lock().unwrap().drain(..).collect();
        for h in handles {
            h.abort();
            // 等待任务真正退出:listener 的 Drop 在此刻完成,
            // 同端口的「修改后重建」才能立刻重新 bind。
            let _ = h.await;
        }
    }

    /// 已删除规则是否已排空(连接自然结束 + UDP 会话回收)。
    fn drained(&self) -> bool {
        self.conns_active.load(Ordering::Relaxed) == 0
            && self.udp_sessions.load(Ordering::Relaxed) == 0
    }
}

struct Registry {
    /// 当前生效规则:id → state。
    active: HashMap<String, Arc<RuleState>>,
    /// 已删除 / 被替换但仍有存活连接的旧 state;stats 保留到排空。
    retired: Vec<Arc<RuleState>>,
}

struct RuntimeInner {
    registry: Mutex<Registry>,
    /// 串行化 apply / shutdown 的「diff → 停旧 → bind 新」整段流程。
    apply_lock: AsyncMutex<()>,
    dns: Arc<dns::DnsCache>,
    /// B6:on_l4_accept 插件与封禁钩子(主会话注入,快照进监听任务)。
    plugins: Mutex<L4Plugins>,
}

/// 端口转发运行时句柄;clone 语义由内部 `Arc` 提供。
pub struct ForwardRuntime {
    inner: Arc<RuntimeInner>,
}

impl Default for ForwardRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardRuntime {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                registry: Mutex::new(Registry {
                    active: HashMap::new(),
                    retired: Vec::new(),
                }),
                apply_lock: AsyncMutex::new(()),
                dns: Arc::new(dns::DnsCache::new()),
                plugins: Mutex::new(L4Plugins { wasm: None, ban_hook: None }),
            }),
        }
    }

    /// 注入 on_l4_accept 插件运行时与封禁钩子(B6)。只影响之后 start_rule
    /// 启动的监听任务(快照式);主会话在首次 reconfigure 前注入。
    pub fn set_plugins(
        &self,
        wasm: Arc<crate::wasmrt::WasmRuntime>,
        ban_hook: Option<Arc<dyn Fn(&str, Duration) + Send + Sync>>,
    ) {
        *self.inner.plugins.lock().unwrap() = L4Plugins {
            wasm: Some(wasm),
            ban_hook,
        };
    }

    /// 全量增量应用:新增规则 bind;删除/修改规则停止 accept,
    /// 已建立连接保留至自然结束。
    /// 修改 = listen/proto/proxy-protocol/accept-pp/acl/limits/target
    /// 任一变化则重建 listener。跳过 `disabled: true` 的规则(视为不存在)。
    pub async fn apply(&self, rules: Vec<ForwardRule>) {
        let _serial = self.inner.apply_lock.lock().await;

        // 规范化:disabled 视为不存在(local 层可屏蔽模板同名项)。
        let mut desired: HashMap<String, (ForwardRule, RuleSnapshot)> = HashMap::new();
        for r in rules {
            if r.disabled.unwrap_or(false) {
                continue;
            }
            match RuleSnapshot::from_rule(&r) {
                Ok(snap) => {
                    desired.insert(r.id.clone(), (r, snap));
                }
                Err(e) => {
                    // 配置非法:整个规则忽略并记日志(校验层应已拦截)。
                    tracing::warn!(rule = %r.id, error = %e, "invalid forward rule, skipping");
                }
            }
        }

        // diff:删除项与修改项都要停掉旧 accept。
        let mut to_stop: Vec<Arc<RuleState>> = Vec::new();
        {
            let mut reg = self.inner.registry.lock().unwrap();
            let ids: Vec<String> = reg.active.keys().cloned().collect();
            for id in ids {
                let replace = match desired.get(&id) {
                    None => true,
                    Some((_, snap)) => *snap != reg.active[&id].snapshot,
                };
                if replace {
                    to_stop.push(reg.active.remove(&id).expect("key just checked"));
                }
            }
        }

        // 停旧:abort accept(等待退出),标记 retired;已排空的直接丢弃。
        for st in to_stop {
            tracing::info!(rule = %st.id, "forward rule removed/changed, stopping accept");
            st.stop_accept().await;
            if !st.drained() {
                self.inner.registry.lock().unwrap().retired.push(st);
            }
        }

        // 增新:bind 成功才置 listening;bind 失败保留条目(listing=false),
        // 面板能看到该规则处于 down 状态,修复配置后下次 apply 重建。
        for (id, (rule, snap)) in &desired {
            if self
                .inner
                .registry
                .lock()
                .unwrap()
                .active
                .contains_key(id)
            {
                continue; // 未变化的规则
            }
            let state = self.start_rule(rule, snap).await;
            self.inner
                .registry
                .lock()
                .unwrap()
                .active
                .insert(id.clone(), state);
        }
    }

    /// bind 并 spawn 本规则的 accept 任务(按 proto 可能是 TCP + UDP 两个)。
    async fn start_rule(&self, rule: &ForwardRule, snap: &RuleSnapshot) -> Arc<RuleState> {
        let state = Arc::new(RuleState::new(rule.id.clone(), snap.clone()));
        // B6:插件面快照一次,连接路径不再回看 registry 锁。
        let l4 = Arc::new(self.inner.plugins.lock().unwrap().clone());
        let mut wanted = 0usize;
        let mut bound = 0usize;
        match snap.proto {
            ForwardProto::Tcp | ForwardProto::TcpUdp => {
                wanted += 1;
                match TcpListener::bind(snap.listen).await {
                    Ok(l) => {
                        bound += 1;
                        let h = tokio::spawn(tcp::accept_loop(
                            state.clone(),
                            self.inner.dns.clone(),
                            l,
                            l4.clone(),
                        ));
                        state.accept_handles.lock().unwrap().push(h);
                        tracing::info!(
                            rule = %rule.id,
                            listen = %snap.listen,
                            target = %rule.target,
                            "tcp forward listening"
                        );
                    }
                    Err(e) => tracing::error!(
                        rule = %rule.id,
                        listen = %snap.listen,
                        error = %e,
                        "forward tcp bind failed; rule kept as down"
                    ),
                }
            }
            ForwardProto::Udp => {}
        }
        match snap.proto {
            ForwardProto::Udp | ForwardProto::TcpUdp => {
                wanted += 1;
                match tokio::net::UdpSocket::bind(snap.listen).await {
                    Ok(s) => {
                        bound += 1;
                        let h = tokio::spawn(udp::run(
                            state.clone(),
                            self.inner.dns.clone(),
                            s,
                        ));
                        state.accept_handles.lock().unwrap().push(h);
                        tracing::info!(
                            rule = %rule.id,
                            listen = %snap.listen,
                            target = %rule.target,
                            "udp forward listening"
                        );
                    }
                    Err(e) => tracing::error!(
                        rule = %rule.id,
                        listen = %snap.listen,
                        error = %e,
                        "forward udp bind failed; rule kept as down"
                    ),
                }
            }
            ForwardProto::Tcp => {}
        }
        state
            .listening
            .store(wanted > 0 && bound == wanted, Ordering::SeqCst);
        state
    }

    pub fn stats(&self) -> Vec<ForwardStats> {
        let mut reg = self.inner.registry.lock().unwrap();
        let mut out: Vec<ForwardStats> = reg.active.values().map(|s| stats_of(s)).collect();
        // 被删规则的统计保留到连接排空,之后回收。
        reg.retired.retain(|s| !s.drained());
        out.extend(reg.retired.iter().map(|s| stats_of(s)));
        out
    }

    /// 停止全部 accept 并关闭全部监听;已有连接自然结束(不强断)。
    pub async fn shutdown(&self) {
        let _serial = self.inner.apply_lock.lock().await;
        let stopped: Vec<Arc<RuleState>> = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.active.drain().map(|(_, v)| v).collect()
        };
        for st in stopped {
            tracing::info!(rule = %st.id, "forward runtime shutdown: stopping accept");
            st.stop_accept().await;
            let mut reg = self.inner.registry.lock().unwrap();
            if !st.drained() {
                reg.retired.push(st);
            }
        }
    }
}

fn stats_of(s: &RuleState) -> ForwardStats {
    ForwardStats {
        id: s.id.clone(),
        proto: match s.snapshot.proto {
            ForwardProto::Tcp => "tcp",
            ForwardProto::Udp => "udp",
            ForwardProto::TcpUdp => "tcp+udp",
        }
        .to_string(),
        listening: s.listening.load(Ordering::Relaxed),
        conns_total: s.conns_total.load(Ordering::Relaxed),
        conns_active: s.conns_active.load(Ordering::Relaxed),
        udp_sessions: s.udp_sessions.load(Ordering::Relaxed),
        bytes_in: s.bytes_in.load(Ordering::Relaxed),
        bytes_out: s.bytes_out.load(Ordering::Relaxed),
    }
}

/// 每条规则的实时统计。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForwardStats {
    pub id: String,
    pub proto: String,
    pub listening: bool,
    /// 已接受的连接总数;UDP 每创建一个会话计一次。
    pub conns_total: u64,
    /// 当前存活的 TCP 连接数。
    pub conns_active: u64,
    /// 当前存活的 UDP 会话数。
    pub udp_sessions: u64,
    /// 客户端 → 上游字节数。
    pub bytes_in: u64,
    /// 上游 → 客户端字节数。
    pub bytes_out: u64,
}
