//! 接线:封禁管理器初始化、管理白名单计算、运行时重配置。
//!
//! `reconfigure` 是所有「生效配置 → 运行时状态」的汇聚点:commit_raw、
//! 热重载 Applied、回滚都会触发(见 `AgentState::runtime_notify`),做三件事:
//! 1. 转发规则增量应用;
//! 2. nftables 白名单全量重算(admin-allowlist + Hub 地址 + 本机地址)
//!    与 ssh-guard 的 L4 限速下发;
//! 3. ssh-guard 任务按配置变化重启(未启用则停止)。

use crate::sshguard::{self, BanSink};
use crate::state::AgentState;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rooster_config::EffectiveConfig;
use rooster_nft::{BanEntry, BanManager, NftBanManager, NftError, NftHandle};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// 封禁引擎状态。不可用时必须带上**具体原因**:否则面板只能看到一个 503,
/// 管理员无从判断是缺 CAP_NET_ADMIN、内核无 nf_tables,还是 `bans.redb` 打不开。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BanStatus {
    pub available: bool,
    pub reason: Option<String>,
}

/// 打开真实封禁管理器(nftables + redb)。无 CAP_NET_ADMIN 或无 nf_tables
/// 时返回 `(None, status)`:转发与管理 API 照常工作,封禁类接口返回 503。
pub fn init(data_dir: &Path) -> (Option<Arc<NftBanManager>>, BanStatus) {
    let handle = match NftHandle::open() {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("nftables unavailable, ban management disabled: {e}");
            return (
                None,
                BanStatus {
                    available: false,
                    reason: Some(format!("nftables unavailable: {e}")),
                },
            );
        }
    };
    let db = data_dir.join("bans.redb");
    match NftBanManager::new(handle, &db) {
        Ok(m) => {
            tracing::info!("ban manager ready (table inet rooster + {})", db.display());
            (
                Some(Arc::new(m)),
                BanStatus {
                    available: true,
                    reason: None,
                },
            )
        }
        Err(e) => {
            tracing::warn!("ban manager init failed, bans disabled: {e}");
            (
                None,
                BanStatus {
                    available: false,
                    reason: Some(format!("ban manager init failed: {e}")),
                },
            )
        }
    }
}

/// 白名单 = `security.admin-allowlist` + Hub 地址 + 全部本机地址。
pub fn compute_allowlist(eff: &EffectiveConfig) -> Vec<IpNet> {
    allowlist_with_sources(eff).into_iter().map(|(net, _)| net).collect()
}

/// 同上,但附来源标签(`admin` / `hub` / `local`)。封禁被拒时管理员需要知道
/// 是哪一条规则、为什么在名单里:自动把 Hub 地址加入名单,而在
/// NAT/portproxy 拓扑下那个地址同时也是客户端的源地址 —— 没有来源标签就
/// 无从解释“这个 IP 为什么封不掉”。
pub fn allowlist_with_sources(eff: &EffectiveConfig) -> Vec<(IpNet, &'static str)> {
    let mut nets: Vec<(IpNet, &'static str)> = Vec::new();
    for cidr in &eff.security.admin_allowlist {
        match cidr.trim().parse::<IpNet>() {
            Ok(n) => push_net(&mut nets, n, "admin"),
            Err(_) => tracing::warn!("admin-allowlist: invalid cidr `{cidr}` skipped"),
        }
    }
    if eff.security.hub_address_exempt {
        if let Some(hub) = &eff.hub {
            if let Some(ip) = resolve_host(&hub.url) {
                push_net(&mut nets, host_net(ip), "hub");
            }
        }
    }
    for ip in local_addrs() {
        push_net(&mut nets, host_net(ip), "local");
    }
    nets
}

fn host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32).expect("prefix 32 valid")),
        IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 128).expect("prefix 128 valid")),
    }
}

/// 去重加入;同一地址已有条目时保留先出现的来源(人工配置优先于自动推导)。
fn push_net(nets: &mut Vec<(IpNet, &'static str)>, net: IpNet, source: &'static str) {
    if !nets.iter().any(|(n, _)| *n == net) {
        nets.push((net, source));
    }
}

/// 从 `wss://hub.example.com:9443/agent/ws` 一类 URL 里取 host 并解析出
/// 一个地址;IP 字面量直接用,域名走一次 getaddrinfo(阻塞,调用方须在
/// spawn_blocking 中)。
fn resolve_host(url: &str) -> Option<IpAddr> {
    let rest = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url);
    let host_port = rest.split(['/', '?']).next().unwrap_or("");
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    use std::net::ToSocketAddrs;
    match (host, 80u16).to_socket_addrs() {
        Ok(mut it) => it.next().map(|sa| sa.ip()),
        Err(e) => {
            tracing::warn!("cannot resolve hub host `{host}` for allowlist: {e}");
            None
        }
    }
}

/// 全部网络接口地址(getifaddrs;本机地址永不封禁)。
fn local_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            tracing::warn!("getifaddrs failed; local addresses missing from allowlist");
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let fam = (*ifa.ifa_addr).sa_family as i32;
                if fam == libc::AF_INET {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    out.push(IpAddr::V4(std::net::Ipv4Addr::from(
                        sa.sin_addr.s_addr.to_be(),
                    )));
                } else if fam == libc::AF_INET6 {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    out.push(IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr)));
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// `Arc<dyn BanManager>` → `Arc<dyn BanSink>` 的适配层(ssh-guard 只依赖
/// 最小封禁面;trait 对象之间不能直接 coerce)。
struct BanManagerSink(Arc<dyn BanManager>);

impl BanSink for BanManagerSink {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError> {
        self.0.apply_ban(entry)
    }
}

/// 生效配置 → 运行时状态;幂等,可反复调用。
pub async fn reconfigure(state: &Arc<AgentState>) {
    let eff = state.effective();

    // 1. 转发规则增量应用(删除规则不影响已有连接)。
    state.forwards.apply(eff.forwards.clone()).await;

    // 2. nftables 侧:白名单 + ssh L4 限速(阻塞操作放线程池)。
    // 先 clone 再判断:RwLockReadGuard 不能跨 await 存活。
    let bans = state.bans.read().unwrap().clone();
    if bans.is_none() {
        // 启动时不可用不代表现在仍不可用:管理员可能刚补上 capability 或
        // `modprobe nf_tables`。每次重配置重试一次,自愈合且状态随之刷新。
        let data_dir = eff.agent.data_dir();
        let (mgr, status) = tokio::task::spawn_blocking(move || init(&data_dir))
            .await
            .unwrap_or_else(|_| (None, BanStatus { available: false, reason: Some("ban probe panicked".into()) }));
        let recovered = mgr.is_some();
        *state.bans.write().unwrap() = mgr.map(|m| m as Arc<dyn BanManager>);
        *state.ban_status.write().unwrap() = status;
        if recovered {
            tracing::info!("ban manager became available, ban APIs re-enabled");
        }
    }
    let bans = state.bans.read().unwrap().clone();
    if let Some(bans) = bans {
        let eff2 = eff.clone();
        let nets = tokio::task::spawn_blocking(move || compute_allowlist(&eff2))
            .await
            .unwrap_or_default();
        if let Err(e) = bans.set_allowlist(&nets) {
            tracing::error!("failed to sync admin allowlist into nftables: {e}");
        }
        let ssh = &eff.plugins.ssh_guard;
        if ssh.enabled {
            if let Err(e) = bans.set_ssh_limit(ssh.port, &ssh.conn_rate, ssh.conn_burst) {
                tracing::warn!("ssh l4 rate limit not applied: {e}");
            }
        }
    }

    // 3. ssh-guard:配置变化重启;未启用停止。
    ensure_sshguard(state, &eff).await;

    // 4. L4 加固:蜜罐/扫描/限速/flag 规则下发 + 命中提升器(全部 opt-in)。
    crate::hardening::ensure(state, &eff).await;

    // 5. http-guard:80/443 反代 + WAF 规则集热重建。
    ensure_httpguard(state, &eff).await;
}

async fn ensure_sshguard(state: &Arc<AgentState>, eff: &EffectiveConfig) {
    let cfg_json = serde_json::to_value(&eff.plugins.ssh_guard).ok();
    let changed = {
        let cur = state.sshguard_cfg.lock().unwrap();
        *cur != cfg_json
    };
    if !changed {
        return;
    }
    // 停旧任务(若在运行);JoinHandle abort 不影响已发出的封禁。
    if let Some(task) = state.sshguard_task.lock().unwrap().take() {
        task.abort();
        tracing::info!("ssh-guard stopped for reconfiguration");
    }
    *state.sshguard_cfg.lock().unwrap() = cfg_json;

    if !eff.plugins.ssh_guard.enabled {
        return;
    }
    let Some(bans) = state.bans.read().unwrap().clone() else {
        // 只记一次:配置未变时不会重复进入这里。
        tracing::error!(
            "ssh-guard enabled but nftables ban manager unavailable; \
             log-based protection inactive (L4 rate limit also inactive)"
        );
        return;
    };
    let Some(events) = state.events_tx.lock().unwrap().clone() else {
        return;
    };
    let node = eff
        .agent
        .node_name
        .clone()
        .unwrap_or_else(|| "unknown-node".to_string());
    let handle = sshguard::spawn(
        eff.plugins.ssh_guard.clone(),
        node,
        Arc::new(BanManagerSink(bans)),
        events,
    );
    *state.sshguard_task.lock().unwrap() = Some(handle);
    tracing::info!("ssh-guard started");
}

pub(crate) async fn ensure_httpguard(state: &Arc<AgentState>, eff: &EffectiveConfig) {
    let data_dir = eff.agent.data_dir();
    let enabled = eff.plugins.http_guard.enabled;

    // WAF 配置变化 → 重建规则集(报告更新到 state)。
    let waf_json = serde_json::to_value(&eff.waf).ok();
    let changed = *state.waf_cfg.lock().unwrap() != waf_json;
    if changed {
        let rules_dir = crate::waf::find_rules_dir(eff, &data_dir);
        let report = state
            .waf
            .rebuild(eff, rules_dir.as_deref());
        *state.waf_report.write().unwrap() = report;
        *state.waf_cfg.lock().unwrap() = waf_json;
    }

    let geo = eff.http_geoip();
    let geoip_db = Some(crate::geoip::db_path(&data_dir, &geo.database))
        .filter(|p| crate::geoip::open_db(p).is_ok());
    // 配了 geo 规则但库不可用时默认不应用:保持上一份生效配置,而不是
    // 让 geo.deny 静默失效。
    if enabled {
        if let Err(e) = crate::geoip::check_available(
            geo.fail_open,
            geoip_db.as_deref(),
            eff.sites.iter().any(|s| s.geo.is_some()),
        ) {
            tracing::error!("{e}; keeping previous http-guard configuration");
            return;
        }
    }

    // CC 防护升级封禁:交由封禁管理器(白名单优先级在其内部保证)。
    let ban_hook = state.bans.read().unwrap().clone().map(|bans| {
        Arc::new(move |ip: &str, ttl: Duration| {
            let entry = crate::bans::manual_ban_entry(ip, ttl.as_secs(), "rate limit escalation", "http-guard");
            match bans.apply_ban(&entry) {
                Ok(()) => tracing::warn!(ip, ttl = ?ttl, "rate limit escalated to ban"),
                Err(e) => tracing::warn!(ip, error = %e, "rate limit ban rejected"),
            }
        }) as Arc<dyn Fn(&str, Duration) + Send + Sync>
    });

    // 未显式配置 cert/key 的 terminate 站点回退到 ACME 缓存。
    // 不在这里回退的话,`tls.acme: true` 的站点即使签发成功也永远握手失败。
    let sites: Vec<_> = eff
        .sites
        .iter()
        .map(|s| {
            let mut s = s.clone();
            if s.tls.cert.is_none() && s.tls.key.is_none() {
                if let Some((cert, key)) = crate::acme::site_cert_paths(&data_dir, &s) {
                    s.tls.cert = Some(cert);
                    s.tls.key = Some(key);
                }
            }
            s
        })
        .collect();

    let settings = crate::httpguard::HttpGuardSettings {
        listen_http: if enabled { eff.plugins.http_guard.listen_http } else { None },
        listen_https: if enabled { eff.plugins.http_guard.listen_https } else { None },
        sites,
        trusted_proxies: eff.plugins.http_guard.trusted_proxies.clone(),
        geoip_db,
        body_limit: 0,
        ban_hook,
        hardening: eff.hardening.clone(),
    };
    state.httpguard.apply(settings).await;
}
pub fn manual_ban_entry(ip: &str, ttl_secs: u64, reason: &str, node: &str) -> BanEntry {
    BanEntry {
        ip: ip.to_string(),
        ttl: Duration::from_secs(ttl_secs.max(1)),
        reason: reason.to_string(),
        plugin: "manual".to_string(),
        node: node.to_string(),
        scope: rooster_nft::BanScope::Local,
        started_at: None,
        expires_at: None,
    }
}

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    fn eff(exempt: Option<bool>) -> EffectiveConfig {
        let yaml = match exempt {
            Some(v) => format!(
                "local:\n  agent:\n    node-name: t\n  hub:\n    url: wss://192.0.2.10:9443/agent/ws\n  security:\n    hub-address-exempt: {}\n",
                v
            ),
            None => "local:\n  agent:\n    node-name: t\n  hub:\n    url: wss://192.0.2.10:9443/agent/ws\n".to_string(),
        };
        let (_file, eff) = rooster_config::parse_and_validate(&yaml).expect("test config parses");
        eff
    }

    /// 默认豁免 Hub 地址;关掉开关后必须只剩本机地址 —— NAT/portproxy
    /// 接入时那个地址同时也是全部客户端的源地址,不关掉就等于封禁整体失效。
    #[test]
    fn hub_address_exempt_defaults_on_and_can_be_disabled() {
        let hub: IpAddr = "192.0.2.10".parse().unwrap();
        let on = allowlist_with_sources(&eff(None));
        assert!(
            on.iter().any(|(n, s)| *s == "hub" && n.addr() == hub),
            "默认应豁免 Hub 地址: {on:?}"
        );
        let off = allowlist_with_sources(&eff(Some(false)));
        assert!(
            !off.iter().any(|(_, s)| *s == "hub"),
            "关闭后不得再出现 hub 来源: {off:?}"
        );
        assert!(
            off.iter().any(|(_, s)| *s == "local"),
            "本机地址豁免与开关无关: {off:?}"
        );
    }
}
