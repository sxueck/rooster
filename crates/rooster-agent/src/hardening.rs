//! L4 加固(docs/hardening-plan.md Batch 1):蜜罐 / 端口扫描检测 / 全局
//! 新建连接限速 / conntrack-invalid 与 TCP flag 异常丢弃。
//!
//! 数据面全部是 `inet rooster` 表里的四条 input 链(见 rooster-nft builders);
//! 内核包路径把命中写进带超时的暂存集(EVAL|TIMEOUT),本模块的**提升器**
//! 轮询 dump 暂存集,把命中经 [`BanManager`] 落地成真正的封禁 —— 白名单拒封、
//! redb 账本、面板事件与集群同步因此全部复用 ssh-guard 的同一条管线。
//! interval set 不支持包路径动态添加,这是必须绕一层用户态的根因。
//!
//! 三类暂存集的消费语义不同:
//! - **蜜罐 / L4 超速**(纯 IP 键):命中即应封,消费后删位防重复报;
//! - **扫描元组**(`saddr . dport` 拼接键):内核只记录「窗口内碰过哪些
//!   端口」,阈值判定(distinct 端口数 ≥ max-hits)在用户态做 —— 内核
//!   计数器数不出 distinct 端口,重复探同一端口不得累计。元组**只读
//!   不删**:元素按 scan 窗口自动过期,删除/重置都会破坏窗口语义,
//!   拼接键也不能当纯 IP 元素删。
//!
//! 所有子项默认关闭:配置里不出现 `hardening` 或子项 `enabled: false` 时,
//! 本模块只做清理(clear_hardening,只删不建),不写任何规则。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rooster_config::schema::{EffectiveConfig, HardeningConfig};
use rooster_nft::builders::{
    HardeningSpec, SET_HP_V4, SET_HP_V6, SET_L4HIT_V4, SET_L4HIT_V6, SET_SCANPORTS_V4,
    SET_SCANPORTS_V6,
};
use rooster_nft::{BanEntry, BanManager, BanScope, NftHandle};
use rooster_proto::Event;
use tokio::sync::mpsc::UnboundedSender;

/// 提升器基础轮询间隔(上限)。蜜罐暂存集 TTL 至少 60s、L4 命中至少
/// 60s,2s 对它们绰绰有余;扫描窗口更短时由 [`promoter_tick`] 收紧到
/// 窗口的一半,保证任一元组在过期前至少被看到一次。
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// 轮询间隔下限:窗口再小也不能退化成忙轮询;校验面已拒绝 <500ms 的
/// find-time,这里只是不变量兜底。
const MIN_TICK: Duration = Duration::from_millis(250);

/// 非路由地址不进封禁:payload 取不到 saddr 的碎片/异常包在内核寄存器里
/// 是 0,dynset 会把 0.0.0.0 写进命中集(VM 实测);回环/组播/广播封了无意义
/// 且脏 redb 账本与集群同步。文档网(TEST-NET 等)同禁,防探针环境误封。
fn promotable(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast()),
    }
}

#[cfg(test)]
mod promotable_tests {
    use super::promotable;

    #[test]
    fn non_routable_and_junk_are_not_promoted() {
        for ip in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "192.0.2.7", "::", "::1", "ff02::1", "not-an-ip"] {
            assert!(!promotable(ip), "{ip} must not be promotable");
        }
        for ip in ["8.8.4.4", "192.168.131.1", "10.1.2.3", "2001:db8::5"] {
            assert!(promotable(ip), "{ip} must be promotable");
        }
    }
}

/// 扫描元组 → 达到 distinct-port 阈值的源 IP(升序,事件顺序确定)。
/// 纯函数,阈值去重/窗口过期语义由单测固定:
/// - 键是 (源 IP, 目的端口):同一端口的重复探测是同一元素,**永远只计
///   1** —— 重复打同一端口不得把源推过阈值;
/// - `remaining_ms == Some(0)` 恰好过期:不计入窗口;
/// - `None`(dump 里没有 timeout 属性):按存活处理,计入。
fn scan_offenders(tuples: &[((IpAddr, u16), Option<u64>)], threshold: u32) -> Vec<IpAddr> {
    let mut per_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for ((ip, port), remaining) in tuples {
        if matches!(remaining, Some(0)) {
            continue; // 恰好过期:窗口外
        }
        per_ip.entry(*ip).or_default().insert(*port);
    }
    let mut out: Vec<IpAddr> = per_ip
        .into_iter()
        .filter(|(_, ports)| ports.len() as u32 >= threshold)
        .map(|(ip, _)| ip)
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod scan_threshold_tests {
    use super::scan_offenders;
    use std::net::IpAddr;

    fn t(ip: &str, port: u16, remaining_ms: Option<u64>) -> ((IpAddr, u16), Option<u64>) {
        ((ip.parse().unwrap(), port), remaining_ms)
    }

    const THRESHOLD: u32 = 5;

    #[test]
    fn same_port_repeats_never_cross_the_threshold() {
        let tuples: Vec<_> = (0..50)
            .map(|rem| t("203.0.113.9", 4444, Some(rem + 1))) // 重复更新同一元组
            .collect();
        assert!(scan_offenders(&tuples, THRESHOLD).is_empty(), "同一端口只计 1");
    }

    #[test]
    fn distinct_ports_at_threshold_promote_but_below_do_not() {
        let below: Vec<_> = (1..THRESHOLD as u16 + 1)
            .take(THRESHOLD as usize - 1)
            .map(|p| t("198.51.100.7", 10_000 + p as u16, Some(9_000)))
            .collect();
        assert!(scan_offenders(&below, THRESHOLD).is_empty(), "阈值之下不封");
        let at: Vec<_> = (0..THRESHOLD as u16)
            .map(|p| t("198.51.100.7", 10_000 + p, Some(9_000)))
            .collect();
        assert_eq!(scan_offenders(&at, THRESHOLD), vec!["198.51.100.7".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn exactly_expired_zero_remaining_is_excluded() {
        // 全部 remaining_ms == 0:窗口已过,不封。
        let expired: Vec<_> = (0..THRESHOLD as u16)
            .map(|p| t("198.51.100.8", 20_000 + p, Some(0)))
            .collect();
        assert!(scan_offenders(&expired, THRESHOLD).is_empty(), "恰好过期不计入");
        // 反向验证:全存活时过阈值,但其中 1 个恰好过期(=0)就把
        // distinct 计数打回阈值之下 —— 0 不是「还活着」。
        let mut mostly_alive = expired.clone();
        for e in mostly_alive.iter_mut() {
            e.1 = Some(9_000);
        }
        assert_eq!(scan_offenders(&mostly_alive, THRESHOLD).len(), 1, "全存活应过阈值");
        mostly_alive[0].1 = Some(0);
        assert!(
            scan_offenders(&mostly_alive, THRESHOLD).is_empty(),
            "恰好过期的端口不计入,5 缺 1 不过阈值"
        );
    }

    #[test]
    fn none_remaining_counts_and_v4_v6_are_independent() {
        // 无 timeout 属性(None)按存活计;v4/v6 各自计数、互不串阈值。
        let v4: Vec<_> = (0..THRESHOLD as u16).map(|p| t("192.0.2.10", 30_000 + p, None)).collect();
        let v6_partial: Vec<_> = (0..THRESHOLD as u16 - 1)
            .map(|p| t("2001:db8::1a", 30_000 + p, Some(5_000)))
            .collect();
        let mut tuples = v4;
        tuples.extend(v6_partial);
        let out = scan_offenders(&tuples, THRESHOLD);
        assert_eq!(out, vec!["192.0.2.10".parse::<IpAddr>().unwrap()], "v6 差一个端口不封");
    }
}

fn honeypot_window(h: &HardeningConfig) -> Duration {
    h.honeypot.as_ref()
        .map(|cfg| cfg.hit_window_or_default())
        .unwrap_or_default()
        .max(Duration::from_secs(60))
}

/// 提升器轮询间隔:基础 2s;扫描/蜜罐窗口更短时收紧到窗口的一半,
/// 保证任一暂存元素在过期前至少被一轮轮询看到。蜜罐 TTL 在
/// [`build_spec`] 钳到 ≥60s,所以只有扫描 find-time 能把间隔压下来。
fn promoter_tick(h: &HardeningConfig) -> Duration {
    let mut tick = POLL_INTERVAL;
    if h.honeypot.as_ref().is_some_and(|c| c.enabled) {
        tick = tick.min(honeypot_window(h) / 2);
    }
    if let Some(pg) = h.port_guard.as_ref().filter(|c| c.enabled) {
        tick = tick.min(pg.find_time_or_default() / 2);
    }
    tick.max(MIN_TICK)
}

#[cfg(test)]
mod tick_tests {
    use super::promoter_tick;
    use rooster_config::schema::{HardeningConfig, PortGuardConfig};
    use std::time::Duration;

    fn cfg(find_time: Option<Duration>) -> HardeningConfig {
        HardeningConfig {
            port_guard: Some(PortGuardConfig {
                enabled: true,
                max_hits: None,
                find_time,
                extra_open_ports: Vec::new(),
                ban_time: None,
            }),
            ..HardeningConfig::default()
        }
    }

    #[test]
    fn tick_is_capped_at_poll_interval_and_halves_short_windows() {
        assert_eq!(promoter_tick(&cfg(None)), Duration::from_secs(2), "默认 60s 窗口 → 2s");
        assert_eq!(
            promoter_tick(&cfg(Some(Duration::from_secs(3)))),
            Duration::from_millis(1500),
            "3s 窗口 → 1.5s"
        );
    }

    #[test]
    fn tick_never_drops_below_the_floor() {
        // 校验面会拒 <500ms 的 find-time;真到了这里也只钳到下限,
        // 不退化成忙轮询。
        assert_eq!(
            promoter_tick(&cfg(Some(Duration::from_millis(1)))),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn honeypot_window_is_clamped_before_halving() {
        // 蜜罐 TTL 钳 60s:配置 10s 窗口也不会把间隔压到 5s。
        let mut c = cfg(None);
        c.honeypot = Some(rooster_config::schema::HoneypotConfig {
            enabled: true,
            ports: None,
            hit_window: Some(Duration::from_secs(10)),
            ban_time: None,
        });
        assert_eq!(promoter_tick(&c), Duration::from_secs(2), "钳后 60s/2=30s > 2s");
        let (spec, _) = super::build_spec(&c, &std::collections::HashSet::new());
        let window = super::honeypot_window(&c);
        let mut cooldown = std::collections::HashMap::new();
        let key = ("203.0.113.8".to_string(), 2222);
        let now = std::time::Instant::now();
        assert!(super::record_honeypot_hit(&mut cooldown, key.clone(), now, window));
        for seconds in [10, 20, 30, 40, 50, 59] {
            assert!(!super::record_honeypot_hit(
                &mut cooldown, key.clone(), now + Duration::from_secs(seconds), window,
            ));
        }
        assert!(super::record_honeypot_hit(
            &mut cooldown, key, now + Duration::from_millis(spec.honeypot_window_ms), window,
        ));
    }
}

/// 一条暂存命中:集合 → 封禁参数(plugin / reason / ttl)。
fn hit_policy(h: &HardeningConfig, set: &'static str) -> Option<(&'static str, String, Duration)> {
    match set {
        SET_HP_V4 | SET_HP_V6 => h.honeypot.as_ref().filter(|c| c.enabled).map(|c| {
            (
                "honeypot",
                "honeypot port hit".to_string(),
                c.ban_time_or_default(),
            )
        }),
        SET_SCANPORTS_V4 | SET_SCANPORTS_V6 => h.port_guard.as_ref().filter(|c| c.enabled).map(|c| {
            (
                "port-guard",
                "port scan (distinct closed-port hits over threshold)".to_string(),
                c.ban_time_or_default(),
            )
        }),
        SET_L4HIT_V4 | SET_L4HIT_V6 => h.conn_limit.as_ref().filter(|c| c.enabled).map(|c| {
            (
                "conn-limit",
                "L4 new-connection rate exceeded".to_string(),
                c.ban_time_or_default(),
            )
        }),
        _ => None,
    }
}

/// 真实监听端口(扫描检测的白名单 + 蜜罐的排除面),配置推导部分。
/// 主机运行时 LISTEN 的端口由 [`ensure`] 在蜜罐/扫描启用时经
/// `rooster_config::listeners::host_listen_tcp_ports` 叠加(读不到就
/// fail-closed,不盲装)。
/// TCP-only:扫描与蜜罐规则只匹配 tcp dport。
pub(crate) fn real_tcp_ports(eff: &EffectiveConfig) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for f in &eff.forwards {
        if f.disabled != Some(true) && f.proto.protocols().contains(&"tcp") {
            ports.insert(f.listen.port());
        }
    }
    if eff.plugins.http_guard.enabled {
        for a in [eff.plugins.http_guard.listen_http, eff.plugins.http_guard.listen_https].into_iter().flatten() {
            ports.insert(a.port());
        }
    }
    // sshd 端口:无论 ssh-guard 是否启用,主机都在监听;management 同理。
    ports.insert(eff.plugins.ssh_guard.port);
    ports.insert(eff.management.listen().port());
    if let Some(m) = eff.management.metrics_listen {
        ports.insert(m.port());
    }
    if let Some(pg) = eff.hardening.port_guard.as_ref().filter(|c| c.enabled) {
        ports.extend(pg.extra_open_ports.iter().copied());
    }
    ports
}

/// hardening 是否启用了任何需要内核数据面的子项。
pub(crate) fn l4_active(h: &HardeningConfig) -> bool {
    h.honeypot.as_ref().is_some_and(|c| c.enabled)
        || h.port_guard.as_ref().is_some_and(|c| c.enabled)
        || h.conn_limit.as_ref().is_some_and(|c| c.enabled)
        || h.flag_guard.as_ref().is_some_and(|c| c.enabled)
}

/// 配置 → nft spec。蜜罐端口再减一次真实监听端口(validate 已拦,双保险:
/// 带病规则会自断服务)。
fn build_spec(h: &HardeningConfig, real: &HashSet<u16>) -> (HardeningSpec, Vec<u16>) {
    let mut spec = HardeningSpec::default();
    let honey: Vec<u16> = match h.honeypot.as_ref().filter(|c| c.enabled) {
        Some(c) => {
            let ports = rooster_config::schema::honeypot_ports_of(c);
            let keep: Vec<u16> = ports
                .into_iter()
                .filter(|p| {
                    if real.contains(p) {
                        tracing::error!(port = p, "honeypot port collides with a real listener; excluded");
                        false
                    } else {
                        true
                    }
                })
                .collect();
            if c.ports.is_none() && keep.is_empty() {
                tracing::warn!("honeypot enabled but every default port is a real listener; inert");
            }
            keep
        }
        None => Vec::new(),
    };
    spec.honey_ports = honey.clone();
    if !honey.is_empty() {
        spec.honeypot_on = true;
        // 暂存集 TTL 下限 60s:提升器最慢 2s 一轮,配置的窗口过短会让
        // 命中在被消费前就过期(等于静默关掉蜜罐)。
        spec.honeypot_window_ms = dur_ms(honeypot_window(h));
    }
    spec.open_ports = real.iter().copied().collect();
    if let Some(pg) = h.port_guard.as_ref().filter(|c| c.enabled) {
        spec.scan_on = true;
        let window = dur_ms(pg.find_time_or_default());
        spec.scan_set_timeout_ms = window;
    }
    if let Some(cl) = h.conn_limit.as_ref().filter(|c| c.enabled) {
        match rooster_nft::builders::parse_rate(cl.rate_or_default()) {
            Ok((n, unit_ms)) => {
                spec.l4_on = true;
                spec.l4_rate = n;
                spec.l4_unit_ms = unit_ms;
                spec.l4_burst = cl.burst_or_default();
                spec.l4_set_timeout_ms = unit_ms.max(60_000);
            }
            Err(e) => tracing::error!(rate = cl.rate_or_default(), "hardening.conn-limit: unparsable rate, feature inert: {e}"),
        }
    }
    spec.flags_on = h.flag_guard.as_ref().is_some_and(|c| c.enabled);
    (spec, honey)
}

fn dur_ms(d: Duration) -> u64 {
    d.as_millis().min(u64::MAX as u128) as u64
}

/// diff 键:hardening 段 + 一切影响 openports 的配置(转发端口、sshd 端口、
/// http-guard 监听、management 端口)。任何一项变了都要重新下发规则。
/// 端口排序后进键:HashSet 迭代序不确定,不排序的话同一份配置每次
/// reconfigure 都会被误判为「已变化」。
fn apply_key(eff: &EffectiveConfig) -> serde_json::Value {
    let mut ports: Vec<u16> = real_tcp_ports(eff).into_iter().collect();
    ports.sort_unstable();
    serde_json::json!({
        "hardening": eff.hardening,
        "real_ports": ports,
    })
}

/// 生效配置 → 内核规则 + 提升器任务。幂等,挂在 `bans::reconfigure` 末尾。
///
/// 失败语义:任何一步(主机监听枚举 / 规则下发 / 全关清理)失败都把
/// `hardening_cfg` 置 **None** 而不是新 key —— 既保证下一次 reconfigure
/// 会重试本配置,也保证「确认超时回滚到旧配置」的恢复下发不会被
/// diff-skip 跳过(失败的尝试不能被记成已生效)。
pub async fn ensure(state: &Arc<crate::state::AgentState>, eff: &EffectiveConfig) {
    let key = apply_key(eff);
    let running = state.hardening_task.lock().unwrap().as_ref().is_some_and(|task| !task.is_finished());
    if *state.hardening_cfg.lock().unwrap() == Some(key.clone())
        && (!l4_active(&eff.hardening) || running)
    {
        return;
    }
    // 先停旧提升器,再动内核:规则重下发期间不能有旧任务并发消费命中集。
    if let Some(task) = state.hardening_task.lock().unwrap().take() {
        task.abort();
    }

    if !l4_active(&eff.hardening) {
        // 全关:clear_hardening 只删不建(链/集不存在时 ENOENT 容忍),
        // 不像 set_hardening(default) 会把空规则集再建一遍。
        // 「本进程从未装过 + nft 不可用」时无需动内核,直接记 key。
        let managed = state.hardening_cfg.lock().unwrap().is_some()
            || state.bans.read().unwrap().is_some();
        if managed {
            match tokio::task::spawn_blocking(|| NftHandle::open().and_then(|h| h.clear_hardening()))
                .await
            {
                Ok(Ok(())) => tracing::debug!("hardening: no L4 feature enabled, rules cleared"),
                Ok(Err(e)) => {
                    tracing::error!("hardening cleanup failed: {e}; will retry on next reconfigure");
                    *state.hardening_cfg.lock().unwrap() = None;
                    return;
                }
                Err(e) => {
                    tracing::error!("hardening cleanup task failed: {e}; will retry on next reconfigure");
                    *state.hardening_cfg.lock().unwrap() = None;
                    return;
                }
            }
        }
        *state.hardening_cfg.lock().unwrap() = Some(key);
        return;
    }

    let hp_on = eff.hardening.honeypot.as_ref().is_some_and(|c| c.enabled);
    let scan_on = eff.hardening.port_guard.as_ref().is_some_and(|c| c.enabled);
    let mut real = real_tcp_ports(eff);
    if hp_on || scan_on {
        match rooster_config::listeners::host_listen_tcp_ports() {
            Ok(host) => real.extend(host),
            Err(e) => {
                // fail-closed:枚举不出排除面就绝不盲装;顺手清掉可能带着
                // 陈旧白名单的旧规则(清不掉只记日志,重试仍可能)。
                tracing::error!(
                    "hardening: host listener enumeration failed: {e}; not installing L4 rules"
                );
                match tokio::task::spawn_blocking(|| NftHandle::open().and_then(|h| h.clear_hardening()))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e2)) => tracing::error!("hardening: stale-rule cleanup also failed: {e2}"),
                    Err(e2) => tracing::error!("hardening: cleanup task failed: {e2}"),
                }
                *state.hardening_cfg.lock().unwrap() = None;
                return;
            }
        }
    }

    if state.bans.read().unwrap().is_none() {
        tracing::error!(
            "hardening enabled but nftables ban manager unavailable; \
             L4 rules are still installed but hits cannot be promoted to bans"
        );
    }

    let (spec, honey) = build_spec(&eff.hardening, &real);
    let mut open: Vec<u16> = real.iter().copied().collect();
    open.sort_unstable(); // 下发批次确定序
    let applied = tokio::task::spawn_blocking(move || match NftHandle::open() {
        Ok(h) => h.set_hardening(&spec, &honey, &open).map_err(|e| format!("{e}")),
        Err(e) => Err(format!("nft handle: {e}")),
    })
    .await;
    match applied {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!("hardening rule apply failed: {e}; will retry on next reconfigure");
            *state.hardening_cfg.lock().unwrap() = None;
            return;
        }
        Err(e) => {
            tracing::error!("hardening apply task panicked: {e}; will retry on next reconfigure");
            *state.hardening_cfg.lock().unwrap() = None;
            return;
        }
    }
    // 只有成功 apply/cleanup 之后才提交 key(见函数注释)。
    *state.hardening_cfg.lock().unwrap() = Some(key);

    let honey_count = eff
        .hardening
        .honeypot
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| rooster_config::schema::honeypot_ports_of(c).len())
        .unwrap_or(0);
    tracing::info!(
        honeypot = eff.hardening.honeypot.as_ref().is_some_and(|c| c.enabled),
        honeypot_ports = honey_count,
        scan = scan_on,
        conn_limit = eff.hardening.conn_limit.as_ref().is_some_and(|c| c.enabled),
        flag_guard = eff.hardening.flag_guard.as_ref().is_some_and(|c| c.enabled),
        "hardening L4 rules applied"
    );

    let Some(bans) = state.bans.read().unwrap().clone() else {
        *state.hardening_cfg.lock().unwrap() = None;
        return;
    };
    let Some(events) = state.events_tx.lock().unwrap().clone() else {
        tracing::error!("hardening promoter has no event channel; will retry on next reconfigure");
        *state.hardening_cfg.lock().unwrap() = None;
        return;
    };
    // 提升器的只读句柄(list/删 命中集);规则下发已在上方用过独立句柄完成。
    let handle = match tokio::task::spawn_blocking(NftHandle::open).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            tracing::error!("hardening promoter cannot open nft handle: {e}");
            *state.hardening_cfg.lock().unwrap() = None;
            return;
        }
        Err(e) => {
            tracing::error!("hardening promoter handle task failed: {e}");
            *state.hardening_cfg.lock().unwrap() = None;
            return;
        }
    };
    let node = eff
        .agent
        .node_name
        .clone()
        .unwrap_or_else(|| "unknown-node".to_string());
    let hardening = eff.hardening.clone();
    let sets: Vec<&'static str> = [
        SET_HP_V4,
        SET_HP_V6,
        SET_SCANPORTS_V4,
        SET_SCANPORTS_V6,
        SET_L4HIT_V4,
        SET_L4HIT_V6,
    ]
    .into_iter()
    .filter(|s| hit_policy(&hardening, s).is_some())
    .collect();

    let task = tokio::spawn(promoter(
        bans,
        events,
        node,
        hardening,
        sets,
        Arc::new(handle),
    ));
    *state.hardening_task.lock().unwrap() = Some(task);
}

/// 提升器:轮询命中的暂存集 → BanManager.apply_ban → 事件。
/// 从不 panic(所有错误记日志继续);ban 冷却表避免封禁有效期内重复刷事件。
/// 自带 netlink 句柄读/清命中集 —— 与封禁写入解耦,不扩 BanManager trait 面。
async fn promoter(
    bans: Arc<dyn BanManager>,
    events: UnboundedSender<Event>,
    node: String,
    hardening: HardeningConfig,
    sets: Vec<&'static str>,
    nft: Arc<NftHandle>,
) {
    let mut cooldown: HashMap<(String, &'static str), Instant> = HashMap::new();
    let mut hit_cooldown: HashMap<(String, u16), Instant> = HashMap::new();
    let mut tick = tokio::time::interval(promoter_tick(&hardening));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        for set in sets.iter().copied() {
            let Some((plugin, reason, ttl)) = hit_policy(&hardening, set) else {
                continue;
            };
            if matches!(set, SET_SCANPORTS_V4 | SET_SCANPORTS_V6) {
                promote_scan_set(&bans, &events, &node, &hardening, set, &nft, &mut cooldown, plugin, &reason, ttl).await;
            } else if matches!(set, SET_HP_V4 | SET_HP_V6) {
                promote_honeypot_set(&bans, &events, &node, &hardening, set, &nft, &mut cooldown, &mut hit_cooldown, plugin, &reason, ttl).await;
            } else {
                promote_plain_set(&bans, &events, &node, set, &nft, &mut cooldown, plugin, &reason, ttl).await;
            }
        }
        if cooldown.len() > 8192 {
            cooldown.retain(|_, t| *t > Instant::now());
        }
        hit_cooldown.retain(|_, t| *t > Instant::now());
    }
}

/// 扫描元组集的提升:distinct-port 阈值判定(`scan_offenders`),元组
/// **只读不删** —— 按窗口自动过期,封禁冷却沿用 (ip, set) 表;封过的源
/// 已在封禁 set 里,不会再产生新元组。
#[allow(clippy::too_many_arguments)]
async fn promote_scan_set(
    bans: &Arc<dyn BanManager>,
    events: &UnboundedSender<Event>,
    node: &str,
    hardening: &HardeningConfig,
    set: &'static str,
    nft: &Arc<NftHandle>,
    cooldown: &mut HashMap<(String, &'static str), Instant>,
    plugin: &'static str,
    reason: &str,
    ttl: Duration,
) {
    let Some(pg) = hardening.port_guard.as_ref().filter(|c| c.enabled) else {
        return;
    };
    let threshold = pg.max_hits_or_default().max(1);
    let tuples: Vec<((IpAddr, u16), Option<u64>)> = {
        let nft = nft.clone();
        match tokio::task::spawn_blocking(move || nft.list_scan_tuples(set)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                tracing::warn!(set, "hardening scan tuple dump failed: {e}");
                return;
            }
            Err(_) => return,
        }
    };
    for ip in scan_offenders(&tuples, threshold) {
        let ip = ip.to_string();
        // 非路由源:不封也不删 —— 元组按窗口自然过期,拼接键也不能当
        // 纯 IP 元素删(delete_plain_element 会错删/报错)。
        if !promotable(&ip) {
            tracing::debug!(ip, set, "non-routable scan tuples ignored");
            continue;
        }
        let cd_key = (ip.clone(), set);
        let now = Instant::now();
        if cooldown.get(&cd_key).is_some_and(|t| *t > now) {
            continue;
        }
        let entry = BanEntry {
            ip: ip.clone(),
            ttl,
            reason: reason.to_string(),
            plugin: plugin.to_string(),
            node: node.to_string(),
            scope: BanScope::Local,
            started_at: None,
            expires_at: None,
        };
        match bans.apply_ban(&entry) {
            Ok(()) => {
                cooldown.insert(cd_key, now + ttl);
                let _ = events.send(Event::Ban {
                    ip: ip.clone(),
                    reason: reason.to_string(),
                    plugin: plugin.to_string(),
                    scope: "local".to_string(),
                    ttl_secs: ttl.as_secs(),
                });
            }
            Err(e) => {
                // 白名单命中(Refused)属预期;冷却 60s 防止每轮刷日志,
                // 元组本身不动(在窗口内的扫描还在继续)。
                tracing::debug!(ip, set, "hardening ban not applied: {e}");
                cooldown.insert(cd_key, now + Duration::from_secs(60));
            }
        }
    }
}

fn record_honeypot_hit(
    cooldown: &mut HashMap<(String, u16), Instant>,
    key: (String, u16),
    now: Instant,
    window: Duration,
) -> bool {
    if cooldown.get(&key).is_some_and(|until| *until > now) {
        return false;
    }
    cooldown.insert(key, now + window);
    true
}

#[allow(clippy::too_many_arguments)]
async fn promote_honeypot_set(
    bans: &Arc<dyn BanManager>,
    events: &UnboundedSender<Event>,
    node: &str,
    hardening: &HardeningConfig,
    set: &'static str,
    nft: &Arc<NftHandle>,
    cooldown: &mut HashMap<(String, &'static str), Instant>,
    hit_cooldown: &mut HashMap<(String, u16), Instant>,
    plugin: &'static str,
    reason: &str,
    ttl: Duration,
) {
    let tuples = {
        let nft = nft.clone();
        match tokio::task::spawn_blocking(move || nft.list_scan_tuples(set)).await {
            Ok(Ok(tuples)) => tuples,
            Ok(Err(e)) => {
                tracing::warn!(set, "honeypot tuple dump failed: {e}");
                return;
            }
            Err(_) => return,
        }
    };
    let window = honeypot_window(hardening);
    for ((addr, port), remaining_ms) in tuples {
        if remaining_ms == Some(0) {
            continue;
        }
        let ip = addr.to_string();
        if !promotable(&ip) {
            continue;
        }
        let now = Instant::now();
        let hit_key = (ip.clone(), port);
        if !record_honeypot_hit(hit_cooldown, hit_key, now, window) {
            continue;
        }
        let _ = events.send(Event::HoneypotHit {
            ip: ip.clone(),
            port,
            protocol: "tcp".to_string(),
        });

        let ban_key = (ip.clone(), set);
        if cooldown.get(&ban_key).is_some_and(|until| *until > now) {
            continue;
        }
        let entry = BanEntry {
            ip: ip.clone(),
            ttl,
            reason: reason.to_string(),
            plugin: plugin.to_string(),
            node: node.to_string(),
            scope: BanScope::Local,
            started_at: None,
            expires_at: None,
        };
        match bans.apply_ban(&entry) {
            Ok(()) => {
                cooldown.insert(ban_key, now + ttl);
                let _ = events.send(Event::Ban {
                    ip,
                    reason: reason.to_string(),
                    plugin: plugin.to_string(),
                    scope: "local".to_string(),
                    ttl_secs: ttl.as_secs(),
                });
            }
            Err(e) => {
                tracing::debug!(ip, set, "honeypot ban not applied: {e}");
                cooldown.insert(ban_key, now + Duration::from_secs(60));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn promote_plain_set(
    bans: &Arc<dyn BanManager>,
    events: &UnboundedSender<Event>,
    node: &str,
    set: &'static str,
    nft: &Arc<NftHandle>,
    cooldown: &mut HashMap<(String, &'static str), Instant>,
    plugin: &'static str,
    reason: &str,
    ttl: Duration,
) {
    let hits: Vec<String> = {
        let nft = nft.clone();
        match tokio::task::spawn_blocking(move || {
            nft.list_set_elements(set)
                .map(|v| v.into_iter().map(|(ip, _)| ip).collect::<Vec<_>>())
        })
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::warn!(set, "hardening hit dump failed: {e}");
                return;
            }
            Err(_) => return,
        }
    };
    for ip in hits {
        let cd_key = (ip.clone(), set);
        let now = Instant::now();
        let fresh = cooldown.get(&cd_key).is_some_and(|t| *t > now);
        // 非路由地址:只清位,不提封。
        if !promotable(&ip) {
            tracing::debug!(ip, set, "non-routable hit dropped (register fallback)");
            let _ = {
                let nft = nft.clone();
                let ip = ip.clone();
                tokio::task::spawn_blocking(move || nft.delete_plain_element(set, &ip))
                    .await
            };
            continue;
        }
        if !fresh {
            let entry = BanEntry {
                ip: ip.clone(),
                ttl,
                reason: reason.to_string(),
                plugin: plugin.to_string(),
                node: node.to_string(),
                scope: BanScope::Local,
                started_at: None,
                expires_at: None,
            };
            match bans.apply_ban(&entry) {
                Ok(()) => {
                    cooldown.insert(cd_key, now + ttl);
                    let _ = events.send(Event::Ban {
                        ip: ip.clone(),
                        reason: reason.to_string(),
                        plugin: plugin.to_string(),
                        scope: "local".to_string(),
                        ttl_secs: ttl.as_secs(),
                    });
                }
                Err(e) => {
                    // 白名单命中(Refused)属预期:记一次 debug,
                    // 元素照常删除,否则暂存集会反复报同一地址。
                    tracing::debug!(ip, set, "hardening ban not applied: {e}");
                    cooldown.insert(cd_key, now + Duration::from_secs(60));
                }
            }
        }
        let _ = {
            let nft = nft.clone();
            let ip = ip.clone();
            tokio::task::spawn_blocking(move || nft.delete_plain_element(set, &ip)).await
        };
    }
}
