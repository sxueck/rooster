//! 语义校验:schema 之上的跨字段规则(端口冲突、CIDR、速率格式等)。
//! 管理 API 写入与热重载共用同一套校验。

use crate::schema::EffectiveConfig;
use ipnet::IpNet;
use std::collections::HashSet;
use std::time::Duration;

pub fn validate_effective(eff: &EffectiveConfig) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();

    if eff.agent.node_name.as_deref().map(str::trim).unwrap_or("").is_empty() {
        errs.push("agent.node-name must not be empty".to_string());
    }

    // forwards:id 唯一、target 合法、监听端口不冲突、速率格式正确。
    let mut forward_ids = HashSet::new();
    // (port, protocol) -> owner id
    let mut occupied: Vec<(u16, &'static str, String)> = Vec::new();
    for f in &eff.forwards {
        if f.id.trim().is_empty() {
            errs.push("forward: id must not be empty".to_string());
        }
        if !forward_ids.insert(f.id.clone()) {
            errs.push(format!("forward `{}`: duplicate id", f.id));
        }
        if let Err(e) = check_host_port(&f.target) {
            errs.push(format!("forward `{}`: invalid target `{}`: {e}", f.id, f.target));
        }
        for proto in f.proto.protocols() {
            if let Some((_, _, owner)) = occupied
                .iter()
                .find(|(p, pr, _)| *p == f.listen.port() && *pr == *proto)
            {
                errs.push(format!(
                    "forward `{}`: port {} ({proto}) already in use by `{owner}`",
                    f.id,
                    f.listen.port()
                ));
            } else {
                occupied.push((f.listen.port(), proto, f.id.clone()));
            }
        }
        if let Some(limits) = &f.limits {
            if let Some(rate) = &limits.conn_rate {
                if let Err(e) = check_rate(rate) {
                    errs.push(format!("forward `{}`: invalid conn-rate `{rate}`: {e}", f.id));
                }
            }
        }
        if let Some(acl) = &f.acl {
            for cidr in &acl.allow {
                if cidr.parse::<IpNet>().is_err() {
                    errs.push(format!("forward `{}`: invalid cidr `{cidr}`", f.id));
                }
            }
        }
    }

    // 进程监听不与转发端口冲突。
    let listeners = [
        ("management.listen", eff.management.listen),
        ("management.metrics-listen", eff.management.metrics_listen),
    ];
    for (name, addr) in listeners {
        if let Some(addr) = addr {
            for proto in ["tcp", "udp"] {
                if let Some((_, _, owner)) = occupied
                    .iter()
                    .find(|(p, pr, _)| *p == addr.port() && *pr == proto)
                {
                    errs.push(format!(
                        "{name}: port {} conflicts with forward `{owner}`",
                        addr.port()
                    ));
                }
            }
        }
    }

    if eff.plugins.http_guard.enabled {
        let ports = [
            ("http-guard.listen-http", eff.plugins.http_guard.listen_http),
            ("http-guard.listen-https", eff.plugins.http_guard.listen_https),
        ];
        for (name, addr) in ports {
            if let Some(addr) = addr {
                if let Some((_, _, owner)) =
                    occupied.iter().find(|(p, _, _)| *p == addr.port())
                {
                    errs.push(format!(
                        "{name}: port {} conflicts with forward `{owner}`",
                        addr.port()
                    ));
                }
            }
        }
    }

    if eff.plugins.ssh_guard.enabled {
        if let Err(e) = check_rate(&eff.plugins.ssh_guard.conn_rate) {
            errs.push(format!("ssh-guard: invalid conn-rate: {e}"));
        }
    }

    // 加固:蜜罐/端口守卫必须排除真实监听端口(带病下发 = 自断服务)。
    {
        let h = &eff.hardening;
        let mut real_ports: HashSet<u16> = HashSet::new();
        for f in &eff.forwards {
            if f.disabled != Some(true) {
                real_ports.insert(f.listen.port());
            }
        }
        if eff.plugins.http_guard.enabled {
            for a in [eff.plugins.http_guard.listen_http, eff.plugins.http_guard.listen_https].into_iter().flatten() {
                real_ports.insert(a.port());
            }
        }
        // sshd 端口无论 ssh-guard 是否启用都在监听;management 同理。
        real_ports.insert(eff.plugins.ssh_guard.port);
        real_ports.insert(eff.management.listen().port());
        if let Some(m) = eff.management.metrics_listen {
            real_ports.insert(m.port());
        }
        // 蜜罐/扫描启用时叠加主机真实监听端口(/proc/net/tcp{,6} 的
        // LISTEN):命中即封的端口绝不能是主机在听的端口。枚举失败 →
        // 直接拒绝启用(fail-closed):拿不到排除面就盲装规则,等于把
        // 打向主机服务的客户端全部交给误封。仅在这两项启用时才读 ——
        // 缺省关闭的配置在非 Linux 上照常加载。
        let hp_on = h.honeypot.as_ref().is_some_and(|c| c.enabled);
        let scan_on = h.port_guard.as_ref().is_some_and(|c| c.enabled);
        if hp_on || scan_on {
            match crate::listeners::host_listen_tcp_ports() {
                Ok(host) => real_ports.extend(host),
                Err(e) => errs.push(format!(
                    "hardening: cannot enumerate host listeners ({e}); \
                     refusing to enable honeypot/port-guard without the exclusion set"
                )),
            }
        }
        if let Some(pg) = h.port_guard.as_ref().filter(|c| c.enabled) {
            // 阈值判定在用户态提升器:同一端口的重复探测只计 1,0 阈值
            // 等于「碰过任何未监听端口即封」,不是扫描检测。
            if pg.max_hits.is_some_and(|m| m == 0) {
                errs.push("hardening.port-guard: max-hits must be >= 1".to_string());
            }
            // 提升器轮询间隔自适应到 find-time/2,且有 250ms 下限:
            // 窗口比下限的两倍还短就无法保证每个元组在过期前被看到。
            if pg.find_time.is_some_and(|t| t < Duration::from_millis(500)) {
                errs.push(
                    "hardening.port-guard: find-time below 500ms is incompatible with the hit promoter poll floor"
                        .to_string(),
                );
            }
        }
        if let Some(hp) = h.honeypot.as_ref().filter(|c| c.enabled) {
            let ports = crate::schema::honeypot_ports_of(hp);
            if ports.is_empty() {
                errs.push("hardening.honeypot: enabled but port list is empty".to_string());
            }
            if ports.len() > 64 {
                errs.push(format!("hardening.honeypot: too many ports ({})", ports.len()));
            }
            for p in &ports {
                if *p == 0 {
                    errs.push(format!("hardening.honeypot: invalid port {p}"));
                } else if real_ports.contains(p) {
                    errs.push(format!(
                        "hardening.honeypot: port {p} is actually listened on (forward/http-guard/sshd/management); remove it from the honeypot list"
                    ));
                }
            }
            for p in &h
                .port_guard
                .as_ref()
                .filter(|c| c.enabled)
                .map(|c| c.extra_open_ports.clone())
                .unwrap_or_default()
            {
                if ports.contains(p) {
                    errs.push(format!(
                        "hardening: port {p} is both honeypot and port-guard extra-open-ports"
                    ));
                }
            }
        }
        if let Some(cl) = h.conn_limit.as_ref().filter(|c| c.enabled) {
            if let Some(rate) = &cl.rate {
                if let Err(e) = check_rate(rate) {
                    errs.push(format!("hardening.conn-limit: invalid rate `{rate}`: {e}"));
                }
            }
        }
        if let Some(ch) = h.client_hello.as_ref().filter(|c| c.enabled) {
            if let Some(rate) = &ch.rate {
                if let Err(e) = check_rate(rate) {
                    errs.push(format!("hardening.client-hello: invalid rate `{rate}`: {e}"));
                }
            }
            if ch.max_size.is_some_and(|m| m < 128) {
                errs.push(format!(
                    "hardening.client-hello: max-size {:?} is below any valid ClientHello (>=517 bytes)",
                    ch.max_size
                ));
            }
        }
        if let Some(bc) = h.body_cap.as_ref().filter(|c| c.enabled) {
            if bc.max_size.is_some_and(|m| m < 1024) {
                errs.push("hardening.body-cap: max-size below 1KiB will break every upload".to_string());
            }
        }
        if let Some(sl) = h.slow_loris.as_ref().filter(|c| c.enabled) {
            if sl.max_conns_per_ip.is_some_and(|m| m == 0) {
                errs.push("hardening.slow-loris: max-conns-per-ip must be >= 1".to_string());
            }
        }
    }

    for cidr in &eff.security.admin_allowlist {
        if cidr.parse::<IpNet>().is_err() {
            errs.push(format!("security.admin-allowlist: invalid cidr `{cidr}`"));
        }
    }

    if let Some(hub) = &eff.hub {
        let scheme_ok = ["ws://", "wss://", "http://", "https://"]
            .iter()
            .any(|s| hub.url.starts_with(s));
        if !scheme_ok {
            errs.push(format!("hub.url: invalid scheme in `{}`", hub.url));
        }
    }

    let mut site_ids = HashSet::new();
    for s in &eff.sites {
        if s.id.trim().is_empty() {
            errs.push("site: id must not be empty".to_string());
        }
        if !site_ids.insert(s.id.clone()) {
            errs.push(format!("site `{}`: duplicate id", s.id));
        }
        if s.server_names.is_empty() {
            errs.push(format!("site `{}`: server-names must not be empty", s.id));
        }
        if s.upstream.trim().is_empty() {
            errs.push(format!("site `{}`: upstream must not be empty", s.id));
        }
        for rl in &s.rate_limit {
            let key_ok = rl.key == "ip"
                || rl.key == "ip+path"
                || rl.key.strip_prefix("header:").is_some_and(|h| !h.is_empty());
            if !key_ok {
                errs.push(format!(
                    "site `{}`: invalid rate-limit key `{}` (expected `ip`, `ip+path` or `header:<name>`)",
                    s.id, rl.key
                ));
            }
            if let Err(e) = check_rate(&rl.rate) {
                errs.push(format!("site `{}`: invalid rate `{}`: {e}", s.id, rl.rate));
            }
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// `host:port`;host 为域名或 IP,裸 IPv6 必须写成 `[::1]`。
pub fn check_host_port(s: &str) -> Result<(), String> {
    let Some((host, port)) = s.rsplit_once(':') else {
        return Err("expected `host:port`".to_string());
    };
    if !host.starts_with('[') && host.contains(':') {
        return Err("bare IPv6 host must be bracketed, e.g. `[::1]:3306`".to_string());
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    let port: u32 = port
        .parse()
        .map_err(|_| format!("invalid port `{port}`"))?;
    if (1..=65535).contains(&port) {
        Ok(())
    } else {
        Err(format!("port {port} out of range"))
    }
}

/// `N/(second|minute|hour)`,如 `30/minute`。
pub fn check_rate(s: &str) -> Result<(), String> {
    let Some((n, unit)) = s.split_once('/') else {
        return Err(format!("`{s}`, expected `N/(second|minute|hour)`"));
    };
    if n.parse::<u32>().map(|n| n > 0) != Ok(true) {
        return Err(format!("invalid count `{n}`"));
    }
    match unit {
        "second" | "minute" | "hour" => Ok(()),
        _ => Err(format!("invalid unit `{unit}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_forms() {
        assert!(check_host_port("10.0.1.20:3306").is_ok());
        assert!(check_host_port("db.internal:5432").is_ok());
        assert!(check_host_port("[::1]:3306").is_ok());
        assert!(check_host_port("10.0.1.20").is_err());
        assert!(check_host_port("a:b:c").is_err());
        assert!(check_host_port("h:0").is_err());
        assert!(check_host_port("h:70000").is_err());
    }

    #[test]
    fn rate_forms() {
        assert!(check_rate("10/minute").is_ok());
        assert!(check_rate("20/second").is_ok());
        assert!(check_rate("5/hour").is_ok());
        assert!(check_rate("10").is_err());
        assert!(check_rate("10/day").is_err());
        assert!(check_rate("0/second").is_err());
    }

    fn eff_of(yaml: &str) -> Result<crate::EffectiveConfig, Vec<String>> {
        crate::parse_and_validate(yaml)
            .map(|(_f, eff)| eff)
            .map_err(|e| vec![format!("{e}")])
    }

    /// 加固全部子项默认关:只配 node-name 时 hardening 各段缺省,
    /// 且不会因反序列化默认值而隐式启用任何防护。
    #[test]
    fn hardening_is_opt_in_and_defaults_off() {
        let eff = eff_of("local:\n  agent:\n    node-name: t\n").expect("bare config valid");
        let h = &eff.hardening;
        assert!(h.honeypot.is_none() && h.port_guard.is_none() && h.conn_limit.is_none());
        assert!(h.flag_guard.is_none() && h.slow_loris.is_none());
        assert!(h.client_hello.is_none() && h.body_cap.is_none());
    }

    /// 蜜罐端口撞真实监听(ssh-guard 端口/转发端口/http-guard 监听)必须
    /// 在配置加载面直接拒,不带病下发 —— 否则启用蜜罐等于自断服务。
    #[test]
    fn honeypot_ports_must_exclude_real_listeners() {
        let cases = [
            ("ports: [22]", "ssh-guard 默认 22 在监听"),
            ("ports: [445]", "与转发规则 445 冲突"),
            ("ports: [8443]", "与 http-guard https 监听冲突"),
        ];
        let tpl = "local:\n  agent:\n    node-name: t\n  hardening:\n    honeypot:\n      enabled: true\n      %s\n  forwards:\n    - id: smb\n      listen: \"0.0.0.0:445\"\n      target: \"10.0.0.5:445\"\nmanaged:\n  plugins:\n    http-guard:\n      enabled: true\n      listen-https: \"0.0.0.0:8443\"\n";
        for (ports, why) in cases {
            let yaml = tpl.replace("%s", ports);
            let errs = eff_of(&yaml).expect_err(&format!("{why}: 应拒写"));
            assert!(
                errs.iter().any(|e| e.contains("hardening.honeypot") && e.contains("listened")),
                "{why}: 实际 {errs:?}"
            );
        }
        // 不撞车的端口 → 通过
        let ok = tpl.replace("%s", "ports: [4444]");
        eff_of(&ok).expect("non-conflicting honeypot port accepted");
    }

    /// 启用后各子项的速率/尺寸格式在加载面校验;关闭时不校验(缺省形状
    /// 不得拦下模板里的残留片段)。
    #[test]
    fn hardening_field_validation() {
        let bad_rate = "local:\n  agent:\n    node-name: t\n  hardening:\n    conn-limit:\n      enabled: true\n      rate: 5/eons\n";
        let errs = eff_of(bad_rate).expect_err("bad rate");
        assert!(errs.iter().any(|e| e.contains("conn-limit")), "{errs:?}");

        let off_not_checked = "local:\n  agent:\n    node-name: t\n  hardening:\n    conn-limit:\n      enabled: false\n      rate: garbage\n";
        eff_of(off_not_checked).expect("disabled section not validated");

        let tiny_hello = "local:\n  agent:\n    node-name: t\n  hardening:\n    client-hello:\n      enabled: true\n      max-size: 64\n";
        let errs = eff_of(tiny_hello).expect_err("hello cap below floor");
        assert!(errs.iter().any(|e| e.contains("client-hello")), "{errs:?}");

        let tiny_body = "local:\n  agent:\n    node-name: t\n  hardening:\n    body-cap:\n      enabled: true\n      max-size: 10\n";
        let errs = eff_of(tiny_body).expect_err("body cap below 1KiB");
        assert!(errs.iter().any(|e| e.contains("body-cap")), "{errs:?}");
    }

    /// 蜜罐端口撞上主机当前真实 LISTEN 的端口(测试里现绑一个临时端口,
    /// 不硬编码 —— 硬编码会撞 CI 宿主自己的服务):/proc/net/tcp 集成,
    /// 排除面缺了它,启用蜜罐就是自断服务。Linux-only:其他平台本来就
    /// 报「无法枚举」而不允许启用。
    #[cfg(target_os = "linux")]
    #[test]
    fn honeypot_port_clashing_with_live_host_listener_is_rejected() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = probe.local_addr().unwrap().port();
        let yaml = format!(
            "local:\n  agent:\n    node-name: t\n  hardening:\n    honeypot:\n      enabled: true\n      ports: [{port}]\n"
        );
        let errs = eff_of(&yaml).expect_err("live listener must be rejected");
        assert!(
            errs.iter().any(|e| e.contains("hardening.honeypot") && e.contains("listened")),
            "实际 {errs:?}"
        );
    }

    /// 端口扫描检测的用户态阈值语义:max-hits 0 与 find-time 过短
    /// (提升器轮询下限的 2 倍以内)都与轮询模型不兼容,加载面直接拒。
    #[test]
    fn port_guard_promoter_incompatible_values_rejected() {
        let base = "local:\n  agent:\n    node-name: t\n  hardening:\n    port-guard:\n      enabled: true\n      %s\n";
        for (field, why) in [("max-hits: 0", "零阈值"), ("find-time: 200ms", "窗口短于轮询下限")] {
            let errs = eff_of(&base.replace("%s", field)).expect_err(&format!("{why}: 应拒写"));
            assert!(
                errs.iter().any(|e| e.contains("port-guard")),
                "{why}: 实际 {errs:?}"
            );
        }
    }

    /// local 层 hardening 覆盖与 managed 层递归合并:标量 local 赢、
    /// 未覆盖字段沿用模板;列表字段是并集(与 allowlist/forwards 同一套
    /// merge_values 规则,这里把真实语义固定进测试)。
    #[test]
    fn hardening_layer_merge_local_wins_lists_union() {
        let yaml = "local:\n  agent:\n    node-name: t\n  hardening:\n    honeypot:\n      enabled: true\n      ports: [4444]\nmanaged:\n  hardening:\n    honeypot:\n      enabled: false\n      ports: [135]\n      ban-time: 2h\n";
        let eff = crate::parse_and_validate(yaml)
            .map(|(_f, e)| e)
            .expect("merge valid");
        let hp = eff.hardening.honeypot.expect("present");
        assert!(hp.enabled, "local.enabled 覆盖 managed");
        assert_eq!(hp.ban_time, Some(std::time::Duration::from_secs(7200)));
        let mut ports = hp.ports.expect("ports merged");
        ports.sort();
        assert_eq!(ports, vec![135, 4444], "列表按既有 merge 规则取并集");
    }
}
