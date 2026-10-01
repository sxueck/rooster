//! 语义校验:schema 之上的跨字段规则(端口冲突、CIDR、速率格式等)。
//! 管理 API 写入与热重载共用同一套校验。

use crate::schema::EffectiveConfig;
use ipnet::IpNet;
use std::collections::HashSet;

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
}
