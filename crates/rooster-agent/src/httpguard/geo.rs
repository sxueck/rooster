//! GeoIP 国家规则。
//!
//! DB-IP Lite mmdb(maxminddb 读取);`geoip_db` 未配置或库加载失败时
//! geo 规则整体跳过(放行)。查库失败 / 无国家码视为放行(保守策略,
//! 避免 mmdb 数据缺口造成误杀)。判定顺序:
//! 1. `allow` 非空:国家码不在 allow 内 → 拒绝;
//! 2. `deny` 非空:国家码在 deny 内 → 拒绝。

use std::net::IpAddr;

use rooster_config::schema::GeoRule;

pub(crate) fn country_of(
    reader: &maxminddb::Reader<Vec<u8>>,
    ip: IpAddr,
) -> Option<String> {
    let c: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
    c.country
        .and_then(|x| x.iso_code)
        .or_else(|| c.registered_country.and_then(|x| x.iso_code))
        .map(|s| s.to_ascii_uppercase())
}

/// 该 IP 是否放行。
pub(crate) fn allowed(rule: &GeoRule, reader: Option<&maxminddb::Reader<Vec<u8>>>, ip: IpAddr) -> bool {
    let Some(reader) = reader else { return true };
    let Some(code) = country_of(reader, ip) else { return true };
    if !rule.allow.is_empty() {
        let allow: Vec<String> = rule
            .allow
            .iter()
            .map(|s| s.to_ascii_uppercase())
            .collect();
        if !allow.contains(&code) {
            return false;
        }
    }
    if !rule.deny.is_empty() {
        let deny: Vec<String> = rule.deny.iter().map(|s| s.to_ascii_uppercase()).collect();
        if deny.contains(&code) {
            return false;
        }
    }
    true
}
