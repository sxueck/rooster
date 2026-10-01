//! 真实客户端 IP 解析。
//!
//! TCP peer 默认即真实 IP;当 peer 命中 `trusted-proxies` CIDR 时,
//! 说明前面还有可信的 CDN / LB,从 `X-Forwarded-For` 链上取「最右侧
//! 的不可信地址」(rightmost untrusted):链上更左侧的值可被客户端
//! 伪造,最右侧不可信值是最靠近可信边界的一跳。整条链全部可信时
//! 回退取最左侧,再退回 peer。

use std::net::IpAddr;

use ipnet::IpNet;

pub(crate) fn real_ip(peer: IpAddr, xff: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    let Some(xff) = xff else { return peer };
    if !trusted.iter().any(|net| net.contains(&peer)) {
        return peer;
    }
    let chain: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();
    if chain.is_empty() {
        return peer;
    }
    for ip in chain.iter().rev() {
        if !trusted.iter().any(|net| net.contains(ip)) {
            return *ip;
        }
    }
    chain[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Vec<IpNet> {
        vec![s.parse().unwrap()]
    }

    #[test]
    fn untrusted_peer_uses_peer() {
        let trusted = net("10.0.0.0/8");
        assert_eq!(
            real_ip("1.2.3.4".parse().unwrap(), Some("8.8.8.8, 9.9.9.9"), &trusted),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_takes_rightmost_untrusted() {
        // 10.0.0.9 是追加 XFF 的可信代理;沿 XFF 自右向左跳过可信项,
        // 第一个不可信项 2.2.2.2 即真实客户端。
        let trusted = vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        assert_eq!(
            real_ip(
                "127.0.0.1".parse().unwrap(),
                Some("1.1.1.1, 2.2.2.2, 10.0.0.9"),
                &trusted
            ),
            "2.2.2.2".parse::<IpAddr>().unwrap()
        );
        // 全部可信:回退最左侧。
        let all_trusted = vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "127.0.0.0/8".parse().unwrap(),
        ];
        assert_eq!(
            real_ip(
                "127.0.0.1".parse().unwrap(),
                Some("127.0.0.2, 127.0.0.3"),
                &all_trusted
            ),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        // 空链 / 非法链:回退 peer。
        assert_eq!(
            real_ip("127.0.0.1".parse().unwrap(), Some("garbage"), &trusted),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
