//! 主机真实监听端口枚举(仅标准库,读 `/proc/net/tcp` + `/proc/net/tcp6`)。
//!
//! 蜜罐 / 端口扫描检测都是「命中即封」语义,它们的排除面除了配置里的
//! 转发端口 / sshd / management,还必须包含主机上一切真在 LISTEN 的 TCP
//! 端口(本地数据库、打印服务等)—— 否则启用等于自断服务 + 误封正常
//! 客户端。本 helper 由 validate(写入/热重载校验)与 agent 的
//! real_tcp_ports 排除面共用,保证两条路径看到同一个端口集合。
//!
//! 非 Linux 没有 `/proc/net/tcp`:显式返回 Err 而不是空集 —— 空集会让
//! 调用方误以为「主机上没有任何监听」而盲装规则;只有 honeypot /
//! port-guard **启用**时这个错误才会让校验失败(fail-closed),缺省关闭
//! 的配置在非 Linux 上照常加载。

use std::collections::HashSet;

/// 主机当前 LISTEN 状态的 TCP 本地端口全集(v4 + v6,任意绑定地址;
/// 含仅绑定回环的监听 —— 保守排除,宁可少封不可误封)。
pub fn host_listen_tcp_ports() -> Result<HashSet<u16>, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = parse_listen_ports;
        return Err(
            "enumerating host listeners is only supported on Linux (/proc/net/tcp)".to_string(),
        );
    }
    #[cfg(target_os = "linux")]
    {
        let mut ports = HashSet::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{path}: unreadable: {e}"))?;
            ports.extend(parse_listen_ports(&text, path)?);
        }
        Ok(ports)
    }
}

/// `/proc/net/tcp{,6}` 的行格式:
/// `sl local_address rem_address st tx_queue ...`,其中 local_address 是
/// `HEXIP:HEXPORT`(tcp6 为 32 位 hex),st == `0A` 即 TCP_LISTEN。
/// 纯函数便于单测;表头与残行跳过,LISTEN 行端口解析失败才算错误。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_listen_ports(text: &str, src: &str) -> Result<HashSet<u16>, String> {
    let mut ports = HashSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[3] != "0A" {
            continue; // 表头 / 残行 / 非 LISTEN
        }
        let Some((_, port_hex)) = f[1].rsplit_once(':') else {
            return Err(format!("{src}: malformed local_address `{}`", f[1]));
        };
        let port = u16::from_str_radix(port_hex, 16)
            .map_err(|_| format!("{src}: bad port hex `{port_hex}`"))?;
        ports.insert(port);
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_listen_sockets_from_both_families() {
        // 127.0.0.1:8080(1F90)LISTEN;10.0.0.5:3306(0CEA)ESTABLISHED(01);
        // [::]:443(01BB)LISTEN;表头与残行跳过。
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                   \x20  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
                   1: 0A000005:0CEA 0A000001:1F90 01 00000000:00000000 02:0000003E 00000000     0        0 0 3\n";
        let tcp6 = "  sl  local_address                         remote_address                        st\n\
                    0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A\n";
        let mut v4 = parse_listen_ports(tcp, "t4").expect("v4 parses");
        let v6 = parse_listen_ports(tcp6, "t6").expect("v6 parses");
        assert_eq!(v4.remove(&8080), true, "LISTEN v4 端口");
        assert!(v4.is_empty(), "非 LISTEN 行不计入");
        assert_eq!(v6.iter().collect::<Vec<_>>(), vec![&443], "LISTEN v6 端口");
    }

    #[test]
    fn malformed_listen_line_is_an_error_not_silence() {
        let bad = "0: nonsense 00000000:0000 0A\n";
        assert!(parse_listen_ports(bad, "t").is_err(), "LISTEN 行解析失败必须报错");
    }
}
