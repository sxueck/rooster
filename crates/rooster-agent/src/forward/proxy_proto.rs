//! PROXY protocol v1 / v2 编解码。
//!
//! - 发送侧(`encode_v1` / `encode_v2`):连接上游成功后先写头,
//!   源地址 = 真实客户端地址(accept-proxy 头里的 src,否则 TCP peer),
//!   目的地址 = 本规则监听地址(accepted socket 的 local_addr)。
//! - 接收侧(`read_header`):`accept-proxy-protocol: true` 时先读头,
//!   解析出真实源地址供 ACL / 限速使用;UNKNOWN / LOCAL 回退 TCP peer;
//!   畸形头直接断开连接。多读出来的字节(payload 前缀)原样转交。

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use rooster_config::ProxyProtocol;
use tokio::io::AsyncReadExt;

/// v2 固定 12 字节签名:\r\n\r\n\0\r\nQUIT\n。
pub(crate) const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// v1 文本行最大长度(含 CRLF,协议规定上限 107 字节 + 结尾,取 108)。
const V1_MAX: usize = 108;
/// 接收头的整体超时:防止只连不发头的客户端长期占用资源。
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// 按站点配置编码 PROXY 头;`None` / `None` 变体返回空。
///
/// forward 的 `tcp` 与 http-guard 的 passthrough 共用本函数:两处
/// 编码同一份线格式,复制会各自漂移。
pub(crate) fn encode(pp: Option<ProxyProtocol>, src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match pp {
        None | Some(ProxyProtocol::None) => Vec::new(),
        Some(ProxyProtocol::V1) => encode_v1(src, dst),
        Some(ProxyProtocol::V2) => encode_v2(src, dst),
    }
}

/// 编码 v1 头:`PROXY TCP4|TCP6 src dst sport dport\r\n`。
pub(crate) fn encode_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let fam = match src {
        SocketAddr::V4(_) => "TCP4",
        SocketAddr::V6(_) => "TCP6",
    };
    format!(
        "PROXY {fam} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    )
    .into_bytes()
}

/// 编码 v2 头(PROXY 命令、STREAM 传输、按源地址族带完整地址块)。
pub(crate) fn encode_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 36);
    out.extend_from_slice(&V2_SIG);
    out.push(0x21); // version=2, command=PROXY
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            out.push(0x11); // AF_INET | SOCK_STREAM
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            out.push(0x21); // AF_INET6 | SOCK_STREAM
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        // 混合族不应出现;保守按 AF_UNSPEC 地址块(len=0)处理。
        _ => {
            out.push(0x11);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

/// 读取并解析客户端 PROXY 头,返回 (真实源地址, 多读出的 payload 前缀)。
/// 头与 payload 常被合并在同一个 TCP 段里,前缀字节不能丢。
pub(crate) async fn read_header<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    match tokio::time::timeout(HEADER_TIMEOUT, read_header_inner(stream, peer)).await {
        Ok(res) => res,
        Err(_) => Err(invalid("timed out waiting for PROXY header")),
    }
}

async fn read_header_inner<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut chunk = [0u8; 512];
    loop {
        if buf.len() >= V2_SIG.len() {
            if buf.starts_with(&V2_SIG) {
                // parse_v2 返回时 buf 已被裁剪为 payload 前缀。
                let src = parse_v2(stream, &mut buf, &mut chunk).await?;
                let leftover = std::mem::take(&mut buf);
                return Ok((src.unwrap_or(peer), leftover));
            }
            if buf.starts_with(b"PROXY ") {
                // parse_v1 返回时 buf 已被裁剪为 payload 前缀。
                let src = parse_v1(stream, &mut buf, &mut chunk).await?;
                let leftover = std::mem::take(&mut buf);
                return Ok((src.unwrap_or(peer), leftover));
            }
            return Err(invalid("stream does not start with a PROXY header"));
        }
        // 字节尚不足以判定:必须是 "PROXY " 或 v2 签名的前缀。
        if !buf.is_empty()
            && !b"PROXY ".starts_with(&buf[..])
            && !V2_SIG.starts_with(&buf[..])
        {
            return Err(invalid("stream does not start with a PROXY header"));
        }
        if buf.len() > V1_MAX {
            return Err(invalid("PROXY v1 header exceeds 108 bytes"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before PROXY header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// v1:`PROXY (TCP4|TCP6) src dst sport dport\r\n` 或 `PROXY UNKNOWN\r\n`。
/// 成功后 `buf` 只剩 CRLF 之后的字节(payload 前缀)。
async fn parse_v1<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    chunk: &mut [u8],
) -> io::Result<Option<SocketAddr>> {
    // 读到 CRLF 为止;v1 头整体不得超过 108 字节。
    let mut end = find_crlf(buf);
    while end.is_none() {
        if buf.len() > V1_MAX {
            return Err(invalid("PROXY v1 header exceeds 108 bytes"));
        }
        let n = stream.read(chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside PROXY v1 header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        end = find_crlf(buf);
    }
    let end = end.expect("loop exited with Some");
    let line = String::from_utf8_lossy(&buf[..end]).to_string();
    let rest = buf.split_off(end + 2); // buf 保留头,rest 是 payload 前缀
    *buf = rest;

    let toks: Vec<&str> = line.split_whitespace().collect();
    match toks.as_slice() {
        ["PROXY", "UNKNOWN"] => Ok(None),
        ["PROXY", "TCP4", src, _dst, sport, _dport] => {
            let ip: Ipv4Addr = src
                .parse()
                .map_err(|_| invalid("PROXY v1 TCP4 source is not an IPv4 address"))?;
            let port: u16 = sport
                .parse()
                .map_err(|_| invalid("PROXY v1 source port is not valid"))?;
            if port == 0 {
                return Err(invalid("PROXY v1 source port is zero"));
            }
            Ok(Some(SocketAddr::from((ip, port))))
        }
        ["PROXY", "TCP6", src, _dst, sport, _dport] => {
            let ip: Ipv6Addr = src
                .parse()
                .map_err(|_| invalid("PROXY v1 TCP6 source is not an IPv6 address"))?;
            let port: u16 = sport
                .parse()
                .map_err(|_| invalid("PROXY v1 source port is not valid"))?;
            if port == 0 {
                return Err(invalid("PROXY v1 source port is zero"));
            }
            Ok(Some(SocketAddr::from((ip, port))))
        }
        _ => Err(invalid("malformed PROXY v1 header")),
    }
}

/// v2:12 字节签名 + ver/cmd + fam/proto + u16 长度 + 地址块。
/// 成功后 `buf` 只剩地址块之后的字节(payload 前缀)。
async fn parse_v2<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    chunk: &mut [u8],
) -> io::Result<Option<SocketAddr>> {
    // 固定头 16 字节。
    while buf.len() < 16 {
        let n = stream.read(chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside PROXY v2 header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let version = buf[12] >> 4;
    let command = buf[12] & 0x0F;
    let family = buf[13] >> 4;
    let _transport = buf[13] & 0x0F;
    let length = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if version != 2 {
        return Err(invalid("unsupported PROXY v2 version"));
    }
    // 期待的地址块长度必须与族匹配。
    let expect = match family {
        0 => 0,     // AF_UNSPEC
        1 => 12,    // AF_INET:  src4 + dst4 + sport + dport
        2 => 36,    // AF_INET6: src6 + dst6 + sport + dport
        _ => return Err(invalid("unsupported PROXY v2 address family")),
    };
    if length != expect {
        return Err(invalid("PROXY v2 length does not match address family"));
    }
    // 读满地址块。
    while buf.len() < 16 + length {
        let n = stream.read(chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside PROXY v2 address block",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let src = match (command, family) {
        (0, _) => None, // LOCAL:直连,无代理语义,回退 TCP peer
        (1, 1) => {
            let ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
            let port = u16::from_be_bytes([buf[24], buf[25]]);
            Some(SocketAddr::from((ip, port)))
        }
        (1, 2) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[16..32]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[48], buf[49]]);
            Some(SocketAddr::from((ip, port)))
        }
        _ => return Err(invalid("unsupported PROXY v2 command")),
    };
    let rest = buf.split_off(16 + length);
    *buf = rest;
    Ok(src)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}
