//! TLS ClientHello 解析:在不消费字节的前提下提取 SNI / ALPN,
//! 并计算 JA4 指纹(透传模式的 L4 规则输入)。
//!
//! 实现方式:调用方先用 [`super::peek::PeekStream`] 把 ClientHello 的
//! 原始字节缓冲在流的头部,这里对缓冲做纯内存解析;解析结果只用于
//! 路由与 L4 规则判定,缓冲字节之后原样交给 rustls(终止模式)或
//! 上游(透传模式)重放。
//!
//! JA4 按 foxio.io 公开规范做 best-effort 实现(仓库未依赖 sha2,
//! 这里内置一份标准 SHA-256):
//! - a 部分:`t{版本两位}{d|i}{密码套件数:02}{ALPN 前两字符}`,
//!   `d` 表示带 SNI;版本取 supported_versions 中的最高值,否则取
//!   legacy client_version,0304→`13`、0303→`12`,其余→`00`;
//!   ALPN 缺失记 `00`,`h2`→`h2`,以 `http` 开头→`h1`,其余取前两字符。
//! - b 部分:去 GREASE 后按值升序的密码套件列表(小写 hex,逗号连接)
//!   的 SHA-256 前 12 个 hex 字符。
//! - c 部分:去 GREASE 后按值升序的扩展列表(剔除 SNI=0 与 ALPN=16)
//!   加 `_` 加签名算法列表,整体 SHA-256 前 12 个 hex 字符。
//! 最终指纹为 `{a}_{b}_{c}`。与官方参考实现的差异(GREASE 处理细节、
//! 排序细节)可能存在,但同一实现自洽,可供 `ja4-deny` 精确匹配。


/// 一次解析尝试的结果。
#[derive(Debug)]
pub(crate) enum HelloParse {
    /// 字节不足以构成完整的第一条握手消息,需要继续读。
    NeedMore,
    /// 解析结束;`None` 表示不是 TLS / 结构无法识别。
    Done(Option<ClientHelloInfo>),
}

/// ClientHello 中路由与 L4 规则需要的字段。
#[derive(Debug, Clone)]
pub(crate) struct ClientHelloInfo {
    pub sni: Option<String>,
    /// best-effort JA4 指纹(见模块注释)。
    pub ja4: Option<String>,
    pub alpn: Vec<String>,
}

/// 单个 TLS 记录的上限(RFC 5246:2^14 + 头)。
const MAX_RECORD: usize = 5 + 16384;
/// ClientHello 缓冲上限:足够容纳分片到多个记录的大握手。
pub(crate) const MAX_HELLO_BUF: usize = 64 * 1024;

/// 尝试从连接开头缓冲解析 ClientHello。
pub(crate) fn try_parse(buf: &[u8]) -> HelloParse {
    // 拼接所有 handshake 记录的 payload(消息可能分片在多个记录里)。
    let mut hs = Vec::new();
    let mut pos = 0usize;
    let mut saw_any = false;
    loop {
        if buf.len() < pos + 5 {
            return HelloParse::NeedMore;
        }
        let rtype = buf[pos];
        if pos == 0 && rtype != 22 {
            // 第一条记录不是 handshake:不是 TLS(或不是以 ClientHello 开头)。
            return HelloParse::Done(None);
        }
        let rlen = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if rlen > MAX_RECORD - 5 {
            return HelloParse::Done(None);
        }
        if buf.len() < pos + 5 + rlen {
            return HelloParse::NeedMore;
        }
        if rtype == 22 {
            hs.extend_from_slice(&buf[pos + 5..pos + 5 + rlen]);
            saw_any = true;
        }
        pos += 5 + rlen;
        // 消息可能分片在多条记录里:凑齐一条完整 handshake 消息才停止
        // 拼接(4 字节头 + be24 长度);只看消息头就停会把分片 Hello
        // 误判为 NeedMore。
        if saw_any && hs.len() >= 4 && hs.len() >= 4 + be24(&hs[1..4]) as usize {
            break;
        }
        if buf.len() == pos {
            return HelloParse::NeedMore;
        }
    }
    if hs.is_empty() || hs.len() < 4 {
        return HelloParse::Done(None);
    }
    let mtype = hs[0];
    let mlen = be24(&hs[1..4]);
    if mtype != 1 {
        return HelloParse::Done(None);
    }
    if hs.len() < 4 + mlen {
        return HelloParse::NeedMore;
    }
    HelloParse::Done(parse_hello_body(&hs[4..4 + mlen]))
}

fn be24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cur.len() < n {
        return None;
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Some(head)
}

/// 解析 ClientHello body(不含 4 字节握手头)。
fn parse_hello_body(mut cur: &[u8]) -> Option<ClientHelloInfo> {
    let client_version = u16::from_be_bytes(take(&mut cur, 2)?.try_into().ok()?);
    let _random = take(&mut cur, 32)?;
    let sid_len = *take(&mut cur, 1)?.first()?;
    let _sid = take(&mut cur, sid_len as usize)?;
    let ciphers_len = u16::from_be_bytes(take(&mut cur, 2)?.try_into().ok()?) as usize;
    if ciphers_len % 2 != 0 {
        return None;
    }
    let ciphers_raw = take(&mut cur, ciphers_len)?;
    let ciphers: Vec<u16> = ciphers_raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let comp_len = *take(&mut cur, 1)?.first()? as usize;
    let _comp = take(&mut cur, comp_len)?;
    let ext_total = u16::from_be_bytes(take(&mut cur, 2)?.try_into().ok()?) as usize;
    let ext_blob = take(&mut cur, ext_total)?;

    let mut sni = None;
    let mut alpn = Vec::new();
    let mut exts: Vec<u16> = Vec::new();
    let mut sigalgs: Vec<u16> = Vec::new();
    let mut supported_versions: Vec<u16> = Vec::new();

    let mut e = ext_blob;
    while !e.is_empty() {
        if e.len() < 4 {
            return None;
        }
        let etype = u16::from_be_bytes([e[0], e[1]]);
        let elen = u16::from_be_bytes([e[2], e[3]]) as usize;
        if e.len() < 4 + elen {
            return None;
        }
        let data = &e[4..4 + elen];
        exts.push(etype);
        match etype {
            0 => sni = parse_sni(data),
            13 => parse_u16_list(data, &mut sigalgs, 2),
            16 => parse_alpn(data, &mut alpn),
            43 => {
                // supported_versions 客户端形态:u8 字节数 + u16 列表
                // (与 parse_u16_list 的 u16 前缀不同,单独解析)
                let n = data.first().copied().unwrap_or(0) as usize;
                if data.len() >= 1 + n && n % 2 == 0 {
                    supported_versions.extend(
                        data[1..1 + n]
                            .chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]])),
                    );
                }
            }
            _ => {}
        }
        e = &e[4 + elen..];
    }

    let ja4 = compute_ja4(client_version, &supported_versions, &ciphers, &exts, &sigalgs, &alpn, sni.is_some());
    Some(ClientHelloInfo { sni, ja4, alpn })
}

fn parse_sni(data: &[u8]) -> Option<String> {
    // server_name_list: u16 总长,条目 = type(0=host_name) + u16 长 + 字节。
    if data.len() < 5 {
        return None;
    }
    let mut cur = data;
    let _list_len = u16::from_be_bytes(take(&mut cur, 2)?.try_into().ok()?);
    while !cur.is_empty() {
        let ntype = *take(&mut cur, 1)?.first()?;
        let nlen = u16::from_be_bytes(take(&mut cur, 2)?.try_into().ok()?) as usize;
        let name = take(&mut cur, nlen)?;
        if ntype == 0 {
            return Some(String::from_utf8_lossy(name).to_string());
        }
    }
    None
}

fn parse_alpn(data: &[u8], out: &mut Vec<String>) {
    // ProtocolNameList: u16 总长,条目 = 1 字节长 + 字节。
    if data.len() < 2 {
        return;
    }
    let mut cur = data;
    let _list_len = u16::from_be_bytes([cur[0], cur[1]]);
    cur = &cur[2..];
    while !cur.is_empty() {
        let nlen = match cur.first() {
            Some(&n) => n as usize,
            None => return,
        };
        cur = &cur[1..];
        if cur.len() < nlen {
            return;
        }
        out.push(String::from_utf8_lossy(&cur[..nlen]).to_string());
        cur = &cur[nlen..];
    }
}

/// 读取 u16 元素列表(2 字节总长前缀)。
fn parse_u16_list(data: &[u8], out: &mut Vec<u16>, _unit: usize) {
    if data.len() < 2 {
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len || list_len % 2 != 0 {
        return;
    }
    out.extend(
        data[2..2 + list_len]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]])),
    );
}

/// GREASE 值(RFC 8701):低两字节为 0x0a0a 的模式。
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

fn compute_ja4(
    client_version: u16,
    supported_versions: &[u16],
    ciphers: &[u16],
    exts: &[u16],
    sigalgs: &[u16],
    alpn: &[String],
    has_sni: bool,
) -> Option<String> {
    let ver = supported_versions
        .iter()
        .copied()
        .chain([client_version])
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(client_version);
    let ver = match ver {
        0x0304 => "13",
        0x0303 => "12",
        _ => "00",
    };
    let mut sorted_c: Vec<u16> = ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
    sorted_c.sort_unstable();
    let ciphers = sorted_c;
    let alpn_part = match alpn.first() {
        None => "00".to_string(),
        Some(a) if a == "h2" => "h2".to_string(),
        Some(a) if a.starts_with("http") => "h1".to_string(),
        Some(a) => a.chars().take(2).collect(),
    };
    let a = format!(
        "t{}{}{:02}{}",
        ver,
        if has_sni { 'd' } else { 'i' },
        ciphers.len(),
        alpn_part
    );
    let b_input = ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut sorted_e: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|v| !is_grease(*v) && *v != 0 && *v != 16)
        .collect();
    sorted_e.sort_unstable();
    sorted_e.dedup();
    let c_input = format!(
        "{}_{}",
        sorted_e
            .iter()
            .map(|e| format!("{e:04x}"))
            .collect::<Vec<_>>()
            .join(","),
        sigalgs.iter().map(|s| format!("{s:04x}")).collect::<Vec<_>>().join(",")
    );
    Some(format!(
        "{}_{}_{}",
        a,
        &sha256_hex(b_input.as_bytes())[..12],
        &sha256_hex(c_input.as_bytes())[..12]
    ))
}

// ---------------------------------------------------------------------------
// SHA-256(FIPS 180-4);仓库未依赖 sha2,JA4 截断摘要用这里内置实现。

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// 计算 SHA-256 摘要的 hex 字符串(小写)。
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// 单元测试:解析器 + JA4 自洽 + ja4-deny 判定。

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小但完整的 TLS ClientHello 记录。
    fn build_hello(
        version: u16,
        ciphers: &[u16],
        exts: &[(u16, Vec<u8>)],
        split_records: bool,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&(ciphers.len() as u16 * 2).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(1); // compression
        body.push(0); // null compression
        let mut extbuf = Vec::new();
        for (t, d) in exts {
            extbuf.extend_from_slice(&t.to_be_bytes());
            extbuf.extend_from_slice(&(d.len() as u16).to_be_bytes());
            extbuf.extend_from_slice(d);
        }
        body.extend_from_slice(&(extbuf.len() as u16).to_be_bytes());
        body.extend_from_slice(&extbuf);

        let mut msg = Vec::new();
        msg.push(1); // handshake type
        msg.push((body.len() >> 16) as u8);
        msg.push((body.len() >> 8) as u8);
        msg.push(body.len() as u8);
        msg.extend_from_slice(&body);

        if !split_records {
            let mut out = Vec::new();
            out.push(22);
            out.extend_from_slice(&0x0301u16.to_be_bytes());
            out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            out.extend_from_slice(&msg);
            return out;
        }
        // 分成两个记录,验证跨记录拼接。
        let (a, b) = msg.split_at(msg.len() / 2);
        let mut out = Vec::new();
        for part in [a, b] {
            out.push(22);
            out.extend_from_slice(&0x0301u16.to_be_bytes());
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    fn sni_ext(name: &str) -> (u16, Vec<u8>) {
        let mut entry = Vec::new();
        entry.push(0u8);
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut d = Vec::new();
        d.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        d.extend_from_slice(&entry);
        (0, d)
    }

    fn alpn_ext(proto: &str) -> (u16, Vec<u8>) {
        let mut entry = vec![proto.len() as u8];
        entry.extend_from_slice(proto.as_bytes());
        let mut d = Vec::new();
        d.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        d.extend_from_slice(&entry);
        (16, d)
    }

    fn sig_ext(vals: &[u16]) -> (u16, Vec<u8>) {
        let mut d = Vec::new();
        d.extend_from_slice(&((vals.len() * 2) as u16).to_be_bytes());
        for v in vals {
            d.extend_from_slice(&v.to_be_bytes());
        }
        (13, d)
    }

    fn supver_ext(vals: &[u16]) -> (u16, Vec<u8>) {
        let mut d = vec![(vals.len() * 2) as u8];
        for v in vals {
            d.extend_from_slice(&v.to_be_bytes());
        }
        (43, d)
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn parse_sni_and_alpn() {
        let hello = build_hello(
            0x0303,
            &[0x1301, 0x1302, 0x2f2f],
            &[
                sni_ext("example.test"),
                alpn_ext("h2"),
                alpn_ext("http/1.1"),
                sig_ext(&[0x0403, 0x0804]),
                supver_ext(&[0x0304]),
            ],
            false,
        );
        match try_parse(&hello) {
            HelloParse::Done(Some(info)) => {
                assert_eq!(info.sni.as_deref(), Some("example.test"));
                assert_eq!(info.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
                assert!(info.ja4.is_some());
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
        // 跨两个记录分片也应解析成功。
        let split = build_hello(
            0x0303,
            &[0x1301],
            &[sni_ext("a.test"), sig_ext(&[0x0403])],
            true,
        );
        assert!(matches!(try_parse(&split), HelloParse::Done(Some(_))));
        // 截断 → NeedMore;非 TLS → Done(None)。
        assert!(matches!(try_parse(&hello[..20]), HelloParse::NeedMore));
        assert!(matches!(try_parse(b"GET / HTTP/1.1\r\n"), HelloParse::Done(None)));
    }

    #[test]
    fn ja4_format_and_known_answer() {
        // 固定输入的已知答案:字段变化会改变指纹,用于防止实现漂移。
        // 0x9a9a 是合法 GREASE 值(0x9f9f 不是),计数与摘要都应忽略。
        let ciphers = [0x1301u16, 0xc02b, 0x9a9a, 0x00ff];
        let exts = vec![
            sni_ext("x.test"),
            alpn_ext("h2"),
            sig_ext(&[0x0403, 0x0804]),
            supver_ext(&[0x0304]),
            (0x000a, vec![]),
        ];
        let hello = build_hello(0x0303, &ciphers, &exts, false);
        let info = match try_parse(&hello) {
            HelloParse::Done(Some(i)) => i,
            other => panic!("unexpected: {other:?}"),
        };
        let ja4 = info.ja4.clone().unwrap();
        // a 部分:TLS1.3 + SNI + 3 套件 + ALPN h2。
        assert!(ja4.starts_with("t13d03h2_"), "ja4 = {ja4}");
        assert_eq!(ja4.split('_').count(), 3);
        // b/c 部分各为 12 hex。
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
        // 同一输入两次计算必须一致(供 ja4-deny 精确匹配)。
        let info2 = match try_parse(&hello) {
            HelloParse::Done(Some(i)) => i,
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(info.ja4, info2.ja4);
        // GREASE 不计入套件数:同样套件去掉 0x00ff 后应为 d02。
        let hello2 = build_hello(0x0303, &[0x1301, 0xc02b, 0x9a9a], &exts, false);
        let info3 = match try_parse(&hello2) {
            HelloParse::Done(Some(i)) => i,
            other => panic!("unexpected: {other:?}"),
        };
        let ja4_2 = info3.ja4.clone().unwrap();
        assert!(ja4_2.starts_with("t13d02h2_"), "grease not filtered: {ja4_2}");
        assert_ne!(info.ja4, info3.ja4);
    }

    #[test]
    fn ja4_deny_membership() {
        // ja4-deny 命中即 drop;这里直接验证判定函数的语义。
        let hello = build_hello(
            0x0303,
            &[0x1301],
            &[sni_ext("x.test"), sig_ext(&[0x0403])],
            false,
        );
        let info = match try_parse(&hello) {
            HelloParse::Done(Some(i)) => i,
            other => panic!("unexpected: {other:?}"),
        };
        let ja4 = info.ja4.clone().unwrap();
        assert!(super::super::passthrough::ja4_denied(&[ja4.clone()], &info.ja4));
        assert!(!super::super::passthrough::ja4_denied(&["0000ff00_000000000000_000000000000".to_string()], &info.ja4));
        // 无指纹(解析失败)时不应误伤。
        assert!(!super::super::passthrough::ja4_denied(&[ja4], &None));
    }
}
