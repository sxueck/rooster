//! 转换函数:`t:none/lowercase/urlDecodeUni/htmlEntityDecode/removeNulls/
//! compressWhitespace/base64Decode/cmdLine` 及 CRS 常用的扩展转换。
//!
//! 全部为纯字符串 → 字符串函数,按 `t:` 出现顺序依次应用。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transform {
    None,
    Lowercase,
    UrlDecodeUni,
    HtmlEntityDecode,
    RemoveNulls,
    CompressWhitespace,
    Base64Decode,
    CmdLine,
    // ---- CRS 扩展(尽力而为的等价实现)----
    Utf8ToUnicode,
    JsDecode,
    CssDecode,
    RemoveWhitespace,
    ReplaceComments,
    NormalizePath,
    NormalizePathWin,
    EscapeSeqDecode,
    Length,
    Sha1,
    HexEncode,
    RemoveCommentsChar,
}

impl Transform {
    /// 名称大小写不敏感(CRS 中出现过 `t:base64decode`)。
    pub(crate) fn parse(name: &str) -> Option<Transform> {
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            "none" => Transform::None,
            "lowercase" => Transform::Lowercase,
            "urldecodeuni" => Transform::UrlDecodeUni,
            "htmlentitydecode" => Transform::HtmlEntityDecode,
            "removenulls" => Transform::RemoveNulls,
            "compresswhitespace" => Transform::CompressWhitespace,
            "base64decode" => Transform::Base64Decode,
            "cmdline" => Transform::CmdLine,
            "utf8tounicode" => Transform::Utf8ToUnicode,
            "jsdecode" => Transform::JsDecode,
            "cssdecode" => Transform::CssDecode,
            "removewhitespace" => Transform::RemoveWhitespace,
            "replacecomments" => Transform::ReplaceComments,
            "normalizepath" => Transform::NormalizePath,
            "normalizepathwin" => Transform::NormalizePathWin,
            "escapeseqdecode" => Transform::EscapeSeqDecode,
            "length" => Transform::Length,
            "sha1" => Transform::Sha1,
            "hexencode" => Transform::HexEncode,
            "removecommentschar" => Transform::RemoveCommentsChar,
            _ => return None,
        })
    }

    pub(crate) fn apply(&self, input: &str) -> String {
        match self {
            Transform::None => input.to_string(),
            Transform::Lowercase => input.to_lowercase(),
            Transform::UrlDecodeUni => url_decode_uni(input, false),
            Transform::HtmlEntityDecode => html_entity_decode(input),
            Transform::RemoveNulls => input.replace('\u{0}', ""),
            Transform::CompressWhitespace => compress_whitespace(input),
            Transform::Base64Decode => base64_decode(input),
            Transform::CmdLine => cmd_line(input),
            Transform::Utf8ToUnicode => utf8_to_unicode(input),
            Transform::JsDecode => js_decode(input),
            Transform::CssDecode => css_decode(input),
            Transform::RemoveWhitespace => input
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
            Transform::ReplaceComments => replace_comments(input),
            Transform::NormalizePath => normalize_path(input, false),
            Transform::NormalizePathWin => normalize_path(input, true),
            Transform::EscapeSeqDecode => escape_seq_decode(input),
            Transform::Length => input.len().to_string(),
            Transform::Sha1 => sha1_hex(input.as_bytes()),
            Transform::HexEncode => hex(input.as_bytes()),
            Transform::RemoveCommentsChar => input
                .replace("/*", "")
                .replace("*/", "")
                .replace('#', "")
                .replace("--", ""),
        }
    }
}

/// 按顺序应用一组转换。
pub(crate) fn apply_all(transforms: &[Transform], input: &str) -> String {
    let mut s = input.to_string();
    for t in transforms {
        s = t.apply(&s);
    }
    s
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}


// SHA-1(手写实现:sha2 crate 不提供且不可新增依赖;仅 `t:sha1` 转换使用)
fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn push_cp_str(out: &mut String, cp: u32) {
    if let Some(c) = char::from_u32(cp) {
        out.push(c);
    } else {
        out.push('\u{fffd}');
    }
}

fn push_cp(out: &mut Vec<u8>, cp: u32) {
    if let Some(c) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    } else {
        out.extend_from_slice("\u{fffd}".as_bytes());
    }
}

/// `%XX` 与 `%uXXXX` 解码;`plus_as_space` 处理表单场景的 `+`。
/// 输出统一走 UTF-8 有损转换,非法字节替换为 U+FFFD。
pub(crate) fn url_decode_uni(s: &str, plus_as_space: bool) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            // `%uXXXX` 与 `\uXXXX`(utf8ToUnicode 的输出形式)同路径解码
            b'%' | b'\\' if i + 2 < b.len() && b[i + 1] == b'u' => {
                let esc = b[i]; // '%' 或 '\\'
                // %uXXXX(代理对合并)
                if i + 5 < b.len()
                    && (i + 11 < b.len())
                    && b[i + 6] == esc
                    && b[i + 7] == b'u'
                {
                    let hi = (0..4).try_fold(0u32, |acc, k| {
                        Some(acc * 16 + hex_val(b[i + 2 + k])? as u32)
                    });
                    let lo = (0..4).try_fold(0u32, |acc, k| {
                        Some(acc * 16 + hex_val(b[i + 8 + k])? as u32)
                    });
                    if let (Some(hi), Some(lo)) = (hi, lo) {
                        let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                        if (0xD800..=0xDBFF).contains(&hi)
                            && (0xDC00..=0xDFFF).contains(&lo)
                            && cp <= 0x10FFFF
                        {
                            push_cp(&mut out, cp);
                            i += 12;
                            continue;
                        }
                    }
                }
                let mut ok = true;
                let mut cp = 0u32;
                for k in 0..4 {
                    match hex_val(b.get(i + 2 + k).copied().unwrap_or(0)) {
                        Some(v) => cp = cp * 16 + v as u32,
                        None => ok = false,
                    }
                }
                if ok {
                    if (0xD800..=0xDFFF).contains(&cp) {
                        push_cp(&mut out, 0xFFFD);
                    } else {
                        push_cp(&mut out, cp);
                    }
                    i += 6;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            b'%' if i + 2 < b.len() && hex_val(b[i + 1]).is_some() && hex_val(b[i + 2]).is_some() => {
                let v = hex_val(b[i + 1]).unwrap() * 16 + hex_val(b[i + 2]).unwrap();
                out.push(v);
                i += 3;
            }
            _ => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_entity_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let cs: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == '&' {
            if let Some(semi) = cs[i + 1..].iter().position(|&c| c == ';').map(|p| i + 1 + p) {
                if semi - i <= 12 {
                    let body: String = cs[i + 1..semi].iter().collect();
                    if let Some(c) = decode_entity(&body) {
                        out.push(c);
                        i = semi + 1;
                        continue;
                    }
                }
            }
            // 无分号的数字实体:&#39 与 &#x27
            if i + 2 < cs.len() && cs[i + 1] == '#' {
                if let Some(n) = parse_num_entity(&cs[i + 2..], &mut 0) {
                    out.push(n);
                    continue;
                }
            }
        }
        out.push(cs[i]);
        i += 1;
    }
    out
}

fn decode_entity(body: &str) -> Option<char> {
    match body {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        _ => {
            let inner = body
                .strip_prefix("#x")
                .map(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| body.strip_prefix('#').map(|d| d.parse::<u32>().ok()))??;
            char::from_u32(inner)
        }
    }
}

fn parse_num_entity(cs: &[char], _used: &mut usize) -> Option<char> {
    let mut j = 0;
    let hex = j < cs.len() && (cs[j] == 'x' || cs[j] == 'X');
    if hex {
        j += 1;
    }
    let mut v = 0u32;
    let start = j;
    while j < cs.len() && j - start <= 8 {
        let d = cs[j].to_digit(if hex { 16 } else { 10 })?;
        v = v * (if hex { 16 } else { 10 }) + d;
        j += 1;
        // 遇到非数字时 to_digit 返回 None 退出;这里只在紧邻数字全消费后接受
        if j < cs.len() && cs[j].to_digit(if hex { 16 } else { 10 }).is_none() {
            break;
        }
    }
    if j == start {
        return None;
    }
    char::from_u32(v)
}

fn compress_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

fn base64_decode(s: &str) -> String {
    let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let b = filtered.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let mut quad = [0u8; 4];
    let mut n = 0usize;
    let mut pad = 0usize;
    let mut bad = false;
    for &c in b {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                0
            }
            _ => {
                bad = true;
                break;
            }
        };
        quad[n % 4] = v;
        n += 1;
        if n % 4 == 0 {
            let t = ((quad[0] as u32) << 18) | ((quad[1] as u32) << 12) | ((quad[2] as u32) << 6) | (quad[3] as u32);
            out.push((t >> 16) as u8);
            if pad < 2 {
                out.push((t >> 8) as u8);
            }
            if pad < 1 {
                out.push(t as u8);
            }
            if pad > 0 {
                break;
            }
        }
    }
    if bad || n % 4 != 0 || pad > 2 {
        // 非法 base64:保持原文(与 ModSecurity 宽松行为一致)
        return s.to_string();
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// t:cmdLine:Windows 风格命令行归一化 —— `/` → `\`,删除 `\` `"` `'`。
fn cmd_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '/' => out.push('\\'),
            '\\' | '"' | '\'' => {}
            c => out.push(c),
        }
    }
    out
}

fn utf8_to_unicode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp < 128 {
            out.push(c);
        } else if cp <= 0xFFFF {
            out.push_str(&format!("\\u{cp:04x}"));
        } else {
            let v = cp - 0x10000;
            out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF)));
        }
    }
    out
}

fn js_decode(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == '\\' && i + 1 < cs.len() {
            let c = cs[i + 1];
            i += 2;
            match c {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'v' => out.push('\u{b}'),
                '0' => out.push('\0'),
                'u' => {
                    let mut cp = 0u32;
                    let mut ok = true;
                    for k in 0..4 {
                        match cs.get(i + k).and_then(|c| c.to_digit(16)) {
                            Some(d) => cp = cp * 16 + d,
                            None => ok = false,
                        }
                    }
                    if ok {
                        i += 4;
                        push_cp_str(&mut out, cp);
                    } else {
                        out.push('u');
                    }
                }
                'x' => {
                    let mut cp = 0u32;
                    let mut ok = true;
                    for k in 0..2 {
                        match cs.get(i + k).and_then(|c| c.to_digit(16)) {
                            Some(d) => cp = cp * 16 + d,
                            None => ok = false,
                        }
                    }
                    if ok {
                        i += 2;
                        push_cp_str(&mut out, cp);
                    } else {
                        out.push('x');
                    }
                }
                c => out.push(c),
            }
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    out
}

fn css_decode(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == '\\' && i + 1 < cs.len() && cs[i + 1].is_ascii_hexdigit() {
            let mut cp = 0u32;
            let mut j = i + 1;
            while j < cs.len() && j - (i + 1) < 6 && cs[j].is_ascii_hexdigit() {
                cp = cp * 16 + cs[j].to_digit(16).unwrap();
                j += 1;
            }
            // 可选尾随空白
            if j < cs.len() && cs[j].is_whitespace() {
                j += 1;
            }
            push_cp_str(&mut out, cp);
            i = j;
        } else if cs[i] == '\\' && i + 1 < cs.len() {
            out.push(cs[i + 1]);
            i += 2;
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    out
}

/// `/* ... */` → 空格;未闭合注释截断到结尾(SQL 语义)。
fn replace_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            match s[i + 2..].find("*/") {
                Some(pos) => {
                    out.push(' ');
                    i = i + 2 + pos + 2;
                }
                None => {
                    out.push(' ');
                    i = b.len();
                }
            }
        } else {
            out.push(s[i..].chars().next().unwrap());
            i += s[i..].chars().next().unwrap().len_utf8();
        }
    }
    out
}

fn normalize_path(s: &str, win: bool) -> String {
    let unified: String = if win {
        s.replace('\\', "/")
    } else {
        s.to_string()
    };
    let absolute = unified.starts_with('/');
    let mut segs: Vec<&str> = Vec::new();
    for seg in unified.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if let Some(last) = segs.last() {
                    if *last != ".." {
                        segs.pop();
                        continue;
                    }
                }
                segs.push("..");
            }
            s => segs.push(s),
        }
    }
    let mut out = String::new();
    if absolute {
        out.push('/');
    }
    out.push_str(&segs.join("/"));
    out
}

fn escape_seq_decode(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == '\\' && i + 1 < cs.len() {
            let c = cs[i + 1];
            i += 2;
            match c {
                'a' => out.push('\u{7}'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'v' => out.push('\u{b}'),
                'x' => {
                    let mut cp = 0u32;
                    let mut ok = true;
                    for k in 0..2 {
                        match cs.get(i + k).and_then(|c| c.to_digit(16)) {
                            Some(d) => cp = cp * 16 + d,
                            None => ok = false,
                        }
                    }
                    if ok {
                        i += 2;
                        push_cp_str(&mut out, cp);
                    } else {
                        out.push('x');
                    }
                }
                '0'..='7' => {
                    let mut cp = c.to_digit(8).unwrap();
                    let mut k = 0;
                    while k < 2 {
                        match cs.get(i).and_then(|c| c.to_digit(8)) {
                            Some(d) => {
                                cp = cp * 8 + d;
                                k += 1;
                                i += 1;
                            }
                            None => break,
                        }
                    }
                    push_cp_str(&mut out, cp);
                }
                c => out.push(c),
            }
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(name: &str, input: &str) -> String {
        Transform::parse(name).expect("known transform").apply(input)
    }

    #[test]
    fn url_decode_uni_cases() {
        assert_eq!(one("urlDecodeUni", "a%20b+c"), "a b+c"); // 不转 +
        assert_eq!(one("urlDecodeUni", "%3Cscript%3E"), "<script>");
        assert_eq!(one("urlDecodeUni", "%u003c"), "<");
        assert_eq!(one("urlDecodeUni", "%uD83D%uDE00"), "😀");
        assert_eq!(one("urlDecodeUni", "100%"), "100%");
    }

    #[test]
    fn html_entities() {
        assert_eq!(one("htmlEntityDecode", "&lt;script&gt;"), "<script>");
        assert_eq!(one("htmlEntityDecode", "&#39;x&#34;"), "'x\"");
        assert_eq!(one("htmlEntityDecode", "&#x3c;"), "<");
        assert_eq!(one("htmlEntityDecode", "&amp;"), "&");
    }

    #[test]
    fn misc_transforms() {
        assert_eq!(one("lowercase", "AbC"), "abc");
        assert_eq!(one("compressWhitespace", "a \t\n b"), "a b");
        assert_eq!(one("removeNulls", "a\u{0}b"), "ab");
        assert_eq!(one("base64Decode", "PGI+dGVzdDwvYj4="), "<b>test</b>");
        assert_eq!(one("base64Decode", "not base64!!"), "not base64!!");
        assert_eq!(one("cmdLine", r#"c"a"t /etc/passwd"#), r"cat \etc\passwd");
        assert_eq!(one("removeWhitespace", " a b\tc "), "abc");
        assert_eq!(one("replaceComments", "sel/**/ect"), "sel ect");
        assert_eq!(one("normalizePath", "/a/../b/./c"), "/b/c");
        assert_eq!(one("normalizePath", "../../etc/passwd"), "../../etc/passwd");
        assert_eq!(one("normalizePathWin", "..\\..\\x"), "../../x");
        assert_eq!(one("length", "abcd"), "4");
        assert_eq!(one("hexEncode", "AB"), "4142");
        assert_eq!(one("jsDecode", "\\u003cscript\\u003e"), "<script>");
        assert_eq!(one("cssDecode", "\\3c script"), "<script");
        assert_eq!(one("escapeSeqDecode", "\\x41\\102"), "AB");
        assert_eq!(one("removeCommentsChar", "a/*b*/c--d"), "abcd");
        // utf8toUnicode + urlDecodeUni 往返(双编码场景)
        assert_eq!(
            apply_all(
                &[
                    Transform::parse("utf8ToUnicode").unwrap(),
                    Transform::parse("urlDecodeUni").unwrap()
                ],
                "😀x"
            ),
            "😀x"
        );
        // sha1 已知向量
        assert_eq!(one("sha1", "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}
