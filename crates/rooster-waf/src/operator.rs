//! 操作符:`@rx/@pm/@pmFromFile/@streq/@contains/@beginsWith/@endsWith/
//! @within/@ipMatch/@detectSQLi/@detectXSS` 加 CRS 依赖的数值比较与校验类操作符,
//! 以及裸 `/regex/` 形式与 `!` 取反。
//!
//! CRS 的正则是 PCRE 方言;rust `regex` 不支持环视、反向引用与占有量词。
//! 加载时先原样编译,失败后做一次最小净化(分支复用组 `(?|` → `(?:`、
//! 占有量词降级为贪婪、`\Q..\E` 字面化),再失败才跳过该规则。

use std::net::IpAddr;
use std::path::Path;

use regex::RegexBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NumKind {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug)]
pub(crate) enum Operator {
    Rx {
        re: regex::Regex,
        negate: bool,
    },
    /// @pm / @pmFromFile:大小写不敏感的词组包含(词组来自空格分隔参数或 .data 文件)
    Pm {
        words: Vec<String>,
        negate: bool,
    },
    Streq {
        s: String,
        negate: bool,
    },
    Contains {
        s: String,
        negate: bool,
    },
    BeginsWith {
        s: String,
        negate: bool,
    },
    EndsWith {
        s: String,
        negate: bool,
    },
    /// 输入是参数串的子串(参数可含 %{TX.*} 宏,运行时展开)
    Within {
        param: String,
        negate: bool,
    },
    IpMatch {
        entries: Vec<IpEntry>,
        negate: bool,
    },
    DetectSQLi {
        negate: bool,
    },
    DetectXSS {
        negate: bool,
    },
    Num {
        kind: NumKind,
        param: String,
        negate: bool,
    },
    ValidateByteRange {
        ranges: Vec<(u8, u8)>,
        negate: bool,
    },
    ValidateUrlEncoding {
        negate: bool,
    },
    ValidateUtf8Encoding {
        negate: bool,
    },
    UnconditionalMatch {
        negate: bool,
    },
}

#[derive(Debug)]
pub(crate) enum IpEntry {
    Exact(IpAddr),
    Cidr { addr: IpAddr, prefix: u8 },
}

impl Operator {
    pub(crate) fn negate(&self) -> bool {
        match self {
            Operator::Rx { negate, .. }
            | Operator::Pm { negate, .. }
            | Operator::Streq { negate, .. }
            | Operator::Contains { negate, .. }
            | Operator::BeginsWith { negate, .. }
            | Operator::EndsWith { negate, .. }
            | Operator::Within { negate, .. }
            | Operator::IpMatch { negate, .. }
            | Operator::DetectSQLi { negate }
            | Operator::DetectXSS { negate }
            | Operator::Num { negate, .. }
            | Operator::ValidateByteRange { negate, .. }
            | Operator::ValidateUrlEncoding { negate }
            | Operator::ValidateUtf8Encoding { negate }
            | Operator::UnconditionalMatch { negate } => *negate,
        }
    }

    /// `capture` 动作写入的 `tx.0..tx.9`(`@rx` 取正则捕获组;其余操作符
    /// 按 ModSecurity 语义把整个匹配值存入 `tx.0`)。
    ///
    /// 正则**没有捕获组**时,ModSecurity 把整个匹配放进 `tx.0`——CRS 的
    /// `setvar:'tx.foo=|%{tx.0}|'` 大量依赖这一点(920420 即是)。
    pub(crate) fn captures(&self, value: &str) -> Vec<String> {
        match self {
            Operator::Rx { re, .. } => match re.captures(value) {
                Some(c) if c.len() > 1 => (1..=9)
                    .map(|i| c.get(i).map(|m| m.as_str().to_string()).unwrap_or_default())
                    .collect(),
                Some(c) => vec![c
                    .get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| value.to_string())],
                None => vec![value.to_string()],
            },
            _ => vec![value.to_string()],
        }
    }

    /// 对单个值求「正向匹配」结果(取反由调用方结合值集合语义处理)。
    /// `expand` 用于运行时展开操作符参数中的 `%{...}` 宏。
    pub(crate) fn matches(&self, value: &str, expand: &dyn Fn(&str) -> String) -> bool {
        match self {
            Operator::Rx { re, .. } => re.is_match(value),
            Operator::Pm { words, .. } => {
                let lower = value.to_lowercase();
                words.iter().any(|w| lower.contains(w.as_str()))
            }
            Operator::Streq { s, .. } => value == s,
            Operator::Contains { s, .. } => value.contains(s.as_str()),
            Operator::BeginsWith { s, .. } => value.starts_with(s.as_str()),
            Operator::EndsWith { s, .. } => value.ends_with(s.as_str()),
            Operator::Within { param, .. } => {
                if value.is_empty() {
                    return false;
                }
                expand(param).contains(value)
            }
            Operator::IpMatch { entries, .. } => match value.trim().parse::<IpAddr>() {
                Ok(ip) => entries.iter().any(|e| ip_entry_matches(e, ip)),
                Err(_) => false,
            },
            Operator::DetectSQLi { .. } => crate::detect::detect_sqli(value),
            Operator::DetectXSS { .. } => crate::detect::detect_xss(value),
            Operator::Num { kind, param, .. } => {
                let lhs = value.trim().parse::<i64>();
                let rhs = expand(param).trim().parse::<i64>();
                match (lhs, rhs) {
                    (Ok(a), Ok(b)) => match kind {
                        NumKind::Eq => a == b,
                        NumKind::Lt => a < b,
                        NumKind::Le => a <= b,
                        NumKind::Gt => a > b,
                        NumKind::Ge => a >= b,
                    },
                    _ => false,
                }
            }
            // ModSecurity validate 系语义:校验「失败」时才匹配
            // (如 920270 用 @validateByteRange 1-255 拦 null 字节)。
            Operator::ValidateByteRange { ranges, .. } => {
                !value.bytes().all(|b| ranges.iter().any(|&(lo, hi)| b >= lo && b <= hi))
            }
            Operator::ValidateUrlEncoding { .. } => {
                let b = value.as_bytes();
                let mut i = 0;
                let mut ok = true;
                while i < b.len() {
                    match b[i] {
                        b'%' => {
                            if i + 2 >= b.len()
                                || !b[i + 1].is_ascii_hexdigit()
                                || !b[i + 2].is_ascii_hexdigit()
                            {
                                ok = false;
                                break;
                            }
                            i += 3;
                        }
                        c if c < 0x20 => {
                            ok = false;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                !ok
            }
            // 值来自有损 UTF-8 转换后的 String:以 U+FFFD 出现近似判定原始非法序列
            Operator::ValidateUtf8Encoding { .. } => value.contains('\u{fffd}'),
            Operator::UnconditionalMatch { .. } => true,
        }
    }
}

fn ip_entry_matches(e: &IpEntry, ip: IpAddr) -> bool {
    match e {
        IpEntry::Exact(a) => *a == ip,
        IpEntry::Cidr { addr, prefix } => match (addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(v)) => {
                let p = *prefix as u32;
                if p > 32 {
                    return false;
                }
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                (u32::from(*net) & mask) == (u32::from(v) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(v)) => {
                let p = *prefix as u32;
                if p > 128 {
                    return false;
                }
                let net = u128::from(*net);
                let v = u128::from(v);
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                (net & mask) == (v & mask)
            }
            _ => false,
        },
    }
}

/// 从操作符 token 构建。`base_dir` 用于 `@pmFromFile` 的 `.data` 相对路径。
pub(crate) fn build(token: &str, base_dir: Option<&Path>) -> Result<Operator, String> {
    let (negate, body) = match token.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, token),
    };
    if let Some(op) = body.strip_prefix('@') {
        let (name, param) = match op.split_once(' ') {
            Some((n, p)) => (n, p),
            None => (op, ""),
        };
        match name {
            "rx" => {
                let re = compile_regex(param)?;
                Ok(Operator::Rx { re, negate })
            }
            "pm" => Ok(Operator::Pm {
                words: param
                    .split_whitespace()
                    .map(|w| w.to_lowercase())
                    .collect(),
                negate,
            }),
            "pmFromFile" => {
                let file = param.trim();
                let path = match base_dir {
                    Some(dir) => dir.join(file),
                    None => Path::new(file).to_path_buf(),
                };
                let content = std::fs::read_to_string(&path)
                    .map_err(|_| format!("rule:data-file:{file}"))?;
                let words = content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| l.to_lowercase())
                    .collect();
                Ok(Operator::Pm { words, negate })
            }
            "streq" => Ok(Operator::Streq {
                s: param.to_string(),
                negate,
            }),
            "contains" => Ok(Operator::Contains {
                s: param.to_string(),
                negate,
            }),
            "beginsWith" => Ok(Operator::BeginsWith {
                s: param.to_string(),
                negate,
            }),
            "endsWith" => Ok(Operator::EndsWith {
                s: param.to_string(),
                negate,
            }),
            "within" => Ok(Operator::Within {
                param: param.to_string(),
                negate,
            }),
            "ipMatch" => {
                let mut entries = Vec::new();
                for ent in param.split(',') {
                    let ent = ent.trim();
                    if ent.is_empty() {
                        continue;
                    }
                    match ent.split_once('/') {
                        Some((addr, prefix)) => {
                            let addr: IpAddr = addr
                                .trim()
                                .parse()
                                .map_err(|_| format!("rule:operator:@ipMatch({ent})"))?;
                            let prefix: u8 = prefix
                                .trim()
                                .parse()
                                .map_err(|_| format!("rule:operator:@ipMatch({ent})"))?;
                            entries.push(IpEntry::Cidr { addr, prefix });
                        }
                        None => {
                            let addr: IpAddr = ent
                                .parse()
                                .map_err(|_| format!("rule:operator:@ipMatch({ent})"))?;
                            entries.push(IpEntry::Exact(addr));
                        }
                    }
                }
                Ok(Operator::IpMatch { entries, negate })
            }
            "detectSQLi" => Ok(Operator::DetectSQLi { negate }),
            "detectXSS" => Ok(Operator::DetectXSS { negate }),
            "eq" => Ok(Operator::Num {
                kind: NumKind::Eq,
                param: param.to_string(),
                negate,
            }),
            "lt" => Ok(Operator::Num {
                kind: NumKind::Lt,
                param: param.to_string(),
                negate,
            }),
            "le" => Ok(Operator::Num {
                kind: NumKind::Le,
                param: param.to_string(),
                negate,
            }),
            "gt" => Ok(Operator::Num {
                kind: NumKind::Gt,
                param: param.to_string(),
                negate,
            }),
            "ge" => Ok(Operator::Num {
                kind: NumKind::Ge,
                param: param.to_string(),
                negate,
            }),
            "validateByteRange" => {
                let mut ranges = Vec::new();
                for part in param.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    match part.split_once('-') {
                        Some((a, b)) => {
                            let a: u8 = a
                                .trim()
                                .parse()
                                .map_err(|_| format!("rule:operator:@validateByteRange({part})"))?;
                            let b: u8 = b
                                .trim()
                                .parse()
                                .map_err(|_| format!("rule:operator:@validateByteRange({part})"))?;
                            ranges.push((a, b));
                        }
                        None => {
                            let v: u8 = part
                                .parse()
                                .map_err(|_| format!("rule:operator:@validateByteRange({part})"))?;
                            ranges.push((v, v));
                        }
                    }
                }
                Ok(Operator::ValidateByteRange { ranges, negate })
            }
            "validateUrlEncoding" => Ok(Operator::ValidateUrlEncoding { negate }),
            "validateUtf8Encoding" => Ok(Operator::ValidateUtf8Encoding { negate }),
            "unconditionalMatch" => Ok(Operator::UnconditionalMatch { negate }),
            other => Err(format!("rule:operator:@{other}")),
        }
    } else if body.starts_with('/') && body.ends_with('/') && body.len() >= 2 {
        let re = compile_regex(&body[1..body.len() - 1])?;
        Ok(Operator::Rx { re, negate })
    } else {
        // 无显式操作符:按正则处理(SecLang 默认)
        let re = compile_regex(body)?;
        Ok(Operator::Rx { re, negate })
    }
}

/// 先按原文编译,失败后尝试 PCRE 净化,再编译。
pub(crate) fn compile_regex(pat: &str) -> Result<regex::Regex, String> {
    let build = |p: &str| {
        RegexBuilder::new(p)
            .size_limit(64 * 1024 * 1024)
            .build()
            .map_err(|e| e.to_string())
    };
    build(pat).or_else(|e| build(&sanitize_pcre(pat)).map_err(|_| format!("rule:regex-compile: {e}")))
}

/// PCRE → rust-regex 的最小净化:
/// 1. `\Q...\E` 字面量段;2. 分支复用组 `(?|` → `(?:`;3. 占有量词 `X*+` → `X*`。
pub(crate) fn sanitize_pcre(pat: &str) -> String {
    let quoted = quote_literals(pat);
    let cs: Vec<char> = quoted.chars().collect();
    let mut out = String::with_capacity(quoted.len());
    let mut i = 0;
    let mut in_class = false;
    while i < cs.len() {
        let c = cs[i];
        if c == '\\' {
            out.push(c);
            if i + 1 < cs.len() {
                out.push(cs[i + 1]);
            }
            i += 2;
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            out.push(c);
            i += 1;
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                out.push(c);
                i += 1;
                if i < cs.len() && cs[i] == '^' {
                    out.push('^');
                    i += 1;
                }
                if i < cs.len() && cs[i] == ']' {
                    out.push(']');
                    i += 1;
                }
            }
            '(' => {
                // 分支复用组 (?| → (?:;其余组头原样透传
                if i + 2 < cs.len() && cs[i + 1] == '?' && cs[i + 2] == '|' {
                    out.push_str("(?:");
                    i += 3;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            '*' | '+' | '?' => {
                out.push(c);
                i += 1;
                // 占有量词标记:量化符后的 '+' 丢弃('?' 为懒惰,保留)
                if i < cs.len() && cs[i] == '+' {
                    i += 1;
                }
            }
            '{' => {
                out.push(c);
                i += 1;
                while i < cs.len() && cs[i] != '}' {
                    out.push(cs[i]);
                    i += 1;
                }
                if i < cs.len() {
                    out.push('}');
                    i += 1;
                }
                if i < cs.len() && cs[i] == '+' {
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn quote_literals(pat: &str) -> String {
    if !pat.contains("\\Q") {
        return pat.to_string();
    }
    let mut out = String::with_capacity(pat.len());
    let mut rest = pat;
    while let Some(pos) = rest.find("\\Q") {
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 2..];
        let end = rest.find("\\E").unwrap_or(rest.len());
        out.push_str(&regex::escape(&rest[..end]));
        rest = &rest[end..];
        rest = rest.strip_prefix("\\E").unwrap_or(rest);
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(op: &Operator, v: &str) -> bool {
        // matches() 返回正向结果;取反由引擎结合值集合处理
        op.matches(v, &|s| s.to_string())
    }

    #[test]
    fn string_operators() {
        assert!(m(&build("@streq abc", None).unwrap(), "abc"));
        let neg = build("!@streq abc", None).unwrap();
        assert!(neg.negate());
        assert!(m(&neg, "abc")); // 正向命中,引擎按「无值命中」取反
        assert!(m(&build("@contains mid", None).unwrap(), "amidb"));
        assert!(m(&build("@beginsWith pre", None).unwrap(), "prefix"));
        assert!(m(&build("@endsWith post", None).unwrap(), "1post"));
        // @within:输入是参数串的子串
        assert!(m(&build("@within GET HEAD POST", None).unwrap(), "GET"));
        assert!(m(&build("@within |utf-8| |json|", None).unwrap(), "utf-8"));
        assert!(!m(&build("@within GET HEAD", None).unwrap(), "TRACE"));
        assert!(!m(&build("@within GET HEAD", None).unwrap(), ""));
    }

    #[test]
    fn numeric_operators() {
        let expand = |s: &str| -> String {
            if s == "%{tx.thr}" {
                "5".to_string()
            } else {
                // 生产语义(expand_macros):非宏文本原样透传
                s.to_string()
            }
        };
        let op = build("@ge %{tx.thr}", None).unwrap();
        assert!(op.matches("5", &expand));
        assert!(!op.matches("4", &expand));
        assert!(!op.matches("", &expand)); // 非数字不匹配
        assert!(build("@eq 0", None).unwrap().matches("0", &expand));
    }

    #[test]
    fn pm_and_ip() {
        let op = build("@pm Foo Bar", None).unwrap();
        assert!(m(&op, "xxfoOxx")); // 大小写不敏感
        let ip = build("@ipMatch 127.0.0.1,10.0.0.0/8,::1", None).unwrap();
        assert!(m(&ip, "127.0.0.1"));
        assert!(m(&ip, "10.1.2.3"));
        assert!(m(&ip, "::1"));
        assert!(!m(&ip, "192.168.1.1"));
        assert!(!m(&ip, ""));
    }

    #[test]
    fn byte_range_and_encoding() {
        // validate 系语义:校验失败才匹配(见 operator::matches 注释)
        let op = build("@validateByteRange 32-36,38-126", None).unwrap();
        assert!(!m(&op, "abc ! ~")); // 全部在范围内 → 不命中
        assert!(m(&op, "a\tb")); // 9 不在集合 → 命中
        assert!(!build("@validateByteRange 9,10,13", None).unwrap().matches("\n\r", &|_| "".into()));
        let url = build("@validateUrlEncoding", None).unwrap();
        assert!(!m(&url, "a=1&b=%20")); // 合法编码 → 不命中
        assert!(m(&url, "100%")); // 非法编码 → 命中
    }

    #[test]
    fn bare_regex_and_negation() {
        let op = build("/^ab/", None).unwrap();
        assert!(m(&op, "abc"));
        let neg = build("!@rx ^x", None).unwrap();
        assert!(neg.negate());
        assert!(m(&neg, "xyz"));
        assert!(!m(&neg, "abc"));
    }

    #[test]
    fn pcre_sanitize_cases() {
        assert_eq!(sanitize_pcre(r"a(?|b|c)"), r"a(?:b|c)");
        assert_eq!(sanitize_pcre(r"a*+b"), r"a*b");
        assert_eq!(sanitize_pcre(r"a++b"), r"a+b");
        assert_eq!(sanitize_pcre(r"a?+b"), r"a?b");
        assert_eq!(sanitize_pcre(r"a{2,3}+b"), r"a{2,3}b");
        assert_eq!(sanitize_pcre(r"\?+b"), r"\?+b"); // 转义字面量后的 + 是普通量词
        assert_eq!(sanitize_pcre(r"\d++b"), r"\d+b");
        assert_eq!(sanitize_pcre(r"a+?b"), r"a+?b"); // 懒惰量词保留
        assert_eq!(sanitize_pcre(r"[a*+b]c"), r"[a*+b]c"); // 字符类内不动
        let q = sanitize_pcre(r"\Qa.b+c\E");
        assert!(regex::Regex::new(&q).unwrap().is_match("xa.b+cy"));
        // rust regex 把 `X*+` 接受为「重复的重复」,语义无害;无法直接编译时才净化
        assert!(compile_regex(r"(?i)(?:a|b)*+c").is_ok());
        assert!(compile_regex(r"a{2,3}+b").is_ok());
    }

    #[test]
    fn unsupported_operator_is_error() {
        assert!(build("@frobnicate 1", None).is_err());
    }
}
