//! `@detectSQLi` / `@detectXSS` 的 Rust 等价启发式实现。
//!
//! # 实现方式与局限
//!
//! libinjection 的做法是把输入切分为 token、映射为字符类别指纹后在已知
//! 攻击指纹表中查找。本实现采用等价的「信号加权」启发式:强信号(如
//! `union select`、永真式、堆叠注入、`<script>`、`javascript:` URI、
//! 带引号的事件处理器属性)命中其一即判定;弱信号(注释序列、引号失衡、
//! SQL 关键词共现等)需两个以上共同命中。输入先做一轮 `%XX`/HTML 实体
//! 解码以覆盖单层编码载荷(规则链中的 `t:urlDecodeUni` 已处理多轮)。
//!
//! 已知局限:这是启发式而非完整 libinjection 指纹库 —— 极端混淆
//! (超长注释穿插、宽字节注入)可能漏报;包含 `or ... =` 形式的自然语言
//! 文本理论上可能误报(需要等号两侧同时出现引号或数字,已尽量收窄)。

use std::sync::OnceLock;

// 简单起见:为每个固定模式使用独立的 OnceLock。
#[allow(non_snake_case)]
macro_rules! static_re {
    ($name:ident, $pat:expr) => {
        #[allow(non_snake_case)]
        fn $name() -> &'static regex::Regex {
            static RE: OnceLock<regex::Regex> = OnceLock::new();
            RE.get_or_init(|| regex::Regex::new($pat).expect("builtin regex"))
        }
    };
}

static_re!(RE_UNION_SELECT, r"(?i)\bunion(?:\s+(?:all|distinct)\b)?[\s\x00-\x2f]{0,40}?\bselect\b");
static_re!(RE_TAUTOLOGY_QUOTED, r#"(?i)\b(?:or|and)\b[\s\x00-\x2f]{0,8}['"`]?\s*(?:\w+|'')\s*['"`]?\s*(?:=|<>|!=|like\b|\bregexp\b)"#);
static_re!(RE_TAUTOLOGY_NUMERIC, r"(?i)\b(?:or|and)\b\s+\d+\s*(?:=|<>)\s*\d+");
static_re!(RE_ALWAYS_TRUE, r#"(?i)['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1|1\s*=\s*1\s*--|\bor\s+true\b"#);
static_re!(RE_STACKED, r"(?i)[;\x0a\x0d]\s*(?:drop|delete|truncate|insert|update|shutdown|alter|create|exec(?:ute)?|grant)\b");
static_re!(RE_SLEEP, r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message|pg_read_file)\s*\(");
static_re!(RE_SQL_COMMENT, r"(?:--(?:\s|$|[\x0a\x0d])|/\*|\*/|#(?:\s|$))");
static_re!(RE_SQL_KEYWORD, r"(?i)\b(?:select|insert|update|delete|drop|union|from|where|having|order\s+by|group\s+by|information_schema|benchmark|concat|chr|substr|version)\b");
static_re!(RE_ODD_QUOTE, r"(?i)(?:^|[^\\])'");

static_re!(RE_XSS_TAG_STRONG, r"(?i)<\s*/?\s*(?:script|iframe|object|embed|svg|math|base|link\s|meta\s+http-equiv|form\s|template)\b");
static_re!(RE_XSS_JS_URI, r"(?i)\b(?:javascript|vbscript|livescript|mocha)\s*:|data\s*:\s*text/html|data\s*:\s*image/svg");
static_re!(RE_XSS_EVENT_QUOTED, r#"(?i)\bon[a-z]{3,30}\s*=\s*["'`]"#);
static_re!(RE_XSS_EVENT_BARE, r#"(?i)[<\s"';(+]on[a-z]{3,30}\s*=[^\s>]"#);
static_re!(RE_XSS_IMG_ONERR, r"(?i)<\s*img\b[^>]{0,200}?\bon(?:error|load)\b");
static_re!(RE_XSS_DOM, r"(?i)\b(?:document\s*\.\s*(?:cookie|write|location|domain)|window\s*\.\s*(?:location|name)|\balert\s*\(|\beval\s*\(|\bprompt\s*\(|\bconfirm\s*\(|string\.fromcharcode|expression\s*\(|\bsrcdoc\s*=|\bsettimeout\s*\(|\bimport\s*\(|\bfetch\s*\()");
static_re!(RE_XSS_ENCODED, r"(?i)%(?:3c|60)|&#x?0*(?:3c|60)|\\u003c");

/// SQL 注入启发式检测。
pub(crate) fn detect_sqli(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    // 覆盖单层编码:规则链上游的 t:urlDecodeUni 已处理常规解码
    let decoded = crate::transform::url_decode_uni(input, false);
    let decoded = crate::transform::apply_all(
        &[crate::transform::Transform::HtmlEntityDecode],
        &decoded,
    );
    let probes = [input, decoded.as_str()];

    let mut strong = 0;
    let mut weak = 0;
    for p in probes {
        if RE_UNION_SELECT().is_match(p) {
            strong += 1;
        }
        if RE_TAUTOLOGY_QUOTED().is_match(p) || RE_TAUTOLOGY_NUMERIC().is_match(p) {
            strong += 1;
        }
        if RE_ALWAYS_TRUE().is_match(p) {
            strong += 1;
        }
        if RE_STACKED().is_match(p) {
            strong += 1;
        }
        if RE_SLEEP().is_match(p) {
            strong += 1;
        }
        if RE_SQL_COMMENT().is_match(p) {
            weak += 1;
        }
        if RE_SQL_KEYWORD().is_match(p) {
            weak += 1;
        }
        // 引号失衡且总数为奇数
        if RE_ODD_QUOTE().is_match(p) && p.matches('\'').count() % 2 == 1 {
            weak += 1;
        }
    }
    strong > 0 || weak >= 3
}

/// XSS 启发式检测。
pub(crate) fn detect_xss(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    let mut decoded = crate::transform::url_decode_uni(input, false);
    // 双重编码
    let twice = crate::transform::url_decode_uni(&decoded, false);
    decoded = crate::transform::apply_all(
        &[crate::transform::Transform::HtmlEntityDecode],
        &decoded,
    );
    let probes = [input, decoded.as_str(), twice.as_str()];

    let mut strong = 0;
    let mut medium = 0;
    for p in probes {
        if RE_XSS_TAG_STRONG().is_match(p) {
            strong += 1;
        }
        if RE_XSS_JS_URI().is_match(p) {
            strong += 1;
        }
        if RE_XSS_EVENT_QUOTED().is_match(p) {
            strong += 1;
        }
        if RE_XSS_IMG_ONERR().is_match(p) {
            strong += 1;
        }
        if RE_XSS_DOM().is_match(p) {
            medium += 1;
        }
        if RE_XSS_EVENT_BARE().is_match(p) {
            medium += 1;
        }
        if RE_XSS_ENCODED().is_match(p) {
            medium += 1;
        }
    }
    strong > 0 || medium >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_positive_corpus() {
        let positives = [
            "1' union select password from users--",
            "1' OR '1'='1",
            "1 or 1=1",
            "'; DROP TABLE users;--",
            "admin'--",
            "1 UNION ALL SELECT version()",
            "1' AND SLEEP(5)",
            "x' OR 1=1#",
            "id=1 union\x00select null",
            "' and 'a'='a",
        ];
        for p in positives {
            assert!(detect_sqli(p), "应当检出: {p}");
        }
    }

    #[test]
    fn sqli_negative_corpus() {
        let negatives = [
            "hello world",
            "black and white",
            "price=10&qty=2",
            "O'Reilly books",
            "it's a test",
            "user@example.com",
            "a=b&c=d",
            "union of states",
            "select your plan",
            "sleepy cat",
            "history of the world",
        ];
        for n in negatives {
            assert!(!detect_sqli(n), "不应误报: {n}");
        }
    }

    #[test]
    fn xss_positive_corpus() {
        let positives = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<body onload=\"alert(1)\">",
            "onmouseover=\"alert(1)\"",
            "data:text/html;base64,PHNjcmlwdD4=",
            "document.cookie",
            "<object data=\"x\">",
        ];
        for p in positives {
            assert!(detect_xss(p), "应当检出: {p}");
        }
    }

    #[test]
    fn xss_negative_corpus() {
        let negatives = [
            "hello",
            "a<b and c>d",
            "node.js and react.js",
            "e=mc2",
            "price<10&qty>2",
            "background:url(bg.png)",
            "user@example.com",
            "quantity=1&color=red",
            "sunny day",
        ];
        for n in negatives {
            assert!(!detect_xss(n), "不应误报: {n}");
        }
    }
}
