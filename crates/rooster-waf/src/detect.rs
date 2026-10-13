//! `@detectSQLi` / `@detectXSS` 的 Rust 等价启发式实现。
//!
//! # 实现方式与局限
//!
//! libinjection 的做法是把输入切分为 token、映射为字符类别指纹后在已知
//! 攻击指纹表中查找;本实现采用等价的「信号分级 + 类别去重」启发式:
//! 强信号(union select、真正的永真式、引号破出后紧跟注释或 or/and+比较、
//! 堆叠注入、时间盲注函数、`<script>`/`javascript:` URI/带引号的事件
//! 处理器)命中其一即判定。弱信号另有前置条件:必须先有一个**语法边界
//! 突破**(未配对的引号),再凑够 2 个不同类别(注释形/关键词形/语句形状)。
//! XSS 则需 3 个不同中信号类别(单个 `eval(` 或 `document.cookie` 不判)。
//!
//! 永真式按 libinjection 的 tautology 定义实现:比较符两侧必须是**同一个
//! token**(`'1'='1`、`1=1`、`a<>a`)。这是与旧实现的关键差别 —— 旧的
//! `\b(?:or|and)\b ... \w+ ... =` 会把自然语言和配置里的 `and id=1`、
//! `and temperature=0.7`、`or dog=2` 当成永真式,LLM/API 流量的 SQLi 误报
//! 绝大部分来自这里。
//!
//! 每个信号在一组探针(原串 / 单层 URL 解码 / HTML 实体解码)上**最多计
//! 一次**。旧实现逐探针累加,解码不变时同一信号被计两遍,`weak >= 3` 实际
//! 等价于「2 类弱信号即判阳」。
//!
//! 已知局限:这是启发式而非完整 libinjection 指纹库。
//! - 极端混淆(超长注释穿插、宽字节注入)可能漏报。
//! - 不含引号破出的裸 SQL 语句(`SELECT * FROM t WHERE a='b'`)判阴:它
//!   没有注入所需的「语法边界突破」,与 libinjection 行为一致。
//! - 讲解注入原理的正文若同时含引号破出与注释(如 `' or 1=1 --`),仍会
//!   判阳;按站点排除规则或用 `waf.mode: detect` 消化。

use std::sync::OnceLock;

use crate::transform;

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
// 永真式:两侧同一 token 才算(`'1'='1` / `1=1` / `'a' like 'a'`)。
static_re!(RE_TAUTOLOGY_PAIR, r#"(?i)\b(?:or|and)\b[\s\x00-\x2f]{0,8}['"]?(\w+)['"]?\s*(?:=|<>|!=|\blike\b|\bregexp\b)\s*['"]?(\w+)"#);
// 引号破出后紧跟 or/and 再接比较(`' or 'a'='b`、`' and 1=2`):
// 重点是引号必须**紧贴**逻辑符 —— 自然语言里的 `and id=1`、`or dog=2`
// 没有这个相邻关系。
static_re!(RE_TAUTOLOGY_AFTER_BREAK, r#"(?i)['"`]\s*\b(?:or|and)\b[\s\x00-\x2f]{0,8}['"]?\w{1,16}['"]?\s*(?:=|<>|!=|\blike\b|\bregexp\b)"#);
static_re!(RE_ALWAYS_TRUE, r#"(?i)['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1|1\s*=\s*1\s*--|[\d'\"]\s*(?:or|and)\s+(?:true|false)\b"#);
// 引号破出后紧跟 SQL 注释(`admin'--`、`1'/*`):注入的边界突破特征。
static_re!(RE_QUOTE_BREAK_COMMENT, r#"(?s)['"`]\s*(?:--|#|/\*)"#);
static_re!(RE_STACKED, r"(?i)[;\x0a\x0d]\s*(?:drop|delete|truncate|insert|update|shutdown|alter|create|exec(?:ute)?|grant)\b");
static_re!(RE_SLEEP, r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message|pg_read_file)\s*\(");
static_re!(RE_SQL_COMMENT, r"(?:--(?:\s|$|[\x0a\x0d])|/\*|\*/|#(?:\s|$))");
static_re!(RE_SQL_KEYWORD, r"(?i)\b(?:select|insert|update|delete|drop|union|from|where|having|order\s+by|group\s+by|information_schema|benchmark|concat|chr|substr|version)\b");
static_re!(RE_ODD_QUOTE, r"(?i)(?:^|[^\\])'");
// 「语句形状」:SQL 动词在 60 字符内接子句关键词。
static_re!(RE_SQL_SHAPE, r"(?is)\b(?:select|insert|update|delete)\b[\s\S]{0,60}\b(?:from|where|values|set)\b");

/// 解码探针集合:原串 + 单层 `%XX`/HTML 实体解码,内容相同的只留一个。
fn probes(input: &str) -> Vec<String> {
    let mut out = vec![input.to_string()];
    let once = transform::url_decode_uni(input, false);
    let entity = transform::apply_all(&[transform::Transform::HtmlEntityDecode], &once);
    // 双重编码探针(旧 xss 路径有,sqli 路径没有):保持覆盖不降级。
    let twice = transform::url_decode_uni(&entity, false);
    push_new(&mut out, once);
    push_new(&mut out, entity);
    push_new(&mut out, twice);
    out
}

fn push_new(probes: &mut Vec<String>, value: String) {
    if !value.is_empty() && !probes.contains(&value) {
        probes.push(value);
    }
}

/// 任一探针命中即算一类信号(类别只计一次)。
fn any_hit(probes: &[String], re: &'static regex::Regex) -> bool {
    probes.iter().any(|p| re.is_match(p))
}

/// 永真式:比较符两侧必须是同一个 token。
fn is_tautology(probes: &[String]) -> bool {
    probes.iter().find_map(|p| RE_TAUTOLOGY_PAIR().captures(p)).is_some_and(|c| {
        c[1].eq_ignore_ascii_case(&c[2])
    })
}

/// 弱信号必须附在一个**语法边界突破**上:未配对的引号(字符串字面量
/// 被提前结束)。一段完整、引号配平的 SQL 代码示例只是 SQL,不是注入 ——
/// 这正是 LLM 回复回带进 messages 后被判阳的主因。
fn has_break(probes: &[String]) -> bool {
    any_hit(probes, RE_ODD_QUOTE())
        && probes.iter().any(|p| p.matches('\'').count() % 2 == 1)
}

/// SQL 注入启发式检测。
pub(crate) fn detect_sqli(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    let probes = probes(input);

    let strong = any_hit(&probes, RE_UNION_SELECT())
        || is_tautology(&probes)
        || any_hit(&probes, RE_TAUTOLOGY_AFTER_BREAK())
        || any_hit(&probes, RE_ALWAYS_TRUE())
        || any_hit(&probes, RE_QUOTE_BREAK_COMMENT())
        || any_hit(&probes, RE_STACKED())
        || any_hit(&probes, RE_SLEEP());
    if strong {
        return true;
    }

    if !has_break(&probes) {
        return false;
    }
    let mut weak = 0;
    if any_hit(&probes, RE_SQL_COMMENT()) {
        weak += 1;
    }
    if any_hit(&probes, RE_SQL_KEYWORD()) {
        weak += 1;
    }
    if any_hit(&probes, RE_SQL_SHAPE()) {
        weak += 1;
    }
    weak >= 2
}

static_re!(RE_XSS_TAG_STRONG, r"(?i)<\s*/?\s*(?:script|iframe|object|embed|svg|math|base|link\s|meta\s+http-equiv|form\s|template)\b");
static_re!(RE_XSS_JS_URI, r"(?i)\b(?:javascript|vbscript|livescript|mocha)\s*:|data\s*:\s*text/html|data\s*:\s*image/svg");
static_re!(RE_XSS_EVENT_QUOTED, r#"(?i)\bon[a-z]{3,30}\s*=\s*["'`]"#);
static_re!(RE_XSS_EVENT_BARE, r#"(?i)[<\s"';(+]on[a-z]{3,30}\s*=[^\s>]"#);
static_re!(RE_XSS_IMG_ONERR, r"(?i)<\s*img\b[^>]{0,200}?\bon(?:error|load)\b");
// 中信号类别 1:DOM/cookie 读取原语。
static_re!(RE_XSS_DOM, r"(?i)\b(?:document\s*\.\s*(?:cookie|write|location|domain)|window\s*\.\s*(?:location|name)|string\.fromcharcode|expression\s*\()");
// 中信号类别 2:可执行函数调用与注入面属性。
static_re!(RE_XSS_CALL, r"(?i)\b(?:alert|eval|prompt|confirm|settimeout|setinterval|fetch|import)\s*\(|\bsrcdoc\s*=");
static_re!(RE_XSS_ENCODED, r"(?i)%(?:3c|60)|&#x?0*(?:3c|60)|\\u003c");

/// XSS 启发式检测。
pub(crate) fn detect_xss(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    let probes = probes(input);

    if any_hit(&probes, RE_XSS_TAG_STRONG())
        || any_hit(&probes, RE_XSS_JS_URI())
        || any_hit(&probes, RE_XSS_EVENT_QUOTED())
        || any_hit(&probes, RE_XSS_IMG_ONERR())
    {
        return true;
    }

    let mut medium = 0;
    for re in [RE_XSS_DOM(), RE_XSS_CALL(), RE_XSS_EVENT_BARE(), RE_XSS_ENCODED()] {
        if any_hit(&probes, re) {
            medium += 1;
        }
    }
    medium >= 3
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
            "%31%27%20or%20%271%27=%271",
            "1' or true",
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
            // 旧实现在这些形态上判阳(and <词> = <值> 被当永真式)
            "如果 and id=1 会重复计数",
            "the model and temperature=0.7 works",
            "Translate O'Brien's letter and keep it natural: cat=1 or dog=2",
            // 裸 SQL 语句:没有注入所需的语法边界突破
            "SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON o.user_id = u.id WHERE u.status = 'active' GROUP BY u.id",
            "/* 用 information_schema 查 version() */",
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
            "<object data=\"x\">",
            "<script>document.cookie;alert(1)</script>",
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
            // 单个中信号类别不再凑数(旧实现按探针重复计数)
            "document.cookie",
            "fetch('/api/data') returns JSON",
            "use eval() with care; document.cookie can leak tokens",
            "<p>Set timeout to 300ms</p>",
        ];
        for n in negatives {
            assert!(!detect_xss(n), "不应误报: {n}");
        }
    }
}
