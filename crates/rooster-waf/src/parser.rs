//! SecLang 子集解析器:`SecRule` / `SecAction` → 规则结构;
//! chain 合并、变量/操作符/动作解析;不支持的语法一律跳过并记录原因,
//! 绝不让整体加载失败。
//!
//! # 跳过原因前缀约定(供面板「规则加载报告」与测试统计使用)
//!
//! - `directive:<名称>`:非规则指令(SecMarker、SecRuleUpdateTargetById、
//!   Include 等),不计入规则加载率分母;
//! - `rule:<原因>`:`SecRule`/`SecAction` 本身被跳过,计入加载率分母。

use std::path::Path;

use crate::lexer::{logical_lines, next_token};
use crate::operator::{self, Operator};
use crate::transform::Transform;

use crate::{LoadReport, Skip};

#[derive(Debug)]
pub(crate) struct RawRule {
    pub id: u32,
    pub phase: u8,
    pub conditions: Vec<RawCondition>,
    pub msg: Option<String>,
    /// 严重度权重:CRITICAL=5 / ERROR=4 / WARNING=3 / NOTICE=2 / 未声明=0
    pub severity: u8,
    /// `capture`:把头部命中的正则捕获组写入 `tx.0..tx.9`
    pub capture: bool,
    pub tags: Vec<String>,
    /// tag `paranoia-level/N`;0 表示无标签(任何 PL 下都评估)
    pub min_pl: u8,
}

#[derive(Debug)]
pub(crate) struct RawCondition {
    pub targets: Vec<TargetTerm>,
    pub op: Operator,
    pub transforms: Vec<Transform>,
    /// 本链接自己的 setvar(chain 成员各自携带)。在 ModSecurity 语义下
    /// 链接命中时即执行,不是整条链全命中后统一执行。
    pub setvars: Vec<SetVar>,
}

#[derive(Debug)]
pub(crate) struct TargetTerm {
    /// 规范化为大写的变量名(如 `REQUEST_HEADERS`)
    pub var: String,
    pub selector: Option<Selector>,
    /// `!` 排除前缀:从并集中剔除该选择器命中的元素
    pub negate: bool,
    /// `&` 计数前缀:取该变量(经排除后)的元素个数
    pub count: bool,
}

#[derive(Debug)]
pub(crate) enum Selector {
    Exact(String),
    Rx(Box<regex::Regex>),
}

impl Selector {
    pub(crate) fn matches(&self, name: &str) -> bool {
        match self {
            Selector::Exact(s) => s.eq_ignore_ascii_case(name),
            Selector::Rx(re) => re.is_match(name),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SetVar {
    /// `tx.foo=值`(值可含 %{...} 宏)
    Set { key: String, val: String },
    /// `tx.foo=+N`(数值累加,可为 %{tx.x})
    Inc { key: String, val: String },
    /// `tx.foo=-N`
    Dec { key: String, val: String },
    /// `!tx.foo`
    Unset { key: String },
}

/// 一条逻辑行解析出的规则片段(变量/操作符/动作串,动作串此时保持原文)。
struct Piece {
    line: usize,
    is_action: bool,
    vars: Option<String>,
    op: Option<String>,
    actions: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct Actions {
    id: Option<u32>,
    phase: Option<u8>,
    msg: Option<String>,
    severity: u8,
    setvars: Vec<SetVar>,
    ctl_remove_ids: Vec<u32>,
    tags: Vec<String>,
    chain: bool,
    capture: bool,
    transforms: Vec<Transform>,
}

/// 解析 SecLang 源文本。永不失败:所有不支持的语法都变成 Skip 条目。
pub(crate) fn parse(source: &str, base_dir: Option<&Path>) -> (Vec<RawRule>, LoadReport) {
    let lines = logical_lines(source);
    let mut rules: Vec<RawRule> = Vec::new();
    let mut report = LoadReport::default();
    let mut i = 0;

    while i < lines.len() {
        let head = &lines[i];
        i += 1;
        let text = head.text.trim();
        let (dir, rest) = match text.split_once(char::is_whitespace) {
            Some((d, r)) => (d, r.trim()),
            None => (text, ""),
        };

        if dir != "SecRule" && dir != "SecAction" {
            // 不认识的指令:跳过并告警(Include 也按此处理,不递归展开)
            report
                .skipped
                .push(Skip { line: head.line, reason: format!("directive:{dir}") });
            continue;
        }

        // ---- 收集片段:头部 + chain 成员 ----
        let mut pieces: Vec<Piece> = Vec::new();
        let mut bad: Option<String> = None;
        let mut want_member = true;
        while want_member {
            want_member = false;
            let (line_no, body) = if pieces.is_empty() {
                (head.line, rest.to_string())
            } else {
                let member = &lines[i - 1];
                let t = member.text.trim();
                let (_, r) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
                (member.line, r.trim().to_string())
            };
            match parse_piece(pieces.is_empty(), dir, &body, line_no) {
                Ok(p) => {
                    let chained = parse_actions(p.actions.as_deref().unwrap_or(""))
                        .map(|a| a.chain)
                        .unwrap_or(false);
                    want_member = chained;
                    pieces.push(p);
                }
                Err(reason) => {
                    bad = Some(reason);
                    break;
                }
            }
            if want_member {
                if i >= lines.len() || !lines[i].text.trim_start().starts_with("SecRule") {
                    bad = Some("rule:chain-no-member".to_string());
                    break;
                }
                i += 1; // 消费成员逻辑行
            }
        }

        if let Some(reason) = bad {
            report.skipped.push(Skip { line: head.line, reason });
            continue;
        }
        match compile_rule(&pieces, base_dir) {
            Ok(rule) => {
                report.loaded += 1;
                rules.push(rule);
            }
            Err(reason) => report.skipped.push(Skip { line: head.line, reason }),
        }
    }

    (rules, report)
}

/// 解析单条逻辑行为片段。`is_head` 仅用于错误定位。
fn parse_piece(
    is_head: bool,
    directive: &str,
    rest: &str,
    line: usize,
) -> Result<Piece, String> {
    let is_action = directive == "SecAction";
    let mut rem = rest;
    let mut vars = None;
    let mut op = None;
    if !is_action {
        let (v, r) = next_token(rem).ok_or_else(|| format!("rule:parse:line{line}:missing-variables"))?;
        let (o, r2) = next_token(r).ok_or_else(|| format!("rule:parse:line{line}:missing-operator"))?;
        vars = Some(v);
        op = Some(o);
        rem = r2;
    }
    let actions = next_token(rem).map(|(t, _)| t);
    // 引号外的尾随内容:SecLang 无此形态,保守跳过
    if let Some((_, trailing)) = next_token(rem) {
        if !trailing.trim().is_empty() {
            return Err(format!("rule:parse:line{line}:trailing-content"));
        }
    }
    let _ = is_head;
    Ok(Piece { line, is_action, vars, op, actions })
}

/// 动作串切分:顶层逗号(引号外)。
fn split_actions(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut esc = false;
    for c in s.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    cur.push(c);
                } else if c == ',' {
                    out.push(cur.trim().to_string());
                    cur = String::new();
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn strip_quotes(v: &str) -> &str {
    let v = v.trim();
    if v.len() >= 2 {
        let f = v.chars().next().unwrap();
        let l = v.chars().next_back().unwrap();
        if (f == '\'' || f == '"') && f == l {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn parse_actions(s: &str) -> Result<Actions, String> {
    let mut a = Actions::default();
    for piece in split_actions(s) {
        if piece.is_empty() {
            continue;
        }
        let (name, value) = match piece.split_once(':') {
            Some((n, v)) => (n, Some(v)),
            None => (piece.as_str(), None),
        };
        match name {
            "id" => {
                let v = strip_quotes(value.unwrap_or_default());
                a.id = v.parse::<u32>().ok();
            }
            "phase" => {
                let v = strip_quotes(value.unwrap_or_default());
                a.phase = v.parse::<u8>().ok();
            }
            "msg" => a.msg = Some(strip_quotes(value.unwrap_or_default()).to_string()),
            "severity" => {
                let v = strip_quotes(value.unwrap_or_default()).to_ascii_uppercase();
                a.severity = match v.as_str() {
                    "CRITICAL" | "EMERGENCY" => 5,
                    "ERROR" => 4,
                    "WARNING" => 3,
                    "NOTICE" => 2,
                    "INFO" | "DEBUG" => 1,
                    _ => 0,
                };
            }
            "tag" => a.tags.push(strip_quotes(value.unwrap_or_default()).to_string()),
            "t" => {
                let v = strip_quotes(value.unwrap_or_default());
                match Transform::parse(v) {
                    Some(t) => a.transforms.push(t),
                    None => return Err(format!("rule:transform:t:{v}")),
                }
            }
            "setvar" => {
                let v = strip_quotes(value.unwrap_or_default());
                if let Some(sv) = parse_setvar(v) {
                    a.setvars.push(sv);
                }
                // 解析不了的 setvar 形式按无动作处理,规则仍加载(宽松语义)
            }
            "ctl" => {
                let v = strip_quotes(value.unwrap_or_default());
                if let Some(rest) = v.strip_prefix("ruleRemoveById=") {
                    if let Ok(id) = rest.trim().parse::<u32>() {
                        a.ctl_remove_ids.push(id);
                    }
                }
                // 其余 ctl(requestBodyProcessor / ruleRemoveByTag 等)
                // 解析后忽略:运行时移除由 evaluate() 的 exclusions 参数承担
            }
            "chain" => a.chain = true,
            "capture" => a.capture = true,
            // deny/pass/block/log/nolog/auditlog/noauditlog/multiMatch/
            // ver/rev/status/skipAfter/logdata/initcol 等元数据动作:解析后忽略
            _ => {}
        }
    }
    Ok(a)
}

fn parse_setvar(v: &str) -> Option<SetVar> {
    if let Some(rest) = v.strip_prefix('!') {
        return Some(SetVar::Unset { key: rest.trim().to_lowercase() });
    }
    let (key, val) = v.split_once('=')?;
    let key = key.trim().to_lowercase();
    if let Some(n) = val.strip_prefix('+') {
        Some(SetVar::Inc { key, val: n.to_string() })
    } else if let Some(n) = val.strip_prefix('-') {
        Some(SetVar::Dec { key, val: n.to_string() })
    } else {
        Some(SetVar::Set { key, val: val.to_string() })
    }
}

/// 把片段列表编译为规则。头部动作决定 id/msg/severity;chain 成员的条件
/// 按顺序追加(全部条件都命中才算命中),成员的 setvar / tag / PL 一并合并。
fn compile_rule(pieces: &[Piece], base_dir: Option<&Path>) -> Result<RawRule, String> {
    let head = &pieces[0];
    let head_actions = parse_actions(head.actions.as_deref().unwrap_or(""))?;

    let mut conditions: Vec<RawCondition> = Vec::new();
    let mut tags = head_actions.tags.clone();
    let mut min_pl = pl_from_tags(&head_actions.tags);

    for (idx, p) in pieces.iter().enumerate() {
        if p.is_action {
            if idx != 0 {
                return Err("rule:parse:sec-action-as-chain-member".to_string());
            }
            // SecAction 无变量/操作符,但它的 setvar 必须执行:合成为一个
            // 恒真、无目标的链接,否则 `SecAction "setvar:tx.x=..."` 静默失效。
            conditions.push(RawCondition {
                targets: Vec::new(),
                op: Operator::UnconditionalMatch { negate: false },
                transforms: Vec::new(),
                setvars: head_actions.setvars.clone(),
            });
            continue;
        }
        let targets = parse_targets(p.vars.as_deref().unwrap_or_default())?;
        let op = operator::build(p.op.as_deref().unwrap_or_default(), base_dir)?;
        let actions = if idx == 0 {
            head_actions.clone()
        } else {
            parse_actions(p.actions.as_deref().unwrap_or(""))?
        };
        if idx > 0 {
            for t in &actions.tags {
                if !tags.contains(t) {
                    tags.push(t.clone());
                }
            }
            min_pl = min_pl.max(pl_from_tags(&actions.tags));
        }
        conditions.push(RawCondition {
            targets,
            op,
            transforms: actions.transforms,
            // 每个链接自带 setvar:头部写 `tx.foo` 的 chain 成员
            // (如 920420 的 `TX:content_type`)才能在自己的条件里看到它。
            setvars: actions.setvars,
        });
    }

    let id = head_actions.id.ok_or_else(|| "rule:missing-id".to_string())?;

    Ok(RawRule {
        id,
        phase: head_actions.phase.unwrap_or(2).min(5),
        conditions,
        msg: head_actions.msg,
        severity: head_actions.severity,
        capture: head_actions.capture,
        tags,
        min_pl,
    })
}

fn pl_from_tags(tags: &[String]) -> u8 {
    tags.iter()
        .filter_map(|t| t.strip_prefix("paranoia-level/"))
        .filter_map(|n| n.parse::<u8>().ok())
        .filter(|&n| n >= 1)
        .max()
        .unwrap_or(0)
}

/// 解析变量列表:`A|!B:sel|&C`。`|` 切分时跳过 `/regex/` 选择器内部的 `|`。
fn parse_targets(vars: &str) -> Result<Vec<TargetTerm>, String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = vars.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '|' if !in_regex_selector(&cur) => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }

    let mut terms = Vec::new();
    for f in parts {
        let mut s = f.as_str();
        let mut count = false;
        let mut negate = false;
        if let Some(rest) = s.strip_prefix('&') {
            count = true;
            s = rest;
        }
        if let Some(rest) = s.strip_prefix('!') {
            negate = true;
            s = rest;
            if let Some(rest2) = rest.strip_prefix('&') {
                count = true;
                s = rest2;
            }
        }
        if s.is_empty() {
            return Err("rule:parse:empty-variable".to_string());
        }
        let (var, selector) = match s.split_once(':') {
            Some((v, sel)) => {
                let sel = sel.trim();
                let parsed = if sel.len() >= 2 && sel.starts_with('/') && sel.ends_with('/') {
                    let inner = &sel[1..sel.len() - 1];
                    match regex::Regex::new(inner) {
                        Ok(re) => Some(Selector::Rx(Box::new(re))),
                        Err(_) => return Err(format!("rule:parse:bad-selector:{sel}")),
                    }
                } else if !sel.is_empty() {
                    Some(Selector::Exact(sel.to_string()))
                } else {
                    None
                };
                (v.to_ascii_uppercase(), parsed)
            }
            None => (s.to_ascii_uppercase(), None),
        };
        terms.push(TargetTerm { var, selector, negate, count });
    }
    if terms.is_empty() {
        return Err("rule:parse:no-variables".to_string());
    }
    Ok(terms)
}

/// 当前已累计的片段是否停在一个未闭合的 `/regex/` 选择器内。
/// 近似判定:冒号后出现了奇数个未转义 `/`。
fn in_regex_selector(cur: &str) -> bool {
    let after_colon = match cur.find(':') {
        Some(pos) => &cur[pos + 1..],
        None => return false,
    };
    let mut slashes = 0usize;
    let mut esc = false;
    for c in after_colon.chars() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' => esc = true,
            '/' => slashes += 1,
            _ => {}
        }
    }
    slashes % 2 == 1
}

#[cfg(test)]
mod tests {
    use crate::RuleSet;

    fn load(src: &str) -> (RuleSet, crate::LoadReport) {
        RuleSet::load_seclang(src, None)
    }

    #[test]
    fn parses_all_operator_forms() {
        let src = r#"
            SecRule ARGS "@rx ^a" "id:1,phase:2,pass"
            SecRule ARGS "@pm one two" "id:2,phase:2,pass"
            SecRule ARGS "@streq x" "id:3,phase:1,pass"
            SecRule ARGS "@contains mid" "id:4,phase:2,pass"
            SecRule ARGS "@beginsWith b" "id:5,phase:2,pass"
            SecRule ARGS "@endsWith e" "id:6,phase:2,pass"
            SecRule ARGS "@within a b c" "id:7,phase:2,pass"
            SecRule ARGS "@detectSQLi" "id:8,phase:2,pass"
            SecRule ARGS "@detectXSS" "id:9,phase:2,pass"
            SecRule ARGS "!@rx ^z" "id:10,phase:2,pass"
            SecRule ARGS "/^re/" "id:11,phase:2,pass"
            SecRule ARGS "@eq 3" "id:12,phase:2,pass"
            SecRule ARGS "@ge %{tx.x}" "id:13,phase:2,pass"
        "#;
        let (rs, rep) = load(src);
        assert_eq!(rep.skipped.len(), 0, "{:?}", rep.skipped);
        assert_eq!(rs.len(), 13);
    }

    #[test]
    fn pm_from_file_resolves_base_dir() {
        let dir = std::env::temp_dir().join("rooster-waf-test-data");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("words.data"), "# 注释\nfoo\nBarBaz\n").unwrap();
        let (rs, rep) = RuleSet::load_seclang(
            r#"SecRule ARGS "@pmFromFile words.data" "id:20,phase:2,pass,msg:'pm test',severity:WARNING""#,
            Some(&dir),
        );
        assert_eq!(rep.skipped.len(), 0);
        let v = rs.evaluate(
            &crate::Request { method: "GET", uri: "/?q=xxbarbazxx", headers: &[], cookies: &[], body: b"" },
            100,
            &[],
        );
        assert_eq!(v.hits.len(), 1);
        assert_eq!(v.hits[0].score, 3);
        assert_eq!(v.score, 3);
    }

    #[test]
    fn quoting_and_escaping() {
        let src = r#"
            SecRule ARGS "@rx a,b" "id:30,phase:2,pass,severity:NOTICE,msg:'逗号, 在引号内',t:none,t:lowercase"
        "#;
        let (rs, rep) = load(src);
        assert_eq!(rep.skipped.len(), 0);
        assert_eq!(rs.len(), 1);
        // 逗号在引号内:动作串未被拆散;大小写归一后命中
        let v = rs.evaluate(
            &crate::Request { method: "GET", uri: "/?q=A%2Cb", headers: &[], cookies: &[], body: b"" },
            100,
            &[],
        );
        assert_eq!(v.hits.len(), 1);
        assert_eq!(v.hits[0].msg, "逗号, 在引号内");
        let v2 = rs.evaluate(
            &crate::Request { method: "GET", uri: "/?q=zz", headers: &[], cookies: &[], body: b"" },
            100,
            &[],
        );
        assert_eq!(v2.hits.len(), 0);
    }

    #[test]
    fn chain_two_level_merge() {
        let src = r#"
            SecRule REQUEST_METHOD "@streq GET" "id:40,phase:1,pass,chain,msg:'m'"
                SecRule REQUEST_URI "@contains /api" "chain"
                    SecRule ARGS "@rx ^tok" "t:none"
        "#;
        let (rs, rep) = load(src);
        assert_eq!(rep.skipped.len(), 0);
        assert_eq!(rs.len(), 1);
        let v = rs.evaluate(
            &crate::Request { method: "GET", uri: "/api/?tok=1", headers: &[], cookies: &[], body: b"" },
            100,
            &[],
        );
        // 无 severity → 无 Hit,但 setvar 语义可用;此处仅验证不 panic
        assert_eq!(v.hits.len(), 0);
    }

    #[test]
    fn unsupported_directives_are_skipped_not_errors() {
        let src = r#"
            SecMarker "END-X"
            SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES:/^_ga$/"
            SecComponentSignature "OWASP_CRS/4"
            Include other.conf
            SecRuleEngine On
            SecResponseBodyMimeType text/html
            SecDefaultAction "phase:1,pass"
            SecRule ARGS "@rx x" "id:50,phase:2,pass"
        "#;
        let (rs, rep) = load(src);
        assert_eq!(rs.len(), 1);
        let reasons: Vec<&str> = rep.skipped.iter().map(|s| s.reason.as_str()).collect();
        for d in ["directive:SecMarker", "directive:SecRuleUpdateTargetById", "directive:SecComponentSignature", "directive:Include", "directive:SecRuleEngine", "directive:SecResponseBodyMimeType", "directive:SecDefaultAction"] {
            assert!(reasons.contains(&d), "缺少 {d}: {reasons:?}");
        }
    }

    #[test]
    fn missing_id_and_bad_rule_skipped() {
        let src = r#"
            SecRule ARGS "@rx x" "phase:2,pass"
            SecRule ARGS "@frobnicate" "id:60,phase:2,pass"
            SecRule ARGS "@rx (" "id:61,phase:2,pass"
            SecRule ARGS "@rx x" "id:62,phase:2,pass,chain"
            SecMarker "ORPHAN"
        "#;
        let (rs, rep) = load(src);
        assert_eq!(rs.len(), 0);
        let reasons: Vec<&str> = rep.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(reasons.contains(&"rule:missing-id"));
        assert!(reasons.iter().any(|r| r.starts_with("rule:operator:")));
        assert!(reasons.iter().any(|r| r.starts_with("rule:regex-compile")));
        assert!(reasons.contains(&"rule:chain-no-member"));
    }

    #[test]
    fn selector_regex_and_exclusion_prefix() {
        let src = r#"
            SecRule REQUEST_COOKIES:/^_ga/ "@rx ." "id:70,phase:2,pass,severity:NOTICE"
            SecRule REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|!REQUEST_HEADERS:Authorization "@rx secret" "id:71,phase:2,pass,severity:NOTICE"
        "#;
        let (rs, rep) = load(src);
        assert_eq!(rep.skipped.len(), 0, "{:?}", rep.skipped);
        let cookies = vec![("_ga_XY".to_string(), "v".to_string())];
        let headers = vec![
            ("x-a".to_string(), "secret".to_string()),
            ("cookie".to_string(), "secret".to_string()),
        ];
        let v = rs.evaluate(
            &crate::Request { method: "GET", uri: "/", headers: &headers, cookies: &cookies, body: b"" },
            100,
            &[],
        );
        assert_eq!(v.hits.len(), 2); // 70 命中 _ga cookie;71 命中 x-a 但排除 cookie
    }
}
