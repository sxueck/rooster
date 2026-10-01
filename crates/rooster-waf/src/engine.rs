//! 求值引擎:变量收集、转换、操作符执行、原生异常评分。
//!
//! # 评分与阻断
//!
//! 引擎采用**原生异常评分**:`Hit.score` = 严重度权重(CRITICAL=5 /
//! ERROR=4 / WARNING=3 / NOTICE=2),`Verdict.score` 为累加值,
//! `blocked = score >= threshold`。`deny/block/pass` 等颠覆性动作不参与
//! 判定 —— CRS 949/959 的「阻断评估」规则在本引擎中天然失效
//! (它们不带 severity,不产生 Hit),阻断完全由本地阈值决定。
//!
//! # 最小 TX 运行时(设计偏差,详见 crate 文档)
//!
//! 引擎维护一个请求级 TX 表,使 CRS 的 PL 守卫规则(`TX:DETECTION_PARANOIA_LEVEL
//! "@lt N" ... skipAfter`)加载后可以无害求值:表内预置 `crs_setup_version`
//! 与三个 PL 变量;`SecAction`/规则命中的 `setvar:tx.*`(含 `%{tx.x}` 宏与
//! `+N` 累加)按文件顺序执行。TX 异常分(`tx.inbound_anomaly_score_pl*`)
//! 即使被累加,也只用于后续宏展开,不影响本地评分。

use std::collections::HashMap;

use crate::parser::{RawCondition, RawRule, Selector, SetVar, TargetTerm};
use crate::transform::apply_all;
use crate::{Hit, Request, Verdict};

/// 单请求最多记录的命中数,防止异常请求撑爆内存。
const MAX_HITS: usize = 200;

/// TX 表预置:等价于「已加载 crs-setup.conf」的标记,避免 CRS 901001
/// (未配置部署检查,deny 全部请求)误伤。
const TX_SEED: [(&str, &str); 4] = [
    ("crs_setup_version", "400"),
    ("paranoia_level", "1"),
    ("detection_paranoia_level", "1"),
    ("blocking_paranoia_level", "1"),
];

struct EvalState<'a> {
    ctx: Ctx<'a>,
    hits: Vec<Hit>,
    score: u32,
}

struct Ctx<'a> {
    req: &'a Request<'a>,
    /// 查询串 + urlencoded body 解析出的参数
    args: Vec<(String, String)>,
    body_str: String,
    /// uri 中 `?` 之前的部分(原始,未解码)
    path: String,
    /// uri 中 `?` 之后的部分(原始,未解码);无 query 时为空
    query: String,
    tx: HashMap<String, String>,
    body_is_urlencoded: bool,
    /// 最近一次命中的值与变量名(供 `%{MATCHED_VAR}` / `MATCHED_VARS`)
    last_matched: Option<String>,
    last_matched_name: Option<String>,
}

pub(crate) fn evaluate(
    rules: &[RawRule],
    paranoia: u8,
    req: &Request,
    threshold: u32,
    exclusions: &[u32],
) -> Verdict {
    let mut st = EvalState {
        ctx: Ctx::build(req, paranoia),
        hits: Vec::new(),
        score: 0,
    };

    for phase in [1u8, 2u8] {
        for rule in rules {
            if rule.phase != phase {
                continue;
            }
            // PL=0 表示不过滤(测试/自定义规则集);否则按 tag 过滤
            if paranoia != 0 && rule.min_pl > paranoia {
                continue;
            }
            if exclusions.contains(&rule.id) {
                continue;
            }
            eval_rule(rule, &mut st);
        }
    }

    let blocked = st.score >= threshold;
    Verdict {
        hits: st.hits,
        score: st.score,
        blocked,
    }
}

impl<'a> Ctx<'a> {
    fn build(req: &'a Request, paranoia: u8) -> Ctx<'a> {
        let mut args = Vec::new();
        let query = req
            .uri
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        if !query.is_empty() {
            parse_query(&query, &mut args);
        }
        let content_type = req
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        let body_is_urlencoded = content_type.contains("application/x-www-form-urlencoded");
        let body_str = String::from_utf8_lossy(req.body).into_owned();
        if body_is_urlencoded {
            parse_query(&body_str, &mut args);
        }
        let path = req
            .uri
            .split_once('?')
            .map(|(p, _)| p.to_string())
            .unwrap_or_else(|| req.uri.to_string());

        let mut tx: HashMap<String, String> = TX_SEED
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let pl = if paranoia == 0 { 1 } else { paranoia };
        for key in ["paranoia_level", "detection_paranoia_level", "blocking_paranoia_level"] {
            tx.insert(key.to_string(), pl.to_string());
        }

        Ctx {
            req,
            args,
            body_str,
            path,
            query,
            tx,
            body_is_urlencoded,
            last_matched: None,
            last_matched_name: None,
        }
    }

    /// 按变量名收集 (元素名, 值)。集合变量仅包含实际存在的元素;
    /// 标量变量恒有一个值(可能为空串)。
    fn collect(&self, var: &str, selector: Option<&Selector>) -> Vec<(String, String)> {
        match var {
            "ARGS" => self
                .args
                .iter()
                .filter(|(n, _)| selector.map_or(true, |s| s.matches(n)))
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            "ARGS_NAMES" => self
                .args
                .iter()
                .filter(|(n, _)| selector.map_or(true, |s| s.matches(n)))
                .map(|(n, _)| (n.clone(), n.clone()))
                .collect(),
            // REQUEST_URI_RAW 与 REQUEST_URI 一致(本引擎不做原始/解码区分,见 crate 文档)
            "REQUEST_URI" | "REQUEST_URI_RAW" => vec![(var.to_string(), self.req.uri.to_string())],
            // 原始 query string(`?` 之后部分)。未建模时 931110 等
            // 直接以 `QUERY_STRING` 为目标的 PL1 规则永远收不到值。
            "QUERY_STRING" => vec![(var.to_string(), self.query.clone())],
            // 最近命中的变量名(CRS 941310 的 chain 成员)。未建模时该
            // chain 成员恒收到空集合,整条规则失效。
            "MATCHED_VARS" => self
                .last_matched_name
                .iter()
                .map(|n| (var.to_string(), n.clone()))
                .collect(),
            "REQUEST_FILENAME" => vec![("".into(), self.path.clone())],
            "REQUEST_BASENAME" => {
                let base = self
                    .path
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("")
                    .to_string();
                vec![("".into(), base)]
            }
            "REQUEST_BODY" => vec![("".into(), self.body_str.clone())],
            "REQUEST_METHOD" => vec![("".into(), self.req.method.to_string())],
            // 协议版本不可得:按 HTTP/1.1 近似(CRS 920 系列仅做版本策略检查)
            "REQUEST_PROTOCOL" => vec![("".into(), "HTTP/1.1".into())],
            "REQUEST_LINE" => vec![(
                "".into(),
                format!("{} {} HTTP/1.1", self.req.method, self.req.uri),
            )],
            "REQUEST_HEADERS" => self
                .req
                .headers
                .iter()
                .filter(|(n, _)| selector.map_or(true, |s| s.matches(n)))
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            "REQUEST_HEADERS_NAMES" => self
                .req
                .headers
                .iter()
                .filter(|(n, _)| selector.map_or(true, |s| s.matches(n)))
                .map(|(n, _)| (n.clone(), n.clone()))
                .collect(),
            "REQUEST_COOKIES" => self
                .req
                .cookies
                .iter()
                .filter(|(n, _)| selector.map_or(true, |s| s.matches(n)))
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            "REQUEST_COOKIES_NAMES" => self
                .req
                .cookies
                .iter()
                .filter(|(n, _)| selector.map_or(true, |s| s.matches(n)))
                .map(|(n, _)| (n.clone(), n.clone()))
                .collect(),
            "TX" => match selector {
                None => self.tx.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                Some(Selector::Exact(name)) => self
                    .tx
                    .get(&name.to_ascii_lowercase())
                    .map(|v| (name.to_string(), v.clone()))
                    .into_iter()
                    .collect(),
                Some(Selector::Rx(re)) => self
                    .tx
                    .iter()
                    .filter(|(k, _)| re.is_match(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            },
            "REQBODY_PROCESSOR" => vec![(
                "".into(),
                if self.body_is_urlencoded { "URLENCODED" } else { "" }.to_string(),
            )],
            // 无客户端地址可用(Request 不携带);@ipMatch 规则自然不命中
            "REMOTE_ADDR" => vec![("".into(), String::new())],
            // 尚未建模的变量(XML、MULTIPART_*、FILES*、RESPONSE_*、
            // UNIQUE_ID 等):空集合。FILES/FILES_NAMES 需要 multipart
            // 解析,当前未实现——因此 920120 这类以它们为目标的规则
            // 虽然加载成功但不会命中,属于已知覆盖缺口(非解析失败)。
            _ => Vec::new(),
        }
    }
}

/// 引擎已建模的请求变量。以此为「可生效覆盖」的判据:目标里含表外
/// 变量的规则虽然能解析、计入 loaded,但运行时恒收到空集合。
const MODELLED_VARS: &[&str] = &[
    "ARGS",
    "ARGS_NAMES",
    "MATCHED_VARS",
    "QUERY_STRING",
    "REQBODY_PROCESSOR",
    "REMOTE_ADDR",
    "REQUEST_BASENAME",
    "REQUEST_BODY",
    "REQUEST_COOKIES",
    "REQUEST_COOKIES_NAMES",
    "REQUEST_FILENAME",
    "REQUEST_HEADERS",
    "REQUEST_HEADERS_NAMES",
    "REQUEST_LINE",
    "REQUEST_METHOD",
    "REQUEST_PROTOCOL",
    "REQUEST_URI",
    "REQUEST_URI_RAW",
    "TX",
];

/// 变量是否已建模(加载报告与覆盖统计用)。
pub(crate) fn is_modelled_var(var: &str) -> bool {
    MODELLED_VARS.contains(&var)
}

/// 目标中含未建模变量的规则 id:这些规则解析成功但永不命中。
pub(crate) fn rules_with_unmodelled_targets(rules: &[RawRule]) -> Vec<u32> {
    rules
        .iter()
        .filter(|r| {
            r.conditions
                .iter()
                .any(|c| c.targets.iter().any(|t| !is_modelled_var(&t.var)))
        })
        .map(|r| r.id)
        .collect()
}

fn parse_query(q: &str, out: &mut Vec<(String, String)>) {
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.push((
            crate::transform::url_decode_uni(k, true),
            crate::transform::url_decode_uni(v, true),
        ));
    }
}

/// 逐链接求值。ModSecurity 语义:每个链接命中时**立即**执行自己的
/// `setvar`(头部命中即写 `tx.*`),后续成员才能在 `TX:` 目标里看到它。
/// 头部命中后还会按 `capture` 写入 `tx.0..tx.9`。
/// 任何链接不命中则整条链不产生 Hit(已执行的 setvar 副作用保留,与
/// ModSecurity 一致)。
fn eval_rule(rule: &RawRule, st: &mut EvalState) {
    for (idx, cond) in rule.conditions.iter().enumerate() {
        if !eval_cond(cond, st) {
            return;
        }
        if idx == 0 && rule.capture {
            if let Some(value) = st.ctx.last_matched.clone() {
                // ModSecurity 约定:捕获组存为 TX:0..TX:9(不带变量名前缀),
                // `%{tx.0}` 才能取到。
                for (n, cap) in cond.op.captures(&value).into_iter().enumerate() {
                    st.ctx.tx.insert(n.to_string(), cap);
                }
            }
        }
        for sv in &cond.setvars {
            exec_setvar(sv, st);
        }
    }
    let sev = rule.severity as u32;
    if sev > 0 && st.hits.len() < MAX_HITS {
        let msg = match &rule.msg {
            Some(m) => expand_macros(m, st),
            None => format!("rule {}", rule.id),
        };
        st.hits.push(Hit {
            rule_id: rule.id,
            msg,
            severity: rule.severity,
            score: sev,
        });
        st.score = st.score.saturating_add(sev);
    }
}

fn eval_cond(cond: &RawCondition, st: &mut EvalState) -> bool {
    // 无目标变量(SecAction / @unconditionalMatch):恒真,不看值集合。
    if cond.targets.is_empty() {
        return !cond.op.negate();
    }
    let mut entries: Vec<(String, String, String)> = Vec::new(); // (var, name, value)
    let mut neg_terms: Vec<&TargetTerm> = Vec::new();
    for term in &cond.targets {
        if term.negate {
            neg_terms.push(term);
            continue;
        }
        let resolved = st.ctx.collect(&term.var, term.selector.as_ref());
        if term.count {
            entries.push((term.var.clone(), String::new(), resolved.len().to_string()));
        } else {
            for (n, v) in resolved {
                entries.push((term.var.clone(), n, v));
            }
        }
    }
    // `!` 排除项后置处理:从并集中剔除同变量、选择器命中的元素
    for term in neg_terms {
        entries.retain(|(v, n, _)| {
            !(v.eq_ignore_ascii_case(&term.var)
                && term.selector.as_ref().map_or(true, |s| s.matches(n)))
        });
    }

    let mut any_match = false;
    let mut matched_value: Option<String> = None;
    let mut matched_name: Option<String> = None;
    for (var, name, raw) in &entries {
        let value = apply_all(&cond.transforms, raw);
        if cond.op.matches(&value, &|m| {
            expand_macros(m, st)
        }) {
            any_match = true;
            matched_value = Some(value);
            // ModSecurity 的 MATCHED_VARS 取 `VAR:selector` 形式的全名。
            matched_name = Some(if name.is_empty() {
                var.clone()
            } else {
                format!("{var}:{name}")
            });
            break;
        }
    }
    // 无候选值时不命中(取反操作符同样如此);`&` 计数项恒产生一个值
    if entries.is_empty() {
        return false;
    }
    let hit = if cond.op.negate() { !any_match } else { any_match };
    if hit {
        st.ctx.last_matched = matched_value;
        st.ctx.last_matched_name = matched_name;
    }
    hit
}

fn exec_setvar(sv: &SetVar, st: &mut EvalState) {
    // 仅执行 TX 目标;IP/GLOBAL 等集合忽略
    let key = match sv {
        SetVar::Set { key, .. }
        | SetVar::Inc { key, .. }
        | SetVar::Dec { key, .. }
        | SetVar::Unset { key } => key,
    };
    let name = match key.strip_prefix("tx.").map(|s| s.to_string()) {
        Some(n) => n,
        None => return,
    };
    match sv {
        SetVar::Set { val, .. } => {
            let v = expand_macros(val, st);
            st.ctx.tx.insert(name, v);
        }
        SetVar::Inc { val, .. } => {
            let delta = expand_macros(val, st).trim().parse::<i64>().unwrap_or(0);
            let cur = st
                .ctx
                .tx
                .get(&name)
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(0);
            st.ctx.tx.insert(name, (cur + delta).to_string());
        }
        SetVar::Dec { val, .. } => {
            let delta = expand_macros(val, st).trim().parse::<i64>().unwrap_or(0);
            let cur = st
                .ctx
                .tx
                .get(&name)
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(0);
            st.ctx.tx.insert(name, (cur - delta).to_string());
        }
        SetVar::Unset { .. } => {
            st.ctx.tx.remove(&name);
        }
    }
}

/// 展开 `%{...}` 宏:TX 变量(大小写不敏感)、MATCHED_VAR;未知宏置空。
fn expand_macros(s: &str, st: &EvalState) -> String {
    if !s.contains("%{") {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        match rest.find('}') {
            Some(end) => {
                let name = &rest[..end];
                rest = &rest[end + 1..];
                let lower = name.to_ascii_lowercase();
                if let Some(txname) = lower.strip_prefix("tx.") {
                    if let Some(v) = st.ctx.tx.get(txname) {
                        out.push_str(v);
                    }
                } else if lower == "matched_var" {
                    if let Some(v) = &st.ctx.last_matched {
                        out.push_str(v);
                    }
                } else if lower == "matched_var_name" || lower == "matched_vars" {
                    if let Some(v) = &st.ctx.last_matched_name {
                        out.push_str(v);
                    }
                }
                // 其余宏(REQUEST_URI 等)置空
            }
            None => {
                out.push_str("%{");
                out.push_str(rest);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// 供 lib.rs 使用的默认 PL(CRS 出厂默认 PL1;自定义规则通常无 PL 标签不受影响)
pub(crate) const DEFAULT_PARANOIA: u8 = 1;
