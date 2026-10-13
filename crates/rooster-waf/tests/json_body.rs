//! JSON 请求体的结构化采集与 raw blob 降级。
//!
//! 回归的正是 LLM/OpenAI 协议流量的误报形态:`/v1/chat/completions` 的请求体
//! 里回带了上一轮 assistant 输出(SQL 语句、代码注释、Markdown 破折号),
//! 整块 JSON 被当成一个值送进 SQLi/XSS 检测。

use rooster_waf::{Request, RuleSet};

/// 持有 headers 所有权的测试夹具(`Request` 按引用取头)。
struct Headers(Vec<(String, String)>);

impl Headers {
    fn with(content_type: &str) -> Self {
        Self(vec![("content-type".to_string(), content_type.to_string())])
    }

    fn req<'a>(&'a self, method: &'a str, uri: &'a str, body: &'a [u8]) -> Request<'a> {
        Request { method, uri, headers: &self.0, cookies: &[], body }
    }
}

/// 一段贴近真实的对话体:assistant 历史里含 SQL、C 注释、`--` 与混合撇号。
const CHAT_BODY: &str = r##"{"model":"gpt-4o","temperature":0.7,"messages":[{"role":"user","content":"帮我写一条查询，统计每个活跃用户的订单数"},{"role":"assistant","content":"SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON o.user_id = u.id WHERE u.status = 'active' GROUP BY u.id;  -- 注意 and id=1 会重复计数\n/* 也可以用 information_schema 看 version() */"},{"role":"user","content":"再翻成英文: O'Brien's letter, cat=1 or dog=2"}],"stream":true}"##;

#[test]
fn json_leaves_are_collected_as_args_json() {
    let src = r#"
        SecRule &ARGS_JSON "@gt 2" "id:900,phase:2,pass,severity:NOTICE"
        SecRule ARGS_JSON:/model "@streq gpt-4o" "id:901,phase:2,pass,severity:NOTICE"
    "#;
    let (rs, rep) = RuleSet::load_seclang(src, None);
    assert_eq!(rep.loaded, 2, "{:?}", rep.skipped);
    let h = Headers::with("application/json");
    let r = h.req("POST", "/v1/chat/completions", CHAT_BODY.as_bytes());
    let v = rs.evaluate(&r, 100, &[]);
    assert_eq!(v.hits.len(), 2, "{:?}", v.hits);

    // 与 ModSecurity 不同的有意偏差:JSON 叶子**不**并入 ARGS —— CRS 几乎全部
    // 规则以 ARGS 为目标,并集会让整块 body 被逐字段重扫 600 次(成本实测见
    // crate 文档)。需要 JSON 字段的规则自己写 ARGS_JSON。
    let (rs2, _) = RuleSet::load_seclang(
        r#"SecRule ARGS "@streq gpt-4o" "id:902,phase:2,pass,severity:NOTICE""#,
        None,
    );
    let v2 = rs2.evaluate(&r, 100, &[]);
    assert!(v2.hits.is_empty(), "ARGS 不应包含 JSON 叶子: {:?}", v2.hits);
}

#[test]
fn chat_completion_body_with_sql_history_does_not_block() {
    let (rs, _) = RuleSet::load_builtin(&[]);
    let h = Headers::with("application/json");
    let r = h.req("POST", "/v1/chat/completions", CHAT_BODY.as_bytes());
    let v = rs.evaluate(&r, 5, &[]);
    let summary: Vec<(u32, u32, bool)> =
        v.hits.iter().map(|x| (x.rule_id, x.score, x.blob_only)).collect();
    assert!(!v.blocked, "score={} hits={summary:?}", v.score);
    assert_eq!(v.score, 0, "hits={summary:?}");
}

#[test]
fn injection_inside_json_string_value_still_blocks() {
    let (rs, _) = RuleSet::load_builtin(&[]);
    let body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"1' union select password from users--"}]}"#;
    let h = Headers::with("application/json");
    let v = rs.evaluate(&h.req("POST", "/v1/chat/completions", body), 5, &[]);
    assert!(v.blocked, "hits={:?}", v.hits);
    assert!(v.hits.iter().any(|x| !x.blob_only && x.score >= 5));
}

/// blob 降级的边界:只有当 body 确实被拆开了,raw blob 才让路。
#[test]
fn blob_hit_scores_zero_only_for_parsed_json() {
    let (rs, _) = RuleSet::load_seclang(
        r#"SecRule REQUEST_BODY "@rx /\*" "id:903,phase:2,pass,severity:CRITICAL""#,
        None,
    );

    // 合法 JSON:`/*` 只出现在字符串叶子内部,逐字段已覆盖 → blob 不计分
    let h = Headers::with("application/json");
    let json = h.req("POST", "/v1/chat/completions", br#"{"content":"see /* note */ here"}"#);
    let v = rs.evaluate(&json, 5, &[]);
    assert_eq!(v.hits.len(), 1, "{:?}", v.hits);
    assert!(v.hits[0].blob_only, "{:?}", v.hits);
    assert_eq!(v.score, 0);
    assert!(!v.blocked);

    // 同一载荷按非结构化类型送来 → blob 照常计分(不把「拆不了」变成「不检」)
    let plain = Headers::with("text/plain");
    let v = rs.evaluate(&plain.req("POST", "/echo", br#"see /* note */ here"#), 5, &[]);
    assert_eq!(v.score, 5, "{:?}", v.hits);
    assert!(v.blocked);

    // 声称是 JSON 但解析失败 → 同样照常计分
    let broken = h.req("POST", "/v1/chat/completions", br#"{"content":"see /* note */ here""#);
    let v = rs.evaluate(&broken, 5, &[]);
    assert_eq!(v.score, 5, "{:?}", v.hits);
    assert!(v.blocked);
}

/// 字段级命中照常计分,否则降级会把真攻击一起降掉。
#[test]
fn leaf_hit_keeps_full_score_even_for_json_body() {
    let (rs, _) = RuleSet::load_seclang(
        r#"SecRule ARGS_JSON "@rx /\*" "id:904,phase:2,pass,severity:CRITICAL""#,
        None,
    );
    let h = Headers::with("application/json");
    let v = rs.evaluate(&h.req("POST", "/v1/chat/completions", br#"{"content":"see /* note */ here"}"#), 5, &[]);
    assert_eq!(v.score, 5, "{:?}", v.hits);
    assert!(v.blocked);
}

/// 拆解上限:超出深度预算的 JSON 不进入「已结构化」状态,
/// 免得拆解本身变成成本攻击面。
#[test]
fn over_deep_json_falls_back_to_blob_weight() {
    let (rs, _) = RuleSet::load_seclang(
        r#"SecRule REQUEST_BODY "@rx needle" "id:905,phase:2,pass,severity:CRITICAL""#,
        None,
    );
    let mut body = String::new();
    for _ in 0..20 {
        body.push_str(r#"{"a":"#);
    }
    body.push_str(r#""needle""#);
    for _ in 0..20 {
        body.push('}');
    }
    let h = Headers::with("application/json");
    let v = rs.evaluate(&h.req("POST", "/api", body.as_bytes()), 5, &[]);
    assert!(v.blocked, "超出深度预算时必须按 raw blob 计分: hits={:?}", v.hits);
    assert_eq!(v.score, 5);
}
