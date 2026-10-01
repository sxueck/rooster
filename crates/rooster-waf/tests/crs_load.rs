//! CRS 加载集成测试(验收:CRS PL1 规则加载率 ≥ 90%)。
//!
//! 数据源:仓库根目录 `rules/crs/`(OWASP Coreruleset v4,Apache-2.0)。
//! 加载率 = loaded / (loaded + 被 Skip 的 SecRule/SecAction 数);
//! Skip 原因以 `rule:` 为前缀的才计入分母(`directive:` 前缀为非规则指令)。
//!
//! 加载率只回答“语法能不能解析”,不回答“规则会不会触发”。后者由
//! `chain_head_setvar_is_visible_to_member`、`pl1_rfi_rule_inspects_query_string`
//! 与 `crs_pl1_blocks_sqli_and_allows_benign` 拿真实规则文本直接验证;
//! 仍无法生效的规则由 `unmodelled_target_gap_is_reported_and_bounded` 计数上界。

use std::path::PathBuf;

use rooster_waf::{Request, RuleSet, Verdict};

fn crs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/crs")
}

fn crs_source() -> String {
    let dir = crs_dir();
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("rules/crs 目录存在")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "conf").unwrap_or(false)
                && !p.to_string_lossy().ends_with(".conf.example")
        })
        .collect();
    files.sort();
    assert!(files.len() >= 20, "CRS conf 文件数量异常: {}", files.len());
    let mut source = String::new();
    for f in files {
        source.push_str(&std::fs::read_to_string(&f).unwrap());
        source.push('\n');
    }
    source
}

#[test]
fn crs_load_rate_at_least_90_percent() {
    let source = crs_source();
    let (mut rs, report) = RuleSet::load_seclang(&source, Some(&crs_dir()));

    let skipped_rules = report
        .skipped
        .iter()
        .filter(|s| s.reason.starts_with("rule:"))
        .count();
    let total = report.loaded + skipped_rules;
    let rate = report.loaded as f64 / total as f64;

    // 原因分布(调试用;断言失败时打印)
    let mut hist = std::collections::BTreeMap::new();
    for s in &report.skipped {
        let key = s.reason.split(':').take(2).collect::<Vec<_>>().join(":");
        *hist.entry(key).or_insert(0usize) += 1;
    }
    eprintln!(
        "CRS: loaded={} skipped_rules={} skipped_directives={} rate={:.4}",
        report.loaded,
        skipped_rules,
        report.skipped.len() - skipped_rules,
        rate
    );
    for (k, v) in &hist {
        eprintln!("  skip {k}: {v}");
    }

    assert!(rate >= 0.90, "CRS 加载率 {rate:.4} 低于 0.90;原因分布: {hist:?}");
    assert!(report.loaded > 400, "加载规则数异常: {}", report.loaded);
    assert!(!rs.is_empty());

    // PL1 生效性由 crs_pl1_blocks_sqli_and_allows_benign 验证(命中 942 系列)
    rs.set_paranoia(1);
}

#[test]
fn crs_pl1_blocks_sqli_and_allows_benign() {
    let source = crs_source();
    let (mut rs, report) = RuleSet::load_seclang(&source, Some(&crs_dir()));
    rs.set_paranoia(1);
    assert!(report.loaded > 400);

    // SQL 注入请求:阈值 5 下必须阻断,且至少命中一条 942xxx 规则
    let headers = vec![
        ("host".to_string(), "example.com".to_string()),
        (
            "user-agent".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0".to_string(),
        ),
        ("accept".to_string(), "text/html,application/xhtml+xml".to_string()),
    ];
    let sqli = Request {
        method: "GET",
        uri: "/?id=1'%20OR%20'1'='1",
        headers: &headers,
        cookies: &[],
        body: b"",
    };
    let v = rs.evaluate(&sqli, 5, &[]);
    assert!(v.blocked, "应阻断: score={} hits={:?}", v.score, v.hits);
    assert!(
        v.hits.iter().any(|h| (942000..=942999).contains(&h.rule_id)),
        "应命中 REQUEST-942 系列: {:?}",
        v.hits
    );

    // 良性请求:低分不阻断
    let benign = Request {
        method: "GET",
        uri: "/index.html",
        headers: &headers,
        cookies: &[],
        body: b"",
    };
    let v = rs.evaluate(&benign, 5, &[]);
    assert!(!v.blocked, "良性请求不应阻断: score={} hits={:?}", v.score, v.hits);
    assert!(v.score < 5, "良性请求得分应低于阈值: {:?}", v.hits);
}

/// 从真实 CRS 文件里抽出指定 id 的完整规则文本(含 chain 成员)。
/// 测试直接跑仓库里 vendored 的规则,不自己重写一份。
fn crs_rule_text(id: u32) -> String {
    let needle = format!("id:{id},");
    let dir = crs_dir();
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("rules/crs 目录存在")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
        .collect();
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        if !text.contains(&needle) {
            continue;
        }
        // 以 SecRule/SecAction 开头的行是规则首行,之后的缩进行是续行。
        // chain 成员的 SecRule 同样顶格:上一条规则末行为 `chain"` 时
        // 它的成员还没收完,必须继续累积。
        let mut cur: Option<String> = None;
        for line in text.lines() {
            let t = line.trim_start();
            let starts_rule = t.starts_with("SecRule ") || t.starts_with("SecAction ");
            if starts_rule {
                let wants_member = cur
                    .as_ref()
                    .and_then(|r| r.lines().last())
                    .is_some_and(|l| l.trim_start().starts_with("chain"));
                if cur.is_none() || !wants_member {
                    if let Some(rule) = cur.take() {
                        if rule.contains(&needle) {
                            return rule;
                        }
                    }
                    cur = Some(line.to_string());
                } else if let Some(rule) = cur.as_mut() {
                    rule.push('\n'); // chain 成员接在同一条规则里
                    rule.push_str(line);
                }
            } else if let Some(rule) = cur.as_mut() {
                rule.push('\n');
                rule.push_str(line);
            }
        }
        if let Some(rule) = cur {
            if rule.contains(&needle) {
                return rule;
            }
        }
    }
    panic!("rules/crs 中找不到规则 id:{id}");
}

fn load_ids(ids: &[u32], seed: &str) -> RuleSet {
    let mut source = String::from(seed);
    for id in ids {
        source.push_str(&crs_rule_text(*id));
        source.push('\n');
    }
    let (mut rs, report) = RuleSet::load_seclang(&source, Some(&crs_dir()));
    assert_eq!(
        report.skipped.len(),
        0,
        "目标规则应全部加载成功,实际跳过: {:?}",
        report.skipped
    );
    rs.set_paranoia(1);
    rs
}

/// 按阈值 5 求值一条 GET 请求。
fn eval_get(rs: &RuleSet, uri: &str, cookies: &[(&str, &str)], headers: &[(&str, &str)]) -> Verdict {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let cookies: Vec<(String, String)> = cookies
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let r = Request {
        method: "GET",
        uri,
        headers: &headers,
        cookies: &cookies,
        body: b"",
    };
    rs.evaluate(&r, 5, &[])
}

/// 回归:`QUERY_STRING` 未建模时 931110(PL1/CRITICAL RFI)收不到值。
#[test]
fn pl1_rfi_rule_inspects_query_string() {
    let rs = load_ids(&[931110], "");
    // RFI payload 只出现在 query string 里,REQUEST_BODY 为空。
    let v = eval_get(
        &rs,
        "/?mosConfig_absolute_path=http://evil.example/x",
        &[],
        &[("host", "example.com")],
    );
    assert!(
        v.hits.iter().any(|h| h.rule_id == 931110),
        "931110 应命中 QUERY_STRING 中的 RFI payload: {:?}",
        v.hits
    );
    assert!(v.blocked, "RFI payload 应阻断: score={}", v.score);
}

/// 回归:chain 成员目标为 `MATCHED_VARS`。未建模时该成员恒收到空集合,
/// 整条链失效。用合成规则固定住“头部命中的变量名 → 成员可见”的数据流。
#[test]
fn matched_vars_flows_into_chain_member() {
    let source = r#"
SecRule ARGS "@rx attack" \
    "id:910001,phase:2,block,capture,t:none,\
    msg:'matched var reaches chain member',severity:'CRITICAL',chain"
    SecRule MATCHED_VARS "@streq ARGS:x" \
        "t:none,log"
"#;
    let (mut rs, report) = RuleSet::load_seclang(source, None);
    assert!(
        report.skipped.is_empty(),
        "合成规则应加载成功: {:?}",
        report.skipped
    );
    rs.set_paranoia(1);

    // 参数名为 x → 成员在 MATCHED_VARS 上看到 ARGS:x → 命中。
    let v = eval_get(&rs, "/?x=attack", &[], &[("host", "example.com")]);
    assert!(
        v.hits.iter().any(|h| h.rule_id == 910001),
        "MATCHED_VARS 应把头部的变量名传给成员: {:?}",
        v.hits
    );

    // 参数名不匹配 → 成员不应命中。
    let v = eval_get(&rs, "/?y=attack", &[], &[("host", "example.com")]);
    assert!(
        !v.hits.iter().any(|h| h.rule_id == 910001),
        "变量名不同时成员不应命中: {:?}",
        v.hits
    );
}

/// 回归:chain 头部命中即写 `tx.*`(`capture` → `tx.0` → 头部 setvar),
/// 成员在 `TX:` 上求值。旧实现把 setvar 放在全部 condition 之后,
/// 920420/920450/920480 这类头部写 TX 的链永远无法命中。
#[test]
fn chain_head_setvar_is_visible_to_member() {
    // crs-setup 的 900200 负责设置允许的 content-type 白名单;
    // 规则集只加载 rules/crs/*.conf,所以这里用等价的 SecAction 种子。
    let seed = "SecAction \"id:900200,phase:1,pass,nolog,\
                setvar:'tx.allowed_request_content_type=application/x-www-form-urlencoded|multipart/form-data|text/xml|application/xml|application/soap+xml|application/json|text/plain'\"\n";
    let rs = load_ids(&[920420], seed);
    // 不在白名单内 → 头部命中、成员 `!@within` 也命中 → 整条链触发。
    let bad = [
        ("host", "example.com"),
        ("content-type", "application/vnd.evil+zip"),
    ];
    let v = eval_get(&rs, "/", &[], &bad);
    assert!(
        v.hits.iter().any(|h| h.rule_id == 920420),
        "920420 应命中不在白名单的 Content-Type: {:?}",
        v.hits
    );

    // 白名单内的 content-type:头部命中、成员不命中 → 整条链不应触发。
    let ok = [
        ("host", "example.com"),
        ("content-type", "application/json"),
    ];
    let v = eval_get(&rs, "/", &[], &ok);
    assert!(
        !v.hits.iter().any(|h| h.rule_id == 920420),
        "白名单内的 Content-Type 不应命中 920420: {:?}",
        v.hits
    );
}

/// 已建模 `QUERY_STRING` / `MATCHED_VARS` / `TX` 之后,这几条 PL1 关键规则
/// 不再落入“目标变量未建模”名单。
///
/// 剩余名单是**已知覆盖缺口**且规模不小:CRS 头部大量使用 `XML:/*`
/// (281 处)、`RESPONSE_BODY`(58 处,引擎本就不评估 phase 3/4)、
/// `MULTIPART_*` / `FILES*`(需 multipart 解析)。这些不是解析失败:
/// 规则会加载但不会触发——所以“加载率”与“可生效覆盖”必须分开报告。
/// 这里钉住上界,防止缺口在无感知的情况下扩大。
#[test]
fn unmodelled_target_gap_is_reported_and_bounded() {
    let source = crs_source();
    let (rs, _) = RuleSet::load_seclang(&source, Some(&crs_dir()));
    let unmodelled = rs.rules_with_unmodelled_targets();

    for id in [931110u32, 920420, 920450, 920480] {
        assert!(
            !unmodelled.contains(&id),
            "规则 {id} 仍含未建模的目标变量,应已修复"
        );
    }
    // 依赖尚未建模的 FILES/FILES_NAMES,应仍在名单中。
    assert!(
        unmodelled.contains(&920120),
        "920120 依赖尚未建模的 FILES/FILES_NAMES"
    );
    eprintln!(
        "CRS 可生效覆盖: {}/{} 条规则目标变量全部已建模;未建模 {} 条(主要为 XML / RESPONSE_* / MULTIPART_* / FILES*)",
        rs.len() - unmodelled.len(),
        rs.len(),
        unmodelled.len()
    );
    // 上界:当前 CRS 快照下未建模规则不超过 300 条。
    assert!(
        unmodelled.len() <= 300,
        "未建模目标变量规则数 {} 超过上界,需重新评估缺口范围",
        unmodelled.len()
    );
}
