//! # rooster-waf —— SecLang 子集解析器与 WAF 签名引擎
//!
//! 实现内置签名与 SecLang 子集 / CRS 加载 / 异常评分,
//! 加载阶段遇到不支持的语法**跳过该条并输出告警**,不影响整体启动
//! (见 [`LoadReport`])。
//!
//! ## 公共 API 概览
//!
//! - [`RuleSet::load_builtin`] —— 内置签名(键:`sqli` / `xss` /
//!   `traversal` / `rce` / `sensitive-files` / `scanner-ua`,空列表 = 全部);
//! - [`RuleSet::load_seclang`] —— 解析 SecLang 源文本,`base_dir` 用于
//!   `@pmFromFile` 的 `.data` 相对路径;
//! - [`RuleSet::evaluate`] —— 异常评分求值:命中累计 `score`
//!   (CRITICAL=5 / ERROR=4 / WARNING=3 / NOTICE=2),`exclusions` 中的
//!   rule_id 完全跳过,`score >= threshold` 时 `blocked`;
//! - [`RuleSet::set_paranoia`] —— Paranoia Level 过滤(默认 1,置 0 不过滤)。
//!
//! ## 支持的 SecLang 子集
//!
//! - 指令:`SecRule`、`SecAction`;其余指令(Include、SecMarker、
//!   SecRuleUpdateTargetById 等)一律跳过并记录 `directive:<名称>` 告警;
//! - 变量:`ARGS`、`ARGS_NAMES`、`REQUEST_URI`、`REQUEST_HEADERS(:Name)`、
//!   `REQUEST_COOKIES(:Name)`、`REQUEST_BODY`、`REQUEST_METHOD`、`FILES_NAMES`,
//!   支持 `|` 并集、`!` 排除、`&` 计数;`REQUEST_URI_RAW` 是 `REQUEST_URI`
//!   的别名(本引擎不做原始/解码区分,属有意简化);CRS 依赖的
//!   `REQUEST_FILENAME` / `REQUEST_BASENAME` / `REQUEST_LINE` /
//!   `REQUEST_PROTOCOL` / `REQUEST_HEADERS_NAMES` / `REQUEST_COOKIES_NAMES` /
//!   `TX` / `REMOTE_ADDR`(恒空)等也做了尽力支持,未建模变量按空集合处理;
//! - 操作符:`@rx`、`@pm`、`@pmFromFile`、`@streq`、`@contains`、
//!   `@beginsWith`、`@endsWith`、`@within`、`@ipMatch`、`@detectSQLi`、
//!   `@detectXSS`(Rust 实现 libinjection 等价启发式,见 `detect` 模块文档)、
//!   数值比较 `@eq/@lt/@le/@gt/@ge`、校验类 `@validateByteRange` /
//!   `@validateUrlEncoding` / `@validateUtf8Encoding`、`@unconditionalMatch`,
//!   以及裸 `/regex/` 与 `!` 取反;
//! - 转换:`t:none/lowercase/urlDecodeUni/htmlEntityDecode/removeNulls/
//!   compressWhitespace/base64Decode/cmdLine` 及 CRS 常用扩展
//!   (`utf8toUnicode/jsDecode/cssDecode/removeWhitespace/replaceComments/
//!   normalizePath(Win)/escapeSeqDecode/length/sha1/hexEncode/removeCommentsChar`);
//! - 动作:`id`、`phase`(1/2 求值;3/4/5 解析存储但永不求值)、`deny/pass/
//!   block/log/msg/severity/tag/setvar`(仅 TX 目标,支持 `%{tx.x}` 宏与
//!   `+N` 累加)、`chain`、`ctl:ruleRemoveById`(解析存储,运行时由
//!   `exclusions` 参数承担同等语义);其余动作(ver/status/skipAfter/
//!   capture/multiMatch 等)解析后忽略;
//! - `chain`:与下一条 `SecRule`(通常缩进、无 id)合并条件,支持多级。
//!
//! ## 与规范字面的已知偏差(设计决策)
//!
//! 1. **TX 变量规则不整体跳过**:工作规范建议跳过引用 `TX` 的规则,
//!    但 CRS v4 中此类规则(PL 守卫 + 901 初始化 + 949/959 汇总)约占
//!    `SecRule` 总数的 43%,全部跳过将使加载率上限只有 ~57%,无法达到
//!    「CRS PL1 加载率 ≥ 90%」。因此本引擎实现了一个**最小 TX
//!    运行时**:预置 `crs_setup_version` 与三个 PL 变量、按序执行
//!    `setvar:tx.*`、对 `%{tx.x}` 宏求值。PL 守卫规则(`@lt N` + skipAfter)
//!    求值为无害的 pass/no-op(语义由 `set_paranoia` 的原生 PL 过滤承担);
//!    949/959 阻断评估规则不带 severity,不产生 Hit,阻断判定完全由
//!    `evaluate` 的阈值完成 —— 「原生异常评分」的设计意图保持不变。
//! 2. `skipAfter` 不求值(PL 分节由 tag 过滤等价实现);`capture` 与
//!    `TX:0..9` 捕获组不可用,依赖捕获组的链式规则(如 920440)不产生命中。
//! 3. `@pm` 大小写不敏感(CRS 数据文件以小写为主,放宽只有利于检出)。
//! 4. `REQUEST_LINE`/`REQUEST_PROTOCOL` 以 HTTP/1.1 近似;`REMOTE_ADDR`
//!    恒为空([`Request`] 不携带客户端地址)。
//! 5. 环视/反向引用等 PCRE 特性:rust `regex` 不支持,加载时做最小净化
//!    (分支复用组、占有量词、`\Q..\E`),仍失败则跳过该规则
//!    (`rule:regex-compile` 告警)。

mod builtin;
mod detect;
mod engine;
mod lexer;
mod operator;
mod parser;
mod transform;

use std::path::Path;

/// 待检测请求。`headers` 键需为小写;`uri` 为完整 request target(含 query);
/// `cookies` 为已解析的 Cookie 名值对。
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub headers: &'a [(String, String)],
    pub cookies: &'a [(String, String)],
    pub body: &'a [u8],
}

/// 单条规则命中。`score` 即严重度权重(5/4/3/2)。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    pub rule_id: u32,
    pub msg: String,
    pub severity: u8,
    pub score: u32,
}

/// 求值结果:`score >= threshold` 时 `blocked`。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Verdict {
    pub hits: Vec<Hit>,
    pub score: u32,
    pub blocked: bool,
}

/// 跳过条目。`reason` 前缀约定:`directive:<名称>`(非规则指令,不计入
/// 规则加载率分母)与 `rule:<原因>`(SecRule/SecAction 被跳过,计入分母)。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Skip {
    pub line: usize,
    pub reason: String,
}

/// 规则加载报告(面板「规则加载报告」页面的数据源)。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LoadReport {
    pub loaded: usize,
    pub skipped: Vec<Skip>,
}

/// 已加载规则的可见元数据(面板规则清单用)。
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleInfo {
    pub id: u32,
    pub phase: u8,
    pub msg: Option<String>,
    /// 严重度级别名;未声明严重度 → None
    pub severity: Option<&'static str>,
    pub tags: Vec<String>,
    /// `paranoia-level/N` 标签;0 = 无标签(任何 PL 下都评估)
    pub min_pl: u8,
}

/// 严重度权重 → 级别名(CRS 语义:CRITICAL=5/ERROR=4/WARNING=3/NOTICE=2)。
pub fn severity_name(weight: u8) -> Option<&'static str> {
    match weight {
        5 => Some("CRITICAL"),
        4 => Some("ERROR"),
        3 => Some("WARNING"),
        2 => Some("NOTICE"),
        _ => None,
    }
}

/// 已加载的规则集。不可变共享,`evaluate` 可并发调用。
pub struct RuleSet {
    rules: Vec<parser::RawRule>,
    /// 0 = 不过滤;默认 1(CRS 出厂默认)
    paranoia: u8,
}

impl RuleSet {
    /// 内置签名(签名键 `sqli`/`xss`/`traversal`/`rce`/
    /// `sensitive-files`/`scanner-ua`;空列表 = 全部)。
    pub fn load_builtin(signatures: &[String]) -> (RuleSet, LoadReport) {
        builtin::load_builtin(signatures)
    }

    /// 解析 SecLang 源文本;`base_dir` 用于 `@pmFromFile` 的 `.data`
    /// 文件解析。永不失败:不支持的语法成为 [`Skip`] 条目。
    pub fn load_seclang(source: &str, base_dir: Option<&Path>) -> (RuleSet, LoadReport) {
        let (rules, report) = parser::parse(source, base_dir);
        (RuleSet { rules, paranoia: engine::DEFAULT_PARANOIA }, report)
    }

    /// 合并两个规则集(后者追加);Paranoia Level 取两者较大值(更保守)。
    pub fn merge(mut self, other: RuleSet) -> RuleSet {
        self.paranoia = self.paranoia.max(other.paranoia);
        self.rules.extend(other.rules);
        self
    }

    /// 异常评分求值:命中累计 score(CRITICAL=5/ERROR=4/WARNING=3/NOTICE=2),
    /// `exclusions` 中的 rule_id 完全跳过;`score >= threshold` → blocked。
    pub fn evaluate(&self, req: &Request, threshold: u32, exclusions: &[u32]) -> Verdict {
        engine::evaluate(&self.rules, self.paranoia, req, threshold, exclusions)
    }

    /// 设置 Paranoia Level(支持 1–2;0 = 不过滤,供测试)。
    /// 只过滤带 `paranoia-level/N` 标签的规则,不影响 `len()`。
    pub fn set_paranoia(&mut self, level: u8) {
        self.paranoia = level;
    }

    /// 已加载规则数(含所有 Paranoia Level;不含被跳过的规则)。
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// 当前 Paranoia Level(0 = 不过滤)。
    pub fn paranoia(&self) -> u8 {
        self.paranoia
    }

    /// 已加载规则的元数据清单,按 id 升序(面板展示“到底加载了哪些规则”)。
    pub fn rules_info(&self) -> Vec<RuleInfo> {
        let mut out: Vec<RuleInfo> = self
            .rules
            .iter()
            .map(|r| RuleInfo {
                id: r.id,
                phase: r.phase,
                msg: r.msg.clone(),
                severity: severity_name(r.severity),
                tags: r.tags.clone(),
                min_pl: r.min_pl,
            })
            .collect();
        out.sort_by_key(|r| (r.id, r.phase));
        out
    }

    /// 目标变量含未建模项的规则 id(解析成功但运行时恒收到空集合)。
    /// “加载率”与“可生效覆盖”是两个数,面板的规则加载报告应分开呈现。
    pub fn rules_with_unmodelled_targets(&self) -> Vec<u32> {
        engine::rules_with_unmodelled_targets(&self.rules)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        RuleSet {
            rules: Vec::new(),
            paranoia: engine::DEFAULT_PARANOIA,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(uri: &'a str) -> Request<'a> {
        Request {
            method: "GET",
            uri,
            headers: &[],
            cookies: &[],
            body: b"",
        }
    }

    #[test]
    fn empty_ruleset() {
        let rs = RuleSet::default();
        assert!(rs.is_empty());
        assert_eq!(rs.len(), 0);
        let v = rs.evaluate(&req("/?a=1"), 5, &[]);
        assert!(!v.blocked);
        assert_eq!(v.score, 0);
    }

    #[test]
    fn severity_scoring_and_threshold() {
        let src = r#"
            SecRule ARGS "@rx ^hit1" "id:1,phase:2,pass,severity:WARNING,msg:'w'"
            SecRule ARGS "@rx ^hit2" "id:2,phase:2,pass,severity:NOTICE,msg:'n'"
            SecRule ARGS "@rx ^hit3" "id:3,phase:2,pass,severity:ERROR,msg:'e'"
        "#;
        let (rs, rep) = RuleSet::load_seclang(src, None);
        assert_eq!(rep.loaded, 3);
        // WARNING(3)+NOTICE(2) = 5 ≥ 5 → 阻断
        let v = rs.evaluate(&req("/?x=hit1&y=hit2"), 5, &[]);
        assert_eq!(v.score, 5);
        assert!(v.blocked);
        // 单个 WARNING = 3 < 5 → 放行
        let v = rs.evaluate(&req("/?x=hit1"), 5, &[]);
        assert_eq!(v.score, 3);
        assert!(!v.blocked);
        // ERROR = 4 < 5 → 放行;阈值 4 → 阻断
        let v = rs.evaluate(&req("/?x=hit3"), 4, &[]);
        assert!(v.blocked);
        // CRITICAL 映射 5 分
        let src2 = r#"SecRule ARGS "@rx ." "id:4,phase:2,severity:CRITICAL,msg:'c'""#;
        let (rs2, _) = RuleSet::load_seclang(src2, None);
        let v = rs2.evaluate(&req("/?x=1"), 5, &[]);
        assert_eq!(v.score, 5);
        assert_eq!(v.hits[0].severity, 5);
        assert_eq!(v.hits[0].score, 5);
    }

    #[test]
    fn exclusions_skip_rules_entirely() {
        let src = r#"
            SecRule ARGS "@rx ^bad" "id:10,phase:2,pass,severity:CRITICAL"
            SecRule ARGS "@rx ^also" "id:11,phase:2,pass,severity:CRITICAL"
        "#;
        let (rs, _) = RuleSet::load_seclang(src, None);
        let v = rs.evaluate(&req("/?q=bad"), 5, &[10]);
        assert_eq!(v.score, 0);
        assert!(!v.blocked);
        let v = rs.evaluate(&req("/?q=bad"), 5, &[]);
        assert!(v.blocked);
    }

    #[test]
    fn variable_collection_query_headers_cookies() {
        let src = r#"
            SecRule REQUEST_HEADERS:X-Custom "@rx ^hdr" "id:20,phase:1,pass,severity:NOTICE"
            SecRule REQUEST_COOKIES:Session "@rx ^cook" "id:21,phase:2,pass,severity:NOTICE"
            SecRule ARGS_NAMES "@rx ^nm" "id:22,phase:2,pass,severity:NOTICE"
            SecRule REQUEST_METHOD "@streq POST" "id:23,phase:1,pass,severity:NOTICE"
            SecRule REQUEST_URI "@contains /path" "id:24,phase:1,pass,severity:NOTICE"
            SecRule REQUEST_BODY "@contains bodysig" "id:25,phase:2,pass,severity:NOTICE"
            SecRule FILES_NAMES "@rx ." "id:26,phase:2,pass,severity:NOTICE"
        "#;
        let (rs, rep) = RuleSet::load_seclang(src, None);
        assert_eq!(rep.loaded, 7);
        let headers = vec![
            ("x-custom".to_string(), "hdr-value".to_string()),
            ("other".to_string(), "nope".to_string()),
        ];
        let cookies = vec![("session".to_string(), "cookie-val".to_string())];
        let r = Request {
            method: "POST",
            uri: "/path/to?nm1=a&other=b",
            headers: &headers,
            cookies: &cookies,
            body: b"this has bodysign inside",
        };
        let v = rs.evaluate(&r, 100, &[]);
        let mut ids: Vec<u32> = v.hits.iter().map(|h| h.rule_id).collect();
        ids.sort();
        // FILES_NAMES 无文件上传 → 26 不命中
        assert_eq!(ids, vec![20, 21, 22, 23, 24, 25]);
    }

    #[test]
    fn count_variable_compares_as_number() {
        let src = r#"
            SecRule &ARGS "@eq 2" "id:30,phase:2,pass,severity:NOTICE"
            SecRule &REQUEST_HEADERS:Accept "@eq 0" "id:31,phase:1,pass,severity:NOTICE"
        "#;
        let (rs, _) = RuleSet::load_seclang(src, None);
        let headers = vec![("host".to_string(), "x".to_string())];
        let r = Request { method: "GET", uri: "/?a=1&b=2", headers: &headers, cookies: &[], body: b"" };
        let v = rs.evaluate(&r, 100, &[]);
        let mut ids: Vec<u32> = v.hits.iter().map(|h| h.rule_id).collect();
        ids.sort();
        assert_eq!(ids, vec![30, 31]);
        // 3 个参数 → @eq 2 不再命中
        let v = rs.evaluate(&req("/?a=1&b=2&c=3"), 100, &[]);
        assert!(v.hits.iter().all(|h| h.rule_id != 30));
    }

    #[test]
    fn paranoia_level_filtering() {
        let src = r#"
            SecRule ARGS "@rx ^pl1" "id:40,phase:2,pass,severity:CRITICAL,tag:'paranoia-level/1'"
            SecRule ARGS "@rx ^pl2" "id:41,phase:2,pass,severity:CRITICAL,tag:'paranoia-level/2'"
        "#;
        let (mut rs, _) = RuleSet::load_seclang(src, None);
        assert_eq!(rs.len(), 2); // 加载保留全部
        rs.set_paranoia(1);
        let v = rs.evaluate(&req("/?q=pl2"), 100, &[]);
        assert!(v.hits.iter().all(|h| h.rule_id != 41), "{:?}", v.hits);
        let v = rs.evaluate(&req("/?q=pl1"), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 40));
        rs.set_paranoia(2);
        let v = rs.evaluate(&req("/?q=pl2"), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 41));
        rs.set_paranoia(0); // 不过滤
        let v = rs.evaluate(&req("/?q=pl2"), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 41));
    }

    #[test]
    fn merge_rulesets() {
        let (a, _) = RuleSet::load_seclang(
            r#"SecRule ARGS "@rx ^a" "id:50,phase:2,severity:NOTICE""#,
            None,
        );
        let (b, _) = RuleSet::load_seclang(
            r#"SecRule ARGS "@rx ^b" "id:51,phase:2,severity:NOTICE""#,
            None,
        );
        let rs = a.merge(b);
        assert_eq!(rs.len(), 2);
        let v = rs.evaluate(&req("/?x=a&y=b"), 100, &[]);
        assert_eq!(v.score, 4);
    }

    #[test]
    fn tx_facade_guards_are_harmless() {
        // 模拟 CRS:PL 守卫 + setvar 初始化 + 宏展开操作符
        let src = r#"
            SecRule &TX:allowed_methods "@eq 0" "id:60,phase:1,pass,setvar:'tx.allowed_methods=GET POST'"
            SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:61,phase:1,pass,nolog"
            SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:62,phase:1,pass,severity:CRITICAL"
            SecAction "id:63,phase:1,pass,setvar:'tx.counter=+%{tx.critical_anomaly_score}',setvar:'tx.critical_anomaly_score=5'"
        "#;
        let (rs, _) = RuleSet::load_seclang(src, None);
        let r = Request { method: "GET", uri: "/", headers: &[], cookies: &[], body: b"" };
        let v = rs.evaluate(&r, 100, &[]);
        // GET 在白名单 → 62 不命中;守卫 61 无 severity 不产生 Hit
        assert_eq!(v.score, 0, "{:?}", v.hits);
        let r = Request { method: "TRACE", uri: "/", headers: &[], cookies: &[], body: b"" };
        let v = rs.evaluate(&r, 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 62), "{:?}", v.hits);
    }

    #[test]
    fn phase_3_4_stored_but_never_evaluated() {
        let src = r#"
            SecRule RESPONSE_BODY "@rx ." "id:70,phase:4,pass,severity:CRITICAL"
            SecRule ARGS "@rx ^x" "id:71,phase:2,pass,severity:CRITICAL"
        "#;
        let (rs, _) = RuleSet::load_seclang(src, None);
        assert_eq!(rs.len(), 2);
        let v = rs.evaluate(&req("/?q=x"), 100, &[]);
        assert_eq!(v.hits.len(), 1);
        assert_eq!(v.hits[0].rule_id, 71);
    }

    #[test]
    fn transform_chain_applies_in_order() {
        let src = r#"
            SecRule ARGS "@streq decoded script" "id:80,phase:2,pass,severity:NOTICE,t:urlDecodeUni,t:htmlEntityDecode,t:compressWhitespace"
        "#;
        let (rs, _) = RuleSet::load_seclang(src, None);
        // %64 → d;%20 → 空格;实体 '&nbsp;' → U+00A0 → 空白压缩为普通空格
        let v = rs.evaluate(&req("/?q=%64ecoded%20%26nbsp%3Bscript"), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 80), "{:?}", v.hits);
        let v = rs.evaluate(&req("/?q=%64ecoded%20script"), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 80), "{:?}", v.hits);
        let v = rs.evaluate(&req("/?q=decoded%20%20script"), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 80), "双空格应被压缩: {:?}", v.hits);
        // 未命中面:多余后缀
        let v = rs.evaluate(&req("/?q=decoded%20script%20x"), 100, &[]);
        assert!(v.hits.iter().all(|h| h.rule_id != 80));
    }
}
