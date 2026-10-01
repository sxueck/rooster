//! 内置签名:以 SecLang 文本为唯一事实源,经 `load_seclang` 加载。
//!
//! ID 段位与签名键的映射:
//! - `sqli`           → 100xx
//! - `xss`            → 101xx
//! - `traversal`      → 102xx(路径穿越)
//! - `rce`            → 103xx(命令注入)
//! - `sensitive-files`→ 104xx(敏感文件/备份扩展名)
//! - `scanner-ua`     → 105xx(扫描器 User-Agent)
//!
//! `load_builtin(["sqli", ...])` 选择对应段位拼接;空列表 = 全部。


use crate::{LoadReport, RuleSet};

const SQLI: &str = r#"
# ---- SQL 注入:union select / 永真式 / 注释截断 / 堆叠 ----
SecRule REQUEST_URI|ARGS|REQUEST_BODY|REQUEST_COOKIES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|REQUEST_HEADERS:X-Forwarded-Host "@rx (?i)(?:union(?:\s|%20|/[\s\S]*?/)+(?:all|distinct)?(?:\s|%20)+select|(?:'|%27)\s*(?:or|and)\b|(?:\b|')\s*(?:or|and)\s*(?:'[^']*'|\"\w+\"|\d+)\s*=\s*|1\s*=\s*1\b|;\s*(?:drop|delete|insert|update|truncate|shutdown|alter)\b|(?:'|%27);|--(?:\s|%20|$|/|\+)|/\*[\s\S]{0,200}?\*/|@@version|sleep\s*\(|benchmark\s*\()" \
    "id:10001,phase:2,block,log,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,msg:'SQL injection: union select / tautology / comment / stacked query',severity:CRITICAL,tag:'attack-sqli',tag:'paranoia-level/1'"

SecRule ARGS|REQUEST_BODY "@detectSQLi" \
    "id:10002,phase:2,block,log,t:none,t:urlDecodeUni,t:htmlEntityDecode,msg:'SQL injection detected via libinjection-equivalent heuristic',severity:CRITICAL,tag:'attack-sqli',tag:'paranoia-level/1'"
"#;

const XSS: &str = r#"
# ---- XSS:脚本标签 / js URI / 事件处理器 ----
SecRule REQUEST_URI|ARGS|REQUEST_BODY|REQUEST_COOKIES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx (?i)(?:<\s*/?\s*(?:script|iframe|object|embed|svg|math|base)\b|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|\bon(?:error|load|click|mouseover|focus|blur|toggle|animationstart|pointerover)\s*=\s*['\"]?|<\s*img[^>]{0,200}?onerror|document\s*\.\s*cookie|\balert\s*\(|\beval\s*\(|string\.fromcharcode|srcdoc\s*=)" \
    "id:10101,phase:2,block,log,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,msg:'XSS: script tag / js URI / event handler',severity:CRITICAL,tag:'attack-xss',tag:'paranoia-level/1'"

SecRule ARGS|REQUEST_URI "@detectXSS" \
    "id:10102,phase:2,block,log,t:none,t:urlDecodeUni,msg:'XSS detected via libinjection-equivalent heuristic',severity:ERROR,tag:'attack-xss',tag:'paranoia-level/1'"
"#;

const TRAVERSAL: &str = r#"
# ---- 路径穿越:解码后与原始编码两种形态 ----
SecRule REQUEST_URI|REQUEST_FILENAME|ARGS|REQUEST_BODY "@rx (?i)(?:\.\./|\.\.\\|(?:^|[/=])\.\.(?:/|\\|$)|(?:^|/)etc/(?:passwd|shadow|hosts|group)\b|boot\.ini|win\.ini)" \
    "id:10201,phase:2,block,log,t:none,t:urlDecodeUni,t:removeNulls,msg:'Path traversal: ../ or ..\\ or system file access',severity:CRITICAL,tag:'attack-lfi',tag:'paranoia-level/1'"

SecRule REQUEST_URI_RAW|REQUEST_FILENAME "@rx (?i)(?:%2e%2e(?:%2f|%5c|/|\\|$)|%252e%252e|\.\.%2f|\.\.%5c|%c0%ae%c0%ae)" \
    "id:10202,phase:2,block,log,t:none,msg:'Path traversal: encoded dot-dot sequence',severity:CRITICAL,tag:'attack-lfi',tag:'paranoia-level/1'"
"#;

const RCE: &str = r#"
# ---- 命令注入:链接符 + 命令、反引号、$() ----
SecRule REQUEST_URI|ARGS|REQUEST_BODY|REQUEST_COOKIES "@rx (?i)(?:[;|&\r\n]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|php|powershell|pwsh|rm|chmod|chown|ping|nslookup|dig|sleep|echo)\b|`[^`]{2,100}`|\$\([^)\s]{1,100}\)|\|\|\s*(?:id|whoami|uname)\b|/bin/(?:ba|z|da)?sh|\beval\s*\(|\bexec\s*\(|&&\s*(?:id|whoami))" \
    "id:10301,phase:2,block,log,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,msg:'Command injection: shell metacharacter + command / backtick / $()',severity:CRITICAL,tag:'attack-rce',tag:'paranoia-level/1'"
"#;

const SENSITIVE: &str = r#"
# ---- 敏感文件:配置/版本库/备份扩展名 ----
SecRule REQUEST_URI|REQUEST_FILENAME "@rx (?i)(?:/\.(?:env|git|svn|hg|bzr|htaccess|htpasswd|ds_store)(?:/|$|[?&#])|\.git/(?:config|HEAD|index)|wp-config\.php~?|\.ssh/(?:id_rsa|authorized_keys)|\.aws/credentials|/\.docker/config|phpunit/logs/|web\.config\.bak|\.DS_Store$)" \
    "id:10401,phase:2,block,log,t:none,t:urlDecodeUni,msg:'Sensitive file access: .env/.git/.svn/.htaccess etc',severity:CRITICAL,tag:'attack-disclosure',tag:'paranoia-level/1'"

SecRule REQUEST_URI|REQUEST_FILENAME "@rx (?i)\.(?:bak|sql|old|orig|save|swp|swo|bkp|backup|copy|default|dist|inc|ini)(?:$|[?&#])" \
    "id:10402,phase:2,block,log,t:none,t:urlDecodeUni,msg:'Sensitive file access: backup extension',severity:ERROR,tag:'attack-disclosure',tag:'paranoia-level/1'"
"#;

const SCANNER_UA: &str = r#"
# ---- 扫描器 User-Agent ----
SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:X-Scanner "@pm sqlmap nikto nuclei masscan zgrab dirbuster gobuster wpscan acunetix nessus netsparker w3af whatweb skipfish arachni dirb wfuzz ffuf httpx naabu snallygaster jaeles hugo ruder burpsuite" \
    "id:10501,phase:1,block,log,t:none,t:lowercase,msg:'Scanner User-Agent detected',severity:ERROR,tag:'attack-reputation-scanner',tag:'paranoia-level/1'"
"#;

/// 签名键 → SecLang 段位文本。
fn categories() -> [(&'static str, &'static str); 6] {
    [
        ("sqli", SQLI),
        ("xss", XSS),
        ("traversal", TRAVERSAL),
        ("rce", RCE),
        ("sensitive-files", SENSITIVE),
        ("scanner-ua", SCANNER_UA),
    ]
}

pub(crate) fn load_builtin(signatures: &[String]) -> (RuleSet, LoadReport) {
    let cats = categories();
    let selected: Vec<&&'static str> = if signatures.is_empty() {
        cats.iter().map(|(_, src)| src).collect()
    } else {
        cats.iter()
            .filter(|(name, _)| signatures.iter().any(|s| s.eq_ignore_ascii_case(name)))
            .map(|(_, src)| src)
            .collect()
    };
    let mut source = String::new();
    for src in selected {
        source.push_str(src);
        source.push('\n');
    }
    RuleSet::load_seclang(&source, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Request;
    #[test]
    fn builtin_source_is_fully_loadable() {
        // 内置签名文本必须 100% 可加载(不产生 Skip)
        let (rs, rep) = load_builtin(&[]);
        assert!(rep.skipped.is_empty(), "{:?}", rep.skipped);
        assert_eq!(rs.len(), 10);
    }

    #[test]
    fn signature_filtering() {
        let (rs, _) = load_builtin(&["sqli".to_string()]);
        assert_eq!(rs.len(), 2);
        let (rs, _) = load_builtin(&["scanner-ua".to_string(), "xss".to_string()]);
        assert_eq!(rs.len(), 3);
        // 未知签名键被忽略
        let (rs, rep) = load_builtin(&["nope".to_string()]);
        assert_eq!(rs.len(), 0);
        assert!(rep.skipped.is_empty());
    }

    fn req_with_headers<'a>(uri: &'a str, headers: &'a [(String, String)]) -> Request<'a> {
        Request { method: "GET", uri, headers, cookies: &[], body: b"" }
    }

    fn req<'a>(uri: &'a str, ua_header: &'a [(String, String)]) -> Request<'a> {
        req_with_headers(uri, ua_header)
    }

    #[test]
    fn classic_sqli_blocked_at_threshold_5() {
        let (rs, _) = load_builtin(&[]);
        let v = rs.evaluate(
            &req("/search?q=1'%20union%20select%20password%20from%20users--", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]),
            5,
            &[],
        );
        assert!(v.blocked, "score={} hits={:?}", v.score, v.hits);
        assert!(v.hits.iter().any(|h| (10001..=10002).contains(&h.rule_id)));

        // 头部注入:Referer / Cookie
        let r = Request {
            method: "GET",
            uri: "/",
            headers: &[("referer".to_string(), "1' OR '1'='1".to_string())],
            cookies: &[("session".to_string(), "x' union select 1--".to_string())],
            body: b"",
        };
        let v = rs.evaluate(&r, 5, &[]);
        assert!(v.blocked, "hits={:?}", v.hits);
    }

    #[test]
    fn xss_traversal_rce_scanner_detected() {
        let (rs, _) = load_builtin(&[]);
        let v = rs.evaluate(&req("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]), 100, &[]);
        assert!(v.hits.iter().any(|h| (10101..=10102).contains(&h.rule_id)), "{:?}", v.hits);

        let v = rs.evaluate(&req("/download?file=../../etc/passwd", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]), 100, &[]);
        assert!(v.hits.iter().any(|h| (10201..=10202).contains(&h.rule_id)), "{:?}", v.hits);

        let v = rs.evaluate(&req("/ping?host=8.8.8.8%3Bcat%20%2Fetc%2Fpasswd", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 10301), "{:?}", v.hits);

        let v = rs.evaluate(&req("/x?c=$(whoami)", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 10301), "{:?}", v.hits);

        // 扫描器 UA:ERROR=4,阈值 5 下记录但不阻断
        let v = rs.evaluate(&req("/", &[("user-agent".to_string(), "sqlmap/1.7.2#stable (http://sqlmap.org)".to_string())]), 5, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 10501));
        assert!(!v.blocked);
        assert_eq!(v.score, 4);

        // 敏感文件
        let v = rs.evaluate(&req("/.env", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 10401), "{:?}", v.hits);
        let v = rs.evaluate(&req("/backup/db.sql", &[("user-agent".to_string(), "Mozilla/5.0".to_string())]), 100, &[]);
        assert!(v.hits.iter().any(|h| h.rule_id == 10402), "{:?}", v.hits);
    }

    #[test]
    fn benign_requests_score_zero() {
        let (rs, _) = load_builtin(&[]);
        for (uri, ua) in [
            ("/index.html", "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0"),
            ("/search?q=hello+world&lang=en", "Mozilla/5.0"),
            ("/api/users/42?page=2", "curl/8.6.0"),
            ("/docs/a%20b.html", "Wget/1.21"),
        ] {
            let v = rs.evaluate(&req(uri, &[("user-agent".to_string(), ua.to_string())]), 5, &[]);
            assert_eq!(v.score, 0, "{uri} hits={:?}", v.hits);
            assert!(!v.blocked);
        }
    }
}
