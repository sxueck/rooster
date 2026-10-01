//! http-guard 的生效配置解析:`HttpGuardSettings` → [`Effective`]。
//!
//! 每次全量 `apply` 都重建一份 `Effective`(站点解析、上游 URL、
//! 限速规则、TLS 服务端配置、GeoIP 库),整体换成 `Arc` 后原子替换。
//! 监听任务与已建立连接按连接粒度取快照,因此配置变化不需要重启
//! listener,也不影响已建立连接(与 forward 同思路)。
//! 副作用:修改站点配置会重建该站点的限速桶(计数器归零),
//! 统计计数器在站点 id 不变时跨 apply 保留。

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipnet::IpNet;
use rooster_config::{Site, TlsMode, WafMode};

use super::throttle::{ParsedRate, RateBook};
use super::HttpGuardSettings;

// ---------------------------------------------------------------------------
// 每站点统计(同源:面板可轮询)。

/// 单站点计数器;`active` 用于 apply 时回收已删除且已排空的条目。
pub(crate) struct SiteStats {
    pub(crate) requests: AtomicU64,
    /// 被拒的请求 / 连接:WAF 403、Geo 403、限速 429 与透传 drop。
    pub(crate) blocked: AtomicU64,
    pub(crate) conns_passthrough: AtomicU64,
    /// 客户端 → 上游字节数(HTTP 请求体 + 透传双向拷贝的 client→upstream)。
    pub(crate) bytes_in: Arc<AtomicU64>,
    /// 上游 → 客户端字节数(HTTP 响应体 + 透传 upstream→client)。
    pub(crate) bytes_out: Arc<AtomicU64>,
    /// 存活连接(HTTP 连接 + 透传连接)。
    pub(crate) active: AtomicU64,
}

impl SiteStats {
    fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            conns_passthrough: AtomicU64::new(0),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
            active: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// 上游解析

/// 解析后的上游地址。`upstream` 支持三种写法:
/// `https://host[:port][/base]`、`http://host[:port][/base]` 与裸
/// `host:port`(视为 http)。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Upstream {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// 基础路径(去尾部 `/`,可为空)。请求路径直接拼接在其后。
    pub base: String,
}

impl Upstream {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            (false, s)
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            // IPv6 字面量
            let (host, tail) = stripped.split_once(']')?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().ok()?,
                None => {
                    if tls {
                        443
                    } else {
                        80
                    }
                }
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                    (h.to_string(), p.parse().ok()?)
                }
                _ => (
                    authority.to_string(),
                    if tls { 443 } else { 80 },
                ),
            }
        };
        if host.is_empty() {
            return None;
        }
        let base = path.trim_end_matches('/').to_string();
        Some(Self {
            tls,
            host,
            port,
            base,
        })
    }

    /// 请求路径 + query 拼接到上游:base + path(path 以 `/` 开头)。
    /// join 规则:`http://h:8080/api` + `/v1/x?q` → `/api/v1/x?q`。
    pub(crate) fn join(&self, path_and_query: &str) -> String {
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let owned_path;
        let path = if path.starts_with('/') {
            path
        } else {
            owned_path = format!("/{path}");
            owned_path.as_str()
        };
        let full = format!("{}{}", self.base, path);
        match query {
            Some(q) => format!("{full}?{q}"),
            None => full,
        }
    }

    pub(crate) fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

// ---------------------------------------------------------------------------
// 生效配置

/// 单站点运行时:原始配置 + 解析产物 + 共享计数器与限速桶。
pub(crate) struct SiteRt {
    pub cfg: Site,
    /// 小写化的 server_names(Host / SNI 匹配)。
    pub names: Vec<String>,
    pub upstream: Upstream,
    pub rates: Vec<ParsedRate>,
    /// terminate 模式的服务端 TLS 配置;加载失败为 None(握手拒绝)。
    pub tls_server: Option<Arc<rustls::ServerConfig>>,
    pub stats: Arc<SiteStats>,
    /// 限速桶:key 含规则索引,站点配置变化时随 SiteRt 重建。
    pub limiter: Mutex<RateBook>,
}

impl SiteRt {
    /// Host / SNI 匹配(大小写不敏感)。
    pub(crate) fn matches(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.names.iter().any(|n| *n == name)
    }

    pub(crate) fn waf_mode(&self) -> WafMode {
        self.cfg.waf.as_ref().map(|w| w.mode).unwrap_or(WafMode::Off)
    }

    pub(crate) fn is_terminate(&self) -> bool {
        self.cfg.tls.mode == TlsMode::Terminate
    }
}

/// 一代生效配置;监听任务 / 连接任务按连接粒度克隆 `Arc<Effective>`。
pub(crate) struct Effective {
    pub sites: Vec<Arc<SiteRt>>,
    pub trusted_proxies: Vec<IpNet>,
    pub geo: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    pub body_limit: usize,
    pub ban_hook: Option<Arc<dyn Fn(&str, Duration) + Send + Sync>>,
}

impl Effective {
    /// 按 Host / SNI 找站点;无匹配取第一个站点(调用方保证非空)。
    pub(crate) fn route(&self, name: Option<&str>) -> Option<Arc<SiteRt>> {
        match name {
            Some(n) => self
                .sites
                .iter()
                .find(|s| s.matches(n))
                .cloned()
                .or_else(|| self.sites.first().cloned()),
            None => self.sites.first().cloned(),
        }
    }
}

/// 构建一代生效配置;非法条目记日志并跳过,整体不失败。
pub(crate) fn build(cfg: &HttpGuardSettings, stats: &Mutex<HashMap<String, Arc<SiteStats>>>) -> Arc<Effective> {
    let mut sites = Vec::new();
    for site in &cfg.sites {
        let Some(upstream) = Upstream::parse(&site.upstream) else {
            tracing::warn!(site = %site.id, upstream = %site.upstream, "invalid site upstream, skipping site");
            continue;
        };
        let rates: Vec<ParsedRate> = site
            .rate_limit
            .iter()
            .enumerate()
            .filter_map(|(id, r)| {
                match ParsedRate::parse(r) {
                    Some(mut p) => {
                        // 稳定的规则身份:限速桶表按它寻址,不按调用方传入
                        // 切片的位置(透传模式只传子集)。
                        p.id = id as u32;
                        Some(p)
                    }
                    None => {
                        tracing::warn!(site = %site.id, key = %r.key, rate = %r.rate, "invalid rate rule, skipping");
                        None
                    }
                }
            })
            .collect();
        // terminate 模式预加载证书;失败仅告警,握手被拒绝。
        // 显式 cert/key 已在 bans::ensure_httpguard 解析(含 ACME 缓存回退)。
        let tls_server = if site.tls.mode == TlsMode::Terminate {
            match (&site.tls.cert, &site.tls.key) {
                (Some(c), Some(k)) => match super::tlsconf::server_config(c, k) {
                    Ok(sc) => Some(sc),
                    Err(e) => {
                        tracing::error!(site = %site.id, error = %e, "tls terminate cert/key load failed; refusing handshakes");
                        None
                    }
                },
                _ => {
                    tracing::warn!(site = %site.id, "terminate site without cert/key; refusing handshakes");
                    None
                }
            }
        } else {
            None
        };
        let st = {
            let mut map = stats.lock().unwrap();
            map.entry(site.id.clone())
                .or_insert_with(|| Arc::new(SiteStats::new()))
                .clone()
        };
        sites.push(Arc::new(SiteRt {
            names: site
                .server_names
                .iter()
                .map(|n| n.to_ascii_lowercase())
                .collect(),
            cfg: site.clone(),
            upstream,
            rates,
            tls_server,
            stats: st,
            limiter: Mutex::new(RateBook::default()),
        }));
    }
    if sites.is_empty() {
        tracing::warn!("http-guard: no usable sites configured");
    }

    let trusted_proxies: Vec<IpNet> = cfg
        .trusted_proxies
        .iter()
        .filter_map(|s| match s.parse::<IpNet>() {
            Ok(n) => Some(n),
            Err(_) => {
                tracing::warn!(cidr = %s, "invalid trusted-proxies entry, skipping");
                None
            }
        })
        .collect();

    let geo = load_geo(&cfg.geoip_db);
    let body_limit = if cfg.body_limit == 0 {
        super::DEFAULT_BODY_LIMIT
    } else {
        cfg.body_limit
    };

    Arc::new(Effective {
        sites,
        trusted_proxies,
        geo,
        body_limit,
        ban_hook: cfg.ban_hook.clone(),
    })
}

fn load_geo(path: &Option<PathBuf>) -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
    let path = path.as_ref()?;
    match maxminddb::Reader::open_readfile(path) {
        Ok(r) => {
            tracing::info!(db = %path.display(), "http-guard geoip db loaded");
            Some(Arc::new(r))
        }
        Err(e) => {
            tracing::warn!(db = %path.display(), error = %e, "geoip db load failed; geo rules disabled");
            None
        }
    }
}

/// apply 后回收:被删除且已排空(active == 0)的站点统计条目。
pub(crate) fn gc_stats(
    stats: &Mutex<HashMap<String, Arc<SiteStats>>>,
    live: &[Arc<SiteRt>],
) {
    let live_ids: Vec<&str> = live.iter().map(|s| s.cfg.id.as_str()).collect();
    stats
        .lock()
        .unwrap()
        .retain(|id, st| live_ids.contains(&id.as_str()) || st.active.load(Ordering::Relaxed) > 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_parse_and_join() {
        let up = Upstream::parse("http://127.0.0.1:8080").unwrap();
        assert!(!up.tls);
        assert_eq!(up.host, "127.0.0.1");
        assert_eq!(up.port, 8080);
        assert_eq!(up.base, "");
        assert_eq!(up.join("/a/b?x=1"), "/a/b?x=1");

        let up = Upstream::parse("https://api.example.test/base/").unwrap();
        assert!(up.tls);
        assert_eq!(up.port, 443);
        assert_eq!(up.base, "/base");
        assert_eq!(up.join("/v1?q=2"), "/base/v1?q=2");

        let up = Upstream::parse("127.0.0.1:9443").unwrap();
        assert!(!up.tls);
        assert_eq!(up.port, 9443);
        assert_eq!(up.authority(), "127.0.0.1:9443");

        let up = Upstream::parse("http://[::1]:8080/x").unwrap();
        assert_eq!(up.host, "::1");
        assert_eq!(up.authority(), "[::1]:8080");
        assert_eq!(up.join("/y"), "/x/y");

        assert!(Upstream::parse("").is_none());
        assert!(Upstream::parse("http://").is_none());
    }

    fn site_rt(id: &str) -> Arc<SiteRt> {
        Arc::new(SiteRt {
            cfg: rooster_config::Site {
                id: id.to_string(),
                server_names: vec![format!("{id}.test")],
                tls: Default::default(),
                upstream: "http://127.0.0.1:1".to_string(),
                waf: None,
                rate_limit: vec![],
                geo: None,
                proxy_protocol: None,
                ja4_deny: vec![],
                redirect_https: None,
            },
            names: vec![format!("{id}.test")],
            upstream: Upstream::parse("http://127.0.0.1:1").unwrap(),
            rates: vec![],
            tls_server: None,
            stats: Arc::new(SiteStats::new()),
            limiter: Mutex::new(RateBook::default()),
        })
    }

    /// 回归(F13):`active` 曾经只减不增(守卫 drop 时 `fetch_sub`,全仓
    /// 没有对应的 `fetch_add`),第一条透传连接关闭就把计数回绕成
    /// `u64::MAX`,`gc_stats` 的 `active > 0` 条件于是永远成立,已删除
    /// 站点的统计条目再也回收不掉。
    #[test]
    fn gc_stats_reclaims_removed_sites_once_no_connections() {
        let stats = Mutex::new(HashMap::new());
        let site = site_rt("s1");
        stats
            .lock()
            .unwrap()
            .insert(site.cfg.id.clone(), site.stats.clone());
        assert_eq!(stats.lock().unwrap().len(), 1);

        // 有活跃连接时保留。
        site.stats.active.store(1, Ordering::Relaxed);
        gc_stats(&stats, &[]);
        assert_eq!(stats.lock().unwrap().len(), 1, "活跃连接期间不应回收");

        // 连接结束后回收(计数由 ConnGuard 对称增减)。
        site.stats.active.store(0, Ordering::Relaxed);
        gc_stats(&stats, &[]);
        assert_eq!(stats.lock().unwrap().len(), 0, "无活跃连接时应回收");
    }

    /// 限速规则在构建时拿到稳定身份:限速桶表按它寻址,而不是按调用方
    /// 传入切片的位置(透传模式只传 `key=ip` 子集,会重新编号)。
    #[test]
    fn rate_rule_ids_are_stable_by_config_position() {
        let cfg = HttpGuardSettings {
            listen_http: None,
            listen_https: None,
            sites: vec![rooster_config::Site {
                id: "s".to_string(),
                server_names: vec!["s.test".to_string()],
                tls: Default::default(),
                upstream: "http://127.0.0.1:1".to_string(),
                waf: None,
                rate_limit: vec![
                    rooster_config::schema::RateLimitRule {
                        key: "header:x-key".to_string(),
                        rate: "10/second".to_string(),
                        burst: 0,
                        on_exceed: rooster_config::schema::OnExceed::Reject,
                        ban_after: None,
                    },
                    rooster_config::schema::RateLimitRule {
                        key: "ip".to_string(),
                        rate: "10/second".to_string(),
                        burst: 0,
                        on_exceed: rooster_config::schema::OnExceed::Reject,
                        ban_after: None,
                    },
                ],
                geo: None,
                proxy_protocol: None,
                ja4_deny: vec![],
                redirect_https: None,
            }],
            trusted_proxies: vec![],
            geoip_db: None,
            body_limit: 0,
            ban_hook: None,
        };
        let eff = build(&cfg, &Mutex::new(HashMap::new()));
        let rates = &eff.sites[0].rates;
        assert_eq!(rates.len(), 2);
        assert_eq!(rates[0].id, 0, "header 规则是配置里的第 0 条");
        assert_eq!(rates[1].id, 1, "ip 规则是配置里的第 1 条");
        // 透传模式过滤后的子集仍携带原 id,不会退化成 0。
        let subset: Vec<_> = rates.iter().filter(|r| r.is_ip_key()).cloned().collect();
        assert_eq!(subset.len(), 1);
        assert_eq!(subset[0].id, 1, "过滤后仍应保留配置位置");
    }
}
