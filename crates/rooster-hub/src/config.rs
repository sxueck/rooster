//! Hub `config.yaml`。
//!
//! 模板、节点、全局封禁、审计存 redb;这里只放进程级静态配置。
//! `secret-key` 与 Agent 一致:明文在首次启动时哈希回写。

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HubConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// External origin, independent of the internal TLS listener behind a proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    #[serde(default)]
    pub tls: HubTls,
    /// bcrypt 哈希;明文首启回写。
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub session_ttl: Option<Duration>,
    /// 面板静态文件目录;不存在时仅提供 API。
    #[serde(default = "default_panel_dir")]
    pub panel_dir: PathBuf,
    /// 模板下发后,Hub 代节点确认(确认类变更)前等待的秒数,
    /// 留出健康检查窗口。
    #[serde(default = "default_auto_confirm_delay")]
    pub auto_confirm_delay_secs: u64,
    /// 升级包 Ed25519 公钥,`ed25519:<base64>`。
    #[serde(default)]
    pub upgrade_public_key: Option<String>,
    /// 全局联动策略;首次启动导入 redb,之后以 redb 为准
    /// (面板可编辑)。
    #[serde(default)]
    pub global_ban_policies: Vec<PolicyConfig>,
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub audit_retention: Option<Duration>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9443))
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/rooster-hub")
}

fn default_panel_dir() -> PathBuf {
    PathBuf::from("web/dist")
}

fn default_auto_confirm_delay() -> u64 {
    10
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HubTls {
    /// `static`(cert/key 文件)或 `none`(明文 http/ws,仅限内网/测试)。
    pub mode: Option<HubTlsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    /// 服务器证书所属的 CA(信任锚)。配了就在 `GET /v0/ca.crt` 公开,
    /// 供 install.sh 落进 Agent 的 hub.ca —— 公开公钥不是私钥,不构成
    /// 凭据;未配则 Agent 只能靠系统根证书库校验。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HubTlsMode {
    /// cert/key 静态证书。
    Static,
    /// 明文监听(开发/内网)。Agent url 用 ws://,面板用 http://。
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PolicyConfig {
    pub id: String,
    pub r#match: PolicyMatch,
    /// 至少 N 个不同节点上报才全网封禁。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_nodes: Option<u32>,
    /// 同一 IP 在窗口内的命中次数阈值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub window: Option<Duration>,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PolicyMatch {
    pub plugin: String,
    pub event: String,
    /// 严重级别匹配(Block 事件的 severity 字段,大小写不敏感):
    /// 声明后仅命中带同名严重级别的事件;不带 severity 的事件(老
    /// Agent / 非 Block 类)不参与该策略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

impl HubConfig {
    pub fn hub_base(&self, host: &str) -> Result<String, String> {
        let scheme = if matches!(self.tls_mode(), HubTlsMode::Static) { "https" } else { "http" };
        let base = self.public_url.clone().unwrap_or_else(|| format!("{scheme}://{host}"));
        let uri: axum::http::Uri = base.parse().map_err(|_| "invalid public-url/Host".to_string())?;
        let authority = uri.authority().ok_or("public-url must include a host")?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || !authority.as_str().bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        {
            return Err("public-url must be an http(s) origin without credentials, path or query".into());
        }
        if uri.scheme_str() == Some("http") && !matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]") {
            return Err("public-url must use HTTPS outside loopback".into());
        }
        Ok(base.trim_end_matches('/').to_string())
    }

    pub fn session_ttl(&self) -> Duration {
        self.session_ttl.unwrap_or(Duration::from_secs(12 * 3600))
    }

    pub fn audit_retention(&self) -> Duration {
        self.audit_retention.unwrap_or(Duration::from_secs(180 * 24 * 3600))
    }

    pub fn tls_mode(&self) -> HubTlsMode {
        self.tls.mode.unwrap_or(HubTlsMode::None)
    }

    pub fn tls_mode_str(&self) -> &'static str {
        match self.tls_mode() {
            HubTlsMode::Static => "static",
            HubTlsMode::None => "none",
        }
    }
}

/// 首次启动写出的带注释模板。
pub fn default_hub_config_template() -> String {
    r#"# rooster hub 配置
# 明文监听只允许绑回环(见 lib.rs 的启动校验);要接远端 Agent 必须改
# tls.mode: static —— Agent 凭客户端证书证明身份(强制 mTLS)。
listen: 127.0.0.1:9443
data-dir: /var/lib/rooster-hub
# public-url: https://hub.example.com:443   # Required behind a TLS terminator
tls:
  # static: 使用下方 cert/key(对外服务用这个)
  # none:   明文,仅允许 listen 为 127.0.0.1(开发/本机反代终止 TLS)
  mode: none
  # cert: /etc/rooster/hub.crt
  # key: /etc/rooster/hub.key
  # ca: /etc/rooster/hub-ca.crt   # 自签/私有 CA 时公开给 install.sh 的信任锚
secret-key: ""            # 明文会在首次启动时自动哈希
cors-allowed-origins: []
session-ttl: 12h
panel-dir: web/dist
auto-confirm-delay-secs: 10
# upgrade-public-key: "ed25519:<base64>"
global-ban-policies:
  - id: ssh-bruteforce
    match: { plugin: ssh-guard, event: ban }
    min-nodes: 1
    ttl: 24h
audit-retention: 180d
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_origin_overrides_internal_plaintext_and_rejects_shell_inputs() {
        let mut cfg: HubConfig = serde_norway::from_str(&default_hub_config_template()).unwrap();
        cfg.public_url = Some("https://hub.example:8443/".into());
        assert_eq!(cfg.hub_base("127.0.0.1:9443").unwrap(), "https://hub.example:8443");
        for invalid in ["http://remote.example:80", "https://hub.example/path", "https://user@hub.example", "https://hub.example?x=1", "https://hub.example/$(id)"] {
            cfg.public_url = Some(invalid.into());
            assert!(cfg.hub_base("127.0.0.1:9443").is_err(), "{invalid}");
        }
        cfg.public_url = None;
        assert_eq!(cfg.hub_base("127.0.0.1:9443").unwrap(), "http://127.0.0.1:9443");
        assert!(cfg.hub_base("bad;host").is_err());
    }

    #[test]
    fn parses_example_config() {
        let cfg: HubConfig = serde_norway::from_str(&default_hub_config_template()).unwrap();
        assert_eq!(cfg.listen.port(), 9443);
        assert!(matches!(cfg.tls_mode(), HubTlsMode::None));
        assert_eq!(cfg.session_ttl(), Duration::from_secs(12 * 3600));
        assert_eq!(cfg.audit_retention(), Duration::from_secs(180 * 24 * 3600));
        assert_eq!(cfg.global_ban_policies.len(), 1);
        assert_eq!(cfg.global_ban_policies[0].min_nodes, Some(1));
    }
}
