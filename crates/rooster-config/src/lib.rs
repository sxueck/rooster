//! `rooster-config`:配置 schema、分层合并、语义校验、保留注释回写、
//! 原子写入与 inotify 热重载。
//!
//! `config.yaml` 是节点静态配置的唯一真相源:所有写入都落盘到
//! yaml;动态状态不经过本 crate。

pub mod error;
pub mod merge;
pub mod schema;
pub mod validate;
pub mod watcher;
pub mod writer;

pub use error::ConfigError;
pub use schema::{
    AcmeConfig, AclConfig, AgentConfigFile, EffectiveConfig, ForwardLimits, ForwardProto,
    ForwardRule, GeoipConfig, HubSection, LocalConfig, ManagedConfig, OnError, ProxyProtocol,
    Site, SiteTls, SshGuardConfig, SshLogSource, TlsMode, UpgradeMethod, UpgradeSection,
    WafMode, WasmLimits, WasmPlugin,
};
pub use watcher::{ReloadOutcome, WatcherState};
pub use writer::{hash_content, ConfigWriter, Seg};

/// 解析 + 校验一份 yaml 文本。热重载与管理 API 写入共用同一条路径,
/// 保证"面板写入"和"手动编辑"的校验行为一致。
pub fn parse_and_validate(raw: &str) -> Result<(AgentConfigFile, EffectiveConfig), ConfigError> {
    let file: AgentConfigFile = serde_norway::from_str(raw).map_err(error::from_yaml)?;
    let effective = file.merge_effective()?;
    validate::validate_effective(&effective).map_err(ConfigError::Validation)?;
    Ok((file, effective))
}

/// 默认生成的 config.yaml 模板(`rooster agent` 首次启动时写出)。
pub fn default_config_template() -> String {
    r#"# rooster agent configuration
# docs: https://example.invalid/rooster/docs
local:
  agent:
    node-name: rooster-local        # change me
    data-dir: /var/lib/rooster
    log-level: info

  management:
    # API only binds to loopback by default;
    # remote access goes through the hub.
    listen: 127.0.0.1:9870
    # Plaintext here is hashed and written back on first start.
    secret-key: changeme

  security:
    # Entries in this list are never banned.
    admin-allowlist: []
    apply-confirm-timeout: 60s

  events:
    retention: 30d

  forwards: []
  # - id: mysql-to-db
  #   proto: tcp
  #   listen: 0.0.0.0:13306
  #   target: 10.0.1.20:3306
  #   proxy-protocol: none

# managed:                      # written by hub templates; keep out for now
"#
    .to_string()
}
