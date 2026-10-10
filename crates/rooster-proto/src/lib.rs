//! Hub <-> Agent 帧协议。
//!
//! 帧在 WSS 长连接上以二进制 WebSocket 消息承载,MessagePack 编码
//! (rmp-serde),基于 `id` 的多路复用用于 ApiRequest/ApiResponse 与
//! ApplyTemplate/TemplateResult。Event 批次携带单调 seq,Hub 用
//! EventAck 确认,Agent 据此清理离线补报缓冲。

use serde::{Deserialize, Serialize};

/// 长连接上的帧。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Agent 连接建立后的第一帧:节点信息、版本、配置哈希。
    Hello {
        node_id: String,
        version: String,
        config_hash: String,
    },
    /// 心跳(15s 间隔);对端必须回 Pong。
    Ping,
    Pong,
    /// 透传管理 API 请求。headers 只携带需要转发的少数头
    /// (content-type / if-match)。
    ApiRequest {
        id: u64,
        method: String,
        path: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        body: Vec<u8>,
    },
    ApiResponse {
        id: u64,
        status: u16,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        body: Vec<u8>,
    },
    /// 事件批量上报;first_seq + 序号便于 Hub 精确去重。
    Event {
        first_seq: u64,
        #[serde(default)]
        batch: Vec<Event>,
    },
    /// Hub 确认已收到 seq 及之前的全部事件;Agent 清理补报缓冲。
    EventAck { acked_through: u64 },
    GlobalBan {
        ip: String,
        ttl_secs: u64,
        reason: String,
        source_node: String,
    },
    GlobalUnban { ip: String },
    /// 节点(重)连上后 Hub 下发当前全部有效全局封禁,Agent 差量合并
    /// 新增的写入,不在列表内的 scope=global 条目移除。
    GlobalBanSync {
        bans: Vec<GlobalBanInfo>,
    },
    /// 模板下发:写入节点 config.yaml 的 managed 段。
    ApplyTemplate { id: u64, yaml: String },
    TemplateResult {
        id: u64,
        ok: bool,
        #[serde(default)]
        error: Option<String>,
        /// 变更触发确认流程时,返回待确认 token 由 Hub 代确认。
        #[serde(default)]
        confirm_token: Option<String>,
    },
    /// Agent 证书到期前 30 天,经已认证的长连接请求续签。
    RenewCert { csr_pem: String },
    Renewed { cert_pem: String },
    /// 远程升级:url 为带签名的下载地址;public_key 为 Hub
    /// 配置的 Ed25519 公钥(本地 security.upgrade-public-key 可锚定)。
    Upgrade {
        version: String,
        url: String,
        signature: String,
        #[serde(default)]
        public_key: Option<String>,
    },
    /// 协议级错误(如注册 token 无效),message 面向日志。
    Error { message: String },
}

/// Agent 上报 / 本地记录的事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Ban {
        ip: String,
        reason: String,
        plugin: String,
        scope: String,
        ttl_secs: u64,
        /// 攻击源国家/地区名（Agent 端 GeoIP 属地标注；无库/无匹配 → None）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
    },
    HoneypotHit {
        ip: String,
        port: u16,
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
    },
    Block {
        ip: String,
        rule_id: String,
        site: String,
        /// WAF 规则严重级别名(CRITICAL/ERROR/WARNING/NOTICE),供联动策略过滤。
        /// 老版 Agent 不带该字段 → None,即“未知严重级别”。
        #[serde(default)]
        severity: Option<String>,
        /// 命中的请求路径(无路径的事件无法定位攻击目标)。
        #[serde(default)]
        path: Option<String>,
        /// 本次评分命中的全部规则 id(异常评分模式下 `rule_id` 只是最严一条,
        /// “哪些规则在真实被打”才是运维要的清单)。
        #[serde(default)]
        hits: Vec<u32>,
        /// 累计异常评分(阈值见 `waf.crs.inbound-anomaly-threshold`)。
        #[serde(default)]
        score: Option<u32>,
        /// 攻击源国家/地区名(同 Ban.country)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
    },
    /// 配置在进程外被修改并通过校验,已热重载。
    ConfigChanged { hash: String },
    /// 配置在进程外被修改但未通过校验,继续沿用旧配置。
    ConfigInvalid { error: String, line: Option<u32> },
    /// 变更未在时限内确认,已回滚。
    ConfigRolledBack { reason: String },
    /// 管理接口鉴权失败达到阈值,来源被临时封禁。
    AuthTempBan { peer: String },
    /// WASM 插件经宿主函数 emit_event 上报。
    PluginEvent { plugin: String, payload: String },
    /// 远程升级状态变化:downloaded / applied / rolled_back / failed。
    UpgradeStatus { version: String, stage: String, detail: Option<String> },
}

/// 全局封禁条目(全量同步用)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalBanInfo {
    pub ip: String,
    pub ttl_secs: u64,
    pub reason: String,
    pub source_node: String,
}

// ---------------------------------------------------------------------------
// MessagePack 编解码

#[derive(Debug, thiserror::Error)]
#[error("frame decode error: {0}")]
pub struct DecodeError(String);

/// 编码一帧为 MessagePack 字节。
pub fn encode(frame: &Frame) -> Vec<u8> {
    rmp_serde::to_vec(frame).expect("frame serializes")
}

/// 解码一帧。多余字节视为协议错误。
pub fn decode(bytes: &[u8]) -> Result<Frame, DecodeError> {
    rmp_serde::from_slice(bytes).map_err(|e| DecodeError(e.to_string()))
}

impl Event {
    /// 事件主语 IP(封禁/拦截类),用于联动策略按 IP 聚合。
    pub fn subject_ip(&self) -> Option<&str> {
        match self {
            Event::Ban { ip, .. } | Event::HoneypotHit { ip, .. } | Event::Block { ip, .. } => Some(ip),
            _ => None,
        }
    }

    /// 事件严重级别名,用于联动策略 match.severity。大小写不敏感比较由策略引擎负责。
    pub fn severity_name(&self) -> Option<&str> {
        match self {
            Event::Block { severity, .. } => severity.as_deref(),
            _ => None,
        }
    }

    /// 事件来源插件名,用于联动策略 match.plugin。
    pub fn source_plugin(&self) -> Option<&str> {
        match self {
            Event::Ban { plugin, .. } => Some(plugin),
            Event::HoneypotHit { .. } => Some("honeypot"),
            Event::Block { .. } => Some("http-guard"),
            _ => None,
        }
    }

    /// 事件类型名(ban / block / ...),用于 match.event。
    pub fn kind_name(&self) -> &'static str {
        match self {
            Event::Ban { .. } => "ban",
            Event::HoneypotHit { .. } => "honeypot_hit",
            Event::Block { .. } => "block",
            Event::ConfigChanged { .. } => "config_changed",
            Event::ConfigInvalid { .. } => "config_invalid",
            Event::ConfigRolledBack { .. } => "config_rolled_back",
            Event::AuthTempBan { .. } => "auth_temp_ban",
            Event::PluginEvent { .. } => "plugin_event",
            Event::UpgradeStatus { .. } => "upgrade_status",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let bytes = encode(&frame);
        let back = decode(&bytes).expect("decode");
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            serde_json::to_string(&back).unwrap(),
            "frame mismatch"
        );
    }

    #[test]
    fn frames_roundtrip() {
        roundtrip(Frame::Hello {
            node_id: "web-01".into(),
            version: "0.1.0".into(),
            config_hash: "abc".into(),
        });
        roundtrip(Frame::Ping);
        roundtrip(Frame::Pong);
        roundtrip(Frame::ApiRequest {
            id: 7,
            method: "PUT".into(),
            path: "/v0/management/forwards/f1".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"listen":"0.0.0.0:13306"}"#.to_vec(),
        });
        roundtrip(Frame::ApiResponse {
            id: 7,
            status: 200,
            headers: vec![("x-rooster-overwrote".into(), "deadbeef".into())],
            body: br#"{"hash":"x"}"#.to_vec(),
        });
        roundtrip(Frame::Event {
            first_seq: 12,
            batch: vec![Event::Ban {
                ip: "203.0.113.9".into(),
                reason: "ssh bruteforce".into(),
                plugin: "ssh-guard".into(),
                scope: "local".into(),
                ttl_secs: 3600,
                country: Some("中国".into()),
            }],
        });
        roundtrip(Frame::EventAck { acked_through: 12 });
        roundtrip(Frame::GlobalBan {
            ip: "198.51.100.7".into(),
            ttl_secs: 86400,
            reason: "ssh-bruteforce".into(),
            source_node: "web-01".into(),
        });
        roundtrip(Frame::GlobalUnban { ip: "198.51.100.7".into() });
        roundtrip(Frame::GlobalBanSync {
            bans: vec![GlobalBanInfo {
                ip: "198.51.100.7".into(),
                ttl_secs: 60,
                reason: "waf-critical".into(),
                source_node: "web-02".into(),
            }],
        });
        roundtrip(Frame::ApplyTemplate { id: 3, yaml: "plugins:\n".into() });
        roundtrip(Frame::TemplateResult {
            id: 3,
            ok: true,
            error: None,
            confirm_token: Some("tok".into()),
        });
        roundtrip(Frame::RenewCert { csr_pem: "-----BEGIN".into() });
        roundtrip(Frame::Renewed { cert_pem: "-----BEGIN".into() });
        roundtrip(Frame::Upgrade {
            version: "0.2.0".into(),
            url: "https://hub/dl".into(),
            signature: "sig".into(),
            public_key: Some("ed25519:abc".into()),
        });
        roundtrip(Frame::Error { message: "bad token".into() });
    }

    #[test]
    fn block_event_carries_severity_and_tolerates_legacy_frames() {
        // 严重级别必须原样往返:联动策略的 match.severity 依赖它。
        roundtrip(Frame::Event {
            first_seq: 1,
            batch: vec![Event::Block {
                ip: "203.0.113.9".into(),
                rule_id: "942100".into(),
                site: "www".into(),
                severity: Some("CRITICAL".into()),
                path: Some("/login".into()),
                hits: vec![942100, 942130],
                score: Some(10),
                country: None,
            }],
        });
        // 老 Agent 发的无 severity/path/hits/score 帧仍要能解码。
        let legacy = r#"{"type":"event","first_seq":1,"batch":[{"kind":"block","ip":"203.0.113.9","rule_id":"942100","site":"www"}]}"#;
        let back: Frame = serde_json::from_str(legacy).expect("legacy block decodes");
        match back {
            Frame::Event { batch, .. } => match &batch[0] {
                Event::Block { severity, path, hits, score, country, .. } => {
                    assert!(severity.is_none());
                    assert!(path.is_none());
                    assert!(hits.is_empty());
                    assert!(score.is_none());
                    assert!(country.is_none(), "老帧缺 country 必须容错为 None");
                }
                other => panic!("wrong event: {other:?}"),
            },
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn decode_garbage_fails() {
        assert!(decode(b"\x93not-a-frame").is_err());
    }

    #[test]
    fn event_accessors() {
        let e = Event::Ban {
            ip: "1.2.3.4".into(),
            reason: "r".into(),
            plugin: "ssh-guard".into(),
            scope: "local".into(),
            ttl_secs: 1,
            country: None,
        };
        assert_eq!(e.subject_ip(), Some("1.2.3.4"));
        assert_eq!(e.source_plugin(), Some("ssh-guard"));
        assert_eq!(e.kind_name(), "ban");
        let hit = Event::HoneypotHit {
            ip: "203.0.113.8".into(),
            port: 2222,
            protocol: "tcp".into(),
            country: None,
        };
        assert_eq!(hit.subject_ip(), Some("203.0.113.8"));
        assert_eq!(hit.source_plugin(), Some("honeypot"));
        assert_eq!(hit.kind_name(), "honeypot_hit");
        assert!(Event::ConfigChanged { hash: String::new() }.subject_ip().is_none());
    }
}
