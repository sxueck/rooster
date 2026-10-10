//! Hub 的 redb 存储:节点、注册 token、吊销、全局封禁、
//! 模板、下发记录、面板会话、审计、WASM 插件、联动策略、下载密钥。
//!
//! 约定:所有表 value 为 JSON 字符串(策略对象见各结构定义),key 除
//! audit(seq u64)外均为字符串。锁粒度为单表事务,redb 自身 MVCC。

use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::PolicyConfig;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// -----------

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct NodeRecord {
    pub id: String,
    pub labels: std::collections::BTreeMap<String, String>,
    pub version: String,
    pub config_hash: String,
    pub last_seen: u64,
    pub revoked: bool,
    /// 客户端证书 SHA-256 指纹(十六进制),连接认证用。
    pub cert_fp: String,
    /// 离线期间的待下发模板。
    pub pending_template: Option<String>,
    /// 离线期间待下发的升级包(入库 key,如 `0.2.0-x86_64`)。
    pub pending_upgrade: Option<String>,
}

impl NodeRecord {
    pub fn new(id: &str, cert_fp: String) -> Self {
        Self {
            id: id.to_string(),
            labels: Default::default(),
            version: String::new(),
            config_hash: String::new(),
            last_seen: now_secs(),
            revoked: false,
            cert_fp,
            pending_template: None,
            pending_upgrade: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TokenRecord {
    pub expires_at: u64,
    pub used: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GlobalBanRecord {
    pub ip: String,
    pub reason: String,
    pub source_node: String,
    pub created: u64,
    pub ttl_secs: u64,
}

impl GlobalBanRecord {
    pub fn expires_at(&self) -> u64 {
        self.created + self.ttl_secs
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TemplateRecord {
    pub name: String,
    /// 标签选择器,如 {"env":"prod","role":"web"};空 = 全部节点。
    pub selector: std::collections::BTreeMap<String, String>,
    pub yaml: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RolloutNodeResult {
    /// 存量 redb 记录以 kebab-case 键(`node-id`)持久化;alias 只影响读取。
    #[serde(alias = "node-id")]
    pub node_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 过程详情(升级进度:下载百分比 / 阶段说明)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RolloutRecord {
    pub kind: String,
    pub template_id: Option<String>,
    pub version: Option<String>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub status: String,
    pub results: Vec<RolloutNodeResult>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditEntry {
    pub ts: u64,
    /// 操作者:"panel" / "policy:<id>" / "system"。
    pub operator: String,
    pub node: Option<String>,
    pub method: String,
    pub path: String,
    /// 请求体摘要(sha256 前 16 hex)。
    pub body_digest: String,
    pub status: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WasmPluginRecord {
    pub size: u64,
    pub uploaded_at: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UpgradeRecord {
    pub size: u64,
    pub uploaded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeBanHistoryRecord {
    pub node_id: String,
    pub ip: String,
    pub reason: String,
    pub plugin: String,
    pub scope: String,
    pub started_at: Option<u64>,
    pub expires_at: u64,
    // None preserves the snapshot without claiming the remote DELETE succeeded.
    pub removed_at: Option<u64>,
    pub removed_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeHoneypotHitRecord {
    pub node_id: String,
    pub ts: u64,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

// -----------

const NODES: TableDefinition<&str, String> = TableDefinition::new("nodes");
const TOKENS: TableDefinition<&str, String> = TableDefinition::new("tokens");
const REVOKED: TableDefinition<&str, ()> = TableDefinition::new("revoked_certs");
const GLOBAL_BANS: TableDefinition<&str, String> = TableDefinition::new("global_bans");
const NODE_BAN_HISTORY: TableDefinition<&str, String> = TableDefinition::new("node_ban_history");
const NODE_HONEYPOT_HITS: TableDefinition<&str, String> = TableDefinition::new("node_honeypot_hits");
const TEMPLATES: TableDefinition<&str, String> = TableDefinition::new("templates");
const ROLLOUTS: TableDefinition<&str, String> = TableDefinition::new("rollouts");
const SESSIONS: TableDefinition<&str, u64> = TableDefinition::new("sessions");
const AUDIT: TableDefinition<u64, String> = TableDefinition::new("audit");
const WASM_META: TableDefinition<&str, String> = TableDefinition::new("wasm_meta");
const WASM_BLOB: TableDefinition<&str, Vec<u8>> = TableDefinition::new("wasm_blob");
const UPGRADES: TableDefinition<&str, String> = TableDefinition::new("upgrades");
const UPGRADE_BLOB: TableDefinition<&str, Vec<u8>> = TableDefinition::new("upgrade_blob");
const UPGRADE_SIG: TableDefinition<&str, String> = TableDefinition::new("upgrade_sig");
const POLICIES: TableDefinition<&str, String> = TableDefinition::new("policies");
const SECRETS: TableDefinition<&str, String> = TableDefinition::new("secrets");

/// 打开(或创建)Hub 数据库,并确保全部表存在。
pub fn open(path: &Path) -> Result<Database, String> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let db = Database::create(path).map_err(json_err)?;
    let tables = db.begin_write().map_err(json_err)?;
    let _ = tables.open_table(NODES).map_err(json_err)?;
    let _ = tables.open_table(TOKENS).map_err(json_err)?;
    let _ = tables.open_table(REVOKED).map_err(json_err)?;
    let _ = tables.open_table(GLOBAL_BANS).map_err(json_err)?;
    let _ = tables.open_table(NODE_BAN_HISTORY).map_err(json_err)?;
    let _ = tables.open_table(NODE_HONEYPOT_HITS).map_err(json_err)?;
    let _ = tables.open_table(TEMPLATES).map_err(json_err)?;
    let _ = tables.open_table(ROLLOUTS).map_err(json_err)?;
    let _ = tables.open_table(SESSIONS).map_err(json_err)?;
    let _ = tables.open_table(AUDIT).map_err(json_err)?;
    let _ = tables.open_table(WASM_META).map_err(json_err)?;
    let _ = tables.open_table(WASM_BLOB).map_err(json_err)?;
    let _ = tables.open_table(UPGRADES).map_err(json_err)?;
    let _ = tables.open_table(UPGRADE_BLOB).map_err(json_err)?;
    let _ = tables.open_table(UPGRADE_SIG).map_err(json_err)?;
    let _ = tables.open_table(POLICIES).map_err(json_err)?;
    let _ = tables.open_table(SECRETS).map_err(json_err)?;
    tables.commit().map_err(json_err)?;
    Ok(db)
}

    /// Hub 全部存储访问的入口(内部 Arc<Database>,句柄可克隆共享)。
/// `retention` 控制审计日志的惰性保留期清理。
#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
    retention: Option<Duration>,
}

fn json_err(e: impl std::fmt::Display) -> String {
    format!("store json: {e}")
}

impl Store {
    pub fn new(db: Database) -> Self {
        Self { db: Arc::new(db), retention: None }
    }

    pub fn with_retention(db: Database, retention: Duration) -> Self {
        Self { db: Arc::new(db), retention: Some(retention) }
    }

    // -- 节点 ----------------------------------------------------------

    pub fn upsert_node(&self, rec: &NodeRecord) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(NODES).map_err(json_err)?;
            t.insert(rec.id.as_str(), serde_json::to_string(rec).unwrap())
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn get_node(&self, id: &str) -> Result<Option<NodeRecord>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(NODES).map_err(json_err)?;
        match t.get(id).map_err(json_err)? {
            Some(v) => serde_json::from_str(&v.value()).map_err(json_err).map(Some),
            None => Ok(None),
        }
    }

    pub fn list_nodes(&self) -> Result<Vec<NodeRecord>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(NODES).map_err(json_err)?;
        let mut out: Vec<NodeRecord> = Vec::new();
        for v in t.iter().map_err(json_err)? {
            let (_, v) = v.map_err(json_err)?;
            out.push(serde_json::from_str(&v.value()).map_err(json_err)?);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn delete_node(&self, id: &str) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(NODES).map_err(json_err)?;
            t.remove(id).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    /// 标签选择器匹配:selector 为空或全部键值命中即选中。
    pub fn select_nodes(
        &self,
        selector: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<NodeRecord>, String> {
        Ok(self
            .list_nodes()?
            .into_iter()
            .filter(|n| !n.revoked && selector.iter().all(|(k, v)| n.labels.get(k) == Some(v)))
            .collect())
    }

    // -- 注册 token(一次性,15 分钟) -----------------------------------

    pub fn insert_token(&self, token: &str, ttl: Duration) -> Result<(), String> {
        let rec = TokenRecord {
            expires_at: now_secs() + ttl.as_secs(),
            used: false,
        };
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(TOKENS).map_err(json_err)?;
            t.insert(token, serde_json::to_string(&rec).unwrap())
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    /// 消费一次性 token:有效(未用、未过期)则标记已用并返回 true。
    pub fn consume_token(&self, token: &str) -> Result<bool, String> {
        let w = self.db.begin_write().map_err(json_err)?;
        let ok = {
            let mut t = w.open_table(TOKENS).map_err(json_err)?;
            let cur = t.get(token).map_err(json_err)?.map(|v| v.value().to_string());
            match cur {
                Some(s) => {
                    let rec: TokenRecord = serde_json::from_str(&s).map_err(json_err)?;
                    if rec.used || rec.expires_at <= now_secs() {
                        false
                    } else {
                        let rec = TokenRecord { used: true, ..rec };
                        t.insert(token, serde_json::to_string(&rec).unwrap())
                            .map_err(json_err)?;
                        true
                    }
                }
                None => false,
            }
        };
        w.commit().map_err(json_err)?;
        Ok(ok)
    }

    // -- 证书吊销 ----------------------------------------------

    pub fn revoke_cert(&self, fp: &str) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(REVOKED).map_err(json_err)?;
            t.insert(fp, ()).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn is_revoked(&self, fp: &str) -> Result<bool, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(REVOKED).map_err(json_err)?;
        Ok(t.get(fp).map_err(json_err)?.is_some())
    }

    // -- 全局封禁(FR-B) -------------------------------------------------

    pub fn put_global_ban(&self, rec: &GlobalBanRecord) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(GLOBAL_BANS).map_err(json_err)?;
            t.insert(rec.ip.as_str(), serde_json::to_string(rec).unwrap())
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn remove_global_ban(&self, ip: &str) -> Result<bool, String> {
        let w = self.db.begin_write().map_err(json_err)?;
        let removed = {
            let mut t = w.open_table(GLOBAL_BANS).map_err(json_err)?;
            let removed = t.remove(ip).map_err(json_err)?.is_some();
            removed
        };
        w.commit().map_err(json_err)?;
        Ok(removed)
    }

    pub fn list_global_bans(&self) -> Result<Vec<GlobalBanRecord>, String> {
        let now = now_secs();
        let r = self.db.begin_read().map_err(json_err)?;
        let mut out = Vec::new();
        let mut expired = Vec::new();
        {
            let t = r.open_table(GLOBAL_BANS).map_err(json_err)?;
            for v in t.iter().map_err(json_err)? {
                let (k, v) = v.map_err(json_err)?;
                let rec: GlobalBanRecord =
                    serde_json::from_str(&v.value()).map_err(json_err)?;
                // 惰性清理已过期条目(内核侧各节点自行到期,无需广播)。
                if rec.expires_at() > now {
                    out.push(rec);
                } else {
                    expired.push(k.value().to_string());
                }
            }
        }
        if !expired.is_empty() {
            let w = self.db.begin_write().map_err(json_err)?;
            {
                let mut t = w.open_table(GLOBAL_BANS).map_err(json_err)?;
                for ip in expired {
                    let _ = t.remove(ip.as_str());
                }
            }
            w.commit().map_err(json_err)?;
        }
        out.sort_by(|a, b| a.ip.cmp(&b.ip));
        Ok(out)
    }

    pub fn archive_node_ban(&self, rec: &NodeBanHistoryRecord) -> Result<String, String> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let key = format!("{}:{}:{unique}", rec.node_id, rec.ip);
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(NODE_BAN_HISTORY).map_err(json_err)?;
            t.insert(key.as_str(), serde_json::to_string(rec).map_err(json_err)?)
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)?;
        Ok(key)
    }

    pub fn confirm_node_unban(&self, key: &str, removed_at: u64) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(NODE_BAN_HISTORY).map_err(json_err)?;
            let mut rec: NodeBanHistoryRecord = {
                let row = t.get(key).map_err(json_err)?.ok_or("unban snapshot missing")?;
                serde_json::from_str(&row.value()).map_err(json_err)?
            };
            rec.removed_at = Some(removed_at);
            t.insert(key, serde_json::to_string(&rec).map_err(json_err)?).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn list_node_ban_history(&self, node_id: &str, limit: usize) -> Result<Vec<NodeBanHistoryRecord>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(NODE_BAN_HISTORY).map_err(json_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(json_err)? {
            let (_, value) = row.map_err(json_err)?;
            let rec: NodeBanHistoryRecord = serde_json::from_str(&value.value()).map_err(json_err)?;
            if rec.node_id == node_id {
                out.push(rec);
            }
        }
        out.sort_by_key(|rec| std::cmp::Reverse(rec.removed_at.unwrap_or(u64::MAX)));
        out.truncate(limit);
        Ok(out)
    }

    pub fn archive_honeypot_hit(&self, rec: &NodeHoneypotHitRecord) -> Result<(), String> {
        let key = format!("{}:{}:{}:{}", rec.node_id, rec.ts, rec.ip, rec.port);
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(NODE_HONEYPOT_HITS).map_err(json_err)?;
            t.insert(key.as_str(), serde_json::to_string(rec).map_err(json_err)?)
                .map_err(json_err)?;
            let mut rows = Vec::new();
            for row in t.iter().map_err(json_err)? {
                let (k, value) = row.map_err(json_err)?;
                let hit: NodeHoneypotHitRecord = serde_json::from_str(&value.value()).map_err(json_err)?;
                if hit.node_id == rec.node_id {
                    rows.push((k.value().to_string(), hit.ts));
                }
            }
            rows.sort_by_key(|(_, ts)| *ts);
            let excess = rows.len().saturating_sub(1000);
            for (key, _) in rows.into_iter().take(excess) {
                let _ = t.remove(key.as_str());
            }
        }
        w.commit().map_err(json_err)
    }

    pub fn list_node_honeypot_hits(&self, node_id: &str, limit: usize) -> Result<Vec<NodeHoneypotHitRecord>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(NODE_HONEYPOT_HITS).map_err(json_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(json_err)? {
            let (_, value) = row.map_err(json_err)?;
            let rec: NodeHoneypotHitRecord = serde_json::from_str(&value.value()).map_err(json_err)?;
            if rec.node_id == node_id {
                out.push(rec);
            }
        }
        out.sort_by(|a, b| b.ts.cmp(&a.ts));
        out.truncate(limit);
        Ok(out)
    }

    // -- 模板 -----------------------------------------------------

    pub fn put_template(&self, id: &str, rec: &TemplateRecord) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(TEMPLATES).map_err(json_err)?;
            t.insert(id, serde_json::to_string(rec).unwrap())
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn get_template(&self, id: &str) -> Result<Option<TemplateRecord>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(TEMPLATES).map_err(json_err)?;
        match t.get(id).map_err(json_err)? {
            Some(v) => serde_json::from_str(&v.value()).map_err(json_err).map(Some),
            None => Ok(None),
        }
    }

    pub fn delete_template(&self, id: &str) -> Result<bool, String> {
        let w = self.db.begin_write().map_err(json_err)?;
        let removed = {
            let mut t = w.open_table(TEMPLATES).map_err(json_err)?;
            let removed = t.remove(id).map_err(json_err)?.is_some();
            removed
        };
        w.commit().map_err(json_err)?;
        Ok(removed)
    }

    pub fn list_templates(&self) -> Result<Vec<(String, TemplateRecord)>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(TEMPLATES).map_err(json_err)?;
        let mut out = Vec::new();
        for v in t.iter().map_err(json_err)? {
            let (k, v) = v.map_err(json_err)?;
            out.push((
                k.value().to_string(),
                serde_json::from_str(&v.value()).map_err(json_err)?,
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    // -- 下发记录 -----------------------------------------

    pub fn put_rollout(&self, id: &str, rec: &RolloutRecord) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(ROLLOUTS).map_err(json_err)?;
            t.insert(id, serde_json::to_string(rec).unwrap())
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn get_rollout(&self, id: &str) -> Result<Option<RolloutRecord>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(ROLLOUTS).map_err(json_err)?;
        match t.get(id).map_err(json_err)? {
            Some(v) => serde_json::from_str(&v.value()).map_err(json_err).map(Some),
            None => Ok(None),
        }
    }

    pub fn list_rollouts(&self, limit: usize) -> Result<Vec<(String, RolloutRecord)>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(ROLLOUTS).map_err(json_err)?;
        let mut out: Vec<(String, RolloutRecord)> = Vec::new();
        // 先取全量再排序截断:redb key 顺序与时间无关,先 take(limit) 会把
        // 最新记录永远挡在门外。同 started_at 以 key 倒序保证确定性。
        for v in t.iter().map_err(json_err)? {
            let (k, v) = v.map_err(json_err)?;
            out.push((
                k.value().to_string(),
                serde_json::from_str(&v.value()).map_err(json_err)?,
            ));
        }
        out.sort_by(|a, b| b.1.started_at.cmp(&a.1.started_at).then(b.0.cmp(&a.0)));
        out.truncate(limit);
        Ok(out)
    }

    // -- 面板会话 ---------------------------------------------------

    pub fn insert_session(&self, token: &str, expires_at: u64) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(SESSIONS).map_err(json_err)?;
            t.insert(token, expires_at).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    /// 会话的绝对过期时间戳(只读);无此会话返回 None。cookie 会话的
    /// 「还剩多久」与面板开机探测都走这一个读路径。
    pub fn session_expiry(&self, token: &str) -> Result<Option<u64>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(SESSIONS).map_err(json_err)?;
        Ok(t.get(token).map_err(json_err)?.map(|v| v.value()))
    }

    /// 校验会话(只读)。过期清理由 Hub 的周期任务 `cleanup_sessions` 负责:
    /// 若在这里顺带清理,任何带无效 Bearer 的未认证请求都会换回一次写事务。
    pub fn validate_session(&self, token: &str) -> Result<bool, String> {
        let now = now_secs();
        Ok(matches!(self.session_expiry(token)?, Some(exp) if exp > now))
    }

    /// 删除全部过期会话。
    pub fn cleanup_sessions(&self) -> Result<usize, String> {
        let now = now_secs();
        let w = self.db.begin_write().map_err(json_err)?;
        let removed = {
            let mut t = w.open_table(SESSIONS).map_err(json_err)?;
            let stale: Vec<_> = t
                .iter()
                .map_err(json_err)?
                .filter_map(|r| r.ok())
                .filter(|(_, v)| v.value() <= now)
                .map(|(k, _)| k.value().to_string())
                .collect();
            let n = stale.len();
            for k in stale {
                let _ = t.remove(k.as_str());
            }
            n
        };
        w.commit().map_err(json_err)?;
        Ok(removed)
    }

    pub fn delete_session(&self, token: &str) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(SESSIONS).map_err(json_err)?;
            let _ = t.remove(token);
        }
        w.commit().map_err(json_err)
    }

    // -- 审计 -------------------------------------------------------

    pub fn append_audit(&self, entry: &AuditEntry) -> Result<(), String> {
        let w = self.db.begin_write().map_err(json_err)?;
        let next = {
            let t = w.open_table(AUDIT).map_err(json_err)?;
            t.iter().map_err(json_err)?.next_back().and_then(|r| r.ok()).map(|(k, _)| k.value() + 1).unwrap_or(0)
        };
        {
            let mut t = w.open_table(AUDIT).map_err(json_err)?;
            t.insert(next, serde_json::to_string(entry).unwrap())
                .map_err(json_err)?;
        }
        w.commit().map_err(json_err)?;
        // 惰性保留期清理(audit-retention):每 100 条触发一次。
        if self.retention.is_some() && next % 100 == 0 {
            let cutoff = now_secs() - self.retention.unwrap_or_default().as_secs();
            let w = self.db.begin_write().map_err(json_err)?;
            {
                let mut t = w.open_table(AUDIT).map_err(json_err)?;
                let stale: Vec<_> = t
                    .range(..next)
                    .map_err(json_err)?
                    .filter_map(|r| r.ok())
                    .take_while(|(_, v)| {
                        serde_json::from_str::<AuditEntry>(&v.value())
                            .map(|e| e.ts < cutoff)
                            .unwrap_or(true)
                    })
                    .map(|(k, _)| k.value())
                    .collect();
                for k in stale {
                    let _ = t.remove(k);
                }
            }
            w.commit().map_err(json_err)?;
        }
        Ok(())
    }

    pub fn list_audit(&self, limit: usize) -> Result<Vec<AuditEntry>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(AUDIT).map_err(json_err)?;
        let mut out = Vec::new();
        for v in t.range(..std::u64::MAX).map_err(json_err)?.rev().take(limit) {
            let (_, v) = v.map_err(json_err)?;
            out.push(serde_json::from_str(&v.value()).map_err(json_err)?);
        }
        Ok(out)
    }

    // -- WASM 插件仓库 --------------------------------------------------

    pub fn put_wasm(&self, name: &str, content: Vec<u8>) -> Result<(), String> {
        let meta = WasmPluginRecord {
            size: content.len() as u64,
            uploaded_at: now_secs(),
        };
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(WASM_META).map_err(json_err)?;
            t.insert(name, serde_json::to_string(&meta).unwrap())
                .map_err(json_err)?;
            let mut t = w.open_table(WASM_BLOB).map_err(json_err)?;
            t.insert(name, content).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn get_wasm(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(WASM_BLOB).map_err(json_err)?;
        match t.get(name).map_err(json_err)? {
            Some(v) => Ok(Some(v.value().to_vec())),
            None => Ok(None),
        }
    }

    pub fn delete_wasm(&self, name: &str) -> Result<bool, String> {
        let w = self.db.begin_write().map_err(json_err)?;
        let removed = {
            let mut t = w.open_table(WASM_BLOB).map_err(json_err)?;
            let removed = t.remove(name).map_err(json_err)?.is_some();
            removed
        };
        {
            let mut t = w.open_table(WASM_META).map_err(json_err)?;
            let _ = t.remove(name);
        }
        w.commit().map_err(json_err)?;
        Ok(removed)
    }

    pub fn list_wasm(&self) -> Result<Vec<(String, WasmPluginRecord)>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(WASM_META).map_err(json_err)?;
        let mut out: Vec<(String, WasmPluginRecord)> = Vec::new();
        for v in t.iter().map_err(json_err)? {
            let (k, v) = v.map_err(json_err)?;
            out.push((
                k.value().to_string(),
                serde_json::from_str(&v.value()).map_err(json_err)?,
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    // -- 升级包 -------------------------------------------------------

    pub fn put_upgrade(&self, version: &str, content: Vec<u8>, sig: &str) -> Result<(), String> {
        let meta = UpgradeRecord {
            size: content.len() as u64,
            uploaded_at: now_secs(),
        };
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(UPGRADES).map_err(json_err)?;
            t.insert(version, serde_json::to_string(&meta).unwrap())
                .map_err(json_err)?;
            let mut t = w.open_table(UPGRADE_BLOB).map_err(json_err)?;
            t.insert(version, content).map_err(json_err)?;
            let mut t = w.open_table(UPGRADE_SIG).map_err(json_err)?;
            t.insert(version, sig.to_string()).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn get_upgrade(&self, version: &str) -> Result<Option<Vec<u8>>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(UPGRADE_BLOB).map_err(json_err)?;
        Ok(t.get(version).map_err(json_err)?.map(|v| v.value().to_vec()))
    }

    pub fn get_upgrade_sig(&self, version: &str) -> Result<Option<String>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(UPGRADE_SIG).map_err(json_err)?;
        Ok(t.get(version).map_err(json_err)?.map(|v| v.value()))
    }

    pub fn list_upgrades(&self) -> Result<Vec<(String, UpgradeRecord)>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(UPGRADES).map_err(json_err)?;
        let mut out: Vec<(String, UpgradeRecord)> = Vec::new();
        for v in t.iter().map_err(json_err)? {
            let (k, v) = v.map_err(json_err)?;
            out.push((
                k.value().to_string(),
                serde_json::from_str(&v.value()).map_err(json_err)?,
            ));
        }
        out.sort_by(|a, b| b.1.uploaded_at.cmp(&a.1.uploaded_at));
        Ok(out)
    }

    // -- 联动策略(redb 为运行时真相源) -------------------------------

    pub fn put_policies(&self, policies: &[PolicyConfig]) -> Result<(), String> {
        let json = serde_json::to_string(policies).unwrap();
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(POLICIES).map_err(json_err)?;
            t.insert("policies", json).map_err(json_err)?;
        }
        w.commit().map_err(json_err)
    }

    pub fn get_policies(&self) -> Result<Option<Vec<PolicyConfig>>, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(POLICIES).map_err(json_err)?;
        match t.get("policies").map_err(json_err)? {
            Some(v) => serde_json::from_str(&v.value()).map_err(json_err).map(Some),
            None => Ok(None),
        }
    }

    // -- 下载地址签名密钥(升级包/WASM 下载 URL) ----------------------------

    pub fn download_secret(&self) -> Result<String, String> {
        let r = self.db.begin_read().map_err(json_err)?;
        let t = r.open_table(SECRETS).map_err(json_err)?;
        if let Some(v) = t.get("download").map_err(json_err)? {
            return Ok(v.value());
        }
        drop(r);
        let secret = {
            let bytes = rand::random::<[u8; 32]>();
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let w = self.db.begin_write().map_err(json_err)?;
        {
            let mut t = w.open_table(SECRETS).map_err(json_err)?;
            t.insert("download", secret.clone()).map_err(json_err)?;
        }
        w.commit().map_err(json_err)?;
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> Store {
        let dir = std::env::temp_dir().join(format!("rooster-hub-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("store-{}.redb", rand::random::<u64>()));
        Store::new(open(&path).unwrap())
    }

    #[test]
    fn token_is_single_use_and_expires() {
        let s = tmp_store();
        s.insert_token("t0", Duration::from_secs(60)).unwrap();
        assert!(s.consume_token("t0").unwrap());
        assert!(!s.consume_token("t0").unwrap(), "token must be one-shot");
        assert!(!s.consume_token("unknown").unwrap());
    }

    #[test]
    fn node_selector_matches_labels() {
        let s = tmp_store();
        let mut n = NodeRecord::new("a", "fp".into());
        n.labels.insert("env".to_string(), "prod".into());
        s.upsert_node(&n).unwrap();
        let mut sel = std::collections::BTreeMap::new();
        sel.insert("env".to_string(), "prod".to_string());
        assert_eq!(s.select_nodes(&sel).unwrap().len(), 1);
        sel.insert("role".to_string(), "web".to_string());
        assert_eq!(s.select_nodes(&sel).unwrap().len(), 0);
    }

    #[test]
    fn global_bans_expire_lazily() {
        let s = tmp_store();
        s.put_global_ban(&GlobalBanRecord {
            ip: "1.2.3.4".into(),
            reason: "r".into(),
            source_node: "a".into(),
            created: now_secs() - 10,
            ttl_secs: 5,
        })
        .unwrap();
        assert!(s.list_global_bans().unwrap().is_empty());
    }

    #[test]
    fn node_ban_history_is_persisted_and_scoped() {
        let s = tmp_store();
        let rec = NodeBanHistoryRecord {
            node_id: "node-a".into(),
            ip: "203.0.113.7".into(),
            reason: "honeypot".into(),
            plugin: "honeypot".into(),
            scope: "local".into(),
            started_at: Some(10),
            expires_at: 70,
            removed_at: Some(20),
            removed_by: "panel".into(),
        };
        s.archive_node_ban(&rec).unwrap();
        assert_eq!(s.list_node_ban_history("node-a", 10).unwrap(), vec![rec]);
        assert!(s.list_node_ban_history("node-b", 10).unwrap().is_empty());
    }

    #[test]
    fn honeypot_hits_are_persisted_and_scoped() {
        let s = tmp_store();
        let hit = NodeHoneypotHitRecord {
            node_id: "node-a".into(),
            ts: 30,
            ip: "203.0.113.8".into(),
            port: 2222,
            protocol: "tcp".into(),
        };
        s.archive_honeypot_hit(&hit).unwrap();
        assert_eq!(s.list_node_honeypot_hits("node-a", 10).unwrap(), vec![hit]);
        assert!(s.list_node_honeypot_hits("node-b", 10).unwrap().is_empty());
    }

    #[test]
    fn sessions_validate_and_expire() {
        let s = tmp_store();
        let exp = now_secs() + 60;
        s.insert_session("tok", exp).unwrap();
        assert!(s.validate_session("tok").unwrap());
        assert_eq!(s.session_expiry("tok").unwrap(), Some(exp));
        assert_eq!(s.session_expiry("nope").unwrap(), None);
        s.insert_session("old", now_secs() - 1).unwrap();
        assert!(!s.validate_session("old").unwrap());
        s.delete_session("tok").unwrap();
        assert!(!s.validate_session("tok").unwrap());
    }

    #[test]
    fn policies_roundtrip() {
        let s = tmp_store();
        assert!(s.get_policies().unwrap().is_none());
        let p = vec![PolicyConfig {
            id: "x".into(),
            r#match: crate::config::PolicyMatch {
                plugin: "ssh-guard".into(),
                event: "ban".into(),
                severity: None,
            },
            min_nodes: Some(2),
            threshold: None,
            window: None,
            ttl: Duration::from_secs(60),
        }];
        s.put_policies(&p).unwrap();
        let back = s.get_policies().unwrap().unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].min_nodes, Some(2));
    }

    #[test]
    fn audit_append_and_list_recent_first() {
        let s = tmp_store();
        for i in 0..5 {
            s.append_audit(&AuditEntry {
                ts: 1000 + i,
                operator: "panel".into(),
                node: Some("n".into()),
                method: "PUT".into(),
                path: "/v0/x".into(),
                body_digest: "d".into(),
                status: 200,
            })
            .unwrap();
        }
        let entries = s.list_audit(3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].ts, 1004);
    }

    #[test]
    fn wasm_and_upgrade_blobs_roundtrip() {
        let s = tmp_store();
        s.put_wasm("p.wasm", vec![1, 2, 3]).unwrap();
        assert_eq!(s.get_wasm("p.wasm").unwrap(), Some(vec![1, 2, 3]));
        assert!(s.delete_wasm("p.wasm").unwrap());
        s.put_upgrade("0.2.0", vec![9, 9], "sig").unwrap();
        assert_eq!(s.get_upgrade("0.2.0").unwrap(), Some(vec![9, 9]));
        assert_eq!(s.get_upgrade_sig("0.2.0").unwrap().as_deref(), Some("sig"));
    }

    fn rollout(started_at: u64) -> RolloutRecord {
        RolloutRecord {
            kind: "template".into(),
            template_id: None,
            version: None,
            started_at,
            finished_at: None,
            status: "running".into(),
            results: vec![],
        }
    }

    /// 存量 redb 记录里的行是 kebab-case 键(`node-id`),改 snake_case 后必须仍可读。
    #[test]
    fn rollout_row_reads_legacy_kebab_case_records() {
        let row: RolloutNodeResult =
            serde_json::from_str(r#"{"node-id":"web-1","status":"sent"}"#).unwrap();
        assert_eq!(row.node_id, "web-1");
        assert_eq!(serde_json::to_string(&row).unwrap(), r#"{"node_id":"web-1","status":"sent"}"#);
    }

    /// 面板的下发列表必须给“最新的 limit 条”:旧实现先按 redb key 顺序
    /// take(limit) 再排序,第 limit+1 条之后的记录永远看不到。
    #[test]
    fn list_rollouts_returns_newest_limit() {
        let s = tmp_store();
        for i in 0..51u64 {
            s.put_rollout(&format!("run-{i:02}"), &rollout(1000 + i))
                .unwrap();
        }
        let out = s.list_rollouts(50).unwrap();
        assert_eq!(out.len(), 50);
        assert_eq!(out[0].0, "run-50", "newest rollout must come first");
        assert_eq!(out[0].1.started_at, 1050);
        assert!(!out.iter().any(|(k, _)| k == "run-00"), "oldest must be dropped, not newest");
    }

    #[test]
    fn list_rollouts_tie_breaks_by_key_desc() {
        let s = tmp_store();
        s.put_rollout("run-a", &rollout(42)).unwrap();
        s.put_rollout("run-b", &rollout(42)).unwrap();
        let out = s.list_rollouts(1).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "run-b", "same started_at must tie-break by key desc");
    }
}
