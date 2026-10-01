//! rooster hub:中控。
//!
//! 职责:节点注册与 PKI、mTLS WSS 长连接、管理 API 透传、审计、
//! 模板/全局封禁/升级下发、面板静态服务。所有状态存 redb,
//! 不依赖外部中间件。

pub mod api;
pub mod config;
pub mod diff;
pub mod http;
pub mod install;
pub mod pki;
pub mod policy;
pub mod registry;
pub mod rollout;
pub mod store;
pub mod ws;

use crate::config::HubConfig;
use policy::PolicyEngine;
use registry::Registry;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use rooster_proto::Event;

/// 面板事件环形缓冲上限(Hub 不持久化全量事件。
const RECENT_EVENTS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct RecentEvent {
    pub node_id: String,
    pub ts: u64,
    pub event: Event,
}

pub struct HubState {
    pub cfg: HubConfig,
    pub store: store::Store,
    pub pki: pki::HubPki,
    pub registry: Registry,
    pub policy: Mutex<PolicyEngine>,
    /// 登录暴力破解防护(配套)。
    pub login_gate: api::LoginGate,
    /// 面板实时事件广播。
    pub events_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// 近期事件环(总览聚合 /v0/overview 的数据源)。
    pub recent: Mutex<VecDeque<RecentEvent>>,
}

impl HubState {
    pub fn push_recent(&self, node_id: &str, ts: u64, event: Event) {
        {
            let mut q = self.recent.lock().unwrap();
            q.push_back(RecentEvent {
                node_id: node_id.to_string(),
                ts,
                event: event.clone(),
            });
            while q.len() > RECENT_EVENTS {
                q.pop_front();
            }
        }
        let msg = serde_json::json!({
            "node_id": node_id,
            "ts": ts,
            "event": event,
        });
        let _ = self.events_tx.send(msg);
    }

    pub fn audit(
        &self,
        operator: &str,
        node: Option<&str>,
        method: &str,
        path: &str,
        body: &[u8],
        status: u16,
    ) {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(body);
        let digest: String = h.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let entry = store::AuditEntry {
            ts: store::now_secs(),
            operator: operator.to_string(),
            node: node.map(str::to_string),
            method: method.to_string(),
            path: path.to_string(),
            body_digest: digest,
            status,
        };
        if let Err(e) = self.store.append_audit(&entry) {
            tracing::warn!("audit append failed: {e}");
        }
    }

    /// 当前生效的联动策略:redb 为真相源,未初始化时用 yaml 种子并导入。
    pub fn effective_policies(&self) -> Vec<config::PolicyConfig> {
        match self.store.get_policies() {
            Ok(Some(p)) => p,
            _ => {
                let seed = self.cfg.global_ban_policies.clone();
                let _ = self.store.put_policies(&seed);
                seed
            }
        }
    }

    /// 构造带过期时间的下载 URL(HMAC 签名,升级包/WASM 用)。
    pub fn signed_download_url(&self, path: &str, ttl_secs: u64) -> String {
        let secret = self.store.download_secret().unwrap_or_default();
        let exp = store::now_secs() + ttl_secs;
        let sig = hmac_sha256(secret.as_bytes(), format!("{path}:{exp}").as_bytes());
        format!("{path}?exp={exp}&sig={sig}")
    }

    /// 校验下载 URL 签名与有效期。
    pub fn verify_download_url(&self, path: &str, exp: u64, sig: &str) -> bool {
        if exp < store::now_secs() {
            return false;
        }
        let secret = match self.store.download_secret() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let expect = hmac_sha256(secret.as_bytes(), format!("{path}:{exp}").as_bytes());
        // 常数时间比较(长度不同直接失败,不泄露时序)。
        if expect.len() != sig.len() {
            return false;
        }
        expect.bytes().zip(sig.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

/// 轻量 HMAC-SHA256(仅用于下载 URL 签名;不引入 hmac crate)。
fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..d.len()].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    outer
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `rooster hub` 入口。
pub async fn run(config_path: &Path) -> Result<(), String> {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(r) => r,
        Err(_) => {
            std::fs::write(config_path, config::default_hub_config_template())
                .map_err(|e| format!("write initial config: {e}"))?;
            return Err(format!(
                "wrote initial config to {}; set secret-key, then start again",
                config_path.display()
            ));
        }
    };
    let mut cfg: HubConfig =
        serde_norway::from_str(&raw).map_err(|e| format!("parse {}: {e}", config_path.display()))?;
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("create data-dir: {e}"))?;

    // 要求 Hub↔Agent 强制 mTLS。明文模式下 Agent 拿不到客户端
    // 证书,ws.rs 的 authorize 只剩“节点已注册且未吊销”可验——知道 node_id
    // 即可冒充节点,因此明文只允许绑回环(本机反代终止 TLS 的应急用法);
    // 对外服务必须 tls.mode: static 配 cert/key。
    if cfg.tls_mode_str() == "none" && !cfg.listen.ip().is_loopback() {
        return Err(format!(
            "tls.mode: none will not bind a non-loopback address ({}); set tls.mode: static with cert/key, or bind listen to 127.0.0.1 behind a TLS terminator",
            cfg.listen
        ));
    }

    // 明文 secret-key 首启哈希回写(保留注释)。
    if let Some(sk) = cfg.secret_key.clone() {
        if !sk.is_empty() && !sk.starts_with("$2") {
            let hashed = bcrypt::hash(&sk, 12).map_err(|e| format!("bcrypt: {e}"))?;
            let patched = rooster_config::writer::replace_subtree(
                &raw,
                &[rooster_config::Seg::K("secret-key")],
                &serde_json::json!(hashed),
            )
            .map_err(|e| format!("patch secret-key: {e}"))?;
            std::fs::write(config_path, &patched).map_err(|e| format!("rewrite config: {e}"))?;
            cfg.secret_key = Some(hashed);
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let db = store::open(&cfg.data_dir.join("hub.redb")).map_err(|e| format!("open redb: {e}"))?;
    let store = store::Store::with_retention(db, cfg.audit_retention());
    let pki = pki::HubPki::ensure(&cfg.data_dir)?;
    let (events_tx, _) = tokio::sync::broadcast::channel(1024);

    let state = Arc::new(HubState {
        cfg,
        store,
        pki,
        registry: Registry::default(),
        policy: Mutex::new(PolicyEngine::new()),
        login_gate: api::LoginGate::default(),
        events_tx,
        recent: Mutex::new(VecDeque::new()),
    });

    // 首次联动策略导入(之后以面板/redb 为准)。
    let _ = state.effective_policies();

    // 过期会话由周期任务清理:validate_session 保持只读,否则带垃圾
    // Bearer 的未认证请求流会把每次读变成一次写事务。
    let janitor = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            tick.tick().await;
            if let Err(e) = janitor.store.cleanup_sessions() {
                tracing::warn!("session cleanup failed: {e}");
            }
        }
    });

    let listen = state.cfg.listen;
    tracing::info!("rooster hub listening on {listen} (tls: {:?})", state.cfg.tls_mode_str());
    http::serve(state, listen).await.map_err(|e| format!("serve: {e}"))
}

/// `rooster hub backup`:复制 redb 与 PKI 到目标目录。
/// 复制前先独占打开一次数据库并提交空事务:既能发现“hub 还在跑”(写锁
/// 拿不到→报错,不产出半快照),又把 WAL checkpoint 成一致文件。
pub fn backup(cfg_path: &Path, out: &Path) -> Result<(), String> {
    let cfg: HubConfig = load_config(cfg_path)?;
    let src_db = cfg.data_dir.join("hub.redb");
    let src_pki = cfg.data_dir.join("pki");
    std::fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    if src_db.exists() {
        checkpoint(&src_db)?;
        std::fs::copy(&src_db, out.join("hub.redb")).map_err(|e| format!("copy db: {e}"))?;
    }
    copy_dir(&src_pki, &out.join("pki"))?;
    println!("backup written to {}", out.display());
    Ok(())
}

/// 见 `backup`:目标库必须处于无人持有写锁的状态才可复制/覆盖。
fn checkpoint(db: &Path) -> Result<(), String> {
    let handle = redb::Database::builder()
        .open(db)
        .map_err(|e| format!("open {}: {e} — stop the hub first", db.display()))?;
    let w = handle.begin_write().map_err(|e| format!("checkpoint: {e}"))?;
    w.commit().map_err(|e| format!("checkpoint commit: {e}"))?;
    drop(handle);
    Ok(())
}

/// `rooster hub restore`:从备份目录恢复 redb 与 PKI。
pub fn restore(cfg_path: &Path, src: &Path) -> Result<(), String> {
    let cfg: HubConfig = load_config(cfg_path)?;
    let dst_db = cfg.data_dir.join("hub.redb");
    let dst_pki = cfg.data_dir.join("pki");
    let from_db = src.join("hub.redb");
    if from_db.exists() {
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("create data-dir: {e}"))?;
        // 覆盖前同样要求目标库无人持有写锁,否则会把在用 hub 的底层文件
        // 抽掉(与备份侧同一约束)。
        if dst_db.exists() {
            checkpoint(&dst_db)?;
        }
        std::fs::copy(&from_db, &dst_db).map_err(|e| format!("restore db: {e}"))?;
    }
    copy_dir(&src.join("pki"), &dst_pki)?;
    println!("restored from {}", src.display());
    Ok(())
}

fn load_config(cfg_path: &Path) -> Result<HubConfig, String> {
    let raw = std::fs::read_to_string(cfg_path).map_err(|e| format!("read config: {e}"))?;
    serde_norway::from_str(&raw).map_err(|e| format!("parse config: {e}"))
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    if !src.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    for entry in std::fs::read_dir(src).map_err(|e| format!("read dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to).map_err(|e| format!("copy file: {e}"))?;
        }
    }
    Ok(())
}

/// 面板/Agent 下载二进制的辅助:hub 自身可执行文件路径。
pub fn self_exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/rooster"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_stable_and_key_sensitive() {
        let a = hmac_sha256(b"k1", b"path:123");
        let b = hmac_sha256(b"k1", b"path:123");
        let c = hmac_sha256(b"k2", b"path:123");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    /// 强制 mTLS:明文模式下的 Agent 身份只剩“知道 node_id”,所以
    /// 明文绑非回环地址必须拒启(见 run() 的校验)。
    #[tokio::test]
    async fn plaintext_listen_is_refused_on_public_interfaces() {
        let dir = std::env::temp_dir().join(format!("rooster-hub-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("hub.yaml");
        std::fs::write(
            &cfg_path,
            format!(
                "listen: 0.0.0.0:9443\ndata-dir: {}\ntls:\n  mode: none\nsecret-key: \"x\"\n",
                dir.display()
            ),
        )
        .unwrap();
        let err = run(&cfg_path).await.unwrap_err();
        assert!(err.contains("non-loopback"), "expected refusal, got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
