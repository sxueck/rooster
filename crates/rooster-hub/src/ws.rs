//! WebSocket 端点:/agent/ws(Agent mTLS 长连接)与
//! /v0/ws(面板实时事件)。

use crate::http::ConnMeta;
use crate::rollout;
use crate::store::now_secs;
use crate::HubState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rooster_proto::{Event, Frame};
use std::sync::Arc;
use std::time::Duration;

const HEARTBEAT: Duration = Duration::from_secs(15);
const DEAD_AFTER: Duration = Duration::from_secs(45);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Agent 长连接入口。
pub async fn agent_ws(
    State(state): State<Arc<HubState>>,
    Extension(meta): Extension<ConnMeta>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |sock| agent_session(state, meta, sock))
}

async fn agent_session(state: Arc<HubState>, meta: ConnMeta, mut sock: WebSocket) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Frame>();

    // 等待 Hello 并认证。
    let hello = tokio::time::timeout(HELLO_TIMEOUT, sock.recv()).await;
    let (node_id, version, config_hash) = match hello {
        Ok(Some(Ok(Message::Binary(bytes)))) => match rooster_proto::decode(&bytes) {
            Ok(Frame::Hello {
                node_id,
                version,
                config_hash,
            }) => (node_id, version, config_hash),
            other => {
                tracing::warn!(?other, peer = meta.peer.to_string(), "agent ws: first frame is not Hello");
                return;
            }
        },
        _ => {
            tracing::warn!(peer = meta.peer.to_string(), "agent ws: no Hello in time");
            return;
        }
    };

    // 连接认证:证书指纹(TLS)或既有节点记录(明文开发模式)。
    match authorize(&state, &node_id, meta.cert_fp.as_deref()).await {
        Ok(()) => {}
        Err(e) => {
            tracing::warn!(node = node_id, error = e, "agent ws rejected");
            let _ = sock
                .send(Message::Binary(rooster_proto::encode(&Frame::Error { message: e }).into()))
                .await;
            return;
        }
    }

    let conn = crate::registry::Conn::new_with_peer_ip(
        &node_id,
        tx.clone(),
        Some(meta.peer.ip()),
    );
    state.registry.register(&node_id, conn.clone());

    // 节点状态更新 + 面板通知。
    if let Ok(Some(mut rec)) = state.store.get_node(&node_id) {
        rec.version = version.clone();
        rec.config_hash = config_hash;
        rec.last_seen = now_secs();
        let _ = state.store.upsert_node(&rec);
    }
    let _ = state.events_tx.send(serde_json::json!({
        "type": "node_status", "node_id": node_id, "online": true,
    }));
    tracing::info!(node = node_id, peer = meta.peer.to_string(), "agent connected");

    // 重连后全量同步全局封禁;补发离线期间的模板与升级包。
    rollout::global_ban_sync(&state, &node_id);
    {
        let state = state.clone();
        let node_id = node_id.clone();
        tokio::spawn(async move {
            rollout::replay_pending_template(&state, &node_id).await;
        });
    }
    {
        let state = state.clone();
        let node_id = node_id.clone();
        tokio::spawn(async move {
            rollout::replay_pending_upgrade(&state, &node_id).await;
        });
    }
    // Hello 版本就是升级成功的事实源:首发窗口、补发、慢重启节点都在
    // 这里闭环(见 rollout::confirm_upgrade_by_hello)。
    rollout::confirm_upgrade_by_hello(&state, &node_id, &version);

    // 心跳:每 15s 发 Ping;读循环里超过 45s 无任何入站帧则断开。
    let hb_tx = tx.clone();
    let heartbeat = tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if hb_tx.send(Frame::Ping).is_err() {
                break;
            }
        }
    });

    let mut last_rx = tokio::time::Instant::now();
    // 注册表挂断(被新连接替换/节点被吊销):必须立刻退出,而不是等心跳
    // 超时——挂断信号用 watch,早于本循环开始 select 也能终止它。
    let mut hangup = conn.subscribe_hangup();
    loop {
        tokio::select! {
            out = rx.recv() => {
                // 出站:Frame → MessagePack 二进制帧。
                match out {
                    Some(frame) => {
                        let bytes = rooster_proto::encode(&frame);
                        if sock.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = sock.recv() => {
                let Some(Ok(msg)) = msg else { break };
                last_rx = tokio::time::Instant::now();
                let frame = match msg {
                    Message::Binary(bytes) => match rooster_proto::decode(&bytes) {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!(node = node_id, error = e.to_string(), "bad frame, closing");
                            break;
                        }
                    },
                    Message::Close(_) => break,
                    // ws 层 Ping/Pong 自动处理;文本帧不是本协议的一部分。
                    _ => continue,
                };
                handle_frame(&state, &conn, &node_id, frame).await;
            }
            _ = hangup.changed() => {
                tracing::info!(node = node_id, "agent ws hung up (replaced or revoked), closing");
                break;
            }
            _ = tokio::time::sleep_until(last_rx + DEAD_AFTER) => {
                tracing::warn!(node = node_id, "agent ws dead (no traffic), closing");
                break;
            }
        }
    }

    heartbeat.abort();
    // 摘除自己:仅当表项仍是本会话(ptr 相同)才宣告离线;若已被新会话
    // 接管(重连替换后挂断退出),不得把节点误标离线。
    if state.registry.unregister(&node_id, &conn) {
        if let Ok(Some(mut rec)) = state.store.get_node(&node_id) {
            rec.last_seen = now_secs();
            let _ = state.store.upsert_node(&rec);
        }
        let _ = state.events_tx.send(serde_json::json!({
            "type": "node_status", "node_id": node_id, "online": false,
        }));
    }
    tracing::info!(node = node_id, "agent disconnected");
}

/// 连接认证:TLS 模式下证书指纹必须与节点记录一致且未吊销;明文模式
/// (开发/内网)退化为“节点已注册且未吊销”。
async fn authorize(state: &Arc<HubState>, node_id: &str, cert_fp: Option<&str>) -> Result<(), String> {
    let rec = state
        .store
        .get_node(node_id)
        .map_err(|e| format!("store: {e}"))?
        .ok_or_else(|| "unknown node".to_string())?;
    if rec.revoked {
        return Err("node is revoked".to_string());
    }
    match cert_fp {
        Some(fp) => {
            cert_fp_is_live_node(state, fp)?;
            if fp != rec.cert_fp {
                return Err("certificate does not match node record (re-register required)".to_string());
            }
            Ok(())
        }
        None => {
            if state.cfg.tls_mode_str() == "none" {
                Ok(())
            } else {
                Err("client certificate required".to_string())
            }
        }
    }
}

/// 证书指纹的节点身份核验(与 /agent/ws 认证同一规则,供 mTLS 制品下载
/// 共用):指纹必须属于某个未吊销的已注册节点,且未进证书吊销表。
pub fn cert_fp_is_live_node(state: &HubState, fp: &str) -> Result<(), String> {
    if state.store.is_revoked(fp).unwrap_or(true) {
        return Err("certificate is revoked".to_string());
    }
    let live = state
        .store
        .list_nodes()
        .map(|ns| ns.iter().any(|n| !n.revoked && n.cert_fp == fp))
        .unwrap_or(false);
    if live {
        Ok(())
    } else {
        Err("certificate does not belong to a registered node".to_string())
    }
}

async fn handle_frame(state: &Arc<HubState>, conn: &Arc<crate::registry::Conn>, node_id: &str, frame: Frame) {
    match frame {
        Frame::Pong => {}
        Frame::Ping => {
            let _ = conn.send(Frame::Pong);
        }
        Frame::Event { first_seq, batch } => {
            let ts = now_secs();
            let policies = state.effective_policies();
            let mut engine = state.policy.lock().unwrap();
            for event in &batch {
                state.push_recent(node_id, ts, event.clone());
                for ban in engine.evaluate(&policies, node_id, event, ts) {
                    if let Err(e) = state.store.put_global_ban(&ban) {
                        tracing::warn!(error = e, "global ban store failed");
                        continue;
                    }
                    rollout::broadcast_global_ban(state, &ban);
                    state.audit(
                        &format!("policy:{}", ban.reason),
                        Some(node_id),
                        "GLOBAL_BAN",
                        &format!("/global-ban/{}", ban.ip),
                        ban.ip.as_bytes(),
                        200,
                    );
                }
            }
            drop(engine);
            // config_hash 过去只在 Hello 时登记,节点热更新后面板会始终
            // 显示旧值(配置漂移判断就错了):事件流里带了新 hash 就立即回填。
            // 回滚也走同一条通道(Agent 在 ConfigRolledBack 后补发 ConfigChanged)。
            let latest_hash = batch.iter().rev().find_map(|e| match e {
                Event::ConfigChanged { hash } => Some(hash.clone()),
                _ => None,
            });
            if let Some(hash) = latest_hash {
                if let Ok(Some(mut rec)) = state.store.get_node(node_id) {
                    if rec.config_hash != hash {
                        rec.config_hash = hash;
                        if let Err(e) = state.store.upsert_node(&rec) {
                            tracing::warn!(node = node_id, error = e, "config_hash refresh failed");
                        }
                    }
                }
            }
            let acked = first_seq + batch.len().saturating_sub(1) as u64;
            let _ = conn.send(Frame::EventAck { acked_through: acked });
            // 升级进度实时回填:agent 每个阶段都会发 UpgradeStatus,
            // 不接这里 rollout 行就永远是 sent→终态两态采样。
            for event in &batch {
                if let Event::UpgradeStatus { version, stage, detail } = event {
                    rollout::update_upgrade_progress(
                        state,
                        node_id,
                        version,
                        stage,
                        detail.clone(),
                    );
                }
            }
        }
        Frame::ApiResponse { .. } | Frame::TemplateResult { .. } => {
            // 完成对应的 oneshot 请求。
            let (id, f) = match frame {
                Frame::ApiResponse { id, .. } => (id, frame),
                Frame::TemplateResult { id, .. } => (id, frame),
                _ => unreachable!(),
            };
            conn.complete(id, f);
        }
        Frame::RenewCert { csr_pem } => {
            // 到期前 30 天续签:连接已通过证书认证,直接签。
            match state.pki.sign_csr(&csr_pem, node_id) {
                Ok((cert_pem, fp)) => {
                    if let Ok(Some(mut rec)) = state.store.get_node(node_id) {
                        rec.cert_fp = fp;
                        let _ = state.store.upsert_node(&rec);
                    }
                    let _ = conn.send(Frame::Renewed { cert_pem });
                }
                Err(e) => {
                    let _ = conn.send(Frame::Error { message: format!("renew failed: {e}") });
                }
            }
        }
        Frame::Hello { .. } => {
            let _ = conn.send(Frame::Error { message: "unexpected Hello".into() });
        }
        other => {
            tracing::debug!(node = node_id, ?other, "ignoring agent frame");
        }
    }
}

// ---------------------------------------------------------------------------
// 面板实时事件

pub async fn panel_ws(
    State(state): State<Arc<HubState>>,
    ws: WebSocketUpgrade,
    uri: axum::http::Uri,
) -> Response {
    // token 经查询参数(浏览器 WS 无法带 Authorization 头)。
    let token = uri
        .query()
        .and_then(|q| {
            q.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == "token").then(|| v.to_string())
            })
        })
        .unwrap_or_default();
    let valid = state.store.validate_session(&token).unwrap_or(false);
    if !valid {
        return (StatusCode::UNAUTHORIZED, "invalid session").into_response();
    }
    ws.on_upgrade(move |mut sock| {
        let mut rx = state.events_tx.subscribe();
        async move {
            // 先补一拍当前在线状态,面板刷新时能立即点亮。
            for id in state.registry.online_ids() {
                let msg = serde_json::json!({
                    "type": "node_status", "node_id": id, "online": true,
                });
                if sock
                    .send(Message::Text(msg.to_string().into()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        if sock
                            .send(Message::Text(msg.to_string().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // 慢消费者:丢弃过期消息继续。
                    }
                    Err(_) => break,
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NodeRecord;

    /// 明文模式的测试状态:节点表 + 吊销表可直接驱动 authorize。
    fn test_state(tag: &str) -> Arc<HubState> {
        let dir = std::env::temp_dir().join(format!("rooster-ws-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::store::open(&dir.join("h.redb")).unwrap();
        let (events_tx, _) = tokio::sync::broadcast::channel(8);
        Arc::new(HubState {
            cfg: crate::config::HubConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                data_dir: dir.clone(),
                public_url: None,
                agent_url: None,
                tls: Default::default(),
                secret_key: None,
                cors_allowed_origins: vec![],
                session_ttl: None,
                panel_dir: dir.clone(),
                auto_confirm_delay_secs: 0,
                upgrade_public_key: None,
                global_ban_policies: vec![],
                audit_retention: None,
            },
            store: crate::store::Store::new(db),
            pki: crate::pki::HubPki::ensure(&dir).unwrap(),
            registry: Default::default(),
            policy: std::sync::Mutex::new(crate::policy::PolicyEngine::new()),
            login_gate: Default::default(),
            events_tx,
            recent: std::sync::Mutex::new(Default::default()),
        })
    }

    #[tokio::test]
    async fn authorize_rules() {
        let state = test_state("auth");
        state.store.upsert_node(&NodeRecord::new("n", "fp-live".into())).unwrap();

        assert!(authorize(&state, "n", Some("fp-live")).await.is_ok());
        // 未知节点 / 指纹不属于任何节点 / 指纹属于别的节点:一律拒绝。
        assert!(authorize(&state, "ghost", Some("fp-live")).await.is_err());
        assert!(authorize(&state, "n", Some("fp-unknown")).await.is_err());
        assert!(authorize(&state, "n", Some("fp-other-node")).await.is_err());
        // 明文模式:无指纹放行(开发模式语义)。
        assert!(authorize(&state, "n", None).await.is_ok());

        // 吊销表命中:即使指纹匹配记录也拒绝(证书本身已作废)。
        state.store.revoke_cert("fp-live").unwrap();
        assert_eq!(
            authorize(&state, "n", Some("fp-live")).await.unwrap_err(),
            "certificate is revoked"
        );
        // 记录被标记 revoked:比指纹检查更早拒绝。
        let mut rec = state.store.get_node("n").unwrap().unwrap();
        rec.revoked = true;
        state.store.upsert_node(&rec).unwrap();
        assert_eq!(authorize(&state, "n", None).await.unwrap_err(), "node is revoked");
    }

    /// C2:面板删除后重新注册,新指纹可用;旧证书指纹仍被吊销表挡下,
    /// 换不回 mTLS 身份。
    #[tokio::test]
    async fn authorize_rejects_old_fingerprint_after_delete_and_reregister() {
        let state = test_state("rereg");
        let old_fp = "fp-old".to_string();
        let rec = NodeRecord::new("n", old_fp.clone());
        state.store.upsert_node(&rec).unwrap();
        state.store.revoke_cert(&old_fp).unwrap();
        state.store.delete_node("n").unwrap();

        // 新 token + 新 CSR → 新记录、新指纹。
        state.store.upsert_node(&NodeRecord::new("n", "fp-new".into())).unwrap();
        assert!(authorize(&state, "n", Some("fp-new")).await.is_ok());
        assert_eq!(
            authorize(&state, "n", Some(&old_fp)).await.unwrap_err(),
            "certificate is revoked",
            "old certificate fingerprint must stay blacklisted"
        );
    }
}
