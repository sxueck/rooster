//! Agent 侧 Hub 客户端(Agent 半边)。
//!
//! - 注册:首次安装时用一次性 token + CSR 换取客户端证书;
//! - 长连接:ws(s) mTLS,心跳 15s,断线指数退避 1s→60s;
//! - ApiRequest:在本进程内直接调用无鉴权的管理路由(mTLS 通道已认证);
//! - 事件:Outbox 持久化,连接健康时批量补报,EventAck 后清理;
//! - GlobalBan/Unban/Sync、ApplyTemplate、RenewCert、Upgrade。

use crate::state::AgentState;
use crate::upgrade;
use futures_util::{SinkExt, StreamExt};
use rooster_config::{Seg, EffectiveConfig};
use rooster_proto::Frame;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const HEARTBEAT: Duration = Duration::from_secs(15);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

struct HubEndpoints {
    ws_url: String,
    rest_base: String,
}

fn endpoints(hub: &rooster_config::HubSection) -> HubEndpoints {
    let url = hub.url.trim().to_string();
    let (ws, rest) = if let Some(rest) = url.strip_prefix("wss://") {
        (format!("wss://{rest}"), format!("https://{rest}"))
    } else if let Some(rest) = url.strip_prefix("ws://") {
        (format!("ws://{rest}"), format!("http://{rest}"))
    } else {
        (url.clone(), "http://localhost".to_string())
    };
    let ws_url = if ws.contains("/agent/ws") {
        ws
    } else {
        format!("{}/agent/ws", ws.trim_end_matches('/'))
    };
    let rest_base = rest.trim_end_matches("/agent/ws").trim_end_matches('/').to_string();
    HubEndpoints { ws_url, rest_base }
}

/// 主循环:注册(如需)→ 连接 → 帧处理 → 断线退避重连。
pub async fn run(state: Arc<AgentState>) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let eff = state.effective();
        let Some(hub) = eff.hub.clone() else {
            // hub 配置被移除:静默等待(热重载可能再加回来)。
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        };
        let data_dir = eff.agent.data_dir();

        // 注册(首次):token + CSR → cert/ca 落盘。节点名与 Hello 共用
        // 同一来源(effective_node_name),否则 hub 侧按 node_id 找到的
        // 证书指纹对不上 mTLS 身份。
        if let Err(e) = ensure_registered(&eff, &data_dir).await {
            tracing::warn!("hub registration: {e}");
            sleep_backoff(&mut backoff).await;
            continue;
        }

        match connect_and_serve(&state, &hub, &data_dir).await {
            Ok(()) => {
                // 正常返回 = 连接曾建立且存活超过一个心跳周期。
                backoff = BACKOFF_MIN;
            }
            Err(e) => {
                tracing::warn!("hub connection: {e}");
            }
        }
        state.hub_connected.send_replace(false);
        sleep_backoff(&mut backoff).await;
    }
}

async fn sleep_backoff(backoff: &mut Duration) {
    tokio::time::sleep(*backoff).await;
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
}

// ---------------------------------------------------------------------------
// 注册

/// 节点身份唯一来源:注册 CSR CN / register node_id / Hello node_id 必须
/// 一致(hub 用 Hello node_id 反查证书指纹做 mTLS 鉴权)。优先级:
/// config agent.node-name → env ROOSTER_NODE_NAME → /etc/hostname → 兜底。
pub fn effective_node_name(eff: &EffectiveConfig) -> String {
    eff.agent
        .node_name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .or_else(|| {
            std::env::var("ROOSTER_NODE_NAME")
                .ok()
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
        })
        .or_else(hostname)
        .unwrap_or_else(|| "node-unknown".to_string())
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn ensure_registered(
    eff: &EffectiveConfig,
    data_dir: &std::path::Path,
) -> Result<(), String> {
    let hub = eff
        .hub
        .as_ref()
        .ok_or_else(|| "hub not configured".to_string())?;
    let (cert, key, _) = cert_paths(hub, data_dir);
    let reg_ca = registration_ca_path(data_dir);
    // 跳过条件只看 agent 身份(证书/私钥 + 注册 CA 文件),绝不要求管理员
    // 安装的服务器 CA 存在。已有证书但没有注册 CA 文件且没有 token 时,
    // 无法补注册,按已注册处理(信任库照常并入管理员 ca 文件里的证书)。
    let has_token = hub
        .token
        .as_deref()
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false);
    if cert.exists() && key.exists() && (reg_ca.exists() || !has_token) {
        return Ok(());
    }
    let token = hub
        .token
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| "no client certificate and no registration token".to_string())?;

    let dir = data_dir.join("pki");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create pki dir: {e}"))?;

    // 生成 key + CSR(节点名即证书 CN)。
    let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("generate key: {e}"))?;
    std::fs::write(&key, key_pair.serialize_pem()).map_err(|e| format!("write key: {e}"))?;
    crate::write_private_file(&key);
    let mut params = rcgen::CertificateParams::default();
    let node = effective_node_name(eff);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, node.clone());
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("serialize csr: {e}"))?;
    let csr_pem = csr
        .pem()
        .map_err(|e| format!("csr pem: {e}"))?;

    let ep = endpoints(hub);
    let client = http_client(hub, data_dir)?;
    let resp = client
        .post(format!("{}/v0/register", ep.rest_base))
        .json(&serde_json::json!({
            "token": token,
            "csr_pem": csr_pem,
            "node_id": node,
        }))
        .send()
        .await
        .map_err(|e| format!("register request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("register rejected: {}", resp.status()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("register body: {e}"))?;
    let cert_pem = body["cert_pem"]
        .as_str()
        .ok_or("register response missing cert_pem")?
        .to_string();
    let ca_pem = body["ca_pem"]
        .as_str()
        .ok_or("register response missing ca_pem")?
        .to_string();
    std::fs::write(&cert, cert_pem).map_err(|e| format!("write cert: {e}"))?;
    // 注册响应的 CA 只签名 agent 客户端证书,写到独立文件;覆盖 pki/ca.crt
    // 会毁掉管理员安装的服务器信任锚。
    std::fs::write(&reg_ca, ca_pem).map_err(|e| format!("write reg ca: {e}"))?;
    tracing::info!(node = node, "registered with hub");
    Ok(())
}

fn cert_paths(hub: &rooster_config::HubSection, data_dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
    let dir = data_dir.join("pki");
    (
        hub.cert.clone().unwrap_or_else(|| dir.join("agent.crt")),
        hub.key.clone().unwrap_or_else(|| dir.join("agent.key")),
        hub.ca.clone().unwrap_or_else(|| dir.join("ca.crt")),
    )
}

/// 注册响应 CA 的落盘位置:与管理员安装的服务器 CA(pki/ca.crt)分开,
/// 二者会同时进入信任库,互不覆盖。
fn registration_ca_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("pki/hub-ca.crt")
}

/// 信任库唯一来源(A2):webpki 公共根 ∪ 管理员 ca 文件里的全部 PEM 证书
/// ∪ 注册 CA 文件里的证书。三者取并集而不是二选一 —— 注册 CA 只签名
/// agent 客户端证书,不能顶替服务器信任锚;反之亦然。文件缺失只是
/// 该来源为空,损坏的 PEM 按错误上报而不是 panic。
fn trust_roots(
    hub: &rooster_config::HubSection,
    data_dir: &std::path::Path,
) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let (_, _, admin_ca) = cert_paths(hub, data_dir);
    let reg_ca = registration_ca_path(data_dir);
    for path in [admin_ca, reg_ca] {
        let pem = match std::fs::read_to_string(&path) {
            Ok(p) => p,
            // 不存在 = 未配置,正常降级到 webpki 公共根。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        if pem.trim().is_empty() {
            continue;
        }
        let mut seen = 0;
        for c in rustls_pemfile::certs(&mut pem.as_bytes()) {
            let c = c.map_err(|e| format!("parse cert in {}: {e}", path.display()))?;
            // 重复/不可用条目跳过,不影响其余根。
            let _ = roots.add(c);
            seen += 1;
        }
        // 管理员显式放了个 CA 文件却解析不出证书:报错而不是静默只用 webpki,
        // 否则 mTLS 部署会退化成"看起来连上了但随时会 UnknownIssuer"。
        if seen == 0 {
            return Err(format!("no certificate in {}", path.display()));
        }
    }
    Ok(roots)
}

/// 解析 agent 客户端身份(A3):证书/私钥任一未落盘 → None(未注册,
/// 调用方降级为不带客户端证书);文件在但解析失败 → 错误而不是 panic。
fn client_identity(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<
    Option<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
    String,
> {
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(cert_path),
        std::fs::read_to_string(key_path),
    ) else {
        return Ok(None);
    };
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse client cert: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificate in {}", cert_path.display()));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("parse client key: {e}"))?
        .ok_or_else(|| format!("no private key in {}", key_path.display()))?;
    Ok(Some((certs, key)))
}

/// REST 客户端:信任库见 [`trust_roots`];已有 agent 证书则附上 mTLS 节点
/// 身份(hub 侧 /v0/downloads/* 按对端证书指纹鉴权),否则降级匿名。
fn http_client(
    hub: &rooster_config::HubSection,
    data_dir: &std::path::Path,
) -> Result<reqwest::Client, String> {
    http_client_with_timeout(hub, data_dir, Duration::from_secs(15))
}

fn http_client_with_timeout(
    hub: &rooster_config::HubSection,
    data_dir: &std::path::Path,
    timeout: Duration,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    // 明文 hub(ws:// → http://)没有 TLS 层:不构建信任库,也不因为管理员
    // 留了个占位 ca.crt 就连不上注册接口。
    if endpoints(hub).rest_base.starts_with("https://") {
        let roots = trust_roots(hub, data_dir)?;
        let cfg = rustls::ClientConfig::builder().with_root_certificates(roots);
        let (cert_path, key_path, _) = cert_paths(hub, data_dir);
        let cfg = match client_identity(&cert_path, &key_path)? {
            Some((certs, key)) => cfg
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("client tls: {e}"))?,
            None => cfg.with_no_client_auth(),
        };
        builder = builder.use_preconfigured_tls(cfg);
    }
    builder
        .build()
        .map_err(|e| format!("http client: {e}"))
}

// ---------------------------------------------------------------------------
// 连接与帧处理

pub async fn connect_and_serve(
    state: &Arc<AgentState>,
    hub: &rooster_config::HubSection,
    data_dir: &std::path::Path,
) -> Result<(), String> {
    let ep = endpoints(hub);
    let eff = state.effective();
    let node = effective_node_name(&eff);

    // TLS:信任库与 REST 客户端同源(trust_roots);wss 必须携带客户端证书。
    let (req, _resp) = if ep.ws_url.starts_with("wss://") {
        let (cert_path, key_path, _) = cert_paths(hub, data_dir);
        let (certs, key) = client_identity(&cert_path, &key_path)?
            .ok_or("wss requires agent client certificate/key")?;
        let roots = trust_roots(hub, data_dir)?;
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("client tls: {e}"))?;
        tokio_tungstenite::connect_async_tls_with_config(
            ep.ws_url.clone(),
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(tls))),
        )
        .await
        .map_err(|e| format!("wss connect: {e}"))?
    } else {
        tokio_tungstenite::connect_async(&ep.ws_url)
            .await
            .map_err(|e| format!("ws connect: {e}"))?
    };
    let _ = _resp;

    let (mut sink, mut stream) = req.split();
    let hash = state.current_hash();

    // Hello。
    let hello = Frame::Hello {
        node_id: node.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        config_hash: hash,
    };
    sink.send(Message::binary(rooster_proto::encode(&hello)))
        .await
        .map_err(|e| format!("send hello: {e}"))?;

    state.hub_connected.send_replace(false);

    // 补报缓冲事件。
    flush_outbox(state, &mut sink).await;

    let mut last_rx = tokio::time::Instant::now();
    let alive_since = tokio::time::Instant::now();
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let hb = tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if pong_tx.send(()).is_err() {
                break;
            }
        }
    });

    // Agent 主动帧(证书续签等)汇入这条通道,由下面的读循环统一写入 sink。
    // 登记放在 Hello 成功之后:否则发送端会泄漏到一个已经死掉的 sink 上,
    // send_hub_frame 报成功而帧永远发不出去。
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<Frame>();
    let frame_gen = state.set_hub_frame(&frame_tx);

    let result: Result<(), String> = loop {
        tokio::select! {
            _ = pong_rx.recv() => {
                if sink.send(Message::binary(rooster_proto::encode(&Frame::Ping))).await.is_err() {
                    break Err("send ping failed".into());
                }
            }
            got = frame_rx.recv() => {
                let Some(frame) = got else { break Err("agent frame channel closed".into()) };
                if sink.send(Message::binary(rooster_proto::encode(&frame))).await.is_err() {
                    break Err("send agent frame failed".into());
                }
            }
            _ = state.outbox_notify.notified() => {
                // push_event 的唤醒:新事件立即补报,不等 ack/重连。
                // 连接不在时许可会留到下一轮(Notify 存储一个许可),不丢失。
                flush_outbox(state, &mut sink).await;
            }
            msg = stream.next() => {
                let Some(msg) = msg else { break Err("hub closed".into()) };
                last_rx = tokio::time::Instant::now();
                let frame = match msg {
                    Ok(Message::Binary(bytes)) => rooster_proto::decode(&bytes)
                        .map_err(|e| format!("bad frame: {e}"))?,
                    Ok(Message::Close(_)) | Err(_) => break Err("hub closed".into()),
                    _ => continue,
                };
                if let Frame::Error { message } = &frame {
                    break Err(format!("hub rejected connection: {message}"));
                }
                if let Err(e) = handle_frame(state, &mut sink, &node, frame).await {
                    break Err(e);
                }
                // The first authenticated hub frame confirms Hello acceptance; send() loses state without subscribers.
                if !state.hub_connected.send_replace(true) {
                    tracing::info!(node = node, "connected to hub {}", ep.ws_url);
                }
            }
            _ = tokio::time::sleep_until(last_rx + HEARTBEAT * 3) => {
                break Err("hub unresponsive (no traffic in 45s)".into());
            }
        }
    };

    hb.abort();
    state.hub_connected.send_replace(false);
    state.clear_hub_frame(frame_gen);
    // 连接曾存活 ≥60s → 视为“曾成功”,由调用方重置退避;短命连接
    // 保持退避以免持续打抖。
    if alive_since.elapsed() >= Duration::from_secs(60) {
        return Ok(());
    }
    result
}

async fn handle_frame<T>(
    state: &Arc<AgentState>,
    sink: &mut T,
    node: &str,
    frame: Frame,
) -> Result<(), String>
where
    T: futures_util::Sink<Message> + Unpin,
    T::Error: std::fmt::Display,
{
    use futures_util::SinkExt as _;
    match frame {
        Frame::Ping => {
            sink.send(Message::binary(rooster_proto::encode(&Frame::Pong)))
                .await
                .map_err(|e| e.to_string())?;
        }
        Frame::Pong => {}
        Frame::ApiRequest {
            id,
            method,
            path,
            headers,
            body,
        } => {
            let (status, resp_headers, resp_body) =
                crate::management::serve_trusted(state, &method, &path, &headers, &body).await;
            let resp = Frame::ApiResponse {
                id,
                status,
                headers: resp_headers,
                body: resp_body,
            };
            sink.send(Message::binary(rooster_proto::encode(&resp)))
                .await
                .map_err(|e| e.to_string())?;
        }
        Frame::EventAck { acked_through } => {
            if let Some(outbox) = state.hub_outbox.lock().unwrap().clone() {
                if let Err(e) = outbox.ack(acked_through) {
                    tracing::warn!("outbox ack: {e}");
                }
                *state.outbox_acked.lock().unwrap() = acked_through;
            }
            // 可能还有积压:立即再补一批。
            flush_outbox(state, sink).await;
        }
        Frame::GlobalBan {
            ip,
            ttl_secs,
            reason,
            source_node,
        } => {
            apply_global_ban(state, &ip, ttl_secs, &reason, &source_node);
        }
        Frame::GlobalUnban { ip } => {
            apply_global_unban(state, &ip);
        }
        Frame::GlobalBanSync { bans } => {
            reconcile_global_bans(state, &bans);
        }
        Frame::ApplyTemplate { id, yaml } => {
            let (ok, error, confirm_token) = apply_template(state, &yaml);
            let resp = Frame::TemplateResult {
                id,
                ok,
                error,
                confirm_token,
            };
            sink.send(Message::binary(rooster_proto::encode(&resp)))
                .await
                .map_err(|e| e.to_string())?;
        }
        Frame::Renewed { cert_pem } => {
            let eff = state.effective();
            // cert_paths = (cert, key, ca):这里要写的是证书,不是私钥。
            let (cert_path, _, _) = cert_paths(eff.hub.as_ref().unwrap(), &eff.agent.data_dir());
            if let Err(e) = std::fs::write(&cert_path, cert_pem) {
                tracing::warn!("write renewed cert: {e}");
            } else {
                tracing::info!("client certificate renewed");
            }
        }
        Frame::Upgrade {
            version,
            url,
            signature,
            public_key,
        } => {
            let state = state.clone();
            tokio::spawn(async move {
                upgrade::handle(&state, &version, &url, &signature, public_key.as_deref()).await;
            });
        }
        Frame::Hello { .. } | Frame::Error { .. } => {
            tracing::debug!(node, "ignoring hub frame");
        }
        other => {
            let _ = other;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 事件补报

async fn flush_outbox<T>(state: &Arc<AgentState>, sink: &mut T)
where
    T: futures_util::Sink<Message> + Unpin,
    T::Error: std::fmt::Display,
{
    use futures_util::SinkExt as _;
    let Some(outbox) = state.hub_outbox.lock().unwrap().clone() else {
        return;
    };
    let last_acked = state.outbox_acked.lock().unwrap().clone();
    let pending = match outbox.pending(last_acked, 500) {
        Ok(p) => p,
        Err(e) => {
            // 静默返回 = 事件停止上报而没有任何痕迹。
            tracing::warn!("outbox pending failed, events not reported: {e}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let first_seq = pending[0].0;
    let batch: Vec<rooster_proto::Event> = pending.into_iter().map(|(_, e)| e).collect();
    let frame = Frame::Event { first_seq, batch };
    // 游标只在 EventAck 时推进;未确认的事件在下次重连时重发,策略引擎
    // 按 (policy, ip) 窗口计数,重复上报只影响计数不影响正确性。
    let _ = sink
        .send(Message::binary(rooster_proto::encode(&frame)))
        .await;
}

// ---------------------------------------------------------------------------
// 全局封禁落地

fn apply_global_ban(state: &Arc<AgentState>, ip: &str, ttl_secs: u64, reason: &str, source_node: &str) {
    let Some(bans) = state.bans.read().unwrap().clone() else {
        tracing::warn!(ip, "global ban ignored: ban manager unavailable");
        return;
    };
    let entry = rooster_nft::BanEntry {
        ip: ip.to_string(),
        reason: format!("global: {reason}"),
        plugin: "hub".to_string(),
        node: source_node.to_string(),
        scope: rooster_nft::BanScope::Global,
        ttl: Duration::from_secs(ttl_secs.max(1)),
        expires_at: None,
    };
    match bans.apply_ban(&entry) {
        Ok(()) => {
            state.push_event(rooster_proto::Event::Ban {
                ip: ip.to_string(),
                reason: reason.to_string(),
                plugin: "hub".to_string(),
                scope: "global".to_string(),
                ttl_secs,
            });
        }
        Err(rooster_nft::NftError::Refused(msg)) => {
            // 管理白名单优先,拒封是预期行为。
            tracing::info!(ip, why = msg, "global ban refused by allowlist");
        }
        Err(e) => tracing::warn!(ip, error = e.to_string(), "global ban failed"),
    }
}

/// 全量同步:新增的补齐,不在列表内的 global 条目移除。
fn reconcile_global_bans(state: &Arc<AgentState>, target: &[rooster_proto::GlobalBanInfo]) {
    let Some(bans) = state.bans.read().unwrap().clone() else {
        return;
    };
    let want: std::collections::HashSet<&str> =
        target.iter().map(|b| b.ip.as_str()).collect();
    let Ok(current) = bans.list_bans() else {
        return;
    };
    for entry in &current {
        if entry.scope == rooster_nft::BanScope::Global && !want.contains(entry.ip.as_str()) {
            let _ = bans.remove_ban(&entry.ip);
        }
    }
    for b in target {
        let fresh = current
            .iter()
            .find(|e| e.ip == b.ip)
            .map(|e| e.expires_at.unwrap_or(0) <= now_secs())
            .unwrap_or(true);
        if fresh {
            apply_global_ban(state, &b.ip, b.ttl_secs, &b.reason, &b.source_node);
        }
    }
}

/// 全局解封(A8):只有当存储行的 scope 确实是 Global 才解;本地插件
/// 的行(内核元素由其所有者管理)不动,避免删掉别人的封禁。
pub fn apply_global_unban(state: &Arc<AgentState>, ip: &str) {
    let Some(bans) = state.bans.read().unwrap().clone() else {
        return;
    };
    let Ok(current) = bans.list_bans() else {
        return;
    };
    let is_global = current
        .iter()
        .any(|e| e.ip == ip && e.scope == rooster_nft::BanScope::Global);
    if !is_global {
        tracing::info!(ip, "global unban skipped: no global ban row (local plugin owns it)");
        return;
    }
    if let Err(e) = bans.remove_ban(ip) {
        tracing::warn!(ip, error = e.to_string(), "global unban failed");
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// 模板下发:写入 managed 段并 commit。

pub fn apply_template(
    state: &Arc<AgentState>,
    yaml: &str,
) -> (bool, Option<String>, Option<String>) {
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => return (false, Some(format!("read config: {e}")), None),
    };
    let value: serde_json::Value = match serde_norway::from_str::<serde_norway::Value>(yaml) {
        Ok(v) => match serde_json::to_value(&v) {
            Ok(j) => j,
            Err(e) => return (false, Some(format!("template not plain data: {e}")), None),
        },
        Err(e) => return (false, Some(format!("invalid template yaml: {e}")), None),
    };
    let seg = [Seg::K("managed")];
    let new_raw = if rooster_config::writer::subtree_exists(&raw, &seg).unwrap_or(false) {
        rooster_config::writer::replace_subtree(&raw, &seg, &value)
    } else {
        rooster_config::writer::add_key(&raw, &[], "managed", &value)
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return (false, Some(format!("patch managed: {e}")), None),
    };

    let old_eff = state.effective();
    let previous_raw = raw;
    match state.commit_raw(&new_raw) {
        Ok(new_eff) => {
            state.push_event(rooster_proto::Event::ConfigChanged {
                hash: state.current_hash(),
            });
            let mut confirm_token = None;
            if AgentState::needs_confirm(&old_eff, &new_eff) {
                let token = crate::management::new_confirm_token();
                let timeout = old_eff.security.apply_confirm_timeout();
                state.start_confirm_timer(token.clone(), previous_raw, timeout);
                confirm_token = Some(token);
            }
            (true, None, confirm_token)
        }
        Err(e) => (false, Some(format!("commit: {e}")), None),
    }
}

// ---------------------------------------------------------------------------
// 从 hub 下载文件(wasm 插件 / 升级包):相对路径解析到 hub 基地址,
// 并携带 mTLS 节点身份(hub 侧按证书指纹鉴权 /v0/downloads/*)。

/// 把 hub 下发的下载路径解析成绝对 URL:已经是 http(s) 绝对地址则原样,
/// 相对路径(/v0/downloads/...)拼到 hub REST 基地址上。
pub fn hub_file_url(hub: &rooster_config::HubSection, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let ep = endpoints(hub);
    format!("{}/{}", ep.rest_base, path.trim_start_matches('/'))
}

/// 下载到内存(升级路径复用;大文件用 120s 超时与升级旧超时一致)。
pub async fn fetch_hub_bytes(
    state: &Arc<AgentState>,
    path: &str,
) -> Result<Vec<u8>, String> {
    let eff = state.effective();
    let hub = eff.hub.clone().ok_or("hub not configured")?;
    let url = hub_file_url(&hub, path);
    let client =
        http_client_with_timeout(&hub, &eff.agent.data_dir(), Duration::from_secs(120))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("http {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("body: {e}"))?;
    Ok(bytes.to_vec())
}

pub async fn fetch_hub_file(
    state: &Arc<AgentState>,
    path: &str,
    dest: &std::path::Path,
) -> Result<(), String> {
    let bytes = fetch_hub_bytes(state, path).await?;
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create dir: {e}"))?;
    }
    std::fs::write(dest, &bytes).map_err(|e| format!("write: {e}"))
}

// ---------------------------------------------------------------------------
// 证书续签(到期前 30 天)。证书文件 mtime 距今 >335 天即续。

/// 每日检查一次;到期前用**现有私钥**重新提交 CSR 请求新证书。
///
/// 不轮换新私钥:密钥与证书必须成对落盘。旧实现在发出请求前就把新生成的 key
/// 覆写进 agent.key,而请求走的通道当时没有接线 —— 证书没续上、私钥先被毁,
/// 一次断线重连后 mTLS 永久失败。
pub async fn renewal_loop(state: Arc<AgentState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
        let eff = state.effective();
        let Some(hub) = eff.hub.clone() else { continue };
        let data_dir = eff.agent.data_dir();
        let (cert_path, key_path, _) = cert_paths(&hub, &data_dir);
        let Ok(modified) = std::fs::metadata(&cert_path).and_then(|m| m.modified()) else {
            continue;
        };
        let Ok(age) = modified.elapsed() else { continue };
        if age < Duration::from_secs(335 * 24 * 3600) {
            continue;
        }
        // 注册端点需要一次性 token,续签只能走长连接(hub 侧 ws.rs 响应)。
        let Ok(key_pem) = std::fs::read_to_string(&key_path) else {
            tracing::warn!("renewal: cannot read {}", key_path.display());
            continue;
        };
        let Ok(key_pair) = rcgen::KeyPair::from_pem(&key_pem) else {
            tracing::warn!("renewal: cannot parse agent key");
            continue;
        };
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, effective_node_name(&eff));
        let Ok(csr) = params.serialize_request(&key_pair) else { continue };
        let Ok(csr_pem) = csr.pem() else { continue };
        if state.send_hub_frame(Frame::RenewCert { csr_pem }).is_err() {
            tracing::info!("renewal: hub not connected, retry tomorrow");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooster_config::HubSection;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rooster-hubclient-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn self_signed() -> String {
        rcgen::generate_simple_self_signed(vec!["test-ca".into()])
            .unwrap()
            .cert
            .pem()
    }

    /// A2:信任库必须是 webpki ∪ 管理员 ca 文件 ∪ 注册 CA 的并集,
    /// 缺哪个文件都不能丢掉其余来源。
    #[test]
    fn trust_roots_union_of_webpki_admin_and_registration_ca() {
        let dir = tmp_dir("roots");
        let admin_ca = dir.join("admin-ca.crt");
        let webpki_len = webpki_roots::TLS_SERVER_ROOTS.len();

        // 期望值:webpki + 2 个管理员证书 + 1 个注册 CA。
        let mut expected = rustls::RootCertStore::empty();
        expected.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let admin = format!("{}{}", self_signed(), self_signed());
        let reg = self_signed();
        for c in rustls_pemfile::certs(&mut admin.as_bytes())
            .chain(rustls_pemfile::certs(&mut reg.as_bytes()))
        {
            let _ = expected.add(c.unwrap());
        }

        std::fs::create_dir_all(dir.join("pki")).unwrap();
        std::fs::write(&admin_ca, &admin).unwrap();
        std::fs::write(registration_ca_path(&dir), &reg).unwrap();
        let hub = HubSection {
            url: "wss://hub.example.com:9443".into(),
            token: None,
            cert: None,
            key: None,
            ca: Some(admin_ca),
        };
        let roots = trust_roots(&hub, &dir).unwrap();
        assert_eq!(roots.len(), expected.len());
        assert!(roots.len() > webpki_len, "自定义 CA 必须并入");

        // 两个文件都缺:仍保留 webpki 公共根。
        let hub = HubSection {
            url: hub.url.clone(),
            token: None,
            cert: None,
            key: None,
            ca: None,
        };
        let dir2 = tmp_dir("roots-none");
        let roots = trust_roots(&hub, &dir2).unwrap();
        assert_eq!(roots.len(), webpki_len);

        // 坏 PEM:报错而不是 panic/静默。
        std::fs::create_dir_all(dir2.join("pki")).unwrap();
        std::fs::write(dir2.join("pki/ca.crt"), "not a pem").unwrap();
        assert!(trust_roots(&hub, &dir2).is_err());
    }

    /// A4:hub 下发的相对下载路径必须解析成绝对 hub URL。
    #[test]
    fn hub_file_url_resolves_relative_download_paths() {
        let hub = HubSection {
            url: "wss://hub.example.com:9443/agent/ws".into(),
            token: None,
            cert: None,
            key: None,
            ca: None,
        };
        assert_eq!(
            hub_file_url(&hub, "/v0/downloads/1.2.3?exp=1&sig=abc"),
            "https://hub.example.com:9443/v0/downloads/1.2.3?exp=1&sig=abc"
        );
        let ws_hub = HubSection {
            url: "ws://127.0.0.1:9000".into(),
            ..hub.clone()
        };
        assert_eq!(
            hub_file_url(&ws_hub, "/v0/downloads/wasm/x.wasm"),
            "http://127.0.0.1:9000/v0/downloads/wasm/x.wasm"
        );
        // 已是绝对地址则原样透传。
        assert_eq!(
            hub_file_url(&hub, "https://mirror.example.com/pkg"),
            "https://mirror.example.com/pkg"
        );
    }

    /// A2/A3:证书+私钥就位时 http_client 应带上客户端身份;只有一半时
    /// 不算身份(返回 Ok 的匿名客户端)。
    #[test]
    fn client_identity_requires_both_cert_and_key() {
        let dir = tmp_dir("identity");
        let cert = dir.join("agent.crt");
        let key = dir.join("agent.key");
        assert!(client_identity(&cert, &key).unwrap().is_none());

        let ck = rcgen::generate_simple_self_signed(vec!["agent".into()]).unwrap();
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        assert!(client_identity(&cert, &key).unwrap().is_none());
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        assert!(client_identity(&cert, &key).unwrap().is_some());

        std::fs::write(&cert, "garbage").unwrap();
        assert!(client_identity(&cert, &key).is_err());
    }
}
