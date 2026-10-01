//! 端到端:hub + 3 个模拟节点(真实 ws 客户端,协议级)。
//! 覆盖「可以在面板中管理 3 台以上节点的全部配置」的
//! 服务端链路:注册 → mTLS 通道(明文开发模式)→ 透传 → 联动广播。

use futures_util::{SinkExt, StreamExt};
use rooster_hub::config::HubConfig;
use rooster_hub::store;
use rooster_hub::HubState;
use rooster_proto::Frame;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// 测试专用 HTTP 客户端:禁用环境代理。
///
/// 本机若设有 http_proxy/https_proxy(常见的代理/抓包工具),reqwest 默认会
/// 读环境变量,把 127.0.0.1 的测试请求也丢进代理 —— `no_proxy` 里的
/// `127.*` 通配符 reqwest 并不识别,于是所有反代测试拿到代理返回的空 body
/// 502。测试连的是回环,必须显式绕开代理。
fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().expect("client")
}

struct HubServer {
    base: String,
    ws_base: String,
    _state: Arc<HubState>,
    dir: std::path::PathBuf,
}

impl Drop for HubServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start_hub(tag: &str) -> HubServer {
    start_hub_with_key(tag, None).await
}

/// `upgrade_public_key` 是上传不验 / 安装脚本验签的锤点。
async fn start_hub_with_key(tag: &str, upgrade_public_key: Option<String>) -> HubServer {
    start_hub_with_tls(tag, upgrade_public_key, rooster_hub::config::HubTls::default()).await
}

async fn start_hub_with_tls(
    tag: &str,
    upgrade_public_key: Option<String>,
    tls: rooster_hub::config::HubTls,
) -> HubServer {
    let dir = std::env::temp_dir().join(format!("rooster-hub-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = HubConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        data_dir: dir.clone(),
        tls,
        secret_key: Some(bcrypt::hash("hub-secret", 4).unwrap()),
        cors_allowed_origins: vec![],
        session_ttl: Some(Duration::from_secs(3600)),
        panel_dir: dir.join("no-panel"),
        auto_confirm_delay_secs: 1,
        upgrade_public_key,
        global_ban_policies: vec![rooster_hub::config::PolicyConfig {
            id: "ssh-bruteforce".into(),
            r#match: rooster_hub::config::PolicyMatch {
                plugin: "ssh-guard".into(),
                event: "ban".into(),
                severity: None,
            },
            min_nodes: Some(1),
            threshold: None,
            window: None,
            ttl: Duration::from_secs(3600),
        }],
        audit_retention: Some(Duration::from_secs(3600)),
    };

    let db = store::open(&dir.join("hub.redb")).unwrap();
    let store = store::Store::with_retention(db, cfg.audit_retention());
    let pki = rooster_hub::pki::HubPki::ensure(&dir).unwrap();
    let (events_tx, _) = tokio::sync::broadcast::channel(64);
    let state = Arc::new(HubState {
        cfg,
        store,
        pki,
        registry: Default::default(),
        policy: std::sync::Mutex::new(rooster_hub::policy::PolicyEngine::new()),
        login_gate: Default::default(),
        events_tx,
        recent: std::sync::Mutex::new(Default::default()),
    });
    let _ = state.effective_policies();

    let app = rooster_hub::api::router(state.clone()).layer(axum::Extension(
        rooster_hub::http::ConnMeta {
            // 默认 ConnMeta 取非回环地址:明文模式只对回环对等端放宽下载,
            // 这样“匿名 wasm 下载仍 401”的断言在 e2e 里仍可测。
            peer: SocketAddr::from(([192, 0, 2, 1], 40000)),
            cert_fp: None,
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    HubServer {
        base: format!("http://{addr}"),
        ws_base: format!("ws://{addr}"),
        _state: state,
        dir,
    }
}

async fn login(hub: &HubServer) -> String {
    let resp = client()
        .post(format!("{}/v0/auth/login", hub.base))
        .json(&serde_json::json!({"secret_key": "hub-secret"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    resp.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// 生成一个合法 CSR(测试须能走到 consume_token,而不是先被“无法解析 CSR”拦下)。
fn csr_pem(node: &str) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, node);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

/// 注册一个节点,返回 (ws url, client cert pem)。
async fn register(hub: &HubServer, token: &str, node: &str) -> (String, String) {
    let resp = client()
        .post(format!("{}/v0/register", hub.base))
        .json(&serde_json::json!({
            "token": token,
            "csr_pem": csr_pem(node),
            "node_id": node,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "register {node} failed");
    let body: serde_json::Value = resp.json().await.unwrap();
    (format!("{}/agent/ws", hub.ws_base), body["cert_pem"].as_str().unwrap().to_string())
}

/// 模拟节点:连接 → Hello → 循环应答(ApiRequest 回固定响应,
/// 记录收到的 GlobalBan / Ping)。
struct FakeAgent {
    node: String,
    global_bans: Arc<std::sync::Mutex<Vec<String>>>,
    passthrough_hits: Arc<std::sync::Mutex<Vec<String>>>,
}

impl FakeAgent {
    async fn run(self, url: String) {
        let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut sink, mut stream) = ws.split();
        sink.send(Message::binary(rooster_proto::encode(&Frame::Hello {
            node_id: self.node.clone(),
            version: "0.1.0".into(),
            config_hash: "h".into(),
        })))
        .await
        .unwrap();
        let mut current_seq = 0u64;
        while let Some(Ok(msg)) = stream.next().await {
            let Message::Binary(bytes) = msg else { continue };
            let frame = rooster_proto::decode(&bytes).unwrap();
            match frame {
                Frame::Ping => {
                    sink.send(Message::binary(rooster_proto::encode(&Frame::Pong)))
                        .await
                        .unwrap();
                }
                Frame::ApiRequest { id, method, path, .. } => {
                    self.passthrough_hits
                        .lock()
                        .unwrap()
                        .push(format!("{method} {path}"));
                    let resp = Frame::ApiResponse {
                        id,
                        status: 200,
                        headers: vec![("content-type".into(), "application/json".into())],
                        body: br#"{"hash":"fake","canned":true}"#.to_vec(),
                    };
                    sink.send(Message::binary(rooster_proto::encode(&resp)))
                        .await
                        .unwrap();
                }
                Frame::GlobalBan { ip, .. } => {
                    self.global_bans.lock().unwrap().push(ip);
                }
                Frame::GlobalBanSync { bans } => {
                    let mut g = self.global_bans.lock().unwrap();
                    for b in bans {
                        g.push(b.ip);
                    }
                }
                Frame::EventAck { .. } => {}
                _ => {}
            }
            current_seq += 1;
            let _ = current_seq;
        }
    }
}

/// 事件上报(独立连接语义:由同一连接内发送,这里单独发一批)。
async fn send_event(url: &str, node: &str, ip: &str) {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::binary(rooster_proto::encode(&Frame::Hello {
        node_id: node.into(),
        version: "0.1.0".into(),
        config_hash: "h".into(),
    })))
    .await
    .unwrap();
    // 先吃掉 Hub 的初始下发(GlobalBanSync / Ping)。
    tokio::time::sleep(Duration::from_millis(100)).await;
    while let Some(Ok(m)) = stream.next().await {
        if matches!(m, Message::Binary(_)) {
            let f = rooster_proto::decode(&m.into_data()).unwrap();
            if let Frame::GlobalBanSync { .. } = f {
                break;
            }
        }
    }
    sink.send(Message::binary(rooster_proto::encode(&Frame::Event {
        first_seq: 0,
        batch: vec![rooster_proto::Event::Ban {
            ip: ip.into(),
            reason: "ssh bruteforce".into(),
            plugin: "ssh-guard".into(),
            scope: "local".into(),
            ttl_secs: 3600,
        }],
    })))
    .await
    .unwrap();
    // 等 ack / 联动广播。
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// 节点热更新后的 ConfigChanged 事件必须刷新 hub 里的 config_hash,
/// 否则面板永远显示 Hello 时的旧值。
#[tokio::test]
async fn config_changed_event_refreshes_node_config_hash() {
    let hub = start_hub("ch").await;
    let state = hub._state.clone();
    state.store.insert_token("tok-hash", Duration::from_secs(60)).unwrap();
    let (url, _cert) = register(&hub, "tok-hash", "hashnode").await;

    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::binary(rooster_proto::encode(&Frame::Hello {
        node_id: "hashnode".into(),
        version: "0.1.0".into(),
        config_hash: "h-before".into(),
    })))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    sink.send(Message::binary(rooster_proto::encode(&Frame::Event {
        first_seq: 0,
        batch: vec![rooster_proto::Event::ConfigChanged {
            hash: "h-after".into(),
        }],
    })))
    .await
    .unwrap();

    let token = login(&hub).await;
    let mut seen = String::new();
    for _ in 0..50 {
        let body: serde_json::Value = client()
            .get(format!("{}/v0/nodes", hub.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        seen = body["nodes"][0]["config_hash"].as_str().unwrap_or_default().to_string();
        if seen == "h-after" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(seen, "h-after", "ConfigChanged must update the stored config_hash");

    // 回滚同样得跟随:Agent 在 ConfigRolledBack 后补发 ConfigChanged(hash
    // =回滚后的值),否则面板停在“变更时”的 hash 上,看起来像配置漂移。
    sink.send(Message::binary(rooster_proto::encode(&Frame::Event {
        first_seq: 1,
        batch: vec![
            rooster_proto::Event::ConfigRolledBack {
                reason: "apply/confirm timeout".into(),
            },
            rooster_proto::Event::ConfigChanged {
                hash: "h-before".into(),
            },
        ],
    })))
    .await
    .unwrap();
    let mut reverted = String::new();
    for _ in 0..50 {
        let body: serde_json::Value = client()
            .get(format!("{}/v0/nodes", hub.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        reverted = body["nodes"][0]["config_hash"].as_str().unwrap_or_default().to_string();
        if reverted == "h-before" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(reverted, "h-before", "ConfigRolledBack must revert the stored config_hash");
    let _ = stream.next().await;
}

#[tokio::test]
async fn three_nodes_register_connect_and_passthrough() {
    let hub = start_hub("a").await;
    let state_empty = hub._state.clone();

    // 一次性 token 只能用一次。
    state_empty.store.insert_token("tok-once", Duration::from_secs(60)).unwrap();
    assert!(state_empty.store.consume_token("tok-once").unwrap());
    assert!(!state_empty.store.consume_token("tok-once").unwrap());

    // 为 3 个节点各发一个 token 并注册。
    let mut agents = Vec::new();
    for i in 0..3 {
        let token = format!("tok-{i}");
        state_empty.store.insert_token(&token, Duration::from_secs(60)).unwrap();
        let (url, _cert) = register(&hub, &token, &format!("node-{i}")).await;
        let fa = FakeAgent {
            node: format!("node-{i}"),
            global_bans: Arc::new(std::sync::Mutex::new(vec![])),
            passthrough_hits: Arc::new(std::sync::Mutex::new(vec![])),
        };
        let url2 = url.clone();
        tokio::spawn(async move { fa.run(url2).await });
        agents.push(url);
    }
    // 用已消费过的 token + 合法 CSR + 新 node_id 再注册 → 401。
    // CSR 合法才能走到 consume_token,否则 422 会掩盖单用约束没生效。
    let resp = client()
        .post(format!("{}/v0/register", hub.base))
        .json(&serde_json::json!({"token": "tok-0", "csr_pem": csr_pem("evil"), "node_id": "evil"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "reused token must be rejected");
    let _ = agents;

    let token = login(&hub).await;
    let client = client();

    // 等三台在线。
    let mut online = 0;
    for _ in 0..50 {
        let resp = client
            .get(format!("{}/v0/nodes", hub.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        online = body["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["online"].as_bool().unwrap_or(false))
            .count();
        if online == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(online, 3, "all three nodes must be online");

    // 透传:面板 → hub → agent → 回。
    let resp = client
        .get(format!("{}/v0/nodes/node-1/management/config", hub.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["canned"].as_bool(), Some(true));

    // 离线节点 → 503。
    let resp = client
        .get(format!("{}/v0/nodes/ghost/management/config", hub.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    // 无会话 → 401。
    let resp = client.get(format!("{}/v0/nodes", hub.base)).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn manual_global_ban_broadcasts_and_policy_triggers() {
    let hub = start_hub("b").await;
    let state = hub._state.clone();
    let token = login(&hub).await;
    let client = client();

    let mut ban_recvs: Vec<Arc<std::sync::Mutex<Vec<String>>>> = Vec::new();
    for i in 0..2 {
        let t = format!("btok-{i}");
        state.store.insert_token(&t, Duration::from_secs(60)).unwrap();
        let (url, _) = register(&hub, &t, &format!("web-{i}")).await;
        let fa = FakeAgent {
            node: format!("web-{i}"),
            global_bans: Arc::new(std::sync::Mutex::new(vec![])),
            passthrough_hits: Arc::new(std::sync::Mutex::new(vec![])),
        };
        let recv = fa.global_bans.clone();
        ban_recvs.push(recv);
        tokio::spawn(async move { fa.run(url).await });
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 手动全局封禁 → 广播。
    let resp = client
        .post(format!("{}/v0/global-bans", hub.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({"ip": "203.0.113.99", "ttl_secs": 600, "reason": "test"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    tokio::time::sleep(Duration::from_millis(300)).await;
    for recv in &ban_recvs {
        let g = recv.lock().unwrap();
        assert!(
            g.contains(&"203.0.113.99".to_string()),
            "manual ban must broadcast, got {g:?}"
        );
    }

    // 联动策略:min-nodes=1,一条 ssh-guard ban 事件即触发。
    let t = "etok";
    state.store.insert_token(t, Duration::from_secs(60)).unwrap();
    let (url, _) = register(&hub, t, "reporter").await;
    send_event(&url, "reporter", "198.51.100.7").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bans: Vec<String> = state
        .store
        .list_global_bans()
        .unwrap()
        .into_iter()
        .map(|b| b.ip)
        .collect();
    assert!(
        bans.contains(&"198.51.100.7".to_string()),
        "policy must trigger global ban, got {bans:?}"
    );
    // 审计里有记录(语义扩展:联动操作也入审计)。
    let audit = state.store.list_audit(10).unwrap();
    assert!(
        audit.iter().any(|a| a.path.contains("198.51.100.7")),
        "policy ban must be audited"
    );
}

/// 一次性 token 不能拿去找回一个已存在的节点:那等于把该节点的 mTLS 身份
/// (证书指纹 + 面板透传流量)交给持 token 的任何外人。
#[tokio::test]
async fn registration_token_cannot_hijack_existing_node() {
    let hub = start_hub("hijack").await;
    let st = hub._state.clone();
    st.store.insert_token("tok-new", Duration::from_secs(60)).unwrap();
    register(&hub, "tok-new", "node-0").await;
    let before = st.store.get_node("node-0").unwrap().unwrap().cert_fp.clone();

    st.store.insert_token("tok-evil", Duration::from_secs(60)).unwrap();
    let resp = client()
        .post(format!("{}/v0/register", hub.base))
        .json(&serde_json::json!({
            "token": "tok-evil",
            "csr_pem": csr_pem("node-0"),
            "node_id": "node-0",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "existing node id must not be re-registered");
    assert_eq!(
        st.store.get_node("node-0").unwrap().unwrap().cert_fp,
        before,
        "rejected registration must leave the node's certificate fingerprint alone"
    );
    // 拒绝发生在消费之前:token 未被烧掉。
    assert!(st.store.consume_token("tok-evil").unwrap());
}

/// 安装脚本的下载必须能匿名完成(此前带鉴权 → 401 → 新机器装不起来),
/// 而 WASM 仓库/版本包仍不得匿名开放。
#[tokio::test]
async fn install_bootstrap_download_is_anonymous() {
    let hub = start_hub("bootstrap").await;
    let client = client();

    // 同架构兜底:hub 自身可执行文件。
    let resp = client
        .get(format!("{}/v0/downloads/rooster", hub.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "install.sh must fetch the binary without a session");

    // 未上传的架构包 → 404(而不是 401)。
    let resp = client
        .get(format!("{}/v0/downloads/rooster-x86_64", hub.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // 其余下载仍要会话或签名 URL。
    let resp = client
        .get(format!("{}/v0/downloads/wasm/header_check.wasm", hub.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 未配 upgrade-public-key 时不对外暴露公钥。
    let resp = client
        .get(format!("{}/v0/pubkey.pem", hub.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// 自签/私有 CA 的 hub 必须把服务器信任锚公开到 /v0/ca.crt:Agent 侧
/// rustls 只认 webpki 根 ∪ hub.ca,拿不到锚就是 UnknownIssuer,注册请求
/// 根本发不出去(面板永远看不到节点)。证书公钥可公开,不能当凭据。
#[tokio::test]
async fn server_ca_is_published_for_agent_trust_anchor() {
    let client = client();

    // 未配 tls.ca 不能凭空编一个锈出来。
    let hub = start_hub("ca-none").await;
    let resp = client
        .get(format!("{}/v0/ca.crt", hub.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "无 tls.ca 配置时不得暴露锈");

    let dir = std::env::temp_dir().join(format!("rooster-ca-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.crt");
    std::fs::write(
        &ca,
        "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let hub = start_hub_with_tls(
        "ca-set",
        None,
        rooster_hub::config::HubTls {
            ca: Some(ca.clone()),
            ..Default::default()
        },
    )
    .await;
    let resp = client
        .get(format!("{}/v0/ca.crt", hub.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "配了 tls.ca 就必须发出锈");
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/x-pem-file")
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("BEGIN CERTIFICATE"), "锈必须是 PEM: {body}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 续签链路:已认证连接上的 RenewCert 必须换回新证书
/// (Agent 侧 send_hub_frame 现已接线到当前会话)。
#[tokio::test]
async fn agent_can_renew_its_certificate_over_ws() {
    let hub = start_hub("renew").await;
    let st = hub._state.clone();
    st.store.insert_token("tok-r", Duration::from_secs(60)).unwrap();
    let (url, _) = register(&hub, "tok-r", "node-r").await;

    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::binary(rooster_proto::encode(&Frame::Hello {
        node_id: "node-r".into(),
        version: "0.1.0".into(),
        config_hash: "h".into(),
    })))
    .await
    .unwrap();
    sink.send(Message::binary(rooster_proto::encode(&Frame::RenewCert {
        csr_pem: csr_pem("node-r"),
    })))
    .await
    .unwrap();

    let cert = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(msg)) = stream.next().await {
            if let Message::Binary(bytes) = msg {
                if let Frame::Renewed { cert_pem } = rooster_proto::decode(&bytes).unwrap() {
                    return cert_pem;
                }
            }
        }
        String::new()
    })
    .await
    .expect("hub must answer RenewCert with Renewed");
    assert!(
        cert.contains("BEGIN CERTIFICATE"),
        "renewed payload is not a certificate: {cert}"
    );
}

/// 安装链路的验签环节:脚本匿名取回 二进制 + 裸 Ed25519 签名 + SPKI 公钥,
/// 交给真 openssl 校验;篡改一个字节必须验不过。
#[tokio::test]
async fn install_artifacts_verify_with_openssl() {
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use std::process::{Command, Stdio};

    if Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        eprintln!("skipping: openssl unavailable");
        return;
    }

    let sk = SigningKey::generate(&mut rand::rng());
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_cfg = format!("ed25519:{}", b64.encode(sk.verifying_key().to_bytes()));
    let hub = start_hub_with_key("openssl", Some(key_cfg)).await;

    // 上传:hub 侧先验签;制品命名 rooster-<ver>-<arch>。
    let binary = b"fake-rooster-binary".to_vec();
    let sig = b64.encode(sk.sign(&binary).to_bytes());
    let resp = client()
        .post(format!("{}/v0/upgrades", hub.base))
        .bearer_auth(login(&hub).await)
        .header("x-rooster-version", "0.1.0-x86_64")
        .header("x-rooster-signature", &sig)
        .body(binary.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "upload rejected: {:?}", resp.text().await.ok());

    // install.sh 的三个匿名请求:路径只带架构(rooster-x86_64),由 hub 解析
    // 到该架构最新的已签名发布包(此处入库名是 0.1.0-x86_64)。
    let client = client();
    let get = |url: String| {
        let client = client.clone();
        async move {
            let r = client.get(&url).send().await.unwrap();
            assert_eq!(r.status(), 200, "anonymous download must work: {url}");
            r.bytes().await.unwrap().to_vec()
        }
    };
    let dir = std::env::temp_dir().join(format!("rooster-install-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = get(format!("{}/v0/downloads/rooster-x86_64", hub.base)).await;
    let sig_raw = get(format!("{}/v0/downloads/rooster-x86_64.sig", hub.base)).await;
    let pem = get(format!("{}/v0/pubkey.pem", hub.base)).await;
    assert_eq!(bin, binary, "downloaded bytes must be the uploaded package");
    let put = |name: &str, bytes: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let (bin_p, sig_p, pem_p) = (put("rooster.new", &bin), put("rooster.sig", &sig_raw), put("rooster.pub", &pem));

    let verify = |file: &std::path::Path| {
        Command::new("openssl")
            .arg("pkeyutl")
            .args(["-verify", "-pubin"])
            .arg("-inkey")
            .arg(&pem_p)
            .arg("-rawin")
            .arg("-in")
            .arg(file)
            .arg("-sigfile")
            .arg(&sig_p)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(verify(&bin_p), "openssl must accept the hub's SPKI PEM + raw signature");

    let mut tampered = bin.clone();
    tampered[0] ^= 0xff;
    assert!(!verify(&put("rooster.bad", &tampered)), "openssl must reject a modified binary");
    let _ = std::fs::remove_dir_all(&dir);
}

/// agent 二进制链接了 wasmtime,体积远超 axum 默认 2MiB 请求体上限;
/// 上传路由必须单独放宽,否则真实发布包一律 413。
#[tokio::test]
async fn upgrade_upload_accepts_multi_megabyte_package() {
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::generate(&mut rand::rng());
    let b64 = base64::engine::general_purpose::STANDARD;
    let hub = start_hub_with_key(
        "bigupload",
        Some(format!("ed25519:{}", b64.encode(sk.verifying_key().to_bytes()))),
    )
    .await;

    let binary = vec![0u8; 4 * 1024 * 1024 + 1024];
    let sig = b64.encode(sk.sign(&binary).to_bytes());
    let resp = client()
        .post(format!("{}/v0/upgrades", hub.base))
        .bearer_auth(login(&hub).await)
        .header("x-rooster-version", "0.1.0-x86_64")
        .header("x-rooster-signature", &sig)
        .body(binary.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "4MiB package: {:?}", resp.text().await.ok());
    assert_eq!(
        hub._state.store.get_upgrade("0.1.0-x86_64").unwrap().map(|b| b.len()),
        Some(binary.len()),
    );

    // 放宽只在上传路由:其他路由仍受默认上限约束(未鉴权也不能灌大 body)。
    let resp = client()
        .post(format!("{}/v0/auth/login", hub.base))
        .header("content-type", "application/json")
        .body(vec![b'x'; 4 * 1024 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413, "non-upload routes must keep the default body limit");
}

/// 用指定 ConnMeta 起一个共用同一 HubState 的服务实例(mTLS 下载分支
/// 的连接级指纹来自这里)。
async fn serve_with_meta(
    state: Arc<HubState>,
    meta: rooster_hub::http::ConnMeta,
) -> String {
    let app = rooster_hub::api::router(state).layer(axum::Extension(meta));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://{addr}")
}

/// DELETE 必须杀死在线会话(旧 socket 上的事件批不再
/// 产生全局封禁)、真的删除节点行(id 可重注册),而旧证书指纹留在
/// 吊销表中换不回身份。
#[tokio::test]
async fn revoke_kills_session_and_frees_reregistration() {
    let hub = start_hub("revoke").await;
    let st = hub._state.clone();
    let token = login(&hub).await;
    let client = client();

    st.store.insert_token("tok-v1", Duration::from_secs(60)).unwrap();
    let (url, _cert) = register(&hub, "tok-v1", "victim").await;
    let old_fp = st.store.get_node("victim").unwrap().unwrap().cert_fp.clone();

    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::binary(rooster_proto::encode(&Frame::Hello {
        node_id: "victim".into(),
        version: "0.1.0".into(),
        config_hash: "h".into(),
    })))
    .await
    .unwrap();
    // 等初始 GlobalBanSync 发完。
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(m)) = stream.next().await {
            if let Message::Binary(b) = m {
                if matches!(rooster_proto::decode(&b).unwrap(), Frame::GlobalBanSync { .. }) {
                    break;
                }
            }
        }
    })
    .await
    .expect("initial GlobalBanSync");

    // 吊销前:事件批有效并触发全局封禁(min-nodes=1)。
    sink.send(Message::binary(rooster_proto::encode(&Frame::Event {
        first_seq: 0,
        batch: vec![rooster_proto::Event::Ban {
            ip: "198.51.100.77".into(),
            reason: "ssh bruteforce".into(),
            plugin: "ssh-guard".into(),
            scope: "local".into(),
            ttl_secs: 3600,
        }],
    })))
    .await
    .unwrap();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if st.store.list_global_bans().unwrap().iter().any(|b| b.ip == "198.51.100.77") {
            break;
        }
    }
    assert!(
        st.store.list_global_bans().unwrap().iter().any(|b| b.ip == "198.51.100.77"),
        "pre-revoke event batch must trigger the global ban"
    );

    // DELETE:行被删 + 证书进吊销表 + 在线会话被挂断。
    let resp = client
        .delete(format!("{}/v0/nodes/victim", hub.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(st.store.get_node("victim").unwrap().is_none(), "row must be deleted");
    assert!(st.store.is_revoked(&old_fp).unwrap(), "old cert fp must stay blacklisted");

    // 旧 socket 被服务端关闭。
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(_)) = stream.next().await {}
    })
    .await;
    assert!(closed.is_ok(), "revoked socket must be closed by the hub");
    // 已关闭的 socket 上再塞事件批也不能产生新的全局封禁。
    let _ = sink
        .send(Message::binary(rooster_proto::encode(&Frame::Event {
            first_seq: 1,
            batch: vec![rooster_proto::Event::Ban {
                ip: "198.51.100.88".into(),
                reason: "ssh bruteforce".into(),
                plugin: "ssh-guard".into(),
                scope: "local".into(),
                ttl_secs: 3600,
            }],
        })))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !st.store.list_global_bans().unwrap().iter().any(|b| b.ip == "198.51.100.88"),
        "events on the revoked socket must not produce a global ban"
    );

    // 节点 id 立即可重注册(新 token + 新 CSR),新指纹不同且未吊销。
    st.store.insert_token("tok-v2", Duration::from_secs(60)).unwrap();
    register(&hub, "tok-v2", "victim").await;
    let new_fp = st.store.get_node("victim").unwrap().unwrap().cert_fp;
    assert_ne!(new_fp, old_fp);
    assert!(!st.store.is_revoked(&new_fp).unwrap());

    // 审计仍保留这次面板删除。
    assert!(
        st.store.list_audit(20).unwrap().iter().any(|a| a.path == "/v0/nodes/victim"),
        "delete must stay audited"
    );
}

/// C11:hub→agent 的制品分发走 mTLS 节点身份——已注册未吊销节点的证书
/// 指纹可以 GET /v0/downloads/wasm/*;未知/已吊销指纹、明文非回环对端
/// 仍被拒;明文回环是开发模式的等价放宽。
#[tokio::test]
async fn mtls_node_identity_authorizes_wasm_download() {
    let hub = start_hub("mtls-dl").await;
    let st = hub._state.clone();
    let token = login(&hub).await;

    st.store.insert_token("tok-m", Duration::from_secs(60)).unwrap();
    register(&hub, "tok-m", "node-m").await;
    let fp = st.store.get_node("node-m").unwrap().unwrap().cert_fp;

    // 面板会话上传一个 wasm 制品。
    let up = client()
        .post(format!("{}/v0/wasm-plugins", hub.base))
        .bearer_auth(&token)
        .header("x-rooster-name", "header_check.wasm")
        .body(b"wasm-bytes".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), 200, "upload: {:?}", up.text().await.ok());

    let meta_url = |peer: [u8; 4], port: u16, cert_fp: Option<String>| {
        let st = st.clone();
        async move {
            serve_with_meta(
                st,
                rooster_hub::http::ConnMeta {
                    peer: SocketAddr::from((peer, port)),
                    cert_fp,
                },
            )
            .await
        }
    };

    // (a) 注册节点的指纹 → 200,内容一致。
    let base = meta_url([127, 0, 0, 1], 0, Some(fp.clone())).await;
    let resp = client()
        .get(format!("{base}/v0/downloads/wasm/header_check.wasm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "registered node fp must download the artifact");
    assert_eq!(resp.bytes().await.unwrap(), b"wasm-bytes"[..]);

    // (b) 未知指纹 → 401;已吊销指纹(面板删除节点)→ 401。
    let base = meta_url([127, 0, 0, 1], 0, Some("deadbeef".into())).await;
    let resp = client()
        .get(format!("{base}/v0/downloads/wasm/header_check.wasm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "unknown fp must be rejected");

    let del = client()
        .delete(format!("{}/v0/nodes/node-m", hub.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 200);
    let base = meta_url([127, 0, 0, 1], 0, Some(fp.clone())).await;
    let resp = client()
        .get(format!("{base}/v0/downloads/wasm/header_check.wasm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked fp must be rejected");

    // (c) 明文模式非回环对端(无证书)→ 401;面板会话仍可用(既有分支)。
    let base = meta_url([192, 0, 2, 9], 5000, None).await;
    let resp = client()
        .get(format!("{base}/v0/downloads/wasm/header_check.wasm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "plain non-loopback peer must be rejected");
    let resp = client()
        .get(format!("{base}/v0/downloads/wasm/header_check.wasm"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "panel session branch must keep working");

    // (d) 明文模式回环对端(开发模式等价放宽)→ 200。
    let base = meta_url([127, 0, 0, 1], 0, None).await;
    let resp = client()
        .get(format!("{base}/v0/downloads/wasm/header_check.wasm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "plain loopback peer is the dev-mode allowance");
}
