//! Agent 半边透传测试:hubclient 的 ApiRequest 在进程内
//! 直接走无鉴权管理路由 —— 真实 AgentState + 真实配置文件。

use rooster_agent::state::AgentState;
use rooster_agent::management;
use rooster_config::{hash_content, ConfigWriter, WatcherState};
use std::sync::Arc;

const SECRET: &str = "agent-secret";

async fn build_state(tag: &str) -> (Arc<AgentState>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("rooster-trusted-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");
    let raw = format!(
        r#"local:
  agent:
    node-name: {tag}
    data-dir: {}
  management:
    listen: 127.0.0.1:19871
    secret-key: "{SECRET}"
"#,
        dir.to_str().unwrap()
    );
    std::fs::write(&config_path, &raw).unwrap();
    let (_file, effective) = rooster_config::parse_and_validate(&raw).unwrap();
    let writer = ConfigWriter::new(&config_path, &dir);
    let watcher = Arc::new(WatcherState::new(hash_content(&raw)));
    let auth = management::auth::AuthGate::new(String::new());
    let state = Arc::new(AgentState::new(
        config_path.clone(),
        writer,
        watcher,
        effective,
        auth,
    ));
    (state, dir)
}

#[tokio::test]
async fn readiness_requires_a_live_hub_connection() {
    let (state, _dir) = build_state("ready").await;
    let (status, _, _) = management::serve_trusted(&state, "GET", "/v0/management/readyz", &[], b"").await;
    assert_eq!(status, 503);
    state.hub_connected.send_replace(true);
    let (status, _, body) = management::serve_trusted(&state, "GET", "/v0/management/readyz", &[], b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"ok");
    state.hub_connected.send_replace(false);
    let (status, _, _) = management::serve_trusted(&state, "GET", "/v0/management/readyz", &[], b"").await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn trusted_requests_bypass_auth_and_hit_real_routes() {
    let (state, _dir) = build_state("read").await;

    // GET /config:返回真实 hash 与 raw。
    let (status, headers, body) = management::serve_trusted(
        &state,
        "GET",
        "/v0/management/config",
        &[],
        b"",
    )
    .await;
    assert_eq!(status, 200);
    assert!(headers
        .iter()
        .any(|(k, v)| k == "content-type" && v.contains("json")));
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["hash"].as_str().is_some_and(|h| !h.is_empty()));
    assert!(body["raw"].as_str().is_some_and(|r| r.contains("node-name: read")));

    // POST /apply/confirm 无 token → 404(路由真实生效,不是桩)。
    let (status, _, _) = management::serve_trusted(
        &state,
        "POST",
        "/v0/management/apply/confirm",
        &[("content-type".into(), "application/json".into())],
        br#"{"token":"nope"}"#,
    )
    .await;
    assert_eq!(status, 404);

    // /layers。
    let (status, _, body) = management::serve_trusted(
        &state,
        "GET",
        "/v0/management/layers",
        &[],
        b"",
    )
    .await;
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body.get("local").is_some());
    assert!(body.get("effective").is_some());
}

#[tokio::test]
async fn template_apply_writes_managed_section() {
    let (state, dir) = build_state("tpl").await;
    let (ok, err, confirm) = rooster_agent::hubclient::apply_template(
        &state,
        "plugins:\n  ssh-guard:\n    enabled: true\n    max-retry: 9\n",
    );
    assert!(ok, "apply failed: {err:?}");
    // ssh-guard 属确认类变更(决定 nftables meter 规则)。
    assert!(confirm.is_some(), "ssh-guard change must require confirm");

    let raw = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    assert!(raw.contains("managed:"));
    assert!(raw.contains("max-retry: 9"));
    // local 层未动。
    assert!(raw.contains("node-name: tpl"));

    // 生效配置已合并。
    let eff = state.effective();
    assert_eq!(eff.plugins.ssh_guard.max_retry, 9);
}

/// 续签帧必须有活的发送通道。旧实现里 `hub_frame_tx` 从未被注入,
/// `send_hub_frame` 永远 Err,而 renewal_loop 却已经把新私钥覆写进 agent.key
/// —— 证书没续、私钥先毁。这里锁住通道的登记/注销语义。
#[tokio::test]
async fn hub_frame_channel_follows_the_live_session() {
    use rooster_proto::Frame;
    let (state, _dir) = build_state("renew").await;
    let req = || state.send_hub_frame(Frame::RenewCert { csr_pem: "csr".into() });
    assert!(req().is_err(), "未连接时不该有发送端");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let gen = state.set_hub_frame(&tx);
    assert!(req().is_ok());
    assert!(matches!(rx.recv().await, Some(Frame::RenewCert { .. })));

    // 新会话接管后,旧会话退出不得注销新发送端。
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
    let gen2 = state.set_hub_frame(&tx2);
    state.clear_hub_frame(gen);
    assert!(req().is_ok());
    assert!(matches!(rx2.recv().await, Some(Frame::RenewCert { .. })));
    state.clear_hub_frame(gen2);
    assert!(req().is_err());
}

// ---------------------------------------------------------------------------
// A1/A2/A6/A7/A8:注册与 Hello 身份同源、信任库不被注册 CA 顶替、
// push_event 立即到达 hub、outbox seq 从 1 起单调、GlobalUnban 认 scope。

use rooster_agent::outbox::Outbox;
use rooster_nft::{BanEntry, BanManager, BanScope, NftError};
use rooster_proto::Frame;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

async fn build_state_with_hub(tag: &str, hub_url: &str) -> (Arc<AgentState>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "rooster-trusted-hub-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");
    let raw = format!(
        r#"local:
  agent:
    node-name: {tag}
    data-dir: {}
  management:
    listen: 127.0.0.1:19872
    secret-key: "{SECRET}"
  hub:
    url: {hub_url}
    token: one-shot-token
"#,
        dir.to_str().unwrap()
    );
    std::fs::write(&config_path, &raw).unwrap();
    let (_file, effective) = rooster_config::parse_and_validate(&raw).unwrap();
    let writer = ConfigWriter::new(&config_path, &dir);
    let watcher = Arc::new(WatcherState::new(hash_content(&raw)));
    let auth = management::auth::AuthGate::new(String::new());
    let state = Arc::new(AgentState::new(
        config_path.clone(),
        writer,
        watcher,
        effective,
        auth,
    ));
    (state, dir)
}

/// 读一条 HTTP/1.1 请求(头 + Content-Length 正文)。
async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before sending full request");
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(header_end) = text.find("\r\n\r\n") {
            let len: usize = text
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            if buf.len() >= header_end + 4 + len {
                return text;
            }
        }
    }
}

async fn write_http_response(stream: &mut TcpStream, body: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await.unwrap();
}

/// 最小 WebSocket 服务端握手(测试环境的 tokio-tungstenite 没编 handshake 特性)。
async fn ws_accept(mut stream: TcpStream) -> WebSocketStream<TcpStream> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before websocket handshake");
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let key = req
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("sec-websocket-key").then(|| v.trim().to_string())
        })
        .expect("missing sec-websocket-key");
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    stream.write_all(resp.as_bytes()).await.unwrap();
    WebSocketStream::from_raw_socket(stream, Role::Server, None).await
}

async fn next_frame(ws: &mut WebSocketStream<TcpStream>) -> Frame {
    use futures_util::StreamExt;
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timeout waiting for frame")
            .expect("stream ended")
            .expect("ws error");
        match msg {
            tokio_tungstenite::tungstenite::Message::Binary(b) => {
                // 心跳 Ping 随时可能插入(心跳任务首 tick 立即触发),
                // 与事件补报在 socket 上无顺序保证,跳过控制帧。
                match rooster_proto::decode(&b).unwrap() {
                    Frame::Ping | Frame::Pong => continue,
                    frame => return frame,
                }
            }
            other => panic!("expected binary frame, got {other:?}"),
        }
    }
}

/// A1:注册(register body node_id)与 Hello node_id 必须同源且等于配置的
/// agent.node-name(而不是 /etc/hostname),否则 hub 按 node_id 反查的
/// 证书指纹与 mTLS 身份对不上。同时覆盖:A2 注册 CA 落独立文件、管理员
/// ca.crt 不被覆盖;A6/A7 已连接状态下 push_event 立即上报、seq 从 1 起。
#[tokio::test]
async fn register_and_hello_share_identity_and_events_flow_without_ack() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (state, dir) = build_state_with_hub("named-by-installer", &format!("ws://{addr}")).await;

    // 管理员预装的服务器 CA:注册绝不能覆盖它(A2)。
    let pki = dir.join("pki");
    std::fs::create_dir_all(&pki).unwrap();
    let admin_ca = pki.join("ca.crt");
    std::fs::write(&admin_ca, "admin-ca-sentinel").unwrap();

    let outbox = Outbox::open(&dir.join("hub-outbox.redb"), 100_000).unwrap();
    *state.hub_outbox.lock().unwrap() = Some(Arc::new(outbox));

    // 连接 1:注册 POST。ensure_registered 必须与 accept 并发 —— 单线程测试
    // runtime 下先 await accept 再发请求会自锁。
    let eff = state.effective();
    let reg = {
        let eff = eff.clone();
        let dir = dir.clone();
        tokio::spawn(async move { rooster_agent::hubclient::ensure_registered(&eff, &dir).await })
    };
    let (mut rest, _) = listener.accept().await.unwrap();
    let req = read_http_request(&mut rest).await;
    assert!(req.starts_with("POST /v0/register"), "unexpected request: {req}");
    let body_start = req.find("\r\n\r\n").unwrap() + 4;
    let reg_body: serde_json::Value = serde_json::from_str(&req[body_start..]).unwrap();
    let reg_node = reg_body["node_id"].as_str().unwrap().to_string();
    write_http_response(
        &mut rest,
        &serde_json::json!({
            "cert_pem": "-----BEGIN CERTIFICATE-----\nagent\n-----END CERTIFICATE-----\n",
            "ca_pem": "registration-ca-pem",
        })
        .to_string(),
    )
    .await;
    drop(rest);
    reg.await.unwrap().unwrap();

    assert_eq!(reg_node, "named-by-installer", "register node_id 必须来自 agent.node-name");
    // A2:注册 CA 写独立文件,管理员服务器 CA 原样保留。
    assert_eq!(std::fs::read_to_string(pki.join("hub-ca.crt")).unwrap(), "registration-ca-pem");
    assert_eq!(std::fs::read_to_string(&admin_ca).unwrap(), "admin-ca-sentinel");

    // 连接 2:WS。注册与 Hello 必须报同一个 node_id。
    let hub = eff.hub.clone().unwrap();
    let cs = {
        let state = state.clone();
        let dir = dir.clone();
        tokio::spawn(async move {
            rooster_agent::hubclient::connect_and_serve(&state, &hub, &dir).await
        })
    };
    let (stream, _) = listener.accept().await.unwrap();
    let mut ws = ws_accept(stream).await;
    match next_frame(&mut ws).await {
        Frame::Hello { node_id, .. } => assert_eq!(node_id, reg_node, "Hello node_id 必须与注册一致"),
        other => panic!("expected Hello, got {other:?}"),
    }

    assert!(!*state.hub_connected.borrow(), "Hello alone does not confirm hub acceptance");
    {
        use futures_util::SinkExt as _;
        ws.send(tokio_tungstenite::tungstenite::Message::binary(rooster_proto::encode(&Frame::Pong))).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while !*state.hub_connected.borrow() {
            tokio::task::yield_now().await;
        }
    }).await.expect("readiness must update without a watch subscriber");

    // A6/A7:已连接的 agent push 一个事件,不等 ack / 不重连就应到达 hub,
    // 且首条事件 seq = 1(初始游标 0 → pending(0) 恰好包含它)。
    state.push_event(rooster_proto::Event::Ban {
        ip: "203.0.113.7".into(),
        reason: "integration".into(),
        plugin: "ssh-guard".into(),
        scope: "local".into(),
        ttl_secs: 60,
        country: None,
    });
    match next_frame(&mut ws).await {
        Frame::Event { first_seq, batch } => {
            assert_eq!(first_seq, 1, "seq 必须从 1 起");
            assert_eq!(batch.len(), 1);
            assert!(matches!(batch[0], rooster_proto::Event::Ban { ref ip, .. } if ip == "203.0.113.7"));
        }
        other => panic!("expected Event, got {other:?}"),
    }
    let _ = ws.close(None).await;
    drop(ws);
    let _ = cs.await;
    assert!(!*state.hub_connected.borrow(), "closed connections must clear readiness");
}

/// A8:GlobalUnban 只解 scope=Global 的行;本地插件的行和无行不动。
struct FakeBans {
    rows: std::sync::Mutex<Vec<BanEntry>>,
    removed: std::sync::Mutex<Vec<String>>,
}

impl BanManager for FakeBans {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError> {
        self.rows.lock().unwrap().push(entry.clone());
        Ok(())
    }
    fn remove_ban(&self, ip: &str) -> Result<(), NftError> {
        self.removed.lock().unwrap().push(ip.to_string());
        self.rows.lock().unwrap().retain(|e| e.ip != ip);
        Ok(())
    }
    fn list_bans(&self) -> Result<Vec<BanEntry>, NftError> {
        Ok(self.rows.lock().unwrap().clone())
    }
    fn set_allowlist(&self, _nets: &[ipnet::IpNet]) -> Result<(), NftError> {
        Ok(())
    }
    fn set_ssh_limit(&self, _port: u16, _rate: &str, _burst: u32) -> Result<(), NftError> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn global_unban_only_lifts_global_scope_rows() {
    let (state, _dir) = build_state("unban").await;
    let fake = Arc::new(FakeBans {
        rows: std::sync::Mutex::new(vec![
            BanEntry {
                ip: "10.0.0.1".into(),
                ttl: Duration::from_secs(60),
                reason: "local: brute".into(),
                plugin: "ssh-guard".into(),
                node: String::new(),
                scope: BanScope::Local,
                started_at: None,
                expires_at: None,
            },
            BanEntry {
                ip: "10.0.0.2".into(),
                ttl: Duration::from_secs(60),
                reason: "global: botnet".into(),
                plugin: "hub".into(),
                node: "peer-1".into(),
                scope: BanScope::Global,
                started_at: None,
                expires_at: None,
            },
        ]),
        removed: std::sync::Mutex::new(Vec::new()),
    });
    *state.bans.write().unwrap() = Some(fake.clone());

    // 本地插件的行:不动。
    rooster_agent::hubclient::apply_global_unban(&state, "10.0.0.1");
    assert!(!fake.removed.lock().unwrap().contains(&"10.0.0.1".to_string()));
    assert!(
        fake.rows.lock().unwrap().iter().any(|e| e.ip == "10.0.0.1"),
        "本地封禁必须保留"
    );

    // 无行:也不调 remove_ban。
    rooster_agent::hubclient::apply_global_unban(&state, "10.0.0.99");
    assert!(!fake.removed.lock().unwrap().contains(&"10.0.0.99".to_string()));

    // 全局行:行为不变,正常解除。
    rooster_agent::hubclient::apply_global_unban(&state, "10.0.0.2");
    assert_eq!(*fake.removed.lock().unwrap(), vec!["10.0.0.2".to_string()]);
    assert!(!fake.rows.lock().unwrap().iter().any(|e| e.ip == "10.0.0.2"));
}
