//! 接线验证:封禁 API(/bans)、白名单写入(/allowlist)、统计(/stats)、
//! 白名单拒封、nft 不可用时 503 降级。

use rooster_agent::bans;
use rooster_agent::management;
use rooster_agent::management::auth::AuthGate;
use rooster_agent::state::AgentState;
use rooster_config::{hash_content, ConfigWriter, WatcherState};
use rooster_nft::{BanEntry, BanManager, BanScope, NftError};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const SECRET: &str = "it-password";

const BASE_CONFIG: &str = r#"# rooster agent configuration
local:
  agent:
    node-name: it-node
    data-dir: DATA_DIR
  management:
    listen: 127.0.0.1:9870
    secret-key: "SECRET"
  security:
    admin-allowlist: [10.0.0.0/8]
    apply-confirm-timeout: 1h
  forwards: []
"#;

/// 内存版 BanManager:记录封禁、拒绝名单、allowlist 与 ssh 限速调用。
#[derive(Default)]
struct MockBan {
    entries: Mutex<Vec<BanEntry>>,
    refused: Mutex<Vec<String>>,
    allowlist: Mutex<Vec<ipnet::IpNet>>,
    ssh_limit: Mutex<Option<(u16, String, u32)>>,
}

impl MockBan {
    fn refuse(&self, ip: &str) {
        self.refused.lock().unwrap().push(ip.to_string());
    }
    fn find(&self, ip: &str) -> Option<BanEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.ip == ip)
            .cloned()
    }
}

impl BanManager for MockBan {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError> {
        if self.refused.lock().unwrap().iter().any(|r| r == &entry.ip) {
            return Err(NftError::Refused(format!(
                "ip {} is allowlisted, refusing ban",
                entry.ip
            )));
        }
        self.entries.lock().unwrap().push(entry.clone());
        Ok(())
    }
    fn remove_ban(&self, ip: &str) -> Result<(), NftError> {
        self.entries.lock().unwrap().retain(|e| e.ip != ip);
        Ok(())
    }
    fn list_bans(&self) -> Result<Vec<BanEntry>, NftError> {
        Ok(self.entries.lock().unwrap().clone())
    }
    fn set_allowlist(&self, nets: &[ipnet::IpNet]) -> Result<(), NftError> {
        *self.allowlist.lock().unwrap() = nets.to_vec();
        Ok(())
    }
    fn set_ssh_limit(&self, port: u16, rate: &str, burst: u32) -> Result<(), NftError> {
        *self.ssh_limit.lock().unwrap() = Some((port, rate.to_string(), burst));
        Ok(())
    }
}

struct TestServer {
    base: String,
    #[allow(dead_code)]
    dir: PathBuf,
    config_path: PathBuf,
    state: Arc<AgentState>,
    mock: Arc<MockBan>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start(tag: &str, with_mock: bool) -> TestServer {
    let dir = std::env::temp_dir().join(format!("rooster-bans-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");
    let raw = BASE_CONFIG
        .replace("DATA_DIR", dir.to_str().unwrap())
        .replace("SECRET", SECRET);
    std::fs::write(&config_path, &raw).unwrap();

    let (_file, effective) = rooster_config::parse_and_validate(&raw).unwrap();
    let writer = ConfigWriter::new(&config_path, &dir);
    let watcher = Arc::new(WatcherState::new(hash_content(&raw)));
    let auth = AuthGate::new(bcrypt::hash(SECRET, 4).unwrap());
    let state = Arc::new(AgentState::new(
        config_path.clone(),
        writer,
        watcher,
        effective,
        auth,
    ));
    let mock = Arc::new(MockBan::default());
    if with_mock {
        *state.bans.write().unwrap() = Some(mock.clone());
    }
    // 子任务事件通道(生产环境由 run() 创建)
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    *state.events_tx.lock().unwrap() = Some(events_tx);
    let drain_state = state.clone();
    tokio::spawn(async move {
        while let Some(e) = events_rx.recv().await {
            drain_state.push_event(e);
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_state = state.clone();
    tokio::spawn(async move {
        // auth 中间件提取 ConnectInfo,必须用 with_connect_info 装配
        let app = management::router(serve_state)
            .into_make_service_with_connect_info::<SocketAddr>();
        let _ = axum::serve(listener, app).await;
    });

    TestServer {
        base: format!("http://{addr}"),
        dir,
        config_path,
        state,
        mock,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

async fn authed_get(srv: &TestServer, path: &str) -> reqwest::Response {
    client()
        .get(format!("{}{path}", srv.base))
        .header("authorization", format!("Bearer {SECRET}"))
        .send()
        .await
        .unwrap()
}

async fn authed_req(
    srv: &TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> reqwest::Response {
    let mut req = client()
        .request(method, format!("{}{path}", srv.base))
        .header("authorization", format!("Bearer {SECRET}"));
    if let Some(b) = body {
        req = req.json(&b);
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn bans_crud_and_events() {
    let srv = start("crud", true).await;

    // 列表初始为空
    let resp = authed_get(&srv, "/v0/management/bans").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["bans"].as_array().unwrap().len(), 0);

    // 手动封禁 → 200 + 记录 + 事件
    let resp = authed_req(
        &srv,
        reqwest::Method::POST,
        "/v0/management/bans",
        Some(serde_json::json!({"ip": "203.0.113.66", "ttl_secs": 1800, "reason": "test ban"})),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(srv.mock.find("203.0.113.66").is_some());
    let entry = srv.mock.find("203.0.113.66").unwrap();
    assert_eq!(entry.plugin, "manual");
    assert_eq!(entry.node, "it-node");
    assert_eq!(entry.scope, BanScope::Local);

    let events = srv.state.recent_events();
    assert!(
        events
            .iter()
            .any(|r| matches!(&r.event, rooster_proto::Event::Ban { ip, plugin, .. }
                if ip == "203.0.113.66" && plugin == "manual"))
    );

    // 列表带字段
    let resp = authed_get(&srv, "/v0/management/bans").await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let arr = body["bans"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ip"], "203.0.113.66");
    assert_eq!(arr[0]["plugin"], "manual");
    assert!(arr[0]["expires_at"].is_null());

    // 白名单命中 → 409,不产生封禁
    srv.mock.refuse("10.1.2.3");
    let resp = authed_req(
        &srv,
        reqwest::Method::POST,
        "/v0/management/bans",
        Some(serde_json::json!({"ip": "10.1.2.3"})),
    )
    .await;
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "allowlisted");

    // 非法 IP → 422
    let resp = authed_req(
        &srv,
        reqwest::Method::POST,
        "/v0/management/bans",
        Some(serde_json::json!({"ip": "not-an-ip"})),
    )
    .await;
    assert_eq!(resp.status(), 422);

    // 解封(幂等,不存在也 204)
    let resp = authed_req(&srv, reqwest::Method::DELETE, "/v0/management/bans/203.0.113.66", None).await;
    assert_eq!(resp.status(), 204);
    assert!(srv.mock.find("203.0.113.66").is_none());
    let resp = authed_req(&srv, reqwest::Method::DELETE, "/v0/management/bans/203.0.113.66", None).await;
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn bans_unavailable_returns_503() {
    let srv = start("no-nft", false).await;
    let resp = authed_get(&srv, "/v0/management/bans").await;
    assert_eq!(resp.status(), 503);
    let resp = authed_req(
        &srv,
        reqwest::Method::POST,
        "/v0/management/bans",
        Some(serde_json::json!({"ip": "203.0.113.66"})),
    )
    .await;
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn allowlist_write_and_runtime_reconfigure() {
    let srv = start("allowlist", true).await;

    // GET 返回配置层白名单
    let resp = authed_get(&srv, "/v0/management/allowlist").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["admin-allowlist"][0], "10.0.0.0/8");

    // 非法 CIDR → 422
    let resp = authed_req(
        &srv,
        reqwest::Method::PUT,
        "/v0/management/allowlist",
        Some(serde_json::json!({"cidrs": ["banana"]})),
    )
    .await;
    assert_eq!(resp.status(), 422);

    // 写入新白名单:配置落盘 + 确认流程(security 变更)+ 注释保留
    let resp = authed_req(
        &srv,
        reqwest::Method::PUT,
        "/v0/management/allowlist",
        Some(serde_json::json!({"cidrs": ["10.0.0.0/8", "192.0.2.0/24"]})),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(!body["confirm"]["token"].is_null(), "allowlist change must require confirm");

    let raw = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(raw.contains("# rooster agent configuration"), "comments preserved");
    assert!(raw.contains("192.0.2.0/24"));

    // 运行时重配置:白名单进入 mock(含本机回环地址);
    // ssh-guard 未启用,无 L4 限速调用。
    bans::reconfigure(&srv.state).await;
    let nets = srv.mock.allowlist.lock().unwrap().clone();
    assert!(nets.iter().any(|n| n.to_string() == "10.0.0.0/8"));
    assert!(nets.iter().any(|n| n.to_string() == "192.0.2.0/24"));
    assert!(
        nets.iter().any(|n| n.contains(&"127.0.0.1".parse::<std::net::IpAddr>().unwrap())),
        "local addresses are never bannable"
    );
    assert!(srv.mock.ssh_limit.lock().unwrap().is_none());
}

#[tokio::test]
async fn stats_shape() {
    let srv = start("stats", true).await;
    let resp = authed_get(&srv, "/v0/management/stats").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["forwards"].is_array());
    assert_eq!(body["bans"], 0);

    // 发生过封禁后计数变化
    authed_req(
        &srv,
        reqwest::Method::POST,
        "/v0/management/bans",
        Some(serde_json::json!({"ip": "198.51.100.10"})),
    )
    .await;
    let resp = authed_get(&srv, "/v0/management/stats").await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["bans"], 1);
}

#[tokio::test]
async fn ssh_guard_reconfigure_spawns_and_stops() {
    let srv = start("sshguard", true).await;
    // 修改配置启用 ssh-guard(文件源):plugins 属 managed 层
    let raw = std::fs::read_to_string(&srv.config_path).unwrap();
    let enabled = format!(
        "{raw}\nmanaged:\n  plugins:\n    ssh-guard:\n      enabled: true\n      source: file\n"
    );
    std::fs::write(&srv.config_path, &enabled).unwrap();
    // 直接改盘 + 手动重配置(不经 watcher,避免时序抖动)
    let (_f, eff) = rooster_config::parse_and_validate(&enabled).unwrap();
    *srv.state.effective.write().unwrap() = eff;
    bans::reconfigure(&srv.state).await;
    assert!(
        srv.state.sshguard_task.lock().unwrap().is_some(),
        "ssh-guard task spawned when enabled"
    );
    let ssh_limit = srv.mock.ssh_limit.lock().unwrap().clone();
    assert_eq!(
        ssh_limit.map(|(p, _, b)| (p, b)),
        Some((22, 5))
    );

    // 禁用 → 任务停止
    let disabled = enabled.replace("enabled: true", "enabled: false");
    let (_f, eff) = rooster_config::parse_and_validate(&disabled).unwrap();
    *srv.state.effective.write().unwrap() = eff;
    bans::reconfigure(&srv.state).await;
    assert!(srv.state.sshguard_task.lock().unwrap().is_none());
}
