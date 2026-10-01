//! /plugins 子树写集成测试:启用 ssh-guard、确认保持、超时回滚、
//! 非法配置拒写、未知插件 404。

use rooster_agent::management;
use rooster_agent::management::auth::AuthGate;
use rooster_agent::state::AgentState;
use rooster_config::{hash_content, ConfigWriter, WatcherState};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const SECRET: &str = "it-password";

const BASE_CONFIG: &str = r#"# rooster agent configuration
local:
  agent:
    node-name: it-node        # keep me
    data-dir: DATA_DIR
  management:
    listen: 127.0.0.1:9870
    secret-key: placeholder   # replaced by the test with a bcrypt hash
  security:
    admin-allowlist: []
    apply-confirm-timeout: 1s
  forwards:
    - id: mysql
      proto: tcp
      listen: 0.0.0.0:13306
      target: 10.0.1.20:3306
"#;

struct TestServer {
    base: String,
    dir: PathBuf,
    config_path: PathBuf,
    state: Arc<AgentState>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start(tag: &str) -> TestServer {
    let dir = std::env::temp_dir().join(format!("rooster-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");

    let raw = BASE_CONFIG
        .replace("DATA_DIR", dir.to_str().unwrap())
        .replace("secret-key: placeholder", &format!("secret-key: \"{SECRET}\""));
    std::fs::write(&config_path, &raw).unwrap();

    let (_file, effective) = rooster_config::parse_and_validate(&raw).unwrap();
    let writer = ConfigWriter::new(&config_path, &dir);
    let watcher = Arc::new(WatcherState::new(hash_content(&raw)));
    let auth = AuthGate::new(bcrypt::hash(SECRET, 4).unwrap());
    let state = Arc::new(AgentState::new(
        config_path.clone(),
        writer,
        watcher.clone(),
        effective,
        auth,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_state = state.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            management::router(serve_state)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    TestServer {
        base: format!("http://{addr}"),
        dir,
        config_path,
        state,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().expect("client")
}

async fn put_sshguard(srv: &TestServer, body: serde_json::Value) -> reqwest::Response {
    client()
        .put(format!("{}/v0/management/plugins/ssh-guard", srv.base))
        .bearer_auth(SECRET)
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_returns_defaults_before_any_write() {
    let srv = start("plug-default").await;
    let resp = client()
        .get(format!("{}/v0/management/plugins/ssh-guard", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], false);
    assert_eq!(body["port"], 22);
    assert_eq!(body["max-retry"], 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_enables_ssh_guard_into_managed_subtree() {
    let srv = start("plug-enable").await;
    // 无 managed 段的最小配置也必须能写(整链路建键)。
    let resp = put_sshguard(
        &srv,
        serde_json::json!({"enabled": true, "port": 2222, "conn-rate": "30/minute"}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["confirm"]["token"].is_string(), "ssh_guard 属确认类变更");
    assert!(body["confirm"]["rollback-in"].as_u64().unwrap() >= 1);

    // 磁盘:managed.plugins.ssh-guard 子树 + 注释保留。
    let on_disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(on_disk.contains("# keep me"), "comments must survive");
    assert!(on_disk.contains("ssh-guard:"));
    assert!(on_disk.contains("enabled: true"));

    // effective 已合并。
    assert!(srv.state.effective().plugins.ssh_guard.enabled);
    assert_eq!(srv.state.effective().plugins.ssh_guard.port, 2222);

    // GET 回读(经确认后仍为启用)。
    let token = body["confirm"]["token"].as_str().unwrap().to_string();
    let confirm = client()
        .post(format!("{}/v0/management/apply/confirm", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);

    let resp = client()
        .get(format!("{}/v0/management/plugins/ssh-guard", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["port"], 2222);
    assert_eq!(body["conn-rate"], "30/minute");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfirmed_change_rolls_back() {
    let srv = start("plug-rollback").await;
    let resp = put_sshguard(&srv, serde_json::json!({"enabled": true})).await;
    assert_eq!(resp.status(), 200);
    // 不确认:apply-confirm-timeout = 1s,超时自动回滚。
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert!(
        !srv.state.effective().plugins.ssh_guard.enabled,
        "unconfirmed ssh-guard change must roll back"
    );
    let on_disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(!on_disk.contains("enabled: true"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_configs_are_rejected_without_writing() {
    let srv = start("plug-invalid").await;
    let before = std::fs::read_to_string(&srv.config_path).unwrap();

    // 字段级:时长不是 humantime 格式 → 反序列化失败 400。
    let resp = put_sshguard(
        &srv,
        serde_json::json!({"enabled": true, "find-time": "banana"}),
    )
    .await;
    assert_eq!(resp.status(), 400);

    // 语义级:conn-rate 非法 → 校验失败 422,不落盘。
    let resp = put_sshguard(
        &srv,
        serde_json::json!({"enabled": true, "conn-rate": "banana"}),
    )
    .await;
    assert_eq!(resp.status(), 422);

    let after = std::fs::read_to_string(&srv.config_path).unwrap();
    assert_eq!(before, after, "rejected writes must not touch the file");
    assert!(!srv.state.effective().plugins.ssh_guard.enabled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_plugin_is_404() {
    let srv = start("plug-404").await;
    for method in [reqwest::Method::GET, reqwest::Method::PUT] {
        let resp = client()
            .request(method, format!("{}/v0/management/plugins/nope", srv.base))
            .bearer_auth(SECRET)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }
}
