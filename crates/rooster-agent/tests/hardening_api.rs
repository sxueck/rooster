//! /hardening 端点集成测试:opt-in 默认、写入落 local 层、确认/回滚、
//! 蜜罐端口冲突拒写、未知字段拒写、模板值不被默认值覆盖。

use rooster_agent::management;
use rooster_agent::management::auth::AuthGate;
use rooster_agent::state::AgentState;
use rooster_config::{hash_content, ConfigWriter, WatcherState};
use std::path::PathBuf;
use std::sync::Arc;

const SECRET: &str = "it-password";

/// managed 模板下发了一份 honeypot 配置(ban-time 2h);local 只写
/// enabled 字段 —— 合并后必须仍是 2h,证明 None 保持语义在 API 链路生效。
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
managed:
  hardening:
    honeypot:
      enabled: false
      ban-time: 2h
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
    let dir = std::env::temp_dir().join(format!("rooster-hard-{tag}-{}", std::process::id()));
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

async fn put_hardening(srv: &TestServer, body: serde_json::Value) -> reqwest::Response {
    client()
        .put(format!("{}/v0/management/hardening", srv.base))
        .bearer_auth(SECRET)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn confirm(srv: &TestServer, token: &str) {
    let resp = client()
        .post(format!("{}/v0/management/apply/confirm", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_reflects_template_with_no_local_override() {
    let srv = start("get").await;
    let resp = client()
        .get(format!("{}/v0/management/hardening", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["honeypot"]["enabled"], false);
    assert_eq!(body["honeypot"]["ban-time"], "2h");
    assert!(body["port-guard"].is_null(), "未配置的子项不出现在生效值里");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_lands_in_local_layer_keeps_comments_and_needs_confirm() {
    let srv = start("write").await;
    let resp = put_hardening(
        &srv,
        serde_json::json!({"honeypot": {"enabled": true, "ports": [445, 6379]}}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["confirm"]["token"].as_str().expect("确认类变更").to_string();

    let on_disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(on_disk.contains("# keep me"), "注释必须保留");
    assert!(on_disk.contains("hardening:"), "local.hardening 已落盘");
    // 只写 local 层:managed 模板段原样不动。
    let managed_pos = on_disk.find("managed:").unwrap();
    assert!(on_disk[..managed_pos].contains("honeypot"), "写入落在 local 层");

    // 未填 ban-time:合并值仍是模板的 2h(None 保持,默认不穿透 local)。
    assert_eq!(srv.state.effective().hardening.honeypot.unwrap().ban_time.map(|d| d.as_secs()), Some(7200));

    confirm(&srv, &token).await;
    assert!(srv.state.effective().hardening.honeypot.as_ref().unwrap().enabled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfirmed_write_rolls_back() {
    let srv = start("rollback").await;
    let resp = put_hardening(&srv, serde_json::json!({"flag-guard": {"enabled": true}})).await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["confirm"]["token"].is_string());
    // apply-confirm-timeout = 1s;超时不回滚点 → 恢复旧配置(无 local.hardening 值)。
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let hp = srv.state.effective().hardening.flag_guard.clone();
    assert!(hp.is_none() || !hp.unwrap().enabled, "超时后必须回到未启用");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honeypot_port_conflict_is_rejected() {
    let srv = start("conflict").await;
    // 13306 是转发规则的监听端口;22 是 ssh-guard 端口 —— 都不得进蜜罐。
    let resp = put_hardening(
        &srv,
        serde_json::json!({"honeypot": {"enabled": true, "ports": [13306]}}),
    )
    .await;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 422, "body: {body}");
    assert!(
        serde_json::to_string(&body)
            .unwrap()
            .contains("hardening.honeypot: port 13306"),
        "错误必须点名冲突端口: {body}"
    );
    // 拒写后生效配置不变:honeypot 不存在或仍是模板的 disabled。
    let hp = srv.state.effective().hardening.honeypot.clone();
    assert!(!hp.map(|h| h.enabled).unwrap_or(false), "拒写后不得启用蜜罐");
    let on_disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(!on_disk.contains("ports:"), "冲突内容不得落盘");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_field_is_rejected_dont_silently_disable() {
    let srv = start("strict").await;
    // `enable` 拼错(应为 enabled):必须 422,而不是静默按 disabled 落盘。
    let resp = put_hardening(&srv, serde_json::json!({"honeypot": {"enable": true}})).await;
    assert_eq!(resp.status(), 422);
}

/// FlagGuardConfig 历史上没有 deny_unknown_fields:`flag-guard` 段里的
/// 拼错字段会被静默吞掉,防护实际未启用而面板却以为开了。回归:拼错
/// 必须 422,且生效配置不得出现已启用的 flag-guard。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flag_guard_typo_field_is_rejected() {
    let srv = start("flagtypo").await;
    let resp = put_hardening(&srv, serde_json::json!({"flag-guard": {"enable": true}})).await;
    assert_eq!(resp.status(), 422, "flag-guard 拼错字段不得静默落盘");
    let fg = srv.state.effective().hardening.flag_guard.clone();
    assert!(fg.is_none() || !fg.unwrap().enabled, "拒写后不得启用 flag-guard");
    let on_disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(!on_disk.contains("flag-guard:"), "拼错内容不得落盘");
}
