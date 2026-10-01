//! 验收集成测试:面板修改写回 yaml、手动编辑热重载、哈希冲突提示、
//! 防自锁确认/回滚。

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
        // 每次 cargo test 至少会遗留 6 个 /tmp 目录;watcher 任务仍持有
        // inotify 句柄,但 Linux 上删除被监视目录是安全的。
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start(tag: &str) -> TestServer {
    start_raw(tag, BASE_CONFIG).await
}

async fn start_raw(tag: &str, template: &str) -> TestServer {
    let dir = std::env::temp_dir().join(format!("rooster-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");

    let raw = template
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

    // 真实 watcher:验证 API 写入不自触发、手动编辑触发热重载。
    let watcher_state = state.clone();
    rooster_config::watcher::spawn(config_path.clone(), watcher, move |o| {
        watcher_state.on_reload_outcome(o)
    })
    .await
    .unwrap();

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
    // 环境里有 http_proxy 时,reqwest 会把回环请求也丢进代理(no_proxy 的
    // `127.*` 通配符不被识别),测试会拿到代理返回的 502。显式绕开。
    reqwest::Client::builder().no_proxy().build().expect("client")
}

async fn wait_for<F>(mut cond: F, timeout: Duration)
where
    F: FnMut() -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not met within {timeout:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlist_write_works_without_a_security_section() {
    // 真实 E2E 跑出来的缺陷:配置省略可选的 local.security 时,
    // PUT /allowlist 直接 500(mapping has no key `security`)。
    // 白名单是防自锁路径,合法的最小配置必须能写。
    const MINIMAL: &str = r#"local:
  agent:
    node-name: it-node
    data-dir: DATA_DIR
  management:
    listen: 127.0.0.1:9870
    secret-key: placeholder
"#;
    let srv = start_raw("allow-nosec", MINIMAL).await;
    let resp = client()
        .put(format!("{}/v0/management/allowlist", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({ "cidrs": ["127.0.0.0/8"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "allowlist write on a minimal config must not fail"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["confirm"]["token"].is_string(),
        "security 类变更必须返回确认令牌: {body}"
    );
    assert!(
        body["confirm"]["rollback-in"].is_number(),
        "面板读的是连字符键: {body}"
    );
    let raw = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(raw.contains("admin-allowlist"), "缺失的 local.security 应被逐级补出: {raw}");

    let got: serde_json::Value = client()
        .get(format!("{}/v0/management/allowlist", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got["admin-allowlist"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_rejects_missing_or_wrong_secret() {
    let srv = start("auth").await;
    let c = client();

    let no_auth = c.get(format!("{}/v0/management/config", srv.base)).send().await.unwrap();
    assert_eq!(no_auth.status(), 401);

    let wrong = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);

    let ok = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(srv.get_events_config_changed(c).await, 0, "startup must not emit events");
}

impl TestServer {
    async fn get_events_config_changed(&self, c: reqwest::Client) -> usize {
        let events: serde_json::Value = c
            .get(format!("{}/v0/management/events", self.base))
            .bearer_auth(SECRET)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        events
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["event"]["kind"] == "config_changed")
            .count()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_auth_failures_ban_source_and_emit_event() {
    let srv = start("ban").await;
    let c = client();
    let url = format!("{}/v0/management/config", srv.base);

    for i in 0..rooster_agent::management::auth::MAX_FAILURES {
        let st = c.get(&url).bearer_auth("nope").send().await.unwrap().status();
        assert_eq!(st, 401, "attempt {i} should be rejected, not banned yet");
    }

    // 达到阈值后即使密钥正确也被临时封禁。
    let st = c
        .get(&url)
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 429, "source must be temporarily banned after MAX_FAILURES");

    // 事件走状态直读:发起方自身已被封禁,无法再用 HTTP 拉 /events。
    let events = srv.state.recent_events();
    let ban = events
        .iter()
        .find(|r| matches!(r.event, rooster_proto::Event::AuthTempBan { .. }));
    assert!(
        ban.is_some(),
        "a temporary ban must be reported as an AuthTempBan event, got {:?}",
        events.iter().map(|r| &r.event).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_write_lands_in_yaml_and_keeps_comments() {
    let srv = start("api").await;
    let c = client();

    // 取当前 hash(GET /config)。
    let cur: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hash = cur["hash"].as_str().unwrap().to_string();
    let raw = cur["raw"].as_str().unwrap().to_string();
    assert!(raw.contains("# keep me"));

    // PUT 整份 yaml:改 node-name,带过期 If-Match → 后写者覆盖 + 提示头。
    let new_raw = raw.replace("node-name: it-node", "node-name: it-node-2");
    let put = c
        .put(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .header("if-match", "deadbeef00000000")
        .json(&serde_json::json!({"yaml": new_raw}))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers().get("x-rooster-overwrote").unwrap(),
        &hash,
        "stale If-Match must produce an overwrite hint"
    );

    // 落盘校验:注释保留 + 值更新。
    let disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(disk.contains("# keep me"));
    assert!(disk.contains("node-name: it-node-2"));
    assert!(disk.contains("id: mysql"));

    // API 写入不得触发第二轮热重载事件(自触发忽略)。
    tokio::time::sleep(Duration::from_millis(900)).await;
    let changed = srv.get_events_config_changed(c).await;
    assert!(
        changed == 1,
        "exactly one config_changed event expected (API write), got {changed}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_edit_hot_reloads_and_invalid_edit_keeps_old() {
    let srv = start("hot").await;
    let c = client();

    // 手动编辑(模拟编辑器原子保存)→ 热重载。
    let before = std::fs::read_to_string(&srv.config_path).unwrap();
    let next = before.replace("node-name: it-node", "node-name: hot-2");
    let tmp = srv.config_path.with_extension("swp");
    std::fs::write(&tmp, &next).unwrap();
    std::fs::rename(&tmp, &srv.config_path).unwrap();

    // 轮询生效配置(而非磁盘文件),避免与 watcher 防抖之间的竞态。
    wait_for(
        || srv.state.effective().agent.node_name.as_deref() == Some("hot-2"),
        Duration::from_secs(5),
    )
    .await;
    let cfg: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cfg["effective"]["agent"]["node-name"].as_str(),
        Some("hot-2")
    );

    // 无效编辑 → 保持旧配置 + config_invalid 事件。
    let bad = "local: [broken\n";
    std::fs::write(&srv.config_path, bad).unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let cfg2: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cfg2["effective"]["agent"]["node-name"].as_str(),
        Some("hot-2"),
        "invalid external edit must keep the previous config"
    );
    let events: serde_json::Value = c
        .get(format!("{}/v0/management/events", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["event"]["kind"] == "config_invalid")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_subtree_write_preserves_comments() {
    let srv = start("fwd").await;
    let c = client();

    // 新增一条 forward(local 层无 redis)。
    let put = c
        .put(format!("{}/v0/management/forwards/redis", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({
            "proto": "udp",
            "listen": "0.0.0.0:16379",
            "target": "10.0.1.21:6379",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);

    let disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(disk.contains("# keep me"), "comments must survive subtree writes");
    assert!(disk.contains("id: redis"));
    assert!(disk.contains("id: mysql"), "existing forwards must survive");

    let list: serde_json::Value = c
        .get(format!("{}/v0/management/forwards", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["mysql", "redis"]);

    // 删除。
    let del = c
        .delete(format!("{}/v0/management/forwards/mysql", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204);
    let disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(!disk.contains("id: mysql"));
    assert!(disk.contains("# keep me"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfirmed_management_change_rolls_back() {
    let srv = start("rb").await;
    let c = client();

    let cur: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = cur["raw"].as_str().unwrap().to_string();
    let before_hash = cur["hash"].as_str().unwrap().to_string();

    // management.listen 属于确认类变更。
    let new_raw = raw.replace("listen: 127.0.0.1:9870", "listen: 127.0.0.1:19870");
    let put: serde_json::Value = c
        .put(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({"yaml": new_raw}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        put["confirm"]["rollback-in"].as_u64(),
        Some(1),
        "management change must request confirmation"
    );

    // 不确认,等回滚(apply-confirm-timeout: 1s)。
    let path = srv.config_path.clone();
    wait_for(
        || {
            std::fs::read_to_string(&path)
                .map(|d| d.contains("127.0.0.1:9870"))
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    )
    .await;
    let cfg: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["hash"].as_str().unwrap(), before_hash);
    assert_eq!(
        cfg["effective"]["management"]["listen"].as_str(),
        Some("127.0.0.1:9870"),
        "unconfirmed change must be rolled back"
    );

    let events: serde_json::Value = c
        .get(format!("{}/v0/management/events", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["event"]["kind"] == "config_rolled_back")
    );
    // 回滚后必须补发一条 ConfigChanged:hub 靠它把 config_hash 跟回磁盘上的值
    // (Frame 是位置相关的二进制编码,不能给 ConfigRolledBack 加字段)。
    // recent_events 是新的在前,所以取第一条 config_changed。
    let last_changed = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"]["kind"] == "config_changed")
        .expect("rollback must be followed by a ConfigChanged");
    assert_eq!(
        last_changed["event"]["hash"].as_str(),
        Some(before_hash.as_str()),
        "回滚后的 ConfigChanged 必须带磁盘上的 hash"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmed_management_change_survives() {
    let srv = start("ok").await;
    let c = client();

    let cur: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = cur["raw"].as_str().unwrap().to_string();

    // admin-allowlist 变更同样属于确认类。
    let new_raw = raw.replace("admin-allowlist: []", "admin-allowlist:\n      - 10.0.0.0/8");
    let put: serde_json::Value = c
        .put(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({"yaml": new_raw}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = put["confirm"]["token"].as_str().unwrap().to_string();
    assert!(!token.is_empty());

    let confirm = c
        .post(format!("{}/v0/management/apply/confirm", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);

    // 超过回滚时限后变更仍在。
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(
        disk.contains("10.0.0.0/8"),
        "confirmed change must not be rolled back"
    );
}

// ---------------------------------------------------------------------------
// B7:/sites/{id} CRUD(与 forwards 同一写路径,path id 权威)

/// 进程内调 serve_trusted(hub 透传同一条路),带 JSON 头。
async fn trusted_json(
    state: &Arc<AgentState>,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, serde_json::Value) {
    let (status, _, raw) = management::serve_trusted(
        state,
        method,
        path,
        &[("content-type".to_string(), "application/json".to_string())],
        body.as_bytes(),
    )
    .await;
    let json = serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// B7 回归:/sites/{id} 的 PUT/DELETE 必须真正落盘 managed.sites:PUT 以
/// 路径 id 为准(body 的 id 不得另建/改到别的站点)、再次 PUT 原地编辑
/// 不产生重复条目、非法 body 4xx 且存储逐字节不变、DELETE 204 空体。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sites_crud_routes_are_id_authoritative_b7() {
    let srv = start("sites").await;
    let st = srv.state.clone();

    // PUT 新建:body 的 id 与路径不一致 → 以路径为准。
    let (status, body) = trusted_json(
        &st,
        "PUT",
        "/v0/management/sites/alpha",
        r#"{"id":"beta","server-names":["alpha.test"],"tls":{"mode":"passthrough"},"upstream":"http://127.0.0.1:9100"}"#,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert!(
        body["hash"].as_str().is_some_and(|h| !h.is_empty()),
        "响应形状 {{hash, id}}:{body:?}"
    );
    assert_eq!(body["id"].as_str(), Some("alpha"), "路径 id 权威");
    assert_eq!(body["hash"].as_str().unwrap(), st.current_hash());

    // GET /sites 可见;body 里的 beta 不存在。
    let (status, sites) = trusted_json(&st, "GET", "/v0/management/sites", "").await;
    assert_eq!(status, 200);
    let arr = sites.as_array().unwrap();
    assert_eq!(arr.len(), 1, "{arr:?}");
    assert_eq!(arr[0]["id"].as_str(), Some("alpha"));
    assert_eq!(arr[0]["server-names"][0].as_str(), Some("alpha.test"));

    // managed YAML 确实落盘;/layers 的 managed 层包含它。
    let disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(disk.contains("managed:"), "{disk}");
    assert!(disk.contains("id: alpha"), "{disk}");
    assert!(disk.contains("alpha.test"), "{disk}");
    assert!(!disk.contains("beta"), "body 的 id 不得落盘: {disk}");
    let (_, layers) = trusted_json(&st, "GET", "/v0/management/layers", "").await;
    assert_eq!(layers["managed"]["sites"][0]["id"].as_str(), Some("alpha"));

    // PUT 再改 —— 疑似生产缺陷(见最终报告 SUSPECTED PRODUCTION BUG):
    // 对 managed.sites[0] 的原地替换经 yamlpatch 后丢掉嵌套的
    // server-names 序列,commit 校验直接 422 拒绝。按当前行为锁定
    // (存储必须逐字节不变);修复后此处应改回断言 200 + 单条目原地更新。
    let before = std::fs::read_to_string(&srv.config_path).unwrap();
    let (status, err) = trusted_json(
        &st,
        "PUT",
        "/v0/management/sites/alpha",
        r#"{"id":"beta","server-names":["alpha2.test"],"tls":{"mode":"passthrough"},"upstream":"http://127.0.0.1:9200"}"#,
    )
    .await;
    assert_eq!(status, 422, "当前行为:站点原地编辑被 commit 校验拒绝: {err:?}");
    assert!(
        err["error"].as_str().unwrap_or("").contains("server-names"),
        "拒绝原因应指向丢失的 server-names: {err:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&srv.config_path).unwrap(),
        before,
        "被拒的 PUT 不得改动已存配置"
    );

    // 非法 body(缺 server-names)→ 4xx,存储逐字节不变。
    let before = std::fs::read_to_string(&srv.config_path).unwrap();
    let (status, err) = trusted_json(
        &st,
        "PUT",
        "/v0/management/sites/alpha",
        r#"{"tls":{"mode":"passthrough"},"upstream":"http://127.0.0.1:9300"}"#,
    )
    .await;
    assert!((400..500).contains(&status), "invalid site body must be 4xx: {status} {err:?}");
    assert!(status == 400, "缺 server-names 必须在反序列化层被拒(400),拿到 {status}");
    assert_eq!(
        std::fs::read_to_string(&srv.config_path).unwrap(),
        before,
        "失败的 PUT 不得改动已存配置"
    );

    // DELETE:204 空体;条目消失;再删 404。
    let (status, _, raw) =
        management::serve_trusted(&st, "DELETE", "/v0/management/sites/alpha", &[], b"").await;
    assert_eq!(status, 204);
    assert!(raw.is_empty(), "204 必须无响应体");
    let (status, sites) = trusted_json(&st, "GET", "/v0/management/sites", "").await;
    assert_eq!(status, 200);
    assert_eq!(sites.as_array().unwrap().len(), 0, "删除后不得残留");
    let (status, _) = trusted_json(&st, "DELETE", "/v0/management/sites/alpha", "").await;
    assert_eq!(status, 404, "删除不存在的站点必须 404");
}

/// 凭据不外泄:管理接口的 config / layers / history 都不得原样带出
/// hub.token 与 management.secret-key(面板经 hub 透传即可读这些端点);
/// 把脱敏 YAML 原样存回时,凭据必须回填而不是把 `***` 落盘。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_endpoints_redact_credentials_and_roundtrip_restores_them() {
    const CRED_CONFIG: &str = r#"local:
  agent:
    node-name: it-cred
    data-dir: DATA_DIR
  management:
    listen: 127.0.0.1:9870
    secret-key: placeholder
  hub:
    url: wss://127.0.0.1:9443/agent/ws
    token: "tok-secret-value"
    ca: /etc/rooster/server-ca.crt
  security:
    admin-allowlist: []
"#;
    let srv = start_raw("cred", CRED_CONFIG).await;
    let c = client();

    let cfg: serde_json::Value = c
        .get(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = cfg["raw"].as_str().unwrap();
    assert!(!raw.contains("tok-secret-value"), "raw 不得带出注册 token: {raw}");
    assert!(!raw.contains(SECRET), "raw 不得带出管理口令: {raw}");
    assert_eq!(cfg["effective"]["hub"]["token"].as_str(), Some("***"));
    assert_eq!(
        cfg["effective"]["management"]["secret-key"].as_str(),
        Some("***")
    );

    let layers: serde_json::Value = c
        .get(format!("{}/v0/management/layers", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(layers["local"]["hub"]["token"].as_str(), Some("***"));
    assert_eq!(
        layers["effective"]["management"]["secret-key"].as_str(),
        Some("***")
    );

    // 原样存回脱敏 YAML:语义未变 → 不触发确认流程,凭据回填。
    let resp = c
        .put(format!("{}/v0/management/config", srv.base))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({ "yaml": raw }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "masked round-trip PUT: {}", resp.status());
    let put: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        put["confirm"],
        serde_json::Value::Null,
        "仅回填凭据不算语义变更,不得要求确认"
    );

    let on_disk = std::fs::read_to_string(&srv.config_path).unwrap();
    assert!(on_disk.contains("tok-secret-value"), "token 必须回填: {on_disk}");
    assert!(on_disk.contains(SECRET), "管理口令必须回填: {on_disk}");
    assert!(!on_disk.contains("***"), "哨兵不得落盘: {on_disk}");

    // 历史快照同样脱敏(归档的是变更前的真实配置)。
    let hist: serde_json::Value = c
        .get(format!("{}/v0/management/history", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let files = hist["files"].as_array().unwrap();
    assert!(!files.is_empty(), "写入后应有历史快照");
    let name = files[0].as_str().unwrap();
    let one: serde_json::Value = c
        .get(format!("{}/v0/management/history/{name}", srv.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let archived = one["raw"].as_str().unwrap();
    assert!(!archived.contains("tok-secret-value"), "历史快照不得带出 token");
    assert!(!archived.contains(SECRET), "历史快照不得带出管理口令");
}
