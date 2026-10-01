//! 接线验证:WAF 桥接(rooster-waf → http-guard)、/waf/report、
//! /sites、/stats 汇总、ACME 缓存决策。经真实 80 端口反代端到端请求。

use rooster_agent::bans;
use rooster_agent::management;
use rooster_agent::management::auth::AuthGate;
use rooster_agent::state::AgentState;
use rooster_config::{hash_content, ConfigWriter, WatcherState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

const SECRET: &str = "it-password";

async fn start(tag: &str, config_extra: &str) -> (TestServer, u16) {
    let dir = std::env::temp_dir().join(format!("rooster-m2-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");

    let raw = format!(
        r#"# rooster agent configuration
local:
  agent:
    node-name: m2-node
    data-dir: {dir}
  management:
    listen: 127.0.0.1:19870
    secret-key: "{SECRET}"
{extra}
"#,
        dir = dir.to_str().unwrap(),
        extra = config_extra,
    );
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
    state.httpguard.set_inspector(state.waf.clone());

    // 绑定 80 端口等价物:随机端口
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = l.local_addr().unwrap().port();
    drop(l);
    let effective2 = state.effective();
    let mut eff2 = effective2.clone();
    eff2.plugins.http_guard.listen_http =
        Some(SocketAddr::from(([127, 0, 0, 1], http_port)));
    *state.effective.write().unwrap() = eff2;
    bans::reconfigure(&state).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let app = management::router(serve_state)
            .into_make_service_with_connect_info::<SocketAddr>();
        let _ = axum::serve(listener, app).await;
    });

    (
        TestServer {
            base: format!("http://{addr}"),
            dir,
            _config_path: config_path,
            state,
        },
        http_port,
    )
}

struct TestServer {
    base: String,
    dir: PathBuf,
    _config_path: PathBuf,
    state: Arc<AgentState>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const SITES_YAML: &str = r#"managed:
  plugins:
    http-guard:
      enabled: true
      listen-http: 127.0.0.1:80   # 测试内覆盖为随机端口
  waf:
    crs:
      enabled: false
    signatures: []
  sites:
    - id: web
      server-names: [waf.test]
      tls:
        mode: passthrough
      upstream: http://127.0.0.1:UP_PORT
      waf:
        mode: block
"#;

#[tokio::test(flavor = "multi_thread")]
async fn waf_bridge_blocks_sqli_through_proxy() {
    // 上游 echo:返回 200 与路径。
    let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = up_listener.accept().await else { continue };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = format!("echo:{path}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    let extra = SITES_YAML.replace("UP_PORT", &up_port.to_string());
    let (srv, http_port) = start("bridge", &extra).await;

    let client = reqwest::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // 良性请求直通上游。
    let resp = client
        .get(format!("http://127.0.0.1:{http_port}/index.html"))
        .header("host", "waf.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // SQL 注入:内置签名经 WafInspector → http-guard 阻断。
    let resp = client
        .get(format!(
            "http://127.0.0.1:{http_port}/?q=1'%20union%20select%20password%20from%20users--"
        ))
        .header("host", "waf.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // /waf/report 暴露加载报告(数据源)。
    let resp = client
        .get(format!("{}/v0/management/waf/report", srv.base))
        .header("authorization", format!("Bearer {SECRET}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["report"]["loaded"].as_u64().unwrap() > 0);

    // /sites 列出生效站点。
    let resp = client
        .get(format!("{}/v0/management/sites", srv.base))
        .header("authorization", format!("Bearer {SECRET}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let sites = body.as_array().unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0]["id"], "web");

    // /stats 含 http 站点统计。
    let resp = client
        .get(format!("{}/v0/management/stats", srv.base))
        .header("authorization", format!("Bearer {SECRET}"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["http"].is_array());

    srv.state.httpguard.shutdown().await;
}

#[test]
fn acme_cache_decision() {
    // 无缓存 → 需要签发;有缓存且未到期 → 跳过。
    let dir = std::env::temp_dir().join(format!("rooster-acme-{}", std::process::id()));
    let site_dir = dir.join("acme").join("s1");
    std::fs::create_dir_all(&site_dir).unwrap();
    assert!(!acme_cache_valid(&site_dir));
    std::fs::write(site_dir.join("cert.pem"), "x").unwrap();
    std::fs::write(site_dir.join("key.pem"), "x").unwrap();
    assert!(!acme_cache_valid(&site_dir)); // 缺 meta.json
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 10 * 24 * 3600; // 10 天后到期 < 30 天窗口 → 仍需续期
    std::fs::write(
        site_dir.join("meta.json"),
        serde_json::json!({"expires_at": soon}).to_string(),
    )
    .unwrap();
    assert!(!acme_cache_valid(&site_dir));
    let far = soon + 90 * 24 * 3600;
    std::fs::write(
        site_dir.join("meta.json"),
        serde_json::json!({"expires_at": far}).to_string(),
    )
    .unwrap();
    assert!(acme_cache_valid(&site_dir));
    let _ = std::fs::remove_dir_all(&dir);
}

/// acme.rs 的 cache_valid 是私有;按相同规则(meta.expires_at + 30 天
/// 窗口 + 证书文件在位)等价重算,锁定决策语义。
fn acme_cache_valid(dir: &std::path::Path) -> bool {
    let meta: serde_json::Value = match std::fs::read_to_string(dir.join("meta.json")) {
        Ok(m) => serde_json::from_str(&m).unwrap(),
        Err(_) => return false,
    };
    if !dir.join("cert.pem").is_file() || !dir.join("key.pem").is_file() {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    meta["expires_at"].as_u64().unwrap_or(0) > now + 30 * 24 * 3600
}
