//! 回归测试:明文 management.secret-key 必须在首次启动时被
//! 哈希回写,并且哈希要同时落到磁盘**和**内存。
//!
//! 锁定的两个回归点:
//! - 回写后必须刷新 effective,否则 `GET /config` 的 effective 字段会继续
//!   对外吐明文(想消除的正是这个暴露面);
//! - 回写必须走 `ConfigWriter::write_atomic`(tmp → fsync → rename + 历史
//! 归档),裸 `fs::write` 会截断重写唯一真相源。
//!
//! 该路径在 `rooster_agent::run()` 内,只能真跑二进制验证。

use rooster_config::parse_and_validate;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// 测试专用 HTTP 客户端:禁用环境代理。
///
/// 本机若设有 http_proxy/https_proxy(常见的代理/抓包工具),reqwest 默认会
/// 读环境变量,把 127.0.0.1 的测试请求也丢进代理 —— `no_proxy` 里的
/// `127.*` 通配符 reqwest 并不识别,于是所有反代测试拿到代理返回的空 body
/// 502。测试连的是回环,必须显式绕开代理。
fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().expect("client")
}

const SECRET: &str = "SuperSecret123";

/// 测试结束时杀掉子进程,避免残留常驻 agent。
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 断言失败时也要清掉临时目录。
struct DirGuard(PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rooster-fr2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 端口按 pid 派生,并给每个测试一个独立偏移:同一测试二进制里的多个
/// `#[tokio::test]` 是并行跑的,共用端口会互相抢占(一个进程的 /healthz
/// 会满足另一个进程的等待)。
fn port_for(offset: u16) -> u16 {
    20000 + (std::process::id() % 20000) as u16 + offset
}

fn write_config(dir: &PathBuf, port: u16) -> PathBuf {
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            r#"local:
  agent:
    node-name: fr2-node
    data-dir: {data}
  management:
    listen: 127.0.0.1:{port}
    secret-key: {secret}
  security:
    admin-allowlist: []
    apply-confirm-timeout: 60s
"#,
            data = dir.display(),
            port = port,
            secret = SECRET,
        ),
    )
    .unwrap();
    config
}

fn spawn_agent(config: &PathBuf) -> ChildGuard {
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_rooster"))
            .args(["agent", "--config"])
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rooster agent"),
    )
}

/// 等待管理端口可连。进程提前退出(端口被占等)时立即失败,而不是空等 20s。
async fn wait_until_serving(child: &mut Child, port: u16) {
    let client = client();
    let url = format!("http://127.0.0.1:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("rooster agent exited early with {status}, port {port} unavailable");
        }
        if client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("rooster agent never started serving on port {port}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_secret_is_hashed_on_disk_and_in_memory() {
    let dir = DirGuard(temp_dir("hash"));
    let port = port_for(0);
    let config = write_config(&dir.0, port);
    let mut child = spawn_agent(&config);
    wait_until_serving(&mut child.0, port).await;

    let body: serde_json::Value = client()
        .get(format!("http://127.0.0.1:{port}/v0/management/config"))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let disk = std::fs::read_to_string(&config).unwrap();
    let (_file, from_disk) = parse_and_validate(&disk).expect("config on disk must stay valid");
    let disk_key = from_disk.management.secret_key.clone().unwrap();
    assert!(
        disk_key.starts_with("$2"),
        "secret-key must be bcrypt on disk, got: {disk_key}"
    );
    assert!(
        !disk.contains(SECRET),
        "plaintext secret must not survive anywhere in the config file"
    );

    // 核心回归点:API 返回的 effective 必须与磁盘重新解析的结果一致。
    // 回写前不刷新 effective 时,这里是明文而磁盘是哈希,断言即失败。
    // 凭据字段在读侧被脱敏成哨兵,比较前先按同一规则掩掉磁盘值。
    let mut expected = serde_json::to_value(&from_disk).unwrap();
    expected["management"]["secret-key"] = serde_json::json!("***");
    if let Some(h) = expected.get_mut("hub") {
        if h.get("token").is_some() {
            h["token"] = serde_json::json!("***");
        }
    }
    assert_eq!(
        body["effective"], expected,
        "GET /config effective must reflect the hashed value written to disk, \
         not the pre-write-back in-memory config"
    );
    assert!(
        !body.to_string().contains(&disk_key),
        "管理接口不得把口令哈希原样带出(raw / effective 都要脱敏)"
    );

    // 原子写:write_atomic 会把回写前的版本归档到
    // <data-dir>/config-history;裸 fs::write 不会产生任何归档。
    let history = dir.0.join("config-history");
    let archived = std::fs::read_dir(&history)
        .unwrap_or_else(|e| panic!("no history archive at {}: {e}", history.display()));
    assert!(
        archived.count() > 0,
        "the write-back must go through ConfigWriter::write_atomic, \
         which archives the pre-write version"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_survives_restart_after_hashing() {
    let dir = DirGuard(temp_dir("restart"));
    let port = port_for(1);
    let config = write_config(&dir.0, port);
    let client = client();

    for round in 1..=2 {
        let mut child = spawn_agent(&config);
        wait_until_serving(&mut child.0, port).await;
        let status = client
            .get(format!("http://127.0.0.1:{port}/v0/management/config"))
            .bearer_auth(SECRET)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(
            status,
            200,
            "round {round}: the original secret must keep working after the write-back"
        );
        drop(child);
        // 等待端口释放,否则下一次 bind 会因 TIME_WAIT/残留句柄失败。
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
