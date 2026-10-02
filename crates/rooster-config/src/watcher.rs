//! inotify 热重载。
//!
//! - 监听配置文件所在目录,按文件名过滤事件,兼容编辑器
//!   "写临时文件后 rename" 的保存方式;
//! - 防抖 500ms;
//! - 内容哈希与 Agent 自己最近一次写入相同 → 忽略(自触发);
//! - 外部变更先走 parse_and_validate:通过则回调 Applied,失败则回调
//!   Invalid 并继续沿用旧配置(current 哈希不变)。

use crate::error::ConfigError;
use crate::writer::hash_content;
use crate::{parse_and_validate, AgentConfigFile, EffectiveConfig};
use notify::{RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub const DEBOUNCE: Duration = Duration::from_millis(500);

pub struct WatcherState {
    /// Agent 自己最近一次写入的内容哈希;相同变更视为自触发并忽略。
    pub last_self_write: Mutex<String>,
    /// 当前生效配置的哈希。
    pub current: Mutex<String>,
}

impl WatcherState {
    pub fn new(current_hash: String) -> Self {
        Self {
            last_self_write: Mutex::new(String::new()),
            current: Mutex::new(current_hash),
        }
    }
}

#[derive(Debug)]
pub enum ReloadOutcome {
    Applied {
        hash: String,
        config: AgentConfigFile,
        effective: EffectiveConfig,
    },
    Invalid {
        hash: String,
        error: String,
        line: Option<u32>,
    },
}

/// 启动热重载任务。返回 JoinHandle 供调用方管理生命周期。
pub async fn spawn(
    path: PathBuf,
    state: Arc<WatcherState>,
    on_reload: impl Fn(ReloadOutcome) + Send + Sync + 'static,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid config path")
        })?
        .to_string();

    let (tx, mut rx) = mpsc::channel::<()>(64);
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
        if let Ok(ev) = res {
            // 只接受会改变内容的事件。读文件产生的 Access(Open/Close) 必须忽略,
            // 否则 handle_change 自己那次读会点亮下一轮 → 每 DEBOUNCE 自激重载。
            if matches!(ev.kind, notify::EventKind::Access(_)) {
                return;
            }
            let touches = ev
                .paths
                .iter()
                .any(|p| p.file_name().and_then(std::ffi::OsStr::to_str) == Some(&file_name));
            if touches {
                let _ = tx.blocking_send(());
            }
        }
    })
    .map_err(std::io::Error::other)?;
    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .map_err(std::io::Error::other)?;

    let handle = tokio::spawn(async move {
        // watcher 必须存活于任务期间
        let _watcher = watcher;
        while rx.recv().await.is_some() {
            let deadline = tokio::time::Instant::now() + DEBOUNCE;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = rx.recv() => {}
                }
            }
            handle_change(&path, &state, &on_reload);
        }
    });
    Ok(handle)
}

fn handle_change(
    path: &Path,
    state: &WatcherState,
    on_reload: &impl Fn(ReloadOutcome),
) {
    // 原子替换窗口期可能读到失败;防抖后的下一个事件会再触发。
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };
    let hash = hash_content(&raw);
    {
        let self_hash = state.last_self_write.lock().unwrap();
        if !self_hash.is_empty() && hash == *self_hash {
            return;
        }
    }
    // 内容就是当前生效配置(重复通知 / 相同字节回写):不再重放一次 Applied。
    // 没有这道锁时,任何一次额外的文件事件都会多灌一条 config_changed 事件。
    {
        let cur = state.current.lock().unwrap();
        if *cur == hash {
            return;
        }
    }
    match parse_and_validate(&raw) {
        Ok((config, effective)) => {
            *state.current.lock().unwrap() = hash.clone();
            on_reload(ReloadOutcome::Applied {
                hash,
                config,
                effective,
            });
        }
        Err(ConfigError::Parse { line, message }) => {
            on_reload(ReloadOutcome::Invalid {
                hash,
                error: message,
                line: Some(line),
            });
        }
        Err(e) => {
            on_reload(ReloadOutcome::Invalid {
                hash,
                error: e.to_string(),
                line: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;

    const VALID: &str = "local:\n  agent:\n    node-name: t\n";

    fn tmp_config(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rooster-watch-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("config.yaml")
    }

    /// 模拟编辑器保存:写 tmp 后 rename。
    fn editor_write(path: &Path, content: &str) {
        let tmp = path.with_extension("swp");
        std::fs::write(&tmp, content).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    /// 连同临时目录删除;只删 config.yaml 会留下空目录。
    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_change_reloads_and_self_write_is_ignored() {
        let path = tmp_config("ext");
        std::fs::write(&path, VALID).unwrap();
        let state = Arc::new(WatcherState::new(hash_content(VALID)));
        let (tx, rx) = std_mpsc::channel::<ReloadOutcome>();

        spawn(path.clone(), state.clone(), move |o| {
            let _ = tx.send(o);
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 外部合法变更 → Applied
        let next = "local:\n  agent:\n    node-name: t2\n";
        editor_write(&path, next);
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            ReloadOutcome::Applied { hash, effective, .. } => {
                assert_eq!(hash, hash_content(next));
                assert_eq!(effective.agent.node_name.as_deref(), Some("t2"));
            }
            other => panic!("expected Applied, got {other:?}"),
        }

        // 自触发:哈希与 last_self_write 相同 → 忽略
        let again = "local:\n  agent:\n    node-name: t3\n";
        *state.last_self_write.lock().unwrap() = hash_content(again);
        editor_write(&path, again);
        assert!(rx.recv_timeout(Duration::from_millis(1200)).is_err());

        cleanup(&path);
    }

    /// 读文件与相同内容回写都不得重放重载(自激循环的根因);
    /// 同时确认真实变更仍能被拾取(过滤没把 watcher 关死)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reads_and_identical_writes_do_not_replay_reload() {
        let path = tmp_config("read");
        std::fs::write(&path, VALID).unwrap();
        let state = Arc::new(WatcherState::new(hash_content(VALID)));
        let (tx, rx) = std_mpsc::channel::<ReloadOutcome>();
        spawn(path.clone(), state.clone(), move |o| {
            let _ = tx.send(o);
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        for _ in 0..3 {
            let _ = std::fs::read_to_string(&path).unwrap();
        }
        std::fs::write(&path, VALID).unwrap();
        assert!(
            rx.recv_timeout(Duration::from_millis(1500)).is_err(),
            "reads and identical writes must not replay a reload"
        );

        let next = "local:\n  agent:\n    node-name: t9\n";
        editor_write(&path, next);
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            ReloadOutcome::Applied { effective, .. } => {
                assert_eq!(effective.agent.node_name.as_deref(), Some("t9"));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        cleanup(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_external_change_keeps_old_config() {
        let path = tmp_config("inv");
        std::fs::write(&path, VALID).unwrap();
        let state = Arc::new(WatcherState::new(hash_content(VALID)));
        let (tx, rx) = std_mpsc::channel::<ReloadOutcome>();

        spawn(path.clone(), state.clone(), move |o| {
            let _ = tx.send(o);
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 非法 yaml → Invalid,current 哈希不变(旧配置继续生效)
        editor_write(&path, "local: [broken\n");
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            ReloadOutcome::Invalid { line, .. } => assert!(line.is_some()),
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert_eq!(*state.current.lock().unwrap(), hash_content(VALID));

        cleanup(&path);
    }
}
