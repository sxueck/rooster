//! 远程升级执行(Agent 半边):下载 → Ed25519 校验 → 备份 →\n//! 原子替换 → 重启;失败路径由 upgrade-guard(ExecStartPre)与\n//! 自检任务回退到 rooster.prev。

use crate::state::AgentState;
use rooster_proto::Event;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// 升级自检标记:重启后 60s 内连上 Hub 才清除;否则回退旧二进制。
pub fn marker_path(state: &Arc<AgentState>) -> PathBuf {
    state
        .effective()
        .agent
        .data_dir()
        .join("upgrade-pending.json")
}

pub fn prev_binary_path() -> Option<PathBuf> {
    let exe = running_exe_path().ok()?;
    Some(exe.with_file_name("rooster.prev"))
}

fn status(state: &Arc<AgentState>, version: &str, stage: &str, detail: Option<String>) {
    state.push_event(Event::UpgradeStatus {
        version: version.to_string(),
        stage: stage.to_string(),
        detail,
    });
}

/// 收到 Upgrade 帧后的执行流程。
pub async fn handle(
    state: &Arc<AgentState>,
    version: &str,
    url: &str,
    signature_b64: &str,
    frame_public_key: Option<&str>,
) {
    status(state, version, "downloading", None);
    // 下载复用 hub 下载通道:hub 下发的是相对路径(/v0/downloads/...),
    // 必须解析到 hub 基地址并携带 mTLS 节点身份;完整性由下方 Ed25519
    // 签名校验保证(与传输通道无关)。
    let bytes = match crate::hubclient::fetch_hub_bytes(state, url).await {
        Ok(b) => b,
        Err(e) => {
            status(state, version, "failed", Some(format!("download: {e}")));
            return;
        }
    };

    // 公钥来源:本地锚点(强)或帧携带(弱,信任 Hub 分发)。
    let eff = state.effective();
    let pinned = eff
        .security
        .upgrade_public_key
        .as_deref()
        .filter(|k| !k.trim().is_empty());
    let key = match (pinned, frame_public_key) {
        (Some(p), Some(f)) if p != f => {
            status(
                state,
                version,
                "failed",
                Some("upgrade public key mismatch with local pin".into()),
            );
            return;
        }
        (Some(p), _) => p,
        (None, Some(f)) => f,
        (None, None) => {
            status(
                state,
                version,
                "failed",
                Some("no upgrade public key available".into()),
            );
            return;
        }
    };
    status(state, version, "verifying", None);
    if let Err(e) = verify_signature(&bytes, signature_b64, key) {
        status(state, version, "failed", Some(format!("signature: {e}")));
        return;
    }

    status(state, version, "applying", None);
    if let Err(e) = swap_binary(state, version, &bytes) {
        status(state, version, "failed", Some(e));
        return;
    }
    status(state, version, "applied", None);

    // 重启前写入标记:新进程自检通过后清除。
    let _ = std::fs::write(
        marker_path(state),
        serde_json::json!({
            "version": version,
            "ts": now_secs(),
        })
        .to_string(),
    );

    match state.effective().upgrade.method {
        rooster_config::UpgradeMethod::Systemd => {
            let _ = tokio::process::Command::new("systemctl")
                .args(["restart", "rooster"])
                .status()
                .await;
        }
        rooster_config::UpgradeMethod::Exit => {
            tracing::info!("upgrade applied, exiting for supervisor restart");
            std::process::exit(0);
        }
        rooster_config::UpgradeMethod::None => {
            // 测试模式:不重启;标记立即清除,自检跳过。
            let _ = std::fs::remove_file(marker_path(state));
        }
    }
}

fn verify_signature(content: &[u8], sig_b64: &str, key: &str) -> Result<(), String> {
    use base64::Engine;
    use ed25519_dalek::Verifier;
    let pk = key
        .strip_prefix("ed25519:")
        .ok_or("public key must be `ed25519:<base64>`")?;
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pk)
        .map_err(|e| format!("bad public key: {e}"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        pk.as_slice().try_into().map_err(|_| "bad public key length")?,
    )
    .map_err(|e| format!("bad public key: {e}"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("bad signature encoding: {e}"))?;
    let sig: ed25519_dalek::Signature =
        sig.as_slice().try_into().map_err(|_| "bad signature length")?;
    vk.verify(content, &sig).map_err(|e| e.to_string())
}

/// 当前二进制在磁盘上的路径。
///
/// 升级失败的真实现场:Linux 下若运行中的 inode 已被删除(典型:管理员重跑
/// install.sh 覆盖了 `/usr/local/bin/rooster`),`current_exe()` 返回
/// `/usr/local/bin/rooster (deleted)` —— 那不是路径。直接拿它备份会报
/// `No such file or directory`,升级永远卡在同一个坑里。这里剥掉标记后缀并
/// 校验路径确实存在,并把失败原因说得可行动。
fn running_exe_path() -> Result<PathBuf, String> {
    let raw = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let candidate = strip_deleted_suffix(&raw);
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(format!(
        "running binary {} does not exist on disk; reinstall the agent before upgrading",
        candidate.display()
    ))
}

/// 剥掉 `current_exe()` 在 inode 被覆盖后追加的 `" (deleted)"` 标记。
fn strip_deleted_suffix(raw: &Path) -> PathBuf {
    match raw.to_str() {
        Some(s) if s.ends_with(DELETED_MARK) => PathBuf::from(&s[..s.len() - DELETED_MARK.len()]),
        _ => raw.to_path_buf(),
    }
}

const DELETED_MARK: &str = " (deleted)";

/// 备份当前二进制 → 原子替换。
fn swap_binary(state: &Arc<AgentState>, version: &str, bytes: &[u8]) -> Result<(), String> {
    let exe = running_exe_path()?;
    let dir = exe
        .parent()
        .ok_or_else(|| "exe has no parent dir".to_string())?
        .to_path_buf();

    let _ = state; // 版本号只用于日志/事件
    // 备份(覆盖旧 prev)。
    let prev = dir.join("rooster.prev");
    std::fs::copy(&exe, &prev)
        .map_err(|e| format!("backup {} -> {}: {e}", exe.display(), prev.display()))?;

    // 写临时文件 → fsync → rename(与配置写入同款原子性)。
    let tmp = dir.join(format!(".rooster.new-{version}"));
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create tmp: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write tmp: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync tmp: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, &exe).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

/// 回退到 rooster.prev(ExecStartPre 守护 / 自检失败共用)。
pub fn restore_previous() -> Result<bool, String> {
    let Some(prev) = prev_binary_path() else {
        return Ok(false);
    };
    if !prev.exists() {
        return Ok(false);
    }
    let exe = running_exe_path()?;
    restore_into(&prev, &exe)
}

/// tmp + rename 原语:直接 `fs::copy` 到正在运行的 exe 会 ETXTBSY(Linux
/// 对正在执行的文件拒绝写打开);rename 覆盖运行中的 exe 是合法的,运行
/// 中进程继续用旧 inode,下次启动就是新内容。
fn restore_into(prev: &std::path::Path, exe: &std::path::Path) -> Result<bool, String> {
    if !prev.exists() {
        return Ok(false);
    }
    let dir = exe
        .parent()
        .ok_or_else(|| "exe has no parent dir".to_string())?
        .to_path_buf();
    // 同目录 tmp:rename 必须落在同一文件系统上才能原子替换。
    let tmp = dir.join(".rooster.restore-tmp");
    std::fs::copy(prev, &tmp).map_err(|e| format!("stage restore: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, exe).map_err(|e| format!("restore rename: {e}"))?;
    Ok(true)
}

/// `rooster upgrade-guard --data-dir`:systemd ExecStartPre 钩子。
/// 标记存在且超过宽限期 → 上次升级失败,回退旧二进制。
pub fn guard(data_dir: &std::path::Path) -> i32 {
    let marker = data_dir.join("upgrade-pending.json");
    let Ok(raw) = std::fs::read_to_string(&marker) else {
        return 0;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        let _ = std::fs::remove_file(&marker);
        return 0;
    };
    let ts = v["ts"].as_u64().unwrap_or(0);
    let version = v["version"].as_str().unwrap_or("?");
    // 宽限 90s:新进程正常时应已自检清除;仍存在说明上次启动即失败。
    if now_secs().saturating_sub(ts) > 90 {
        match restore_previous() {
            Ok(true) => {
                let _ = std::fs::remove_file(&marker);
                eprintln!("upgrade-guard: rolled back to rooster.prev (version {version} failed)");
            }
            Ok(false) => {
                let _ = std::fs::remove_file(&marker);
                eprintln!("upgrade-guard: no rooster.prev to roll back to");
            }
            Err(e) => {
                eprintln!("upgrade-guard: rollback failed: {e}");
                return 1;
            }
        }
    }
    0
}

/// 启动时自检:标记存在 → 60s 内连上 Hub 则清除标记,
/// 否则回退并退出(由 systemd 拉起旧版本)。
pub fn spawn_self_check(state: Arc<AgentState>) {
    let marker = marker_path(&state);
    if !marker.exists() {
        return;
    }
    tokio::spawn(async move {
        let mut rx = state.hub_connected.subscribe();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let ok = tokio::select! {
            changed = rx.changed() => {
                changed.is_ok() && *rx.borrow_and_update()
            }
            _ = tokio::time::sleep_until(deadline) => false,
        };
        if ok {
            let _ = std::fs::remove_file(marker_path(&state));
            tracing::info!("upgrade self-check passed (hub reachable)");
        } else {
            tracing::error!("upgrade self-check failed, rolling back to rooster.prev");
            rollback_on_failed_self_check(&marker_path(&state));
            std::process::exit(1);
        }
    });
}

/// 自检失败后的回退(A5):只有回退真正落盘(或确实无 prev 可回退)才清
/// 标记;回退失败时保留标记,让下一次 ExecStartPre guard 再试一次,否则
/// 一次暂时性失败就会把“需要回退”这件事永久丢失。
fn rollback_on_failed_self_check(marker: &std::path::Path) {
    match restore_previous() {
        Ok(true) => {
            let _ = std::fs::remove_file(marker);
            tracing::info!("rolled back to rooster.prev");
        }
        Ok(false) => {
            let _ = std::fs::remove_file(marker);
            tracing::warn!("no rooster.prev to roll back to, clearing upgrade marker");
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "rollback to rooster.prev failed, keeping upgrade marker for guard retry"
            );
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    /// restore_previous/guard 都作用于 current_exe 同目录的 rooster.prev,
    /// 相关测试串行以免互相干扰。
    static PREV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn signature_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        use base64::Engine;
        let sk = SigningKey::generate(&mut rand::rng());
        let vk_b64 = base64::engine::general_purpose::STANDARD
            .encode(sk.verifying_key().to_bytes());
        let key = format!("ed25519:{vk_b64}");
        let content = b"fake-binary-bytes";
        let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(content).to_bytes());
        assert!(verify_signature(content, &sig, &key).is_ok());
        assert!(verify_signature(b"tampered", &sig, &key).is_err());
        assert!(verify_signature(content, "not-base64!", &key).is_err());
        assert!(verify_signature(content, &sig, "rawkey").is_err());
    }

    #[test]
    fn guard_cleans_stale_marker() {
        let _guard = PREV_LOCK.lock().unwrap();
        ensure_no_prev();
        let dir = std::env::temp_dir().join(format!("rooster-guard-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let marker = dir.join("upgrade-pending.json");
        std::fs::write(
            &marker,
            serde_json::json!({"version": "9.9.9", "ts": now_secs() - 1000}).to_string(),
        )
        .unwrap();
        // 没有 rooster.prev:标记被清,不回退,退出码 0。
        assert_eq!(guard(&dir), 0);
        assert!(!marker.exists());
    }

    /// 重跑 install.sh 覆盖运行中的二进制后,current_exe() 带 " (deleted)"
    /// 后缀;不剥掉它,备份/回退都会指向一个不存在的路径(靶场实测的失败)。
    #[test]
    fn deleted_exe_marker_is_stripped() {
        assert_eq!(
            strip_deleted_suffix(Path::new("/usr/local/bin/rooster (deleted)")),
            PathBuf::from("/usr/local/bin/rooster")
        );
        // 正常路径与含空格目录都不该被动。
        assert_eq!(
            strip_deleted_suffix(Path::new("/opt/my dir/rooster")),
            PathBuf::from("/opt/my dir/rooster")
        );
    }

    fn exe_prev_path() -> PathBuf {
        std::env::current_exe()
            .unwrap()
            .with_file_name("rooster.prev")
    }

    fn ensure_no_prev() {
        let prev = exe_prev_path();
        if prev.is_dir() {
            let _ = std::fs::remove_dir_all(&prev);
        } else if prev.exists() {
            let _ = std::fs::remove_file(&prev);
        }
    }

    /// A5:回退必须能在 exe 正在运行时成功 —— 直接 copy 会 ETXTBSY,
    /// tmp+rename 才合法。用一个"正在被执行"的副本当目标。
    /// 注意:coreutils 的 sleep/tail 是多调用二进制,按 argv[0] 派发,
    /// 复制后立刻退出 → 没有 busy inode,前提就不成立了;bash 忽略 argv[0],
    /// 且 `read` 是内置命令,阻塞在父进程持有的管道 stdin 上。
    #[test]
    fn restore_replaces_running_executable_via_rename() {
        let shell = "/bin/bash";
        if !std::path::Path::new(shell).exists() {
            eprintln!("no /bin/bash; skipping ETXTBSY test");
            return;
        }
        let dir = std::env::temp_dir()
            .join(format!("rooster-restore-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("agent-under-test");
        std::fs::copy(std::fs::canonicalize(shell).unwrap(), &exe).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut child = std::process::Command::new(&exe)
            .arg("--norc")
            .arg("--noprofile")
            .arg("-c")
            .arg("read -t 20 x")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(
            child.try_wait().unwrap().is_none(),
            "test premise: the copy must still be executing"
        );

        let prev = dir.join("rooster.prev");
        std::fs::write(&prev, b"previous-binary").unwrap();
        // 旧实现的行为:直接 copy 到运行中的 exe → ETXTBSY(errno 26)。
        let direct = std::fs::copy(&prev, &exe);
        assert!(direct.is_err(), "copy onto a running exe must fail");
        assert_eq!(direct.unwrap_err().raw_os_error(), Some(26), "expected ETXTBSY");

        // tmp+rename:成功替换运行中 exe 的内容,并保持 0755。
        assert!(restore_into(&prev, &exe).unwrap());
        assert_eq!(std::fs::read(&exe).unwrap(), b"previous-binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A5:自检失败的回退没落盘时必须保留标记(供 ExecStartPre guard 重试),
    /// 只有成功(或无 prev 可回退)才清标记。
    #[test]
    fn self_check_rollback_marker_semantics() {
        let _guard = PREV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("rooster-selfcheck-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let marker = dir.join("upgrade-pending.json");
        std::fs::write(&marker, "{}").unwrap();

        // 分支 1:无 rooster.prev → 清标记(避免无限重启循环)。
        ensure_no_prev();
        rollback_on_failed_self_check(&marker);
        assert!(!marker.exists(), "无 prev 可回退时清标记");

        // 分支 2:回退失败(prev 损坏,如被写成了目录)→ 保留标记。
        std::fs::write(&marker, "{}").unwrap();
        let prev = exe_prev_path();
        std::fs::create_dir_all(&prev).unwrap(); // copy 读目录 → Err
        rollback_on_failed_self_check(&marker);
        assert!(marker.exists(), "回退失败时必须保留标记供 guard 重试");
        let _ = std::fs::remove_dir_all(&prev);
    }
}
