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
    Some(prev_path_for(&exe))
}

/// 回滚备份路径:`<exe 同目录>/<exe 文件名 stem>.prev`。显式目标
/// (容器守卫 `--binary`)与自备份使用同一规则,保证能对上。
pub fn prev_path_for(exe: &Path) -> PathBuf {
    let stem = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("rooster");
    exe.with_file_name(format!("{stem}.prev"))
}

fn status(state: &Arc<AgentState>, version: &str, stage: &str, detail: Option<String>) {
    state.push_event(Event::UpgradeStatus {
        version: version.to_string(),
        stage: stage.to_string(),
        detail,
    });
}

/// 进度节流:已知总长按 10% 步进上报,未知按 16MiB 步进。返回
/// (新标记, 本次 detail);标记不前进则不上报。纯函数,便于单测。
fn download_progress_detail(last: u64, loaded: u64, total: Option<u64>) -> (u64, Option<String>) {
    const MIB: u64 = 1024 * 1024;
    match total.filter(|t| *t > 0) {
        Some(total) => {
            let pct = (loaded * 100 / total).min(100);
            if pct >= last + 10 || (pct == 100 && last < 100) {
                (pct, Some(format!("{pct}%")))
            } else {
                (last, None)
            }
        }
        None => {
            let step = loaded / (16 * MIB);
            if step > last {
                (
                    step,
                    Some(format!("{:.1} MiB", loaded as f64 / MIB as f64)),
                )
            } else {
                (last, None)
            }
        }
    }
}

/// 收到 Upgrade 帧后的执行流程。整段持 `upgrade_lock`:备份 prev → 写
/// marker → 原子替换必须串行,否则并发升级会互相覆盖回滚备份或交错
/// rename(后到者把先到者的新二进制当旧版本备份走)。
pub async fn handle(
    state: &Arc<AgentState>,
    version: &str,
    url: &str,
    signature_b64: &str,
    frame_public_key: Option<&str>,
) {
    let _upgrade_guard = state.upgrade_lock.lock().await;
    status(state, version, "downloading", None);
    // 下载复用 hub 下载通道:hub 下发的是相对路径(/v0/downloads/...),
    // 必须解析到 hub 基地址并携带 mTLS 节点身份;完整性由下方 Ed25519
    // 签名校验保证(与传输通道无关)。进度按 10%/16MiB 节流上报,
    // 否则几十 MB 的包会刷屏事件流。
    let mut last_marker: u64 = 0;
    let fetch_state = state.clone();
    let fetch_version = version.to_string();
    let bytes = match crate::hubclient::fetch_hub_bytes_with_progress(state, url, move |loaded, total| {
        let (marker, detail) = download_progress_detail(last_marker, loaded, total);
        if let Some(d) = detail {
            status(&fetch_state, &fetch_version, "downloading", Some(d));
        }
        last_marker = marker;
    })
    .await
    {
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

    // marker 已在 swap_binary 内于替换前原子落盘;此处无需重写。
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

/// 版本号只允许出现在同目录临时文件名里:过滤到 [A-Za-z0-9._-],
/// 超长截断 —— Hub 下发的 version 是外部输入,不清洗会拼出
/// `../../` 或带 `/` 的路径(路径注入)。
fn sanitize_version_component(version: &str) -> String {
    let mut s: String = version
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        s.push_str("unknown");
    }
    s
}

/// 备份当前二进制 → 原子替换。marker 必须在新二进制 rename 提交**之前**
/// 原子落盘且不容忍失败:否则崩溃窗口内新二进制已生效却没有回滚凭据。
fn swap_binary(state: &Arc<AgentState>, version: &str, bytes: &[u8]) -> Result<(), String> {
    let exe = running_exe_path()?;
    apply_bytes(&exe, bytes, version, &marker_path(state))
}

/// 纯文件操作版升级提交(便于单测):备份 → 写新二进制临时文件 →
/// **原子持久化 marker** → rename 提交。marker 失败则删除临时文件并
/// 报错,绝不提交新二进制(fail-closed)。
fn apply_bytes(exe: &Path, bytes: &[u8], version: &str, marker: &Path) -> Result<(), String> {
    let dir = exe
        .parent()
        .ok_or_else(|| "exe has no parent dir".to_string())?
        .to_path_buf();

    if marker.exists() {
        return Err("another upgrade is pending self-check or rollback".into());
    }
    // Stage the backup so an interrupted copy cannot destroy the last rollback image.
    let prev = prev_path_for(exe);
    let staged_prev = dir.join(".rooster.prev-tmp");
    std::fs::copy(exe, &staged_prev).map_err(|e| format!("backup: {e}"))?;
    std::fs::File::open(&staged_prev).and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync backup: {e}"))?;
    std::fs::rename(&staged_prev, &prev).map_err(|e| format!("commit backup: {e}"))?;
    sync_directory(&dir)?;

    // 写临时文件 → fsync → rename(与配置写入同款原子性)。
    let tmp = dir.join(format!(".rooster.new-{}", sanitize_version_component(version)));

    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create tmp: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write tmp: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod staged executable: {e}"))?;
    }
    f.sync_all().map_err(|e| format!("fsync tmp: {e}"))?;
    // 提交前先落回滚凭据:原子写失败 → 放弃本次升级,保留旧二进制。
    if let Err(e) = persist_marker(marker, version) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("persist upgrade marker {}: {e}", marker.display()));
    }
    std::fs::rename(&tmp, exe).map_err(|e| format!("rename: {e}"))?;
    sync_directory(&dir)
}

/// 原子写升级标记(tmp → fsync → rename);失败必须上抛,不得忽略。
fn persist_marker(marker: &Path, version: &str) -> Result<(), String> {
    let dir = marker
        .parent()
        .ok_or_else(|| "marker has no parent dir".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = dir.join(".upgrade-pending.json.tmp");
    let body = serde_json::json!({ "version": version, "ts": now_secs() }).to_string();
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create: {e}"))?;
    f.write_all(body.as_bytes()).map_err(|e| format!("write: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    std::fs::rename(&tmp, marker).map_err(|e| format!("rename: {e}"))?;
    sync_directory(dir)
}

fn sync_directory(dir: &Path) -> Result<(), String> {
    // fsync the directory as well: file fsync alone does not persist the rename after a crash.
    #[cfg(unix)]
    std::fs::File::open(dir).and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync directory {}: {e}", dir.display()))?;
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
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod restored executable: {e}"))?;
    }
    std::fs::File::open(&tmp).and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync restored executable: {e}"))?;
    std::fs::rename(&tmp, exe).map_err(|e| format!("restore rename: {e}"))?;
    sync_directory(&dir)?;
    Ok(true)
}

/// `rooster agent upgrade-guard --data-dir [--binary]`:systemd
/// ExecStartPre / 容器监督进程的启动前钩子。
/// - 无 `--binary`(systemd):回退对象是本进程 exe 旁的 `rooster.prev`;
/// - 有 `--binary`(容器,守护进程是不可变 /usr/local/bin/rooster,
///   Agent 是可变 /var/lib/rooster/bin/rooster):回退对象是该显式路径
///   及其 `<stem>.prev`。新二进制“无法执行”时 Agent 进程永远起不来,
///   自检永远不清 marker —— 因此目标缺失/不可执行时立即回退,不等宽限期。
pub fn guard(data_dir: &std::path::Path, binary: Option<&std::path::Path>) -> i32 {
    let marker = data_dir.join("upgrade-pending.json");
    let raw = match std::fs::read_to_string(&marker) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            eprintln!("upgrade-guard: cannot read pending marker: {e}");
            return 1;
        }
    };
    let v = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("upgrade-guard: invalid pending marker: {e}");
            return 1;
        }
    };
    let ts = v["ts"].as_u64().unwrap_or(0);
    let version = v["version"].as_str().unwrap_or("?");
    // 宽限 90s:新进程正常时应已自检清除;仍存在说明上次启动即失败。
    let stale = now_secs().saturating_sub(ts) > 90;
    // 显式目标:文件缺失或无执行位 → 新二进制不可能跑起来清 marker,
    // 立即回退而不是空转 90s 崩溃循环。(二进制有 +x 但内容损坏的
    // 情况由宽限期兜底:自检失败保留 marker,下次 guard 回退。)
    let target_broken = binary.is_some_and(|b| !is_executable_file(b));
    if !stale && !target_broken {
        return 0;
    }
    let restore = match binary {
        Some(b) => restore_into(&prev_path_for(b), b),
        None => restore_previous(),
    };
    match restore {
        Ok(true) => {
            let _ = std::fs::remove_file(&marker);
            eprintln!("upgrade-guard: rolled back to previous binary (version {version} failed)");
        }
        Ok(false) => {
            eprintln!("upgrade-guard: no previous binary to roll back to");
            if binary.is_some() {
                return 1;
            }
            let _ = std::fs::remove_file(&marker);
        }
        Err(e) => {
            // 回退失败保留 marker(下次 guard 重试),退出码 1 交监督方处置。
            eprintln!("upgrade-guard: rollback failed: {e}");
            return 1;
        }
    }
    0
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
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
        // 订阅时可能已经连上 Hub,先读当前值以免一直等待 changed()。
        // 瞬时断线不是终态:继续等待重连或超时。
        let ok = 'wait: {
            if *rx.borrow() {
                break 'wait true;
            }
            loop {
                tokio::select! {
                    changed = rx.changed() => {
                        if changed.is_err() {
                            break 'wait false; // watch sender 已销毁
                        }
                        if *rx.borrow_and_update() {
                            break 'wait true;
                        }
                        // 瞬时断线:继续等直到 deadline。
                    }
                    _ = tokio::time::sleep_until(deadline) => break 'wait false,
                }
            }
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
    fn download_progress_throttles_by_percent_and_mib() {
        let total = Some(100 * 1024 * 1024);
        // 9% 不报,10% 报;之后每 +10% 一报
        assert_eq!(download_progress_detail(0, 9 * 1024 * 1024, total).1, None);
        assert_eq!(download_progress_detail(0, 10 * 1024 * 1024, total).1.as_deref(), Some("10%"));
        let (m, d) = download_progress_detail(10, 19 * 1024 * 1024, total);
        assert_eq!(d, None, "same bucket stays silent");
        assert_eq!(m, 10);
        assert_eq!(download_progress_detail(90, 100 * 1024 * 1024, total).1.as_deref(), Some("100%"));
        // 未知总长:16MiB 步进
        let (m, d) = download_progress_detail(0, 17 * 1024 * 1024, None);
        assert_eq!(m, 1);
        assert_eq!(d.as_deref(), Some("17.0 MiB"));
        assert_eq!(download_progress_detail(1, 17 * 1024 * 1024, None).1, None);
        // total=0 视为未知,除零保护
        let (m, _) = download_progress_detail(0, 1, Some(0));
        assert_eq!(m, 0);
    }

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
        assert_eq!(guard(&dir, None), 0);
        assert!(!marker.exists());
    }

    fn write_marker(dir: &std::path::Path, ts: u64) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let marker = dir.join("upgrade-pending.json");
        std::fs::write(
            &marker,
            serde_json::json!({"version": "1.0.0-container", "ts": ts}).to_string(),
        )
        .unwrap();
        marker
    }

    /// 容器守护(guard 自身是不可变二进制,不看 current_exe):
    /// `--binary` 显式指定 Agent 可执行文件,stale marker → 从
    /// `<binary>.prev` 恢复到显式目标并清标记。
    #[test]
    fn guard_restores_explicit_target_from_prev() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-guard-target-{}-{}", std::process::id(), rand::random::<u64>()));
        let bin = dir.join("bin").join("rooster");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"new-broken").unwrap();
        std::fs::write(prev_path_for(&bin), b"old-good").unwrap();
        let marker = write_marker(&dir.join("data"), now_secs() - 1000);

        assert_eq!(guard(&dir.join("data"), Some(&bin)), 0);
        assert_eq!(std::fs::read(&bin).unwrap(), b"old-good");
        assert!(!marker.exists(), "成功回退后必须清 marker");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 新二进制“无法执行”(这里模拟缺失执行位;文件缺失同理):Agent
    /// 进程永远起不来清 marker,守护必须立即回退而不是空等 90s 宽限。
    #[test]
    fn guard_restores_broken_target_without_waiting_grace() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-guard-exec-{}-{}", std::process::id(), rand::random::<u64>()));
        let bin = dir.join("bin").join("rooster");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"garbage-no-exec-bit").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::write(prev_path_for(&bin), b"old-good").unwrap();
        // ts=now:宽限期内;若只看宽限会直接返回 0 不回退。
        let marker = write_marker(&dir.join("data"), now_secs());

        assert_eq!(guard(&dir.join("data"), Some(&bin)), 0);
        assert_eq!(std::fs::read(&bin).unwrap(), b"old-good");
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// fail-closed:回退本身失败(prev 不可读)→ 保留 marker 供下次
    // guard 重试,退出码 1。
    #[test]
    fn guard_fails_closed_when_explicit_rollback_fails() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-guard-fail-{}-{}", std::process::id(), rand::random::<u64>()));
        let bin = dir.join("bin").join("rooster");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"new-broken").unwrap();
        // prev 是目录:fs::copy 读它必失败。
        std::fs::create_dir_all(prev_path_for(&bin)).unwrap();
        let marker = write_marker(&dir.join("data"), now_secs() - 1000);

        assert_eq!(guard(&dir.join("data"), Some(&bin)), 1);
        assert!(marker.exists(), "回退失败必须保留 marker 供重试");
        assert_eq!(std::fs::read(&bin).unwrap(), b"new-broken");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// fail-closed:marker 无法原子落盘(data-dir 被占位文件堵住)→
    /// 升级必须在提交新二进制之前放弃,旧二进制原封不动,临时文件清理。
    #[test]
    fn apply_bytes_fails_closed_when_marker_cannot_persist() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-marker-fail-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("rooster");
        std::fs::write(&exe, b"old-binary").unwrap();
        // 占位文件使 marker 的父目录无法创建。
        std::fs::write(dir.join("data"), b"not-a-dir").unwrap();
        let marker = dir.join("data").join("upgrade-pending.json");

        let err = apply_bytes(&exe, b"new-binary", "2.0.0", &marker).unwrap_err();
        assert!(err.contains("marker"), "错误应指向 marker 持久化: {err}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old-binary", "不得提交新二进制");
        assert_eq!(std::fs::read(prev_path_for(&exe)).unwrap(), b"old-binary");
        assert!(!dir.join(".rooster.new-2.0.0").exists(), "临时文件应清理");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_upgrade_preserves_rollback_backup() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-pending-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("rooster");
        let marker = dir.join("upgrade-pending.json");
        std::fs::write(&exe, b"current").unwrap();
        std::fs::write(prev_path_for(&exe), b"previous").unwrap();
        std::fs::write(&marker, b"pending").unwrap();
        assert!(apply_bytes(&exe, b"next", "3.0.0", &marker).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"current");
        assert_eq!(std::fs::read(prev_path_for(&exe)).unwrap(), b"previous");
        assert_eq!(std::fs::read(&marker).unwrap(), b"pending");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn explicit_guard_retains_marker_when_backup_missing_or_marker_invalid() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-guard-missing-{}", rand::random::<u64>()));
        let marker = write_marker(&dir, now_secs() - 1000);
        let binary = dir.join("rooster");
        assert_eq!(guard(&dir, Some(&binary)), 1);
        assert!(marker.exists());
        std::fs::write(&marker, b"invalid-json").unwrap();
        assert_eq!(guard(&dir, Some(&binary)), 1);
        assert!(marker.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 正常路径:marker 在提交前原子落盘;成功后 exe 是新内容,
    /// prev 是旧内容,marker 携带版本与时间戳。
    #[test]
    fn apply_bytes_commits_only_after_marker_persisted() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-marker-ok-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("rooster");
        std::fs::write(&exe, b"old-binary").unwrap();
        let data = dir.join("data");
        let marker = data.join("upgrade-pending.json");

        apply_bytes(&exe, b"new-binary", "2.0.0", &marker).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new-binary");
        assert_eq!(std::fs::read(prev_path_for(&exe)).unwrap(), b"old-binary");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&marker).unwrap()).unwrap();
        assert_eq!(v["version"].as_str(), Some("2.0.0"));
        assert!(v["ts"].as_u64().unwrap() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Hub 下发的 version 是外部输入:临时文件名必须清洗掉路径分隔符,
    /// 否则 `.rooster.new-../../x` 会写到 exe 目录之外(路径注入)。
    #[test]
    fn version_component_is_sanitized() {
        assert_eq!(sanitize_version_component("1.2.3"), "1.2.3");
        assert_eq!(sanitize_version_component("../../pwned"), ".._.._pwned");
        assert!(!sanitize_version_component("a/b\\c").contains('/'));
        assert!(!sanitize_version_component("a/b\\c").contains('\\'));
        assert_eq!(sanitize_version_component(""), "unknown");
        assert!(sanitize_version_component(&"x".repeat(200)).len() <= 64);
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
        prev_path_for(&std::env::current_exe().unwrap())
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
