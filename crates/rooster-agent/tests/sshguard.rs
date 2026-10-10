//! ssh-guard 集成测试:
//! 1. [`Judge`] 滑窗判定 / 递增封禁 / 窗口修剪 / 多 IP 独立(纯逻辑,注入 Instant);
//! 2. [`builtin_patterns`] 对真实 sshd 日志行的匹配与噪声排除;
//! 3. 文件源端到端:tail 从 END 开始,只统计新行,追加触发封禁 + Ban 事件。

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rooster_agent::sshguard::{
    builtin_patterns, extract_journal_message, run_file_tail, BanSink, Judge,
};
use rooster_config::schema::{SshGuardConfig, SshLogSource};
use rooster_nft::{BanEntry, BanScope, NftError};
use rooster_proto::Event;

const IP: &str = "203.0.113.5";
const BAN_1H: Duration = Duration::from_secs(3600);
const BAN_2H: Duration = Duration::from_secs(2 * 3600);
const BAN_7D: Duration = Duration::from_secs(7 * 24 * 3600);

/// 默认值:max_retry=5,find_time=10m,ban_time=1h,×2,上限 7d。
fn test_cfg() -> SshGuardConfig {
    SshGuardConfig {
        enabled: true,
        port: 22,
        source: SshLogSource::File,
        max_retry: 5,
        find_time: Some(Duration::from_secs(600)),
        ban_time: Some(BAN_1H),
        ban_time_factor: 2,
        ban_time_max: Some(BAN_7D),
        conn_rate: "10/minute".to_string(),
        conn_burst: 5,
    }
}

fn unique_tmp(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rooster-sshguard-{name}-{}-{nanos}.log", std::process::id()))
}

/// 记录收到的封禁条目的 mock(判定结果的落地验证)。
#[derive(Default)]
struct MockBanSink {
    bans: Mutex<Vec<BanEntry>>,
}

impl BanSink for MockBanSink {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError> {
        self.bans.lock().unwrap().push(entry.clone());
        Ok(())
    }
}

impl MockBanSink {
    fn bans(&self) -> Vec<BanEntry> {
        self.bans.lock().unwrap().clone()
    }
}

/// 始终拒绝封禁的 mock(验证错误路径不 panic、不发事件)。
struct FailingBanSink;

impl BanSink for FailingBanSink {
    fn apply_ban(&self, _entry: &BanEntry) -> Result<(), NftError> {
        Err(NftError::Netlink("simulated netlink failure".to_string()))
    }
}

/// 第 5 次失败触发第 1 次封禁(1h);窗口清空后重新攒满 → 2h → 4h …,
/// 到 7d 上限后不再增长。
#[test]
fn judge_escalates_and_caps_ttl() {
    let cfg = test_cfg();
    let mut judge = Judge::new(&cfg);
    let t0 = Instant::now();
    let mut t = t0;
    let step = |t: &mut Instant, secs: u64| {
        *t += Duration::from_secs(secs);
        *t
    };
    // 第 1 次封禁:4 次 None,第 5 次 Some(1h)。
    for _ in 0..4 {
        assert_eq!(judge.on_failure(IP, step(&mut t, 1)), None);
    }
    assert_eq!(judge.on_failure(IP, step(&mut t, 1)), Some(BAN_1H));
    // 递增:2h → 4h → …,封禁计数进程内永不重置,直到 7d 上限。
    let mut expect = BAN_2H;
    loop {
        for _ in 0..4 {
            assert_eq!(judge.on_failure(IP, step(&mut t, 1)), None);
        }
        assert_eq!(judge.on_failure(IP, step(&mut t, 1)), Some(expect));
        if expect >= BAN_7D {
            break;
        }
        expect = (expect * 2).min(BAN_7D);
    }
    // 已到上限:再次触发仍是 7d(上限兜底,不再增长)。
    for _ in 0..4 {
        assert_eq!(judge.on_failure(IP, step(&mut t, 1)), None);
    }
    assert_eq!(judge.on_failure(IP, step(&mut t, 1)), Some(BAN_7D));
}

/// 滑窗修剪——超过 find_time 的失败不计入阈值;封禁后窗口清空。
#[test]
fn judge_window_prunes_old_failures() {
    let mut cfg = test_cfg();
    cfg.find_time = Some(Duration::from_secs(100));
    let mut judge = Judge::new(&cfg);
    let t0 = Instant::now();
    // 四次失败彼此相隔 200s(> find_time=100s),每次窗口都只剩 1 条 → 全部 None。
    for i in 0..4u32 {
        let now = t0 + Duration::from_secs(u64::from(i) * 200);
        assert_eq!(judge.on_failure(IP, now), None);
    }
    // 紧接着 3 条密集失败(窗口内累计 4 条)→ 仍 None;第 5 条(总计第 8 次)
    // 达到阈值才封——若没有修剪,第 5 次总失败(610s 处)早就触发了。
    for i in 1..=3u32 {
        let now = t0 + Duration::from_secs(600 + u64::from(i) * 10);
        assert_eq!(judge.on_failure(IP, now), None);
    }
    assert_eq!(judge.on_failure(IP, t0 + Duration::from_secs(640)), Some(BAN_1H));
    // 封禁后窗口已清空:下一次失败重新计数,不封。
    assert_eq!(judge.on_failure(IP, t0 + Duration::from_secs(650)), None);
}

/// 不同 IP 的窗口与封禁计数互不影响。
#[test]
fn judge_tracks_ips_independently() {
    let cfg = test_cfg();
    let mut judge = Judge::new(&cfg);
    let t0 = Instant::now();
    for i in 0..4u32 {
        let now = t0 + Duration::from_secs(u64::from(i));
        assert_eq!(judge.on_failure("1.1.1.1", now), None);
        assert_eq!(judge.on_failure("2.2.2.2", now), None);
    }
    // 各自的第 5 次失败分别触发封禁,互不借用计数。
    assert_eq!(judge.on_failure("2.2.2.2", t0 + Duration::from_secs(4)), Some(BAN_1H));
    assert_eq!(judge.on_failure("1.1.1.1", t0 + Duration::from_secs(4)), Some(BAN_1H));
    // 封禁后各自窗口清空。
    assert_eq!(judge.on_failure("1.1.1.1", t0 + Duration::from_secs(5)), None);
    assert_eq!(judge.on_failure("2.2.2.2", t0 + Duration::from_secs(5)), None);
}

/// 六条内置规则各匹配真实 sshd 日志行(含 journald JSON 包装),
/// 捕获组即攻击者 IP;成功登录等噪声不得匹配。
#[test]
fn builtin_patterns_match_real_sshd_lines() {
    let patterns = builtin_patterns();
    assert_eq!(patterns.len(), 6);
    let hit = |line: &str| -> Option<(&'static str, IpAddr)> {
        patterns.iter().find_map(|p| {
            p.regex
                .captures(line)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse::<IpAddr>().ok())
                .map(|ip| (p.kind, ip))
        })
    };
    // journald JSON 包装:先解出 MESSAGE 再匹配(与 journald 采集同一路径)。
    let journal_line = r#"{"__REALTIME_TIMESTAMP":"1730000000000000","MESSAGE":"Failed password for invalid user admin from 203.0.113.5 port 41234 ssh2"}"#;
    let msg = extract_journal_message(journal_line).expect("MESSAGE must be extracted");
    assert_eq!(
        hit(&msg),
        Some(("failed-password", "203.0.113.5".parse().unwrap()))
    );
    let cases: &[(&str, &str, &str)] = &[
        (
            "Failed password for invalid user admin from 203.0.113.5 port 41234 ssh2",
            "failed-password",
            "203.0.113.5",
        ),
        // 同一行含 "invalid user":按规则顺序归为 failed-password。
        (
            "Failed password for root from 192.0.2.1 port 22 ssh2",
            "failed-password",
            "192.0.2.1",
        ),
        (
            "Invalid user oracle from 198.51.100.7 port 55555",
            "invalid-user",
            "198.51.100.7",
        ),
        (
            "Connection closed by authenticating user root 192.0.2.9 port 51234 [preauth]",
            "closed-preauth",
            "192.0.2.9",
        ),
        (
            "Connection closed by invalid user foo 192.0.2.9 port 51234 [preauth]",
            "closed-preauth",
            "192.0.2.9",
        ),
        (
            "Disconnected from authenticating user admin 203.0.113.5 port 41234 [preauth]",
            "disconnected-preauth",
            "203.0.113.5",
        ),
        (
            "Disconnected from user admin 203.0.113.5 port 41234 [preauth]",
            "disconnected-preauth",
            "203.0.113.5",
        ),
        (
            "maximum authentication attempts exceeded for root from 198.51.100.7 port 41001 ssh2 [preauth]",
            "max-auth",
            "198.51.100.7",
        ),
        (
            "banner exchange: connection from 203.0.113.99: invalid format",
            "banner-exchange",
            "203.0.113.99",
        ),
    ];
    for (line, kind, ip) in cases {
        assert_eq!(hit(line), Some((*kind, ip.parse().unwrap())), "line: {line}");
    }
    // 噪声(成功登录仅展示)不得匹配任何规则。
    for line in [
        "Accepted publickey for deploy from 10.0.0.5 port 40122 ssh2",
        "systemd[1]: Started OpenBSD Secure Shell server.",
        "CRON[1234]: (root) CMD (run-parts)",
        "PAM unix(sudo:session): session opened for user root",
    ] {
        assert_eq!(hit(line), None, "noise must not match: {line}");
    }
    // 捕获组不是 IP(hostname)→ 整行忽略(<IP> 校验)。
    assert_eq!(hit("Failed password for admin from bastion.corp port 22 ssh2"), None);
}

/// 端到端:文件源从 END 开始 tail——历史 4 行不触发封禁,追加的第 5 行
/// (max_retry=1)触发封禁 + Ban 事件;临时文件用后清理。
#[tokio::test]
async fn file_tail_bans_after_appended_line() {
    let path = unique_tmp("e2e");
    let history = [
        "Failed password for root from 203.0.113.10 port 40001 ssh2",
        "Failed password for root from 203.0.113.10 port 40002 ssh2",
        "Invalid user oracle from 203.0.113.10 port 40003",
        "Failed password for root from 203.0.113.10 port 40004 ssh2",
    ]
    .join("\n");
    std::fs::write(&path, history + "\n").unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let bans = Arc::new(MockBanSink::default());
    let mut cfg = test_cfg();
    cfg.max_retry = 1; // 追加 1 行新失败即达阈值,便于端到端验证
    let task = tokio::spawn(run_file_tail(
        path.clone(),
        cfg,
        "test-node".to_string(),
        bans.clone() as Arc<dyn BanSink>,
        tx,
    ));

    // 等 tailer 打开文件并定位到 END(轮询间隔 500ms,1.2s 足够)。
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    use std::io::Write;
    writeln!(&mut f, "Failed password for root from 203.0.113.77 port 40123 ssh2").unwrap();
    drop(f);

    // 最多等 5s:封禁记录与 Ban 事件都应到达。
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut event = None;
    while Instant::now() < deadline {
        if let Ok(ev) = rx.try_recv() {
            event = Some(ev);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    task.abort();

    let recorded = bans.bans();
    assert_eq!(
        recorded.len(),
        1,
        "exactly one ban expected; history lines must not ban (tail from END)"
    );
    let entry = &recorded[0];
    assert_eq!(entry.ip, "203.0.113.77");
    assert_eq!(entry.plugin, "ssh-guard");
    assert_eq!(entry.node, "test-node");
    assert_eq!(entry.scope, BanScope::Local);
    assert_eq!(entry.ttl, BAN_1H);
    assert_eq!(entry.reason, "ssh brute force (failed-password)");
    match event {
        Some(Event::Ban {
            ip,
            reason,
            plugin,
            scope,
            ttl_secs,
            country: _,
        }) => {
            assert_eq!(ip, "203.0.113.77");
            assert_eq!(plugin, "ssh-guard");
            assert_eq!(scope, "local");
            assert_eq!(ttl_secs, 3600);
            assert_eq!(reason, "ssh brute force (failed-password)");
        }
        other => panic!("expected Ban event, got {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}

/// BanSink 报错时:采集任务不 panic、继续运行,且不发送 Ban 事件。
#[tokio::test]
async fn ban_sink_error_is_contained() {
    let path = unique_tmp("err");
    std::fs::write(&path, "").unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut cfg = test_cfg();
    cfg.max_retry = 1;
    let task = tokio::spawn(run_file_tail(
        path.clone(),
        cfg,
        "test-node".to_string(),
        Arc::new(FailingBanSink),
        tx,
    ));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    use std::io::Write;
    writeln!(&mut f, "Failed password for root from 198.51.100.66 port 40222 ssh2").unwrap();
    drop(f);
    // 轮询间隔 500ms,留 1.5s 让判定与 BanSink 调用发生。
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!task.is_finished(), "tail task must survive BanSink errors");
    assert!(rx.try_recv().is_err(), "failed ban must not emit an event");
    task.abort();
    let _ = std::fs::remove_file(&path);
}
