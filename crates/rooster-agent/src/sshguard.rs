//! ssh-guard 插件:日志采集、滑窗判定、递增封禁。
//!
//! - **日志采集**:优先 `journalctl -f -o json -u ssh -u sshd`;二进制
//!   缺失或 spawn 失败时回退 tail `/var/log/auth.log` / `/var/log/secure`。
//!   文件源从**文件末尾**开始读,只统计新行——启动时不得因历史日志批量封禁。
//!   运行中 journalctl 退出按指数退避重启(1s→60s)。
//! - **识别规则**:六条内置正则(见 [`builtin_patterns`]),命中后把
//!   捕获组验证为 IP,非 IP 行忽略。
//! - **判定**:[`Judge`] 每 IP 滑窗计数,达到 `max-retry` 触发递增封禁
//!   `min(ban_time × factor^(n-1), ban_time_max)`。
//! - `conn-rate` / `conn-burst` / `port` 由 nftables 侧
//!   (`set_ssh_rate_limit` meter 与 ssh set 规则)消费,**不在本模块处理**;
//!   成功登录("Accepted ...")仅用于展示,不参与封禁。
//!
//! 与封禁管理器的最小耦合面是 [`BanSink`];主线以 blanket impl 桥接
//! `rooster_nft::BanManager`。[`spawn`] 的任务从不 panic:数据源致命错误
//! (journalctl 启动失败且文件源也不可用)只记录 error 并结束任务。

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rooster_config::schema::{SshGuardConfig, SshLogSource};
use rooster_nft::{BanEntry, BanScope, NftError};
use rooster_proto::Event;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;

/// 文件源轮询间隔。
const FILE_POLL: Duration = Duration::from_millis(500);
/// 文件源打不开时的重试间隔,失败只记录一次告警。
const FILE_RETRY: Duration = Duration::from_secs(5);
/// journalctl 运行中退出后的首次重启退避。
const JOURNAL_RESTART_MIN: Duration = Duration::from_secs(1);
/// journalctl 重启退避上限。
const JOURNAL_RESTART_MAX: Duration = Duration::from_secs(60);
/// 窗口表内存护栏:IP 数超过该值时清扫整窗过期的条目。
const WINDOW_SWEEP_THRESHOLD: usize = 4096;

/// cfg 中这几个字段是 `Option<Duration>`;缺省时取默认值。
const FIND_TIME_FALLBACK: Duration = Duration::from_secs(10 * 60);
const BAN_TIME_FALLBACK: Duration = Duration::from_secs(3600);
const BAN_TIME_MAX_FALLBACK: Duration = Duration::from_secs(7 * 24 * 3600);

/// 与封禁管理器的最小耦合面;主线以 blanket impl 桥接 rooster_nft::BanManager。
pub trait BanSink: Send + Sync {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError>;
}

/// 主线桥接:任何 `BanManager` 自动成为 `BanSink`,`Arc<dyn BanManager>` 可
/// 直接当作 `Arc<dyn BanSink>` 传给 [`spawn`]。
impl<T: ?Sized + rooster_nft::BanManager> BanSink for T {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError> {
        rooster_nft::BanManager::apply_ban(self, entry)
    }
}

/// 一条识别规则。`regex` 的第 1 捕获组是来源主机 token,命中后必须
/// 能解析为 [`IpAddr`],否则整行忽略(`<IP>` 占位符)。
pub struct SshPattern {
    pub regex: regex::Regex,
    pub kind: &'static str,
}

/// 内置六条识别规则(正则内置;覆盖能力留待配置面接入)。
///
/// 文本逐条对应:`<IP>` 替换为第 1 捕获组;贪婪匹配保证取行内
/// 最后一个主机 token。统一加 `(?i)`:不同发行版 / OpenSSH 版本对这几条日志
/// 的大小写不一致。
///
/// IPv6 说明:`from <IP>` 类规则用 `\S+` 捕获,裸 IPv6(如 `2001:db8::1`)可以
/// 命中;banner-exchange 的 `<IP>` 后紧跟冒号分隔,只能按 IPv4 处理——已知局限。
///
/// 顺序敏感:`failed-password` 必须在 `invalid-user` 之前——
/// "Failed password for invalid user ..." 同时含两个特征,按规则顺序归为前者。
pub fn builtin_patterns() -> Vec<SshPattern> {
    let defs: [(&'static str, &str); 6] = [
        // Failed password for (invalid user )?<user> from <IP> port <p> ssh2
        ("failed-password", r"(?i)failed password for (?:invalid user )?\S+ from (\S+)"),
        // Invalid user <user> from <IP> port <p>
        ("invalid-user", r"(?i)invalid user \S+ from (\S+)"),
        // Connection closed by (authenticating|invalid) user <user> <IP> port <p> [preauth]
        ("closed-preauth", r"(?i)connection closed by (?:authenticating|invalid) user .* (\S+) port \d+ \[preauth\]"),
        // Disconnected from (authenticating )?user <user> <IP> port <p> [preauth]
        ("disconnected-preauth", r"(?i)disconnected from .* (\S+) port \d+ \[preauth\]"),
        // (M|m)aximum authentication attempts exceeded for <user> from <IP> ...
        ("max-auth", r"(?i)maximum authentication attempts exceeded .* from (\S+)"),
        // banner exchange: Connection from <IP>[ port <p>]: invalid format
        ("banner-exchange", r"(?i)banner exchange: .* from (\S+?)[\s:].*invalid format"),
    ];
    defs.into_iter()
        .map(|(kind, pattern)| SshPattern {
            regex: regex::Regex::new(pattern).expect("builtin ssh-guard regex must compile"),
            kind,
        })
        .collect()
}

/// 逐条尝试内置规则;第一条命中且捕获组能解析为 IP 的规则生效。
/// 捕获组不是 IP(如 hostname)时按行忽略。非匹配行返回 `None` 直接跳过。
fn match_line(patterns: &[SshPattern], line: &str) -> Option<(&'static str, IpAddr)> {
    for p in patterns {
        if let Some(caps) = p.regex.captures(line) {
            let token = match caps.get(1) {
                Some(m) => m.as_str(),
                None => continue,
            };
            match token.parse::<IpAddr>() {
                Ok(ip) => return Some((p.kind, ip)),
                Err(_) => tracing::debug!(
                    target: "ssh_guard",
                    kind = p.kind,
                    token,
                    "captured host token is not an IP; ignoring line"
                ),
            }
        }
    }
    None
}

/// 纯逻辑滑窗判定,与 IO 无关,单测友好。
///
/// 时间由调用方注入(`on_failure` 的 `now: Instant`),本结构不读时钟;测试可
/// 用 `Instant::now() + offset` 构造合成时间轴。
pub struct Judge {
    max_retry: u32,
    find_time: Duration,
    ban_time: Duration,
    factor: u32,
    ban_time_max: Duration,
    /// 每 IP 滑动窗口内的失败时刻。
    windows: HashMap<String, VecDeque<Instant>>,
    /// 每 IP 已封禁次数。进程生命周期内**永不重置**(刻意为之):
    /// 递增封禁按第 n 次封禁计算;增长上限由 ban_time_max 兜底,攻击者无法
    /// 通过重置窗口把 TTL 拉回 1h。
    ban_counts: HashMap<String, u32>,
}

impl Judge {
    pub fn new(cfg: &SshGuardConfig) -> Self {
        Self {
            // 防御:max_retry=0 / factor=0 会让「第 1 次失败即封」或 TTL 归零
            //(TTL=0 在 nft set timeout 里等价于永不过期),都钳到安全值。
            max_retry: cfg.max_retry.max(1),
            factor: cfg.ban_time_factor.max(1),
            find_time: cfg.find_time.unwrap_or(FIND_TIME_FALLBACK),
            ban_time: cfg.ban_time.unwrap_or(BAN_TIME_FALLBACK),
            ban_time_max: cfg.ban_time_max.unwrap_or(BAN_TIME_MAX_FALLBACK),
            windows: HashMap::new(),
            ban_counts: HashMap::new(),
        }
    }

    /// 记录一次失败;达到 max_retry 时返回封禁 TTL。
    /// TTL = min(ban_time × factor^(第 n 次封禁 − 1), ban_time_max);
    /// 窗口内不足阈值不封。
    ///
    /// 已封禁期间到来的失败照常计数:窗口清空后重新攒满 max_retry 即触发
    /// 第 n+1 次封禁(内核侧 timeout 由新的 apply_ban 续期)。
    pub fn on_failure(&mut self, ip: &str, now: Instant) -> Option<Duration> {
        let window = self.windows.entry(ip.to_string()).or_default();
        // 修剪滑窗:只保留 now - find_time 之内(含)的失败。
        while let Some(&front) = window.front() {
            match now.checked_duration_since(front) {
                Some(age) if age > self.find_time => {
                    window.pop_front();
                }
                _ => break,
            }
        }
        window.push_back(now);
        if (window.len() as u32) < self.max_retry {
            self.sweep_if_large(now);
            return None;
        }
        // 达到阈值:清窗 + 递增封禁计数(第 n 次封禁,n 从 1 起)。
        window.clear();
        let count = match self.ban_counts.get_mut(ip) {
            Some(count) => {
                *count += 1;
                *count
            }
            None => {
                self.ban_counts.insert(ip.to_string(), 1);
                1
            }
        };
        Some(self.ttl_for(count))
    }

    /// 第 n 次封禁的 TTL = min(ban_time × factor^(n-1), ban_time_max);
    /// 乘法溢出(checked_mul)时直接取上限。
    fn ttl_for(&self, n: u32) -> Duration {
        let mut ttl = self.ban_time;
        for _ in 1..n {
            match ttl.checked_mul(self.factor) {
                Some(next) => ttl = next,
                None => return self.ban_time_max,
            }
        }
        ttl.min(self.ban_time_max)
    }

    /// 内存护栏:窗口表过大时,清理最后一个事件已滑出 find_time 的 IP。
    /// 用传入的 `now` 保持与判定同一时间轴(纯逻辑,不读时钟)。
    fn sweep_if_large(&mut self, now: Instant) {
        if self.windows.len() <= WINDOW_SWEEP_THRESHOLD {
            return;
        }
        let find_time = self.find_time;
        self.windows.retain(|_, w| {
            w.back()
                .map(|last| now.checked_duration_since(*last).map(|a| a <= find_time) == Some(true))
                .unwrap_or(false)
        });
    }
}

/// 采集 → 解析 → 判定 → BanSink + 事件 的共用管线(journald 与文件源共用)。
struct Pipeline {
    judge: Judge,
    patterns: Vec<SshPattern>,
    node: String,
    bans: Arc<dyn BanSink>,
    events: UnboundedSender<Event>,
}

impl Pipeline {
    fn new(
        cfg: &SshGuardConfig,
        node: String,
        bans: Arc<dyn BanSink>,
        events: UnboundedSender<Event>,
    ) -> Self {
        Self {
            judge: Judge::new(cfg),
            patterns: builtin_patterns(),
            node,
            bans,
            events,
        }
    }

    /// 处理一行 sshd 日志(已完成 journald MESSAGE 解码或文件行切分)。
    /// 非匹配行静默忽略;成功登录行不匹配任何规则,只用于展示。
    fn process_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let Some((kind, ip)) = match_line(&self.patterns, line) else {
            return;
        };
        let ip = ip.to_string();
        let Some(ttl) = self.judge.on_failure(&ip, Instant::now()) else {
            return;
        };
        self.emit_ban(kind, &ip, ttl);
    }

    /// 封禁落地:BanSink 成功 → 发 Ban 事件;失败按错误类别降级记录,绝不 panic。
    fn emit_ban(&self, kind: &'static str, ip: &str, ttl: Duration) {
        let reason = format!("ssh brute force ({kind})");
        let entry = BanEntry {
            ip: ip.to_string(),
            ttl,
            reason: reason.clone(),
            plugin: "ssh-guard".to_string(),
            node: self.node.clone(),
            scope: BanScope::Local,
            started_at: None,
            expires_at: None,
        };
        match self.bans.apply_ban(&entry) {
            Ok(()) => {
                // 事件通道无界,send 永不阻塞;接收端已关闭时静默丢弃。
                let _ = self.events.send(Event::Ban {
                    ip: ip.to_string(),
                    reason,
                    plugin: "ssh-guard".to_string(),
                    scope: "local".to_string(),
                    ttl_secs: ttl.as_secs(),
                    country: None,
                });
            }
            Err(err) => match err {
                // 内核级失败(nftables 写入出错):必须让运维看到。
                NftError::Netlink(_) => tracing::error!(
                    target: "ssh_guard", ip, kind, ttl = ?ttl,
                    "failed to apply ban: {err}"
                ),
                // Refused = 命中管理白名单拒封;InvalidAddress =
                // 入参被拒:按告警降级,不影响采集任务。
                NftError::Refused(_) | NftError::InvalidAddress(_) => tracing::warn!(
                    target: "ssh_guard", ip, kind, ttl = ?ttl,
                    "ban not applied: {err}"
                ),
            },
        }
    }
}

/// 从 journal export JSON 行取出 sshd 日志文本。`MESSAGE` 通常是字符串,少数
/// 导出格式里是数组(取第一个元素);`__REALTIME_TIMESTAMP`(µs 字符串)只用于
/// 排序展示,判定窗口一律用 `Instant`,此处忽略。
/// 坏 JSON / 缺 MESSAGE 返回 `None`(调用方按 debug 记录后忽略)。
pub fn extract_journal_message(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    match value.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Array(items)) => items
            .first()
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

/// [`run_journald_once`] 的返回:区分「没能启动」与「运行中退出」。
enum JournaldStop {
    /// journalctl 二进制缺失或 spawn 失败 → 回退文件源。
    SpawnFailed(std::io::Error),
    /// 曾经运行,之后退出(stdout EOF)或读取出错 → 指数退避重启。
    Exited(std::io::Error),
}

/// 跟随 journalctl 直到其退出;正常情况下永不返回。
async fn run_journald_once(pipeline: &mut Pipeline) -> JournaldStop {
    let mut cmd = tokio::process::Command::new("journalctl");
    // `-f -o json -u ssh -u sshd`。kill_on_drop 保证本任务被 abort 时
    // 子进程一并退出,不留孤儿 journalctl。
    cmd.args(["-f", "-o", "json", "-u", "ssh", "-u", "sshd"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return JournaldStop::SpawnFailed(err),
    };
    tracing::info!(
        target: "ssh_guard",
        "following journalctl -f -o json -u ssh -u sshd"
    );
    // stderr「inherited-ish」:逐行透传为 debug 日志,不混入正式输出。
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "ssh_guard::journalctl", "{line}");
            }
        });
    }
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout was piped")).lines();
    loop {
        match stdout.next_line().await {
            Ok(Some(line)) => match extract_journal_message(&line) {
                Some(msg) => pipeline.process_line(&msg),
                // 坏 JSON 静默降级为 debug,不刷屏。
                None => tracing::debug!(
                    target: "ssh_guard::journalctl",
                    "ignoring malformed journal line"
                ),
            },
            Ok(None) => {
                return JournaldStop::Exited(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "journalctl stdout closed",
                ))
            }
            Err(err) => return JournaldStop::Exited(err),
        }
    }
}

/// 文件源:第一个存在的日志文件(/var/log/auth.log 优先,其次 secure)。
pub fn resolve_file_source() -> Option<PathBuf> {
    ["/var/log/auth.log", "/var/log/secure"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// 打开文件并把游标定位到**末尾**,返回 (文件, 起始读取位置)。
/// tail 从 END 开始:历史行不参与判定——启动时不得因旧日志批量封禁。
async fn open_at_end(path: &Path) -> std::io::Result<(tokio::fs::File, u64)> {
    let mut file = tokio::fs::File::open(path).await?;
    let pos = file.seek(std::io::SeekFrom::End(0)).await?;
    Ok((file, pos))
}

/// 跟随单个日志文件。[`spawn`] 内部使用,也可独立调用(集成测试)。
///
/// - 从文件末尾开始 tail:只统计**新**行(启动不应因历史日志批量封禁);
/// - 每 500ms 轮询;文件比上次读取位置短(轮转 / 截断)则从头重读;
/// - 打开失败每 5s 重试,同一段失败只记录一次告警;
/// - 永不返回(除非任务被 abort)。若轮转后新文件比旧位置更长(rename+新建
///   但内容更大的极端情形),从旧位置续读,可能漏开头几行——可接受的近似。
pub async fn run_file_tail(
    path: PathBuf,
    cfg: SshGuardConfig,
    node: String,
    bans: Arc<dyn BanSink>,
    events: UnboundedSender<Event>,
) {
    let mut pipeline = Pipeline::new(&cfg, node, bans, events);
    tracing::info!(
        target: "ssh_guard",
        file = %path.display(),
        "tailing ssh log from end; only new lines count"
    );
    let mut warned_open = false;
    let (mut file, mut pos) = loop {
        match open_at_end(&path).await {
            Ok(pair) => break pair,
            Err(err) => {
                if !warned_open {
                    tracing::warn!(
                        target: "ssh_guard",
                        file = %path.display(),
                        "cannot open ({err}); retrying every 5s"
                    );
                    warned_open = true;
                }
                tokio::time::sleep(FILE_RETRY).await;
            }
        }
    };
    let mut partial: Vec<u8> = Vec::new();
    let mut warned_io = false;
    loop {
        tokio::time::sleep(FILE_POLL).await;
        // 轮转/截断检测:文件比已读位置短 → logrotate(rename+新建)或
        // truncate,从头重读(对轮转的鲁棒性)。
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.len() < pos => {
                tracing::info!(
                    target: "ssh_guard",
                    file = %path.display(),
                    "log rotated or truncated; rereading from start"
                );
                match tokio::fs::File::open(&path).await {
                    Ok(f) => {
                        file = f;
                        pos = 0;
                        partial.clear();
                    }
                    Err(err) => tracing::warn!(
                        target: "ssh_guard",
                        file = %path.display(),
                        "reopen after rotation failed ({err}); will retry"
                    ),
                }
                continue;
            }
            Ok(_) => {}
            Err(err) => {
                if !warned_io {
                    tracing::warn!(target: "ssh_guard", file = %path.display(), "stat failed ({err})");
                    warned_io = true;
                }
                continue;
            }
        }
        warned_io = false;
        let mut chunk = Vec::new();
        match file.read_to_end(&mut chunk).await {
            Ok(0) => continue,
            Ok(_) => {}
            Err(err) => {
                if !warned_io {
                    tracing::warn!(target: "ssh_guard", file = %path.display(), "read failed ({err})");
                    warned_io = true;
                }
                continue;
            }
        }
        pos += chunk.len() as u64;
        partial.extend_from_slice(&chunk);
        // 按换行切分;末尾不完整的一行留到下一轮补全。
        let mut start = 0;
        for (i, byte) in partial.iter().enumerate() {
            if *byte == b'\n' {
                pipeline.process_line(&String::from_utf8_lossy(&partial[start..i]));
                start = i + 1;
            }
        }
        partial.drain(..start);
    }
}

/// 常驻任务:采集日志 → 解析 → 判定 → [`BanSink`] + 事件。
/// 从不 panic;数据源致命错误(journalctl 启动失败且文件源也不可用)时
/// 记录 error 并返回;运行中 journalctl 退出按指数退避重启(1s→60s)。
///
/// `cfg.conn_rate` / `cfg.conn_burst` / `cfg.port` 在此**不消费**——它们由
/// nftables 侧(`set_ssh_rate_limit` meter;端口匹配规则)使用;
/// 成功登录事件仅用于展示,不参与封禁。调用方负责检查 `cfg.enabled`。
pub fn spawn(
    cfg: SshGuardConfig,
    node: String,
    bans: std::sync::Arc<dyn BanSink>,
    events: tokio::sync::mpsc::UnboundedSender<rooster_proto::Event>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            target: "ssh_guard",
            port = cfg.port,
            source = ?cfg.source,
            "ssh-guard running; conn-rate/conn-burst/port are enforced on the nftables side"
        );
        if cfg.source == SshLogSource::Journald {
            let mut pipeline = Pipeline::new(&cfg, node.clone(), bans.clone(), events.clone());
            let mut backoff = JOURNAL_RESTART_MIN;
            loop {
                match run_journald_once(&mut pipeline).await {
                    // 启动失败:告警一次,回退文件源。
                    JournaldStop::SpawnFailed(err) => {
                        tracing::warn!(
                            target: "ssh_guard",
                            "journalctl unavailable ({err}); falling back to file source"
                        );
                        break;
                    }
                    // 运行中退出:指数退避重启(1s→60s),不回退文件源——
                    // journal 通常比文件源可靠,退避足以度过重启窗口。
                    JournaldStop::Exited(err) => {
                        tracing::warn!(
                            target: "ssh_guard",
                            "journalctl exited ({err}); restarting in {backoff:?}"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(JOURNAL_RESTART_MAX);
                    }
                }
            }
        }
        // 回退到 / 指定为文件源。
        match resolve_file_source() {
            Some(path) => run_file_tail(path, cfg, node, bans, events).await,
            None => tracing::error!(
                target: "ssh_guard",
                "no usable log source: journalctl unavailable and neither /var/log/auth.log \
                 nor /var/log/secure exists; ssh-guard giving up"
            ),
        }
    })
}
