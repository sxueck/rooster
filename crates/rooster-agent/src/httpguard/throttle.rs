//! 速率限制:令牌桶 + 持续超限升级 Ban。
//!
//! - 令牌桶:容量 = `N + burst`,按 `N / window` 的速率连续回填,
//!   初始满桶。`3/second burst 0` 即一秒内前三笔放行、第四笔拒绝。
//! - key 支持 `ip`、`ip+path`、`header:<name>`(见 [`RateKey`])。
//! - `on-exceed: reject` → 429(终止模式)/ reset(透传);
//!   `on-exceed: ban` → 同样先拒绝,同时跟踪该 key 的持续超限状态,
//!   超限状态持续 ≥ `ban-after`(缺省 10 分钟)时升级为 Ban:调用
//!   ban_hook(ip, 10min) 并在封禁期内直接拒绝。Ban 的 TTL 固定
//!   10 分钟是实现选择(与缺省 ban-after 一致)。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rooster_config::schema::{OnExceed, RateLimitRule};

/// Ban 触发后的封禁时长(实现选择)。
pub(crate) const BAN_TTL: Duration = Duration::from_secs(600);
/// `ban-after` 缺省值。
const DEFAULT_BAN_AFTER: Duration = Duration::from_secs(600);
/// 桶表硬上限:key 里含攻击者可控字符串(路径、header 值),没有上限
/// 就是无界的内存增长,须守住节点内存占用。
const MAX_KEYS: usize = 32_768;
/// 触发一次空闲清扫的检查间隔(每笔请求一次清扫太贵)。
const SWEEP_EVERY: u64 = 1024;
/// 桶的空闲回收时间:超过此时长没被触碰的桶可回收(令牌桶在此时长内
/// 早已回满,删除不影响判定)。
const IDLE_TTL: Duration = Duration::from_secs(600);
/// 触顶后回收到该水位(留出余量,避免每笔请求都淘汰)。
const LOW_WATER: usize = MAX_KEYS * 3 / 4;

#[derive(Clone)]
pub(crate) enum RateKey {
    Ip,
    IpPath,
    Header(String),
}

#[derive(Clone)]
pub(crate) struct ParsedRate {
    /// 规则在站点 `rate-limit` 列表中的下标;`settings::build` 赋值。
    /// 桶表的 key 必须用它而不是“传入切片的下标”:透传模式只传
    /// `key=ip` 的子集(重新编号),用切片下标会让同一条规则在终止
    /// 模式与透传模式下落到两个桶,客户端混用协议即可拿到双倍配额。
    pub id: u32,
    pub key: RateKey,
    /// 每个窗口补充的令牌数。
    pub n: u32,
    pub window: Duration,
    pub burst: u32,
    pub on_exceed: OnExceed,
    pub ban_after: Option<Duration>,
}

/// 解析 `N/(second|minute|hour)`。
pub(crate) fn parse_rate(s: &str) -> Option<(u32, Duration)> {
    let (n, unit) = s.trim().rsplit_once('/')?;
    let n: u32 = n.trim().parse().ok()?;
    let window = match unit.trim().to_ascii_lowercase().as_str() {
        "second" | "s" => Duration::from_secs(1),
        "minute" | "m" => Duration::from_secs(60),
        "hour" | "h" => Duration::from_secs(3600),
        _ => return None,
    };
    Some((n, window))
}

impl ParsedRate {
    pub(crate) fn parse(rule: &RateLimitRule) -> Option<Self> {
        let key = match rule.key.trim() {
            "ip" => RateKey::Ip,
            "ip+path" => RateKey::IpPath,
            k if k.starts_with("header:") => RateKey::Header(k[7..].to_ascii_lowercase()),
            _ => return None,
        };
        let (n, window) = parse_rate(&rule.rate)?;
        Some(Self {
            id: 0,
            key,
            n,
            window,
            burst: rule.burst,
            on_exceed: rule.on_exceed,
            ban_after: rule.ban_after,
        })
    }

    /// 该规则的 key 是否为纯 IP(透传模式只能在 accept 时按 IP 限速)。
    pub(crate) fn is_ip_key(&self) -> bool {
        matches!(self.key, RateKey::Ip)
    }
}

/// 单个 key 的桶状态与持续超限跟踪。
struct KeyState {
    tokens: f64,
    updated: Instant,
    first_exceed: Option<Instant>,
    banned_until: Option<Instant>,
}

impl KeyState {
    fn full(n: u32, burst: u32) -> Self {
        Self {
            tokens: (n + burst) as f64,
            updated: Instant::now(),
            first_exceed: None,
            banned_until: None,
        }
    }
}

/// 一条限速判定的结论。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RateDecision {
    Allow,
    /// 拒绝:终止模式 429,透传模式直接断开。
    Reject,
    /// 持续超限升级为 Ban:调用方需要触发 ban_hook 并按 Reject 处理。
    Ban,
}

/// 每站点一本:key → 桶。规则顺序即索引,配置变化时随站点重建。
#[derive(Default)]
pub(crate) struct RateBook {
    keys: HashMap<(u32, String), KeyState>,
    checks: u64,
}


impl RateBook {
    /// 回收空闲桶,并在触顶时淘汰最久未用的桶;内存占用因此有上界。
    fn sweep(&mut self, now: Instant) {
        self.checks += 1;
        if self.keys.len() <= MAX_KEYS && !self.checks.is_multiple_of(SWEEP_EVERY) {
            return;
        }
        if !self.checks.is_multiple_of(SWEEP_EVERY) {
            tracing::warn!(
                entries = self.keys.len(),
                max = MAX_KEYS,
                "rate-limit key table at capacity; evicting least recently used"
            );
        }
        self.keys
            .retain(|_, st| now.saturating_duration_since(st.updated) < IDLE_TTL);
        // 清扫后仍超上限(攻击者持续用新 key):按 updated 升序淘汰到低水位。
        if self.keys.len() > LOW_WATER {
            let mut by_age: Vec<(&(u32, String), Instant)> = self
                .keys
                .iter()
                .map(|(k, st)| (k, st.updated))
                .collect();
            by_age.sort_by_key(|(_, t)| *t);
            let drop_n = self.keys.len() - LOW_WATER;
            let victims: Vec<(u32, String)> =
                by_age.into_iter().take(drop_n).map(|(k, _)| k.clone()).collect();
            for k in victims {
                self.keys.remove(&k);
            }
        }
    }

    /// 对一笔请求逐规则取令牌,返回最严重的结论(Allow < Reject < Ban)。
    /// `path` 不含 query;`headers` 为小写键值对。
    pub(crate) fn check(
        &mut self,
        rules: &[ParsedRate],
        ip: IpAddr,
        path: &str,
        headers: &[(String, String)],
    ) -> RateDecision {
        let now = Instant::now();
        let mut worst = RateDecision::Allow;
        self.sweep(now);
        for rule in rules.iter() {
            let key = match &rule.key {
                RateKey::Ip => ip.to_string(),
                RateKey::IpPath => format!("{ip}|{path}"),
                RateKey::Header(name) => headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| "-".to_string()),
            };
            let map_key = (rule.id, key);
            let state = self
                .keys
                .entry(map_key)
                .or_insert_with(|| KeyState::full(rule.n, rule.burst));

            // 封禁期内直接拒绝。
            if state.banned_until.is_some_and(|t| t > now) {
                if RateDecision::Ban.rank() > worst.rank() {
                    worst = RateDecision::Ban;
                }
                continue;
            }
            if state.banned_until.is_some_and(|t| t <= now) {
                state.banned_until = None;
                state.first_exceed = None;
            }

            // 回填并取令牌。
            let capacity = (rule.n + rule.burst) as f64;
            let rate = rule.n as f64 / rule.window.as_secs_f64().max(1e-9);
            let elapsed = now.saturating_duration_since(state.updated).as_secs_f64();
            state.tokens = (state.tokens + elapsed * rate).min(capacity);
            state.updated = now;

            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
                state.first_exceed = None;
                continue;
            }

            // 超限。
            match rule.on_exceed {
                OnExceed::Reject => {
                    if worst == RateDecision::Allow {
                        worst = RateDecision::Reject;
                    }
                }
                OnExceed::Ban => {
                    let threshold = rule.ban_after.unwrap_or(DEFAULT_BAN_AFTER);
                    match state.first_exceed {
                        // 首次超限同样按 Reject 拒绝(模块文档「ban → 同样先拒绝」);
                        // 这里只额外记录超限起点供后续升级判定。
                        None => {
                            state.first_exceed = Some(now);
                            if worst == RateDecision::Allow {
                                worst = RateDecision::Reject;
                            }
                        }
                        Some(fe) if now.saturating_duration_since(fe) >= threshold => {
                            state.banned_until = Some(now + BAN_TTL);
                            state.first_exceed = Some(now);
                            worst = RateDecision::Ban;
                        }
                        Some(_) => {
                            if worst == RateDecision::Allow {
                                worst = RateDecision::Reject;
                            }
                        }
                    }
                }
            }
        }
        worst
    }
}

impl RateDecision {
    /// 严重度排序:Allow < Reject < Ban。
    fn rank(&self) -> u8 {
        match self {
            RateDecision::Allow => 0,
            RateDecision::Reject => 1,
            RateDecision::Ban => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooster_config::schema::{OnExceed, RateLimitRule};

    fn rule(key: &str, rate: &str, burst: u32, on_exceed: OnExceed, ban_after: Option<Duration>) -> ParsedRate {
        ParsedRate::parse(&RateLimitRule {
            key: key.to_string(),
            rate: rate.to_string(),
            burst,
            on_exceed,
            ban_after,
        })
        .unwrap()
    }

    #[test]
    fn rate_parsing() {
        assert_eq!(parse_rate("3/second"), Some((3, Duration::from_secs(1))));
        assert_eq!(parse_rate("30/minute"), Some((30, Duration::from_secs(60))));
        assert_eq!(parse_rate("2/hour"), Some((2, Duration::from_secs(3600))));
        assert_eq!(parse_rate("x/second"), None);
        assert_eq!(parse_rate("3/day"), None);
    }

    #[test]
    fn token_bucket_reject_and_ban() {
        let rules = vec![rule("ip", "3/second", 0, OnExceed::Reject, None)];
        let mut book = RateBook::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..3 {
            assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Allow);
        }
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Reject);
        // 不同 IP 不互相影响。
        let other: IpAddr = "1.2.3.5".parse().unwrap();
        assert_eq!(book.check(&rules, other, "/", &[]), RateDecision::Allow);
    }

    #[test]
    fn sustained_exceed_escalates_to_ban() {
        let rules = vec![rule("ip", "1/hour", 0, OnExceed::Ban, Some(Duration::from_millis(20)))];
        let mut book = RateBook::default();
        let ip: IpAddr = "2.2.2.2".parse().unwrap();
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Allow);
        // 首次超限:仅 Reject,并记录超限起点。
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Reject);
        std::thread::sleep(Duration::from_millis(40));
        // 持续超限 ≥ ban-after:升级 Ban,之后维持 Ban(封禁期内)。
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Ban);
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Ban);
    }

    #[test]
    fn recovery_clears_exceed_state() {
        let rules = vec![rule("ip", "10/second", 0, OnExceed::Ban, Some(Duration::from_millis(20)))];
        let mut book = RateBook::default();
        let ip: IpAddr = "3.3.3.3".parse().unwrap();
        for _ in 0..10 {
            assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Allow);
        }
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Reject);
        // 等令牌回填后成功一笔 → 超限状态清零,不升级。
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Allow);
        assert_eq!(book.check(&rules, ip, "/", &[]), RateDecision::Reject);
    }

    #[test]
    fn header_and_ip_path_keys() {
        // 两种 key 独立成桶,分开验证(同请求叠加多规则时任一耗尽即拒,
        // 由专门的叠加语义测试覆盖)。
        let ip: IpAddr = "4.4.4.4".parse().unwrap();
        let rules = vec![rule("ip+path", "2/second", 0, OnExceed::Reject, None)];
        let mut book = RateBook::default();
        for _ in 0..2 {
            assert_eq!(book.check(&rules, ip, "/a", &[]), RateDecision::Allow);
        }
        // ip+path:/a 已耗尽;换 path /b 放行。
        assert_eq!(book.check(&rules, ip, "/a", &[]), RateDecision::Reject);
        assert_eq!(book.check(&rules, ip, "/b", &[]), RateDecision::Allow);

        let rules = vec![rule("header:x-api-key", "2/second", 0, OnExceed::Reject, None)];
        let mut book = RateBook::default();
        let hdrs = vec![("x-api-key".to_string(), "abc".to_string())];
        for _ in 0..2 {
            assert_eq!(book.check(&rules, ip, "/a", &hdrs), RateDecision::Allow);
        }
        assert_eq!(book.check(&rules, ip, "/a", &hdrs), RateDecision::Reject);
        // header key 换值放行。
        let hdrs2 = vec![("x-api-key".to_string(), "xyz".to_string())];
        assert_eq!(book.check(&rules, ip, "/a", &hdrs2), RateDecision::Allow);
    }

    /// 回归(F8):透传模式只把 `key=ip` 的规则子集传给 `check`,子集里的
    /// 下标与 `site.rates` 不同。用切片下标寻址时,同一条 `key=ip` 规则
    /// 在终止模式是桶 0、在透传模式是桶 1,客户端混用协议即得双倍配额。
    #[test]
    fn rule_identity_is_stable_across_filtered_slices() {
        let ip: IpAddr = "5.5.5.5".parse().unwrap();
        // site.rates 的真实顺序:header 规则在前(id = 0),ip 规则在后(id = 1)。
        // header 规则给足配额,避免它先耗尽而干扰本用例的断言。
        let header_rule = rule("header:x-key", "1000/second", 0, OnExceed::Reject, None);
        let mut ip_rule = rule("ip", "2/second", 0, OnExceed::Reject, None);
        ip_rule.id = 1;
        let all = vec![header_rule, ip_rule.clone()];
        // 透传模式传入的过滤子集(重新编号前的老代码会用 enumerate → id 0)。
        let passthrough_subset = vec![ip_rule];

        let mut book = RateBook::default();
        assert_eq!(book.check(&all, ip, "/", &[]), RateDecision::Allow);
        assert_eq!(book.check(&all, ip, "/", &[]), RateDecision::Allow);
        // 终止模式已耗尽:透传模式必须看到同一个桶并同样拒绝。
        assert_eq!(
            book.check(&passthrough_subset, ip, "", &[]),
            RateDecision::Reject
        );
    }

    /// 回归(F-ConnGate):计数归零的条目必须移除,不能只减不删 ——
    /// 否则每个历史 IP 永久占据表项,普通流量也能把计数表无限撑大。
    #[test]
    fn conn_gate_removes_zero_count_entries_on_release() {
        let mut gate = ConnGate::default();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        assert!(gate.try_admit(ip, 2));
        assert_eq!(gate.per_ip.len(), 1);
        gate.release(ip);
        assert_eq!(gate.per_ip.len(), 0, "zero-count entry must be removed on release");

        // 大量「连上即断」的一次性 IP(扫描器形态)不能留下任何残余条目。
        for i in 0..1000u32 {
            let ip: IpAddr = format!("10.{}.{}.{}", i >> 16 & 0xff, i >> 8 & 0xff, i & 0xff)
                .parse()
                .unwrap();
            assert!(gate.try_admit(ip, 2));
            gate.release(ip);
        }
        assert!(gate.per_ip.is_empty(), "transient ips must not accumulate: {}", gate.per_ip.len());

        // 活跃连接的条目仍然保留(不能为了清理误删在计数中的 IP)。
        assert!(gate.try_admit(ip_of("9.9.9.9"), 2));
        assert!(gate.try_admit(ip_of("9.9.9.9"), 2));
        assert_eq!(gate.per_ip.len(), 1);
        assert!(!gate.try_admit(ip_of("9.9.9.9"), 2), "at-cap ip must be rejected");
        gate.release(ip_of("9.9.9.9"));
        assert_eq!(gate.per_ip.len(), 1, "still-one-active entry must remain");
    }

    fn ip_of(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// 回归(F7):桶表 key 含攻击者可控字符串,必须有上界。
    #[test]
    fn key_table_is_bounded() {
        let rules = vec![rule("ip+path", "100/second", 0, OnExceed::Reject, None)];
        let mut book = RateBook::default();
        let ip: IpAddr = "6.6.6.6".parse().unwrap();
        // 插入量远大于上限:表长必须仍被 MAX_KEYS 卡住,而不是线性增长。
        for i in 0..(MAX_KEYS * 3) {
            book.check(&rules, ip, &format!("/p{i}"), &[]);
        }
        assert!(
            book.keys.len() <= MAX_KEYS,
            "key table grew unbounded: {} entries (max {MAX_KEYS})",
            book.keys.len()
        );
    }

    /// 回归(F7):空闲桶会被回收,不会因长跑而无界增长。
    #[test]
    fn idle_entries_are_swept() {
        let rules = vec![rule("ip+path", "100/second", 0, OnExceed::Reject, None)];
        let mut book = RateBook::default();
        let ip: IpAddr = "7.7.7.7".parse().unwrap();
        for i in 0..2000 {
            book.check(&rules, ip, &format!("/p{i}"), &[]);
        }
        assert!(!book.keys.is_empty());
        // 把所有桶的 updated 改到远期之前,下一次检查的清扫应清空它们。
        for st in book.keys.values_mut() {
            st.updated = Instant::now() - IDLE_TTL - Duration::from_secs(1);
        }
        book.checks = SWEEP_EVERY - 1; // 下一次 check 触发清扫
        book.check(&rules, ip, "/after", &[]);
        // 只剩 /after 这一个新桶。
        assert!(book.keys.len() <= 2, "idle entries not swept: {}", book.keys.len());
    }
}

// ---------------------------------------------------------------------------
// L7 加固限速器(hardening):TLS ClientHello 每 IP 新建连接速率。
// 令牌桶与 RateBook 同一数学形状,但 key 只有 IP、判定只有 Reject,
// 且在 TLS 窥探之前执行 —— 独立实现,不与站点限速规则共享状态。

/// `N/(second|minute|hour)` + burst 的每 IP 令牌桶。表有上界(触顶按空闲清扫 +
/// LRU 淘汰),否则握手洪水的伪造源 IP 本身就成了内存耗尽攻击面。
#[derive(Debug)]
pub(crate) struct IpRateGate {
    rate_per_window: u32,
    window: Duration,
    burst: u32,
    keys: HashMap<IpAddr, (f64, Instant)>, // (tokens, updated)
    checks: u64,
}

impl IpRateGate {
    pub(crate) fn new(rate_per_window: u32, window: Duration, burst: u32) -> Self {
        Self {
            rate_per_window: rate_per_window.max(1),
            window: window.max(Duration::from_millis(1)),
            burst,
            keys: HashMap::new(),
            checks: 0,
        }
    }

    /// 取一枚令牌;超限返回 false(调用方直接断开连接)。
    pub(crate) fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.sweep(now);
        let capacity = (self.rate_per_window + self.burst) as f64;
        let per_sec = self.rate_per_window as f64 / self.window.as_secs_f64();
        let entry = self.keys.entry(ip).or_insert((capacity, now));
        let elapsed = now.saturating_duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * per_sec).min(capacity);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.checks += 1;
        if self.keys.len() <= MAX_KEYS && !self.checks.is_multiple_of(SWEEP_EVERY) {
            return;
        }
        self.keys.retain(|_, (_, t)| {
            now.saturating_duration_since(*t) < IDLE_TTL
        });
        if self.keys.len() > LOW_WATER {
            let mut by_age: Vec<(IpAddr, Instant)> =
                self.keys.iter().map(|(k, (_, t))| (*k, *t)).collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (k, _) in by_age.into_iter().take(self.keys.len() - LOW_WATER) {
                self.keys.remove(&k);
            }
        }
    }
}

/// 每 IP 并发连接计数(slow-loris `max-conns-per-ip`)。连接作用域由
/// `ConnGuard` RAII 递减;表满时拒绝新连接(计数表自身即限流点)。
#[derive(Debug, Default)]
pub(crate) struct ConnGate {
    per_ip: HashMap<IpAddr, u32>,
}

impl ConnGate {
    /// 名额 +1;超上限返回 false。
    pub(crate) fn try_admit(&mut self, ip: IpAddr, max: u32) -> bool {
        let e = self.per_ip.entry(ip).or_insert(0);
        if *e >= max {
            if self.per_ip.len() > MAX_KEYS {
                self.per_ip.retain(|_, n| *n > 0);
            }
            return false;
        }
        *e += 1;
        true
    }

    fn release(&mut self, ip: IpAddr) {
        let drained = match self.per_ip.get_mut(&ip) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => false,
        };
        // Historical peers must not occupy the map after their last connection closes.
        if drained {
            self.per_ip.remove(&ip);
        }
    }
}

/// 连接级守卫:drop 即归还并发名额。接受/连接失败路径靠 RAII 保证计数对称。
pub(crate) struct ConnGuard {
    gate: Arc<std::sync::Mutex<ConnGate>>,
    ip: IpAddr,
}

impl ConnGuard {
    pub(crate) fn new(gate: Arc<std::sync::Mutex<ConnGate>>, ip: IpAddr) -> Self {
        Self { gate, ip }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.gate.lock().unwrap().release(self.ip);
    }
}
