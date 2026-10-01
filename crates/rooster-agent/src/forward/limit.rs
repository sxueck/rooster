//! CIDR ACL 与每 IP 连接速率 / 并发上限。
//!
//! 速率是保守滑窗:窗口内该 IP 的「连接获取」次数达到 N 即拒绝,
//! 直到最早的记录滑出窗口。TCP 每连接获取一次,UDP 每会话创建获取一次
//! (数据报不重复计数)。并发计数在连接 / 会话结束时释放。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ipnet::IpNet;

/// ACL 判定:allow 为空 = 放行所有;否则真实源 IP 必须命中某个 CIDR。
pub(crate) fn acl_allows(acl: &[IpNet], ip: IpAddr) -> bool {
    acl.is_empty() || acl.iter().any(|net| net.contains(&ip))
}

/// 解析 `N/(second|minute|hour)`(容忍复数与单字母缩写)。
/// 非法或 N == 0 返回 None,视为不启用限速(由配置校验层负责报错)。
pub(crate) fn parse_rate(s: &str) -> Option<(u32, Duration)> {
    let (n, unit) = s.trim().split_once('/')?;
    let n: u32 = n.trim().parse().ok()?;
    if n == 0 {
        return None;
    }
    let window = match unit.trim().to_ascii_lowercase().as_str() {
        "second" | "seconds" | "s" => Duration::from_secs(1),
        "minute" | "minutes" | "m" => Duration::from_secs(60),
        "hour" | "hours" | "h" => Duration::from_secs(3600),
        _ => return None,
    };
    Some((n, window))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DenyReason {
    /// 滑窗内连接数达到 conn_rate 上限。
    RateLimited,
    /// 该 IP 并发连接 / 会话数达到 max_conns_per_ip。
    TooManyConcurrent,
}

impl DenyReason {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            DenyReason::RateLimited => "rate limited",
            DenyReason::TooManyConcurrent => "too many concurrent connections",
        }
    }
}

#[derive(Default)]
struct IpSlot {
    /// 当前持有(TCP 连接或 UDP 会话)。
    conns: u32,
    /// 滑窗内的连接获取时刻。
    events: VecDeque<Instant>,
}

pub(crate) struct PerIpLimiter {
    rate: Option<(u32, Duration)>,
    max_conns: Option<u32>,
    per_ip: HashMap<IpAddr, IpSlot>,
}

/// 触发一次全表惰性清理的阈值(防大量一次性源 IP 撑大 map)。
const LAZY_SWEEP_THRESHOLD: usize = 1024;

impl PerIpLimiter {
    pub(crate) fn new(rate: Option<(u32, Duration)>, max_conns: Option<u32>) -> Self {
        Self {
            rate,
            max_conns,
            per_ip: HashMap::new(),
        }
    }

    /// 尝试为该 IP 获取一个连接 / 会话名额;成功则同时记一次滑窗事件。
    pub(crate) fn try_acquire(&mut self, ip: &IpAddr) -> Result<(), DenyReason> {
        let now = Instant::now();
        let rate = self.rate;
        {
            let slot = self.per_ip.entry(*ip).or_default();
            if let Some((limit, window)) = rate {
                let cutoff = now.checked_sub(window).unwrap_or(now);
                while let Some(front) = slot.events.front() {
                    if *front <= cutoff {
                        slot.events.pop_front();
                    } else {
                        break;
                    }
                }
                if slot.events.len() >= limit as usize {
                    return Err(DenyReason::RateLimited);
                }
            }
            if let Some(max) = self.max_conns {
                if slot.conns >= max {
                    return Err(DenyReason::TooManyConcurrent);
                }
            }
            slot.conns += 1;
            if rate.is_some() {
                slot.events.push_back(now);
            }
        }
        // 惰性清理:清掉既无并发也无滑窗事件的残留条目。
        if self.per_ip.len() > LAZY_SWEEP_THRESHOLD {
            self.sweep(now);
        }
        Ok(())
    }

    /// 释放名额(连接 / 会话结束)。
    pub(crate) fn release(&mut self, ip: &IpAddr) {
        let now = Instant::now();
        let mut drop_slot = false;
        if let Some(slot) = self.per_ip.get_mut(ip) {
            slot.conns = slot.conns.saturating_sub(1);
            if let Some((_, window)) = self.rate {
                let cutoff = now.checked_sub(window).unwrap_or(now);
                while let Some(front) = slot.events.front() {
                    if *front <= cutoff {
                        slot.events.pop_front();
                    } else {
                        break;
                    }
                }
            }
            drop_slot = slot.conns == 0 && slot.events.is_empty();
        }
        if drop_slot {
            self.per_ip.remove(ip);
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.per_ip.retain(|_, slot| {
            if let Some((_, window)) = self.rate {
                let cutoff = now.checked_sub(window).unwrap_or(now);
                while let Some(front) = slot.events.front() {
                    if *front <= cutoff {
                        slot.events.pop_front();
                    } else {
                        break;
                    }
                }
            }
            slot.conns > 0 || !slot.events.is_empty()
        });
    }
}
