//! 全局封禁联动策略引擎。
//!
//! 消费各节点上报的事件,按策略聚合:
//! - `min-nodes`:窗口内至少 N 个**不同**节点上报同一 IP;
//! - `threshold`:窗口内同一 IP 命中次数(任意节点合计)。
//! 触发后由调用方广播 GlobalBan;同 IP 在 TTL 内不重复触发。

use crate::config::PolicyConfig;
use crate::store::{now_secs, GlobalBanRecord};
use rooster_proto::Event;
use std::collections::{HashMap, VecDeque};

#[derive(Default)]
pub struct PolicyEngine {
    /// (policy_id, ip) → 窗口内的 (ts, node_id)。
    windows: HashMap<(String, String), VecDeque<(u64, String)>>,
    /// 已触发:ip → (policy_id, expires_at)。TTL 内去重。
    triggered: HashMap<String, (String, u64)>,
    /// 评估计数,用于周期性回收空闲 key。
    evals: u64,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// 评估一条来自 `node_id` 的事件;返回应执行的全局封禁(可能多条,
    /// 多个策略同时命中时全部返回,调用方按 ip 幂等落库)。
    pub fn evaluate(
        &mut self,
        policies: &[PolicyConfig],
        node_id: &str,
        event: &Event,
        now: u64,
    ) -> Vec<GlobalBanRecord> {
        // 窗口已空的 key 与 TTL 已过期的触发记录必须回收:上报的 IP 来自
        // 真实攻击流量,扫描器轮换源 IP 会让两张表无界增长。摊销在每 512
        // 次评估扫一遍,事件洪峰下也不会退化成每事件全表遍历。回收不能
        // 只挑“当前为空”的 key:只被命中过一次的源 IP 若不再被评估,它
        // 的窗口永远不会为空,必须按各策略的 horizon 把过期条目清出来。
        self.evals = self.evals.wrapping_add(1);
        if self.evals % 512 == 0 {
            let horizons: HashMap<&str, u64> = policies
                .iter()
                .map(|p| {
                    let window = p.window.map(|w| w.as_secs()).unwrap_or(u64::MAX);
                    let horizon = if window == u64::MAX { p.ttl.as_secs() } else { window };
                    (p.id.as_str(), horizon)
                })
                .collect();
            // 与 evaluate 内同款 horizon 截断;策略已删除的 key 视为
            // horizon=0 全清。O(n) 遍历,不改任何在窗记录的判定语义。
            self.windows.retain(|(pid, _), w| {
                let horizon = horizons.get(pid.as_str()).copied().unwrap_or(0);
                while let Some((ts, _)) = w.front() {
                    if now.saturating_sub(*ts) > horizon {
                        w.pop_front();
                    } else {
                        break;
                    }
                }
                !w.is_empty()
            });
            self.triggered.retain(|_, (_, exp)| *exp > now);
        }
        let Some(ip) = event.subject_ip().map(str::to_owned) else {
            return vec![];
        };
        let plugin = event.source_plugin().unwrap_or_default();
        let kind = event.kind_name();
        let mut out = Vec::new();
        for p in policies {
            if p.r#match.plugin != plugin || p.r#match.event != kind {
                continue;
            }
            // severity 限定:策略声明了严重级别时,事件必须带同名级别
            // (大小写不敏感);无 severity 的事件(老 Agent / 非 Block)
            // 不参与。未声明的策略行为不变。
            if let Some(want) = &p.r#match.severity {
                match event.severity_name() {
                    Some(got) if got.eq_ignore_ascii_case(want) => {}
                    _ => continue,
                }
            }
            let window_secs = p.window.map(|w| w.as_secs()).unwrap_or(u64::MAX);
            let key = (p.id.clone(), ip.clone());
            let w = self.windows.entry(key).or_default();
            w.push_back((now, node_id.to_string()));
            // 只保留窗口内的记录(窗口无界时按 TTL 截断,防内存膨胀)。
            let horizon = if window_secs == u64::MAX {
                p.ttl.as_secs()
            } else {
                window_secs
            };
            while let Some((ts, _)) = w.front() {
                if now.saturating_sub(*ts) > horizon {
                    w.pop_front();
                } else {
                    break;
                }
            }

            let mut hit = false;
            if let Some(min) = p.min_nodes {
                let distinct =
                    w.iter().map(|(_, n)| n.as_str()).collect::<std::collections::HashSet<_>>();
                hit = hit || distinct.len() as u32 >= min;
            }
            if let Some(th) = p.threshold {
                hit = hit || w.len() as u32 >= th;
            }
            // 既没配 min_nodes 也没配 threshold 的策略:单次命中即触发。
            let unconfigured = p.min_nodes.is_none() && p.threshold.is_none();
            if !(hit || unconfigured) {
                continue;
            }
            let ttl_secs = p.ttl.as_secs();
            match self.triggered.get(&ip) {
                Some((_, exp)) if *exp > now => continue, // TTL 内去重
                _ => {}
            }
            self.triggered.insert(ip.clone(), (p.id.clone(), now + ttl_secs));
            out.push(GlobalBanRecord {
                ip: ip.clone(),
                reason: p.id.clone(),
                source_node: node_id.to_string(),
                created: now,
                ttl_secs,
            });
        }
        out
    }

    /// 手动封禁/解封后的簿记(手动操作不走策略,但占用去重表防抖)。
    pub fn note_manual(&mut self, ip: &str, ttl_secs: u64) {
        self.triggered.insert(
            ip.to_string(),
            ("manual".to_string(), now_secs() + ttl_secs),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(id: &str, min_nodes: Option<u32>, threshold: Option<u32>, window_secs: Option<u64>) -> PolicyConfig {
        PolicyConfig {
            id: id.into(),
            r#match: crate::config::PolicyMatch {
                plugin: "ssh-guard".into(),
                event: "ban".into(),
                severity: None,
            },
            min_nodes,
            threshold,
            window: window_secs.map(std::time::Duration::from_secs),
            ttl: std::time::Duration::from_secs(3600),
        }
    }

    fn ban_event(ip: &str) -> Event {
        Event::Ban {
            ip: ip.into(),
            reason: "ssh bruteforce".into(),
            plugin: "ssh-guard".into(),
            scope: "local".into(),
            ttl_secs: 3600,
            country: None,
        }
    }

    fn block_event(ip: &str, severity: Option<&str>) -> Event {
        Event::Block {
            ip: ip.into(),
            rule_id: "942100".into(),
            site: "www".into(),
            severity: severity.map(str::to_string),
            path: Some("/login".into()),
            hits: vec![942100],
            country: None,
            score: Some(5),
        }
    }

    /// http-guard block 类策略(可带 severity 限定)。
    fn http_policy(id: &str, severity: Option<&str>) -> PolicyConfig {
        PolicyConfig {
            id: id.into(),
            r#match: crate::config::PolicyMatch {
                plugin: "http-guard".into(),
                event: "block".into(),
                severity: severity.map(str::to_string),
            },
            min_nodes: None,
            threshold: None,
            window: None,
            ttl: std::time::Duration::from_secs(3600),
        }
    }

    #[test]
    fn min_nodes_needs_distinct_reporters() {
        let mut eng = PolicyEngine::new();
        let ps = vec![policy("p", Some(2), None, None)];
        assert!(eng.evaluate(&ps, "a", &ban_event("1.1.1.1"), 100).is_empty());
        // 同一节点重复上报不计入 min_nodes。
        assert!(eng.evaluate(&ps, "a", &ban_event("1.1.1.1"), 110).is_empty());
        let hits = eng.evaluate(&ps, "b", &ban_event("1.1.1.1"), 120);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reason, "p");
        // TTL 内去重。
        assert!(eng.evaluate(&ps, "c", &ban_event("1.1.1.1"), 130).is_empty());
    }

    #[test]
    fn threshold_counts_window_total() {
        let mut eng = PolicyEngine::new();
        let ps = vec![policy("p", None, Some(3), Some(60))];
        assert!(eng.evaluate(&ps, "a", &ban_event("2.2.2.2"), 100).is_empty());
        assert!(eng.evaluate(&ps, "b", &ban_event("2.2.2.2"), 101).is_empty());
        assert_eq!(eng.evaluate(&ps, "c", &ban_event("2.2.2.2"), 102).len(), 1);
        // 窗口滑出后重新计数。
        assert!(eng.evaluate(&ps, "d", &ban_event("3.3.3.3"), 200).is_empty());
        assert!(eng.evaluate(&ps, "e", &ban_event("3.3.3.3"), 201).is_empty());
        assert_eq!(eng.evaluate(&ps, "f", &ban_event("3.3.3.3"), 202).len(), 1);
        // 触发后 TTL 内去重。
        assert!(eng.evaluate(&ps, "g", &ban_event("3.3.3.3"), 203).is_empty());
    }

    #[test]
    fn window_expiry_drops_old_hits() {
        let mut eng = PolicyEngine::new();
        let ps = vec![policy("p", None, Some(2), Some(10))];
        assert!(eng.evaluate(&ps, "a", &ban_event("4.4.4.4"), 0).is_empty());
        // 100s 后窗口已滑出,计数从零开始。
        assert!(eng.evaluate(&ps, "b", &ban_event("4.4.4.4"), 100).is_empty());
    }

    #[test]
    fn unrelated_events_ignored() {
        let mut eng = PolicyEngine::new();
        let ps = vec![policy("p", None, None, None)];
        let e = Event::ConfigChanged { hash: "h".into() };
        assert!(eng.evaluate(&ps, "a", &e, 1).is_empty());
        let block = Event::Block {
            ip: "5.5.5.5".into(),
            rule_id: "942100".into(),
            site: "www".into(),
            severity: None,
            path: None,
            hits: vec![],
            score: None,
            country: None,
        };
        // 插件不匹配(ssh-guard vs http-guard)。
        assert!(eng.evaluate(&ps, "a", &block, 1).is_empty());
        // 单次命中即触发型策略。
        assert_eq!(eng.evaluate(&ps, "a", &ban_event("6.6.6.6"), 1).len(), 1);
    }

    /// severity 限定的策略必须真的按事件 severity 过滤:不带 severity
    /// 的 Block 与级别不同的 Block 都不得触发,同名级别大小写不敏感命中。
    #[test]
    fn severity_scoped_policy_filters_on_event_severity() {
        let mut eng = PolicyEngine::new();
        let ps = vec![http_policy("crit", Some("critical"))];
        assert!(
            eng.evaluate(&ps, "a", &block_event("7.7.7.1", None), 1).is_empty(),
            "event without severity must not match a severity-scoped policy"
        );
        assert!(
            eng.evaluate(&ps, "a", &block_event("7.7.7.2", Some("warning")), 2).is_empty(),
            "non-matching severity must not trigger"
        );
        let hits = eng.evaluate(&ps, "a", &block_event("7.7.7.3", Some("CRITICAL")), 3);
        assert_eq!(hits.len(), 1, "matching severity (case-insensitive) must trigger");
        assert_eq!(hits[0].reason, "crit");
    }

    #[test]
    fn unscoped_policies_match_any_severity() {
        let mut eng = PolicyEngine::new();
        let ps = vec![http_policy("any", None)];
        assert_eq!(eng.evaluate(&ps, "a", &block_event("8.8.8.1", None), 1).len(), 1);
        assert_eq!(eng.evaluate(&ps, "b", &block_event("8.8.8.2", Some("notice")), 2).len(), 1);
        // Ban 类事件没有 severity 概念,但也不受影响。
        assert_eq!(eng.evaluate(&ps, "c", &ban_event("8.8.8.3"), 3).len(), 0);
    }

    /// 周期回收必须覆盖只被命中过一次的 key:不再被评估的源 IP 也要按
    /// 策略 horizon 清出,且回收后判定语义不变。
    #[test]
    fn periodic_pass_reclaims_once_seen_keys() {
        let mut eng = PolicyEngine::new();
        let ps = vec![policy("p", None, Some(2), Some(60))];
        // 单次命中的 IP:永不再次评估。
        assert!(eng.evaluate(&ps, "a", &ban_event("9.9.9.9"), 100).is_empty());
        assert_eq!(eng.windows.len(), 1);
        // 511 次无关评估(无主语 IP,不进窗口)后触发第 512 次的周期回收;
        // now=1000 早已超出 60s 窗口。
        let filler = Event::ConfigChanged { hash: "h".into() };
        for _ in 0..511 {
            assert!(eng.evaluate(&ps, "a", &filler, 1000).is_empty());
        }
        assert!(eng.windows.is_empty(), "once-seen key must be reclaimed by the periodic pass");
        // 判定语义不变:新 IP 仍需两次命中才触发。
        assert!(eng.evaluate(&ps, "a", &ban_event("9.9.9.8"), 2000).is_empty());
        assert_eq!(eng.evaluate(&ps, "b", &ban_event("9.9.9.8"), 2001).len(), 1);
        // 在窗记录不得被周期回收误删:第二条还在窗口内。
        assert_eq!(eng.windows.len(), 1);
    }
}
