//! 管理接口鉴权:Bearer + bcrypt 校验,
//! 同一来源失败达到阈值后临时封禁。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

pub const MAX_FAILURES: usize = 5;
pub const FAILURE_WINDOW: Duration = Duration::from_secs(600);
pub const TEMP_BAN: Duration = Duration::from_secs(600);

pub enum AuthOutcome {
    Allowed,
    WrongSecret,
    TemporarilyBanned { until: Instant },
}

pub struct AuthGate {
    /// bcrypt 哈希;空表示未配置,拒绝所有请求。
    hash: RwLock<String>,
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    bans: Mutex<HashMap<IpAddr, Instant>>,
}

impl AuthGate {
    pub fn new(hash: String) -> Self {
        Self {
            hash: RwLock::new(hash),
            failures: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_hash(&self, hash: String) {
        *self.hash.write().unwrap() = hash;
    }

    pub fn hash(&self) -> String {
        self.hash.read().unwrap().clone()
    }

    pub fn verify(&self, peer: IpAddr, presented: Option<&str>) -> AuthOutcome {
        let now = Instant::now();

        {
            // 到期分支必须先释放 guard 再返回/再取锁:`if let` 的 scrutinee
            // 临时值(这里的 MutexGuard)活到整个 if-let 块结束,在块内再次
            // lock 同一把锁会自死锁。
            let mut bans = self.bans.lock().unwrap();
            match bans.get(&peer).copied() {
                Some(until) if now < until => return AuthOutcome::TemporarilyBanned { until },
                Some(_) => {
                    bans.remove(&peer);
                }
                None => {}
            }
        }

        let hash = self.hash.read().unwrap().clone();
        if hash.is_empty() {
            // 未配置密钥:拒绝而不是放行。
            self.record_failure(peer, now);
            return AuthOutcome::WrongSecret;
        }

        let ok = presented
            .map(|p| bcrypt::verify(p, &hash).unwrap_or(false))
            .unwrap_or(false);
        if ok {
            self.failures.lock().unwrap().remove(&peer);
            return AuthOutcome::Allowed;
        }
        self.record_failure(peer, now);
        AuthOutcome::WrongSecret
    }

    fn record_failure(&self, peer: IpAddr, now: Instant) {
        let mut failures = self.failures.lock().unwrap();
        let window = failures.entry(peer).or_default();
        window.push_back(now);
        while window.front().is_some_and(|t| now.duration_since(*t) > FAILURE_WINDOW) {
            window.pop_front();
        }
        if window.len() >= MAX_FAILURES {
            let until = now + TEMP_BAN;
            failures.remove(&peer);
            drop(failures);
            self.bans.lock().unwrap().insert(peer, until);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn gate() -> AuthGate {
        // bcrypt hash of "s3cret"
        AuthGate::new(
            bcrypt::hash("s3cret", 4).unwrap(),
        )
    }

    #[test]
    fn verify_accepts_correct_secret() {
        let g = gate();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(matches!(
            g.verify(ip, Some("s3cret")),
            AuthOutcome::Allowed
        ));
        assert!(matches!(
            g.verify(ip, Some("wrong")),
            AuthOutcome::WrongSecret
        ));
        assert!(matches!(g.verify(ip, None), AuthOutcome::WrongSecret));
    }

    #[test]
    fn repeated_failures_temp_ban() {
        let g = AuthGate::new(bcrypt::hash("x", 4).unwrap());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        for _ in 0..MAX_FAILURES {
            let _ = g.verify(ip, Some("nope"));
        }
        assert!(matches!(
            g.verify(ip, Some("x")),
            AuthOutcome::TemporarilyBanned { .. }
        ));
    }

    #[test]
    fn expired_ban_is_cleared_and_request_succeeds() {
        let g = gate();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4));
        // TEMP_BAN 是 600s,不能真等:直接植入一条已过期的封禁,覆盖
        // `repeated_failures_temp_ban` 走不到的到期分支。
        g.bans
            .lock()
            .unwrap()
            .insert(ip, Instant::now() - Duration::from_secs(1));
        assert!(matches!(
            g.verify(ip, Some("s3cret")),
            AuthOutcome::Allowed
        ));
        assert!(
            !g.bans.lock().unwrap().contains_key(&ip),
            "expired ban entry must be dropped"
        );
    }

    #[test]
    fn empty_hash_rejects_everything() {
        let g = AuthGate::new(String::new());
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(matches!(
            g.verify(ip, Some("anything")),
            AuthOutcome::WrongSecret
        ));
    }
}
