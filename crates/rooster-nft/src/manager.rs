//! [`NftBanManager`]:nft 内核 set + redb 持久化的 [`BanManager`] 实现。
//!
//! - **内核侧**:`block_v4`/`block_v6` set 元素带 timeout,到期内核自摘除;
//! - **用户侧**:redb 表 `bans`(key = ip 字符串,value = `BanEntry` JSON,
//!   `expires_at` 持久化时必填)承担重启后的账本;
//! - 白名单命中的 IP 在任何内核写入之前直接拒封(`Refused`);
//! - 启动对账——redb 里已到期的行删除;仍存活的行按剩余时长重建内核 set
//!   (flush + 写入一个批次,原子完成,同时清掉旧版本误编码的残留)。

use crate::netlink::{allow_contains, block_set_of};
use crate::{BanEntry, BanManager, NftError, NftHandle, SET_ALLOW_V4, SET_ALLOW_V6, SET_BLOCK_V4, SET_BLOCK_V6};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableTable, TableDefinition};

/// 封禁账本:key = ip 字符串,value = `BanEntry` JSON(含 `expires_at`)。
const BANS: TableDefinition<&str, String> = TableDefinition::new("bans");

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// redb 各类错误(Display)统一折算为 `NftError::Netlink` 文本。
fn redb_err(ctx: &str, e: impl std::fmt::Display) -> NftError {
    NftError::Netlink(format!("redb {ctx}: {e}"))
}

/// 默认 [`BanManager`] 实现。
///
/// 内部状态全部放在 `Mutex` 之后,句柄可跨线程共享(`Send + Sync`)。
pub struct NftBanManager {
    handle: NftHandle,
    db: Mutex<Database>,
    /// 白名单网段(拒封 + set_allowlist 全量替换的内存副本)。
    allow: Mutex<Vec<ipnet::IpNet>>,
}

impl NftBanManager {
    /// 打开(或创建)管理器:
    /// 1. `handle.ensure_table()` 保证内核侧表/链/set/规则就位;
    /// 2. 打开 db_path 的 redb(自动建父目录);
    /// 3. 对账(见模块注释)。
    pub fn new(handle: NftHandle, db_path: &Path) -> Result<Self, NftError> {
        handle.ensure_table()?;
        if let Some(dir) = db_path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| NftError::Netlink(format!("create db dir: {e}")))?;
            }
        }
        let db = Database::create(db_path).map_err(|e| redb_err("open", e))?;
        let mgr = NftBanManager {
            handle,
            db: Mutex::new(db),
            allow: Mutex::new(Vec::new()),
        };
        mgr.reconcile()?;
        Ok(mgr)
    }

    /// 重启对账:清理 redb 过期行;存活行按剩余时长全量重建 block set。
    /// 不靠 dump 逐元素比对:旧版本曾把单 IP 编成开区间(覆盖到地址上界),
    /// 逐元素比对会误判为「已在内核」而把它留下;全量重建才能根除。
    fn reconcile(&self) -> Result<(), NftError> {
        let now = now_secs();
        let mut v4: Vec<(String, Option<Duration>)> = Vec::new();
        let mut v6: Vec<(String, Option<Duration>)> = Vec::new();
        for (ip, entry) in self.read_rows()? {
            let Some(expires_at) = entry.expires_at else {
                // 持久化行必须带 expires_at;缺字段视为脏数据清除
                self.remove_row(&ip)?;
                continue;
            };
            if expires_at <= now {
                self.remove_row(&ip)?;
                continue;
            }
            let Ok(addr) = ip.trim().parse::<std::net::IpAddr>() else {
                tracing::warn!(ip, "redb ban row has unparsable ip, dropping");
                self.remove_row(&ip)?;
                continue;
            };
            let ttl = Duration::from_secs(expires_at - now);
            match block_set_of(&addr) {
                SET_BLOCK_V6 => v6.push((ip, Some(ttl))),
                _ => v4.push((ip, Some(ttl))),
            }
        }
        self.handle.replace_set_elements(SET_BLOCK_V4, &v4)?;
        self.handle.replace_set_elements(SET_BLOCK_V6, &v6)
    }

    /// 读取全部 (ip, entry) 行;无法反序列化的行直接清除。
    fn read_rows(&self) -> Result<Vec<(String, BanEntry)>, NftError> {
        let (rows, corrupt) = {
            let db = self.db.lock().unwrap();
            let txn = db
                .begin_read()
                .map_err(|e| redb_err("read txn", e))?;
            // 新库尚无 bans 表(从未写入)视为空,而不是错误
            let table = match txn.open_table(BANS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(redb_err("open table", e)),
            };
            let mut rows = Vec::new();
            let mut corrupt = Vec::new();
            for row in table.iter().map_err(|e| redb_err("iter", e))? {
                let (k, v) = row.map_err(|e| redb_err("row", e))?;
                let ip = k.value().to_string();
                match serde_json::from_str::<BanEntry>(&v.value()) {
                    Ok(entry) => rows.push((ip, entry)),
                    Err(_) => corrupt.push(ip),
                }
            }
            (rows, corrupt)
        };
        for ip in corrupt {
            tracing::warn!(ip, "corrupt ban row in redb, dropping");
            self.remove_row(&ip)?;
        }
        Ok(rows)
    }

    /// 写入/覆盖一行(expires_at 必填,由调用方设置)。
    fn put_row(&self, entry: &BanEntry, expires_at: u64) -> Result<(), NftError> {
        let mut stored = entry.clone();
        stored.expires_at = Some(expires_at);
        let json = serde_json::to_string(&stored)
            .map_err(|e| NftError::Netlink(format!("serialize ban: {e}")))?;
        let db = self.db.lock().unwrap();
        let txn = db
            .begin_write()
            .map_err(|e| redb_err("write txn", e))?;
        {
            let mut table = txn
                .open_table(BANS)
                .map_err(|e| redb_err("open table", e))?;
            table
                .insert(entry.ip.as_str(), json)
                .map_err(|e| redb_err("put", e))?;
        }
        txn.commit().map_err(|e| redb_err("commit", e))?;
        Ok(())
    }

    /// 删除一行;行不存在也返回 Ok。
    fn remove_row(&self, ip: &str) -> Result<(), NftError> {
        let db = self.db.lock().unwrap();
        let txn = db
            .begin_write()
            .map_err(|e| redb_err("write txn", e))?;
        {
            let mut table = txn
                .open_table(BANS)
                .map_err(|e| redb_err("open table", e))?;
            table.remove(ip).map_err(|e| redb_err("remove", e))?;
        }
        txn.commit().map_err(|e| redb_err("commit", e))?;
        Ok(())
    }
}

impl BanManager for NftBanManager {
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError> {
        let addr: std::net::IpAddr = entry
            .ip
            .trim()
            .parse()
            .map_err(|_| NftError::InvalidAddress(entry.ip.clone()))?;
        // 白名单命中在任何内核写入之前拒绝
        if allow_contains(&self.allow.lock().unwrap(), &addr) {
            return Err(NftError::Refused(format!(
                "ip {} is allowlisted, refusing ban",
                entry.ip
            )));
        }
        let set = block_set_of(&addr);
        // 重复封禁:内核元素 timeout 刷新 + redb 行覆盖 → 延长
        self.handle
            .add_set_element(set, &entry.ip, Some(entry.ttl))?;
        self.put_row(entry, now_secs().saturating_add(entry.ttl.as_secs()))
    }

    fn remove_ban(&self, ip: &str) -> Result<(), NftError> {
        let addr: std::net::IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| NftError::InvalidAddress(ip.to_string()))?;
        let set = block_set_of(&addr);
        // 元素不存在 → ENOENT 被底层容忍,返回 Ok
        self.handle.delete_set_element(set, ip)?;
        self.remove_row(ip.trim())
    }

    fn list_bans(&self) -> Result<Vec<BanEntry>, NftError> {
        let now = now_secs();
        let rows = self.read_rows()?;
        let mut live = Vec::new();
        for (ip, mut entry) in rows {
            match entry.expires_at {
                Some(expires_at) if expires_at > now => {
                    // ttl 置为剩余秒数(展示用);expires_at 保持绝对时间
                    entry.ttl = Duration::from_secs(expires_at - now);
                    live.push(entry);
                }
                _ => {
                    self.remove_row(&ip)?;
                }
            }
        }
        Ok(live)
    }

    fn set_allowlist(&self, nets: &[ipnet::IpNet]) -> Result<(), NftError> {
        // 全量替换内核 allow set:一个原子批次里 flush + 写入新网段,
        // 不再 dump-回删(旧编码的开区间残留无法用 dump 字符串回删)
        for (set, want_v6) in [(SET_ALLOW_V4, false), (SET_ALLOW_V6, true)] {
            let rows: Vec<(String, Option<Duration>)> = nets
                .iter()
                .filter(|n| matches!(n, ipnet::IpNet::V6(_)) == want_v6)
                .map(|n| (n.to_string(), None))
                .collect();
            self.handle.replace_set_elements(set, &rows)?;
        }
        *self.allow.lock().unwrap() = nets.to_vec();
        Ok(())
    }

    fn set_ssh_limit(&self, port: u16, rate: &str, burst: u32) -> Result<(), NftError> {
        self.handle.set_ssh_rate_limit(port, rate, burst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{shared_handle, MockSocket};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rooster-nft-{}-{}-{}.redb",
            tag,
            std::process::id(),
            DB_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn entry(ip: &str, ttl: Duration) -> BanEntry {
        BanEntry {
            ip: ip.into(),
            ttl,
            reason: "ssh brute force".into(),
            plugin: "ssh-guard".into(),
            node: "node-a".into(),
            scope: crate::BanScope::Local,
            expires_at: None,
        }
    }

    /// 直接向 redb 预置行(模拟上次运行残留)。
    fn seed_db(path: &std::path::Path, rows: &[BanEntry]) {
        let db = Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(BANS).unwrap();
            for e in rows {
                t.insert(e.ip.as_str(), serde_json::to_string(e).unwrap())
                    .unwrap();
            }
        }
        txn.commit().unwrap();
        drop(db);
    }

    #[test]
    fn ban_entry_serde_round_trip_and_skip() {
        let e = BanEntry {
            ip: "203.0.113.5".into(),
            ttl: Duration::from_secs(3600),
            reason: "ssh brute".into(),
            plugin: "ssh-guard".into(),
            node: "node-a".into(),
            scope: crate::BanScope::Local,
            expires_at: None,
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(!j.contains("expires_at"));
        assert!(j.contains("\"scope\":\"local\""));
        let back: BanEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(back.ip, e.ip);
        assert_eq!(back.expires_at, None);

        let mut e2 = e.clone();
        e2.expires_at = Some(42);
        let j2 = serde_json::to_string(&e2).unwrap();
        assert!(j2.contains("\"expires_at\":42"));
        let back2: BanEntry = serde_json::from_str(&j2).unwrap();
        assert_eq!(back2.expires_at, Some(42));
        assert_eq!(back2.scope, crate::BanScope::Local);
    }

    #[test]
    fn apply_list_remove_round_trip() {
        let db = temp_db("roundtrip");
        let mock = MockSocket::default();
        let mgr = NftBanManager::new(
            NftHandle::with_socket(Box::new(mock)),
            &db,
        )
        .unwrap();

        mgr.apply_ban(&entry("203.0.113.7", Duration::from_secs(3600)))
            .unwrap();
        let bans = mgr.list_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "203.0.113.7");
        let exp = bans[0].expires_at.unwrap();
        assert!(exp > now_secs(), "expires_at must be absolute unix secs");
        assert!(bans[0].ttl.as_secs() <= 3600 && bans[0].ttl.as_secs() > 3590);

        // 重复封禁视为延长:expires_at 只增不减
        mgr.apply_ban(&entry("203.0.113.7", Duration::from_secs(7200)))
            .unwrap();
        let bans = mgr.list_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert!(bans[0].expires_at.unwrap() >= exp);

        mgr.remove_ban("203.0.113.7").unwrap();
        assert!(mgr.list_bans().unwrap().is_empty());
        drop(mgr);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn refused_on_allowlist_and_kernel_replace() {
        let db = temp_db("allowlist");
        let mock = std::sync::Arc::new(std::sync::Mutex::new(MockSocket::default()));
        let mgr = NftBanManager::new(shared_handle(mock.clone()), &db).unwrap();

        mgr.set_allowlist(&["10.0.0.0/8".parse().unwrap()])
            .unwrap();
        let sock = mock.lock().unwrap();
        // 全量替换 = 一个批次里 flush + 写入,不再 dump-回删(旧编码的开区间
        // 残留无法用 dump 字符串回删)
        assert!(sock.sent_flush(crate::SET_ALLOW_V4));
        assert!(sock.sent_flush(crate::SET_ALLOW_V6));
        let added = sock.setelem_ops(crate::consts::NFT_MSG_NEWSETELEM, crate::SET_ALLOW_V4);
        assert!(added.iter().any(|(s, _)| s == "10.0.0.0/8"));

        // 白名单 IP 拒封,且不产生任何内核写入
        let before = sock.sent.len();
        let err = mgr
            .apply_ban(&entry("10.1.2.3", Duration::from_secs(60)))
            .unwrap_err();
        assert!(matches!(err, NftError::Refused(_)));
        assert_eq!(sock.sent.len(), before, "no kernel writes on refused ban");
        assert!(mgr.list_bans().unwrap().is_empty());
        drop(mgr);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn reconcile_prunes_expired_and_readds_missing() {
        let db = temp_db("reconcile");
        let mut expired = entry("198.51.100.9", Duration::from_secs(60));
        expired.expires_at = Some(now_secs().saturating_sub(10));
        let mut live = entry("203.0.113.20", Duration::from_secs(1800));
        live.expires_at = Some(now_secs() + 1800);
        seed_db(&db, &[expired, live]);

        let mock = MockSocket::default();
        let mock = std::sync::Arc::new(std::sync::Mutex::new(mock));
        let mgr = NftBanManager::new(shared_handle(mock.clone()), &db).unwrap();

        // 过期行已被清理,仅剩 live 行
        let bans = mgr.list_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "203.0.113.20");
        // 重新下发的元素带剩余时长(≈1800s,允许 ±5s)
        let sock = mock.lock().unwrap();
        let adds = sock.setelem_ops(crate::consts::NFT_MSG_NEWSETELEM, crate::SET_BLOCK_V4);
        assert!(adds.iter().any(|(s, t)| {
            s == "203.0.113.20" && t.map(|x| (1795..=1800).contains(&x)).unwrap_or(false)
        }));
        drop(mgr);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn remove_absent_ban_is_ok() {
        let db = temp_db("remove-absent");
        let mock = std::sync::Arc::new(std::sync::Mutex::new(MockSocket::default()));
        let mgr = NftBanManager::new(shared_handle(mock.clone()), &db).unwrap();
        // 建表批已 ACK;下一个写批(DELSETELEM)回 ENOENT → tolerated
        mock.lock().unwrap().error_once = Some(-2);
        mgr.remove_ban("192.0.2.9").unwrap();
        assert!(mgr.list_bans().unwrap().is_empty());
        drop(mgr);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn list_set_elements_parses_dump_and_errors_propagate() {
        let mut mock = MockSocket::default();
        mock.elem_dumps.push_back(vec![MockSocket::elem_payload(
            crate::SET_BLOCK_V4,
            &[("203.0.113.9", Some(42_000)), ("10.0.0.0/8", None)],
        )]);
        let h = NftHandle::with_socket(Box::new(mock));
        let elems = h.list_set_elements(crate::SET_BLOCK_V4).unwrap();
        assert!(elems.contains(&("203.0.113.9".to_string(), Some(42))));
        assert!(elems.contains(&("10.0.0.0/8".to_string(), None)));

        // 非容忍 errno → Netlink 错误文本带 errno
        let mut mock = MockSocket::default();
        mock.error_once = Some(-22);
        let h = NftHandle::with_socket(Box::new(mock));
        let err = h
            .add_set_element(crate::SET_BLOCK_V4, "203.0.113.9", Some(Duration::from_secs(1)))
            .unwrap_err();
        assert!(err.to_string().contains("errno -22"), "got: {err}");
    }
}

