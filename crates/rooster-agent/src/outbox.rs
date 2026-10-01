//! 事件补报缓冲:Hub 离线期间事件写入 redb,重连后按 seq
//! 批量补报,收到 EventAck 后清理。上限 100k 条,超出丢最旧。

use redb::{Database, ReadableTable, TableDefinition};
use rooster_proto::Event;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// key = 全局 seq,value = msgpack((ts, Event))。
const OUTBOX: TableDefinition<u64, Vec<u8>> = TableDefinition::new("outbox");
/// 单调 seq 计数器("seq")。ack 清空表后也绝不复用/回退 seq,否则
/// hub 侧游标(outbox_acked)会把新事件当成已确认的旧 seq 跳过。
const META: TableDefinition<&str, u64> = TableDefinition::new("outbox_meta");

/// Agent 侧进程内单库;所有方法内部不 await,持锁安全。
pub struct Outbox {
    db: Mutex<Database>,
    cap: usize,
    /// 表内条目数:open 时数一次,之后由 push/ack 增量维护。
    len: AtomicU64,
    /// 已分配的最大 seq(open 时取 max(meta, 表尾 key),之后只增)。
    next_seq: AtomicU64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Outbox {
    pub fn open(path: &Path, cap: usize) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let db = Database::create(path).map_err(|e| format!("open outbox: {e}"))?;
        {
            let w = db
                .begin_write()
                .map_err(|e| format!("outbox write: {e}"))?;
            let _ = w
                .open_table(OUTBOX)
                .map_err(|e| format!("outbox table: {e}"))?;
            let _ = w
                .open_table(META)
                .map_err(|e| format!("outbox meta table: {e}"))?;
            w.commit().map_err(|e| format!("outbox commit: {e}"))?;
        }
        // 一次性统计已有条目数;此后不再全表扫描(事件热路径)。
        let (len, last_key, persisted_seq) = {
            let r = db.begin_read().map_err(|e| format!("outbox read: {e}"))?;
            let t = r.open_table(OUTBOX).map_err(|e| format!("outbox table: {e}"))?;
            let len = t.iter().map_err(|e| e.to_string())?.count() as u64;
            let last_key = t
                .iter()
                .map_err(|e| e.to_string())?
                .next_back()
                .and_then(|r| r.ok())
                .map(|(k, _)| k.value())
                .unwrap_or(0);
            let m = r
                .open_table(META)
                .map_err(|e| format!("outbox meta table: {e}"))?;
            let persisted = m
                .get("seq")
                .map_err(|e| e.to_string())?
                .map(|v| v.value())
                .unwrap_or(0);
            (len, last_key, persisted)
        };
        Ok(Self {
            db: Mutex::new(db),
            cap,
            len: AtomicU64::new(len),
            next_seq: AtomicU64::new(persisted_seq.max(last_key)),
        })
    }

    /// 追加一条事件,返回分配的 seq(从 1 起,单调递增,永不复用)。
    pub fn push(&self, event: &Event) -> Result<u64, String> {
        let db = self.db.lock().unwrap();
        let w = db.begin_write().map_err(|e| e.to_string())?;
        let next = {
            let mut t = w.open_table(OUTBOX).map_err(|e| e.to_string())?;
            let last = t
                .iter()
                .map_err(|e| e.to_string())?
                .next_back()
                .and_then(|r| r.ok())
                .map(|(k, _)| k.value())
                .unwrap_or(0);
            let next = self.next_seq.load(Ordering::Relaxed).max(last) + 1;
            let payload = rmp_serde::to_vec(&(now_secs(), event)).map_err(|e| e.to_string())?;
            t.insert(next, payload).map_err(|e| e.to_string())?;
            let mut m = w.open_table(META).map_err(|e| e.to_string())?;
            m.insert("seq", next).map_err(|e| e.to_string())?;
            // 容量上限:丢最旧(默认 100k)。条目数走 self.len,
            // 越界时只取最旧的 evict 个 key,不再全表 count()。
            let total = self.len.fetch_add(1, Ordering::Relaxed) + 1;
            if total > self.cap as u64 {
                let evict = (total - self.cap as u64) as usize;
                let keys: Vec<u64> = t
                    .iter()
                    .map_err(|e| e.to_string())?
                    .take(evict)
                    .filter_map(|r| r.ok())
                    .map(|(k, _)| k.value())
                    .collect();
                let mut removed = 0u64;
                for k in keys {
                    if t.remove(k).is_ok() {
                        removed += 1;
                    }
                }
                self.len.fetch_sub(removed, Ordering::Relaxed);
            }
            next
        };
        w.commit().map_err(|e| e.to_string())?;
        // 提交成功后才推进内存计数器:失败只会留下空隙,绝不会回退复用。
        self.next_seq.store(next, Ordering::Relaxed);
        Ok(next)
    }

    /// 取 (after_seq, ..] 范围内的事件,升序。
    pub fn pending(&self, after_seq: u64, limit: usize) -> Result<Vec<(u64, Event)>, String> {
        let (out, bad) = {
            let db = self.db.lock().unwrap();
            let r = db.begin_read().map_err(|e| format!("outbox read: {e}"))?;
            let t = r.open_table(OUTBOX).map_err(|e| format!("outbox table: {e}"))?;
            let mut out: Vec<(u64, Event)> = Vec::new();
            let mut bad: Vec<u64> = Vec::new();
            for row in t
                .range(after_seq + 1..)
                .map_err(|e| e.to_string())?
                .take(limit)
            {
                let (k, v) = row.map_err(|e| e.to_string())?;
                match rmp_serde::from_slice::<(u64, Event)>(&v.value()) {
                    Ok((_ts, event)) => out.push((k.value(), event)),
                    Err(e) => {
                        tracing::warn!(seq = k.value(), error = %e, "outbox row undecodable, dropping");
                        bad.push(k.value());
                    }
                }
            }
            (out, bad)
        };
        // 坏行必须一并删掉:否则一条旧 schema 写不回来的条目会永久堵住
        // 整个补报队列(flush 每次都卡在同一行上,事件永远不再上报)。
        if !bad.is_empty() {
            self.drop_rows(&bad);
        }
        Ok(out)
    }

    /// 删除指定 seq 的行(用于丢弃解不开的坏行)。
    fn drop_rows(&self, keys: &[u64]) {
        let db = self.db.lock().unwrap();
        let Ok(w) = db.begin_write() else { return };
        {
            let Ok(mut t) = w.open_table(OUTBOX) else { return };
            let mut removed = 0u64;
            for k in keys {
                if t.remove(*k).is_ok() {
                    removed += 1;
                }
            }
            self.len.fetch_sub(removed, Ordering::Relaxed);
        }
        let _ = w.commit();
    }

    /// 清理 acked_through(含)之前的全部条目。
    pub fn ack(&self, acked_through: u64) -> Result<(), String> {
        let db = self.db.lock().unwrap();
        let w = db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut t = w.open_table(OUTBOX).map_err(|e| e.to_string())?;
            let keys: Vec<u64> = t
                .range(..=acked_through)
                .map_err(|e| e.to_string())?
                .filter_map(|r| r.ok())
                .map(|(k, _)| k.value())
                .collect();
            let mut removed = 0u64;
            for k in keys {
                if t.remove(k).is_ok() {
                    removed += 1;
                }
            }
            self.len.fetch_sub(removed, Ordering::Relaxed);
        }
        w.commit().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> Outbox {
        let dir = std::env::temp_dir().join(format!("rooster-outbox-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Outbox::open(
            &dir.join(format!("o-{}.redb", rand::random::<u64>())),
            100_000,
        )
        .unwrap()
    }

    fn ev(ip: &str) -> Event {
        Event::Ban {
            ip: ip.into(),
            reason: "r".into(),
            plugin: "ssh-guard".into(),
            scope: "local".into(),
            ttl_secs: 60,
        }
    }

    #[test]
    fn push_pending_ack_cycle() {
        let o = tmp();
        for i in 0..5 {
            let seq = o.push(&ev(&format!("1.2.3.{i}"))).unwrap();
            assert_eq!(seq, (i + 1) as u64, "seq 从 1 起");
        }
        let pending = o.pending(1, 10).unwrap();
        assert_eq!(pending.len(), 4, "游标之后全部待发:seqs 2,3,4,5");
        assert_eq!(pending[0].0, 2);
        o.ack(3).unwrap();
        assert_eq!(o.pending(0, 10).unwrap().len(), 2);
        // ack 清掉表尾后新事件不复用 seq。
        assert_eq!(o.push(&ev("1.2.3.9")).unwrap(), 6);
        assert_eq!(o.pending(3, 10).unwrap()[0].0, 4);
        assert_eq!(o.pending(0, 10).unwrap().len(), 3, "seqs 4,5,6");
    }

    #[test]
    fn cap_evicts_oldest() {
        let dir = std::env::temp_dir().join(format!("rooster-outbox-cap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let o = Outbox::open(&dir.join(format!("cap-{}.redb", rand::random::<u64>())), 3).unwrap();
        for i in 0..6 {
            o.push(&ev(&format!("1.1.1.{i}"))).unwrap();
        }
        let pending = o.pending(0, 10).unwrap();
        assert_eq!(pending.len(), 3, "capped at 3");
        assert_eq!(pending[0].0, 4);
    }

    /// A7:重开数据库后编号继续,即使表已被 ack 清空也不回退复用。
    #[test]
    fn seq_survives_reopen_after_ack_empties_table() {
        let dir = std::env::temp_dir().join(format!("rooster-outbox-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("o.redb");
        {
            let o = Outbox::open(&path, 100_000).unwrap();
            assert_eq!(o.push(&ev("1.1.1.1")).unwrap(), 1);
            assert_eq!(o.push(&ev("1.1.1.2")).unwrap(), 2);
            assert_eq!(o.pending(0, 10).unwrap().len(), 2);
            o.ack(2).unwrap();
            assert!(o.pending(0, 10).unwrap().is_empty(), "表已清空");
        }
        let o = Outbox::open(&path, 100_000).unwrap();
        let seq = o.push(&ev("1.1.1.3")).unwrap();
        assert_eq!(seq, 3, "重开后 seq 必须继续而不是重新从 1 开始");
        let pending = o.pending(0, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 3);
    }

    /// 旧 schema 遗留的解不开的行不能堵住整个补报队列。
    #[test]
    fn undecodable_row_is_skipped_and_removed() {
        let o = tmp();
        o.push(&ev("1.1.1.1")).unwrap();
        {
            let db = o.db.lock().unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut t = w.open_table(OUTBOX).unwrap();
                // 0xc1 是 msgpack 未分配的类型字节 → 必然解码失败。
                t.insert(2u64, vec![0xc1u8, 0x00, 0x7f]).unwrap();
            }
            w.commit().unwrap();
        }
        assert_eq!(o.push(&ev("1.1.1.2")).unwrap(), 3, "坏行不得让 seq 回退");
        let seqs: Vec<u64> = o.pending(0, 10).unwrap().into_iter().map(|(s, _)| s).collect();
        assert_eq!(seqs, vec![1, 3], "坏行必须被跳过而不是让整批报错");
        assert_eq!(o.pending(0, 10).unwrap().len(), 2, "坏行已删除,队列可继续排空");
    }
}
