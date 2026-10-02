//! Agent 共享状态:生效配置、事件环、待确认变更(防自锁回滚)。

use rooster_config::{parse_and_validate, ConfigError, ConfigWriter, EffectiveConfig, WatcherState};
use rooster_nft::BanManager;
use rooster_proto::Event;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::management::auth::AuthGate;
use crate::outbox::Outbox;

const MAX_EVENTS: usize = 500;

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub ts: u64,
    pub event: Event,
}

/// 已应用但未确认的变更:超时未确认则回滚快照。
pub struct PendingConfirm {
    pub token: String,
    pub snapshot_raw: String,
    pub deadline: tokio::time::Instant,
}

pub struct AgentState {
    pub config_path: PathBuf,
    pub writer: ConfigWriter,
    pub watcher: Arc<WatcherState>,
    pub effective: RwLock<EffectiveConfig>,
    pub events: Mutex<VecDeque<EventRecord>>,
    pub pending_confirm: Mutex<Option<PendingConfirm>>,
    pub auth: AuthGate,
    /// 串行化「读磁盘 → 打补丁 → 原子落盘」整段配置读改写。读与写之间
    /// 没有 CAS,并发请求会基于同一份旧快照互相覆盖(后写者静默吞掉先写者,
    /// 连 `X-Rooster-Overwrote` 都不会发)。`commit_raw` 自身不取这把锁,
    /// 否则已持锁的调用方会自死锁;由各调用点在临界区入口获取。
    pub write_lock: Mutex<()>,
    /// 封禁管理器:无 CAP_NET_ADMIN / 无 nf_tables 时为 None,
    /// 封禁类接口返回 503,其余功能不受影响。
    pub bans: RwLock<Option<Arc<dyn BanManager>>>,
    /// 封禁引擎状态:与 `bans` 同步更新,不可用时携带具体原因,
    /// 经 `/stats` 与 `/bans` 透出(否则面板只能看到一个空 503)。
    pub ban_status: RwLock<crate::bans::BanStatus>,
    /// 端口转发运行时:commit/热重载后增量应用。
    pub forwards: Arc<crate::forward::ForwardRuntime>,
    /// ssh-guard 常驻任务句柄;配置变化时重启。
    pub sshguard_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 当前运行中的 ssh-guard 配置(序列化快照,变更比对用)。
    pub sshguard_cfg: Mutex<Option<serde_json::Value>>,
    /// L4 加固提升器任务(蜜罐/扫描/限速命中 → 封禁);配置变化时重启。
    pub hardening_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 加固下发快照:hardening 段 + 影响 openports 的字段(变更比对用)。
    pub hardening_cfg: Mutex<Option<serde_json::Value>>,
    /// 事件通道(ssh-guard 等子任务 → 事件环)。
    pub events_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Event>>>,
    /// 运行时重配置通知:commit_raw 与热重载 Applied 后触发,run() 中的
    /// 循环消费(转发 diff、白名单重算、ssh-guard 重启、wasm 重载)。
    /// 回滚也走 commit_raw,因此自动被覆盖。
    pub runtime_notify: tokio::sync::Notify,
    /// WASM 插件运行时。
    pub wasmrt: Arc<crate::wasmrt::WasmRuntime>,
    /// 当前运行的 wasm 配置快照(变更比对)。
    pub wasm_cfg: Mutex<Option<serde_json::Value>>,
    /// http-guard 运行时:80/443 反代,热重载增量应用。
    pub httpguard: Arc<crate::httpguard::HttpGuardRuntime>,
    /// WAF 引擎桥接(内置签名 + CRS 子集)。
    pub waf: Arc<crate::waf::WafInspector>,
    /// 最近一次 WAF 规则加载报告(面板「规则加载报告」数据源)。
    pub waf_report: RwLock<serde_json::Value>,
    /// 当前运行的 waf 配置快照(变更比对)。
    pub waf_cfg: Mutex<Option<serde_json::Value>>,
    /// Hub 离线事件补报缓冲;未配置 hub 时为 None。
    pub hub_outbox: Mutex<Option<Arc<Outbox>>>,
    /// push_event 后唤醒 hub 会话发送循环立即补报;连接不在时
    /// 许可留到下一轮会话,不会丢。
    pub outbox_notify: tokio::sync::Notify,
    /// 已被 Hub EventAck 确认的 outbox 游标。
    pub outbox_acked: Mutex<u64>,
    /// hub 连接状态(升级自检用)。
    pub hub_connected: tokio::sync::watch::Sender<bool>,
    /// 注入当前 hub 连接的发送端(证书续签等 Agent 主动帧),附会话代号以便
    /// 旧会话退出时不会误注销新会话的发送端。
    pub hub_frame_tx: Mutex<Option<(u64, tokio::sync::mpsc::UnboundedSender<rooster_proto::Frame>)>>,
    hub_frame_gen: AtomicU64,
}

impl AgentState {
    pub fn new(
        config_path: PathBuf,
        writer: ConfigWriter,
        watcher: Arc<WatcherState>,
        effective: EffectiveConfig,
        auth: AuthGate,
    ) -> Self {
        // WAF 桥接先于 effective 移动构造(需要借用读取 data-dir 规则目录)。
        let rules_dir = crate::waf::find_rules_dir(&effective, &effective.agent.data_dir());
        let waf = Arc::new(crate::waf::WafInspector::new(
            &effective,
            rules_dir.as_deref(),
        ));
        Self {
            config_path,
            writer,
            watcher,
            effective: RwLock::new(effective),
            events: Mutex::new(VecDeque::new()),
            pending_confirm: Mutex::new(None),
            auth,
            write_lock: Mutex::new(()),
            bans: RwLock::new(None),
            ban_status: RwLock::new(crate::bans::BanStatus::default()),
            forwards: Arc::new(crate::forward::ForwardRuntime::new()),
            sshguard_task: Mutex::new(None),
            sshguard_cfg: Mutex::new(None),
            hardening_task: Mutex::new(None),
            hardening_cfg: Mutex::new(None),
            events_tx: Mutex::new(None),
            runtime_notify: tokio::sync::Notify::new(),
            wasmrt: Arc::new(crate::wasmrt::WasmRuntime::new()),
            wasm_cfg: Mutex::new(None),
            httpguard: Arc::new(crate::httpguard::HttpGuardRuntime::new(None)),
            waf,
            waf_report: RwLock::new(serde_json::Value::Null),
            waf_cfg: Mutex::new(None),
            hub_outbox: Mutex::new(None),
            outbox_notify: tokio::sync::Notify::new(),
            outbox_acked: Mutex::new(0),
            hub_connected: tokio::sync::watch::Sender::new(false),
            hub_frame_tx: Mutex::new(None),
            hub_frame_gen: AtomicU64::new(0),
        }
    }

    pub fn effective(&self) -> EffectiveConfig {
        self.effective.read().unwrap().clone()
    }

    pub fn current_hash(&self) -> String {
        self.watcher.current.lock().unwrap().clone()
    }

    pub fn push_event(&self, event: Event) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        {
            let mut q = self.events.lock().unwrap();
            q.push_back(EventRecord { ts, event: event.clone() });
            while q.len() > MAX_EVENTS {
                q.pop_front();
            }
        }
        // 配置了 hub 时同步写入补报缓冲(上限 100k,超出丢最旧),
        // 并唤醒会话发送循环立即上报 —— 否则新事件要等下一次 ack/重连。
        if let Some(outbox) = self.hub_outbox.lock().unwrap().as_ref() {
            if let Err(e) = outbox.push(&event) {
                tracing::warn!("outbox push: {e}");
            }
            self.outbox_notify.notify_one();
        }
    }

    /// 经当前 hub 连接发送 Agent 主动帧(未连接时 Err)。
    pub fn send_hub_frame(&self, frame: rooster_proto::Frame) -> Result<(), ()> {
        let slot = self.hub_frame_tx.lock().unwrap().clone();
        match slot {
            Some((_, tx)) => tx.send(frame).map_err(|_| ()),
            None => Err(()),
        }
    }

    /// 连接建立时登记发送端,返回会话号(注销时回传比对)。
    pub fn set_hub_frame(&self, tx: &tokio::sync::mpsc::UnboundedSender<rooster_proto::Frame>) -> u64 {
        let gen = self.hub_frame_gen.fetch_add(1, Ordering::Relaxed) + 1;
        *self.hub_frame_tx.lock().unwrap() = Some((gen, tx.clone()));
        gen
    }

    /// 断线时注销;号不是最新的那次会话就什么都不做(已被新会话接管)。
    pub fn clear_hub_frame(&self, gen: u64) {
        let mut cur = self.hub_frame_tx.lock().unwrap();
        if cur.as_ref().is_some_and(|(g, _)| *g == gen) {
            *cur = None;
        }
    }

    pub fn recent_events(&self) -> Vec<EventRecord> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .map(|r| EventRecord {
                ts: r.ts,
                event: r.event.clone(),
            })
            .collect()
    }

    /// 热重载回调:Applied 更新生效配置;Invalid 保持旧配置。
    pub fn on_reload_outcome(&self, outcome: rooster_config::ReloadOutcome) {
        match outcome {
            rooster_config::ReloadOutcome::Applied {
                hash,
                effective,
                ..
            } => {
                *self.effective.write().unwrap() = effective;
                self.push_event(Event::ConfigChanged { hash });
                self.runtime_notify.notify_one();
                tracing::info!("config reloaded after external change");
            }
            rooster_config::ReloadOutcome::Invalid { error, line, .. } => {
                self.push_event(Event::ConfigInvalid {
                    error,
                    line: line.map(|l| l),
                });
                tracing::warn!("external config change rejected, keeping previous config");
            }
        }
    }

    /// 校验 + 原子落盘 + 生效,并记录 self hash 防止热重载自触发。
    /// 不产生事件;调用方按场景(ConfigChanged / ConfigRolledBack)自行记录。
    pub fn commit_raw(&self, new_raw: &str) -> Result<EffectiveConfig, ConfigError> {
        let (_file, effective) = parse_and_validate(new_raw)?;
        self.writer.write_atomic(new_raw)?;
        let h = rooster_config::hash_content(new_raw);
        *self.watcher.last_self_write.lock().unwrap() = h.clone();
        *self.watcher.current.lock().unwrap() = h;
        *self.effective.write().unwrap() = effective.clone();
        self.runtime_notify.notify_one();
        Ok(effective)
    }

    /// 这些部分的变更需要走确认-回滚流程(nftables 相关配置在
    /// 加入后同样归入此类)。纯展示/统计类修改不触发。
    pub fn needs_confirm(old: &EffectiveConfig, new: &EffectiveConfig) -> bool {
        let part = |e: &EffectiveConfig| {
            serde_json::json!({
                "management": &e.management,
                "hub": &e.hub,
                "security": &e.security,
                // ssh-guard 限速/端口直接决定 nftables meter 规则
                "ssh_guard": &e.plugins.ssh_guard,
                // 加固规则同样直接写 nftables(蜜罐封禁误配会断真实服务)
                "hardening": &e.hardening,
            })
        };
        part(old) != part(new)
    }

    /// 登记待确认变更并启动回滚计时器。返回 false 表示覆盖了
    /// 尚未确认的上一笔变更(旧计时器会自动失效)。
    pub fn start_confirm_timer(
        self: &Arc<Self>,
        token: String,
        snapshot_raw: String,
        timeout: Duration,
    ) {
        {
            let mut pending = self.pending_confirm.lock().unwrap();
            *pending = Some(PendingConfirm {
                token: token.clone(),
                snapshot_raw,
                deadline: tokio::time::Instant::now() + timeout,
            });
        }
        let state = self.clone();
        tokio::spawn(async move {
            let deadline = state
                .pending_confirm
                .lock()
                .unwrap()
                .as_ref()
                .map(|p| p.deadline)
                .unwrap_or_else(tokio::time::Instant::now);
            tokio::time::sleep_until(deadline).await;
            let snapshot = {
                let pending = state.pending_confirm.lock().unwrap();
                match pending.as_ref() {
                    Some(p) if p.token == token => p.snapshot_raw.clone(),
                    _ => return, // 已被确认或被更新的变更取代
                }
            };
            tracing::warn!("config change not confirmed in time, rolling back");
            // 与 API 写入互斥:回滚快照基于变更时的磁盘内容,若中途有
            // 子树写入或外部编辑已落盘,不加锁会把它们一并回退掉。
            let _guard = state.write_lock.lock().unwrap();
            match state.commit_raw(&snapshot) {
                Ok(_) => {
                    state.push_event(Event::ConfigRolledBack {
                        reason: "apply/confirm timeout".to_string(),
                    });
                    // 回滚同样改了配置 hash。Frame 编码是位置相关的(bincode),
                    // 给 ConfigRolledBack 加字段会让老 Hub 直接解不了帧,所以这里
                    // 补一条 ConfigChanged:hub 靠它把 config_hash 跟回来。
                    state.push_event(Event::ConfigChanged {
                        hash: state.current_hash(),
                    });
                }
                Err(e) => tracing::error!("rollback failed: {e}"),
            }
        });
    }

    /// 确认入口:token 匹配则取消回滚。
    pub fn confirm(&self, token: &str) -> bool {
        let mut pending = self.pending_confirm.lock().unwrap();
        match pending.as_ref() {
            Some(p) if p.token == token => {
                *pending = None;
                true
            }
            _ => false,
        }
    }
}
