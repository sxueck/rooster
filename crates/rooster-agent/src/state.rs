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

/// GeoIP reader 缓存项:(库路径, reader;无库/损坏时 None)。
type GeoCache = (PathBuf, Option<Arc<maxminddb::Reader<Vec<u8>>>>);

/// CLI 运行时覆盖项(容器部署):叠加在每次 effective 配置读取之上,
/// 热重载/commit 后自动重新应用,不回写 enrolled config.yaml。
#[derive(Debug, Clone, Default)]
pub struct RuntimeOverrides {
    pub data_dir: Option<PathBuf>,
    pub upgrade_method: Option<rooster_config::UpgradeMethod>,
}

impl RuntimeOverrides {
    /// 幂等叠加:只覆盖显式给出的字段。
    pub fn apply(&self, mut effective: EffectiveConfig) -> EffectiveConfig {
        if let Some(data_dir) = &self.data_dir {
            effective.agent.data_dir = Some(data_dir.clone());
        }
        if let Some(method) = self.upgrade_method {
            effective.upgrade.method = method;
        }
        effective
    }
}

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
    /// Serialize Nginx discovery mutations and recovery journals.
    pub nginx_lock: Mutex<()>,
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
    /// CLI 运行时覆盖项(容器);effective() 每次读取时叠加。
    pub runtime_overrides: RwLock<RuntimeOverrides>,
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
    /// 串行化并发 Upgrade 帧:备份 prev → 写 marker → 原子替换必须整体
    /// 互斥,否则两个升级互相覆盖回滚备份 / 交错 rename。
    pub upgrade_lock: tokio::sync::Mutex<()>,
    /// 注入当前 hub 连接的发送端(证书续签等 Agent 主动帧),附会话代号以便
    /// 旧会话退出时不会误注销新会话的发送端。
    pub hub_frame_tx: Mutex<Option<(u64, tokio::sync::mpsc::UnboundedSender<rooster_proto::Frame>)>>,
    hub_frame_gen: AtomicU64,
    /// 事件属地标注用的 GeoIP reader 缓存(路径→reader;路径随配置变化
    /// 才重开库,避免每个事件重读 ~10MB mmdb)。无库时存 None,
    /// 下一个事件再试(后台会自动下载补齐)。
    geo_reader: Mutex<Option<GeoCache>>,
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
            nginx_lock: Mutex::new(()),
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
            runtime_overrides: RwLock::new(RuntimeOverrides::default()),
            hub_connected: tokio::sync::watch::Sender::new(false),
            upgrade_lock: tokio::sync::Mutex::new(()),
            hub_frame_tx: Mutex::new(None),
            hub_frame_gen: AtomicU64::new(0),
            geo_reader: Mutex::new(None),
        }
    }

    /// CLI 运行时覆盖项(容器);构造后、共享 Arc 前设置一次。
    pub fn set_runtime_overrides(&self, overrides: RuntimeOverrides) {
        *self.runtime_overrides.write().unwrap() = overrides;
    }

    /// 读取生效配置,叠加 CLI 运行时覆盖项(容器模式的 data-dir /
    /// upgrade-method 在热重载后仍然生效)。
    pub fn effective(&self) -> EffectiveConfig {
        let eff = self.effective.read().unwrap().clone();
        self.runtime_overrides.read().unwrap().apply(eff)
    }

    pub fn current_hash(&self) -> String {
        self.watcher.current.lock().unwrap().clone()
    }

    pub fn push_event(&self, event: Event) {
        let event = self.annotate_country(event);
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

    /// 拦截/封禁类事件标注攻击源国家(Hub 总览 top-countries 的唯一
    /// 数据源;无库/解析失败 → 不动,保持 country=None)。
    /// 只在 push_event 这个唯一汇入点做一次,所有发射处不用各自关心。
    fn annotate_country(&self, mut event: Event) -> Event {
        let ip = match &mut event {
            Event::Ban { ip, country, .. }
            | Event::HoneypotHit { ip, country, .. }
            | Event::Block { ip, country, .. } => {
                if country.is_some() {
                    return event;
                }
                ip.clone()
            }
            _ => return event,
        };
        let name = self.geo_country(&ip);
        if let Event::Ban { country, .. }
        | Event::HoneypotHit { country, .. }
        | Event::Block { country, .. } = &mut event
        {
            *country = name;
        }
        event
    }

    fn geo_country(&self, ip: &str) -> Option<String> {
        let eff = self.effective();
        let geo = eff.attribution_geoip();
        if !geo.enabled() {
            return None;
        }
        let path = crate::geoip::db_path(&eff.agent.data_dir(), geo.database());
        let mut cache = self.geo_reader.lock().unwrap();
        let reader: Option<Arc<maxminddb::Reader<Vec<u8>>>> = match cache.as_ref() {
            Some((cached, reader)) if *cached == path => reader.clone(),
            _ => {
                let opened = crate::geoip::open_db(&path).ok().map(Arc::new);
                *cache = Some((path, opened.clone()));
                opened
            }
        };
        crate::geoip::country_name(reader.as_ref()?, ip)
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
                let effective = self.runtime_overrides.read().unwrap().apply(effective);
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
        // 覆盖项叠加在返回值与内存生效配置上;磁盘文件保持 enrolled 内容。
        let effective = self.runtime_overrides.read().unwrap().apply(effective);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::auth::AuthGate;
    use rooster_config::{hash_content, parse_and_validate, ConfigWriter, WatcherState};
    use std::path::Path;

    fn build_state(dir: &Path) -> Arc<AgentState> {
        let raw = format!(
            "local:\n  agent:\n    node-name: override-test\n    data-dir: {}\n  upgrade:\n    method: systemd\n",
            dir.join("enrolled-data").display()
        );
        let config_path = dir.join("config.yaml");
        std::fs::write(&config_path, &raw).unwrap();
        let (_file, effective) = parse_and_validate(&raw).unwrap();
        let writer = ConfigWriter::new(&config_path, dir);
        let watcher = Arc::new(WatcherState::new(hash_content(&raw)));
        Arc::new(AgentState::new(
            config_path,
            writer,
            watcher,
            effective,
            AuthGate::new(String::new()),
        ))
    }

    /// 容器模式 CLI 覆盖项(agent --data-dir / --upgrade-method):
    /// ①立即生效;②热重载 Applied 后仍然生效;③commit_raw 写入新配置
    /// 后生效视图仍带覆盖,但磁盘 enrolled 文件不被改写。
    #[test]
    fn runtime_overrides_survive_reload_and_commit() {
        let dir = std::env::temp_dir()
            .join(format!("rooster-overrides-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = build_state(&dir);
        let override_dir = dir.join("container-data");
        state.set_runtime_overrides(RuntimeOverrides {
            data_dir: Some(override_dir.clone()),
            upgrade_method: Some(rooster_config::UpgradeMethod::Exit),
        });

        // ① 立即生效。
        let eff = state.effective();
        assert_eq!(eff.agent.data_dir(), override_dir);
        assert_eq!(eff.upgrade.method, rooster_config::UpgradeMethod::Exit);

        // ② 外部热重载(磁盘文件换成另一个 data-dir):覆盖项保持。
        let raw2 = format!(
            "local:\n  agent:\n    node-name: override-test\n    data-dir: {}\n",
            dir.join("rewritten-data").display()
        );
        let config_path = &state.config_path;
        std::fs::write(config_path, &raw2).unwrap();
        let (file, effective) = parse_and_validate(&raw2).unwrap();
        state.on_reload_outcome(rooster_config::ReloadOutcome::Applied {
            hash: hash_content(&raw2),
            config: file,
            effective,
        });
        let eff = state.effective();
        assert_eq!(eff.agent.data_dir(), override_dir, "热重载不得冲掉 CLI 覆盖");
        assert_eq!(eff.upgrade.method, rooster_config::UpgradeMethod::Exit);

        // ③ API 路径 commit_raw:生效视图带覆盖,磁盘保持 enrolled 值。
        let raw3 = format!(
            "local:\n  agent:\n    node-name: override-test\n    data-dir: {}\n",
            dir.join("api-data").display()
        );
        let committed = state.commit_raw(&raw3).unwrap();
        assert_eq!(committed.agent.data_dir(), override_dir);
        assert_eq!(state.effective().agent.data_dir(), override_dir);
        let on_disk = std::fs::read_to_string(config_path).unwrap();
        assert!(on_disk.contains("api-data"), "enrolled 配置应保留 API 写入值");
        assert!(!on_disk.contains("container-data"), "覆盖项不得回写磁盘");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
