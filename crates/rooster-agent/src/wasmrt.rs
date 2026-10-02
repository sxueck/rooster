//! WASM 插件宿主。
//!
//! - wasmtime,无 WASI:不提供文件系统/网络,只暴露精简宿主函数
//!   (log / header 读写 / 按插件隔离的 kv / emit_event / config);
//! - 资源上限:内存(默认 16 MiB)+ epoch 超时(默认 5ms,
//!   独立线程每 1ms 推进 engine epoch);
//! - 失败策略:panic/超时按插件配置 fail-open(默认)或 fail-closed;
//! - manifest:调用导出函数 `rooster_manifest`,返回 JSON
//!   (name/version/hooks/config_schema),面板据此渲染表单;
//! - 热加载:配置变化 → `reconfigure` 增删插件实例。

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rooster_config::WasmPlugin;
use wasmtime::{AsContextMut, Caller, Engine, Linker, Memory, Store};

const DEFAULT_MEMORY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 5;

/// 本 Agent 有真实调用点的 hook(B6):按插件声明分发;声明了
/// 列表之外的 hook 一律拒绝加载(见 `load`),不能静默加载一个
/// 实际什么都不保护的插件。
pub const HOOK_HTTP_REQUEST_HEADERS: &str = "on_http_request_headers";
pub const HOOK_L4_ACCEPT: &str = "on_l4_accept";
const SUPPORTED_HOOKS: [&str; 2] = [HOOK_HTTP_REQUEST_HEADERS, HOOK_L4_ACCEPT];

/// 每插件保留事件队列上限(B3):sink 缺席(dev 模式)时事件也不无限堆积,
// 超出丢最旧(与事件环 MAX_EVENTS 同思路)。
const MAX_RETAINED_EVENTS: usize = 256;

/// 请求上下文里由调用方(httpguard)提供的逐请求字段。
pub struct RequestCtx {
    pub headers: Vec<(String, String)>,
    /// 本轮 hook 内 emit 的事件;hook 结束后即移入插件级队列/ sink,
    /// 不跨请求驻留(见 HostCtx::pending_events)。
    pub events: Vec<String>,
}

/// 单次 hook 调用的判决。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Continue,
    Deny,
    Ban,
}

/// 宿主函数可访问的 Store 数据。
struct HostCtx {
    plugin_id: String,
    config_json: String,
    on_error_fail_closed: bool,
    req: RequestCtx,
    /// 插件自己的 kv 命名空间(B3):按插件实例持久,跨 hook 调用保留;
    /// 重载(配置/文件变化)自然清零。
    kv: HashMap<String, String>,
    /// 事件队列(B3):hook 结束先走 sink;sink 缺席时留在这里等
    /// take_events 兑底(有界,超出丢最旧)。
    pending_events: VecDeque<String>,
    /// 当前连接对端地址(on_l4_accept 期间由宿主注入)。
    conn_peer: Option<String>,
    /// 内存上限器:挂在 Store 数据上供 limiter 闭包取用。
    limiter: MemLimiter,
}

impl HostCtx {
    /// 事件入队并执行上限截断(B3)。
    fn retain_events(&mut self, new_events: Vec<String>) {
        self.pending_events.extend(new_events);
        while self.pending_events.len() > MAX_RETAINED_EVENTS {
            self.pending_events.pop_front();
        }
    }
}

/// 内存上限器。**聚合**记账:上限是每插件的,不是每块内存的 ——
/// wasm 模块可以声明第二块私有内存(`(memory N)`,不导出),只比 `desired`
/// 就能源源不断突破 16MiB。每次增长只累加增量(wasm 内存不会缩),
/// 因此总和恰好等于本插件全部线性内存占用的宿主内存。
struct MemLimiter {
    max: usize,
    used: usize,
}

impl wasmtime::ResourceLimiter for MemLimiter {
    fn memory_growing(&mut self, current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        let delta = desired.saturating_sub(current);
        if self.used.saturating_add(delta) > self.max {
            return Ok(false);
        }
        self.used += delta;
        Ok(true)
    }

    // 表元素也是宿主内存,不封顶就等于绕过 16MiB 上限。
    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMS)
    }
}

struct LoadedPlugin {
    store: Store<HostCtx>,
    instance: wasmtime::Instance,
    manifest: serde_json::Value,
    /// 整份插件 spec(B2):任一字段(sites/hooks/limits/on_error/config)
    /// 变化都必须重载,不能只看 config/file/mtime。
    spec: WasmPlugin,
    /// 有效 hook 集(B6):config 声明优先,缺省取 manifest 声明。
    hooks: Vec<String>,
    pub on_error_fail_closed: bool,
    pub timeout_ms: u64,
    /// 源文件与 mtime:文件更新后 reconfigure 重载。
    source: PathBuf,
    source_mtime: Option<std::time::SystemTime>,
}

/// 插件注册表;AgentState 持有,reconfigure 时重建 diff。
pub struct WasmRuntime {
    engine: Engine,
    plugins: RwLock<HashMap<String, LoadedPlugin>>,
    /// 最近一次加载报告(面板用)。
    pub load_errors: Mutex<Vec<(String, String)>>,
    /// 事件 sink(B3):hook 结束即上报节点事件流;缺省时事件留在
    /// 插件队列里不丢。
    event_sink: RwLock<Option<Arc<dyn Fn(&str, &str) + Send + Sync>>>,
}

/// 有效 hook 集(B6):config 声明优先(用户可显式收窄),为空则取
/// manifest 声明 —— SDK 把 hooks 列为必填,老配置不写也不能静默失去防护。
fn effective_hooks(p: &WasmPlugin, manifest: &serde_json::Value) -> Vec<String> {
    if !p.hooks.is_empty() {
        return p.hooks.clone();
    }
    manifest
        .get("hooks")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 声明了本 Agent 没有调用点的 hook → 可见错误(不静默加载)。
fn unsupported_hook_error(hooks: &[String]) -> Option<String> {
    let unsupported: Vec<&str> = hooks
        .iter()
        .map(String::as_str)
        .filter(|h| !SUPPORTED_HOOKS.contains(h))
        .collect();
    if unsupported.is_empty() {
        return None;
    }
    Some(format!(
        "declared hook(s) {} have no dispatch point in this agent; plugin not loaded",
        unsupported
            .iter()
            .map(|h| format!("`{h}`"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn parse_memory_limit(s: Option<&str>) -> usize {
    // 支持 `16MiB` / `1MiB` / `1048576`。
    s.and_then(|v| {
        let v = v.trim();
        let (num, mult) = if let Some(n) = v.strip_suffix("MiB") {
            (n, 1024 * 1024usize)
        } else if let Some(n) = v.strip_suffix("KiB") {
            (n, 1024)
        } else {
            (v, 1)
        };
        num.parse::<usize>().ok().map(|v| v * mult)
    })
    .unwrap_or(DEFAULT_MEMORY_BYTES)
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    pub fn new() -> Self {
        let mut cfg = wasmtime::Config::new();
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg).expect("wasmtime engine");
        // epoch 推进线程:1ms 粒度,set_epoch_deadline(ms) 即毫秒超时。
        let e = engine.clone();
        std::thread::spawn(move || loop {
            e.increment_epoch();
            std::thread::sleep(Duration::from_millis(1));
        });
        Self {
            engine,
            plugins: RwLock::new(HashMap::new()),
            load_errors: Mutex::new(Vec::new()),
            event_sink: RwLock::new(None),
        }
    }

    /// 注入事件 sink(B3):hook 结束即把插件事件送进节点事件流。
    /// 未注入(纯 dev / 测试)时事件留在有界队列里,由 take_events 扫出。
    pub fn set_event_sink(&self, sink: Arc<dyn Fn(&str, &str) + Send + Sync>) {
        *self.event_sink.write().unwrap() = Some(sink);
    }

    /// 按配置重建插件集(热加载/卸载)。
    /// `resolve_file` 把配置的 file 字段解析为本地 .wasm 路径
    /// (含 `rooster-hub:<name>` 下载逻辑,由调用方注入)。
    pub fn reconfigure(
        &self,
        plugins: &[WasmPlugin],
        resolve_file: impl Fn(&WasmPlugin) -> Option<PathBuf>,
    ) {
        let mut next_ids: Vec<&str> = Vec::new();
        let mut errors = Vec::new();
        for p in plugins {
            next_ids.push(&p.id);
            let file = match resolve_file(p) {
                Some(f) => f,
                None => {
                    errors.push((p.id.clone(), format!("cannot resolve plugin file {}", p.file.display())));
                    continue;
                }
            };
            let mtime = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
            // B2:整个 spec 参与比对(sites/hooks/limits/on_error/config 任一
            // 变化都重载);mtime 未变且 spec 未变时保持快速路径不重载。
            let needs_reload = match self.plugins.read().unwrap().get(&p.id) {
                Some(loaded) => loaded.spec != *p || loaded.source != file || loaded.source_mtime != mtime,
                None => true,
            };
            if !needs_reload {
                continue;
            }
            match self.load(p, &file) {
                Ok(()) => tracing::info!(plugin = p.id, file = file.display().to_string(), "wasm plugin loaded"),
                Err(e) => {
                    tracing::warn!(plugin = p.id, error = e, "wasm plugin failed to load");
                    // 新 spec 加载失败必须卸下旧实例:否则旧配置继续生效,
                    // 调用方却以为已按新 spec 重载(B2 的可观测性前提)。
                    self.plugins.write().unwrap().remove(&p.id);
                    errors.push((p.id.clone(), e));
                }
            }
        }
        // 卸载不在配置里的。
        self.plugins
            .write()
            .unwrap()
            .retain(|id, _| next_ids.contains(&id.as_str()));
        *self.load_errors.lock().unwrap() = errors;
    }

    fn load(&self, p: &WasmPlugin, file: &Path) -> Result<(), String> {
        // B6:声明了本 Agent 无调用点的 hook(如 body/response 阶段)时
        // 直接拒绝加载并在 load_errors 里可见,不能静默加载一个
        // 什么都不保护的插件。
        if let Some(e) = unsupported_hook_error(&p.hooks) {
            return Err(e);
        }
        let bytes = std::fs::read(file).map_err(|e| format!("read: {e}"))?;
        let module = wasmtime::Module::new(&self.engine, &bytes[..])
            .map_err(|e| format!("compile: {e}"))?;

        // 插件 ABI 假定单一线性内存(manifest/header/kv 的
        // 偏移都指向同一块内存),且 memory 上限是逐内存生效的 —— 声明
        // 多块内存就成倍突破 16MiB 上限,加载即拒绝。
        let memory_count = module
            .imports()
            .filter(|i| matches!(i.ty(), wasmtime::ExternType::Memory(_)))
            .count()
            + module
                .exports()
                .filter(|e| matches!(e.ty(), wasmtime::ExternType::Memory(_)))
                .count();
        if memory_count > 1 {
            return Err(format!(
                "module declares {memory_count} memories; the plugin ABI allows exactly one"
            ));
        }

        let timeout_ms = p
            .limits
            .as_ref()
            .and_then(|l| l.timeout)
            .map(|d| d.as_millis().max(1) as u64)
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let memory_limit = parse_memory_limit(p.limits.as_ref().and_then(|l| l.memory.as_deref()));
        let fail_closed = matches!(p.on_error, Some(rooster_config::OnError::FailClosed));
        let config_json = p
            .config
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "{}".to_string());

        let mut store = Store::new(&self.engine, HostCtx {
            plugin_id: p.id.clone(),
            config_json,
            on_error_fail_closed: fail_closed,
            req: RequestCtx {
                headers: Vec::new(),
                events: Vec::new(),
            },
            kv: HashMap::new(),
            pending_events: VecDeque::new(),
            conn_peer: None,
            limiter: MemLimiter {
                max: memory_limit,
                used: 0,
            },
        });
        store.set_epoch_deadline(timeout_ms);
        store.limiter(|ctx: &mut HostCtx| &mut ctx.limiter);

        let mut linker: Linker<HostCtx> = Linker::new(&self.engine);
        link_host_functions(&mut linker)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| format!("instantiate: {e}"))?;

        // manifest:导出函数 rooster_manifest() -> (ptr, len)。
        let manifest = read_manifest(&mut store, &instance)?;
        // 有效 hook 集:config 没写 hooks 的老配置按 manifest 声明继续分发,
        // 否则 B6 会把"没声明"变成"静默不防护"。
        let hooks = effective_hooks(p, &manifest);
        if let Some(e) = unsupported_hook_error(&hooks) {
            return Err(e);
        }

        let loaded = LoadedPlugin {
            store,
            instance,
            manifest,
            spec: p.clone(),
            hooks,
            on_error_fail_closed: fail_closed,
            timeout_ms,
            source: file.to_path_buf(),
            source_mtime: std::fs::metadata(file).and_then(|m| m.modified()).ok(),
        };
        self.plugins.write().unwrap().insert(p.id.clone(), loaded);
        Ok(())
    }

    /// on_http_request_headers hook(B6):只对「声明了该 hook 且
    /// 绑定到该站点」的插件执行(未声明的不付费);任一返回 Deny/Ban
    /// 即短路。headers 原地回写。
    pub fn on_http_request_headers(
        &self,
        site: &str,
        headers: &mut Vec<(String, String)>,
    ) -> Vec<Verdict> {
        let ids: Vec<String> = self
            .plugins
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut verdicts = Vec::new();
        // B3:本轮产生的事件,sink 在锁外送达(避免 sink 反入运行时死锁)。
        let mut emitted: Vec<(String, String)> = Vec::new();
        for id in ids {
            let mut guard = self.plugins.write().unwrap();
            let Some(plugin) = guard.get_mut(&id) else { continue };
            if !plugin.hooks.iter().any(|h| h == HOOK_HTTP_REQUEST_HEADERS) {
                continue;
            }
            // 站点绑定:sites 为空 = 全部站点;否则仅列出的站点。
            if !plugin.spec.sites.is_empty() && !plugin.spec.sites.iter().any(|s| s == site) {
                continue;
            }
            {
                let ctx = plugin.store.data_mut();
                ctx.req = RequestCtx {
                    headers: headers.clone(),
                    events: Vec::new(),
                };
            }
            let (code, events) = run_hook(plugin, HOOK_HTTP_REQUEST_HEADERS);
            verdicts.push(code_to_verdict(code));
            // 回写 header 变更;事件即时出队(B3)。
            {
                let ctx = plugin.store.data_mut();
                *headers = ctx.req.headers.clone();
                ctx.retain_events(events);
                if self.event_sink.read().unwrap().is_some() {
                    for payload in ctx.pending_events.drain(..) {
                        emitted.push((id.clone(), payload));
                    }
                }
            }
        }
        self.deliver_emitted(emitted);
        verdicts
    }

    /// on_l4_accept hook(B6):forward accept 路径调用,peer 经
    /// `rooster_conn_peer` 暴露给插件;Deny/Ban 的处置(拒连/封禁)
    /// 由调用方完成,与 httpguard 同一约定。
    pub fn on_l4_accept(&self, rule: &str, peer: SocketAddr) -> Vec<Verdict> {
        let ids: Vec<String> = self
            .plugins
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut verdicts = Vec::new();
        let mut emitted: Vec<(String, String)> = Vec::new();
        for id in ids {
            let mut guard = self.plugins.write().unwrap();
            let Some(plugin) = guard.get_mut(&id) else { continue };
            if !plugin.hooks.iter().any(|h| h == HOOK_L4_ACCEPT) {
                continue;
            }
            // 与 HTTP 侧同一绑定语义:空 = 全部规则,否则按规则 id 匹配。
            if !plugin.spec.sites.is_empty() && !plugin.spec.sites.iter().any(|s| s == rule) {
                continue;
            }
            {
                let ctx = plugin.store.data_mut();
                ctx.req = RequestCtx {
                    headers: Vec::new(),
                    events: Vec::new(),
                };
                ctx.conn_peer = Some(peer.to_string());
            }
            let (code, events) = run_hook(plugin, HOOK_L4_ACCEPT);
            verdicts.push(code_to_verdict(code));
            {
                let ctx = plugin.store.data_mut();
                ctx.conn_peer = None;
                ctx.retain_events(events);
                if self.event_sink.read().unwrap().is_some() {
                    for payload in ctx.pending_events.drain(..) {
                        emitted.push((id.clone(), payload));
                    }
                }
            }
        }
        self.deliver_emitted(emitted);
        verdicts
    }

    /// 把本轮事件送进 sink(无 sink 时已留在有界队列,不丢,B3)。
    fn deliver_emitted(&self, emitted: Vec<(String, String)>) {
        if emitted.is_empty() {
            return;
        }
        let sink = self.event_sink.read().unwrap().clone();
        if let Some(sink) = sink {
            for (plugin, payload) in emitted {
                sink(&plugin, &payload);
            }
        }
    }

    /// 面板 manifest(`/v0/management/wasm`)。
    pub fn manifest_json(&self, id: &str) -> Result<serde_json::Value, String> {
        self.plugins
            .read()
            .unwrap()
            .get(id)
            .map(|p| p.manifest.clone())
            .ok_or_else(|| "not loaded".to_string())
    }

    pub fn plugin_status(&self, id: &str) -> String {
        if self.plugins.read().unwrap().contains_key(id) {
            "loaded".to_string()
        } else if self
            .load_errors
            .lock()
            .unwrap()
            .iter()
            .any(|(pid, _)| pid == id)
        {
            "error".to_string()
        } else {
            "unloaded".to_string()
        }
    }

    pub fn loaded_ids(&self) -> Vec<String> {
        self.plugins.read().unwrap().keys().cloned().collect()
    }
}

impl LoadedPlugin {}

/// 单插件单 hook 的公共执行尾巴:epoch 超时 + 失败策略映射 +
/// 事件出队(即使 panic/超时,已 emit 的事件也不丢,B3)。
fn run_hook(plugin: &mut LoadedPlugin, hook: &str) -> (i32, Vec<String>) {
    plugin.store.set_epoch_deadline(plugin.timeout_ms);
    match call_hook(plugin, hook) {
        Ok(code) => {
            let events = std::mem::take(&mut plugin.store.data_mut().req.events);
            (code, events)
        }
        Err(e) => {
            // panic/超时:按配置 fail-open / fail-closed。
            tracing::warn!(plugin = %plugin.spec.id, hook, error = e, "wasm hook failed");
            let code = if plugin.on_error_fail_closed { 1 } else { 0 };
            let events = std::mem::take(&mut plugin.store.data_mut().req.events);
            (code, events)
        }
    }
}

fn code_to_verdict(code: i32) -> Verdict {
    match code {
        1 => Verdict::Deny,
        2 => Verdict::Ban,
        _ => Verdict::Continue,
    }
}

fn call_hook(plugin: &mut LoadedPlugin, name: &str) -> Result<i32, String> {
    let func = plugin
        .instance
        .get_func(&mut plugin.store, name)
        .ok_or_else(|| format!("hook `{name}` not exported"))?;
    let mut result = [wasmtime::Val::I32(0)];
    func.call(&mut plugin.store, &[], &mut result)
        .map_err(|e| format!("call: {e}"))?;
    Ok(result[0].i32().unwrap_or(0))
}

/// manifest ABI:guest 导出 `rooster_manifest_ptr() -> i32` 与
/// `rooster_manifest_len() -> i32`,指向线性内存中的 JSON。单 i32
/// 返回值在所有 guest 工具链下 ABI 稳定(rustc 不会把元组返回降级成
/// sret 指针参数)。
fn read_manifest(store: &mut Store<HostCtx>, instance: &wasmtime::Instance) -> Result<serde_json::Value, String> {
    let call_i32 = |store: &mut Store<HostCtx>, name: &str| -> Result<usize, String> {
        let func = instance
            .get_func(&mut *store, name)
            .ok_or_else(|| format!("missing `{name}` export"))?;
        let mut result = [wasmtime::Val::I32(0)];
        func.call(&mut *store, &[], &mut result)
            .map_err(|e| format!("{name} call: {e}"))?;
        Ok(result[0].i32().unwrap_or(0) as u32 as usize)
    };
    let ptr = call_i32(store, "rooster_manifest_ptr")?;
    let len = call_i32(store, "rooster_manifest_len")?;
    if len > 64 * 1024 {
        return Err("manifest too large".to_string());
    }
    let memory = instance
        .get_memory(&mut *store, "memory")
        .ok_or("no exported memory")?;
    let mut buf = vec![0u8; len];
    memory
        .read(&mut *store, ptr, &mut buf)
        .map_err(|e| format!("manifest read: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("manifest json: {e}"))
}

// ---------------------------------------------------------------------------
// 宿主函数(只能调用这些)

/// guest 传入的长度直接决定宿主侧分配大小:不封顶时一次
/// `rooster_log(ptr, 0x7fffffff)` 就能在 2GiB 分配上打死小内存节点
/// (alloc 失败是 abort,不受 fuel/epoch 与 fail-open 策略约束)。
const MAX_GUEST_STR_BYTES: usize = 1 << 20;
/// 表元素上限(约 512KiB 宿主内存),与 16MiB 内存上限同一量级。
const MAX_TABLE_ELEMS: usize = 1 << 16;

fn read_str(caller: &mut Caller<'_, HostCtx>, ptr: i32, len: i32) -> Result<String, String> {
    if len < 0 || len as usize > MAX_GUEST_STR_BYTES {
        return Err(format!("guest string length out of range: {len}"));
    }
    let memory = guest_memory(caller)?;
    let mut buf = vec![0u8; len as usize];
    memory
        .read(caller.as_context_mut(), ptr as u32 as usize, &mut buf)
        .map_err(|e| format!("read guest memory: {e}"))?;
    String::from_utf8(buf).map_err(|e| format!("utf8: {e}"))
}

fn write_buf(
    caller: &mut Caller<'_, HostCtx>,
    ptr: i32,
    data: &[u8],
) -> Result<i32, String> {
    let memory = guest_memory(caller)?;
    memory
        .write(caller.as_context_mut(), ptr as u32 as usize, data)
        .map_err(|e| format!("write guest memory: {e}"))?;
    Ok(data.len() as i32)
}

fn guest_memory(caller: &mut Caller<'_, HostCtx>) -> Result<Memory, String> {
    caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| "no exported memory".to_string())
}

fn link_host_functions(linker: &mut Linker<HostCtx>) -> Result<(), String> {
    linker
        .func_wrap("env", "rooster_log", |mut caller: Caller<'_, HostCtx>, ptr: i32, len: i32| {
            match read_str(&mut caller, ptr, len) {
                Ok(msg) => {
                    let id = caller.data().plugin_id.clone();
                    tracing::info!(plugin = id, "{msg}");
                }
                Err(e) => {
                    let id = caller.data().plugin_id.clone();
                    tracing::debug!(plugin = id, "rooster_log rejected: {e}");
                }
            }
        })
        .and_then(|l| {
            l.func_wrap("env", "rooster_header_count", |caller: Caller<'_, HostCtx>| -> i32 {
                caller.data().req.headers.len() as i32
            })
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_header_name",
                |mut caller: Caller<'_, HostCtx>, i: i32, ptr: i32, cap: i32| -> i32 {
                    let name = caller.data().req.headers.get(i as usize).map(|h| h.0.clone());
                    match name {
                        Some(n) if n.len() <= cap as usize => write_buf(&mut caller, ptr, n.as_bytes()).unwrap_or(-1),
                        Some(_) => -2, // buffer too small
                        None => -1,
                    }
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_header_value",
                |mut caller: Caller<'_, HostCtx>, i: i32, ptr: i32, cap: i32| -> i32 {
                    let value = caller.data().req.headers.get(i as usize).map(|h| h.1.clone());
                    match value {
                        Some(v) if v.len() <= cap as usize => write_buf(&mut caller, ptr, v.as_bytes()).unwrap_or(-1),
                        Some(_) => -2,
                        None => -1,
                    }
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_set_header",
                |mut caller: Caller<'_, HostCtx>, nptr: i32, nlen: i32, vptr: i32, vlen: i32| -> i32 {
                    let name = match read_str(&mut caller, nptr, nlen) {
                        Ok(s) => s,
                        Err(_) => return -1,
                    };
                    let value = match read_str(&mut caller, vptr, vlen) {
                        Ok(s) => s,
                        Err(_) => return -1,
                    };
                    let ctx = caller.data_mut();
                    // SDK 契约是「同名整体替换」(set_header doc):先把同名
                    // 的全部值清掉再写入单值,否则多值头会残留旧值(B4)。
                    ctx.req.headers.retain(|h| h.0 != name);
                    ctx.req.headers.push((name, value));
                    0
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_remove_header",
                |mut caller: Caller<'_, HostCtx>, nptr: i32, nlen: i32| -> i32 {
                    let name = match read_str(&mut caller, nptr, nlen) {
                        Ok(s) => s,
                        Err(_) => return -1,
                    };
                    let ctx = caller.data_mut();
                    let before = ctx.req.headers.len();
                    ctx.req.headers.retain(|h| h.0 != name);
                    (before != ctx.req.headers.len()) as i32
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_kv_get",
                |mut caller: Caller<'_, HostCtx>, kptr: i32, klen: i32, buf: i32, cap: i32| -> i32 {
                    let key = match read_str(&mut caller, kptr, klen) {
                        Ok(k) => k,
                        Err(_) => return -1,
                    };
                    let value = caller.data().kv.get(&key).cloned();
                    match value {
                        Some(v) if v.len() <= cap as usize => {
                            write_buf(&mut caller, buf, v.as_bytes()).unwrap_or(-1)
                        }
                        Some(_) => -2,
                        None => -1,
                    }
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_kv_set",
                |mut caller: Caller<'_, HostCtx>, kptr: i32, klen: i32, vptr: i32, vlen: i32| {
                    let key = match read_str(&mut caller, kptr, klen) {
                        Ok(k) => k,
                        Err(_) => return,
                    };
                    let value = match read_str(&mut caller, vptr, vlen) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    caller.data_mut().kv.insert(key, value);
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_emit_event",
                |mut caller: Caller<'_, HostCtx>, ptr: i32, len: i32| {
                    if let Ok(payload) = read_str(&mut caller, ptr, len) {
                        caller.data_mut().req.events.push(payload);
                    }
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_conn_peer",
                |mut caller: Caller<'_, HostCtx>, ptr: i32, cap: i32| -> i32 {
                    // on_l4_accept 期间的连接对端(B6);返回约定与
                    // rooster_kv_get 一致:字节数 / -1 无 / -2 缓冲不足。
                    let peer = caller.data().conn_peer.clone();
                    match peer {
                        Some(p) if p.len() <= cap as usize => {
                            write_buf(&mut caller, ptr, p.as_bytes()).unwrap_or(-1)
                        }
                        Some(_) => -2,
                        None => -1,
                    }
                },
            )
        })
        .and_then(|l| {
            l.func_wrap(
                "env",
                "rooster_config",
                |mut caller: Caller<'_, HostCtx>, ptr: i32, cap: i32| -> i32 {
                    let cfg = caller.data().config_json.clone();
                    if cfg.len() <= cap as usize {
                        write_buf(&mut caller, ptr, cfg.as_bytes()).unwrap_or(-1)
                    } else {
                        -2
                    }
                },
            )
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

impl WasmRuntime {
    /// 取出插件经 rooster_emit_event 上报的事件。
    /// B3 后事件在每次 hook 结束即送 sink;这里是 reload 时的兑底扫描
    /// (sink 缺席的 dev 模式 / sink 一次性注入前累积的事件)。
    pub fn take_events(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for plugin in self.plugins.write().unwrap().values_mut() {
            let id = plugin.store.data().plugin_id.clone();
            for payload in plugin.store.data_mut().pending_events.drain(..) {
                out.push((id.clone(), payload));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WAT 版最小 guest:校验 X-Api-Key 头,缺失返回 1(Deny)。
    const HEADER_CHECK_WAT: &str = r#"
(module
  (import "env" "rooster_header_count" (func $hc (result i32)))
  (import "env" "rooster_header_name" (func $hn (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"n\":1}")
  (func (export "rooster_manifest_ptr") (result i32) (i32.const 0))
  (func (export "rooster_manifest_len") (result i32) (i32.const 7))
  (func (export "on_http_request_headers") (result i32)
    (local $i i32) (local $found i32)
    (local.set $i (i32.const 0))
    (block $done
      (loop $scan
        (br_if $done (i32.ge_u (local.get $i) (call $hc)))
        ;; 读 header name 到内存 64..96
        (drop (call $hn (local.get $i) (i32.const 64) (i32.const 32)))
        ;; 与 "X-Api-Key" 比较(简化:逐字节)
        (if (i32.and
              (i32.eq (i32.load8_u (i32.const 64)) (i32.const 88)) ;; 'X'
              (i32.eq (i32.load8_u (i32.const 65)) (i32.const 45))) ;; '-'
          (then (local.set $found (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (if (result i32) (local.get $found) (then (i32.const 0)) (else (i32.const 1))))
)
"#;

    fn plugin(id: &str, file: &Path) -> WasmPlugin {
        WasmPlugin {
            id: id.to_string(),
            file: file.to_path_buf(),
            hooks: vec!["on_http_request_headers".to_string()],
            sites: vec![],
            limits: None,
            on_error: None,
            config: None,
        }
    }

    #[test]
    fn header_check_plugin_denies_missing_key() {
        let rt = WasmRuntime::new();
        let file = std::env::temp_dir().join("header_check_test.wat");
        std::fs::write(&file, HEADER_CHECK_WAT).unwrap();
        rt.reconfigure(&[plugin("hc", &file)], |_| Some(file.clone()));
        if rt.plugin_status("hc") != "loaded" {
            panic!("load failed: {:?}", rt.load_errors.lock().unwrap());
        }

        let mut headers = vec![("Host".to_string(), "example.com".to_string())];
        let v = rt.on_http_request_headers("www", &mut headers);
        assert_eq!(v, vec![Verdict::Deny]);

        let mut headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Api-Key".to_string(), "secret".to_string()),
        ];
        let v = rt.on_http_request_headers("www", &mut headers);
        assert_eq!(v, vec![Verdict::Continue]);
    }

    /// 真实构建产物冒烟:SDK 宏 + 宿主 ABI 全链路。未构建 wasm 时跳过
    /// (需 `rustup target add wasm32-unknown-unknown` 后单独构建示例)。
    #[test]
    fn real_example_plugin_roundtrip() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/rooster-plugin-sdk/example-plugins/header-check/target/wasm32-unknown-unknown/release/rooster_example_header_check.wasm");
        if !path.exists() {
            eprintln!("skipping: example wasm not built ({})", path.display());
            return;
        }
        let rt = WasmRuntime::new();
        rt.reconfigure(&[plugin("header-check", &path)], |_| Some(path.clone()));
        assert_eq!(
            rt.plugin_status("header-check"), "loaded",
            "load errors: {:?}",
            rt.load_errors.lock().unwrap()
        );
        let manifest = rt.manifest_json("header-check").unwrap();
        assert_eq!(manifest["name"].as_str(), Some("header-check"));
        assert_eq!(manifest["hooks"][0].as_str(), Some("on_http_request_headers"));

        // 缺 X-Api-Key → Deny;带 → Continue。
        let mut headers = vec![("host".to_string(), "example.com".to_string())];
        let v = rt.on_http_request_headers("www", &mut headers);
        assert_eq!(v, vec![Verdict::Deny]);
        let mut headers = vec![
            ("host".to_string(), "example.com".to_string()),
            ("x-api-key".to_string(), "abc".to_string()),
        ];
        let v = rt.on_http_request_headers("www", &mut headers);
        assert_eq!(v, vec![Verdict::Continue]);
    }

    #[test]
    fn missing_hook_is_reported() {
        let rt = WasmRuntime::new();
        let file = std::env::temp_dir().join("empty.wat");
        std::fs::write(&file, "(module (memory (export \"memory\") 1))").unwrap();
        // 无 rooster_manifest 导出 → 加载失败,状态 error。
        rt.reconfigure(&[plugin("bad", &file)], |_| Some(file.clone()));
        assert_eq!(rt.plugin_status("bad"), "error");
    }

    /// 资源上限必须在实例化时就拦住:同一模块只改声明规模,小的能加载、
    /// 大的必须被拒(旧实现 `table_growing` 无条件放行,等于绕过 16MiB 上限)。
    #[test]
    fn resource_limiter_bounds_memory_and_table() {
        // 公共尾巴:manifest 两个导出 + 一个空 hook。
        const TAIL: &str = "  (data (i32.const 0) \"{\\\"n\\\":1}\")\n  (func (export \"rooster_manifest_ptr\") (result i32) (i32.const 0))\n  (func (export \"rooster_manifest_len\") (result i32) (i32.const 7))\n  (func (export \"on_http_request_headers\") (result i32) (i32.const 0))\n";
        let ok = format!("(module\n  (memory (export \"memory\") 1)\n{TAIL})\n");
        let big_mem = format!("(module\n  (memory (export \"memory\") 1024)\n{TAIL})\n");
        let big_table = format!(
            "(module\n  (memory (export \"memory\") 1)\n  (table (export \"t\") 70000 funcref)\n{TAIL})\n"
        );

        // 1 页 = 64KiB,在默认 16MiB 上限内(对照组)。
        assert_eq!(load_wat("lim-ok", &ok), "loaded");
        // 1024 页 = 64MiB > 上限。
        assert_eq!(
            load_wat("lim-mem", &big_mem),
            "error",
            "initial memory above the cap must be refused at instantiation"
        );
        // 表元素也是宿主内存。
        assert_eq!(
            load_wat("lim-tab", &big_table),
            "error",
            "table above MAX_TABLE_ELEMS must be refused"
        );
    }

    /// guest 传入的 ptr/len 直接决定宿主侧分配大小:负数与超大值必须走错误
    /// 分支并被 fail-open 容错,不能把 Agent 进程打死。
    #[test]
    fn host_string_reads_are_clamped() {
        const WAT_HOST_ABUSE: &str = r#"
(module
  (import "env" "rooster_log" (func $log (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"n\":1}")
  (func (export "rooster_manifest_ptr") (result i32) (i32.const 0))
  (func (export "rooster_manifest_len") (result i32) (i32.const 7))
  (func (export "on_http_request_headers") (result i32)
    (call $log (i32.const 0) (i32.const -1))
    (call $log (i32.const 0) (i32.const 2147483647))
    (i32.const 0))
)
"#;
        let rt = WasmRuntime::new();
        let file = std::env::temp_dir().join(format!("rooster-abuse-{}.wat", std::process::id()));
        std::fs::write(&file, WAT_HOST_ABUSE).unwrap();
        rt.reconfigure(&[plugin("abuse", &file)], |_| Some(file.clone()));
        assert_eq!(
            rt.plugin_status("abuse"),
            "loaded",
            "{:?}",
            rt.load_errors.lock().unwrap()
        );
        let mut headers = vec![("host".to_string(), "example.com".to_string())];
        assert_eq!(rt.on_http_request_headers("www", &mut headers), vec![Verdict::Continue]);
    }

    fn load_wat(id: &str, wat: &str) -> String {
        let rt = WasmRuntime::new();
        let file = std::env::temp_dir().join(format!("rooster-{id}-{}.wat", std::process::id()));
        std::fs::write(&file, wat).unwrap();
        rt.reconfigure(&[plugin(id, &file)], |_| Some(file.clone()));
        rt.plugin_status(id).to_string()
    }

    // --- B1/B2/B3/B6 回归测试 --------------------------------------------

    /// 拼一个最小模块:manifest 字节长度由 Rust 侧算,手写容易偏一个字节
    /// 导致宿主读到截断 JSON。
    fn module_wat(manifest: &str, pages: u32, exports: &str) -> String {
        module_wat_full("", manifest, pages, exports)
    }

    fn module_wat_full(prefix: &str, manifest: &str, pages: u32, exports: &str) -> String {
        let escaped = manifest.replace('"', "\\\"");
        format!(
            "(module\n{prefix}  (memory (export \"memory\") {pages})\n  (data (i32.const 0) \"{escaped}\")\n  (func (export \"rooster_manifest_ptr\") (result i32) (i32.const 0))\n  (func (export \"rooster_manifest_len\") (result i32) (i32.const {}))\n{exports})\n",
            manifest.len()
        )
    }

    fn spec(id: &str, file: &Path, hooks: &[&str], sites: &[&str]) -> WasmPlugin {
        WasmPlugin {
            id: id.to_string(),
            file: file.to_path_buf(),
            hooks: hooks.iter().map(|h| h.to_string()).collect(),
            sites: sites.iter().map(|s| s.to_string()).collect(),
            limits: None,
            on_error: None,
            config: None,
        }
    }

    fn write_wat(name: &str, wat: &str) -> PathBuf {
        let file = std::env::temp_dir().join(format!("rooster-{name}-{}.wat", std::process::id()));
        std::fs::write(&file, wat).unwrap();
        file
    }

    const DENY_HTTP: &str =
        "  (func (export \"on_http_request_headers\") (result i32) (i32.const 1))\n";
    const DENY_L4: &str = "  (func (export \"on_l4_accept\") (result i32) (i32.const 1))\n";

    /// 16MiB 是**每插件**额度。不导出的第二块内存以前绕过上限
    /// (逐内存比 desired),现在按聚合用量在实例化时就拒。
    #[test]
    fn private_second_memory_cannot_double_the_cap() {
        let rt = WasmRuntime::new();
        let wat = module_wat("{\"name\":\"two\"}", 256, DENY_HTTP)
            .replace("  (memory (export \"memory\") 256)\n", "  (memory (export \"memory\") 256)\n  (memory 256)\n");
        let file = write_wat("priv-mem", &wat);
        rt.reconfigure(&[spec("two", &file, &["on_http_request_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(
            rt.plugin_status("two"),
            "error",
            "两块 16MiB 内存必须被拒: {:?}",
            rt.load_errors.lock().unwrap()
        );

        // 对照:同样声明规模的单块内存照常加载。
        let ok = module_wat("{\"name\":\"one\"}", 256, DENY_HTTP);
        let file = write_wat("one-mem", &ok);
        rt.reconfigure(&[spec("two", &file, &["on_http_request_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("two"), "loaded");
    }

    /// B1:导出两块内存直接违反插件 ABI —— manifest/header/kv 的偏移都只
    /// 指向一段线性内存,再多一块就是绕过上限。
    #[test]
    fn two_exported_memories_are_refused() {
        let rt = WasmRuntime::new();
        let wat = module_wat("{\"name\":\"x\"}", 1, DENY_HTTP).replace(
            "  (memory (export \"memory\") 1)\n",
            "  (memory (export \"memory\") 1)\n  (memory (export \"m2\") 1)\n",
        );
        let file = write_wat("two-exp", &wat);
        rt.reconfigure(&[spec("x", &file, &["on_http_request_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("x"), "error", "多块导出内存必须拒加载");
    }

    /// B2:只改 sites(config/mtime 完全不变)也要重载。旧实现只看
    /// config/file/mtime → 旧站点继续拦、新站点裸奔。
    #[test]
    fn reconfigure_rebinds_when_only_sites_change() {
        let rt = WasmRuntime::new();
        let file = write_wat("sites", &module_wat("{\"name\":\"s\"}", 1, DENY_HTTP));
        let load = |sites: &[&str]| {
            rt.reconfigure(&[spec("s", &file, &["on_http_request_headers"], sites)], |_| {
                Some(file.clone())
            });
        };
        load(&["a"]);
        assert_eq!(rt.plugin_status("s"), "loaded");
        let mut h = vec![];
        assert_eq!(rt.on_http_request_headers("a", &mut h), vec![Verdict::Deny]);
        assert!(rt.on_http_request_headers("b", &mut h).is_empty(), "未绑定的站点不该有 verdict");

        load(&["b"]);
        assert!(
            rt.on_http_request_headers("a", &mut h).is_empty(),
            "改绑后旧站点仍在生效 = spec 变化没触发重载"
        );
        assert_eq!(rt.on_http_request_headers("b", &mut h), vec![Verdict::Deny]);
    }

    /// B2:只改 limits 也要重载 —— 收紧到 1KiB 后连 1 页内存都放不下,
    /// 必须看到 error(旧实例也不能残留)。
    #[test]
    fn reconfigure_reloads_when_only_limits_change() {
        let rt = WasmRuntime::new();
        let file = write_wat("limits", &module_wat("{\"name\":\"l\"}", 1, DENY_HTTP));
        rt.reconfigure(&[spec("l", &file, &["on_http_request_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("l"), "loaded");

        let mut p = spec("l", &file, &["on_http_request_headers"], &[]);
        p.limits = Some(rooster_config::WasmLimits {
            memory: Some("1KiB".to_string()),
            timeout: None,
        });
        rt.reconfigure(&[p], |_| Some(file.clone()));
        assert_eq!(
            rt.plugin_status("l"),
            "error",
            "limits 变化必须按新上限重载: {:?}",
            rt.load_errors.lock().unwrap()
        );
    }

    /// B6 回归:config 没写 hooks 的老配置按 manifest 声明继续分发。
    /// 否则“改成按声明调度”会把存量配置静默变成不防护。
    #[test]
    fn empty_config_hooks_fall_back_to_manifest_hooks() {
        let rt = WasmRuntime::new();
        let wat = module_wat("{\"name\":\"m\",\"hooks\":[\"on_http_request_headers\"]}", 1, DENY_HTTP);
        let file = write_wat("mman", &wat);
        rt.reconfigure(&[spec("m", &file, &[], &[])], |_| Some(file.clone()));
        assert_eq!(rt.plugin_status("m"), "loaded", "{:?}", rt.load_errors.lock().unwrap());
        let mut h = vec![];
        assert_eq!(rt.on_http_request_headers("www", &mut h), vec![Verdict::Deny]);
    }

    /// B6:声明了本 Agent 没有调用点的 hook(manifest 或 config)→ 可见错误,
    /// 不能加载一个“什么都不保护”的插件。
    #[test]
    fn unsupported_hook_declaration_refuses_load() {
        let rt = WasmRuntime::new();
        let wat = module_wat("{\"name\":\"b\",\"hooks\":[\"on_http_request_body\"]}", 1, DENY_HTTP);
        let file = write_wat("unsupported", &wat);
        rt.reconfigure(&[spec("b", &file, &[], &[])], |_| Some(file.clone()));
        assert_eq!(rt.plugin_status("b"), "error", "manifest 声明无调用点的 hook 要拒加载");

        // config 侧声明同样拒(不进 manifest 解析也能拒)。
        let ok = module_wat("{\"name\":\"b2\"}", 1, DENY_HTTP);
        let file = write_wat("unsupported2", &ok);
        rt.reconfigure(&[spec("b2", &file, &["on_http_response_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("b2"), "error");
    }

    /// B6:on_l4_accept 只由 L4 路径调用,并按规则 id 绑定。
    #[test]
    fn l4_hook_dispatches_only_from_l4_and_honours_rule_binding() {
        let rt = WasmRuntime::new();
        let file = write_wat("l4", &module_wat("{\"name\":\"l4\"}", 1, DENY_L4));
        rt.reconfigure(&[spec("l4", &file, &["on_l4_accept"], &["ssh"])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("l4"), "loaded", "{:?}", rt.load_errors.lock().unwrap());
        let mut h = vec![];
        assert!(
            rt.on_http_request_headers("www", &mut h).is_empty(),
            "HTTP 路径不得调用只在 L4 声明的 hook"
        );
        let peer: std::net::SocketAddr = "203.0.113.7:22".parse().unwrap();
        assert_eq!(rt.on_l4_accept("ssh", peer), vec![Verdict::Deny]);
        assert!(rt.on_l4_accept("other", peer).is_empty(), "规则绑定外的连接不该走该插件");
    }

    /// kv/事件用例的模块:首次看不到 kv → Deny + emit "1st";
    /// 第二次看到 kv → Continue + emit "2nd"。
    fn kv_wat() -> String {
        let prefix = "  (import \"env\" \"rooster_kv_get\" (func $get (param i32 i32 i32 i32) (result i32)))\n  (import \"env\" \"rooster_kv_set\" (func $set (param i32 i32 i32 i32)))\n  (import \"env\" \"rooster_emit_event\" (func $ev (param i32 i32)))\n";
        let hook = "  (func (export \"on_http_request_headers\") (result i32)\n    (local $prev i32)\n    (local.set $prev (call $get (i32.const 64) (i32.const 1) (i32.const 80) (i32.const 8)))\n    (call $set (i32.const 64) (i32.const 1) (i32.const 65) (i32.const 1))\n    (if (result i32) (i32.eq (local.get $prev) (i32.const -1))\n      (then (block (result i32) (call $ev (i32.const 96) (i32.const 3)) (i32.const 1)))\n      (else (block (result i32) (call $ev (i32.const 100) (i32.const 3)) (i32.const 0)))))\n";
        let data = "  (data (i32.const 64) \"kv\")\n  (data (i32.const 96) \"1st\")\n  (data (i32.const 100) \"2nd\")\n";
        module_wat_full(prefix, "{\"name\":\"kv\"}", 1, &format!("{data}{hook}"))
    }

    /// B3:插件 kv 跳请求保留、事件本次 hook 结束就进 sink。
    /// 旧实现每次调用重建 RequestCtx → kv 丢、事件要等下一次 reconfigure。
    #[test]
    fn plugin_kv_persists_and_events_reach_sink_at_once() {
        let rt = WasmRuntime::new();
        let file = write_wat("kv", &kv_wat());
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
        let sink = seen.clone();
        rt.set_event_sink(Arc::new(move |plugin, payload| {
            sink.lock().unwrap().push((plugin.to_string(), payload.to_string()));
        }));
        rt.reconfigure(&[spec("kv", &file, &["on_http_request_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("kv"), "loaded", "{:?}", rt.load_errors.lock().unwrap());

        let mut h = vec![];
        assert_eq!(rt.on_http_request_headers("www", &mut h), vec![Verdict::Deny], "首次看不到 kv");
        assert_eq!(
            rt.on_http_request_headers("www", &mut h),
            vec![Verdict::Continue],
            "kv 必须跨请求保留"
        );
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                ("kv".to_string(), "1st".to_string()),
                ("kv".to_string(), "2nd".to_string())
            ],
            "事件要本次就送 sink,不能留在 store 里等重载"
        );
    }

    /// B3 兑底:没有 sink(dev 模式)时事件不丢,take_events 能扫出。
    #[test]
    fn events_are_retained_when_no_sink_is_wired() {
        let rt = WasmRuntime::new();
        let file = write_wat("kv-nosink", &kv_wat());
        rt.reconfigure(&[spec("kv", &file, &["on_http_request_headers"], &[])], |_| {
            Some(file.clone())
        });
        assert_eq!(rt.plugin_status("kv"), "loaded", "{:?}", rt.load_errors.lock().unwrap());
        let mut h = vec![];
        rt.on_http_request_headers("www", &mut h);
        rt.on_http_request_headers("www", &mut h);
        assert_eq!(
            rt.take_events(),
            vec![
                ("kv".to_string(), "1st".to_string()),
                ("kv".to_string(), "2nd".to_string())
            ],
            "无 sink 时事件必须留在有界队列而不是被下一次调用重置"
        );
    }
}
