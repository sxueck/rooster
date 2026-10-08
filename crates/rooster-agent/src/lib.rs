//! rooster agent:本地管理 API 与配置同步。
//!
//! 在此 crate 加入:端口代理(forwards)、插件宿主、ssh-guard
//! 日志采集与 nftables 封禁管理。

pub mod acme;
pub mod bans;
pub mod forward;
pub mod geoip;
pub mod hardening;
pub mod httpguard;
pub mod hubclient;
pub mod management;
pub mod nginx;
pub mod outbox;
pub mod plugin;
pub mod sshguard;
pub mod state;
pub mod upgrade;
pub mod waf;
pub mod wasmrt;

use rooster_config::{
    default_config_template, hash_content, parse_and_validate, writer::replace_subtree,
    ConfigWriter, Seg, WatcherState,
};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use state::AgentState;

/// 私钥类文件收紧权限(0600)。
pub fn write_private_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// `rooster agent` 入口:装载配置 → 回写明文密钥 → 热重载 → 管理 API。
pub async fn run(config_path: &Path) -> ExitCode {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(_) => {
            // 首次安装:写出模板并退出,让管理员填好 node-name / secret-key 再启动。
            if let Err(e) = std::fs::write(config_path, default_config_template()) {
                eprintln!("failed to write initial config {}: {e}", config_path.display());
                return ExitCode::FAILURE;
            }
            eprintln!(
                "wrote initial config to {}; edit node-name and secret-key, then start again",
                config_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let (_file, effective) = match parse_and_validate(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid config {}: {e}", config_path.display());
            return ExitCode::FAILURE;
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| effective.agent.log_level().into()),
        )
        .init();

    let data_dir = effective.agent.data_dir();
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        tracing::error!("cannot create data-dir {}: {e}", data_dir.display());
        return ExitCode::FAILURE;
    }

    let writer = ConfigWriter::new(config_path, &data_dir);
    let watcher = Arc::new(WatcherState::new(hash_content(&raw)));
    let auth = management::auth::AuthGate::new(String::new());

    let state = Arc::new(AgentState::new(
        config_path.to_path_buf(),
        writer,
        watcher.clone(),
        effective.clone(),
        auth,
    ));

    // 明文 secret-key 首次启动时哈希回写(保留注释)。
    if let Some(plaintext) = effective.management.secret_key.as_deref() {
        if !plaintext.trim().is_empty() && !plaintext.starts_with("$2") {
            match bcrypt::hash(plaintext, 12) {
                Ok(hashed) => {
                    // 走 commit_raw(校验 → ConfigWriter::write_atomic 的
                    // tmp/fsync/rename → 刷新 watcher 与 effective),与 API
                    // 写入同一条路径。不能改成裸 fs::write:那会截断重写
                    // 唯一真相源;漏掉 effective 刷新则明文密钥会
                    // 继续经 GET /config 的 effective 字段外泄。
                    let patched = replace_subtree(
                        &raw,
                        &[Seg::K("local"), Seg::K("management"), Seg::K("secret-key")],
                        &serde_json::json!(hashed),
                    );
                    match patched.and_then(|new_raw| state.commit_raw(&new_raw)) {
                        Ok(_) => tracing::info!("hashed plaintext management secret-key"),
                        Err(e) => tracing::error!("failed to hash secret-key in place: {e}"),
                    }
                    state.auth.set_hash(hashed);
                }
                Err(e) => tracing::error!("bcrypt hashing failed: {e}"),
            }
        } else if plaintext.starts_with("$2") {
            state.auth.set_hash(plaintext.to_string());
        }
    }

    if state.auth.hash().is_empty() {
        tracing::warn!(
            "management.secret-key is empty; the management API rejects all requests \
             until one is configured"
        );
    }

    // 配置目录热重载。回调只更新状态与事件;运行时重配置(转发/
    // 白名单/ssh-guard)由 runtime_notify 循环统一消费,回滚路径同样覆盖。
    let watcher_state = state.clone();
    match rooster_config::watcher::spawn(
        config_path.to_path_buf(),
        watcher,
        move |outcome| watcher_state.on_reload_outcome(outcome),
    )
    .await
    {
        Ok(_handle) => tracing::info!("config hot-reload watcher started"),
        Err(e) => {
            tracing::error!("failed to watch {}: {e}", config_path.display());
            return ExitCode::FAILURE;
        }
    }

    // 封禁管理器(nftables + redb)。不可用时降级运行(503 + 告警),
    // 原因存进 state.ban_status 供面板展示。
    let (ban_mgr, ban_status) = crate::bans::init(&data_dir);
    *state.bans.write().unwrap() = ban_mgr.map(|m| m as Arc<dyn rooster_nft::BanManager>);
    *state.ban_status.write().unwrap() = ban_status;

    // WAF 桥接注入 http-guard 运行时;GeoIP 数据库就位(缺失时按
    // 配置拉取,失败降级);ACME(HTTP-01)后台签发/续期。
    state.httpguard.set_inspector(state.waf.clone());
    state.httpguard.set_wasm(state.wasmrt.clone());
    // http-guard 的拦截类事件(WAF Block)即时进节点事件流,
    // hub 联动策略才有数据可消费。
    {
        let s = state.clone();
        state.httpguard.set_event_sink(Arc::new(move |event| {
            s.push_event(event);
        }));
    }
    // B3:WASM 插件事件在 hook 结束即上报事件流(此前只在 reconfigure
    // 时扫出,请求路径事件全部丢失)。
    {
        let s = state.clone();
        state.wasmrt.set_event_sink(Arc::new(move |plugin, payload| {
            s.push_event(rooster_proto::Event::PluginEvent {
                plugin: plugin.to_string(),
                payload: payload.to_string(),
            });
        }));
    }
    // B6:on_l4_accept 插件挂到 forward accept 路径;Ban 复用
    // 封禁管理器(与 http-guard 的 ban_hook 同一执行面,600s 同参)。
    {
        let ban_hook = state.bans.read().unwrap().clone().map(|bans| {
            Arc::new(move |ip: &str, ttl: std::time::Duration| {
                let entry = crate::bans::manual_ban_entry(
                    ip,
                    ttl.as_secs(),
                    "wasm plugin on_l4_accept",
                    "forward",
                );
                match bans.apply_ban(&entry) {
                    Ok(()) => tracing::warn!(ip, ttl = ?ttl, "on_l4_accept escalated to ban"),
                    Err(e) => tracing::warn!(ip, error = %e, "on_l4_accept ban rejected"),
                }
            }) as Arc<dyn Fn(&str, std::time::Duration) + Send + Sync>
        });
        state
            .forwards
            .set_plugins(state.wasmrt.clone(), ban_hook);
    }
    if let Some(geo) = &effective.plugins.http_guard.geoip {
        let path =
            crate::geoip::ensure_db(&data_dir, &geo.database, geo.auto_update).await;
        // 配了 geo 规则却查不到库时默认拒绝启动;否则
        // geo.deny 会在库缺失期间静默失效(读不到国家码 → 放行)。
        if let Err(e) = crate::geoip::check_available(
            geo.fail_open,
            path.as_deref(),
            effective.sites.iter().any(|s| s.geo.is_some()),
        ) {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
        if let Some(path) = path {
            tracing::info!("geoip database ready: {}", path.display());
        }
    }
    {
        // 月度自动更新。只在启动时拉一次会让长跑节点一直用过期
        // 库,启动失败也永不重试;这里每日复查(fresh 命中直接返回)。
        let state = state.clone();
        let data_dir = data_dir.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
                let Some(geo) = state.effective().plugins.http_guard.geoip.clone() else {
                    continue;
                };
                let db = crate::geoip::ensure_db(&data_dir, &geo.database, geo.auto_update).await;
                if crate::geoip::check_available(
                    geo.fail_open,
                    db.as_deref(),
                    state.effective().sites.iter().any(|s| s.geo.is_some()),
                )
                .is_ok()
                    && db.is_some()
                {
                    // 库更新后重配置 http-guard,让新的 mmdb 生效。
                    state.runtime_notify.notify_one();
                }
            }
        });
    }
    {
        let acme = Arc::new(crate::acme::Acme::new(
            state.httpguard.clone(),
            data_dir.clone(),
            effective.plugins.http_guard.acme.clone(),
        ));
        let state2 = state.clone();
        tokio::spawn(async move {
            loop {
                let sites = state2.effective().sites;
                acme.ensure_certificates(&sites).await;
                // 签发/续期后触发重配置,让 tlsconf 重新加载证书文件。
                state2.runtime_notify.notify_one();
                tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
            }
        });
    }

    // hub 离线事件补报缓冲(上限 100k)。
    if effective.hub.is_some() {
        match crate::outbox::Outbox::open(&data_dir.join("hub-outbox.redb"), 100_000) {
            Ok(outbox) => {
                *state.hub_outbox.lock().unwrap() = Some(Arc::new(outbox));
            }
            Err(e) => tracing::warn!("hub outbox unavailable: {e}"),
        }
    }

    // hub 长连接客户端 + 证书续签 + 升级自检。
    if effective.hub.is_some() {
        let s = state.clone();
        tokio::spawn(async move {
            crate::hubclient::run(s).await;
        });
        let s2 = state.clone();
        tokio::spawn(async move {
            crate::hubclient::renewal_loop(s2).await;
        });
    }
    crate::upgrade::spawn_self_check(state.clone());

    // 事件通道:ssh-guard 等子任务 → 事件环(未来由同一通道上报 Hub)。
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    *state.events_tx.lock().unwrap() = Some(events_tx);
    {
        let state = state.clone();
        tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                state.push_event(event);
            }
        });
    }

    // 初始重配置 + 常驻循环:commit/热重载/回滚后重算运行时状态。
    crate::bans::reconfigure(&state).await;
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                state.runtime_notify.notified().await;
                crate::bans::reconfigure(&state).await;
                wasm_reconfigure(&state).await;
            }
        });
    }

    let listen = effective.management.listen();
    tracing::info!("management API listening on http://{listen}");
    let serve_state = state.clone();
    let mut serve = tokio::spawn(async move { management::serve(serve_state, listen).await });

    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cannot install SIGTERM handler: {e}");
            return ExitCode::FAILURE;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down"),
        res = &mut serve => {
            // 正常退出保留 nftables 表,重启窗口期不失保护;
            // 删表仅发生在 `rooster agent uninstall`。
            if let Err(e) = res.unwrap_or_else(|_| Err(std::io::Error::other("serve task panicked"))) {
                tracing::error!("management API failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    serve.abort();
    if let Some(task) = state.sshguard_task.lock().unwrap().take() {
        task.abort();
    }
    if let Some(task) = state.hardening_task.lock().unwrap().take() {
        task.abort();
    }
    state.forwards.shutdown().await;
    state.httpguard.shutdown().await;
    tracing::info!("shutdown complete");
    ExitCode::SUCCESS
}

/// WASM 插件重载:配置变化时按需下载 `rooster-hub:<name>`
/// 并重建插件实例。
async fn wasm_reconfigure(state: &Arc<AgentState>) {
    let eff = state.effective();
    let snapshot = serde_json::to_value(&eff.wasm_plugins).unwrap_or_default();
    if state.wasm_cfg.lock().unwrap().clone() == Some(snapshot.clone()) {
        return;
    }
    // 先下载缺失的 rooster-hub: 插件(异步),再同步 reconfigure。
    for p in eff.wasm_plugins.iter() {
        if let Some(name) = p.file.to_string_lossy().strip_prefix("rooster-hub:") {
            let dest = eff.agent.data_dir().join("plugins").join(name);
            if !dest.exists() {
                if let Err(e) = crate::hubclient::fetch_hub_file(state, &format!("/v0/downloads/wasm/{name}"), &dest).await {
                    tracing::warn!(plugin = p.id, error = e, "wasm download failed");
                }
            }
        }
    }
    let data_dir = eff.agent.data_dir();
    state.wasmrt.reconfigure(&eff.wasm_plugins, |p| {
        let file = p.file.to_string_lossy();
        if let Some(name) = file.strip_prefix("rooster-hub:") {
            let f = data_dir.join("plugins").join(name);
            f.is_file().then_some(f)
        } else if p.file.is_absolute() {
            p.file.is_file().then_some(p.file.clone())
        } else {
            let f = data_dir.join("plugins").join(&p.file);
            f.is_file().then_some(f)
        }
    });
    for (id, payload) in state.wasmrt.take_events() {
        state.push_event(rooster_proto::Event::PluginEvent { plugin: id, payload });
    }
    *state.wasm_cfg.lock().unwrap() = Some(snapshot);
}
