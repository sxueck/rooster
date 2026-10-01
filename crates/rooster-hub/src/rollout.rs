//! 下发引擎:模板三步下发、全局封禁
//! 广播、升级分批观察。

use crate::store::{now_secs, GlobalBanRecord, NodeRecord, RolloutNodeResult, RolloutRecord};
use crate::HubState;
use rooster_config::Seg;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const APPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// `uname -m` 架构名(install.sh 与 resolve_bootstrap 的 `rooster-<arch>` /
/// `rooster-<ver>-<arch>` 命名使用的后缀集合,仅此一份)。
const ARTIFACT_ARCHES: &[&str] = &[
    "x86_64", "aarch64", "arm", "armv7", "i686", "i386", "riscv64", "powerpc64", "s390x",
];

/// 升级制品 key → Agent Hello 上报的 semver:剥离已知的 `-<arch>` 后缀
/// (`0.2.0-x86_64` → `0.2.0`);无已知后缀时原样返回(`1.0.0-rc1` 不是
/// 架构)。下载仍用原 key(入库 key 就是文件名)。
pub fn artifact_semver(key: &str) -> &str {
    ARTIFACT_ARCHES
        .iter()
        .find_map(|a| key.strip_suffix(&format!("-{a}")))
        .unwrap_or(key)
}

/// 模板变量渲染:`{{ node.name }}`、`{{ node.labels.<k> }}`。
/// 未知变量返回错误(下发前即可发现拼错)。
pub fn render_template(yaml: &str, node: &NodeRecord) -> Result<String, String> {
    let mut out = String::with_capacity(yaml.len());
    let mut rest = yaml;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let Some(end_rel) = rest[start + 2..].find("}}") else {
            return Err("unterminated `{{` in template".to_string());
        };
        let end = start + 2 + end_rel;
        let var = rest[start + 2..end].trim();
        let value = match var.strip_prefix("node.") {
            Some("name") => node.id.clone(),
            Some(path) => match path.strip_prefix("labels.") {
                Some(k) => node
                    .labels
                    .get(k)
                    .ok_or_else(|| format!("node {node} has no label `{k}`", node = node.id))?
                    .clone(),
                None => return Err(format!("unsupported variable `{{{var}}}`")),
            },
            None => return Err(format!("unsupported variable `{{{var}}}`")),
        };
        out.push_str(&value);
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// 用渲染后的模板替换节点 config.yaml 的 managed 段(预览与实际下发
/// 共用,保证所见即所得)。
pub fn replace_managed(current_raw: &str, rendered: &str) -> Result<String, String> {
    let value: serde_json::Value = yaml_to_json(rendered)?;
    let seg = [Seg::K("managed")];
    if rooster_config::writer::subtree_exists(current_raw, &seg).unwrap_or(false) {
        rooster_config::writer::replace_subtree(current_raw, &seg, &value)
    } else {
        rooster_config::writer::add_key(current_raw, &[], "managed", &value)
    }
    .map_err(|e| format!("patch managed section: {e}"))
}

/// yaml 片段 → json 值(模板限制为纯数据,无 anchor)。
fn yaml_to_json(yaml: &str) -> Result<serde_json::Value, String> {
    let v: serde_norway::Value =
        serde_norway::from_str(yaml).map_err(|e| format!("template is not valid yaml: {e}"))?;
    serde_json::to_value(&v).map_err(|e| format!("template is not plain data: {e}"))
}

/// 广播全局封禁到全部在线节点(离线节点靠重连全量同步)。
pub fn broadcast_global_ban(state: &Arc<HubState>, rec: &GlobalBanRecord) {
    let failed = state.registry.broadcast(rooster_proto::Frame::GlobalBan {
        ip: rec.ip.clone(),
        ttl_secs: rec.ttl_secs,
        reason: rec.reason.clone(),
        source_node: rec.source_node.clone(),
    });
    for id in failed {
        tracing::warn!(node = id, ip = rec.ip, "global ban send failed (node offline?)");
    }
}

/// 全量同步:节点(重)连后下发当前全部有效全局封禁。
pub fn global_ban_sync(state: &Arc<HubState>, node: &str) {
    let bans = state.store.list_global_bans().unwrap_or_default();
    let infos = bans
        .into_iter()
        .map(|b| rooster_proto::GlobalBanInfo {
            ip: b.ip,
            ttl_secs: b.ttl_secs,
            reason: b.reason,
            source_node: b.source_node,
        })
        .collect();
    if let Some(conn) = state.registry.get(node) {
        let _ = conn.send(rooster_proto::Frame::GlobalBanSync { bans: infos });
    }
}

/// 节点重连后补发待下发模板(离线记录待下发状态,重连自动补发)。
pub async fn replay_pending_template(state: &Arc<HubState>, node_id: &str) {
    let mut rec = match state.store.get_node(node_id) {
        Ok(Some(r)) if r.pending_template.is_some() => r,
        _ => return,
    };
    let tpl_id = rec.pending_template.clone().unwrap_or_default();
    let Some(tpl) = state.store.get_template(&tpl_id).unwrap_or(None) else {
        rec.pending_template = None;
        let _ = state.store.upsert_node(&rec);
        return;
    };
    let rendered = match render_template(&tpl.yaml, &rec) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(node = node_id, template = tpl_id, error = e, "pending template render failed");
            return;
        }
    };
    let Some(conn) = state.registry.get(node_id) else { return };
    match conn.apply_template(rendered, APPLY_TIMEOUT).await {
        Ok(rooster_proto::Frame::TemplateResult { ok, error, confirm_token, .. }) if ok => {
            match confirm_token {
                Some(token) => {
                    // 需要确认的变更,补发也必须走代确认序列;
                    // 确认成功前 pending_template 保留——否则节点侧自动回滚后
                    // 再也没有人重发这个模板。
                    let status = auto_confirm(state, node_id, token, state.cfg.auto_confirm_delay_secs)
                        .await;
                    if status == "confirmed" {
                        rec.pending_template = None;
                        let _ = state.store.upsert_node(&rec);
                        tracing::info!(node = node_id, template = tpl_id, "pending template applied and confirmed");
                    } else {
                        tracing::warn!(node = node_id, template = tpl_id, status, "pending template confirm failed, will retry on reconnect");
                    }
                }
                None => {
                    rec.pending_template = None;
                    let _ = state.store.upsert_node(&rec);
                    tracing::info!(node = node_id, template = tpl_id, "pending template applied");
                }
            }
            let _ = error;
        }
        other => {
            tracing::warn!(node = node_id, template = tpl_id, ?other, "pending template apply failed");
        }
    }
}

/// 模板下发:逐节点并发执行(并发度可配),结果落 RolloutRecord。
#[allow(clippy::too_many_arguments)]
pub fn spawn_template_rollout(
    state: Arc<HubState>,
    run_id: String,
    template_id: String,
    selector: BTreeMap<String, String>,
    concurrency: usize,
    auto_confirm_delay_secs: u64,
) {
    tokio::spawn(async move {
        let nodes = state.store.select_nodes(&selector).unwrap_or_default();
        let tpl = state.store.get_template(&template_id).unwrap_or(None);
        let Some(tpl) = tpl else {
            let _ = state.store.put_rollout(
                &run_id,
                &RolloutRecord {
                    kind: "template".into(),
                    template_id: Some(template_id.clone()),
                    version: None,
                    started_at: now_secs(),
                    finished_at: Some(now_secs()),
                    status: "failed: template missing".into(),
                    results: vec![],
                },
            );
            return;
        };
        let _ = state.store.put_rollout(
            &run_id,
            &RolloutRecord {
                kind: "template".into(),
                template_id: Some(template_id.clone()),
                version: None,
                started_at: now_secs(),
                finished_at: None,
                status: "running".into(),
                results: vec![],
            },
        );

        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let mut handles = Vec::new();
        for node in nodes {
            let state = state.clone();
            let run_id = run_id.clone();
            let tpl_yaml = tpl.yaml.clone();
            let sem = sem.clone();
            let delay = auto_confirm_delay_secs;
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await;
                apply_template_to_node(&state, &run_id, node, &tpl_yaml, delay).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        finish_rollout(&state, &run_id);
    });
}

async fn apply_template_to_node(
    state: &Arc<HubState>,
    run_id: &str,
    node: NodeRecord,
    tpl_yaml: &str,
    auto_confirm_delay_secs: u64,
) {
    let rendered = match render_template(tpl_yaml, &node) {
        Ok(r) => r,
        Err(e) => {
            add_result(state, run_id, node.id, "failed", Some(e));
            return;
        }
    };
    let Some(conn) = state.registry.get(&node.id) else {
        // 离线:登记待下发,重连补发。
        let mut node = node;
        let pending = state
            .store
            .get_rollout(run_id)
            .unwrap_or(None)
            .and_then(|r| r.template_id.clone());
        if let Some(t) = pending {
            node.pending_template = Some(t);
            let _ = state.store.upsert_node(&node);
        }
        add_result(state, run_id, node.id, "pending-offline", None);
        return;
    };
    match conn.apply_template(rendered, APPLY_TIMEOUT).await {
        Ok(rooster_proto::Frame::TemplateResult {
            ok,
            error,
            confirm_token,
            ..
        }) => {
            if !ok {
                add_result(state, run_id, node.id, "failed", error);
                return;
            }
            if let Some(token) = confirm_token {
                // 确认类模板变更,延迟后代确认(留出回滚窗口;
                // 节点侧 confirm 超时会自动回滚,这里到点补一票)。序列与
                // 重连补发共用 auto_confirm,一处实现两个入口。
                let state = state.clone();
                let node_id = node.id.clone();
                let run_id = run_id.to_string();
                add_result(&state, &run_id, node_id.clone(), "applied", None);
                tokio::spawn(async move {
                    let status = auto_confirm(&state, &node_id, token, auto_confirm_delay_secs).await;
                    add_result(&state, &run_id, node_id, status, None);
                    // 代确认完成后重新收尾 run(等待中的 applied 变为
                    // confirmed 时应当落 finished)。
                    finish_rollout(&state, &run_id);
                });
            } else {
                add_result(state, run_id, node.id, "applied", None);
            }
        }
        Ok(_) => add_result(state, run_id, node.id, "failed", Some("unexpected frame".into())),
        Err(e) => add_result(state, run_id, node.id, "error", Some(e.to_string())),
    }
}

/// 代确认序列(在线下发与重连补发共用):等待 `delay_secs`
/// (至少 1s,留出回滚窗口)后 POST apply/confirm,返回最终状态
/// ("confirmed" / "applied-confirm-failed")。
async fn auto_confirm(
    state: &Arc<HubState>,
    node_id: &str,
    token: String,
    delay_secs: u64,
) -> &'static str {
    tokio::time::sleep(Duration::from_secs(delay_secs.max(1))).await;
    let body = serde_json::json!({"token": token});
    match state.registry.get(node_id) {
        Some(conn) => {
            match conn
                .api_request(
                    "POST",
                    "/v0/management/apply/confirm",
                    vec![("content-type".into(), "application/json".into())],
                    serde_json::to_vec(&body).unwrap_or_default(),
                    APPLY_TIMEOUT,
                )
                .await
            {
                Ok((200, _, _)) => "confirmed",
                _ => "applied-confirm-failed",
            }
        }
        None => "applied-confirm-failed",
    }
}

fn add_result(
    state: &Arc<HubState>,
    run_id: &str,
    node_id: String,
    status: &str,
    error: Option<String>,
) {
    if let Ok(Some(mut run)) = state.store.get_rollout(run_id) {
        // 幂等:同一节点保留最新状态。
        run.results.retain(|r| r.node_id != node_id);
        run.results.push(RolloutNodeResult {
            node_id,
            status: status.to_string(),
            error,
        });
        let _ = state.store.put_rollout(run_id, &run);
    }
}

fn finish_rollout(state: &Arc<HubState>, run_id: &str) {
    if let Ok(Some(mut run)) = state.store.get_rollout(run_id) {
        // 尚有 applied 未 confirmed 的延迟任务,不算 finished。
        let waiting = run
            .results
            .iter()
            .any(|r| r.status == "applied" || r.status == "pending-offline");
        if !waiting {
            run.finished_at = Some(now_secs());
            run.status = "done".into();
        } else {
            run.status = "waiting-confirm".into();
        }
        let _ = state.store.put_rollout(run_id, &run);
    }
}

/// 升级分批下发:每批 batch_size 台,等待观察窗口,通过节点
/// Hello 上报的版本判定成功。
pub fn spawn_upgrade_rollout(
    state: Arc<HubState>,
    run_id: String,
    version: String,
    selector: BTreeMap<String, String>,
    batch_size: usize,
    wait_secs: u64,
) {
    tokio::spawn(async move {
        let nodes = state.store.select_nodes(&selector).unwrap_or_default();
        let url = state.signed_download_url(&format!("/v0/downloads/{version}"), 24 * 3600);
        let sig = state
            .store
            .get_upgrade_sig(&version)
            .unwrap_or(None)
            .unwrap_or_default();
        let _ = state.store.put_rollout(
            &run_id,
            &RolloutRecord {
                kind: "upgrade".into(),
                template_id: None,
                version: Some(version.clone()),
                started_at: now_secs(),
                finished_at: None,
                status: "running".into(),
                results: vec![],
            },
        );
        for batch in nodes.chunks(batch_size.max(1)) {
            for node in batch {
                let Some(conn) = state.registry.get(&node.id) else {
                    add_result(&state, &run_id, node.id.clone(), "offline", None);
                    continue;
                };
                let sent = conn.send(rooster_proto::Frame::Upgrade {
                    version: version.clone(),
                    url: url.clone(),
                    signature: sig.clone(),
                    public_key: state.cfg.upgrade_public_key.clone(),
                });
                add_result(
                    &state,
                    &run_id,
                    node.id.clone(),
                    if sent.is_ok() { "sent" } else { "offline" },
                    None,
                );
            }
            // 观察窗口:等节点重启并以新版本 Hello 回来。上报的是纯
            // semver(CARGO_PKG_VERSION),入库 key 可能带 -<arch> 后缀,
            // 必须先归一再比较,否则架构包永远“没升级”。
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;
            let want = artifact_semver(&version);
            for node in batch {
                if let Ok(Some(rec)) = state.store.get_node(&node.id) {
                    if rec.version == want {
                        replace_result(&state, &run_id, &node.id, "upgraded");
                    } else if state.registry.is_online(&node.id) && rec.version != want {
                        // 还在线且版本没变:节点还没执行或执行失败。
                        replace_result(&state, &run_id, &node.id, "version-unchanged");
                    } else {
                        replace_result(&state, &run_id, &node.id, "unresponsive");
                    }
                }
            }
        }
        if let Ok(Some(mut run)) = state.store.get_rollout(&run_id) {
            run.finished_at = Some(now_secs());
            run.status = "done".into();
            let _ = state.store.put_rollout(&run_id, &run);
        }
    });
}

fn replace_result(state: &Arc<HubState>, run_id: &str, node_id: &str, status: &str) {
    if let Ok(Some(mut run)) = state.store.get_rollout(run_id) {
        for r in run.results.iter_mut() {
            if r.node_id == node_id {
                r.status = status.to_string();
            }
        }
        let _ = state.store.put_rollout(run_id, &run);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rooster_proto::Frame;

    fn node(id: &str, labels: &[(&str, &str)]) -> NodeRecord {
        let mut n = NodeRecord::new(id, "fp".into());
        for (k, v) in labels {
            n.labels.insert(k.to_string(), v.to_string());
        }
        n
    }

    #[test]
    fn renders_node_and_label_vars() {
        let n = node("web-01", &[("env", "prod")]);
        let out = render_template("name: {{ node.name }}\nenv: {{ node.labels.env }}\n", &n).unwrap();
        assert_eq!(out, "name: web-01\nenv: prod\n");
    }

    #[test]
    fn unknown_vars_fail() {
        let n = node("a", &[]);
        assert!(render_template("{{ node.foo }}", &n).is_err());
        assert!(render_template("{{ node.labels.missing }}", &n).is_err());
        assert!(render_template("{{ other }}", &n).is_err());
        assert!(render_template("{{ node.name ", &n).is_err());
    }

    #[test]
    fn replace_managed_roundtrip() {
        let current = "local:\n  agent:\n    node-name: a\n";
        let out = replace_managed(current, "plugins:\n  ssh-guard:\n    enabled: true\n").unwrap();
        assert!(out.contains("managed:"));
        assert!(out.contains("ssh-guard"));
        assert!(out.contains("node-name: a"));
        // 已有 managed 段:替换而不是叠加。
        let out2 = replace_managed(&out, "waf:\n  signatures: [sqli]\n").unwrap();
        assert!(out2.contains("signatures"));
        assert!(!out2.contains("ssh-guard"));
    }

    #[test]
    fn invalid_yaml_fails_replace() {
        assert!(replace_managed("local: {}", ":\n  - [").is_err());
    }

    #[test]
    fn artifact_semver_strips_known_arch_suffixes() {
        assert_eq!(artifact_semver("0.2.0"), "0.2.0");
        assert_eq!(artifact_semver("1.0.0-rc1"), "1.0.0-rc1", "prerelease is not an arch");
        assert_eq!(artifact_semver("1.0.0-rc1-aarch64"), "1.0.0-rc1");
        assert_eq!(artifact_semver("0.2.0-x86_64"), "0.2.0");
        assert_eq!(artifact_semver("0.2.0-notanarch"), "0.2.0-notanarch");
        for a in ARTIFACT_ARCHES {
            assert_eq!(artifact_semver(&format!("9.9.9-{a}")), "9.9.9");
        }
    }

    /// 构建可驱动下发引擎的测试状态(临时目录 + 真实 store/pki)。
    fn test_state(tag: &str) -> (Arc<crate::HubState>, crate::store::Store) {
        let dir = std::env::temp_dir().join(format!("rooster-rollout-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::store::open(&dir.join("h.redb")).unwrap();
        let store = crate::store::Store::new(db);
        let pki = crate::pki::HubPki::ensure(&dir).unwrap();
        let (events_tx, _) = tokio::sync::broadcast::channel(8);
        let state = Arc::new(crate::HubState {
            cfg: crate::config::HubConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                data_dir: dir.clone(),
                public_url: None,
                tls: Default::default(),
                secret_key: None,
                cors_allowed_origins: vec![],
                session_ttl: None,
                panel_dir: dir.clone(),
                auto_confirm_delay_secs: 0,
                upgrade_public_key: None,
                global_ban_policies: vec![],
                audit_retention: None,
            },
            store: store.clone(),
            pki,
            registry: Default::default(),
            policy: std::sync::Mutex::new(crate::policy::PolicyEngine::new()),
            login_gate: Default::default(),
            events_tx,
            recent: std::sync::Mutex::new(Default::default()),
        });
        (state, store)
    }

    fn put_template(store: &crate::store::Store, id: &str) {
        store
            .put_template(
                id,
                &crate::store::TemplateRecord {
                    name: "n".into(),
                    selector: Default::default(),
                    yaml: "plugins:\n  ssh-guard:\n    enabled: true\n".into(),
                    updated_at: 0,
                },
            )
            .unwrap();
    }

    #[tokio::test]
    async fn template_rollout_applies_and_confirms_via_conn() {
        let (state, store) = test_state("run");
        put_template(&store, "tpl");
        store.upsert_node(&node("web-1", &[])).unwrap();

        // 模拟在线节点:ApplyTemplate → TemplateResult(带 confirm token),
        // 随后 Hub 代发 apply/confirm,同样走 ApiRequest。
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = crate::registry::Conn::new("web-1", tx);
        state.registry.register("web-1", conn.clone());
        {
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    match frame {
                        Frame::ApplyTemplate { id, .. } => {
                            conn.complete(
                                id,
                                Frame::TemplateResult {
                                    id,
                                    ok: true,
                                    error: None,
                                    confirm_token: Some("ctok".into()),
                                },
                            );
                        }
                        Frame::ApiRequest { id, method, path, .. } => {
                            assert_eq!(method, "POST");
                            assert_eq!(path, "/v0/management/apply/confirm");
                            conn.complete(
                                id,
                                Frame::ApiResponse {
                                    id,
                                    status: 200,
                                    headers: vec![],
                                    body: b"{}".to_vec(),
                                },
                            );
                        }
                        _ => {}
                    }
                }
            });
        }

        spawn_template_rollout(
            state.clone(),
            "run1".into(),
            "tpl".into(),
            Default::default(),
            2,
            0,
        );
        // 等待后台任务跑完(auto_confirm_delay = 0 → helper 内部至少 1s)。
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if let Ok(Some(run)) = state.store.get_rollout("run1") {
                if run.finished_at.is_some() {
                    assert_eq!(run.status, "done");
                    assert!(run.results.iter().any(|r| r.node_id == "web-1" && r.status == "confirmed"),
                        "results: {:?}", run.results);
                    return;
                }
            }
        }
        panic!("rollout did not finish: {:?}", state.store.get_rollout("run1").unwrap());
    }

    /// C5:重连补发遇到需要确认的模板时,必须先 POST apply/confirm 并
    /// 拿到 200 才清 pending_token——首次确认失败时保留,下次重连重试。
    #[tokio::test]
    async fn replay_pending_template_honours_confirm_token() {
        let (state, store) = test_state("replay");
        put_template(&store, "tpl");
        let mut n = node("web-1", &[]);
        n.pending_template = Some("tpl".into());
        store.upsert_node(&n).unwrap();

        // 模拟节点:ApplyTemplate 回带 confirm_token 的结果;apply/confirm
        // 第一次回 500,之后回 200。
        let confirm_hits: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = crate::registry::Conn::new("web-1", tx);
        state.registry.register("web-1", conn.clone());
        {
            let conn = conn.clone();
            let confirm_hits = confirm_hits.clone();
            let attempts = attempts.clone();
            tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    match frame {
                        Frame::ApplyTemplate { id, .. } => {
                            conn.complete(
                                id,
                                Frame::TemplateResult {
                                    id,
                                    ok: true,
                                    error: None,
                                    confirm_token: Some("ctok".into()),
                                },
                            );
                        }
                        Frame::ApiRequest { id, method, path, .. } => {
                            confirm_hits.lock().unwrap().push(format!("{method} {path}"));
                            let status =
                                if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                                    500
                                } else {
                                    200
                                };
                            conn.complete(
                                id,
                                Frame::ApiResponse {
                                    id,
                                    status,
                                    headers: vec![],
                                    body: b"{}".to_vec(),
                                },
                            );
                        }
                        _ => {}
                    }
                }
            });
        }

        replay_pending_template(&state, "web-1").await;
        let hits = confirm_hits.lock().unwrap().clone();
        assert_eq!(
            hits,
            vec!["POST /v0/management/apply/confirm".to_string()],
            "replay must issue the confirm ApiRequest"
        );
        assert_eq!(
            state.store.get_node("web-1").unwrap().unwrap().pending_template,
            Some("tpl".into()),
            "pending must survive a failed confirm"
        );

        // 第二次补发:确认 200 → pending 才被清掉。
        replay_pending_template(&state, "web-1").await;
        let hits = confirm_hits.lock().unwrap().clone();
        assert_eq!(hits.len(), 2, "second replay must confirm again");
        assert_eq!(
            state.store.get_node("web-1").unwrap().unwrap().pending_template,
            None,
            "pending must be cleared only after a successful confirm"
        );
    }

    /// C6:入库 key 带架构后缀、节点 Hello 上报纯 semver → 必须判为
    /// upgraded,而不是永远 version-unchanged。
    #[tokio::test]
    async fn arch_suffixed_upgrade_rollout_reports_upgraded() {
        let (state, store) = test_state("arch");
        let mut n = node("web-1", &[]);
        n.version = "0.2.0".into();
        store.upsert_node(&n).unwrap();
        // 在线节点(Upgrade 帧无人消费也不影响判定)。
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        state.registry.register("web-1", crate::registry::Conn::new("web-1", tx));

        spawn_upgrade_rollout(
            state.clone(),
            "run-u".into(),
            "0.2.0-x86_64".into(),
            Default::default(),
            1,
            0,
        );
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if let Ok(Some(run)) = state.store.get_rollout("run-u") {
                if run.finished_at.is_some() {
                    assert!(
                        run.results.iter().any(|r| r.node_id == "web-1" && r.status == "upgraded"),
                        "results: {:?}",
                        run.results
                    );
                    return;
                }
            }
        }
        panic!("upgrade rollout did not finish: {:?}", state.store.get_rollout("run-u").unwrap());
    }
}
