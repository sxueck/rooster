//! 本地管理 API:`/v0/management/*`,默认只绑定回环。
//! 远程访问一律经由 Hub 透传;覆盖 /config、/plugins、/forwards、
//! /events、/history、/apply/confirm。

pub mod auth;
mod network;

use crate::state::AgentState;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rand::RngExt;
use rooster_config::{writer, ConfigError, ForwardRule, Seg};
use rooster_nft::{BanManager, NftError};
use rooster_proto::Event;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn serve(state: Arc<AgentState>, addr: SocketAddr) -> std::io::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(std::io::Error::other)
}

pub fn router(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/v0/management", mgmt_router(state.clone()))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
}

/// 无鉴权管理路由:供 hub 透传调用(ApiRequest 已在 mTLS 通道内认证)
/// 与测试使用。
pub fn mgmt_router(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/readyz", get(get_ready))
        .route("/config", get(get_config).put(put_config))
        .route("/forwards", get(list_forwards))
        .route(
            "/forwards/{id}",
            put(put_forward).delete(delete_forward),
        )
        .route("/events", get(list_events))
        .route("/history", get(list_history))
        .route("/history/{name}", get(get_history))
        .route("/apply/confirm", post(post_confirm))
        .route("/bans", get(list_bans).post(post_ban))
        .route("/bans/{ip}", delete(delete_ban))
        .route("/allowlist", get(get_allowlist).put(put_allowlist))
        .route("/hardening", get(get_hardening).put(put_hardening))
        .route("/plugins/{name}", get(get_plugin).put(put_plugin))
        .route("/stats", get(get_stats))
        .route("/network", get(get_network))
        .route("/sites", get(list_sites))
        .route("/sites/{id}", put(put_site).delete(delete_site))
        .route("/layers", get(get_layers))
        .route("/wasm", get(get_wasm))
        .route("/wasm/{id}", put(put_wasm).delete(delete_wasm))
        .route("/waf/report", get(get_waf_report))
        .route("/waf/rules", get(get_waf_rules))
        .with_state(state)
}

/// 在进程内直接调用无鉴权管理路由(hub 透传的 Agent 半边)。
/// 返回 (status, 需转发的响应头, body)。
pub async fn serve_trusted(
    state: &Arc<AgentState>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tower::Service as _;
    let mut app = mgmt_router(state.clone());
    let method = axum::http::Method::from_bytes(method.as_bytes())
        .unwrap_or(axum::http::Method::GET);
    // 透传帧携带完整路径;mgmt_router 的路由定义在 /v0/management 之内。
    let path = path.strip_prefix("/v0/management").unwrap_or(path);
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = match builder.body(axum::body::Body::from(body.to_vec())) {
        Ok(r) => r,
        Err(e) => {
            return (
                400,
                vec![],
                format!("{{\"error\":\"bad request: {e}\"}}").into_bytes(),
            )
        }
    };
    match app.call(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let mut fwd = Vec::new();
            for (name, value) in resp.headers().iter() {
                let n = name.as_str();
                if n == "content-type" || n.starts_with("x-rooster-") {
                    if let Ok(v) = value.to_str() {
                        fwd.push((n.to_string(), v.to_string()));
                    }
                }
            }
            let body = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
                .await
                .unwrap_or_default();
            (status, fwd, body.to_vec())
        }
        Err(e) => (500, vec![], format!("{{\"error\":\"{e}\"}}").into_bytes()),
    }
}

/// 确认 token 生成(hubclient 的模板下发也使用)。
pub fn new_confirm_token() -> String {
    new_token()
}

// ---------------------------------------------------------------------------
// 鉴权中间件

async fn auth_middleware(
    State(state): State<Arc<AgentState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);

    // bcrypt 校验是 CPU 密集操作,放到阻塞线程池,避免占用 worker。
    let state_for_verify = state.clone();
    let peer_ip = peer.ip();
    let outcome = tokio::task::spawn_blocking(move || {
        state_for_verify.auth.verify(peer_ip, presented.as_deref())
    })
    .await
    .unwrap_or(auth::AuthOutcome::WrongSecret);

    match outcome {
        auth::AuthOutcome::Allowed => next.run(req).await,
        auth::AuthOutcome::TemporarilyBanned { .. } => {
            // 封禁只有经事件上报才可观测;AuthGate 自身拿不到
            // AgentState,所以由中间件在这里补报。
            state.push_event(Event::AuthTempBan {
                peer: peer_ip.to_string(),
            });
            (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "temporarily banned after repeated auth failures"}))).into_response()
        }
        auth::AuthOutcome::WrongSecret => {
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid credentials"}))).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// helpers

fn err_status(e: &ConfigError) -> StatusCode {
    match e {
        ConfigError::Parse { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ConfigError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn config_err_response(e: ConfigError) -> Response {
    let body = match &e {
        ConfigError::Parse { line, message } => json!({"error": message, "line": line}),
        ConfigError::Validation(errs) => json!({"error": "validation failed", "details": errs}),
        other => json!({"error": other.to_string()}),
    };
    (err_status(&e), Json(body)).into_response()
}

fn new_token() -> String {
    let bytes = rand::rng().random::<[u8; 16]>();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// /config

/// 读侧哨兵:写回时出现该值即表示“沿用节点上的现值”。
const SECRET_MASK: &str = "***";
/// 凭据字段(相对配置文件的 `local` 段):hub 注册 token 与本地管理口令。
const SECRET_PATHS: [&[&str]; 2] = [&["hub", "token"], &["management", "secret-key"]];

fn with_local(rel: &'static [&'static str]) -> Vec<&'static str> {
    let mut v = vec!["local"];
    v.extend_from_slice(rel);
    v
}

fn path_str<'a>(v: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str()
}

fn descend_mut<'a>(
    v: &'a mut serde_json::Value,
    path: &[&str],
) -> Option<&'a mut serde_json::Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get_mut(*p)?;
    }
    Some(cur)
}

/// raw YAML → 脱敏后的 YAML。解析失败时原样返回(后续校验会拒绝)。
/// 只改写有值的字段,注释与其余格式由 writer 保留。
fn mask_raw_secrets(raw: &str) -> String {
    let Ok(doc) = serde_norway::from_str::<serde_json::Value>(raw) else {
        return raw.to_string();
    };
    let mut out = raw.to_string();
    for rel in SECRET_PATHS {
        if path_str(&doc, &with_local(rel)).unwrap_or("").is_empty() {
            continue;
        }
        let segs: Vec<Seg> = with_local(rel).into_iter().map(Seg::K).collect();
        if let Ok(patched) = writer::replace_subtree(&out, &segs, &json!(SECRET_MASK)) {
            out = patched;
        }
    }
    out
}

/// JSON 形态(effective / local 段)的凭据字段脱敏。
fn mask_json_secrets(v: &mut serde_json::Value) {
    for rel in SECRET_PATHS {
        let Some((leaf, parents)) = rel.split_last() else {
            continue;
        };
        let Some(node) = descend_mut(v, parents) else {
            continue;
        };
        if let Some(s) = node.get_mut(*leaf) {
            if s.as_str().is_some_and(|s| !s.is_empty()) {
                *s = json!(SECRET_MASK);
            }
        }
    }
}

/// 写回:把哨兵还原为磁盘上的现值;现值不存在则删掉该键,
/// 绝不把哨兵当口令落盘。
fn restore_secrets(new_raw: &str, prev_raw: &str) -> Result<String, String> {
    let Ok(doc) = serde_norway::from_str::<serde_json::Value>(new_raw) else {
        return Ok(new_raw.to_string());
    };
    let prev = serde_norway::from_str::<serde_json::Value>(prev_raw).unwrap_or_default();
    let mut out = new_raw.to_string();
    for rel in SECRET_PATHS {
        let full = with_local(rel);
        if path_str(&doc, &full) != Some(SECRET_MASK) {
            continue;
        }
        let segs: Vec<Seg> = with_local(rel).into_iter().map(Seg::K).collect();
        out = match path_str(&prev, &full) {
            Some(old) => writer::replace_subtree(&out, &segs, &json!(old)).map_err(|e| e.to_string())?,
            None => writer::remove_subtree(&out, &segs).map_err(|e| e.to_string())?,
        };
    }
    Ok(out)
}

async fn get_config(State(state): State<Arc<AgentState>>) -> Response {
    let hash = state.current_hash();
    let raw = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let mut effective = serde_json::to_value(state.effective()).unwrap_or_default();
    mask_json_secrets(&mut effective);
    Json(json!({
        "hash": hash,
        "raw": mask_raw_secrets(&raw),
        "effective": effective,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct PutConfigBody {
    yaml: String,
}

async fn put_config(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    Json(body): Json<PutConfigBody>,
) -> Response {
    // 临界区覆盖「读快照 → 落盘 → 登记回滚」;否则并发请求/回滚定时器
    // 会基于同一份旧快照互相覆盖。函数体内无 await,持锁安全。
    let _guard = state.write_lock.lock().unwrap();
    let old_eff = state.effective();
    let current = state.current_hash();
    let previous_raw = std::fs::read_to_string(&state.config_path).unwrap_or_default();

    // 面板拿到的是脱敏 YAML;哨兵先还原成磁盘现值再落盘,否则会把
    // `***` 当成口令写进配置。
    let yaml = match restore_secrets(&body.yaml, &previous_raw) {
        Ok(y) => y,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": e})),
            )
                .into_response()
        }
    };

    let new_eff = match state.commit_raw(&yaml) {
        Ok(eff) => eff,
        Err(e) => return config_err_response(e),
    };

    // If-Match 不匹配时仍然写入(后写者覆盖),但带覆盖提示头。
    let mut headers_out: Vec<(String, String)> = Vec::new();
    if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        if !if_match.is_empty() && if_match != current && !current.is_empty() {
            headers_out.push(("x-rooster-overwrote".to_string(), current));
        }
    }

    state.push_event(Event::ConfigChanged {
        hash: state.current_hash(),
    });

    // 确认类变更需要 apply/confirm,超时回滚。
    let mut confirm = serde_json::Value::Null;
    if AgentState::needs_confirm(&old_eff, &new_eff) {
        let token = new_token();
        let timeout = old_eff.security.apply_confirm_timeout();
        state.start_confirm_timer(token.clone(), previous_raw, timeout);
        confirm = json!({
            "token": token,
            "rollback-in": timeout.as_secs(),
        });
    }

    let mut resp = Json(json!({
        "hash": state.current_hash(),
        "confirm": confirm,
    }))
    .into_response();
    for (k, v) in headers_out {
        if let Ok(name) = axum::http::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(val) = axum::http::HeaderValue::from_str(&v) {
                resp.headers_mut().insert(name, val);
            }
        }
    }
    resp
}

// ---------------------------------------------------------------------------
// /forwards

async fn list_forwards(State(state): State<Arc<AgentState>>) -> Response {
    Json(state.effective().forwards).into_response()
}

async fn put_forward(
    State(state): State<Arc<AgentState>>,
    Path(id): Path<String>,
    Json(rule): Json<serde_json::Value>,
) -> Response {
    // 反序列化触发字段级校验(枚举取值等);id 以路径为准。
    let mut value = rule;
    value["id"] = serde_json::json!(id);
    let rule: ForwardRule = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid forward rule: {e}")})),
            )
                .into_response()
        }
    };

    // 临界区覆盖「读磁盘 → yamlpatch → 落盘」整段,否则两个并发子树写
    // 会基于同一份旧快照互相覆盖。函数体内无 await,持锁安全。
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // 单节点修改默认写入 local 层。
    let file: rooster_config::AgentConfigFile = match serde_norway::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!("config on disk is not parseable: {e}")})),
            )
                .into_response()
        }
    };
    let idx = file.local.forwards.iter().position(|f| f.id == rule.id);
    let local_forwards_exists = writer::subtree_exists(
        &raw,
        &[Seg::K("local"), Seg::K("forwards")],
    )
    .unwrap_or(false);

    let value = serde_json::to_value(&rule).expect("forward rule serializes");
    let new_raw = match idx {
        Some(i) => writer::replace_subtree(
            &raw,
            &[Seg::K("local"), Seg::K("forwards"), Seg::I(i)],
            &value,
        ),
        // 非空 block 列表:追加。
        None if !file.local.forwards.is_empty() => {
            writer::append_item(&raw, &[Seg::K("local"), Seg::K("forwards")], &value)
        }
        // 列表键存在但为空(常为 `forwards: []` flow 形式):整体替换,
        // yamlpatch 不支持对 flow sequence 追加。
        None if local_forwards_exists => writer::replace_subtree(
            &raw,
            &[Seg::K("local"), Seg::K("forwards")],
            &serde_json::json!([value]),
        ),
        None => writer::add_key(
            &raw,
            &[Seg::K("local")],
            "forwards",
            &serde_json::json!([value]),
        ),
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };

    match state.commit_raw(&new_raw) {
        Ok(_) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            Json(json!({"hash": state.current_hash(), "id": rule.id})).into_response()
        }
        Err(e) => config_err_response(e),
    }
}

async fn delete_forward(
    State(state): State<Arc<AgentState>>,
    Path(id): Path<String>,
) -> Response {
    // 同 put_forward:临界区覆盖整段读改写。函数体内无 await,持锁安全。
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let file: rooster_config::AgentConfigFile = match serde_norway::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!("config on disk is not parseable: {e}")})),
            )
                .into_response()
        }
    };
    let Some(idx) = file.local.forwards.iter().position(|f| f.id == id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "forward not found"})))
            .into_response();
    };
    let new_raw = match writer::remove_subtree(
        &raw,
        &[Seg::K("local"), Seg::K("forwards"), Seg::I(idx)],
    ) {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };
    match state.commit_raw(&new_raw) {
        Ok(_) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => config_err_response(e),
    }
}

// ---------------------------------------------------------------------------
// /events, /history, /apply/confirm

async fn list_events(State(state): State<Arc<AgentState>>) -> Response {
    let events: Vec<serde_json::Value> = state
        .recent_events()
        .into_iter()
        .map(|r| json!({"ts": r.ts, "event": r.event}))
        .collect();
    Json(events).into_response()
}

async fn list_history(State(state): State<Arc<AgentState>>) -> Response {
    Json(json!({"files": state.writer.list_history()})).into_response()
}

async fn get_history(
    State(state): State<Arc<AgentState>>,
    Path(name): Path<String>,
) -> Response {
    match state.writer.read_history(&name) {
        Ok(raw) => Json(json!({"name": name, "raw": mask_raw_secrets(&raw)})).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ConfirmBody {
    token: String,
}

async fn post_confirm(
    State(state): State<Arc<AgentState>>,
    Json(body): Json<ConfirmBody>,
) -> Response {
    if state.confirm(&body.token) {
        StatusCode::OK.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no pending change for this token"})),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// /bans, /allowlist, /stats

/// 取封禁管理器并执行 `f`;不可用 503,Refused 409,其余错误 500。
fn with_bans<T>(
    state: &Arc<AgentState>,
    f: impl FnOnce(&Arc<dyn BanManager>) -> Result<T, NftError>,
) -> Result<T, Response> {
    let bans = state.bans.read().unwrap().clone();
    let Some(bans) = bans else {
        // 降级原因必须随 503 一起返回:否则“节点不能封禁”在面板上是一个
        // 无法诊断的黑洞(缺 capability?内核无 nf_tables?redb 打不开?)。
        let status = state.ban_status.read().unwrap().clone();
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "nftables ban management unavailable on this node",
                "ban_engine": { "available": false, "reason": status.reason },
            })),
        )
            .into_response());
    };
    match f(&bans) {
        Ok(v) => Ok(v),
        Err(NftError::Refused(msg)) => Err((
            StatusCode::CONFLICT,
            Json(json!({"error": msg, "code": "allowlisted"})),
        )
            .into_response()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response()),
    }
}

fn ban_country_reader(state: &AgentState) -> Option<maxminddb::Reader<Vec<u8>>> {
    let eff = state.effective();
    let geo = eff.plugins.http_guard.geoip.as_ref()?;
    let path = crate::geoip::db_path(&eff.agent.data_dir(), &geo.database);
    maxminddb::Reader::open_readfile(path).ok()
}

fn ban_country(reader: Option<&maxminddb::Reader<Vec<u8>>>, ip: &str) -> Option<String> {
    let reader = reader?;
    let ip = ip.parse::<std::net::IpAddr>().ok()?;
    let country: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
    let record = country.country?;
    record
        .names
        .and_then(|names| names.get("zh-CN").or_else(|| names.get("en")).map(|name| (*name).to_string()))
        .or_else(|| record.iso_code.map(str::to_string))
}

fn ban_to_json(b: &rooster_nft::BanEntry, country: Option<String>) -> serde_json::Value {
    json!({
        "ip": b.ip,
        "country": country,
        "reason": b.reason,
        "plugin": b.plugin,
        "node": b.node,
        "scope": match b.scope { rooster_nft::BanScope::Local => "local", rooster_nft::BanScope::Global => "global" },
        "started_at": b.started_at,
        "expires_at": b.expires_at,
        "ttl_secs": b.ttl.as_secs(),
    })
}

async fn list_bans(State(state): State<Arc<AgentState>>) -> Response {
    let country_reader = ban_country_reader(&state);
    match with_bans(&state, |b| b.list_bans()) {
        Ok(bans) => Json(json!({
            "bans": bans.iter().map(|ban| ban_to_json(ban, ban_country(country_reader.as_ref(), &ban.ip))).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(resp) => resp,
    }
}

#[derive(serde::Deserialize)]
struct PostBanBody {
    ip: String,
    #[serde(default = "default_ban_ttl")]
    ttl_secs: u64,
    #[serde(default)]
    reason: String,
}

fn default_ban_ttl() -> u64 {
    3600
}

async fn post_ban(
    State(state): State<Arc<AgentState>>,
    Json(body): Json<PostBanBody>,
) -> Response {
    let ip = body.ip.trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": format!("invalid ip `{ip}`")})),
        )
            .into_response();
    }
    let node = state
        .effective()
        .agent
        .node_name
        .clone()
        .unwrap_or_default();
    let entry = crate::bans::manual_ban_entry(
        &ip,
        body.ttl_secs,
        if body.reason.is_empty() { "manual ban" } else { &body.reason },
        &node,
    );
    match with_bans(&state, |b| b.apply_ban(&entry)) {
        Ok(()) => {
            state.push_event(Event::Ban {
                ip: entry.ip.clone(),
                reason: entry.reason.clone(),
                plugin: "manual".into(),
                scope: "local".into(),
                ttl_secs: entry.ttl.as_secs(),
            });
            Json(json!({"ok": true, "ip": entry.ip, "ttl_secs": entry.ttl.as_secs()})).into_response()
        }
        Err(resp) => resp,
    }
}

async fn delete_ban(
    State(state): State<Arc<AgentState>>,
    Path(ip): Path<String>,
) -> Response {
    match with_bans(&state, |b| b.remove_ban(&ip)) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}

async fn get_allowlist(State(state): State<Arc<AgentState>>) -> Response {
    // 展示生效白名单(admin-allowlist 配置层;运行时还叠加 Hub/本机地址,
    // 那些不可经面板修改)。带来源列出有效集:封禁被 409
    // 拒掉时,管理员需要看到到底是哪一条、为什么在名单里。
    let eff = state.effective();
    let with_src = crate::bans::allowlist_with_sources(&eff);
    Json(json!({
        "admin-allowlist": eff.security.admin_allowlist,
        "effective": with_src.iter().map(|(net, src)| json!({
            "cidr": net.to_string(),
            "source": src,
        })).collect::<Vec<_>>(),
        "hub_address_exempt": with_src.iter().any(|(_, src)| *src == "hub"),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct PutAllowlistBody {
    #[serde(default)]
    cidrs: Vec<String>,
}

async fn put_allowlist(
    State(state): State<Arc<AgentState>>,
    Json(body): Json<PutAllowlistBody>,
) -> Response {
    for cidr in &body.cidrs {
        if cidr.trim().parse::<ipnet::IpNet>().is_err() {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": format!("invalid cidr `{cidr}`")})),
            )
                .into_response();
        }
    }
    // 与 put_forward 相同的临界区:读磁盘 → 局部替换 → 原子落盘。
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let path = [Seg::K("local"), Seg::K("security"), Seg::K("admin-allowlist")];
    let value = serde_json::json!(body.cidrs);
    let new_raw = if writer::subtree_exists(&raw, &path).unwrap_or(false) {
        writer::replace_subtree(&raw, &path, &value)
    } else {
        writer::add_key(
            &raw,
            &[Seg::K("local"), Seg::K("security")],
            "admin-allowlist",
            &value,
        )
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };

    let old_eff = state.effective();
    let previous_raw = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    match state.commit_raw(&new_raw) {
        Ok(new_eff) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            // security 属确认类变更:白名单/封禁规则变更后需确认,
            // 超时回滚(回滚会再次触发 runtime 重配置恢复内核白名单)。
            let mut confirm = serde_json::Value::Null;
            if AgentState::needs_confirm(&old_eff, &new_eff) {
                let token = new_token();
                let timeout = old_eff.security.apply_confirm_timeout();
                state.start_confirm_timer(token.clone(), previous_raw, timeout);
                confirm = json!({"token": token, "rollback-in": timeout.as_secs()});
            }
            Json(json!({
                "hash": state.current_hash(),
                "confirm": confirm,
            }))
            .into_response()
        }
        Err(e) => config_err_response(e),
    }
}

// ---------------------------------------------------------------------------
// /hardening:加固配置单段读写(面板表单直改;全部子项 opt-in)。

async fn get_hardening(State(state): State<Arc<AgentState>>) -> Response {
    // 表单回填用生效值(local/managed 合并后);字段名与 Rust schema 同源,
    // 新增子项无需改动本端点。
    let eff = state.effective();
    Json(serde_json::to_value(&eff.hardening).expect("hardening serializes")).into_response()
}

async fn put_hardening(
    State(state): State<Arc<AgentState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    // 严格反序列化:未知字段直接 422(防 `enable` 拼错导致静默不生效)。
    let cfg: rooster_config::schema::HardeningConfig = match serde_json::from_value(body) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": format!("invalid hardening config: {e}")})),
            )
                .into_response()
        }
    };
    // 写入 local 层覆盖:单节点面板修改不动 Hub 模板下发的 managed 层。
    // 所有字段 None 保持 + skip_serializing_if,未填字段不落盘,
    // 不会以解析期默认值静默覆盖模板值(merge 测试固定了这一语义)。
    let value = serde_json::to_value(&cfg).expect("hardening serializes");

    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let path = [Seg::K("local"), Seg::K("hardening")];
    let new_raw = if writer::subtree_exists(&raw, &path).unwrap_or(false) {
        writer::replace_subtree(&raw, &path, &value)
    } else {
        writer::add_key(&raw, &[Seg::K("local")], "hardening", &value)
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };

    let old_eff = state.effective();
    let previous_raw = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    match state.commit_raw(&new_raw) {
        Ok(new_eff) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            // hardening 属确认类变更(state::needs_confirm 已含):蜜罐端口
            // 误配会自断服务,超时未确认自动回滚。
            let mut confirm = serde_json::Value::Null;
            if AgentState::needs_confirm(&old_eff, &new_eff) {
                let token = new_token();
                let timeout = old_eff.security.apply_confirm_timeout();
                state.start_confirm_timer(token.clone(), previous_raw, timeout);
                confirm = json!({"token": token, "rollback-in": timeout.as_secs()});
            }
            Json(json!({
                "hash": state.current_hash(),
                "confirm": confirm,
            }))
            .into_response()
        }
        Err(e) => config_err_response(e),
    }
}

// ---------------------------------------------------------------------------
// /plugins:内置插件(ssh-guard)表单直改,面板不再要求手编 YAML。

async fn get_plugin(
    State(state): State<Arc<AgentState>>,
    Path(name): Path<String>,
) -> Response {
    // 返回 effective 合并结果(含默认值),表单直接回填。
    match name.as_str() {
        "ssh-guard" => {
            let eff = state.effective();
            Json(serde_json::to_value(&eff.plugins.ssh_guard).expect("ssh-guard serializes"))
                .into_response()
        }
        _ => unknown_plugin(&name),
    }
}

async fn put_plugin(
    State(state): State<Arc<AgentState>>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if name != "ssh-guard" {
        return unknown_plugin(&name);
    }
    // 反序列化触发字段级校验(时长格式、枚举值)。
    let cfg: rooster_config::SshGuardConfig = match serde_json::from_value(body) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid ssh-guard config: {e}")})),
            )
                .into_response()
        }
    };
    let value = serde_json::to_value(&cfg).expect("ssh-guard serializes");

    // 与 put_allowlist 相同的临界区:读磁盘 → 子树替换 → 原子落盘。
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let m = [Seg::K("managed")];
    let p = [Seg::K("managed"), Seg::K("plugins")];
    let s = [Seg::K("managed"), Seg::K("plugins"), Seg::K("ssh-guard")];
    let new_raw = if writer::subtree_exists(&raw, &s).unwrap_or(false) {
        writer::replace_subtree(&raw, &s, &value)
    } else if writer::subtree_exists(&raw, &p).unwrap_or(false) {
        writer::add_key(&raw, &p, "ssh-guard", &value)
    } else if writer::subtree_exists(&raw, &m).unwrap_or(false) {
        writer::add_key(&raw, &m, "plugins", &json!({ "ssh-guard": value }))
    } else {
        writer::add_key(&raw, &[], "managed", &json!({ "plugins": { "ssh-guard": value } }))
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };

    let old_eff = state.effective();
    match state.commit_raw(&new_raw) {
        Ok(new_eff) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            // ssh_guard 段直接决定 nftables meter 规则:确认-回滚类变更。
            let mut confirm = serde_json::Value::Null;
            if AgentState::needs_confirm(&old_eff, &new_eff) {
                let token = new_token();
                let timeout = old_eff.security.apply_confirm_timeout();
                state.start_confirm_timer(token.clone(), raw, timeout);
                confirm = json!({"token": token, "rollback-in": timeout.as_secs()});
            }
            Json(json!({
                "hash": state.current_hash(),
                "confirm": confirm,
            }))
            .into_response()
        }
        Err(e) => config_err_response(e),
    }
}

fn unknown_plugin(name: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": format!("unknown builtin plugin `{name}`")})),
    )
        .into_response()
}

async fn get_ready(State(state): State<Arc<AgentState>>) -> Response {
    if *state.hub_connected.borrow() {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "hub not connected").into_response()
    }
}

async fn get_stats(State(state): State<Arc<AgentState>>) -> Response {
    let forward_stats = state.forwards.stats();
    let ban_count = state
        .bans
        .read()
        .unwrap()
        .as_ref()
        .and_then(|b| b.list_bans().ok())
        .map(|v| v.len());
    Json(json!({
        "forwards": forward_stats,
        "http": state.httpguard.stats(),
        "bans": ban_count,
        "ban_engine": *state.ban_status.read().unwrap(),
    }))
    .into_response()
}

async fn get_network() -> Response {
    Json(network::snapshot()).into_response()
}

async fn list_sites(State(state): State<Arc<AgentState>>) -> Response {
    Json(state.effective().sites).into_response()
}

// ---------------------------------------------------------------------------
// /sites/{id}(B7):站点 CRUD,与 /forwards/{id} 同一写路径/语义;
// 站点只存在于 managed 层,因此写入 managed.sites。

async fn put_site(
    State(state): State<Arc<AgentState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    // 反序列化触发字段级校验;id 以路径为准,body 不能指向别的站点。
    let mut value = body;
    value["id"] = serde_json::json!(id);
    let site: rooster_config::Site = match serde_json::from_value(value) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid site: {e}")})),
            )
                .into_response()
        }
    };

    // 与 put_forward 相同的临界区:读磁盘 → yamlpatch → 原子落盘。
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let file: rooster_config::AgentConfigFile = match serde_norway::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!("config on disk is not parseable: {e}")})),
            )
                .into_response()
        }
    };
    let idx = file.managed.sites.iter().position(|s| s.id == site.id);
    let sites_path = [Seg::K("managed"), Seg::K("sites")];
    let site_value = serde_json::to_value(&site).expect("site serializes");
    let new_raw = match idx {
        Some(i) => writer::replace_subtree(
            &raw,
            &[Seg::K("managed"), Seg::K("sites"), Seg::I(i)],
            &site_value,
        ),
        None if !file.managed.sites.is_empty() => {
            writer::append_item(&raw, &sites_path, &site_value)
        }
        None if writer::subtree_exists(&raw, &sites_path).unwrap_or(false) => {
            writer::replace_subtree(&raw, &sites_path, &serde_json::json!([site_value]))
        }
        // managed 键存在但无 sites:加子键。
        None if writer::subtree_exists(&raw, &[Seg::K("managed")]).unwrap_or(false) => {
            writer::add_key(
                &raw,
                &[Seg::K("managed")],
                "sites",
                &serde_json::json!([site_value]),
            )
        }
        // 整个 managed 层缺失:连键一起建。
        None => writer::add_key(
            &raw,
            &[],
            "managed",
            &serde_json::json!({"sites": [site_value]}),
        ),
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };
    match state.commit_raw(&new_raw) {
        Ok(_) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            Json(json!({"hash": state.current_hash(), "id": site.id})).into_response()
        }
        Err(e) => config_err_response(e),
    }
}

async fn delete_site(State(state): State<Arc<AgentState>>, Path(id): Path<String>) -> Response {
    // 同 put_site:临界区覆盖整段读改写。
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let file: rooster_config::AgentConfigFile = match serde_norway::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!("config on disk is not parseable: {e}")})),
            )
                .into_response()
        }
    };
    // 与 delete_forward 一致:不存在 → 404。
    let Some(idx) = file.managed.sites.iter().position(|s| s.id == id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "site not found"})))
            .into_response();
    };
    let new_raw = match writer::remove_subtree(
        &raw,
        &[Seg::K("managed"), Seg::K("sites"), Seg::I(idx)],
    ) {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };
    match state.commit_raw(&new_raw) {
        Ok(_) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => config_err_response(e),
    }
}

/// 配置分层展示:managed / local / effective 三层对比,
/// 面板用颜色区分漂移。
async fn get_layers(State(state): State<Arc<AgentState>>) -> Response {
    let raw = std::fs::read_to_string(&state.config_path).unwrap_or_default();
    let file: rooster_config::AgentConfigFile = serde_norway::from_str(&raw).unwrap_or_default();
    let mut local = serde_json::to_value(&file.local).unwrap_or_default();
    let mut effective = serde_json::to_value(state.effective()).unwrap_or_default();
    mask_json_secrets(&mut local);
    mask_json_secrets(&mut effective);
    Json(json!({
        "managed": file.managed,
        "local": local,
        "effective": effective,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// /wasm:插件配置 CRUD;file 支持本地路径或 `rooster-hub:<name>`
// (从 hub 插件仓库下载到 data-dir/plugins/)。

async fn get_wasm(State(state): State<Arc<AgentState>>) -> Response {
    let eff = state.effective();
    let mut plugins: Vec<serde_json::Value> = Vec::new();
    for p in eff.wasm_plugins.iter() {
        let manifest = state
            .wasmrt
            .manifest_json(&p.id)
            .unwrap_or(serde_json::Value::Null);
        let status = state.wasmrt.plugin_status(&p.id);
        plugins.push(json!({
            "id": p.id,
            "file": p.file,
            "hooks": p.hooks,
            "sites": p.sites,
            "limits": p.limits,
            "on_error": p.on_error,
            "config": p.config,
            "manifest": manifest,
            "status": status,
        }));
    }
    Json(json!({"plugins": plugins})).into_response()
}

async fn put_wasm(
    State(state): State<Arc<AgentState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut value = body;
    value["id"] = serde_json::json!(id);
    let plugin: rooster_config::WasmPlugin = match serde_json::from_value(value) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid wasm plugin entry: {e}")})),
            )
                .into_response()
        }
    };
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let file: rooster_config::AgentConfigFile = match serde_norway::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!("config on disk is not parseable: {e}")})),
            )
                .into_response()
        }
    };
    let value = serde_json::to_value(&plugin).expect("wasm entry serializes");
    let path = [Seg::K("local"), Seg::K("wasm-plugins")];
    let new_raw = match file.local.wasm_plugins.iter().position(|p| p.id == plugin.id) {
        Some(i) => writer::replace_subtree(
            &raw,
            &[Seg::K("local"), Seg::K("wasm-plugins"), Seg::I(i)],
            &value,
        ),
        None if !file.local.wasm_plugins.is_empty() => {
            writer::append_item(&raw, &path, &value)
        }
        None if writer::subtree_exists(&raw, &path).unwrap_or(false) => {
            writer::replace_subtree(&raw, &path, &serde_json::json!([value]))
        }
        None => writer::add_key(&raw, &[Seg::K("local")], "wasm-plugins", &serde_json::json!([value])),
    };
    let new_raw = match new_raw {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };
    match state.commit_raw(&new_raw) {
        Ok(_) => {
            state.push_event(Event::ConfigChanged {
                hash: state.current_hash(),
            });
            Json(json!({"hash": state.current_hash(), "id": plugin.id})).into_response()
        }
        Err(e) => config_err_response(e),
    }
}

async fn delete_wasm(
    State(state): State<Arc<AgentState>>,
    Path(id): Path<String>,
) -> Response {
    let _guard = state.write_lock.lock().unwrap();
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let file: rooster_config::AgentConfigFile = match serde_norway::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!("config on disk is not parseable: {e}")})),
            )
                .into_response()
        }
    };
    let Some(idx) = file.local.wasm_plugins.iter().position(|p| p.id == id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "wasm plugin not found"})))
            .into_response();
    };
    let new_raw = match writer::remove_subtree(
        &raw,
        &[Seg::K("local"), Seg::K("wasm-plugins"), Seg::I(idx)],
    ) {
        Ok(r) => r,
        Err(e) => return config_err_response(e),
    };
    match state.commit_raw(&new_raw) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => config_err_response(e),
    }
}

/// WAF 规则加载报告(不支持语法跳过明细;面板数据源)。
async fn get_waf_report(State(state): State<Arc<AgentState>>) -> Response {
    let report = state.waf_report.read().unwrap().clone();
    Json(json!({
        "report": report,
        "threshold": state.waf.threshold(),
    }))
    .into_response()
}

/// 当前生效规则集的完整清单:面板“规则”页需要知道到底加载了
/// 哪些规则,而不是只有一个 loaded 计数。
async fn get_waf_rules(State(state): State<Arc<AgentState>>) -> Response {
    let rules = state.waf.rules_info();
    let mut by_severity: std::collections::BTreeMap<String, u64> = Default::default();
    let mut by_phase: std::collections::BTreeMap<String, u64> = Default::default();
    for r in &rules {
        *by_severity.entry(r.severity.unwrap_or("NONE").to_string()).or_default() += 1;
        *by_phase.entry(r.phase.to_string()).or_default() += 1;
    }
    Json(json!({
        "rules": rules,
        "total": rules.len(),
        "paranoia": state.waf.paranoia(),
        "threshold": state.waf.threshold(),
        "by_severity": by_severity,
        "by_phase": by_phase,
    }))
    .into_response()
}
