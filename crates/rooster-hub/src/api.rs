//! Hub REST API:面板与 Agent 注册。
//!
//! - `/v0/auth/login`:secret-key → 短期会话 token;
//! - `/v0/register`:一次性 token + CSR → 客户端证书;
//! - `/v0/nodes/{id}/management/*`:透传;
//! - 模板 / 全局封禁 / 事件 / 审计 / 升级 / WASM。
//!
//! CORS 只放行 `cors-allowed-origins` 白名单。

use crate::http::ConnMeta;
use crate::install;
use crate::rollout;
use crate::store::{now_secs, AuditEntry};
use crate::HubState;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use rand::RngExt;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const PASSTHROUGH_TIMEOUT: Duration = Duration::from_secs(10);

/// 升级包 / WASM 制品的上传上限:agent 二进制链接了 wasmtime,默认 2MiB
/// 请求体限制会把所有真实制品挡在 413。仅上传路由放宽。
const MAX_UPLOAD_BODY: usize = 256 * 1024 * 1024;

/// 登录暴力破解防护(同款语义)。
#[derive(Default)]
pub struct LoginGate {
    fails: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, u64)>>,
}

const LOGIN_MAX_FAILS: u32 = 5;
const LOGIN_LOCK_SECS: u64 = 300;

impl LoginGate {
    fn check(&self, ip: std::net::IpAddr) -> bool {
        let m = self.fails.lock().unwrap();
        match m.get(&ip) {
            Some((_, until)) if *until > now_secs() => false,
            _ => true,
        }
    }

    fn fail(&self, ip: std::net::IpAddr) {
        let mut m = self.fails.lock().unwrap();
        let e = m.entry(ip).or_insert((0, 0));
        e.0 += 1;
        if e.0 >= LOGIN_MAX_FAILS {
            *e = (0, now_secs() + LOGIN_LOCK_SECS);
        }
    }

    fn clear(&self, ip: std::net::IpAddr) {
        self.fails.lock().unwrap().remove(&ip);
    }
}

pub fn router(state: Arc<HubState>) -> Router {
    let public = Router::new()
        .route("/v0/auth/login", post(login))
        .route("/v0/register", post(register))
        .route("/v0/pubkey.pem", get(pubkey_pem))
        .route("/v0/ca.crt", get(server_ca))
        .route("/install.sh", get(install_script))
        .route("/v0/ws", get(crate::ws::panel_ws))
        .route("/agent/ws", get(crate::ws::agent_ws))
        .route("/v0/downloads/{*rest}", get(download))
        .route("/healthz", get(|| async { "ok" }));

    let protected = Router::new()
        .route("/v0/overview", get(overview))
        .route("/v0/nodes", get(list_nodes))
        .route("/v0/nodes/register-tokens", post(create_register_token))
        .route("/v0/nodes/{id}/labels", put(put_labels))
        .route("/v0/nodes/{id}", delete(revoke_node))
        .route("/v0/nodes/{id}/management/{*path}", any(passthrough))
        .route("/v0/templates", get(list_templates))
        .route("/v0/templates/{id}", put(put_template).delete(delete_template))
        .route("/v0/templates/{id}/preview", post(preview_template))
        .route("/v0/templates/{id}/rollout", post(rollout_template))
        .route("/v0/rollouts", get(list_rollouts))
        .route("/v0/rollouts/{id}", get(get_rollout))
        .route("/v0/global-bans", get(list_global_bans).post(post_global_ban))
        .route("/v0/global-bans/{ip}", delete(delete_global_ban))
        .route("/v0/global-ban-policies", get(get_policies).put(put_policies))
        .route("/v0/events", get(query_events))
        .route("/v0/audit", get(query_audit))
        .route("/v0/upgrades", get(list_upgrades))
        .route("/v0/upgrades/{version}/rollout", post(rollout_upgrade))
        .route("/v0/wasm-plugins", get(list_wasm))
        .route("/v0/wasm-plugins/{name}", delete(delete_wasm))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session_auth,
        ));

    let uploads = Router::new()
        .route("/v0/upgrades", post(post_upgrade))
        .route("/v0/wasm-plugins", post(post_wasm))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session_auth,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .merge(uploads)
        .fallback(static_handler)
        .layer(middleware::from_fn_with_state(state.clone(), cors))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// 中间件:会话鉴权 + CORS

async fn session_auth(
    State(state): State<Arc<HubState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let ok = match token {
        Some(t) => state.store.validate_session(&t).unwrap_or(false),
        None => false,
    };
    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid or expired session"})),
        )
            .into_response()
    }
}

async fn cors(
    State(state): State<Arc<HubState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let allowed = origin
        .as_deref()
        .and_then(|o| {
            state
                .cfg
                .cors_allowed_origins
                .iter()
                .find(|c| c.as_str() == o || c.as_str() == "*")
        })
        .map(|_| origin.clone().unwrap());
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        apply_cors(resp.headers_mut(), allowed.as_deref());
        return resp;
    }
    let mut resp = next.run(req).await;
    if let Some(o) = allowed {
        apply_cors(resp.headers_mut(), Some(&o));
    }
    resp
}

fn apply_cors(h: &mut header::HeaderMap, origin: Option<&str>) {
    if let Some(o) = origin {
        if let Ok(v) = header::HeaderValue::from_str(o) {
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::HeaderValue::from_static("GET, PUT, POST, DELETE, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::HeaderValue::from_static(
            "authorization, content-type, if-match, x-rooster-version, x-rooster-signature, x-rooster-name",
        ),
    );
    merge_vary_origin(h);
}

/// Vary 只能合并不能覆盖:下载响应已带 `Vary: Accept-Encoding`,直接
/// insert `origin` 会把它抹掉,共享缓存就会把 gzip 表示发给声明了 identity
/// 的客户端(或反之)。取首条 Vary 行合并即可 —— 本服务所有响应都只有单条。
fn merge_vary_origin(h: &mut header::HeaderMap) {
    let existing = h
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let merged = if existing.trim().is_empty() {
        "origin".to_owned()
    } else if existing
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("origin"))
    {
        existing
    } else {
        format!("{existing}, origin")
    };
    if let Ok(v) = header::HeaderValue::from_str(&merged) {
        h.insert(header::VARY, v);
    }
}

// ---------------------------------------------------------------------------
// 登录 / 注册

#[derive(Deserialize)]
struct LoginBody {
    secret_key: String,
}

async fn login(
    State(state): State<Arc<HubState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> Response {
    if !state.login_gate.check(peer.ip()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "too many failed logins, retry later"})),
        )
            .into_response();
    }
    let hash = state.cfg.secret_key.clone().unwrap_or_default();
    let ok = tokio::task::spawn_blocking(move || bcrypt::verify(&body.secret_key, &hash))
        .await
        .unwrap_or(Ok(false))
        .unwrap_or(false);
    if !ok {
        state.login_gate.fail(peer.ip());
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid credentials"})),
        )
            .into_response();
    }
    state.login_gate.clear(peer.ip());
    let token = new_token();
    let exp = now_secs() + state.cfg.session_ttl().as_secs();
    if let Err(e) = state.store.insert_session(&token, exp) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    Json(json!({"token": token, "expires_at": exp})).into_response()
}

fn new_token() -> String {
    let bytes = rand::rng().random::<[u8; 32]>();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 下发 run_id:秒级时间戳可读,但同一秒内并发触发的两次下发会写同一个
/// redb key 互相覆盖,必须叠加随机量(与 new_token 同一随机源)。
fn new_run_id(prefix: &str) -> String {
    let bytes = rand::rng().random::<[u8; 8]>();
    format!(
        "{prefix}{}-{}",
        now_secs(),
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

#[derive(Deserialize)]
struct RegisterBody {
    token: String,
    csr_pem: String,
    node_id: String,
}

/// Agent 注册:一次性 token + CSR → 客户端证书 + CA。
async fn register(
    State(state): State<Arc<HubState>>,
    Json(body): Json<RegisterBody>,
) -> Response {
    let node_id = body.node_id.trim().to_string();
    if node_id.is_empty() || node_id.len() > 64 || !node_id.chars().all(is_node_char) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "invalid node id"})),
        )
            .into_response();
    }
    // 一次性 token 只用于新增节点:若允许覆盖既有记录,任何一枚有效 token
    // 配上猜得到的 node_id(通常是主机名)即可接管该节点的 mTLS 身份,并把
    // 真 Agent 用证书指纹校验锁在门外。重新注册需先在面板删除该节点。
    if state.store.get_node(&node_id).unwrap_or(None).is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "node id already registered or revoked; delete it in the panel before re-registering"})),
        )
            .into_response();
    }
    // 先验 CSR 再消费 token:坏 CSR 不应烧掉一次性 token。
    let Ok((cert_pem, fp)) = state.pki.sign_csr(&body.csr_pem, &node_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "cannot sign csr"})),
        )
            .into_response();
    };
    let Ok(true) = state.store.consume_token(&body.token) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid, expired or used registration token"})),
        )
            .into_response();
    };
    let rec = crate::store::NodeRecord::new(&node_id, fp);
    if let Err(e) = state.store.upsert_node(&rec) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state.audit("agent", Some(&node_id), "REGISTER", "/v0/register", b"", 200);
    Json(json!({
        "cert_pem": cert_pem,
        "ca_pem": state.pki.ca_cert_pem,
    }))
    .into_response()
}

fn is_node_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

// ---------------------------------------------------------------------------
// 节点

async fn list_nodes(State(state): State<Arc<HubState>>) -> Response {
    let nodes: Vec<_> = state
        .store
        .list_nodes()
        .unwrap_or_default()
        .into_iter()
        .map(|mut n| {
            let online = state.registry.is_online(&n.id);
            if online {
                n.last_seen = now_secs();
                let _ = state.store.upsert_node(&n);
            }
            json!({
                "id": n.id,
                "labels": n.labels,
                "version": n.version,
                "online": online,
                "last_seen": n.last_seen,
                "config_hash": n.config_hash,
                "pending_template": n.pending_template.is_some(),
            })
        })
        .collect();
    Json(json!({"nodes": nodes})).into_response()
}

async fn create_register_token(
    State(state): State<Arc<HubState>>,
    ConnectInfo(_): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let base = match state.cfg.hub_base(request_host(&headers)) {
        Ok(base) => base,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let ca_sha256 = match state.cfg.tls.ca.as_ref().map(|path| ca_fingerprint(path)).transpose() {
        Ok(fingerprint) => fingerprint,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let ca_arg = ca_sha256.as_ref().map(|fp| format!(" --ca-sha256 {fp}")).unwrap_or_default();
    let token = new_token();
    if let Err(e) = state.store.insert_token(&token, Duration::from_secs(15 * 60)) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
    }
    state.audit("panel", None, "POST", "/v0/nodes/register-tokens", b"", 200);
    Json(json!({
        "token": token,
        "expires_at": now_secs() + 15 * 60,
        "ca_sha256": ca_sha256,
        "install_cmd": format!(
            "curl -fsSL https://raw.githubusercontent.com/sxueck/rooster/main/enroll.sh | sudo sh -s -- --hub {base} --token {token}{ca_arg}"
        ),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct LabelsBody {
    labels: BTreeMap<String, String>,
}

async fn put_labels(
    State(state): State<Arc<HubState>>,
    Path(id): Path<String>,
    Json(body): Json<LabelsBody>,
) -> Response {
    let Some(mut rec) = state.store.get_node(&id).unwrap_or(None) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "node not found"}))).into_response();
    };
    rec.labels = body.labels;
    if let Err(e) = state.store.upsert_node(&rec) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state.audit("panel", Some(&id), "PUT", &format!("/v0/nodes/{id}/labels"), b"labels", 200);
    Json(json!({"ok": true})).into_response()
}

async fn revoke_node(State(state): State<Arc<HubState>>, Path(id): Path<String>) -> Response {
    let Some(mut rec) = state.store.get_node(&id).unwrap_or(None) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "node not found"}))).into_response();
    };
    if let Err(e) = state.store.revoke_cert(&rec.cert_fp) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    rec.revoked = true;
    let _ = state.store.upsert_node(&rec);
    // 注册接口的 409 文案承诺“先在面板删除”:必须真的删行,否则该
    // node_id 永远无法重新注册;证书指纹已进吊销表,旧证书换不回身份。
    if let Err(e) = state.store.delete_node(&id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    // 断开在线连接;Agent 按本地配置继续运行。
    if let Some(conn) = state.registry.get(&id) {
        let _ = conn.send(rooster_proto::Frame::Error {
            message: "node revoked".to_string(),
        });
        state.registry.disconnect(&id);
    }
    state.audit("panel", Some(&id), "DELETE", &format!("/v0/nodes/{id}"), b"", 200);
    Json(json!({"ok": true})).into_response()
}

// ---------------------------------------------------------------------------
// 透传

async fn passthrough(
    State(state): State<Arc<HubState>>,
    Path((id, path)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Response {
    let method = req.method().to_string();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap_or_default();

    let Some(conn) = state.registry.get(&id) else {
        // 离线 → 503 + 最后在线时间。
        let last_seen = state
            .store
            .get_node(&id)
            .unwrap_or(None)
            .map(|n| n.last_seen)
            .unwrap_or(0);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "node offline", "last_seen": last_seen})),
        )
            .into_response();
    };

    let fwd_headers: Vec<(String, String)> = ["content-type", "if-match"]
        .iter()
        .filter_map(|h| {
            headers
                .get(*h)
                .and_then(|v| v.to_str().ok())
                .map(|v| (h.to_string(), v.to_string()))
        })
        .collect();
    let mgmt_path = format!("/v0/management/{path}");
    match conn
        .api_request(&method, &mgmt_path, fwd_headers, body.to_vec(), PASSTHROUGH_TIMEOUT)
        .await
    {
        Ok((status, resp_headers, resp_body)) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            // 写操作记录审计。
            if method != "GET" && method != "HEAD" && method != "OPTIONS" {
                state.audit("panel", Some(&id), &method, &mgmt_path, &body, status.as_u16());
            }
            let mut resp = (status, resp_body).into_response();
            for (k, v) in resp_headers {
                if let (Ok(name), Ok(val)) = (
                    header::HeaderName::from_bytes(k.as_bytes()),
                    header::HeaderValue::from_str(&v),
                ) {
                    if name == header::CONTENT_TYPE || name.as_str().starts_with("x-rooster-") {
                        resp.headers_mut().insert(name, val);
                    }
                }
            }
            resp
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// 模板

async fn list_templates(State(state): State<Arc<HubState>>) -> Response {
    let templates: Vec<_> = state
        .store
        .list_templates()
        .unwrap_or_default()
        .into_iter()
        .map(|(id, t)| {
            json!({
                "id": id,
                "name": t.name,
                "selector": t.selector,
                "yaml": t.yaml,
                "updated_at": t.updated_at,
            })
        })
        .collect();
    Json(json!({"templates": templates})).into_response()
}

#[derive(Deserialize)]
struct TemplateBody {
    name: String,
    #[serde(default)]
    selector: BTreeMap<String, String>,
    yaml: String,
}

async fn put_template(
    State(state): State<Arc<HubState>>,
    Path(id): Path<String>,
    Json(body): Json<TemplateBody>,
) -> Response {
    if let Err(e) = validate_template_fragment(&body.yaml) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    let rec = crate::store::TemplateRecord {
        name: body.name,
        selector: body.selector,
        yaml: body.yaml,
        updated_at: now_secs(),
    };
    if let Err(e) = state.store.put_template(&id, &rec) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state.audit("panel", None, "PUT", &format!("/v0/templates/{id}"), rec.yaml.as_bytes(), 200);
    Json(json!({"ok": true})).into_response()
}

/// 模板只能包含可管理字段。
fn validate_template_fragment(yaml: &str) -> Result<(), String> {
    let v: serde_norway::Value =
        serde_norway::from_str(yaml).map_err(|e| format!("invalid yaml: {e}"))?;
    let allowed = ["plugins", "waf", "sites", "forwards", "allowlist", "wasm-plugins"];
    match v {
        serde_norway::Value::Null => Ok(()),
        serde_norway::Value::Mapping(m) => {
            for k in m.keys() {
                let key = k.as_str().unwrap_or_default();
                if !allowed.contains(&key) {
                    return Err(format!(
                        "field `{key}` is not allowed in a template (allowed: {allowed:?})"
                    ));
                }
            }
            Ok(())
        }
        _ => Err("template must be a mapping".to_string()),
    }
}

async fn delete_template(State(state): State<Arc<HubState>>, Path(id): Path<String>) -> Response {
    match state.store.delete_template(&id) {
        Ok(true) => {
            state.audit("panel", None, "DELETE", &format!("/v0/templates/{id}"), b"", 200);
            Json(json!({"ok": true})).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct SelectorBody {
    #[serde(default)]
    selector: Option<BTreeMap<String, String>>,
}

async fn preview_template(
    State(state): State<Arc<HubState>>,
    Path(id): Path<String>,
    body: Option<Json<SelectorBody>>,
) -> Response {
    let Some(tpl) = state.store.get_template(&id).unwrap_or(None) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "template not found"}))).into_response();
    };
    let selector = body.and_then(|Json(b)| b.selector).unwrap_or(tpl.selector.clone());
    let nodes = match state.store.select_nodes(&selector) {
        Ok(n) => n,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    };
    let mut results = Vec::new();
    for n in nodes {
        let Some(conn) = state.registry.get(&n.id) else {
            results.push(json!({
                "node_id": n.id,
                "status": "offline",
                "diff": "",
            }));
            continue;
        };
        let rendered = match rollout::render_template(&tpl.yaml, &n) {
            Ok(r) => r,
            Err(e) => {
                results.push(json!({"node_id": n.id, "status": "render-error", "diff": e}));
                continue;
            }
        };
        let current = match conn
            .api_request("GET", "/v0/management/config", vec![], vec![], PASSTHROUGH_TIMEOUT)
            .await
        {
            Ok((200, _, body)) => {
                serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("raw").and_then(|r| r.as_str()).map(str::to_string))
            }
            _ => None,
        };
        let Some(current) = current else {
            results.push(json!({"node_id": n.id, "status": "error", "diff": "cannot read node config"}));
            continue;
        };
        let new_raw = match rollout::replace_managed(&current, &rendered) {
            Ok(r) => r,
            Err(e) => {
                results.push(json!({"node_id": n.id, "status": "error", "diff": e}));
                continue;
            }
        };
        let diff = crate::diff::unified(&current, &new_raw);
        let status = if diff.is_empty() { "no-change" } else { "online" };
        results.push(json!({"node_id": n.id, "status": status, "diff": diff}));
    }
    Json(json!({"nodes": results})).into_response()
}

#[derive(Deserialize)]
struct RolloutBody {
    #[serde(default)]
    selector: Option<BTreeMap<String, String>>,
    #[serde(default)]
    concurrency: Option<usize>,
    #[serde(default)]
    auto_confirm_delay_secs: Option<u64>,
}

async fn rollout_template(
    State(state): State<Arc<HubState>>,
    Path(id): Path<String>,
    body: Option<Json<RolloutBody>>,
) -> Response {
    let Some(tpl) = state.store.get_template(&id).unwrap_or(None) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "template not found"}))).into_response();
    };
    let Json(body) = body.unwrap_or_default();
    let selector = body.selector.unwrap_or(tpl.selector.clone());
    let run_id = new_run_id("t");
    rollout::spawn_template_rollout(
        state.clone(),
        run_id.clone(),
        id.clone(),
        selector,
        body.concurrency.unwrap_or(3),
        body.auto_confirm_delay_secs.unwrap_or(state.cfg.auto_confirm_delay_secs),
    );
    state.audit("panel", None, "POST", &format!("/v0/templates/{id}/rollout"), b"", 200);
    Json(json!({"run_id": run_id})).into_response()
}

impl Default for RolloutBody {
    fn default() -> Self {
        Self {
            selector: None,
            concurrency: None,
            auto_confirm_delay_secs: None,
        }
    }
}

async fn list_rollouts(State(state): State<Arc<HubState>>) -> Response {
    let runs: Vec<_> = state
        .store
        .list_rollouts(50)
        .unwrap_or_default()
        .into_iter()
        .map(|(id, r)| {
            json!({
                "id": id,
                "kind": r.kind,
                "template_id": r.template_id,
                "version": r.version,
                "started_at": r.started_at,
                "status": r.status,
                "results": r.results,
            })
        })
        .collect();
    Json(json!({"runs": runs})).into_response()
}

async fn get_rollout(State(state): State<Arc<HubState>>, Path(id): Path<String>) -> Response {
    match state.store.get_rollout(&id).unwrap_or(None) {
        Some(r) => Json(json!({
            "id": id,
            "kind": r.kind,
            "template_id": r.template_id,
            "version": r.version,
            "started_at": r.started_at,
            "status": r.status,
            "results": r.results,
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// 全局封禁(FR-B)

async fn list_global_bans(State(state): State<Arc<HubState>>) -> Response {
    let bans: Vec<_> = state
        .store
        .list_global_bans()
        .unwrap_or_default()
        .into_iter()
        .map(|b| {
            json!({
                "ip": b.ip,
                "reason": b.reason,
                "source_node": b.source_node,
                "created": b.created,
                "expires_at": b.expires_at(),
                "ttl_secs": b.ttl_secs,
            })
        })
        .collect();
    Json(json!({"bans": bans})).into_response()
}

#[derive(Deserialize)]
struct GlobalBanBody {
    ip: String,
    #[serde(default = "default_ban_ttl")]
    ttl_secs: u64,
    #[serde(default)]
    reason: String,
}

fn default_ban_ttl() -> u64 {
    3600
}

async fn post_global_ban(
    State(state): State<Arc<HubState>>,
    Json(body): Json<GlobalBanBody>,
) -> Response {
    let ip = body.ip.trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": format!("invalid ip `{ip}`")})),
        )
            .into_response();
    }
    let rec = crate::store::GlobalBanRecord {
        reason: if body.reason.is_empty() { "manual".into() } else { body.reason },
        source_node: "panel".into(),
        created: now_secs(),
        ttl_secs: body.ttl_secs,
        ip: ip.clone(),
    };
    if let Err(e) = state.store.put_global_ban(&rec) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state
        .policy
        .lock()
        .unwrap()
        .note_manual(&ip, body.ttl_secs);
    rollout::broadcast_global_ban(&state, &rec);
    state.audit("panel", None, "POST", "/v0/global-bans", rec.ip.as_bytes(), 200);
    Json(json!({"ok": true})).into_response()
}

async fn delete_global_ban(State(state): State<Arc<HubState>>, Path(ip): Path<String>) -> Response {
    let removed = state.store.remove_global_ban(&ip).unwrap_or(false);
    if removed {
        state.registry.broadcast(rooster_proto::Frame::GlobalUnban { ip: ip.clone() });
        state.audit("panel", None, "DELETE", &format!("/v0/global-bans/{ip}"), b"", 200);
        Json(json!({"ok": true})).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "not banned"}))).into_response()
    }
}

async fn get_policies(State(state): State<Arc<HubState>>) -> Response {
    let policies: Vec<_> = state.effective_policies().iter().map(policy_to_json).collect();
    Json(json!({"policies": policies})).into_response()
}

fn policy_to_json(p: &crate::config::PolicyConfig) -> serde_json::Value {
    json!({
        "id": p.id,
        "match": {
            "plugin": p.r#match.plugin,
            "event": p.r#match.event,
            "severity": p.r#match.severity,
        },
        "min_nodes": p.min_nodes,
        "threshold": p.threshold,
        "window_secs": p.window.map(|w| w.as_secs()),
        "ttl_secs": p.ttl.as_secs(),
    })
}

fn policy_from_json(v: &serde_json::Value) -> Result<crate::config::PolicyConfig, String> {
    let hum = |field: &str| -> Result<std::time::Duration, String> {
        v.get(field)
            .and_then(|x| x.as_u64())
            .map(std::time::Duration::from_secs)
            .ok_or_else(|| format!("missing `{field}`"))
    };
    Ok(crate::config::PolicyConfig {
        id: v.get("id").and_then(|x| x.as_str()).ok_or("missing `id`")?.to_string(),
        r#match: crate::config::PolicyMatch {
            plugin: v.pointer("/match/plugin").and_then(|x| x.as_str()).ok_or("missing `match.plugin`")?.to_string(),
            event: v.pointer("/match/event").and_then(|x| x.as_str()).ok_or("missing `match.event`")?.to_string(),
            severity: v.pointer("/match/severity").and_then(|x| x.as_str()).map(str::to_string),
        },
        min_nodes: v.get("min_nodes").and_then(|x| x.as_u64()).map(|x| x as u32),
        threshold: v.get("threshold").and_then(|x| x.as_u64()).map(|x| x as u32),
        window: v.get("window_secs").and_then(|x| x.as_u64()).map(std::time::Duration::from_secs),
        ttl: hum("ttl_secs")?,
    })
}

#[derive(Deserialize)]
struct PoliciesBody {
    policies: Vec<serde_json::Value>,
}

async fn put_policies(State(state): State<Arc<HubState>>, Json(body): Json<PoliciesBody>) -> Response {
    let mut parsed = Vec::new();
    for p in &body.policies {
        match policy_from_json(p) {
            Ok(cfg) => parsed.push(cfg),
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({"error": format!("invalid policy: {e}")})),
                )
                    .into_response()
            }
        }
    }
    for p in &parsed {
        if p.id.is_empty() || p.ttl.is_zero() {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": "policy needs id and non-zero ttl"})),
            )
                .into_response();
        }
    }
    if let Err(e) = state.store.put_policies(&parsed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state.audit("panel", None, "PUT", "/v0/global-ban-policies", b"policies", 200);
    Json(json!({"ok": true})).into_response()
}

// ---------------------------------------------------------------------------
// 事件 / 审计 / 总览

#[derive(Deserialize)]
struct EventsQuery {
    node: Option<String>,
    plugin: Option<String>,
    ip: Option<String>,
    rule_id: Option<String>,
    since: Option<u64>,
    until: Option<u64>,
    limit: Option<usize>,
}

/// 跨节点事件查询:实时 fan-out 到在线节点聚合。
async fn query_events(
    State(state): State<Arc<HubState>>,
    Query(q): Query<EventsQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(200).min(1000);
    let online = state.registry.online_ids();
    let targets: Vec<String> = match &q.node {
        Some(n) => vec![n.clone()],
        None => online,
    };
    let mut events = Vec::new();
    let mut offline = Vec::new();
    for node_id in targets {
        let Some(conn) = state.registry.get(&node_id) else {
            offline.push(node_id);
            continue;
        };
        let Ok((200, _, body)) = conn
            .api_request("GET", "/v0/management/events", vec![], vec![], PASSTHROUGH_TIMEOUT)
            .await
        else {
            offline.push(node_id);
            continue;
        };
        let Ok(list) = serde_json::from_slice::<Vec<serde_json::Value>>(&body) else {
            continue;
        };
        for e in list {
            let Some(ev) = e.get("event") else { continue };
            let matches = |v: &str, field: &str| {
                q_fields(ev, field).map(|f| f == v).unwrap_or(false)
            };
            if let Some(p) = &q.plugin {
                if !matches(p, "plugin") {
                    continue;
                }
            }
            if let Some(ip) = &q.ip {
                if !matches(ip, "ip") {
                    continue;
                }
            }
            if let Some(rid) = &q.rule_id {
                if !matches(rid, "rule_id") {
                    continue;
                }
            }
            let ts = e.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
            if let Some(s) = q.since {
                if ts < s {
                    continue;
                }
            }
            if let Some(u) = q.until {
                if ts > u {
                    continue;
                }
            }
            events.push(json!({"node_id": node_id, "ts": ts, "event": ev}));
        }
    }
    events.sort_by(|a, b| b["ts"].as_u64().cmp(&a["ts"].as_u64()));
    events.truncate(limit);
    Json(json!({"events": events, "offline_nodes": offline})).into_response()
}

fn q_fields(ev: &serde_json::Value, field: &str) -> Option<String> {
    ev.get(field).and_then(|v| {
        v.as_str()
            .map(str::to_string)
            .or_else(|| v.as_u64().map(|n| n.to_string()))
    })
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn query_audit(State(state): State<Arc<HubState>>, Query(q): Query<AuditQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).min(1000);
    let offset = q.offset.unwrap_or(0);
    let mut entries = state.store.list_audit(limit + offset).unwrap_or_default();
    entries.drain(..offset.min(entries.len()));
    entries.truncate(limit);
    let list: Vec<AuditEntry> = entries;
    Json(json!({"entries": list})).into_response()
}

async fn overview(State(state): State<Arc<HubState>>) -> Response {
    let nodes = state.store.list_nodes().unwrap_or_default();
    let nodes_total = nodes.iter().filter(|n| !n.revoked).count();
    let nodes_online = nodes.iter().filter(|n| state.registry.is_online(&n.id)).count();
    let global_bans = state.store.list_global_bans().unwrap_or_default().len();

    // 从近期事件环聚合 24h 数据(总览)。cutoff 对齐整点,使 trend_24h 桶标签为整点时刻。
    let cutoff = (now_secs() / 3600 * 3600).saturating_sub(24 * 3600);
    let mut bans_24h = 0u64;
    let mut ips: BTreeMap<String, u64> = BTreeMap::new();
    let mut rules: BTreeMap<String, u64> = BTreeMap::new();
    let mut trend = vec![0u64; 24];
    for r in state.recent.lock().unwrap().iter() {
        if r.ts < cutoff {
            continue;
        }
        match &r.event {
            rooster_proto::Event::Ban { ip, .. } => {
                bans_24h += 1;
                *ips.entry(ip.clone()).or_default() += 1;
                let bucket = ((r.ts - cutoff) / 3600) as usize;
                if bucket < 24 {
                    trend[bucket] += 1;
                }
            }
            rooster_proto::Event::Block { ip, rule_id, .. } => {
                *ips.entry(ip.clone()).or_default() += 1;
                *rules.entry(rule_id.clone()).or_default() += 1;
                let bucket = ((r.ts - cutoff) / 3600) as usize;
                if bucket < 24 {
                    trend[bucket] += 1;
                }
            }
            _ => {}
        }
    }
    let top = |m: BTreeMap<String, u64>| {
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.into_iter().take(10).collect::<Vec<_>>()
    };
    let trend_24h: Vec<_> = (0..24usize)
        .map(|h| json!({"hour": cutoff + (h as u64) * 3600, "count": trend[h]}))
        .collect();
    Json(json!({
        "nodes_total": nodes_total,
        "nodes_online": nodes_online,
        "global_bans": global_bans,
        "bans_24h": bans_24h,
        "top_attack_ips": top(ips).into_iter().map(|(ip, count)| json!({"ip": ip, "count": count})).collect::<Vec<_>>(),
        "top_rules": top(rules).into_iter().map(|(rule_id, count)| json!({"rule_id": rule_id, "count": count})).collect::<Vec<_>>(),
        "top_countries": [],
        "trend_24h": trend_24h,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// 升级

async fn list_upgrades(State(state): State<Arc<HubState>>) -> Response {
    let upgrades: Vec<_> = state
        .store
        .list_upgrades()
        .unwrap_or_default()
        .into_iter()
        .map(|(version, u)| {
            json!({"version": version, "size": u.size, "uploaded_at": u.uploaded_at})
        })
        .collect();
    Json(json!({"upgrades": upgrades})).into_response()
}

async fn post_upgrade(
    State(state): State<Arc<HubState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let version = headers
        .get("x-rooster-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let sig_b64 = headers
        .get("x-rooster-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if version.is_empty()
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "missing or invalid x-rooster-version"})),
        )
            .into_response();
    }
    if let Err(e) = verify_upgrade_signature(&state, &body, &sig_b64) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": format!("signature verification failed: {e}")})),
        )
            .into_response();
    }
    if let Err(e) = state.store.put_upgrade(&version, body.to_vec(), &sig_b64) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state.audit("panel", None, "POST", "/v0/upgrades", version.as_bytes(), 200);
    Json(json!({"ok": true, "version": version})).into_response()
}

/// Ed25519 签名校验:公钥来自 hub 配置 `ed25519:<base64>`。
fn verify_upgrade_signature(state: &Arc<HubState>, content: &[u8], sig_b64: &str) -> Result<(), String> {
    use base64::Engine;
    let pk = state
        .cfg
        .upgrade_public_key
        .as_deref()
        .and_then(|s| s.strip_prefix("ed25519:"))
        .ok_or("upgrade-public-key not configured")?;
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pk)
        .map_err(|e| format!("bad public key: {e}"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("bad signature encoding: {e}"))?;
    use ed25519_dalek::Verifier;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        pk.as_slice().try_into().map_err(|_| "bad public key length")?,
    )
    .map_err(|e| format!("bad public key: {e}"))?;
    let sig: ed25519_dalek::Signature =
        sig.as_slice().try_into().map_err(|_| "bad signature length")?;
    vk.verify(content, &sig).map_err(|e| e.to_string())
}

#[derive(Deserialize, Default)]
struct UpgradeRolloutBody {
    #[serde(default)]
    selector: BTreeMap<String, String>,
    #[serde(default)]
    batch_size: Option<usize>,
    #[serde(default)]
    wait_secs: Option<u64>,
}

async fn rollout_upgrade(
    State(state): State<Arc<HubState>>,
    Path(version): Path<String>,
    body: Option<Json<UpgradeRolloutBody>>,
) -> Response {
    if state.store.get_upgrade(&version).unwrap_or(None).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "upgrade version not uploaded"})),
        )
            .into_response();
    }
    let body = match body {
        Some(Json(b)) => b,
        None => Default::default(),
    };
    let run_id = new_run_id("u");
    rollout::spawn_upgrade_rollout(
        state.clone(),
        run_id.clone(),
        version.clone(),
        body.selector,
        body.batch_size.unwrap_or(1),
        body.wait_secs.unwrap_or(300),
    );
    state.audit("panel", None, "POST", &format!("/v0/upgrades/{version}/rollout"), b"", 200);
    Json(json!({"run_id": run_id})).into_response()
}

// ---------------------------------------------------------------------------
// 下载(升级包 / sig / wasm):Bearer 会话或 HMAC 签名 URL
// 大正文可按 Accept-Encoding 走 gzip:签名与入库字节仍是原文,压缩只在传输层。

async fn download(
    State(state): State<Arc<HubState>>,
    Extension(meta): Extension<ConnMeta>,
    Path(rest): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    // 鉴权:会话 token、签名 URL、匿名引导制品,或 mTLS 节点身份
    // (hub→agent 的 wasm/升级包分发,Agent 侧只有证书没有面板会话)。
    let authed = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| state.store.validate_session(t).unwrap_or(false))
        .unwrap_or(false);
    let signed = match (params.get("exp"), params.get("sig")) {
        (Some(e), Some(s)) => state
            .verify_download_url(&format!("/v0/downloads/{rest}"), e.parse().unwrap_or(0), s),
        _ => false,
    };
    let node_tls = match meta.cert_fp.as_deref() {
        // 与 /agent/ws 认证同一套指纹规则(见 ws::cert_fp_is_live_node):
        // 下载侧没有 node_id,按指纹反查存活节点。
        Some(fp) => crate::ws::cert_fp_is_live_node(&state, fp).is_ok(),
        // 明文开发模式的等价放宽:仅回环对端(ws 的 None-fp 放行同款语义)。
        None => state.cfg.tls_mode_str() == "none" && meta.peer.ip().is_loopback(),
    };
    if !authed && !signed && !is_bootstrap_artifact(&rest) && !node_tls {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing session, valid signature or node identity"})),
        )
            .into_response();
    }
    let gzip = crate::compress::accepts_gzip(&headers);

    if let Some(name) = rest.strip_prefix("wasm/") {
        return match state.store.get_wasm(name) {
            Ok(Some(bytes)) => crate::compress::encode(bytes, "application/wasm", gzip).await,
            _ => (StatusCode::NOT_FOUND, "not found").into_response(),
        };
    }

    // 引导名解析:`rooster-<arch>` 可以是直接的入库名,也可以按
    // `rooster-<ver>-<arch>` 命名命中该架构最新的已签名发布包——面板下发的
    // 一行安装命令不知道也不该知道版本号。
    let lookup = resolve_bootstrap(&state.store, &rest)
        .unwrap_or_else(|| rest.strip_suffix(".sig").unwrap_or(&rest).to_string());

    if let Some(_version) = rest.strip_suffix(".sig") {
        return match state.store.get_upgrade_sig(&lookup) {
            // 引导包的 `.sig` 以裸 64 字节签名提供:openssl 对 Ed25519 的
            // `pkeyutl -verify -rawin` 直接吃裸签名(install.sh 就是这么用,
            // `dgst` 对 Ed25519 有 16MiB 单次输入限制);其余调用方拿到的
            // 仍是入库时的 base64 原文。
            Ok(Some(sig)) if is_bootstrap_artifact(&rest) => match bootstrap_sig_bytes(&sig) {
                Some(raw) => (
                    StatusCode::OK,
                    [(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/octet-stream"),
                    )],
                    raw,
                )
                    .into_response(),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "stored signature is not a raw ed25519 signature",
                )
                    .into_response(),
            },
            Ok(Some(sig)) => (StatusCode::OK, sig).into_response(),
            _ => (StatusCode::NOT_FOUND, "not found").into_response(),
        };
    }
    match state.store.get_upgrade(&lookup) {
        Ok(Some(bytes)) => crate::compress::encode(bytes, "application/octet-stream", gzip).await,
        // 同架构兜底:hub 自身的可执行文件(未签名,需 --allow-unsigned)。
        Ok(None) if lookup == "rooster" => match hub_self_binary() {
            Some(bytes) => crate::compress::encode(bytes, "application/octet-stream", gzip).await,
            None => (StatusCode::NOT_FOUND, "hub executable not readable").into_response(),
        },
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// 引导制品:agent 安装二进制不是秘密(完整性由 install.sh 的签名校验
/// 保证),允许匿名下载;版本包与 WASM 仍需会话或签名 URL。
fn is_bootstrap_artifact(rest: &str) -> bool {
    let name = rest.strip_suffix(".sig").unwrap_or(rest);
    name == "rooster"
        || name.strip_prefix("rooster-").is_some_and(|a| {
            !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        })
}

fn hub_self_binary() -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    std::fs::read(&exe).ok()
}

/// 把引导请求路径解析成实际的入库 version key;非引导路径返回 None。
fn resolve_bootstrap(store: &crate::store::Store, rest: &str) -> Option<String> {
    if !is_bootstrap_artifact(rest) {
        return None;
    }
    let name = rest.strip_suffix(".sig").unwrap_or(rest);
    if store.get_upgrade(name).ok().flatten().is_some() {
        return Some(name.to_string());
    }
    let arch = name.strip_prefix("rooster-")?;
    // list_upgrades 已按上传时间倒序 → 取该架构最新的一个包。
    store
        .list_upgrades()
        .ok()?
        .into_iter()
        .map(|(v, _)| v)
        .find(|v| v.ends_with(&format!("-{arch}")))
}

/// 入库的 Ed25519 签名(base64)→ 裸 64 字节。openssl 3.x 对 Ed25519 用
/// `pkeyutl -verify -rawin` 直接吃裸签名,不做 DER 包裹。
fn bootstrap_sig_bytes(sig_b64: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .ok()?;
    (raw.len() == 64).then_some(raw)
}

/// 把配置里的 `ed25519:<base64>` 公钥包装成 SPKI PEM(install.sh 用)。
pub(crate) fn ed25519_spki_pem(pubkey_cfg: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(pubkey_cfg.trim().strip_prefix("ed25519:")?.trim())
        .ok()?;
    if raw.len() != 32 {
        return None;
    }
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 } OCTET STRING(32) }
    let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    der.extend_from_slice(&raw);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).ok()?);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Some(pem)
}

/// 服务器信任锚：私有 CA 场景下 Agent 拿不到它就验不过 hub 证书链
/// (rustls UnknownIssuer → 注册请求根本发不出去)。install.sh --insecure
/// 按 TOFU 抓一次并固定到本地 hub.ca,之后仍是完整链+SAN 校验。
async fn server_ca(State(state): State<Arc<HubState>>) -> Response {
    match state
        .cfg
        .tls
        .ca
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
    {
        Some(pem) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/x-pem-file"),
            )],
            pem,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "no tls.ca configured on this hub",
        )
            .into_response(),
    }
}

async fn pubkey_pem(State(state): State<Arc<HubState>>) -> Response {
    match state
        .cfg
        .upgrade_public_key
        .as_deref()
        .and_then(ed25519_spki_pem)
    {
        Some(pem) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/x-pem-file"),
            )],
            pem,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "no upgrade-public-key configured",
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// WASM 插件仓库

async fn list_wasm(State(state): State<Arc<HubState>>) -> Response {
    let plugins: Vec<_> = state
        .store
        .list_wasm()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, m)| json!({"name": name, "size": m.size, "uploaded_at": m.uploaded_at}))
        .collect();
    Json(json!({"plugins": plugins})).into_response()
}

async fn post_wasm(State(state): State<Arc<HubState>>, headers: HeaderMap, body: Bytes) -> Response {
    let name = headers
        .get("x-rooster-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "missing or invalid x-rooster-name"})),
        )
            .into_response();
    }
    if body.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "empty plugin"})),
        )
            .into_response();
    }
    if let Err(e) = state.store.put_wasm(&name, body.to_vec()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }
    state.audit("panel", None, "POST", "/v0/wasm-plugins", name.as_bytes(), 200);
    Json(json!({"ok": true, "name": name, "size": body.len()})).into_response()
}

async fn delete_wasm(State(state): State<Arc<HubState>>, Path(name): Path<String>) -> Response {
    match state.store.delete_wasm(&name) {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// install.sh 与静态面板

fn ca_fingerprint(path: &std::path::Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let pem = std::fs::read(path).map_err(|e| format!("read server CA: {e}"))?;
    let cert = rustls_pemfile::certs(&mut pem.as_slice()).next()
        .ok_or("server CA has no certificate")?
        .map_err(|e| format!("parse server CA: {e}"))?;
    Ok(Sha256::digest(cert.as_ref()).iter().map(|b| format!("{b:02x}")).collect())
}

/// 注册/安装入口从请求取 Host:调用方用哪个地址访问 hub,agent 就拨哪个地址。
fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST).and_then(|v| v.to_str().ok())
}

async fn install_script(State(state): State<Arc<HubState>>, headers: HeaderMap) -> Response {
    let base = match state.cfg.hub_base(request_host(&headers)) {
        Ok(base) => base,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("text/x-shellscript"))],
        install::script(&base),
    )
        .into_response()
}

async fn static_handler(
    State(state): State<Arc<HubState>>,
    uri: axum::http::Uri,
) -> Response {
    if uri.path().starts_with("/v0") || uri.path().starts_with("/agent") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    crate::http::serve_panel(&state, uri.path()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_artifact_paths_are_anonymous_and_bounded() {
        assert!(is_bootstrap_artifact("rooster"));
        assert!(is_bootstrap_artifact("rooster-x86_64"));
        assert!(is_bootstrap_artifact("rooster-0.1.0-aarch64.sig"));
        assert!(!is_bootstrap_artifact("rooster-"));
        assert!(!is_bootstrap_artifact("0.1.0"));
        assert!(!is_bootstrap_artifact("wasm/header_check.wasm"));
        assert!(!is_bootstrap_artifact("rooster-../../etc/passwd"));
    }

    /// run_id 是 redb key:同一秒内触发的两次下发不得撞 key(否则两个
    /// 后台任务会互相读改写同一条记录)。
    #[test]
    fn run_ids_are_unique_within_the_same_second() {
        let ids: Vec<String> = (0..128).map(|_| new_run_id("t")).collect();
        let mut uniq = std::collections::HashSet::new();
        for id in &ids {
            assert!(id.starts_with('t'), "run_id: {id}");
            assert!(
                id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "run_id charset: {id}"
            );
            uniq.insert(id.clone());
        }
        assert_eq!(uniq.len(), ids.len(), "same-second run ids must be pairwise distinct");
        assert!(new_run_id("u").starts_with('u'));
    }

    #[test]
    fn cors_merges_vary_instead_of_overwriting_it() {
        let mut h = header::HeaderMap::new();
        h.insert(header::VARY, header::HeaderValue::from_static("Accept-Encoding"));
        apply_cors(&mut h, Some("https://panel.example"));
        let tokens: Vec<String> = h
            .get(header::VARY)
            .unwrap()
            .to_str()
            .unwrap()
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .collect();
        assert!(tokens.iter().any(|t| t == "origin"), "Vary: {:?}", tokens);
        assert!(tokens.iter().any(|t| t == "accept-encoding"), "Vary: {:?}", tokens);
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://panel.example"
        );

        // 无既有 Vary → 只写 origin;已有 origin → 不重复追加。
        let mut h = header::HeaderMap::new();
        apply_cors(&mut h, None);
        assert_eq!(h.get(header::VARY).unwrap(), "origin");
        let mut h = header::HeaderMap::new();
        h.insert(header::VARY, header::HeaderValue::from_static("origin"));
        apply_cors(&mut h, None);
        assert_eq!(h.get(header::VARY).unwrap(), "origin");
    }

    #[test]
    fn spki_pem_and_raw_signature_follow_openssl_layout() {
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let vk = sk.verifying_key();
        let b64 = base64::engine::general_purpose::STANDARD;

        let pem = ed25519_spki_pem(&format!("ed25519:{}", b64.encode(vk.to_bytes()))).unwrap();
        let der = b64
            .decode(
                pem.lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let expect = [
            &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00][..],
            &vk.to_bytes()[..],
        ]
        .concat();
        assert_eq!(der, expect, "SPKI 必须是 openssl 可识别的 Ed25519 结构");
        assert!(ed25519_spki_pem("ed25519:short").is_none());

        let raw = sk.sign(b"rooster").to_bytes();
        assert_eq!(bootstrap_sig_bytes(&b64.encode(raw)).unwrap(), raw.to_vec());
        assert!(bootstrap_sig_bytes("not-base64!").is_none());
        assert!(bootstrap_sig_bytes(&b64.encode(&raw[..63])).is_none());
    }
}
