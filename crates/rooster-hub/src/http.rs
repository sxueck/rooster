//! HTTP/WSS 服务引导:单端口同时承载 REST、/agent/ws(mTLS)与面板
//! 静态文件;TLS static 模式下客户端证书可选提供,指纹经连接级
//! extension 注入请求(由 /agent/ws 校验)。

use crate::HubState;
use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

/// 一条连接的元信息(随 extension 注入每个请求)。
#[derive(Clone, Debug)]
pub struct ConnMeta {
    pub peer: SocketAddr,
    /// 对端客户端证书 SHA-256 指纹;明文模式或未提供证书时为 None。
    pub cert_fp: Option<String>,
}

/// 把 ConnMeta 注入请求后转交 axum Router。
#[derive(Clone)]
struct ConnService {
    meta: ConnMeta,
    router: Router,
}

impl hyper::service::Service<Request<Incoming>> for ConnService {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                + Send,
        >,
    >;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        req.extensions_mut().insert(self.meta.clone());
        // ConnectInfo 与 into_make_service_with_connect_info 语义一致,
        // login / register-token 等处理器依赖。
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(self.meta.peer));
        use tower::Service as _;
        let fut = self.router.clone().call(req);
        Box::pin(std::future::IntoFuture::into_future(fut))
    }
}

pub async fn serve(state: Arc<HubState>, addr: SocketAddr) -> std::io::Result<()> {
    let router = crate::api::router(state.clone());
    let listener = TcpListener::bind(addr).await?;
    match state.cfg.tls_mode() {
        crate::config::HubTlsMode::None => {
            tracing::warn!("tls mode none: plain http/ws listener (dev/intranet only)");
            loop {
                let (stream, peer) = listener.accept().await?;
                let router = router.clone();
                tokio::spawn(async move {
                    let meta = ConnMeta { peer, cert_fp: None };
                    let svc = ConnService { meta, router };
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }
        crate::config::HubTlsMode::Static => {
            let tls = build_tls(&state).await?;
            let acceptor = tokio_rustls::TlsAcceptor::from(tls);
            loop {
                let (stream, peer) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let cert_fp = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .map(|c| crate::pki::fingerprint(c.as_ref()));
                    let meta = ConnMeta { peer, cert_fp };
                    let svc = ConnService { meta, router };
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                        .await;
                });
            }
        }
    }
}

/// 服务端 TLS:面板证书(cert/key)+ 可选客户端证书验证(证书必须
/// 链到本 Hub CA;未提供证书的连接由路由层区分对待)。
async fn build_tls(state: &Arc<HubState>) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let cfg = &state.cfg;
    let (cert_path, key_path) = (cfg.tls.cert.clone(), cfg.tls.key.clone());
    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(c), Some(k)) => (c, k),
        _ => {
            return Err(std::io::Error::other(
                "tls.mode=static requires tls.cert and tls.key",
            ))
        }
    };
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::fs::read(&cert_path)?.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| std::io::Error::other(format!("parse cert: {e}")))?;
    let key = rustls_pemfile::private_key(&mut std::fs::read(&key_path)?.as_slice())
        .map_err(|e| std::io::Error::other(format!("parse key: {e}")))?
        .ok_or_else(|| std::io::Error::other("no private key found"))?;

    let mut roots = rustls::RootCertStore::empty();
    if let Err(e) = roots.add(rustls::pki_types::CertificateDer::from(state.pki.ca_cert_der())) {
        tracing::warn!("cannot add own ca to client trust store: {e}");
    }
    let verifier = OptionalClientAuth(
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| std::io::Error::other(format!("client verifier: {e}")))?,
    );
    // 可选 mTLS:面板 REST 走会话 token,/agent/ws 才要求客户端证书。
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::other(format!("tls config: {e}")))?;
    Ok(Arc::new(tls))
}

/// 客户端证书可选:提供则必须有效(链到 Hub CA),不提供也放行
/// (是否需要证书由路由决定)。
#[derive(Debug)]
struct OptionalClientAuth(Arc<dyn rustls::server::danger::ClientCertVerifier>);

impl rustls::server::danger::ClientCertVerifier for OptionalClientAuth {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.0.verify_client_cert(end_entity, intermediates, now)
    }

    fn client_auth_mandatory(&self) -> bool {
        // 面板 REST 不带客户端证书;/agent/ws 在路由层自行要求。
        false
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// 面板静态文件(web/dist,纯静态)

/// 静态文件服务:命中文件返回内容,否则回退 index.html(SPA 路由)。
/// `/v0`、`/agent`、`/install.sh` 等已由 Router 优先匹配。
pub async fn serve_panel(state: &Arc<HubState>, path: &str) -> Response {
    let root = state.cfg.panel_dir.clone();
    if path.contains("..") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let rel = path.trim_start_matches('/');
    let candidate = if rel.is_empty() {
        root.join("index.html")
    } else {
        root.join(rel)
    };
    if let Some((bytes, ctype)) = read_file(&candidate) {
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, HeaderValue::from_static_or(ctype)),
                (header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300")),
            ],
            bytes,
        )
            .into_response();
    }
    // SPA 回退。
    match read_file(&root.join("index.html")) {
        Some((bytes, _)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],
            bytes,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            format!(
                "panel not built: {} missing (run `npm run build` in web/)",
                root.join("index.html").display()
            ),
        )
            .into_response(),
    }
}

fn read_file(path: &PathBuf) -> Option<(Vec<u8>, &'static str)> {
    if !path.is_file() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let ctype = match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    };
    Some((bytes, ctype))
}

trait FromStaticOr {
    fn from_static_or(s: &str) -> HeaderValue;
}

impl FromStaticOr for HeaderValue {
    fn from_static_or(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap_or(HeaderValue::from_static("application/octet-stream"))
    }
}

/// 空体 404 响应(http 工具)。
pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

// Body 用于静态响应。
#[allow(dead_code)]
fn _assert_body(b: Body) {
    let _ = b;
}
