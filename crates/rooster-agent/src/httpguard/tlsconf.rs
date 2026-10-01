//! rustls 配置构造。
//!
//! - 服务端:站点 `tls.cert` / `tls.key` PEM(rustls-pemfile 解析);
//!   未显式配置时由 `bans::ensure_httpguard` 从 ACME 缓存
//!   `<data_dir>/acme/<id>/{cert,key}.pem` 回填后再进来;
//!   ALPN 声明 `h2` + `http/1.1`;加载失败只记日志,握手被拒绝
//!   (调用方拿到 `None` 后直接断开该连接)。
//! - 客户端:上游 `https://` 时的出站 TLS。默认用 webpki 根证书集校验
//!   证书链与 hostname;`tls.skip-verify` 为 true 时才退回不校验
//!   (仅限自签内网上游,此时对端可冒充源站)。两种配置各缓存一份。

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use tokio_rustls::TlsAcceptor;

/// 从 PEM 文件构造服务端配置;文件缺失 / 解析失败返回 Err(调用方记日志)。
pub(crate) fn server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("bad cert/key pair: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::certs(&mut r)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs {}: {e}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::private_key(&mut r)
        .map_err(|e| format!("parse key {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key in {}", path.display()))
}

/// 构造 terminate 模式的握手 acceptor(None = 证书不可用,握手拒绝)。
pub(crate) fn acceptor(cfg: &Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(cfg.clone())
}

// ---------------------------------------------------------------------------
// 上游 https 客户端:默认校验,`skip-verify` 时不校验(见模块注释)。

#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// 上游 TLS 客户端配置。`skip_verify = false`(默认)走 webpki 根证书集
/// 并校验 hostname;`true` 时不校验——此时能劫持连接的对端可冒充源站。
pub(crate) fn upstream_client_config(skip_verify: bool) -> Arc<ClientConfig> {
    static VERIFYING: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    static SKIPPING: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    let cell = if skip_verify { &SKIPPING } else { &VERIFYING };
    cell.get_or_init(|| {
        let mut cfg = if skip_verify {
            tracing::warn!("upstream TLS certificate verification disabled for this site");
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}
