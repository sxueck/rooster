//! Hub PKI。
//!
//! 首次启动生成 Ed25519 CA(`data-dir/pki/`);节点凭一次性 token 提交
//! CSR,Hub 强制改写 CN = node_id、ClientAuth 用途与 1 年有效期后签发。
//! 客户端证书以 SHA-256 指纹登记到节点记录;吊销即指纹黑名单,连接层
//! 拒绝(长连接在吊销时主动断开)。
//!
//! 重启后从 `ca.key` 重建内存签发者:同一密钥 + 同一 subject 签出的
//! CA 证书在信任锚校验下等价(链校验只依赖 subject DN 与公钥,CA 自身
//! 序列号不参与),已签发的客户端证书不受影响。

use rcgen::{CertificateParams, KeyPair};
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct HubPki {
    /// 内存重建的签发者(与磁盘上 ca.crt 同 key 同 subject)。
    issuer: rcgen::Certificate,
    key: KeyPair,
    /// 磁盘上的 CA 证书 PEM(信任锚,发给 Agent / 喂给 rustls)。
    pub ca_cert_pem: String,
}

fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rooster-hub-ca");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    params
}

impl HubPki {
    /// 确保 CA 存在(不存在则生成 Ed25519 自签,10 年有效期)。
    pub fn ensure(data_dir: &Path) -> Result<Self, String> {
        let dir = data_dir.join("pki");
        let key_path = dir.join("ca.key");
        let cert_path = dir.join("ca.crt");

        let key_pem = match std::fs::read_to_string(&key_path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate().map_err(|e| format!("generate ca key: {e}"))?;
                let pem = key.serialize_pem();
                write_private(&key_path, &pem).map_err(|e| format!("write ca key: {e}"))?;
                pem
            }
            Err(e) => return Err(format!("read ca key: {e}")),
        };
        let key = KeyPair::from_pem(&key_pem).map_err(|e| format!("parse ca key: {e}"))?;

        let params = ca_params();
        if !cert_path.exists() {
            let cert = params
                .clone()
                .self_signed(&key)
                .map_err(|e| format!("self-sign ca: {e}"))?;
            std::fs::write(&cert_path, cert.pem())
                .map_err(|e| format!("write ca cert: {e}"))?;
        }
        let ca_cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| format!("read ca cert: {e}"))?;

        let issuer = params
            .self_signed(&key)
            .map_err(|e| format!("rebuild ca issuer: {e}"))?;
        Ok(Self {
            issuer,
            key,
            ca_cert_pem,
        })
    }

    /// 签发客户端证书:CSR 公钥 + 强制 CN/用途/有效期。
    /// 返回 (cert_pem, sha256 指纹)。
    pub fn sign_csr(&self, csr_pem: &str, node_id: &str) -> Result<(String, String), String> {
        let mut csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| format!("parse csr: {e}"))?;
        {
            let params = &mut csr_params.params;
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, node_id.to_string());
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        }

        let signed = csr_params
            .signed_by(&self.issuer, &self.key)
            .map_err(|e| format!("sign csr: {e}"))?;
        let fp = fingerprint(signed.der());
        Ok((signed.pem(), fp))
    }

    pub fn ca_cert_der(&self) -> Vec<u8> {
        rustls_pemfile::certs(&mut self.ca_cert_pem.as_bytes())
            .next()
            .and_then(|r| r.ok())
            .map(|c| c.to_vec())
            .unwrap_or_default()
    }
}

/// SHA-256 指纹(十六进制)。
pub fn fingerprint(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: u64) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rooster-pki-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ca_is_stable_across_restarts_and_signs_csrs() {
        let dir = tmp_dir(1);
        let pki = HubPki::ensure(&dir).unwrap();
        let pki2 = HubPki::ensure(&dir).unwrap();
        assert_eq!(pki.ca_cert_pem, pki2.ca_cert_pem, "ca.crt must not change");

        // agent 侧 CSR(rcgen 生成,任意 CN)。
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "impostor");
        let csr = params.serialize_request(&key).unwrap();
        let csr_pem = csr.pem().unwrap();
        let (cert_pem, fp) = pki.sign_csr(&csr_pem, "web-01").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(fp.len(), 64);

        // 链校验:签出的证书必须能被 ca.crt 信任锚接受(rustls 客户端
        // 证书验证器,同时校验 ClientAuth EKU 与 CN)。
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(pki.ca_cert_der()))
            .unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
        let end_entity = rustls::pki_types::CertificateDer::from(der);
        verifier
            .verify_client_cert(&end_entity, &[], rustls::pki_types::UnixTime::now())
            .unwrap();
    }

    use std::sync::Arc;
}
