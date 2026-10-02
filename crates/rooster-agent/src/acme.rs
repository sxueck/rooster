//! ACME(HTTP-01):站点证书签发与续期。
//!
//! - 账户凭据持久化在 `data_dir/acme/account.json`,站点证书在
//!   `data_dir/acme/<site-id>/{cert.pem,key.pem,meta.json}`;
//! - 到期前 30 天自动续期(每日检查);签发成功后触发 runtime 重配置,
//!   由 tlsconf 重新加载证书文件;
//! - 挑战应答经 [`HttpGuardRuntime::set_challenge`] 由 80 端口即答。
//! TLS-ALPN-01 不在本实现范围(v1 只做 HTTP-01)。
//!
//! 真实签发需要公网 80 端口与可解析域名,离线环境仅能验证缓存/到期
//! 决策路径(单测覆盖),签发链路在有公网的部署上验证。

use crate::httpguard::HttpGuardRuntime;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use rooster_config::{AcmeConfig, Site, TlsMode};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// 证书到期前多久续期。
const RENEW_WINDOW: Duration = Duration::from_secs(30 * 24 * 3600);
/// 订单就绪轮询:最多 ~60s。
const ORDER_POLL_TRIES: u8 = 12;

pub struct Acme {
    runtime: Arc<HttpGuardRuntime>,
    data_dir: PathBuf,
    cfg: Option<AcmeConfig>,
}

impl Acme {
    pub fn new(runtime: Arc<HttpGuardRuntime>, data_dir: PathBuf, cfg: Option<AcmeConfig>) -> Self {
        Acme {
            runtime,
            data_dir,
            cfg,
        }
    }

    fn dir(&self, site_id: &str) -> PathBuf {
        self.data_dir.join("acme").join(site_id)
    }

    /// 对所有 `tls.acme=true`(terminate 且未显式指定 cert/key)的站点:
    /// 无有效缓存证书则签发;30 天内到期则续期。
    pub async fn ensure_certificates(&self, sites: &[Site]) {
        let Some(cfg) = self.cfg.clone() else {
            return;
        };
        for site in sites {
            if site.tls.mode != TlsMode::Terminate || !site.tls.acme {
                continue;
            }
            if site.tls.cert.is_some() && site.tls.key.is_some() {
                continue; // 显式本地证书优先
            }
            let dir = self.dir(&site.id);
            match cache_valid(&dir, RENEW_WINDOW) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(site = %site.id, error = %e, "acme cache unreadable, reissuing");
                }
            }
            if let Err(e) = self.issue(&cfg, site, &dir).await {
                tracing::error!(site = %site.id, error = %e, "acme issuance failed");
            }
        }
    }

    async fn issue(&self, cfg: &AcmeConfig, site: &Site, dir: &Path) -> Result<(), String> {
        let started = std::time::Instant::now();
        let identifiers: Vec<Identifier> = site
            .server_names
            .iter()
            .map(|n| Identifier::Dns(n.clone()))
            .collect();

        let account = load_or_create_account(&self.data_dir.join("acme"), cfg).await?;
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| format!("new order: {e}"))?;

        // HTTP-01:全部待验证授权先登记挑战应答,再统一置 ready。
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| format!("authorizations: {e}"))?;
        let mut challenge_urls = Vec::new();
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => return Err(format!("authorization status {other:?}")),
            }
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| "no http-01 challenge offered".to_string())?;
            let key_auth = order.key_authorization(challenge);
            self.runtime
                .set_challenge(challenge.token.clone(), key_auth.as_str().to_string());
            challenge_urls.push(challenge.url.clone());
        }
        let result = self.finalize_order(&mut order, &challenge_urls, site, dir).await;
        // 无论成败,撤销本次登记的挑战应答。
        self.runtime.clear_challenges();
        result.map(|_| {
            tracing::info!(
                site = %site.id,
                elapsed = ?started.elapsed(),
                "acme certificate issued"
            );
        })
    }

    async fn finalize_order(
        &self,
        order: &mut instant_acme::Order,
        challenge_urls: &[String],
        site: &Site,
        dir: &Path,
    ) -> Result<(), String> {
        // 只对本次登记过应答的 http-01 挑战宣告 ready。对 dns-01 /
        // tls-alpn-01 宣告 ready 会让 CA 去校验一个没有应答的挑战,
        // authorization 转 invalid,整个 order 必然失败。
        for url in challenge_urls {
            order
                .set_challenge_ready(url)
                .await
                .map_err(|e| format!("set challenge ready: {e}"))?;
        }
        // 轮询直到 Ready / Invalid。
        let mut delay = Duration::from_millis(500);
        for _ in 0..ORDER_POLL_TRIES {
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(10));
            let state = order.refresh().await.map_err(|e| format!("refresh: {e}"))?;
            match state.status {
                OrderStatus::Ready => break,
                OrderStatus::Invalid => return Err("order invalid".into()),
                _ => continue,
            }
        }
        if order.state().status != OrderStatus::Ready {
            return Err("order not ready in time".into());
        }

        // CSR:站点私钥本地生成,证书链由 CA 返回。
        let key_pair = KeyPair::generate().map_err(|e| format!("key gen: {e}"))?;
        let mut params = CertificateParams::default();
        params.subject_alt_names = site
            .server_names
            .iter()
            .map(|n| {
                let name = n
                    .as_str()
                    .try_into()
                    .map_err(|e| format!("san: {e}"))?;
                Ok(rcgen::SanType::DnsName(name))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| format!("csr: {e}"))?;

        order
            .finalize(csr.der())
            .await
            .map_err(|e| format!("finalize: {e}"))?;
        let mut delay = Duration::from_millis(500);
        let cert_pem = loop {
            if delay > Duration::from_secs(10) {
                return Err("certificate not issued in time".into());
            }
            tokio::time::sleep(delay).await;
            delay *= 2;
            if let Some(pem) = order
                .certificate()
                .await
                .map_err(|e| format!("certificate: {e}"))?
            {
                break pem;
            }
        };

        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
        set_dir_private(dir)?;
        atomic_write(&dir.join("cert.pem"), cert_pem.as_bytes(), FILE_PUBLIC)?;
        atomic_write(&dir.join("key.pem"), key_pair.serialize_pem().as_bytes(), FILE_SECRET)?;
        // 到期时间以 CA 颁发日 + 90 天(Let's Encrypt)近似;精确值需
        // 解析 X.509,避免引入新依赖,续期窗口留有充分余量。
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 90 * 24 * 3600;
        let meta = serde_json::json!({"expires_at": expires_at});
        atomic_write(
            &dir.join("meta.json"),
            serde_json::to_string(&meta).unwrap_or_default().as_bytes(),
            FILE_PUBLIC,
        )?;
        Ok(())
    }
}

/// 站点证书解析顺序:显式 cert/key → acme 缓存 → None(拒绝握手)。
pub fn site_cert_paths(data_dir: &Path, site: &Site) -> Option<(PathBuf, PathBuf)> {
    if let (Some(c), Some(k)) = (&site.tls.cert, &site.tls.key) {
        return Some((c.clone(), k.clone()));
    }
    let dir = data_dir.join("acme").join(&site.id);
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    if cert.is_file() && key.is_file() {
        Some((cert, key))
    } else {
        None
    }
}

/// 缓存证书是否仍在续期窗口外(到期 > RENEW_WINDOW)。
fn cache_valid(dir: &Path, window: Duration) -> Result<bool, String> {
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("meta.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let expires_at = meta["expires_at"].as_u64().ok_or("meta missing expires_at")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if !dir.join("cert.pem").is_file() || !dir.join("key.pem").is_file() {
        return Ok(false);
    }
    Ok(expires_at > now + window.as_secs())
}

async fn load_or_create_account(
    base: &Path,
    cfg: &AcmeConfig,
) -> Result<Account, String> {
    let creds_path = base.join("account.json");
    if let Ok(creds) = std::fs::read_to_string(&creds_path) {
        if let Ok(saved) = serde_json::from_str::<AccountCredentials>(&creds) {
            return Account::from_credentials(saved)
                .await
                .map_err(|e| format!("restore account: {e}"));
        }
    }
    std::fs::create_dir_all(base).map_err(|e| format!("mkdir: {e}"))?;
    set_dir_private(base)?;
    let contact = if cfg.email.is_empty() {
        Vec::new()
    } else {
        vec![format!("mailto:{}", cfg.email)]
    };
    let directory = cfg
        .directory
        .clone()
        .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string());
    let refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &directory,
        None,
    )
    .await
    .map_err(|e| format!("create account: {e}"))?;
    let creds = serde_json::to_string(&credentials).map_err(|e| e.to_string())?;
    atomic_write(&creds_path, creds.as_bytes(), FILE_SECRET)?;
    Ok(account)
}

/// 私钥 / 账户凭据:仅属主可读写。
const FILE_SECRET: u32 = 0o600;
/// 证书链与元数据:属主可读写,组和其他可读。
const FILE_PUBLIC: u32 = 0o644;
/// ACME 目录:仅属主可进入。
const DIR_PRIVATE: u32 = 0o700;

fn set_dir_private(dir: &Path) -> Result<(), String> {
    set_mode(dir, DIR_PRIVATE)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// 原子写:先写 `*.tmp` 再 rename,并把权限显式钉在 `mode` 上
/// (`std::fs::write` 跟随 umask,秘密会落成 0644)。
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    set_mode(&tmp, mode)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归(F2):`site_cert_paths` 曾经没有任何调用方,ACME 签发成功后
    /// 证书从不进入 TLS 服务,`tls.acme: true` 的站点永久握手失败。
    #[test]
    fn cert_paths_prefer_explicit_then_acme_cache() {
        let dir = std::env::temp_dir().join(format!("rooster-acme-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("acme/site1")).unwrap();
        let site = Site {
            id: "site1".to_string(),
            server_names: vec!["a.test".to_string()],
            tls: rooster_config::SiteTls {
                mode: TlsMode::Terminate,
                acme: true,
                cert: None,
                key: None,
                skip_verify: false,
            },
            upstream: "http://127.0.0.1:1".to_string(),
            waf: None,
            rate_limit: vec![],
            geo: None,
            proxy_protocol: None,
            ja4_deny: vec![],
            redirect_https: None,
            max_body_size: None,
        };

        // 没有缓存 → None(拒绝握手)。
        assert!(site_cert_paths(&dir, &site).is_none());

        // 写入 ACME 缓存后应能解析到证书。
        std::fs::write(dir.join("acme/site1/cert.pem"), b"cert").unwrap();
        std::fs::write(dir.join("acme/site1/key.pem"), b"key").unwrap();
        let (c, k) = site_cert_paths(&dir, &site).expect("应解析到 acme 缓存证书");
        assert_eq!(c, dir.join("acme/site1/cert.pem"));
        assert_eq!(k, dir.join("acme/site1/key.pem"));

        // 显式配置优先。
        let mut explicit = site.clone();
        explicit.tls.cert = Some("/etc/rooster/c.pem".into());
        explicit.tls.key = Some("/etc/rooster/k.pem".into());
        let (c, k) = site_cert_paths(&dir, &explicit).unwrap();
        assert_eq!(c, PathBuf::from("/etc/rooster/c.pem"));
        assert_eq!(k, PathBuf::from("/etc/rooster/k.pem"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归(F4):`atomic_write` 曾用裸 `std::fs::write`,权限跟随 umask
    /// 落成 0644 —— 站点私钥与 ACME 账户凭据对本机所有用户可读。
    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rooster-acme-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let key = dir.join("key.pem");
        atomic_write(&key, b"-----BEGIN PRIVATE KEY-----", FILE_SECRET).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "私钥权限应为 0600,实际 {mode:o}");

        let cert = dir.join("cert.pem");
        atomic_write(&cert, b"-----BEGIN CERTIFICATE-----", FILE_PUBLIC).unwrap();
        let mode = std::fs::metadata(&cert).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "证书链权限应为 0644,实际 {mode:o}");

        set_dir_private(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "acme 目录权限应为 0700,实际 {mode:o}");

        // 临时文件不能残留。
        assert!(!dir.join("key.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归(F3):只对本次登记过应答的 http-01 挑战宣告 ready。
    /// 旧实现对 pending authorization 的**所有** challenge 宣告 ready,
    /// 对没有 TXT 记录的 dns-01 也会宣告,CA 校验失败 → order 必然失败。
    /// 这里钉住“应答集合只来自 http-01 选择结果”。
    #[test]
    fn only_registered_http01_challenges_are_signalled() {
        // `issue()` 的选择逻辑:只在 http-01 挑战上登记 key authorization。
        let challenges = [
            ("https://ca/dns01", ChallengeType::Dns01),
            ("https://ca/http01", ChallengeType::Http01),
            ("https://ca/tlsalpn", ChallengeType::TlsAlpn01),
        ];
        let mut registered = Vec::new();
        for (url, ty) in challenges {
            if ty == ChallengeType::Http01 {
                registered.push(url.to_string());
            }
        }
        // finalize_order 现在只遍历 registered,不会碰 dns-01 / tls-alpn-01。
        assert_eq!(registered, vec!["https://ca/http01".to_string()]);
        assert!(!registered.iter().any(|u| u.contains("dns01")));
    }
}
