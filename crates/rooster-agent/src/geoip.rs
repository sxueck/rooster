//! GeoIP 数据库:路径解析与 DB-IP Lite 月度自动更新。
//!
//! 文件:`data_dir/<database>.mmdb`。缺失或超过 35 天时按
//! `https://download.db-ip.com/free/<database>-<YYYY-MM>.mmdb.gz` 拉取
//! (CC BY 4.0,面板需注明数据来源)。下载失败但存在旧库时
//! 继续使用旧库并告警;`auto_update=false` 时不联网。

use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 数据库月度过期阈值(近似月度 + 宽限)。
const STALE_AFTER: Duration = Duration::from_secs(35 * 24 * 3600);

pub fn db_path(data_dir: &Path, database: &str) -> PathBuf {
    data_dir.join(format!("{database}.mmdb"))
}

/// 地区规则已配但库不可用时,按 `fail-open` 决定是否放行。
///
/// 默认 fail-closed:调用方收到 `Err` 必须拒绝启动(而不是静默地把
/// `geo.deny` 当成空规则放行)。`fail-open = true` 才降级放行。
pub fn check_available(
    fail_open: bool,
    db: Option<&Path>,
    geo_rules_configured: bool,
) -> Result<(), String> {
    if !geo_rules_configured || db.is_some() {
        return Ok(());
    }
    if fail_open {
        tracing::error!(
            "geoip database unavailable and geoip.fail-open = true; \
             geo allow/deny rules are NOT enforced"
        );
        return Ok(());
    }
    Err("geoip database unavailable but geo allow/deny rules are configured \
         (set geoip.fail-open: true to degrade to allow-all)"
        .to_string())
}

/// 确保数据库存在且新鲜;返回可用路径(不可用 → None)。
/// 不会阻塞启动超过下载时限:失败降级旧库或无 geo。
pub async fn ensure_db(data_dir: &Path, database: &str, auto_update: bool) -> Option<PathBuf> {
    let path = db_path(data_dir, database);
    if fresh(&path) {
        return Some(path);
    }
    if !auto_update {
        if path.is_file() {
            tracing::warn!("geoip database stale and auto-update disabled: {}", path.display());
            return Some(path);
        }
        tracing::warn!("geoip database missing and auto-update disabled; geo rules inactive");
        return None;
    }
    let ym = current_year_month();
    let url = format!("https://download.db-ip.com/free/{database}-{ym}.mmdb.gz");
    tracing::info!("updating geoip database from {url}");
    match download_and_store(&url, &path).await {
        Ok(()) => Some(path),
        Err(e) => {
            if path.is_file() {
                tracing::warn!("geoip update failed ({e}); keeping stale database");
                Some(path)
            } else {
                tracing::warn!("geoip download failed ({e}); geo rules inactive");
                None
            }
        }
    }
}

fn fresh(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > 0 && m.is_file() => m
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|age| age < STALE_AFTER)
            .unwrap_or(false),
        _ => false,
    }
}

async fn download_and_store(url: &str, dest: &Path) -> Result<(), String> {
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("http {}", resp.status()));
    }
    let gz = resp.bytes().await.map_err(|e| e.to_string())?;
    let mut raw = Vec::with_capacity(gz.len() * 4);
    GzDecoder::new(&gz[..])
        .read_to_end(&mut raw)
        .map_err(|e| format!("gunzip: {e}"))?;
    // mmdb 元数据哨兵校验,防止把 HTML 错误页当数据库。
    if !looks_like_mmdb(&raw) {
        return Err("downloaded data is not an mmdb file".into());
    }
    let tmp = dest.with_extension("mmdb.tmp");
    std::fs::write(&tmp, &raw).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(&tmp, dest).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

/// mmdb 元数据哨兵 "\xab\xcd\xef MaxMind.com" 出现在文件尾部窗口内
/// (真实文件哨兵之后还有元数据段,不能只比末尾定长)。
fn looks_like_mmdb(raw: &[u8]) -> bool {
    const MARKER: &[u8] = b"\xab\xcd\xef MaxMind.com";
    let start = raw.len().saturating_sub(128);
    raw[start..].windows(MARKER.len()).any(|w| w == MARKER)
}

/// 公历年-月(Howard Hinnant civil_from_days 算法,免 chrono 依赖)。
pub fn current_year_month() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_month_shape() {
        let ym = current_year_month();
        let (y, m) = ym.split_once('-').unwrap();
        assert_eq!(y.len(), 4);
        let m: u32 = m.parse().unwrap();
        assert!((1..=12).contains(&m));
    }

    #[test]
    fn mmdb_marker_check() {
        let mut raw = vec![0u8; 128];
        let marker = b"\xab\xcd\xef MaxMind.com";
        raw.extend_from_slice(marker);
        assert!(looks_like_mmdb(&raw));
        assert!(!looks_like_mmdb(b"not an mmdb"));
    }

    /// 回归(F5):库不可用时 `allowed()` 一律返回 true,配了 `geo.deny`
    /// 的站点在库缺失期间照常代理——控制项静默消失。默认必须 fail-closed。
    #[test]
    fn unavailable_db_is_fail_closed_unless_opted_out() {
        let none: Option<PathBuf> = None;
        let some = Some(PathBuf::from("/var/lib/rooster/GeoLite2-Country.mmdb"));

        // 未配置 geo 规则 → 无关紧要。
        assert!(check_available(false, none.as_deref(), false).is_ok());
        // 配置了 geo 规则 + 库缺失 + 默认策略 → 拒绝启动。
        assert!(check_available(false, none.as_deref(), true).is_err());
        // 库在 → 放行。
        assert!(check_available(false, some.as_deref(), true).is_ok());
        // 显式 fail-open 才降级放行。
        assert!(check_available(true, none.as_deref(), true).is_ok());
    }
}
