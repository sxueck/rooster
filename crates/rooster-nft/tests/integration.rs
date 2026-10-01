//! 真机集成测试:仅在 `ROOSTER_NFT_ITEST=1` 且 euid==0(有 CAP_NET_ADMIN
//! 与 nf_tables 内核模块)时执行;普通 `cargo test` 自动跳过。
//!
//! 运行:`sudo ROOSTER_NFT_ITEST=1 cargo test -p rooster-nft --test integration`
//! 注意:测试会创建并最终删除 `table inet rooster`;机器上已有 rooster
//! 实例时不要运行。

use rooster_nft::{BanEntry, BanManager, NftBanManager, NftHandle, SET_ALLOW_V4, SET_BLOCK_V4};
use std::time::Duration;

fn enabled() -> bool {
    if std::env::var("ROOSTER_NFT_ITEST").ok().as_deref() != Some("1") {
        return false;
    }
    unsafe { libc::geteuid() == 0 }
}

fn temp_db(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    std::env::temp_dir().join(format!("rooster-nft-itest-{tag}-{n}.redb"))
}

/// 内核的独立视角:`nft list set` 的文本输出(nft CLI 不可用时返回 None,断言自动降级)。
/// 之所以要绕开本 crate 的解析器来断言:写入与回读共用同一个 bug 时,
/// 自洽断言永远绿——interval 元素漏写终点哨兵(封一个 IP 实际封到
/// 255.255.255.255)就是这样溜过原有测试的。
fn kernel_set_view(set: &str) -> Option<String> {
    let out = std::process::Command::new("nft")
        .args(["list", "set", "inet", "rooster", set])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn ensure_table_and_elements_round_trip() {
    if !enabled() {
        eprintln!("skipping (no root or ROOSTER_NFT_ITEST!=1)");
        return;
    }
    let h = NftHandle::open().expect("open netlink socket");
    h.delete_table().ok(); // 清理可能的历史残留
    h.ensure_table().expect("ensure_table (first)");
    h.ensure_table().expect("ensure_table (idempotent)");

    h.add_set_element(SET_BLOCK_V4, "203.0.113.77", Some(Duration::from_secs(60)))
        .expect("add element");
    let elems = h.list_set_elements(SET_BLOCK_V4).expect("list elements");
    assert!(
        elems.iter().any(|(s, t)| s == "203.0.113.77" && t.is_some()),
        "element present with timeout: {elems:?}"
    );
    // 关键:单 IP 在内核里必须是闭合单地址,不能是 [x, 上界] 开区间
    if let Some(view) = kernel_set_view(SET_BLOCK_V4) {
        assert!(
            view.contains("203.0.113.77") && !view.contains("255.255.255.255"),
            "内核里单 IP 封禁变成了开区间: {view}"
        );
    }
    h.delete_set_element(SET_BLOCK_V4, "203.0.113.77")
        .expect("delete element");
    assert!(
        !h.list_set_elements(SET_BLOCK_V4)
            .unwrap()
            .iter()
            .any(|(s, _)| s == "203.0.113.77")
    );
    if let Some(view) = kernel_set_view(SET_BLOCK_V4) {
        assert!(
            !view.contains("203.0.113.77"),
            "成对回删后内核应残留空集: {view}"
        );
    }

    // CIDR 元素:内核侧必须还原成同一个网段(旧编码把终点键当成不存在的属性,静默 EINVAL)
    h.add_set_element(SET_ALLOW_V4, "10.0.0.0/8", None)
        .expect("add cidr element");
    let elems = h.list_set_elements(SET_ALLOW_V4).expect("list allow");
    assert!(
        elems.iter().any(|(s, _)| s == "10.0.0.0/8"),
        "dump 应还原 CIDR: {elems:?}"
    );
    if let Some(view) = kernel_set_view(SET_ALLOW_V4) {
        assert!(
            (view.contains("10.0.0.0/8") || view.contains("10.0.0.0-10.255.255.255"))
                && !view.contains("-255.255.255.255"),
            "CIDR 在内核里被写成开区间: {view}"
        );
    }

    // 全量替换:flush + 写入一个批次;顺带清掉旧版本误编码的开区间残留
    h.replace_set_elements(
        SET_ALLOW_V4,
        &[
            ("172.16.0.0/12".to_string(), None),
            ("192.0.2.7".to_string(), None),
        ],
    )
    .expect("replace elements");
    let elems = h.list_set_elements(SET_ALLOW_V4).expect("list after replace");
    assert!(
        elems.iter().any(|(s, _)| s == "172.16.0.0/12")
            && elems.iter().any(|(s, _)| s == "192.0.2.7")
            && !elems.iter().any(|(s, _)| s == "10.0.0.0/8"),
        "replace 应为全量: {elems:?}"
    );
    if let Some(view) = kernel_set_view(SET_ALLOW_V4) {
        assert!(
            !view.contains("-255.255.255.255") && view.contains("172.16.0.0/12"),
            "replace 后内核视图: {view}"
        );
    }
    h.flush_set_elements(SET_ALLOW_V4).expect("flush");
    assert!(
        h.list_set_elements(SET_ALLOW_V4).unwrap().is_empty(),
        "flush 应清空"
    );

    h.delete_table().expect("cleanup delete_table");
}

/// ssh-guard 的 meter 下发。Debian 13 / 6.12 实测该批回 errno -34 (ERANGE),
/// 即 SSH 速率限制从未在真内核上生效——与 SET_ID、区间终点哨兵同类的
/// 「只跟 mock 自洽、未对过真内核」问题。修好前保持 #[ignore],不要当成已验证。
#[test]
#[ignore = "meter 批在内核上回 ERANGE(-34),待修"]
fn ssh_meter_round_trip() {
    if !enabled() {
        eprintln!("skipping (no root or ROOSTER_NFT_ITEST!=1)");
        return;
    }
    let h = NftHandle::open().expect("open netlink socket");
    h.delete_table().ok();
    h.ensure_table().expect("ensure_table");
    h.set_ssh_rate_limit(22, "10/minute", 5)
        .expect("ssh rate limit meter");
    h.delete_table().expect("cleanup delete_table");
}

#[test]
fn ban_manager_round_trip() {
    if !enabled() {
        eprintln!("skipping (no root or ROOSTER_NFT_ITEST!=1)");
        return;
    }
    let h = NftHandle::open().expect("open netlink socket");
    h.delete_table().ok();
    let db = temp_db("bans");
    let mgr = NftBanManager::new(h, &db).expect("manager init");

    mgr.set_allowlist(&["10.0.0.0/8".parse().unwrap()])
        .expect("set allowlist");
    let entry = BanEntry {
        ip: "198.51.100.23".into(),
        ttl: Duration::from_secs(120),
        reason: "integration test".into(),
        plugin: "itest".into(),
        node: "local".into(),
        scope: rooster_nft::BanScope::Local,
        expires_at: None,
    };
    mgr.apply_ban(&entry).expect("apply ban");
    let bans = mgr.list_bans().unwrap();
    assert!(bans.iter().any(|b| b.ip == "198.51.100.23" && b.expires_at.is_some()));

    // 端到端:封一个 IP 不能连累它以上的整段地址,白名单也不能放行整段空间
    if let Some(view) = kernel_set_view(SET_BLOCK_V4) {
        assert!(
            view.contains("198.51.100.23") && !view.contains("255.255.255.255"),
            "封禁在内核里变成了开区间: {view}"
        );
    }
    if let Some(view) = kernel_set_view(SET_ALLOW_V4) {
        assert!(
            view.contains("10.0.0.0/8") && !view.contains("255.255.255.255"),
            "白名单在内核里变成了开区间: {view}"
        );
    }

    // 白名单 IP 拒封
    let refused = mgr.apply_ban(&BanEntry {
        ip: "10.9.9.9".into(),
        ..entry
    });
    assert!(matches!(refused, Err(rooster_nft::NftError::Refused(_))));

    mgr.remove_ban("198.51.100.23").expect("remove ban");
    assert!(!mgr.list_bans().unwrap().iter().any(|b| b.ip == "198.51.100.23"));

    drop(mgr);
    let _ = std::fs::remove_file(&db);
    // 收尾删表,避免残留
    NftHandle::open().unwrap().delete_table().unwrap();
}

/// 真实丢包验证(默认跳过,需能出外网):
/// `sudo ROOSTER_NFT_ITEST=1 ROOSTER_NFT_PING=1 [ROOSTER_NFT_PING_IP=1.1.1.1] cargo test -p rooster-nft --test integration`
/// pre 链按「入向源地址」丢弃,所以封一个可达地址后本机 ping 的回包应被丢掉。
#[test]
fn ban_drops_traffic() {
    if !enabled() || std::env::var("ROOSTER_NFT_PING").ok().as_deref() != Some("1") {
        eprintln!("skipping (need ROOSTER_NFT_ITEST=1 and ROOSTER_NFT_PING=1)");
        return;
    }
    let ip = std::env::var("ROOSTER_NFT_PING_IP").unwrap_or_else(|_| "1.1.1.1".to_string());
    if !ping_ok(&ip) {
        eprintln!("skipping ({ip} 本机不可达,无法断言丢包)");
        return;
    }
    let h = NftHandle::open().expect("open netlink socket");
    h.delete_table().ok();
    h.ensure_table().expect("ensure_table");
    h.add_set_element(SET_BLOCK_V4, &ip, Some(Duration::from_secs(60)))
        .expect("ban");
    assert!(!ping_ok(&ip), "封禁 {ip} 后回包应被 pre 链丢弃");
    h.delete_set_element(SET_BLOCK_V4, &ip).expect("unban");
    assert!(ping_ok(&ip), "解封后应恢复连通");
    h.delete_table().expect("cleanup delete_table");
}

fn ping_ok(ip: &str) -> bool {
    std::process::Command::new("ping")
        .args(["-c", "2", "-W", "2", ip])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
