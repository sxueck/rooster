use rooster_config::parse_and_validate;

fn effective(managed: &str) -> rooster_config::EffectiveConfig {
    let raw = format!("local:\n  agent:\n    node-name: crs-test\nmanaged:\n{managed}");
    parse_and_validate(&raw).unwrap().1
}

/// CRS 默认必须开启：内嵌规则集随二进制分发，默认关闭会让未显式配置的
/// 节点只剩内置签名（面板随即报“CRS 未生效、覆盖面不足”）。
#[test]
fn crs_enabled_by_default_and_can_be_opted_out() {
    let eff = effective("  plugins: {}\n");
    assert!(eff.waf.crs.enabled, "CRS must default to enabled");
    assert_eq!(eff.waf.crs.paranoia_level, 1);

    let eff = effective("  waf:\n    crs:\n      enabled: false\n  plugins: {}\n");
    assert!(!eff.waf.crs.enabled, "explicit opt-out must be honored");
}
