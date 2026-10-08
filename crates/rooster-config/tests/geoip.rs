use rooster_config::parse_and_validate;

fn effective(managed: &str, local: &str) -> rooster_config::EffectiveConfig {
    let raw = format!("local:\n  agent:\n    node-name: geoip-test\n{local}managed:\n{managed}");
    parse_and_validate(&raw).unwrap().1
}

#[test]
fn attribution_is_default_on_without_http_guard() {
    let eff = effective("  plugins: {}\n", "");
    let geo = eff.attribution_geoip();
    assert!(geo.enabled());
    assert!(geo.auto_update());
    let serialized = serde_json::to_value(&eff).unwrap();
    assert_eq!(serialized["geoip"]["enabled"], true);
    assert_eq!(serialized["geoip"]["database"], "dbip-country-lite");
    assert_eq!(geo.database(), "dbip-country-lite");
    assert!(!eff.plugins.http_guard.enabled);
    assert_eq!(eff.http_geoip().database, "dbip-country-lite");
    assert!(!eff.http_geoip().fail_open);
}

#[test]
fn legacy_http_database_is_preserved_when_global_is_absent() {
    let eff = effective(
        "  plugins:\n    http-guard:\n      geoip:\n        database: legacy-country\n        auto-update: false\n        fail-open: true\n",
        "",
    );
    let geo = eff.attribution_geoip();
    assert!(geo.enabled());
    assert_eq!(geo.database(), "legacy-country");
    assert!(!geo.auto_update());
    assert_eq!(eff.http_geoip().database, "legacy-country");
    assert!(eff.http_geoip().fail_open);
}

#[test]
fn explicit_global_and_http_override_are_independent() {
    let eff = effective(
        "  geoip:\n    database: global-country\n    auto-update: false\n  plugins:\n    http-guard:\n      geoip:\n        database: http-country\n        auto-update: true\n",
        "",
    );
    assert_eq!(eff.attribution_geoip().database(), "global-country");
    assert!(!eff.attribution_geoip().auto_update());
    assert_eq!(eff.http_geoip().database, "http-country");
    assert!(eff.http_geoip().auto_update);
}

#[test]
fn explicit_empty_global_uses_defaults_instead_of_legacy_database() {
    let eff = effective(
        "  geoip: {}\n  plugins:\n    http-guard:\n      geoip:\n        database: legacy-country\n",
        "",
    );
    assert_eq!(eff.attribution_geoip().database(), "dbip-country-lite");
    assert_eq!(eff.http_geoip().database, "legacy-country");
}

#[test]
fn local_partial_override_preserves_managed_database_and_update_policy() {
    let eff = effective(
        "  geoip:\n    database: managed-country\n    auto-update: false\n",
        "  geoip:\n    enabled: false\n",
    );
    let geo = eff.attribution_geoip();
    assert!(!geo.enabled());
    assert_eq!(geo.database(), "managed-country");
    assert!(!geo.auto_update());
    assert_eq!(eff.http_geoip().database, "managed-country");
    assert!(!eff.http_geoip().fail_open);
}

#[test]
fn shared_database_uses_http_update_policy() {
    for http_updates in [false, true] {
        let managed = format!("  geoip:\n    database: shared-country\n    auto-update: {}\n  plugins:\n    http-guard:\n      geoip:\n        database: shared-country\n        auto-update: {http_updates}\n", !http_updates);
        let eff = effective(&managed, "");
        assert_eq!(eff.attribution_geoip().auto_update(), http_updates);
        assert_eq!(eff.http_geoip().auto_update, http_updates);
        assert_eq!(serde_json::to_value(&eff).unwrap()["geoip"]["auto-update"], http_updates);
    }
}

#[test]
fn generated_template_enables_attribution_without_enabling_http() {
    let eff = parse_and_validate(&rooster_config::default_config_template()).unwrap().1;
    assert!(eff.attribution_geoip().enabled());
    assert!(!eff.plugins.http_guard.enabled);
}

#[test]
fn global_geoip_rejects_misspelled_fields() {
    assert!(parse_and_validate("local:\n  agent:\n    node-name: test\n  geoip:\n    auto-updat: false\n").is_err());
}
