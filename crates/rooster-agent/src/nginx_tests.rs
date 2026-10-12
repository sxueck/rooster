use super::*;

fn files(entries: &[(&str, &str)]) -> BTreeMap<PathBuf, String> {
    entries
        .iter()
        .map(|(p, s)| (PathBuf::from(p), (*s).into()))
        .collect()
}

fn row(source: &str) -> NginxSite {
    discover_sites(&files(&[("/etc/nginx/sites-enabled/a.conf", source)]))
        .unwrap()
        .remove(0)
}

fn journal(row: &NginxSite, file: &str) -> Journal {
    Journal {
        id: row.id.clone(),
        instance: Instance {
            binary: "/usr/sbin/nginx".into(),
            args: vec![],
            running: true,
            pid: Some(1),
        },
        file: file.into(),
        original: None,
        injected: None,
        upstream: String::new(),
        spans: row
            .locs
            .iter()
            .enumerate()
            .map(|(i, plan)| {
                let site_id = plan.site_id(&row.id, i == 0);
                JournalSpan {
                    site_id: site_id.clone(),
                    upstream: plan.upstream.clone(),
                    context_fingerprint: Some(plan_fingerprint(plan)),
                    original: row.source[plan.proxy.start..plan.proxy.end].into(),
                    injected: injection(plan, &site_id, LISTEN).unwrap(),
                    fixups: plan.fixups.clone(),
                }
            })
            .collect(),
        phase: "active".into(),
        original_hash: hash_content(&row.source),
        listener: LISTEN.into(),
    }
}

fn attach(row: &NginxSite, j: &Journal) -> String {
    let replacements = row
        .locs
        .iter()
        .zip(&j.spans)
        .flat_map(|(p, sp)| {
            std::iter::once((p.proxy.start, p.proxy.end, sp.injected.clone())).chain(
                p.fixups
                    .iter()
                    .map(|f| (f.start, f.end, f.injected.clone())),
            )
        })
        .collect::<Vec<_>>();
    splice(&row.source, &replacements).unwrap()
}

#[test]
fn quoted_delimiters_and_embedded_hash_are_values() {
    let source = "server { location / { proxy_set_header X-Brace \"}\"; proxy_set_header X-Semi ';'; add_header X-Key abc#123; proxy_pass http://127.0.0.1:3000; } }";
    let r = row(source);
    assert!(r.supported, "{:?}", r.reason);
    assert_eq!(r.locs[0].headers[0].words()[2], "}");
    assert_eq!(r.locs[0].headers[1].words()[2], ";");
    let inj = injection(&r.locs[0], &r.id, LISTEN).unwrap();
    let p = &r.locs[0].proxy;
    let changed = splice(source, &[(p.start, p.end, inj)]).unwrap();
    assert!(changed.contains("abc#123"));
    assert!(parse(&changed).is_ok());
    let escaped = parse(r#"proxy_set_header X "a\tb\n\"c\\d";"#).unwrap();
    assert_eq!(escaped[0].words[2], "a\tb\n\"c\\d");
    let embedded = parse(r#"proxy_set_header X abc"def;"#).unwrap();
    assert_eq!(embedded[0].words[2], "abc\"def");
}

#[test]
fn dynamic_handlers_and_nested_locations_decline_the_server() {
    for handler in [
        "location /admin { location /admin/api { proxy_pass http://127.0.0.1:4000; } }",
        "location ~ \\.php$ { fastcgi_pass unix:/run/php.sock; }",
        "location /rpc { grpc_pass grpc://127.0.0.1:9000; }",
        "location /app { uwsgi_pass 127.0.0.1:9001; }",
        "location /app { scgi_pass 127.0.0.1:9002; }",
        "location /app { content_by_lua_block { return; } }",
    ] {
        let r = row(&format!(
            "server {{ location / {{ proxy_pass http://127.0.0.1:3000; }} {handler} }}"
        ));
        assert!(!r.supported, "{handler}");
        assert!(r.reason.unwrap().contains("动态处理"));
    }
    let r = row("server { location / { proxy_pass http://127.0.0.1:3000; } location /static { root /www; } location /.well-known/acme-challenge/ { return 200 ok; } }");
    assert!(r.supported);
    assert_eq!(r.bypassed_locations, 2);
}

#[test]
fn recursive_server_headers_are_materialized() {
    let fs = files(&[
        ("/etc/nginx/nginx.conf", "http { include /etc/nginx/sites-enabled/*; }"),
        ("/etc/nginx/sites-enabled/a.conf", "server { include /etc/nginx/h1.conf; location / { proxy_pass http://127.0.0.1:3000; } }"),
        ("/etc/nginx/h1.conf", "include /etc/nginx/h2.conf;"),
        ("/etc/nginx/h2.conf", "proxy_set_header Host $host; proxy_set_header Authorization \"\";"),
    ]);
    let r = discover_sites(&fs).unwrap().remove(0);
    assert!(r.supported, "{:?}", r.reason);
    let inj = injection(&r.locs[0], &r.id, LISTEN).unwrap();
    assert!(inj.contains("proxy_set_header Host $host;"));
    assert!(inj.contains("proxy_set_header Authorization \"\";"));
}

#[test]
fn recursive_location_fixups_restore_the_outer_include() {
    let fs = files(&[
        ("/etc/nginx/nginx.conf", "http { upstream g { server 127.0.0.1:8080; } include /etc/nginx/sites-enabled/*; }"),
        ("/etc/nginx/sites-enabled/a.conf", "server { location / { include /etc/nginx/h1.conf; proxy_pass http://g; } }"),
        ("/etc/nginx/h1.conf", "proxy_set_header X-Before yes; include /etc/nginx/h2.conf; proxy_set_header X-After yes;"),
        ("/etc/nginx/h2.conf", "proxy_set_header Host $proxy_host; proxy_set_header X-Port $proxy_port;"),
    ]);
    let r = discover_sites(&fs).unwrap().remove(0);
    assert!(r.supported, "{:?}", r.reason);
    let fix = &r.locs[0].fixups[0];
    assert_eq!(fix.original, "include /etc/nginx/h1.conf;");
    assert!(fix.injected.contains("Host g;"));
    assert!(fix.injected.contains("X-Port 80;"));
    assert!(fix.injected.contains("X-Before yes;"));
    assert!(fix.injected.contains("X-After yes;"));
    let j = journal(&r, &r.file);
    let changed = attach(&r, &j);
    assert!(parse(&changed).is_ok());
    assert_eq!(restore_all(&j, &changed), r.source);
    assert_eq!(
        fs[Path::new("/etc/nginx/h2.conf")],
        "proxy_set_header Host $proxy_host; proxy_set_header X-Port $proxy_port;"
    );
}

#[test]
fn include_cycles_decline_without_recursing_forever() {
    let fs = files(&[
        ("/etc/nginx/sites-enabled/a.conf", "server { include /etc/nginx/h1.conf; location / { proxy_pass http://127.0.0.1:3000; } }"),
        ("/etc/nginx/h1.conf", "include /etc/nginx/h2.conf;"),
        ("/etc/nginx/h2.conf", "include /etc/nginx/h1.conf;"),
    ]);
    assert!(!discover_sites(&fs).unwrap()[0].supported);
}

#[test]
fn posix_include_character_classes_preserve_http_headers() {
    let fs = files(&[
        (
            "/etc/nginx/nginx.conf",
            "http { include /etc/nginx/headers[0-9]*.conf; include /etc/nginx/sites-enabled/*; }",
        ),
        (
            "/etc/nginx/headers1.conf",
            "proxy_set_header Host $host; proxy_set_header Authorization \"\";",
        ),
        (
            "/etc/nginx/sites-enabled/a.conf",
            "server { location / { proxy_pass http://127.0.0.1:3000; } }",
        ),
    ]);
    let r = discover_sites(&fs).unwrap().remove(0);
    assert!(r.supported, "{:?}", r.reason);
    assert_eq!(r.locs[0].headers.len(), 2);
    assert!(glob_match("/etc/[[:digit:]].conf", "/etc/2.conf"));
    assert!(!glob_match("/etc/*.conf", "/etc/sub/a.conf"));
    assert!(!glob_match("/etc/*", "/etc/.hidden"));
}

#[test]
fn http_upstreams_do_not_merge_stream_or_unreachable_groups() {
    let fs = files(&[
        ("/etc/nginx/nginx.conf", "stream { upstream g { server 127.0.0.1:9000; } } http { upstream g { server 127.0.0.1:3000; } server { location / { proxy_pass http://g; } } }"),
        ("/etc/nginx/stream-group.conf", "upstream g { server 127.0.0.1:9001; }"),
    ]);
    let r = discover_sites(&fs).unwrap().remove(0);
    assert!(r.supported, "{:?}", r.reason);
    assert_eq!(r.upstream.as_deref(), Some("http://127.0.0.1:3000"));
    let r = row("stream { upstream backend { server 127.0.0.1:9000; } } http { server { location / { proxy_pass http://backend; } } }");
    assert!(!r.supported);
}

#[test]
fn inherited_redirect_off_and_proxy_port_use_logical_target() {
    for (scheme, expected) in [("http", "80"), ("https", "443")] {
        let r = row(&format!("upstream g {{ server 127.0.0.1:8080; }} server {{ proxy_redirect off; proxy_set_header X-Port $proxy_port; location / {{ proxy_pass {scheme}://g; }} }}"));
        assert!(r.supported, "{:?}", r.reason);
        let inj = injection(&r.locs[0], &r.id, LISTEN).unwrap();
        assert!(!inj.contains("proxy_redirect"));
        assert!(inj.contains(&format!("X-Port {expected};")), "{inj}");
    }
}

#[test]
fn nginx_connect_timeout_defaults_inherits_and_overrides() {
    for (setting, expected) in [
        ("", Duration::from_secs(60)),
        ("proxy_connect_timeout 75;", Duration::from_secs(75)),
        ("proxy_connect_timeout 250ms;", Duration::from_millis(250)),
        ("proxy_connect_timeout 1m30s;", Duration::from_secs(90)),
        (
            "proxy_connect_timeout '1h 2m 3s';",
            Duration::from_secs(3723),
        ),
    ] {
        let r = row(&format!(
            "server {{ {setting} location / {{ proxy_pass http://127.0.0.1:3000; }} }}"
        ));
        assert!(r.supported, "{:?}", r.reason);
        assert_eq!(r.locs[0].connect_timeout, expected);
    }
    let r = row("server { proxy_connect_timeout 75s; location / { proxy_connect_timeout 5s; proxy_pass http://127.0.0.1:3000; } }");
    assert_eq!(r.locs[0].connect_timeout, Duration::from_secs(5));
    let site: Site = serde_json::from_value(json!({"id": "s", "server-names": ["s.test"], "upstream": "http://127.0.0.1:3000", "tls": {"mode": "terminate"}, "upstream-connect-timeout": "250ms"})).unwrap();
    assert_eq!(
        site.upstream_connect_timeout,
        Some(Duration::from_millis(250))
    );
}

#[test]
fn restore_uses_dump_alias_not_canonical_write_path() {
    let r = row("server { location / { proxy_pass http://127.0.0.1:3000; } }");
    let j = journal(&r, "/etc/nginx/sites-available/a.conf");
    let changed = attach(&r, &j);
    let fs = files(&[(r.file.as_str(), changed.as_str())]);
    let restored = restored_site(&fs, &j, &changed).unwrap().unwrap();
    assert_eq!(restored.id, r.id);
    assert!(restored.supported, "{:?}", restored.reason);
    assert!(spans_match_site(&restored, &j.spans));
}

#[test]
fn dependency_changes_invalidate_scan_and_attached_plan() {
    let mut fs = files(&[
        (
            "/etc/nginx/nginx.conf",
            "http { upstream g { server 127.0.0.1:3000; } include /etc/nginx/sites-enabled/*; }",
        ),
        (
            "/etc/nginx/sites-enabled/a.conf",
            "server { include /etc/nginx/headers.conf; location / { proxy_pass http://g; } }",
        ),
        ("/etc/nginx/headers.conf", "proxy_set_header Host $host;"),
    ]);
    let r = discover_sites(&fs).unwrap().remove(0);
    let j = journal(&r, &r.file);
    let changed = attach(&r, &j);
    fs.insert(
        PathBuf::from("/etc/nginx/nginx.conf"),
        "http { upstream g { server 127.0.0.1:4000; } include /etc/nginx/sites-enabled/*; }".into(),
    );
    let next = discover_sites(&fs).unwrap().remove(0);
    assert_ne!(next.fingerprint, r.fingerprint);
    assert!(!spans_match_site(&next, &j.spans));
    fs.insert(PathBuf::from(&r.file), changed.clone());
    let restored = restored_site(&fs, &j, &changed).unwrap().unwrap();
    assert!(!spans_match_site(&restored, &j.spans));
    fs.insert(
        PathBuf::from("/etc/nginx/nginx.conf"),
        "http { upstream g { server 127.0.0.1:3000; } include /etc/nginx/sites-enabled/*; }".into(),
    );
    fs.insert(
        PathBuf::from("/etc/nginx/headers.conf"),
        "proxy_set_header Host example.test;".into(),
    );
    let restored = restored_site(&fs, &j, &changed).unwrap().unwrap();
    assert!(!spans_match_site(&restored, &j.spans));
}

#[test]
fn wire_gate_and_fold_flag() {
    let on = row("server { listen 443 ssl; location / { proxy_pass http://127.0.0.1:3001; } }");
    let on = serde_json::to_value(on).unwrap();
    assert_eq!(on["supported"].as_bool(), Some(true), "Enable WAF 靠这个字段门控");
    assert_eq!(on["has_proxy_pass"].as_bool(), Some(true));
    assert!(on.get("source").is_none() && on.get("locs").is_none(), "完整配置不出节点");

    // 有转发但被分类器拒绝：必须独立成行，原因不能被折进跳转块。
    let declined = row("server { listen 443 ssl; location / { rewrite ^ /a; proxy_pass http://127.0.0.1:3001; } }");
    let declined = serde_json::to_value(declined).unwrap();
    assert_eq!(declined["supported"].as_bool(), Some(false));
    assert_eq!(declined["has_proxy_pass"].as_bool(), Some(true));

    // 纯静态/跳转块：无转发，允许折叠。
    let static_row = serde_json::to_value(row("server { listen 80; location / { root /www; } }")).unwrap();
    assert_eq!(static_row["has_proxy_pass"].as_bool(), Some(false));

    // proxy_pass 藏在展不开的 snippet 里：按有转发处理。
    let hidden = discover_sites(&files(&[
        ("/etc/nginx/sites-enabled/a.conf", "server { listen 443 ssl; location / { include /etc/nginx/proxy_params; } }"),
        ("/etc/nginx/proxy_params", "proxy_pass http://127.0.0.1:3001; proxy_set_header Host $host;"),
    ]))
    .unwrap()
    .remove(0);
    assert!(!hidden.supported, "{:?}", hidden.reason);
    assert!(hidden.has_proxy_pass);
}

#[test]
fn legacy_journal_without_context_fingerprint_still_checks_upstream() {
    let r = row("server { location / { proxy_pass http://127.0.0.1:3000; } }");
    let mut j = journal(&r, &r.file);
    let raw = serde_json::to_value(&j).unwrap();
    j.spans[0].context_fingerprint = None;
    let legacy = serde_json::to_value(&j).unwrap();
    assert!(raw["spans"][0].get("context_fingerprint").is_some());
    assert!(legacy["spans"][0].get("context_fingerprint").is_none());
    let parsed: Journal = serde_json::from_value(legacy).unwrap();
    assert!(spans_match_site(&r, &parsed.spans));
    let other = row("server { location / { proxy_pass http://127.0.0.1:4000; } }");
    assert!(!spans_match_site(&other, &parsed.spans));
}
