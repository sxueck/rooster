//! Local Nginx discovery and transactional onboarding of simple proxy locations.
//! Never accepts a path or command from the remote caller. Nginx owns TLS;
//! Rooster inspects the complete proxy request on a loopback HTTP listener.
use crate::state::AgentState;
use rooster_config::{hash_content, writer, Seg, Site, WafMode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_CONFIG: usize = 4 * 1024 * 1024;
const ROUTE_HEADER: &str = "X-Rooster-Site";
const LISTEN: &str = "127.0.0.1:18080";
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Instance {
    binary: PathBuf,
    args: Vec<String>,
    running: bool,
    pid: Option<u32>,
}
impl Instance {
    fn discover() -> Result<Self> {
        let mut instances = Vec::new();
        for entry in fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let Ok(raw) = fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let title = String::from_utf8_lossy(&raw);
            let Some(title) = title.strip_prefix("nginx: master process ") else {
                continue;
            };
            let title = title.trim_end_matches('\0');
            if fs::read_link(entry.path().join("ns/mnt")).ok()
                != fs::read_link("/proc/self/ns/mnt").ok()
            {
                return Err(
                    "Nginx is in another mount namespace; container onboarding is not supported"
                        .into(),
                );
            }
            let binary = fs::read_link(entry.path().join("exe"))
                .map_err(|e| format!("cannot inspect nginx executable: {e}"))?;
            let words: Vec<_> = title.split_whitespace().collect();
            let mut args = Vec::new();
            let mut i = 1;
            while i < words.len() {
                match words[i] {
                    "-c" | "-p" => {
                        let value = words.get(i + 1).ok_or("invalid nginx process arguments")?;
                        if !Path::new(value).is_absolute() {
                            return Err(
                                "relative nginx -c/-p is not supported; use absolute paths".into(),
                            );
                        }
                        args.extend([words[i].to_string(), value.to_string()]);
                        i += 2;
                    }
                    "-g" => {
                        args.extend(["-g".into(), words[i + 1..].join(" ")]);
                        break;
                    }
                    "-e" => {
                        i += 2;
                    }
                    _ => {
                        return Err(
                            "unrecognised nginx startup arguments; automatic writes disabled"
                                .into(),
                        )
                    }
                }
            }
            instances.push(Self {
                binary,
                args,
                running: true,
                pid: entry.file_name().to_string_lossy().parse().ok(),
            });
        }
        if instances.len() > 1 {
            return Err("multiple nginx master processes found; select a single host instance before onboarding".into());
        }
        if let Some(i) = instances.pop() {
            return Ok(i);
        }
        for binary in [
            "/usr/sbin/nginx",
            "/usr/local/nginx/sbin/nginx",
            "/usr/local/sbin/nginx",
        ] {
            if Path::new(binary).is_file() {
                return Ok(Self {
                    binary: binary.into(),
                    args: vec![],
                    running: false,
                    pid: None,
                });
            }
        }
        Err("Nginx not found on this host (container Nginx is not supported)".into())
    }
    fn command(&self, extra: &[&str]) -> Result<String> {
        let mut child = Command::new(&self.binary)
            .args(&self.args)
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let out = std::thread::spawn(move || read_bounded(stdout));
        let err = std::thread::spawn(move || read_bounded(stderr));
        let start = Instant::now();
        let status = loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(status) => break status,
                None if start.elapsed() < Duration::from_secs(5) => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("nginx command timed out".into());
                }
            }
        };
        let out = out.join().map_err(|_| "nginx output reader failed")??;
        let err = err.join().map_err(|_| "nginx error reader failed")??;
        // Full command output can contain credentials and is never sent to the panel.
        if !status.success() {
            tracing::warn!(stderr = %err, "nginx command failed");
            return Err("nginx validation/reload failed; see agent log".into());
        }
        Ok(out)
    }
    fn reload(&self) -> Result<()> {
        let current = Self::discover()?;
        if current.binary != self.binary
            || current.args != self.args
            || current.pid != self.pid
            || !current.running
        {
            return Err("Nginx instance changed; refusing to reload another process".into());
        }
        self.command(&["-t"])?;
        let children = || -> Result<Vec<String>> {
            let master = self.pid.ok_or("Nginx master missing")?;
            let mut workers = Vec::new();
            for entry in fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
                let pid = entry.file_name().to_string_lossy().to_string();
                if pid.parse::<u32>().is_err() {
                    continue;
                }
                let Ok(title) = fs::read(entry.path().join("cmdline")) else {
                    continue;
                };
                if !title.starts_with(b"nginx: worker process")
                    || String::from_utf8_lossy(&title).contains("shutting down")
                {
                    continue;
                }
                let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                    continue;
                };
                if stat
                    .rsplit_once(") ")
                    .and_then(|(_, fields)| fields.split_whitespace().nth(1))
                    .and_then(|p| p.parse::<u32>().ok())
                    == Some(master)
                {
                    workers.push(pid);
                }
            }
            Ok(workers)
        };
        let previous = children()?;
        self.command(&["-s", "reload"])?;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            let active = children()?;
            if active.iter().any(|pid| !previous.contains(pid))
                && !active.iter().any(|pid| previous.contains(pid))
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        Err("Nginx signalled but no new worker appeared; reload not verified".into())
    }
}
fn read_bounded(mut reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_CONFIG + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    // Drain excess so a child cannot block on a full pipe, but keep bounded memory.
    let too_large = bytes.len() > MAX_CONFIG;
    std::io::copy(&mut reader, &mut std::io::sink()).map_err(|e| e.to_string())?;
    if too_large {
        return Err("nginx configuration exceeds 4 MiB".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

#[derive(Clone, Debug)]
struct Token {
    value: String,
    start: usize,
    end: usize,
}
fn tokens(source: &str) -> Result<Vec<Token>> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i] == b'#' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        if b"{};".contains(&b[i]) {
            i += 1;
            out.push(Token {
                value: source[start..i].into(),
                start,
                end: i,
            });
            continue;
        }
        let mut value = Vec::new();
        let mut quote = None;
        while i < b.len() {
            let c = b[i];
            if c == b'\\' {
                i += 1;
                if i == b.len() {
                    return Err("unterminated nginx escape".into());
                }
                // Preserve escapes in quoted values when rendering inherited directives.
                value.push(b'\\');
                value.push(b[i]);
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                } else {
                    value.push(c);
                }
                i += 1;
                continue;
            }
            if c == b'\'' || c == b'"' {
                quote = Some(c);
                i += 1;
                continue;
            }
            if c == b'$' && b.get(i + 1) == Some(&b'{') {
                let end = b[i + 2..]
                    .iter()
                    .position(|c| *c == b'}')
                    .ok_or("unterminated nginx variable")?
                    + i
                    + 3;
                value.extend_from_slice(&b[i..end]);
                i = end;
                continue;
            }
            if c.is_ascii_whitespace() || b"{};#".contains(&c) {
                break;
            }
            value.push(c);
            i += 1;
        }
        if quote.is_some() {
            return Err("unterminated nginx quote".into());
        }
        out.push(Token {
            value: String::from_utf8(value).map_err(|e| e.to_string())?,
            start,
            end: i,
        });
    }
    Ok(out)
}
#[derive(Clone, Debug)]
struct Directive {
    words: Vec<String>,
    start: usize,
    end: usize,
    children: Option<Vec<Directive>>,
}
fn parse(source: &str) -> Result<Vec<Directive>> {
    fn block(ts: &[Token], i: &mut usize, nested: bool, depth: usize) -> Result<Vec<Directive>> {
        if depth > 64 {
            return Err("nginx nesting exceeds 64 levels".into());
        }
        let mut out = Vec::new();
        while *i < ts.len() {
            if ts[*i].value == "}" {
                if !nested {
                    return Err("unexpected nginx closing brace".into());
                }
                *i += 1;
                return Ok(out);
            }
            let start = ts[*i].start;
            let mut words = Vec::new();
            while *i < ts.len() && !["{", "}", ";"].contains(&ts[*i].value.as_str()) {
                words.push(ts[*i].value.clone());
                *i += 1;
            }
            if words.is_empty() || *i == ts.len() {
                return Err("incomplete nginx directive".into());
            }
            let children = match ts[*i].value.as_str() {
                ";" => {
                    *i += 1;
                    None
                }
                "{" => {
                    *i += 1;
                    Some(block(ts, i, true, depth + 1)?)
                }
                _ => return Err("nginx directive missing semicolon".into()),
            };
            out.push(Directive {
                words,
                start,
                end: ts[*i - 1].end,
                children,
            });
        }
        if nested {
            return Err("unclosed nginx block".into());
        }
        Ok(out)
    }
    block(&tokens(source)?, &mut 0, false, 0)
}
fn named<'a>(nodes: &'a [Directive], name: &str) -> Vec<&'a Directive> {
    nodes.iter().filter(|n| n.words[0] == name).collect()
}
fn dump_files(dump: &str) -> Result<BTreeMap<PathBuf, String>> {
    let mut files = BTreeMap::new();
    let mut path = None;
    let mut source = String::new();
    for line in dump.split_inclusive('\n') {
        if let Some(p) = line
            .trim_end()
            .strip_prefix("# configuration file ")
            .and_then(|p| p.strip_suffix(':'))
        {
            if let Some(p) = path.take() {
                files.insert(p, std::mem::take(&mut source));
            }
            let p = PathBuf::from(p);
            if !p.is_absolute() {
                return Err("nginx dump contains a relative configuration path".into());
            }
            path = Some(p);
        } else if path.is_some() {
            source.push_str(line);
        }
    }
    if let Some(p) = path {
        files.insert(p, source);
    }
    if files.is_empty() {
        return Err("nginx -T returned no configuration files".into());
    }
    Ok(files)
}

#[derive(Clone, Serialize)]
pub struct NginxSite {
    pub id: String,
    pub domains: Vec<String>,
    pub listen: Vec<String>,
    pub file: String,
    pub upstream: Option<String>,
    #[serde(skip)]
    proxy_host: Option<String>,
    pub supported: bool,
    pub reason: Option<String>,
    pub mode: String,
    pub status: String,
    pub fingerprint: String,
    #[serde(skip)]
    source: String,
    #[serde(skip)]
    proxy: Option<Directive>,
    #[serde(skip)]
    headers: Vec<Directive>,
    #[serde(skip)]
    location_headers: bool,
    #[serde(skip)]
    redirect_off: bool,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub running: bool,
    pub sites: Vec<NginxSite>,
}
fn discover_sites(files: &BTreeMap<PathBuf, String>) -> Result<Vec<NginxSite>> {
    fn servers<'a>(
        nodes: &'a [Directive],
        inherited: &[Directive],
        out: &mut Vec<(&'a Directive, Vec<Directive>)>,
    ) {
        let own: Vec<_> = named(nodes, "proxy_set_header")
            .into_iter()
            .cloned()
            .collect();
        let headers = if own.is_empty() {
            inherited.to_vec()
        } else {
            own
        };
        for n in nodes {
            if n.words[0] == "server" && n.children.is_some() {
                out.push((n, headers.clone()));
            } else if n.words[0] == "http" {
                if let Some(kids) = &n.children {
                    servers(kids, &headers, out);
                }
            }
        }
    }
    // Conservatively decline inheritance through includes when HTTP-level proxy
    // settings exist: a standalone server file cannot establish its ancestry.
    let global_proxy_settings = files.values().any(|s| {
        parse(s).ok().is_some_and(|ns| {
            ns.iter().filter(|n| n.words[0] == "http").any(|n| {
                n.children
                    .as_ref()
                    .is_some_and(|cs| cs.iter().any(|c| c.words[0].starts_with("proxy_")))
            })
        })
    });
    let groups = upstream_groups(files);
    let mut rows = Vec::new();
    for (path, source) in files {
        let ns = parse(source)?;
        let mut found = Vec::new();
        servers(&ns, &[], &mut found);
        for (ordinal, (server, inherited)) in found.iter().enumerate() {
            let id = format!(
                "nginx-{}",
                hash_content(&format!("{}:{ordinal}", path.display()))
            );
            let kids = server.children.as_ref().unwrap();
            let mut domains: Vec<String> = named(kids, "server_name")
                .iter()
                .flat_map(|n| n.words[1..].to_vec())
                .collect();
            if domains.is_empty() {
                domains.push("_".into());
            }
            let listen = named(kids, "listen")
                .iter()
                .map(|n| n.words[1..].join(" "))
                .collect();
            let locations = named(kids, "location");
            let loc = locations
                .iter()
                .find(|n| n.words == ["location", "/"] || n.words == ["location", "^~", "/"]);
            let lk = loc.and_then(|n| n.children.as_deref()).unwrap_or(&[]);
            let proxies = named(lk, "proxy_pass");
            let proxy = proxies.first().copied().cloned();
            let upstream = proxy.as_ref().and_then(|n| n.words.get(1)).cloned();
            let resolved = upstream.as_deref().map(|u| resolve_upstream(u, &groups));
            let own_headers: Vec<_> = named(lk, "proxy_set_header").into_iter().cloned().collect();
            let server_headers: Vec<_> = named(kids, "proxy_set_header")
                .into_iter()
                .cloned()
                .collect();
            let headers = if !own_headers.is_empty() {
                own_headers.clone()
            } else if !server_headers.is_empty() {
                server_headers
            } else {
                inherited.clone()
            };
            // 首因可见：每个检查只在还没有更早的原因时才写入。
            let mut reason = None;
            if proxy.is_none() {
                reason =
                    Some("该 server 块没有 proxy_pass 转发（跳转/ACME/静态站点），不是 WAF 接入对象".into());
            }
            if reason.is_none()
                && headers.iter().any(|h| {
                    h.words.iter().any(|w| {
                        w.contains("$proxy_host")
                            || w.contains("$proxy_port")
                            || w.contains("${proxy_host}")
                            || w.contains("${proxy_port}")
                    })
                })
            {
                reason = Some(
                    "转发头使用 $proxy_host/$proxy_port，修改上游会改变语义，请手动接入".into(),
                );
            }
            if reason.is_none()
                && ns.iter().filter(|n| n.words[0] == "http").any(|n| {
                    n.children.as_ref().is_some_and(|cs| {
                        cs.iter().any(|c| {
                            (c.words[0].starts_with("proxy_") && c.words[0] != "proxy_set_header")
                                || ["rewrite", "if", "set"].contains(&c.words[0].as_str())
                        })
                    })
                })
            {
                reason = Some("HTTP 层包含复杂代理设置，需要手动接入".into());
            }
            if reason.is_none()
                && (locations.len() != 1 || loc.is_none() || proxies.len() != 1)
            {
                // 其余 location 留在 Nginx 层不经过 WAF，用户会误以为整站已受保护。
                reason = Some(
                    "自动接入仅支持恰好一个 location / 且其中仅一个静态 proxy_pass；其他 location 不经过 WAF，请合并或手动接入".into(),
                );
            }
            if reason.is_none()
                && global_proxy_settings
                && ns.iter().any(|n| n.words[0] == "server")
            {
                reason = Some("HTTP 层包含代理设置，无法安全确定 include 继承关系".into());
            }
            // Any routing, code/module hook, cache, or nested location needs manual onboarding.
            let safe_location = [
                "proxy_pass",
                "proxy_set_header",
                "proxy_http_version",
                "proxy_read_timeout",
                "proxy_send_timeout",
                "proxy_connect_timeout",
                "proxy_buffering",
                "proxy_buffers",
                "proxy_buffer_size",
                "client_max_body_size",
                "access_log",
                "error_log",
                "add_header",
                "proxy_request_buffering",
                "proxy_redirect",
            ];
            if reason.is_none()
                && (lk.iter().any(|n| {
                    n.children.is_some()
                        || !safe_location.contains(&n.words[0].as_str())
                        || (n.words[0] == "proxy_redirect"
                            && n.words != ["proxy_redirect", "off"])
                }) || kids.iter().any(|n| {
                    [
                        "include",
                        "rewrite",
                        "if",
                        "set",
                        "try_files",
                        "error_page",
                        "return",
                    ]
                    .contains(&n.words[0].as_str())
                        || n.words[0].contains("_by_lua")
                        || n.words[0].starts_with("js_")
                        || (n.words[0].starts_with("proxy_") && n.words[0] != "proxy_set_header")
                }))
            {
                reason = Some("存在 include、重写、缓存或其他复杂指令，需要手动接入".into());
            }
            if reason.is_none() {
                if let Some(Err(msg)) = &resolved {
                    reason = Some(msg.clone());
                }
            }
            if reason.is_none()
                && headers.iter().any(|h| {
                h.words
                    .get(1)
                    .is_some_and(|k| k.eq_ignore_ascii_case(ROUTE_HEADER))
                    || (h
                        .words
                        .get(1)
                        .is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-For"))
                        && h.words.get(2).is_none_or(|v| {
                            !["$remote_addr", "$proxy_add_x_forwarded_for"].contains(&v.as_str())
                        }))
                    || (h
                        .words
                        .get(1)
                        .is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-Proto"))
                        && h.words
                            .get(2)
                            .is_none_or(|v| !["$scheme", "http", "https"].contains(&v.as_str())))
            }) {
                reason = Some("内部路由头或自定义客户端来源头需要手动接入".into());
            }
            let (resolved_upstream, proxy_host) = match &resolved {
                Some(Ok((u, h))) => (Some(u.clone()), Some(h.clone())),
                _ => (upstream.clone(), None),
            };
            rows.push(NginxSite {
                id,
                domains,
                listen,
                file: path.display().to_string(),
                upstream: resolved_upstream,
                proxy_host,
                supported: reason.is_none(),
                reason,
                mode: "off".into(),
                status: "discovered".into(),
                fingerprint: hash_content(source),
                source: source.clone(),
                proxy,
                headers,
                location_headers: !own_headers.is_empty(),
                redirect_off: named(lk, "proxy_redirect")
                    .iter()
                    .any(|n| n.words == ["proxy_redirect", "off"]),
            });
        }
    }
    Ok(rows)
}
/// nginx -T 全量配置里的 `upstream` 组：组名 -> (server 地址， 是否不可安全接管)。
/// down/backup 标记与 unix socket 都让该组不可自动解析。
fn upstream_groups(files: &BTreeMap<PathBuf, String>) -> BTreeMap<String, Vec<(String, bool)>> {
    let mut out = BTreeMap::new();
    for source in files.values() {
        let Ok(ns) = parse(source) else { continue };
        let mut walk: Vec<&Directive> = ns.iter().collect();
        // upstream 组与 http{} 平级或嵌套在 http{} 内，两种形态都收。
        walk.extend(ns.iter().filter_map(|n| n.children.as_deref()).flatten());
        for node in walk {
            if node.words[0] != "upstream" || node.words.len() != 2 {
                continue;
            }
            let Some(kids) = node.children.as_deref() else { continue };
            let entry: &mut Vec<(String, bool)> = out.entry(node.words[1].clone()).or_default();
            for s in kids.iter().filter(|n| n.words[0] == "server" && n.words.len() >= 2) {
                let flagged = s.words[1].starts_with("unix:")
                    || s.words[2..].iter().any(|w| w == "down" || w == "backup");
                entry.push((s.words[1].clone(), flagged));
            }
        }
    }
    out
}

/// 把 proxy_pass 的上游解析为可转发字面量，返回 (带 scheme 的上游， nginx $proxy_host)。
/// 命名上游组只接受恰好一台非 backup/down 的 server，否则负载均衡/故障转移语义会变。
fn resolve_upstream(
    u: &str,
    groups: &BTreeMap<String, Vec<(String, bool)>>,
) -> std::result::Result<(String, String), String> {
    let Some((scheme, rest)) = u.split_once("://") else {
        return Err("只支持 http:// 或 https:// 上游".into());
    };
    if scheme != "http" && scheme != "https" {
        return Err("只支持 http:// 或 https:// 上游".into());
    }
    if rest.is_empty() || rest.contains(['/', '$', '@', '\\', '"', '\'', '?', '#']) {
        return Err(
            "只支持 http://主机:端口 字面上游或单服务器 upstream 组，URI 后缀和变量不支持".into(),
        );
    }
    if let Some(servers) = groups.get(rest) {
        let usable = servers
            .first()
            .filter(|(_addr, flagged)| servers.len() == 1 && !*flagged)
            .map(|(addr, _)| addr.clone());
        let Some(mut addr) = usable else {
            return Err(
                "上游组需恰好一台非 backup/down 的 server 才能自动接入".into(),
            );
        };
        // nginx 上游 server 缺省端口是 80。
        let has_port = if addr.starts_with('[') {
            addr.contains("]:")
        } else {
            addr.contains(':')
        };
        if !has_port {
            addr.push_str(":80");
        }
        return Ok((format!("{scheme}://{addr}"), rest.to_string()));
    }
    if rest.contains(':') {
        return u.parse::<http::Uri>()
            .ok()
            .filter(|parsed| parsed.authority().is_some())
            .map(|_| (u.to_string(), rest.to_string()))
            .ok_or_else(|| "上游地址无法解析".into());
    }
    Err("无端口字面上游会被当成 DNS 主机名；请显式写端口或定义 upstream 组".into())
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    id: String,
    instance: Instance,
    file: PathBuf,
    original: String,
    injected: String,
    phase: String,
    original_hash: String,
    upstream: String,
    listener: String,
}
fn journal_path(state: &AgentState, id: &str) -> Result<PathBuf> {
    if !id.starts_with("nginx-")
        || id.len() != 22
        || !id[6..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid nginx site id".into());
    }
    Ok(state
        .effective()
        .agent
        .data_dir()
        .join("nginx")
        .join(format!("{id}.json")))
}
fn load_journal(state: &AgentState, id: &str) -> Result<Option<Journal>> {
    match fs::read(journal_path(state, id)?) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn atomic_write(path: &Path, content: &[u8], private: bool) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let parent = path.parent().ok_or("file has no parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(
        ".rooster-{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let outcome = (|| {
        let mode = if private {
            0o600
        } else {
            fs::metadata(path)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o777
        };
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        if !private {
            use std::os::unix::fs::MetadataExt;
            let m = fs::metadata(path).map_err(|e| e.to_string())?;
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(f.as_raw_fd(), m.uid(), m.gid()) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            f.set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|e| e.to_string())?;
        }
        f.write_all(content)
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(tmp);
    }
    outcome
}
fn save_journal(state: &AgentState, j: &Journal) -> Result<()> {
    atomic_write(
        &journal_path(state, &j.id)?,
        &serde_json::to_vec(j).map_err(|e| e.to_string())?,
        true,
    )
}

pub fn snapshot(state: &AgentState) -> Result<Snapshot> {
    let instance = Instance::discover()?;
    let files = dump_files(&instance.command(&["-T"])?)?;
    let mut sites = discover_sites(&files)?;
    let eff = state.effective();
    for row in &mut sites {
        if let Some(j) = load_journal(state, &row.id)? {
            let current = fs::read_to_string(&j.file).map_err(|e| e.to_string())?;
            let site = eff.sites.iter().find(|s| s.id == row.id);
            let in_location = row.proxy.as_ref().is_some_and(|p| {
                current
                    .find(&j.injected)
                    .is_some_and(|start| p.start >= start && p.end <= start + j.injected.len())
            });
            let restored = current.replacen(&j.injected, &j.original, 1);
            let context_supported =
                discover_sites(&BTreeMap::from([(PathBuf::from(&row.file), restored)]))
                    .ok()
                    .is_some_and(|rows| rows.iter().any(|s| s.id == row.id && s.supported));
            let attached = in_location
                && context_supported
                && j.phase == "active"
                && current.matches(&j.injected).count() == 1
                && site.is_some_and(|s| {
                    s.upstream == j.upstream
                        && s.waf.as_ref().is_some_and(|w| w.mode != WafMode::Off)
                })
                && eff.plugins.http_guard.enabled
                && eff
                    .plugins
                    .http_guard
                    .listen_http
                    .is_some_and(|a| a.to_string() == j.listener)
                && state
                    .httpguard
                    .stats()
                    .iter()
                    .any(|s| s["id"] == row.id && s["listening_http"] == true);
            row.upstream = site.map(|s| s.upstream.clone()).or(row.upstream.clone());
            row.status = if attached {
                "attached"
            } else {
                "needs-recovery"
            }
            .into();
            row.mode = site
                .and_then(|s| s.waf.as_ref())
                .map(|w| mode_name(w.mode))
                .unwrap_or("off")
                .into();
            row.supported = false;
            row.reason = if attached {
                None
            } else {
                Some("接入记录与配置不一致，请恢复后重新扫描".into())
            };
        }
        if !instance.running && row.status == "discovered" {
            row.supported = false;
            row.reason = Some("Nginx 未运行，不能自动接入".into());
        }
    }
    // Deleted/moved configurations must still offer recovery, rather than silently disappear.
    let dir = state.effective().agent.data_dir().join("nginx");
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        {
            let j: Journal =
                serde_json::from_slice(&fs::read(e.path()).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            if !sites.iter().any(|s| s.id == j.id) {
                sites.push(NginxSite {
                    id: j.id,
                    domains: vec![],
                    listen: vec![],
                    file: j.file.display().to_string(),
                    upstream: None,
                    proxy_host: None,
                    supported: false,
                    reason: Some("原站点已移动或删除，请检查接入备份".into()),
                    mode: "off".into(),
                    status: "needs-recovery".into(),
                    fingerprint: String::new(),
                    source: String::new(),
                    proxy: None,
                    headers: vec![],
                    location_headers: false,
                    redirect_off: false,
                });
            }
        }
    }
    Ok(Snapshot {
        running: instance.running,
        sites,
    })
}
fn mode_name(mode: WafMode) -> &'static str {
    match mode {
        WafMode::Off => "off",
        WafMode::Detect => "detect",
        WafMode::Block => "block",
    }
}
fn patch(raw: &str, path: &[Seg], key: &str, value: &Value) -> Result<String> {
    let mut full = path.to_vec();
    full.push(Seg::K(key));
    if writer::subtree_exists(raw, &full).map_err(|e| e.to_string())? {
        writer::replace_subtree(raw, &full, value)
    } else {
        writer::add_key(raw, path, key, value)
    }
    .map_err(|e| e.to_string())
}
fn config_with_site(raw: &str, site: &Site, listener: &str) -> Result<String> {
    let (file, eff) = rooster_config::parse_and_validate(raw).map_err(|e| e.to_string())?;
    let mut sites = file.managed.sites;
    sites.retain(|s| s.id != site.id);
    sites.push(site.clone());
    let mut out = patch(
        raw,
        &[Seg::K("managed")],
        "sites",
        &serde_json::to_value(sites).map_err(|e| e.to_string())?,
    )?;
    let mut guard = eff.plugins.http_guard;
    guard.enabled = true;
    guard.listen_http = Some(listener.parse().map_err(|_| "invalid listener")?);
    if !guard.trusted_proxies.iter().any(|s| s == "127.0.0.1/32") {
        guard.trusted_proxies.push("127.0.0.1/32".into());
    }
    out = patch(
        &out,
        &[Seg::K("managed"), Seg::K("plugins")],
        "http-guard",
        &serde_json::to_value(guard).map_err(|e| e.to_string())?,
    )?;
    rooster_config::parse_and_validate(&out).map_err(|e| e.to_string())?;
    Ok(out)
}
fn quoted(word: &str) -> String {
    format!("\"{}\"", word.replace('"', "\\\""))
}
fn injection(row: &NginxSite, listener: &str) -> Result<String> {
    // 命名上游组的 nginx $proxy_host 是组名而非解析后的地址，
    // 后端常按 Host 路由，必须原样保留。
    let proxy_host = row.proxy_host.as_deref().ok_or("no upstream")?;
    let scheme = row
        .upstream
        .as_deref()
        .and_then(|u| u.split("://").next())
        .unwrap_or("http");
    let mut out = format!(
        "# rooster-waf begin {}\nproxy_pass http://{listener};\n",
        row.id
    );
    // Materialize inherited headers before adding any header at location level:
    // Nginx stops inheriting the entire proxy_set_header array at that point.
    if !row.location_headers {
        for h in &row.headers {
            if h.words.get(1).is_some_and(|k| {
                k.eq_ignore_ascii_case(ROUTE_HEADER)
                    || k.eq_ignore_ascii_case("X-Forwarded-For")
                    || k.eq_ignore_ascii_case("X-Forwarded-Proto")
            }) {
                continue;
            }
            out.push_str(
                row.source
                    .get(h.start..h.end)
                    .ok_or("inherited header offsets changed")?,
            );
            out.push('\n');
        }
    }
    if row.headers.iter().any(|h| {
        h.words
            .get(1)
            .is_some_and(|k| k.eq_ignore_ascii_case(ROUTE_HEADER))
    }) {
        return Err("X-Rooster-Site is reserved for managed onboarding".into());
    }
    if !row.headers.iter().any(|h| {
        h.words
            .get(1)
            .is_some_and(|k| k.eq_ignore_ascii_case("Host"))
    }) {
        out.push_str(&format!(
            "proxy_set_header Host {};\n",
            quoted(proxy_host)
        ));
    }
    // Preserve Nginx's original implicit redirect mapping after changing proxy_pass.
    // Explicit proxy_redirect off is tracked separately by the discovery row.
    if !row.redirect_off {
        // nginx 隐式 proxy_redirect 以 $proxy_host 为基准：字面上游是 host:port，
        // 命名上游组是组名。
        out.push_str(&format!("proxy_redirect {scheme}://{proxy_host}/ /;\n"));
    }
    out.push_str(&format!(
        "proxy_set_header {ROUTE_HEADER} {};\n",
        quoted(&row.id)
    ));
    if !row.location_headers
        || !row.headers.iter().any(|h| {
            h.words
                .get(1)
                .is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-For"))
        })
    {
        out.push_str("proxy_set_header X-Forwarded-For $remote_addr;\n");
    }
    if !row.location_headers
        || !row.headers.iter().any(|h| {
            h.words
                .get(1)
                .is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-Proto"))
        })
    {
        out.push_str("proxy_set_header X-Forwarded-Proto $scheme;\n");
    }
    out.push_str(&format!("# rooster-waf end {}\n", row.id));
    Ok(out)
}

/// Runs on a blocking worker. Configuration commits use short write-lock scopes
/// and compare the original content; no runtime thread waits on a long-held lock.
pub fn change(
    state: Arc<AgentState>,
    id: String,
    mode: WafMode,
    fingerprint: Option<String>,
    rt: tokio::runtime::Handle,
) -> Result<Value> {
    let _serial = state.nginx_lock.lock().map_err(|_| "nginx lock poisoned")?;
    let raw = fs::read_to_string(&state.config_path).map_err(|e| e.to_string())?;
    if let Some(j) = load_journal(&state, &id)? {
        if mode == WafMode::Off {
            return detach(&state, j, &raw, &rt);
        }
        if j.phase != "active"
            || fs::read_to_string(&j.file)
                .map_err(|e| e.to_string())?
                .matches(&j.injected)
                .count()
                != 1
        {
            return Err("configuration drift detected; restore before changing WAF mode".into());
        }
        if !snapshot(&state)?
            .sites
            .iter()
            .any(|s| s.id == id && s.status == "attached")
        {
            return Err("site routing or runtime changed; restore before changing WAF mode".into());
        }
        let mut site = state
            .effective()
            .sites
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("Rooster site missing; restore first")?;
        site.waf.get_or_insert_with(Default::default).mode = mode;
        let listener = state
            .effective()
            .plugins
            .http_guard
            .listen_http
            .ok_or("listener missing")?
            .to_string();
        let new_raw = config_with_site(&raw, &site, &listener)?;
        if let Err(e) = apply(&state, &raw, &new_raw, &rt)
            .and_then(|_| verify(&state, &id, &listener, mode, &rt))
        {
            let rollback = rollback_config(&state, &new_raw, &raw, &rt);
            return Err(format!("{e}; rollback: {rollback:?}"));
        }
        return Ok(json!({"id": id, "mode": mode_name(mode), "status": "attached"}));
    }
    if mode == WafMode::Off {
        return Err("site is not attached".into());
    }
    let instance = Instance::discover()?;
    if !instance.running {
        return Err("Nginx is not running".into());
    }
    let files = dump_files(&instance.command(&["-T"])?)?;
    let row = discover_sites(&files)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or("site no longer exists; rescan")?;
    if !row.supported {
        return Err(row.reason.unwrap_or("unsupported site".into()));
    }
    if fingerprint.as_deref() != Some(row.fingerprint.as_str()) {
        return Err("Nginx config changed since the displayed scan; rescan before enabling".into());
    }
    let path = fs::canonicalize(&row.file).map_err(|e| e.to_string())?;
    let source = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    // nginx -T inserts a separating newline; trim only that known suffix.
    if source != row.source && format!("{source}\n") != row.source {
        return Err("Nginx config changed during scan; rescan".into());
    }
    let (_, eff) = rooster_config::parse_and_validate(&raw).map_err(|e| e.to_string())?;
    if eff.sites.iter().any(|s| s.id == id) {
        return Err("Rooster site id already exists".into());
    }
    let listener = if eff.plugins.http_guard.enabled {
        if eff.plugins.http_guard.listen_https.is_some() {
            return Err("automatic onboarding requires a dedicated HTTP-only loopback guard; existing HTTPS guard needs manual integration".into());
        }
        let addr = eff
            .plugins
            .http_guard
            .listen_http
            .ok_or("existing HTTP guard has no HTTP listener")?;
        if addr.ip() != "127.0.0.1".parse::<std::net::IpAddr>().unwrap() || addr.port() == 0 {
            return Err("existing HTTP guard must use a fixed IPv4 loopback listener".into());
        }
        addr.to_string()
    } else {
        if !eff.sites.is_empty() {
            return Err(
                "HTTP guard disabled with existing sites; configure it explicitly first".into(),
            );
        }
        let reserve = std::net::TcpListener::bind(LISTEN).map_err(|_| {
            "127.0.0.1:18080 is occupied; configure a free loopback HTTP guard port"
        })?;
        drop(reserve);
        LISTEN.into()
    };
    let authority = row
        .upstream
        .as_ref()
        .and_then(|u| u.parse::<http::Uri>().ok())
        .and_then(|u| u.authority().cloned())
        .ok_or("invalid upstream")?;
    let loopback = authority.host().eq_ignore_ascii_case("localhost")
        || authority
            .host()
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback());
    if loopback
        && authority.port_u16()
            == listener
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|a| a.port())
    {
        return Err("upstream would form a proxy loop".into());
    }
    let proxy = row.proxy.as_ref().ok_or("no proxy_pass")?;
    let original = source
        .get(proxy.start..proxy.end)
        .ok_or("configuration offsets changed")?
        .to_string();
    let injected = injection(&row, &listener)?;
    let changed = format!(
        "{}{}{}",
        &source[..proxy.start],
        injected,
        &source[proxy.end..]
    );
    // https 上游默认 skip-verify：nginx 本就不校验上游证书，接入不应
    // 改变现有转发语义（内网自签源站若无此项会直接 502）。
    let skip_verify = row
        .upstream
        .as_deref()
        .is_some_and(|u| u.starts_with("https://"));
    let site: Site = serde_json::from_value(json!({"id": id, "server-names": row.domains, "tls": {"mode": "terminate", "skip-verify": skip_verify}, "upstream": row.upstream, "waf": {"mode": mode_name(mode)}})).map_err(|e| e.to_string())?;
    let new_raw = config_with_site(&raw, &site, &listener)?;
    if fs::read_to_string(&state.config_path).map_err(|e| e.to_string())? != raw {
        return Err("Rooster config changed during preparation; retry".into());
    }
    // The original complete file remains as a private recovery backup.
    let backup = journal_path(&state, &id)?.with_extension("conf.backup");
    atomic_write(&backup, source.as_bytes(), true)?;
    let mut j = Journal {
        id: id.clone(),
        instance,
        file: path,
        original,
        injected,
        phase: "prepared".into(),
        original_hash: hash_content(&source),
        upstream: site.upstream.clone(),
        listener: listener.clone(),
    };
    save_journal(&state, &j)?;
    let outcome = (|| {
        apply(&state, &raw, &new_raw, &rt)?;
        verify(&state, &id, &listener, mode, &rt)?;
        if fs::read_to_string(&j.file).map_err(|e| e.to_string())? != source {
            return Err("Nginx configuration changed; aborted".into());
        }
        atomic_write(&j.file, changed.as_bytes(), false)?;
        j.instance.reload()?;
        j.phase = "active".into();
        save_journal(&state, &j)?;
        Ok(json!({"id": id, "mode": mode_name(mode), "status": "attached"}))
    })();
    if let Err(e) = outcome {
        let ng = if fs::read_to_string(&j.file).is_ok_and(|s| s == source) {
            Ok(()) // No Nginx write occurred, so no reload is needed.
        } else {
            restore_fragment(&j).and_then(|_| j.instance.reload())
        };
        let cfg = if ng.is_ok() {
            rollback_config(&state, &new_raw, &raw, &rt)
        } else {
            Err("Rooster route retained because Nginx rollback could not be verified; restore from the journal".into())
        };
        if ng.is_ok() && cfg.is_ok() {
            let _ = fs::remove_file(journal_path(&state, &id)?);
        }
        return Err(format!(
            "{e}; Nginx rollback: {ng:?}; Rooster rollback: {cfg:?}"
        ));
    }
    outcome
}
fn apply(
    state: &Arc<AgentState>,
    expected: &str,
    raw: &str,
    rt: &tokio::runtime::Handle,
) -> Result<()> {
    let eff = {
        let _write = state
            .write_lock
            .lock()
            .map_err(|_| "config lock poisoned")?;
        if fs::read_to_string(&state.config_path).map_err(|e| e.to_string())? != expected {
            return Err(
                "Rooster configuration changed during the operation; recovery record retained"
                    .into(),
            );
        }
        state.commit_raw(raw).map_err(|e| e.to_string())?
    };
    rt.block_on(crate::bans::ensure_httpguard(state, &eff));
    state.push_event(rooster_proto::Event::ConfigChanged {
        hash: state.current_hash(),
    });
    Ok(())
}
fn rollback_config(
    state: &Arc<AgentState>,
    changed: &str,
    original: &str,
    rt: &tokio::runtime::Handle,
) -> Result<()> {
    if fs::read_to_string(&state.config_path).map_err(|e| e.to_string())? == original {
        return Ok(());
    }
    apply(state, changed, original, rt)
}
fn verify(
    state: &AgentState,
    id: &str,
    listener: &str,
    mode: WafMode,
    rt: &tokio::runtime::Handle,
) -> Result<()> {
    if !state
        .httpguard
        .stats()
        .iter()
        .any(|s| s["id"] == id && s["listening_http"] == true)
    {
        return Err("Rooster HTTP listener failed to start".into());
    }
    if mode != WafMode::Block {
        return Ok(());
    }
    // First establish that this payload is blocked by the loaded engine. It must
    // never be sent to the business upstream if a custom ruleset permits it.
    use crate::httpguard::RequestInspector;
    let uri = "/?rooster_self_test=%3Cscript%3Ealert(1)%3C/script%3E";
    if !state
        .waf
        .inspect(crate::httpguard::InspectCtx {
            method: "GET",
            uri,
            headers: &[],
            cookies: &[],
            body: b"",
        })
        .blocked
    {
        return Err("loaded rules do not block the self-test; check signatures/threshold".into());
    }
    rt.block_on(async {
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| e.to_string())?
            .get(format!("http://{listener}{uri}"))
            .header(ROUTE_HEADER, id)
            .header("x-rooster-self-test", state.httpguard.probe_token())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status() != reqwest::StatusCode::FORBIDDEN
            || response.text().await.map_err(|e| e.to_string())? != "blocked by waf\n"
        {
            return Err("WAF self-test did not produce a verified block".into());
        }
        Ok(())
    })
}
fn restore_fragment(j: &Journal) -> Result<()> {
    let source = fs::read_to_string(&j.file).map_err(|e| e.to_string())?;
    match source.matches(&j.injected).count() {
        1 => atomic_write(&j.file, source.replacen(&j.injected, &j.original, 1).as_bytes(), false),
        0 if j.phase == "prepared" && hash_content(&source) == j.original_hash => Ok(()),
        _ => Err("injected configuration was edited or removed; recovery backup retained, manual reconciliation required".into()),
    }
}
fn detach(
    state: &Arc<AgentState>,
    mut j: Journal,
    raw: &str,
    rt: &tokio::runtime::Handle,
) -> Result<Value> {
    let current = Instance::discover()?;
    if current.binary != j.instance.binary || current.args != j.instance.args || !current.running {
        return Err(
            "Nginx instance differs from the recorded configuration; restore manually".into(),
        );
    }
    j.instance = current;
    let source = fs::read_to_string(&j.file).map_err(|e| e.to_string())?;
    // Validate exact fragment before preparing changes; preserve other site edits.
    if source.matches(&j.injected).count() != 1
        && !(j.phase == "prepared" && hash_content(&source) == j.original_hash)
    {
        return Err(
            "injection drift detected; use the private .conf.backup to reconcile manually".into(),
        );
    }
    let (mut file, _) = rooster_config::parse_and_validate(raw).map_err(|e| e.to_string())?;
    file.managed.sites.retain(|s| s.id != j.id);
    let new_raw = patch(
        raw,
        &[Seg::K("managed")],
        "sites",
        &serde_json::to_value(file.managed.sites).map_err(|e| e.to_string())?,
    )?;
    let previous_phase = j.phase.clone();
    j.original_hash = hash_content(&source.replacen(&j.injected, &j.original, 1));
    j.phase = "prepared".into();
    save_journal(state, &j)?;
    let outcome = (|| {
        restore_fragment(&j)?;
        j.instance.reload()?;
        apply(state, raw, &new_raw, rt)?;
        fs::remove_file(journal_path(state, &j.id)?).map_err(|e| e.to_string())?;
        Ok(json!({"id": j.id, "mode": "off", "status": "discovered"}))
    })();
    if let Err(e) = outcome {
        let current = fs::read_to_string(&state.config_path).map_err(|e| e.to_string())?;
        if current != raw && current != new_raw {
            return Err(format!(
                "{e}; concurrent Rooster edits preserved, recovery record retained"
            ));
        }
        let restored = source.replacen(&j.injected, &j.original, 1);
        let ng = match fs::read_to_string(&j.file) {
            Ok(content) if content == source => Ok(()),
            Ok(content) if content == restored => {
                atomic_write(&j.file, source.as_bytes(), false).and_then(|_| j.instance.reload())
            }
            _ => Err("concurrent Nginx edits preserved; recovery record retained".into()),
        };
        let cfg = rollback_config(state, &new_raw, raw, rt);
        j.phase = previous_phase;
        let journal = save_journal(state, &j);
        return Err(format!(
            "{e}; Nginx rollback: {ng:?}; Rooster rollback: {cfg:?}; journal: {journal:?}"
        ));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows(source: &str) -> Vec<NginxSite> {
        discover_sites(&BTreeMap::from([(
            PathBuf::from("/etc/nginx/conf.d/app.conf"),
            source.into(),
        )]))
        .unwrap()
    }
    #[test]
    fn discovers_proxy_and_rejects_other_handlers() {
        let r = rows("# header\nserver { listen 443 ssl; server_name a.test b.test; location / { proxy_pass http://127.0.0.1:3000; } }\nserver { listen 80; server_name static.test; location / { root /www; } }");
        assert_eq!(r.len(), 2);
        assert!(r[0].supported);
        assert!(!r[1].supported);
        assert_eq!(r[0].domains, ["a.test", "b.test"]);
    }
    #[test]
    fn excludes_ambiguous_routing_and_upstreams() {
        for conf in ["server { location / { proxy_pass http://backend; } }", "server { location / { proxy_pass http://127.0.0.1:3000/api/; } }", "server { location / { proxy_pass http://$upstream:3000; } }", "server { location / { rewrite ^ /a; proxy_pass http://127.0.0.1:3000; } }", "server { location / { proxy_pass http://127.0.0.1:3000; } location /api { proxy_pass http://127.0.0.1:4000; } }"] { assert!(!rows(conf)[0].supported, "{conf}"); }
    }
    #[test]
    fn inherited_headers_and_comments_are_preserved() {
        let source = "server { proxy_set_header Host $host; proxy_set_header X-Secret 'hello; world'; location / { # proxy_pass fake;\n proxy_pass http://127.0.0.1:3000; } }";
        let r = rows(source);
        let injected = injection(&r[0], LISTEN).unwrap();
        assert!(injected.contains("X-Secret 'hello; world'"));
        assert!(injected.contains("proxy_set_header Host $host;"));
        let p = r[0].proxy.as_ref().unwrap();
        assert_eq!(&source[p.start..p.end], "proxy_pass http://127.0.0.1:3000;");
        assert!(parse(&injected).is_ok());
    }
    #[test]
    fn local_source_headers_are_not_duplicated_and_default_names_are_valid() {
        let source = "server { location / { proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; proxy_pass http://127.0.0.1:3000; } }";
        let r = rows(source);
        assert!(r[0].supported);
        assert_eq!(r[0].domains, ["_"]);
        let injected = injection(&r[0], LISTEN).unwrap();
        assert!(!injected.contains("proxy_set_header X-Forwarded-For"));
        assert!(!injected.contains("proxy_set_header X-Forwarded-Proto"));
        assert!(injected.contains("proxy_redirect http://127.0.0.1:3000/ /;"));
    }
    #[test]
    fn stable_ids_across_injection() {
        let source = "server { location / { proxy_pass http://127.0.0.1:3000; } } server { location / { proxy_pass http://127.0.0.1:4000; } }";
        let before = rows(source);
        let p = before[0].proxy.as_ref().unwrap();
        let new = format!(
            "{}{}{}",
            &source[..p.start],
            injection(&before[0], LISTEN).unwrap(),
            &source[p.end..]
        );
        let after = rows(&new);
        assert_eq!(
            before.iter().map(|s| &s.id).collect::<Vec<_>>(),
            after.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }
    #[test]
    fn dump_does_not_expose_unrelated_file_content() {
        let files = dump_files("# configuration file /etc/nginx/nginx.conf:\nhttp {}\n\n# configuration file /etc/nginx/conf.d/a.conf:\nserver {}\n\n").unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[Path::new("/etc/nginx/nginx.conf")].starts_with("http {}"));
    }
    fn rows_in(files: &[(&str, &str)]) -> Vec<NginxSite> {
        discover_sites(
            &files
                .iter()
                .map(|(p, s)| (PathBuf::from(p), (*s).into()))
                .collect(),
        )
        .unwrap()
    }
    #[test]
    fn single_server_upstream_group_resolves() {
        let r = rows_in(&[
            (
                "/etc/nginx/nginx.conf",
                "http { upstream llm_gateway { server 10.0.0.5:8080; } }",
            ),
            (
                "/etc/nginx/sites-enabled/a.conf",
                "server { listen 443 ssl; server_name api.test; location / { proxy_pass http://llm_gateway; } }",
            ),
        ]);
        assert!(r[0].supported, "{}", r[0].reason.clone().unwrap_or_default());
        assert_eq!(r[0].upstream.as_deref(), Some("http://10.0.0.5:8080"));
        assert_eq!(r[0].proxy_host.as_deref(), Some("llm_gateway"));
        let injected = injection(&r[0], LISTEN).unwrap();
        // $proxy_host 语义保留：Host 与 proxy_redirect 都用组名。
        assert!(injected.contains("proxy_set_header Host \"llm_gateway\";"));
        assert!(injected.contains("proxy_redirect http://llm_gateway/ /;"));
    }
    #[test]
    fn multi_server_or_flagged_upstream_group_is_declined() {
        let base = |group: &str| -> String {
            rows_in(&[
                ("/etc/nginx/nginx.conf", &format!("http {{ upstream g {{ {group} }} }}")),
                (
                    "/etc/nginx/sites-enabled/a.conf",
                    "server { location / { proxy_pass http://g; } }",
                ),
            ])[0]
                .reason
                .clone()
                .unwrap_or_default()
        };
        assert!(base("server 10.0.0.5:8080; server 10.0.0.6:8080;").contains("上游组"));
        assert!(base("server 10.0.0.5:8080 backup;").contains("上游组"));
        assert!(base("server 10.0.0.5:8080 down;").contains("上游组"));
    }
    #[test]
    fn https_upstream_resolves_with_skip_verify_site() {
        let r = rows_in(&[
            (
                "/etc/nginx/nginx.conf",
                "http { upstream firewall_backend { server 10.0.0.9:8443; } }",
            ),
            (
                "/etc/nginx/sites-enabled/f.conf",
                "server { listen 443 ssl; server_name fw.test; location / { proxy_pass https://firewall_backend; } }",
            ),
        ]);
        assert!(r[0].supported);
        assert_eq!(r[0].upstream.as_deref(), Some("https://10.0.0.9:8443"));
        let injected = injection(&r[0], LISTEN).unwrap();
        assert!(injected.contains("proxy_redirect https://firewall_backend/ /;"));
        let literal = rows(
            "server { location / { proxy_pass https://10.0.0.9:8443; } }",
        );
        assert!(literal[0].supported);
        assert_eq!(literal[0].upstream.as_deref(), Some("https://10.0.0.9:8443"));
        assert_eq!(literal[0].proxy_host.as_deref(), Some("10.0.0.9:8443"));
    }
    #[test]
    fn first_blocking_reason_wins_over_later_checks() {
        let r = rows_in(&[
            (
                "/etc/nginx/nginx.conf",
                "http { upstream g { server 10.0.0.5:8080; } }",
            ),
            (
                "/etc/nginx/sites-enabled/a.conf",
                "server { location / { proxy_pass http://g; } location /api { return 204; } }",
            ),
        ]);
        assert_eq!(
            r[0].reason.as_deref(),
            Some(
                "自动接入仅支持恰好一个 location / 且其中仅一个静态 proxy_pass；其他 location 不经过 WAF，请合并或手动接入"
            )
        );
    }
    #[test]
    fn proxyless_redirect_block_reports_itself() {
        let r = rows(
            "server { listen 80; server_name x.test; return 301 https://x.test$request_uri; }",
        );
        assert!(!r[0].supported);
        assert!(
            r[0].reason.as_deref().is_some_and(|s| s.contains("没有 proxy_pass")),
            "reason={:?}",
            r[0].reason
        );
    }
}

/// Generic site edits/deletions must not orphan an Nginx injection.
pub fn is_managed(state: &AgentState, id: &str) -> bool {
    id.starts_with("nginx-") && journal_path(state, id).is_ok_and(|p| p.exists())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::management::auth::AuthGate;
    use rooster_config::{ConfigWriter, WatcherState};
    struct Fixture {
        dir: PathBuf,
        nginx: std::process::Child,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.nginx.kill();
            let _ = self.nginx.wait();
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    async fn change_async(state: Arc<AgentState>, row: &NginxSite, mode: WafMode) -> Result<Value> {
        let id = row.id.clone();
        let fingerprint = Some(row.fingerprint.clone());
        let rt = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || change(state, id, mode, fingerprint, rt))
            .await
            .unwrap()
    }
    /// Opt-in because discovery addresses the real host process namespace. CI
    /// runs this test on an isolated runner with a single temporary Nginx master.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn nginx_waf_lifecycle() {
        if std::env::var("ROOSTER_TEST_NGINX").as_deref() != Ok("1") {
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "rooster-nginx-it-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| { let h = h.clone(); async move {
            h.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let headers = req.headers().clone();
            let body = axum::body::to_bytes(req.into_body(), 1024 * 1024).await.unwrap();
            axum::Json(json!({"host": headers.get("host").and_then(|v| v.to_str().ok()), "scheme": headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()), "xff": headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()), "secret": headers.get("x-inherited").and_then(|v| v.to_str().ok()), "observed": headers.get("x-observed-client").and_then(|v| v.to_str().ok()), "route": headers.get("x-rooster-site").and_then(|v| v.to_str().ok()), "body": String::from_utf8_lossy(&body)}))
        }});
        let business = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let port = free_port();
        let source = format!("# preserved comment\nuser root root; worker_processes 1; pid {}/nginx.pid; error_log {}/error.log; events {{ worker_connections 64; }} http {{ access_log off; proxy_set_header Host $host; proxy_set_header X-Inherited 'kept; value'; proxy_set_header X-Observed-Client $remote_addr; server {{ listen 127.0.0.1:{port}; server_name a.test; location / {{ proxy_pass http://{upstream}; }} }} server {{ listen 127.0.0.1:{port}; server_name b.test; location / {{ proxy_pass http://{upstream}; }} }} }}\n", dir.display(), dir.display());
        let conf = dir.join("nginx.conf");
        fs::write(&conf, &source).unwrap();
        let nginx = Command::new("/usr/sbin/nginx")
            .args([
                "-p",
                dir.to_str().unwrap(),
                "-c",
                conf.to_str().unwrap(),
                "-g",
                "daemon off;",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fixture = Fixture {
            dir: dir.clone(),
            nginx,
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(0)
            .build()
            .unwrap();
        let url = format!("http://127.0.0.1:{port}");
        for _ in 0..100 {
            if client
                .get(&url)
                .header("host", "a.test")
                .send()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            client
                .get(&url)
                .header("host", "a.test")
                .send()
                .await
                .is_ok(),
            "Nginx failed to start: {}",
            fs::read_to_string(dir.join("error.log")).unwrap_or_default()
        );
        let guard_port = free_port();
        let raw = format!("local:\n  agent:\n    node-name: nginx-test\n    data-dir: {}\nmanaged:\n  plugins:\n    http-guard:\n      enabled: true\n      listen-http: 127.0.0.1:{guard_port}\n  waf:\n    signatures: [scanner-ua]\n", dir.display());
        let config_path = dir.join("config.yaml");
        fs::write(&config_path, &raw).unwrap();
        let (_, eff) = rooster_config::parse_and_validate(&raw).unwrap();
        let state = Arc::new(AgentState::new(
            config_path.clone(),
            ConfigWriter::new(&config_path, &dir),
            Arc::new(WatcherState::new(hash_content(&raw))),
            eff,
            AuthGate::new(String::new()),
        ));
        state.httpguard.set_inspector(state.waf.clone());
        let events = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let event_count = events.clone();
        state.httpguard.set_event_sink(Arc::new(move |_| {
            event_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        let snapshot_state = state.clone();
        let scanned = tokio::task::spawn_blocking(move || snapshot(&snapshot_state))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(scanned.sites.len(), 2);
        assert!(scanned.sites.iter().all(|s| s.supported));
        // Failed block self-test rolls both configs back and leaves no active journal.
        let error = change_async(state.clone(), &scanned.sites[0], WafMode::Block)
            .await
            .unwrap_err();
        assert!(error.contains("self-test"), "{error}");
        assert_eq!(fs::read_to_string(&conf).unwrap(), source);
        assert_eq!(fs::read_to_string(&config_path).unwrap(), raw);
        assert!(load_journal(&state, &scanned.sites[0].id)
            .unwrap()
            .is_none());
        let raw = raw.replace("signatures: [scanner-ua]", "signatures: []");
        let eff = state.commit_raw(&raw).unwrap();
        crate::bans::ensure_httpguard(&state, &eff).await;
        change_async(state.clone(), &scanned.sites[0], WafMode::Block)
            .await
            .unwrap();
        // Repeated enable changes mode rather than adding a second injection.
        change_async(state.clone(), &scanned.sites[0], WafMode::Block)
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(&conf)
                .unwrap()
                .matches("# rooster-waf begin")
                .count(),
            1
        );
        assert_eq!(
            events.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "self-tests must not trigger ban policies"
        );
        let (status, _, _) = crate::management::serve_trusted(
            &state,
            "DELETE",
            &format!("/v0/management/sites/{}", scanned.sites[0].id),
            &[],
            &[],
        )
        .await;
        assert_eq!(
            status, 409,
            "managed sites must use restore rather than generic deletion"
        );
        let count = hits.load(std::sync::atomic::Ordering::Relaxed);
        let response = client
            .post(&url)
            .header("host", "a.test")
            .body("<script>alert(1)</script>")
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "body={body}; stats={:?}",
            state.httpguard.stats()
        );
        assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), count);
        assert_eq!(
            events.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "real attacks still produce Block events"
        );
        let normal: Value = client
            .post(&url)
            .header("host", "a.test")
            .header("x-rooster-site", "forged")
            .header("x-forwarded-for", "9.9.9.9")
            .body("hello")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(normal["host"], "a.test");
        assert_eq!(normal["secret"], "kept; value");
        assert!(normal["route"].is_null());
        assert_eq!(normal["body"], "hello");
        let observed = normal["observed"].as_str().unwrap();
        assert_eq!(normal["xff"], format!("{observed}, {observed}"), "{normal}");
        // Trusted front proxy can preserve HTTPS even over the local HTTP hop.
        let local: Value = client
            .get(format!("http://127.0.0.1:{guard_port}/"))
            .header("x-rooster-site", &scanned.sites[0].id)
            .header("x-forwarded-proto", "https")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(local["scheme"], "https");
        // The other virtual host remains unprotected until explicitly enabled.
        assert_eq!(
            client
                .post(&url)
                .header("host", "b.test")
                .body("<script>alert(1)</script>")
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        let snapshot_state = state.clone();
        let current = tokio::task::spawn_blocking(move || snapshot(&snapshot_state))
            .await
            .unwrap()
            .unwrap();
        let b = current
            .sites
            .iter()
            .find(|s| s.domains == ["b.test"])
            .unwrap();
        assert!(
            change_async(state.clone(), &scanned.sites[1], WafMode::Block)
                .await
                .unwrap_err()
                .contains("rescan")
        );
        change_async(state.clone(), b, WafMode::Block)
            .await
            .unwrap();
        let attached_source = fs::read_to_string(&conf).unwrap();
        let j = load_journal(&state, &scanned.sites[0].id).unwrap().unwrap();
        let tampered = attached_source.replacen(
            &j.injected,
            &j.injected.replace("X-Rooster-Site", "X-Changed-Site"),
            1,
        );
        fs::write(&conf, &tampered).unwrap();
        assert!(change_async(state.clone(), &scanned.sites[0], WafMode::Off)
            .await
            .unwrap_err()
            .contains("drift"));
        assert_eq!(fs::read_to_string(&conf).unwrap(), tampered);
        fs::write(&conf, &attached_source).unwrap();
        let extended = attached_source.replace(
            "server_name a.test;",
            "server_name a.test; location /bypass { return 200 unguarded; }",
        );
        fs::write(&conf, &extended).unwrap();
        let snapshot_state = state.clone();
        let drift = tokio::task::spawn_blocking(move || snapshot(&snapshot_state))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            drift
                .sites
                .iter()
                .find(|s| s.id == scanned.sites[0].id)
                .unwrap()
                .status,
            "needs-recovery"
        );
        assert!(change_async(state.clone(), &scanned.sites[0], WafMode::Detect)
            .await
            .unwrap_err()
            .contains("routing or runtime changed"));
        fs::write(&conf, &attached_source).unwrap();
        change_async(state.clone(), &scanned.sites[0], WafMode::Detect)
            .await
            .unwrap();
        assert_eq!(
            client
                .post(&url)
                .header("host", "a.test")
                .body("<script>alert(1)</script>")
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        // Per-fragment restore keeps the second attached site and unrelated comments.
        let modified = format!(
            "{}# external edit retained\n",
            fs::read_to_string(&conf).unwrap()
        );
        fs::write(&conf, &modified).unwrap();
        change_async(state.clone(), &scanned.sites[0], WafMode::Off)
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(&conf)
                .unwrap()
                .matches("# rooster-waf begin")
                .count(),
            1
        );
        assert!(fs::read_to_string(&conf)
            .unwrap()
            .contains("external edit retained"));
        change_async(state.clone(), b, WafMode::Off).await.unwrap();
        assert_eq!(
            fs::read_to_string(&conf).unwrap(),
            format!("{source}# external edit retained\n")
        );
        assert!(state.effective().sites.is_empty());
        state.httpguard.apply(Default::default()).await;
        business.abort();
        drop(fixture);
    }
}
