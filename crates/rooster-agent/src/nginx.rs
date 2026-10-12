//! Local Nginx discovery and transactional onboarding of simple proxy locations.
//! Never accepts a path or command from the remote caller. Nginx owns TLS;
//! Rooster inspects the complete proxy request on a loopback HTTP listener.
use crate::state::AgentState;
use rooster_config::{hash_content, writer, Seg, Site, WafMode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    symbol: Option<u8>,
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
                symbol: Some(b[start]),
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
                match b[i] {
                    b't' => value.push(b'\t'),
                    b'r' => value.push(b'\r'),
                    b'n' => value.push(b'\n'),
                    b'\\' | b'\'' | b'"' => value.push(b[i]),
                    c => {
                        value.push(b'\\');
                        value.push(c);
                    }
                }
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                    i += 1;
                    break;
                }
                value.push(c);
                i += 1;
                continue;
            }
            if i == start && (c == b'\'' || c == b'"') {
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
            if c.is_ascii_whitespace() || b"{;".contains(&c) {
                break;
            }
            value.push(c);
            i += 1;
        }
        if quote.is_some() {
            return Err("unterminated nginx quote".into());
        }
        out.push(Token {
            symbol: None,
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
            if ts[*i].symbol == Some(b'}') {
                if !nested {
                    return Err("unexpected nginx closing brace".into());
                }
                *i += 1;
                return Ok(out);
            }
            let start = ts[*i].start;
            let mut words = Vec::new();
            while *i < ts.len() && ts[*i].symbol.is_none() {
                words.push(ts[*i].value.clone());
                *i += 1;
            }
            if words.is_empty() || *i == ts.len() {
                return Err("incomplete nginx directive".into());
            }
            let children = match ts[*i].symbol {
                Some(b';') => {
                    *i += 1;
                    None
                }
                Some(b'{') => {
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

/// 一个可接管 location 的接入计划(多 location 站点每个各一份)。
/// 不序列化;面板展示用 NginxSite 上的汇总字段。
#[derive(Clone)]
struct LocPlan {
    /// 在 server 块内 location 列表中的序号(生成子站点 id 用,重扫稳定)。
    ordinal: usize,
    /// 面板展示用的 location 声明(如 "location /api")。
    label: String,
    location_path: String,
    /// 该 location 的 proxy_pass 指令(原文 span)。
    proxy: Directive,
    /// 解析后的上游(scheme://host:port,不含 URI 前缀)。
    upstream: String,
    /// nginx $proxy_host(字面量上游是 host:port,命名组是组名)。
    proxy_host: String,
    /// proxy_pass 自带的 URI 前缀(nginx 用它替换 location 前缀)。
    proxy_uri: String,
    /// 该 location 生效的转发头(own → server → http 继承)。
    headers: Vec<Node>,
    /// location 内是否有自己的 proxy_set_header(决定注入时是否物化继承头)。
    own_headers: bool,
    redirect_off: bool,
    proxy_port: String,
    connect_timeout: Duration,
    /// 接入时对原文件的补充改写($proxy_host 字面量化等)。
    fixups: Vec<Fixup>,
}

impl LocPlan {
    /// 对应的 rooster 站点 id:主 location(吮底/首个)直接用块 id,
    /// 其余追加 `-l<ordinal>`,与 journal/mgmt 的托管识别保持一致。
    fn site_id(&self, block_id: &str, primary: bool) -> String {
        if primary {
            block_id.to_string()
        } else {
            format!("{block_id}-l{}", self.ordinal)
        }
    }
}

/// 面板展示用的附加 location 摘要。
#[derive(Clone, Serialize)]
pub struct LocSummary {
    pub location: String,
    pub upstream: String,
}

#[derive(Clone, Serialize)]
pub struct NginxSite {
    pub id: String,
    pub domains: Vec<String>,
    pub listen: Vec<String>,
    pub file: String,
    pub upstream: Option<String>,
    /// 其余可接管 location(主 upstream 之外)的摘要,面板展示用。
    pub extra_locations: Vec<LocSummary>,
    /// 保留在 Nginx、不经过 WAF 的非代理 location 数量(静态文件/ACME 等)。
    pub bypassed_locations: usize,
    #[serde(skip)]
    pub supported: bool,
    pub reason: Option<String>,
    pub mode: String,
    pub status: String,
    pub fingerprint: String,
    #[serde(skip)]
    source: String,
    /// 可接管的 location 计划(有序;首个为主 location)。
    #[serde(skip)]
    locs: Vec<LocPlan>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub running: bool,
    pub sites: Vec<NginxSite>,
}

/// 一条指令及其所在文件原文。include 展开出来的指令也带着来源文件,
/// 这样跨文件继承的 `proxy_set_header` 依然能原样物化。
#[derive(Clone)]
struct Node {
    d: Directive,
    src: Arc<String>,
    /// 由本层的这条 include 引入;直接书写时为 None。
    via: Option<Directive>,
}

impl Node {
    fn words(&self) -> &[String] {
        &self.d.words
    }
    fn name(&self) -> &str {
        &self.words()[0]
    }
    /// 指令原文(保留引号与对齐),物化/改写时按它匹配。
    fn text(&self) -> &str {
        self.src.get(self.d.start..self.d.end).unwrap_or_default()
    }
    fn header_name(&self) -> Option<&str> {
        self.words().get(1).map(String::as_str)
    }
}

fn node_named<'a>(nodes: &'a [Node], name: &str) -> Vec<&'a Node> {
    nodes.iter().filter(|n| n.name() == name).collect()
}

/// nginx 风格通配:`*` 不跨 `/`,`?` 匹配单个字符。
fn glob_match(pat: &str, text: &str) -> bool {
    let (Ok(pat), Ok(text)) = (std::ffi::CString::new(pat), std::ffi::CString::new(text)) else {
        return false;
    };
    unsafe { libc::fnmatch(pat.as_ptr(), text.as_ptr(), libc::FNM_PATHNAME | libc::FNM_PERIOD) == 0 }
}

/// include 目标解析:只在 `nginx -T` 转储出的文件里查找,绝不按调用方给的
/// 路径读磁盘。相对目标按主配置所在目录(即 nginx prefix)展开。
struct Includes {
    files: BTreeMap<PathBuf, Arc<String>>,
    prefix: PathBuf,
}

impl Includes {
    fn resolve(&self, spec: &str) -> Result<Vec<(PathBuf, Arc<String>)>> {
        if spec.is_empty() || spec.contains('$') {
            return Err("include 目标含变量,需要手动接入".into());
        }
        let pat = if spec.starts_with('/') {
            PathBuf::from(spec)
        } else {
            self.prefix.join(spec)
        };
        let pat = pat.to_string_lossy().to_string();
        let wild = pat.contains(['*', '?', '[']);
        let mut hits: Vec<(PathBuf, Arc<String>)> = self
            .files
            .iter()
            .filter(|(p, _)| {
                let p = p.to_string_lossy();
                if wild {
                    glob_match(&pat, &p)
                } else {
                    *p == pat
                }
            })
            .map(|(p, s)| (p.clone(), s.clone()))
            .collect();
        hits.sort();
        if hits.is_empty() && !wild {
            return Err("include 目标不在 nginx -T 转储中,需要手动接入".into());
        }
        Ok(hits)
    }
}

/// HTTP 上下文的代理设置。sites-enabled 下的独立 server 文件本身不含 http{},
/// 必须沿主配置的 include 链确定它到底继承了什么。
struct HttpCtx {
    /// http 层 `proxy_set_header`:server/location 层没有自己的指令时被继承。
    headers: Vec<Node>,
    /// http 层存在 `proxy_set_header` 之外的 proxy_* 指令:接入后它们作用在
    /// Nginx→Rooster 这一跳上,语义会变,只能交给手动接入。
    complex: bool,
    /// 无法建立唯一的 http 上下文(多个 http 块 / 主配置不可辨认)。
    ambiguous: bool,
}

fn http_context(inc: &Includes) -> HttpCtx {
    let mut ctx = HttpCtx {
        headers: Vec::new(),
        complex: false,
        ambiguous: false,
    };
    let mains: Vec<&PathBuf> = inc
        .files
        .iter()
        .filter(|(_, s)| {
            parse(s)
                .ok()
                .is_some_and(|ns| ns.iter().any(|n| n.words[0] == "http"))
        })
        .map(|(p, _)| p)
        .collect();
    // 转储里没有 http{} 时没有可继承的 HTTP 层设置(单文件片段);多个 http{}
    // 时无法判定 server 块属于哪一个,只能手动接入。
    let Some(main) = mains.first().copied() else {
        return ctx;
    };
    if mains.len() > 1 {
        ctx.ambiguous = true;
        return ctx;
    }
    let Ok(ns) = inc.files.get(main).map(|s| parse(s)).unwrap_or_else(|| Err(String::new())) else {
        ctx.ambiguous = true;
        return ctx;
    };
    let Some(http) = ns.iter().find(|n| n.words[0] == "http") else {
        ctx.ambiguous = true;
        return ctx;
    };
    let main_src = inc.files[main].clone();
    let nodes = match expand_scope(http.children.as_deref().unwrap_or(&[]), &main_src, inc, true) {
        Ok(nodes) => nodes,
        Err(_) => {
            ctx.ambiguous = true;
            return ctx;
        }
    };
    for n in nodes {
        if n.name() == "proxy_set_header" {
            ctx.headers.push(n);
        } else if n.name() == "http"
            || (n.name().starts_with("proxy_") && n.name() != "proxy_set_header")
            || (n.d.children.is_none() && mentions_proxy_vars(n.text()))
        {
            ctx.complex = true;
        }
    }
    ctx
}

/// 展开本层 include,返回该层生效的指令列表。目标不可定位、含嵌套块或含
/// 变量时返回 Err,由调用方按复杂配置拒绝。
fn scope(kids: &[Directive], src: &Arc<String>, inc: &Includes) -> Result<Vec<Node>> {
    expand_scope(kids, src, inc, false)
}

fn expand_scope(kids: &[Directive], src: &Arc<String>, inc: &Includes, allow_blocks: bool) -> Result<Vec<Node>> {
    fn walk(
        kids: &[Directive], src: &Arc<String>, inc: &Includes, allow_blocks: bool,
        via: Option<&Directive>, stack: &mut BTreeSet<PathBuf>, budget: &mut usize,
        out: &mut Vec<Node>,
    ) -> Result<()> {
        for d in kids {
            if d.words[0] != "include" {
                if via.is_some() && !allow_blocks && d.children.is_some() {
                    return Err("include 内含块指令,需要手动接入".into());
                }
                out.push(Node { d: d.clone(), src: src.clone(), via: via.cloned() });
                continue;
            }
            let spec = d.words.get(1).ok_or("include 缺少目标,需要手动接入")?;
            for (path, text) in inc.resolve(spec)? {
                if stack.len() >= 64 || !stack.insert(path.clone()) {
                    return Err("include 链循环或超过 64 层,需要手动接入".into());
                }
                *budget = budget.checked_sub(text.len()).ok_or("include 展开超过 4 MiB,需要手动接入")?;
                // Nested includes retain the outer local span, so shared files are never edited.
                walk(&parse(&text)?, &text, inc, allow_blocks, via.or(Some(d)), stack, budget, out)?;
                stack.remove(&path);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    let mut budget = MAX_CONFIG;
    walk(kids, src, inc, allow_blocks, None, &mut BTreeSet::new(), &mut budget, &mut out)?;
    Ok(out)
}

/// 一次事务里对原文件的补充改写(把 `$proxy_host` 字面量化等)。
/// `injected` 自带站点标记,恢复时按文本唯一匹配。
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Fixup {
    start: usize,
    end: usize,
    original: String,
    injected: String,
}

/// `$proxy_host`/`$proxy_port` 的四种书写形式。
const PROXY_VARS: [&str; 4] = ["$proxy_host", "${proxy_host}", "$proxy_port", "${proxy_port}"];

fn mentions_proxy_vars(text: &str) -> bool {
    PROXY_VARS.iter().any(|v| text.contains(v))
}

/// 把变量换成接入前的字面量,其余文本(对齐、引号)原样保留。
fn substitute_proxy_vars(text: &str, host: &str, port: &str) -> String {
    text.replace("${proxy_host}", host)
        .replace("${proxy_port}", port)
        .replace("$proxy_host", host)
        .replace("$proxy_port", port)
}

/// 上游端口(nginx $proxy_port 在缺省端口时给 80/443)。
fn proxy_port(upstream: &str) -> String {
    let uri = upstream.parse::<http::Uri>().ok();
    if let Some(port) = uri.as_ref().and_then(|u| u.port_u16()) {
        return port.to_string();
    }
    if upstream.starts_with("https://") {
        "443"
    } else {
        "80"
    }
    .into()
}

fn inherited_connect_timeout(location: &[Node], server: &[Node]) -> Result<Duration> {
    let directive = node_named(location, "proxy_connect_timeout").first().copied()
        .or_else(|| node_named(server, "proxy_connect_timeout").first().copied());
    let Some(value) = directive.and_then(|n| n.words().get(1)) else {
        return Ok(Duration::from_secs(60));
    };
    let mut rest = value.as_str();
    let mut millis = 0u64;
    while !rest.trim().is_empty() {
        rest = rest.trim_start();
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let number = rest[..digits].parse::<u64>().map_err(|_| "proxy_connect_timeout 无法解析")?;
        rest = &rest[digits..];
        let (scale, suffix) = if rest.starts_with("ms") { (1, 2) }
            else if rest.starts_with('s') { (1000, 1) }
            else if rest.starts_with('m') { (60_000, 1) }
            else if rest.starts_with('h') { (3_600_000, 1) }
            else if rest.starts_with('d') { (86_400_000, 1) }
            else if rest.starts_with('w') { (604_800_000, 1) }
            else if rest.trim().is_empty() { (1000, 0) }
            else { return Err("proxy_connect_timeout 无法解析".into()); };
        millis = number.checked_mul(scale).and_then(|v| millis.checked_add(v))
            .ok_or("proxy_connect_timeout 超出范围")?;
        rest = &rest[suffix..];
    }
    Ok(Duration::from_millis(millis))
}

fn line_indent(source: &str, start: usize) -> String {
    let head = source.get(..start.min(source.len())).unwrap_or_default();
    let line_start = head.rfind('\n').map(|i| i + 1).unwrap_or(0);
    source[line_start..]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// 生效转发头里出现 `$proxy_host`/`$proxy_port` 时,接入后这两个变量会变成回环
/// 守卫地址。把那条指令改写成接入前的字面量;指令来自 include 文件时改写
/// 目标是本层的 include 行(就地展开共享文件),不修改共享文件本身。
fn proxy_host_fixups(
    nodes: &[Node],
    proxy_host: &str,
    port: &str,
    tag: &str,
    source: &str,
) -> Vec<Fixup> {
    let span_of = |n: &Node| match &n.via {
        Some(inc) => (inc.start, inc.end),
        None => (n.d.start, n.d.end),
    };
    let mut out: Vec<Fixup> = Vec::new();
    let mut done: BTreeSet<(usize, usize)> = BTreeSet::new();
    for n in nodes {
        if n.name() != "proxy_set_header" || !mentions_proxy_vars(n.text()) {
            continue;
        }
        let (start, end) = span_of(n);
        if !done.insert((start, end)) {
            continue;
        }
        let Some(range) = source.get(start..end) else {
            continue;
        };
        let indent = line_indent(source, start);
        let mut lines = vec![format!("# rooster-waf host {tag}")];
        for m in nodes.iter().filter(|m| span_of(m) == (start, end)) {
            for line in substitute_proxy_vars(m.text(), proxy_host, port).lines() {
                if !line.trim().is_empty() {
                    lines.push(format!("{indent}{line}"));
                }
            }
        }
        out.push(Fixup {
            start,
            end,
            original: range.to_string(),
            injected: lines.join("\n"),
        });
    }
    out
}

fn discover_sites(files: &BTreeMap<PathBuf, String>) -> Result<Vec<NginxSite>> {
    fn servers<'a>(
        nodes: &'a [Directive],
        inherited: &[Node],
        out: &mut Vec<(&'a Directive, Vec<Node>)>,
    ) {
        for n in nodes {
            if n.words[0] == "server" && n.children.is_some() {
                out.push((n, inherited.to_vec()));
            } else if n.words[0] == "http" {
                if let Some(kids) = &n.children {
                    servers(kids, inherited, out);
                }
            }
        }
    }
    let arc_files: BTreeMap<PathBuf, Arc<String>> = files
        .iter()
        .map(|(p, s)| (p.clone(), Arc::new(s.clone())))
        .collect();
    // 主配置所在目录即 nginx 的 prefix,相对 include 以它为基准。
    let prefix = arc_files
        .keys()
        .find(|p| {
            arc_files
                .get(*p)
                .map(|s| parse(s).ok().is_some_and(|ns| ns.iter().any(|n| n.words[0] == "http")))
                .unwrap_or(false)
        })
        .or_else(|| {
            arc_files
                .keys()
                .find(|p| p.to_string_lossy().ends_with("nginx.conf"))
        })
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/nginx"));
    let inc = Includes {
        files: arc_files,
        prefix,
    };
    let ctx = http_context(&inc);
    let groups = upstream_groups(&inc).unwrap_or_default();
    let fingerprint = hash_content(&serde_json::to_string(files).map_err(|e| e.to_string())?);
    let mut rows = Vec::new();
    for (path, source) in files {
        let file_src = inc
            .files
            .get(path)
            .cloned()
            .unwrap_or_else(|| Arc::new(source.clone()));
        let ns = parse(source)?;
        let mut found = Vec::new();
        servers(&ns, &ctx.headers, &mut found);
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
            let mut server_headers: Vec<Node> = Vec::new();
            let mut server_nodes: Vec<Node> = Vec::new();
            let mut server_scope_err: Option<String> = None;
            let locations: Vec<Node> = match scope(kids, &file_src, &inc) {
                Ok(nodes) => {
                    let found = node_named(&nodes, "location")
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    server_headers = node_named(&nodes, "proxy_set_header")
                        .into_iter()
                        .cloned()
                        .collect();
                    server_nodes = nodes;
                    found
                }
                Err(e) => {
                    server_scope_err = Some(e);
                    Vec::new()
                }
            };
            let catchall = locations
                .iter()
                .position(|n| n.words() == ["location", "/"] || n.words() == ["location", "^~", "/"]);
            // 逐 location 分类：纯代理（可接管，逐个注入）/ 无 proxy_pass
            // （留在 Nginx 不经过 WAF，计数透出）/ 其余（含不支持的指令或上游）
            // 则拒绝。这样常见形态（location / 代理 + /static 静态 + /api 代理
            // 到另一个上游）不再整体拒绝，而量词复杂的 location 仍交给手动接入。
            // Any routing, code/module hook, cache, or nested location needs manual onboarding.
            const SAFE_LOCATION: [&str; 19] = [
                "proxy_pass",
                "proxy_set_header",
                "proxy_http_version",
                "proxy_read_timeout",
                "proxy_send_timeout",
                "proxy_connect_timeout",
                "proxy_buffering",
                "proxy_buffers",
                "proxy_buffer_size",
                "proxy_busy_buffers_size",
                "proxy_max_temp_file_size",
                "proxy_request_buffering",
                "client_max_body_size",
                "client_body_buffer_size",
                "access_log",
                "error_log",
                "add_header",
                "set_header",
                "proxy_redirect",
            ];
            let mut locs: Vec<LocPlan> = Vec::new();
            let mut bypassed = 0usize;
            let mut reason = server_scope_err.clone();
            for (ordinal, l) in locations.iter().enumerate() {
                let label = format!("location {}", l.words()[1..].join(" "));
                if l.via.is_some() {
                    reason = Some(format!("{label} 定义在 include 文件里，需要手动接入"));
                    continue;
                }
                let (lk, include_err) = match scope(l.d.children.as_deref().unwrap_or(&[]), &l.src, &inc) {
                    Ok(nodes) => (nodes, None),
                    Err(e) => (Vec::new(), Some(e)),
                };
                let proxies = node_named(&lk, "proxy_pass");
                if let Some(err) = include_err {
                    if !proxies.is_empty() || reason.is_none() {
                        reason = Some(err);
                    }
                    continue;
                }
                if proxies.is_empty() {
                    if lk.iter().any(|n| {
                        n.d.children.is_some()
                            || ["fastcgi_pass", "grpc_pass", "uwsgi_pass", "scgi_pass", "memcached_pass"].contains(&n.name())
                            || n.name().contains("_by_lua") || n.name().starts_with("js_")
                    }) {
                        reason = Some(format!("{label} 含嵌套块或动态处理，需要手动接入"));
                    } else {
                        bypassed += 1;
                    }
                    continue;
                }
                if reason.is_none() && proxies.len() != 1 {
                    reason = Some(format!("{label} 含多个 proxy_pass，需要手动接入"));
                }
                if reason.is_none()
                    && lk.iter().any(|n| {
                        n.d.children.is_some()
                            || !SAFE_LOCATION.contains(&n.name())
                            || (n.name() == "proxy_redirect"
                                && n.words() != ["proxy_redirect", "off"])
                    })
                {
                    reason = Some(format!(
                        "{label} 含重写、缓存或其他复杂指令，需要手动接入"
                    ));
                }
                if reason.is_some() {
                    continue;
                }
                let proxy = *proxies.first().unwrap();
                if proxy.via.is_some() {
                    reason = Some(format!("{label} 的 proxy_pass 写在 include 文件里，需要手动接入"));
                    continue;
                }
                let own_headers: Vec<Node> = node_named(&lk, "proxy_set_header")
                    .into_iter()
                    .cloned()
                    .collect();
                let headers = if !own_headers.is_empty() {
                    own_headers.clone()
                } else if !server_headers.is_empty() {
                    server_headers.clone()
                } else {
                    inherited.clone()
                };
                let resolved = proxy.words().get(1).map(|u| resolve_upstream(u, &groups));
                if reason.is_none() {
                    if let Some(Err(msg)) = &resolved {
                        reason = Some(msg.clone());
                    }
                }
                let (upstream, proxy_host, proxy_uri) = match &resolved {
                    Some(Ok(r)) => r.clone(),
                    _ => (String::new(), String::new(), String::new()),
                };
                // $proxy_host/$proxy_port 只能出现在 proxy_set_header 里:其余
                // 指令(如 add_header)取值会随 proxy_pass 改变,无法补偿。
                if reason.is_none()
                    && lk.iter().any(|n| {
                        n.name() != "proxy_set_header" && mentions_proxy_vars(n.text())
                    })
                {
                    reason = Some(format!(
                        "{label} 在非 proxy_set_header 指令里使用 $proxy_host/$proxy_port，请手动接入"
                    ));
                }
                if reason.is_none()
                    && headers.iter().any(|h| {
                    h.header_name()
                        .is_some_and(|k| k.eq_ignore_ascii_case(ROUTE_HEADER))
                        || (h
                            .header_name()
                            .is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-For"))
                            && h.words().get(2).is_none_or(|v| {
                                !["$remote_addr", "$proxy_add_x_forwarded_for"].contains(&v.as_str())
                            }))
                        || (h
                            .header_name()
                            .is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-Proto"))
                            && h
                                .words()
                                .get(2)
                                .is_none_or(|v| !["$scheme", "http", "https"].contains(&v.as_str())))
                }) {
                    reason = Some("内部路由头或自定义客户端来源头需要手动接入".into());
                }
                let original_port = proxy_port(proxy.words().get(1).map(String::as_str).unwrap_or_default());
                let connect_timeout = match inherited_connect_timeout(&lk, &server_nodes) {
                    Ok(value) => value,
                    Err(e) => {
                        reason = Some(format!("{label}: {e}"));
                        continue;
                    }
                };
                let fixups = if reason.is_none() {
                    proxy_host_fixups(&lk, &proxy_host, &original_port, &format!("{id}-l{ordinal}"), source)
                } else {
                    Vec::new()
                };
                if reason.is_some() {
                    continue;
                }
                locs.push(LocPlan {
                    ordinal,
                    label,
                    location_path: l.words().last().cloned().unwrap_or_default(),
                    proxy: proxy.d.clone(),
                    upstream,
                    proxy_host,
                    proxy_uri,
                    headers,
                    own_headers: !own_headers.is_empty(),
                    redirect_off: node_named(&lk, "proxy_redirect").first().copied()
                        .or_else(|| node_named(&server_nodes, "proxy_redirect").first().copied())
                        .is_some_and(|n| n.words() == ["proxy_redirect", "off"]),
                    proxy_port: original_port,
                    connect_timeout,
                    fixups,
                });
            }
            if reason.is_none() && locs.is_empty() {
                reason =
                    Some("该 server 块没有 proxy_pass 转发（跳转/ACME/静态站点），不是 WAF 接入对象".into());
            }
            if reason.is_none() && ctx.ambiguous && !locs.is_empty() {
                reason = Some("无法确定 HTTP 层上下文（多个 http 块），需要手动接入".into());
            }
            if reason.is_none() && ctx.complex && !locs.is_empty() {
                reason = Some("HTTP 层包含 proxy_set_header 之外的代理设置，需要手动接入".into());
            }
            // Origin connect timeout is copied into the guard; cache/failover cannot be preserved.
            const SERVER_SAFE_PROXY: [&str; 11] = [
                "proxy_http_version",
                "proxy_connect_timeout",
                "proxy_send_timeout",
                "proxy_read_timeout",
                "proxy_buffering",
                "proxy_buffers",
                "proxy_buffer_size",
                "proxy_busy_buffers_size",
                "proxy_max_temp_file_size",
                "proxy_request_buffering",
                "proxy_redirect",
            ];
            if reason.is_none() {
                let bad = server_nodes.iter().find(|n| {
                    let proxy_unsafe = n.name().starts_with("proxy_")
                        && n.name() != "proxy_set_header"
                        && (!SERVER_SAFE_PROXY.contains(&n.name())
                            || (n.name() == "proxy_redirect"
                                && n.words() != ["proxy_redirect", "off"]));
                    [
                        "rewrite",
                        "if",
                        "set",
                        "try_files",
                        "error_page",
                        "return",
                    ]
                    .contains(&n.name())
                        || n.name().contains("_by_lua")
                        || n.name().starts_with("js_")
                        || proxy_unsafe
                        || (n.d.children.is_none()
                            && n.name() != "proxy_set_header"
                            && mentions_proxy_vars(n.text()))
                });
                if let Some(n) = bad {
                    reason = Some(format!("server 级 {} 需要手动接入", n.name()));
                }
            }
            // 主 location（吮底 location /）排在首位，用块 id 作站点 id；
            // 其余依次追加 -l<ordinal>。
            if let Some(pos) = catchall {
                if let Some(idx) = locs.iter().position(|p| p.ordinal == pos) {
                    let plan = locs.remove(idx);
                    locs.insert(0, plan);
                }
            }
            let upstream = locs.first().map(|p| p.upstream.clone());
            let extra_locations = locs
                .iter()
                .skip(1)
                .map(|p| LocSummary {
                    location: p.label.clone(),
                    upstream: p.upstream.clone(),
                })
                .collect::<Vec<_>>();
            rows.push(NginxSite {
                id,
                domains,
                listen,
                file: path.display().to_string(),
                upstream,
                extra_locations,
                bypassed_locations: bypassed,
                supported: reason.is_none(),
                reason,
                mode: "off".into(),
                status: "discovered".into(),
                fingerprint: fingerprint.clone(),
                source: source.clone(),
                locs,
            });
        }
    }
    Ok(rows)
}
/// nginx -T 全量配置里的 `upstream` 组：组名 -> (server 地址， 是否不可安全接管)。
/// down/backup 标记与 unix socket 都让该组不可自动解析。
fn upstream_groups(inc: &Includes) -> Result<BTreeMap<String, Vec<(String, bool)>>> {
    let mut out = BTreeMap::new();
    let mut http_nodes = Vec::new();
    let mut fragments = Vec::new();
    let mut has_http = false;
    for source in inc.files.values() {
        let ns = parse(source)?;
        for n in ns {
            if n.words[0] == "http" {
                has_http = true;
                http_nodes.extend(expand_scope(n.children.as_deref().unwrap_or(&[]), source, inc, true)?);
            } else if n.words[0] == "upstream" {
                fragments.push(Node { d: n, src: source.clone(), via: None });
            }
        }
    }
    // Fragment-only tests have no HTTP root; a full dump must follow its HTTP include graph.
    for n in if has_http { http_nodes } else { fragments } {
        let node = &n.d;
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
    Ok(out)
}

/// 把 proxy_pass 的上游解析为可转发字面量，返回 (带 scheme 的上游， nginx $proxy_host)。
/// 命名上游组只接受恰好一台非 backup/down 的 server，否则负载均衡/故障转移语义会变。
/// 把 proxy_pass 解析为 (可转发上游, nginx $proxy_host, URI 前缀)。
/// 命名上游组只接受恰好一台非 backup/down 的 server，否则负载均衡/故障转移语义会变。
fn resolve_upstream(
    u: &str,
    groups: &BTreeMap<String, Vec<(String, bool)>>,
) -> std::result::Result<(String, String, String), String> {
    let Some((scheme, rest)) = u.split_once("://") else {
        return Err("只支持 http:// 或 https:// 上游".into());
    };
    if scheme != "http" && scheme != "https" {
        return Err("只支持 http:// 或 https:// 上游".into());
    }
    if rest.is_empty() || rest.contains(['$', '@', '\\', '"', '\'', '?', '#']) {
        return Err(
            "只支持 http://主机:端口 字面上游或单服务器 upstream 组，变量上游不支持".into(),
        );
    }
    // proxy_pass 自带的 URI 前缀由 Nginx 继续用于替换 location 前缀,Rooster
    // 只原样转发收到的路径,因此站点上游不包含这段前缀。
    let (authority, proxy_uri) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    if authority.is_empty() {
        return Err("上游缺少主机".into());
    }
    if let Some(servers) = groups.get(authority) {
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
        return Ok((
            format!("{scheme}://{addr}"),
            authority.to_string(),
            proxy_uri,
        ));
    }
    if authority.contains(':') {
        let literal = format!("{scheme}://{authority}");
        return literal
            .parse::<http::Uri>()
            .ok()
            .filter(|parsed| parsed.authority().is_some())
            .map(|_| (literal, authority.to_string(), proxy_uri))
            .ok_or_else(|| "上游地址无法解析".into());
    }
    Err("无端口字面上游会被当成 DNS 主机名；请显式写端口或定义 upstream 组".into())
}

#[derive(Clone, Serialize, Deserialize)]
struct JournalSpan {
    site_id: String,
    upstream: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context_fingerprint: Option<String>,
    /// 原 proxy_pass 指令原文。
    original: String,
    /// 注入片段(含 begin/end 标记,每 location 一段)。
    injected: String,
    /// 同一事务对原文件其他位置的补充改写(如 $proxy_host 字面量化)。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fixups: Vec<Fixup>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    id: String,
    instance: Instance,
    file: PathBuf,
    /// 单 location 时代的字段;仅读取旧日志时用于迁移,新日志不再写。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    injected: Option<String>,
    #[serde(default)]
    upstream: String,
    #[serde(default)]
    spans: Vec<JournalSpan>,
    phase: String,
    original_hash: String,
    listener: String,
}

impl Journal {
    /// 事务写进文件的全部片段:(原文, 注入后)。注入主体与补充改写一起算,
    /// 漂移检测和恢复都走这一份视图。
    fn fragments(&self) -> Vec<(String, String)> {
        self.effective_spans()
            .into_iter()
            .flat_map(|sp| {
                std::iter::once((sp.original, sp.injected)).chain(
                    sp.fixups
                        .into_iter()
                        .map(|f| (f.original, f.injected)),
                )
            })
            .collect()
    }

    /// 生效的注入面:新日志直接用 spans,旧日志把 original/injected 迁移成
    /// 单元素 spans(所有读写只走这一份视图)。
    fn effective_spans(&self) -> Vec<JournalSpan> {
        if !self.spans.is_empty() {
            return self.spans.clone();
        }
        match (&self.original, &self.injected) {
            (Some(original), Some(injected)) => vec![JournalSpan {
                site_id: self.id.clone(),
                upstream: self.upstream.clone(),
                context_fingerprint: None,
                original: original.clone(),
                injected: injected.clone(),
                fixups: Vec::new(),
            }],
            _ => vec![],
        }
    }
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
            let spans = j.effective_spans();
            // 注入片段与补充改写都必须在文件里恰好出现一次。
            let frags = j.fragments();
            let in_location = !frags.is_empty()
                && frags
                    .iter()
                    .all(|(_, injected)| current.matches(injected).count() == 1);
            // 注入后的配置在发现层必然被拒(路由头/非 off 的 proxy_redirect),
            // 站点真实形态以去掉注入片段的恢复版为准。
            let restored_site = restored_site(&files, &j, &current).ok().flatten();
            let context_supported = restored_site.as_ref().is_some_and(|s| s.supported);
            // 接入面必须与 journal spans 完全一致:接入后新增的 proxy location
            // 不在 spans 内,流量会绕过 WAF 而面板仍显示已接入。
            let spans_match_locations = restored_site.as_ref().is_some_and(|s| {
                spans_match_site(s, &spans)
            });
            let sites_ok = !spans.is_empty()
                && spans.iter().all(|sp| {
                    eff.sites.iter().any(|s| {
                        s.id == sp.site_id
                            && s.upstream == sp.upstream
                            && (sp.context_fingerprint.is_none() || restored_site.as_ref().is_some_and(|r| {
                                r.locs.iter().enumerate().any(|(i, p)| p.site_id(&r.id, i == 0) == sp.site_id
                                    && s.upstream_connect_timeout == Some(p.connect_timeout))
                            }))
                            && s.waf.as_ref().is_some_and(|w| w.mode != WafMode::Off)
                    })
                });
            let attached = in_location
                && context_supported
                && spans_match_locations
                && j.phase == "active"
                && sites_ok
                && eff.plugins.http_guard.enabled
                && eff
                    .plugins
                    .http_guard
                    .listen_http
                    .is_some_and(|a| a.to_string() == j.listener)
                && state.httpguard.stats().iter().any(|s| {
                    s["listening_http"] == true
                        && spans
                            .iter()
                            .any(|sp| s["id"].as_str() == Some(sp.site_id.as_str()))
                });
            row.upstream = eff
                .sites
                .iter()
                .find(|s| spans.first().is_some_and(|sp| s.id == sp.site_id))
                .map(|s| s.upstream.clone())
                .or_else(|| restored_site.as_ref().and_then(|s| s.upstream.clone()))
                .or(row.upstream.clone());
            if let Some(s) = &restored_site {
                row.extra_locations = s.extra_locations.clone();
                row.bypassed_locations = s.bypassed_locations;
            }
            row.status = if attached {
                "attached"
            } else {
                "needs-recovery"
            }
            .into();
            row.mode = eff
                .sites
                .iter()
                .find(|s| spans.first().is_some_and(|sp| s.id == sp.site_id))
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
                    extra_locations: vec![],
                    bypassed_locations: 0,
                    supported: false,
                    reason: Some("原站点已移动或删除，请检查接入备份".into()),
                    mode: "off".into(),
                    status: "needs-recovery".into(),
                    fingerprint: String::new(),
                    source: String::new(),
                    locs: vec![],
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
fn config_with_sites(raw: &str, new_sites: &[Site], listener: &str) -> Result<String> {
    let (file, eff) = rooster_config::parse_and_validate(raw).map_err(|e| e.to_string())?;
    let ids: std::collections::HashSet<&str> = new_sites.iter().map(|s| s.id.as_str()).collect();
    let mut sites = file.managed.sites;
    sites.retain(|s| !ids.contains(s.id.as_str()));
    sites.extend(new_sites.iter().cloned());
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
fn injection(plan: &LocPlan, site_id: &str, listener: &str) -> Result<String> {
    // 命名上游组的 nginx $proxy_host 是组名而非解析后的地址，
    // 后端常按 Host 路由，必须原样保留。
    let proxy_host = plan.proxy_host.as_str();
    if proxy_host.is_empty() {
        return Err("no upstream".into());
    }
    let scheme = plan.upstream.split("://").next().unwrap_or("http");
    let mut out = format!(
        "# rooster-waf begin {site_id}\nproxy_pass http://{listener}{};\n",
        plan.proxy_uri
    );
    // Materialize inherited headers before adding any header at location level:
    // Nginx stops inheriting the entire proxy_set_header array at that point.
    if !plan.own_headers {
        for h in &plan.headers {
            if h.header_name().is_some_and(|k| {
                k.eq_ignore_ascii_case(ROUTE_HEADER)
                    || k.eq_ignore_ascii_case("X-Forwarded-For")
                    || k.eq_ignore_ascii_case("X-Forwarded-Proto")
            }) {
                continue;
            }
            out.push_str(&substitute_proxy_vars(h.text(), proxy_host, &plan.proxy_port));
            out.push('\n');
        }
    }
    if plan.headers.iter().any(|h| {
        h.header_name()
            .is_some_and(|k| k.eq_ignore_ascii_case(ROUTE_HEADER))
    }) {
        return Err("X-Rooster-Site is reserved for managed onboarding".into());
    }
    if !plan.headers.iter().any(|h| {
        h.header_name()
            .is_some_and(|k| k.eq_ignore_ascii_case("Host"))
    }) {
        out.push_str(&format!(
            "proxy_set_header Host {};\n",
            quoted(proxy_host)
        ));
    }
    // Changing proxy_pass authority also changes Nginx's implicit redirect match.
    if !plan.redirect_off {
        if plan.proxy_uri.is_empty() {
            out.push_str(&format!("proxy_redirect {scheme}://{proxy_host}/ /;\n"));
        } else {
            out.push_str(&format!(
                "proxy_redirect {} {};\n",
                quoted(&format!("{scheme}://{proxy_host}{}", plan.proxy_uri)),
                quoted(&plan.location_path)
            ));
        }
    }
    out.push_str(&format!(
        "proxy_set_header {ROUTE_HEADER} {};\n",
        quoted(site_id)
    ));
    if !plan.own_headers
        || !plan
            .headers
            .iter()
            .any(|h| h.header_name().is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-For")))
    {
        out.push_str("proxy_set_header X-Forwarded-For $remote_addr;\n");
    }
    if !plan.own_headers
        || !plan
            .headers
            .iter()
            .any(|h| h.header_name().is_some_and(|k| k.eq_ignore_ascii_case("X-Forwarded-Proto")))
    {
        out.push_str("proxy_set_header X-Forwarded-Proto $scheme;\n");
    }
    out.push_str(&format!("# rooster-waf end {site_id}\n"));
    Ok(out)
}

fn splice(source: &str, replacements: &[(usize, usize, String)]) -> Result<String> {
    // 从后往前替换,前面的字节偏移不被破坏。
    let mut reps = replacements.to_vec();
    reps.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out = source.to_string();
    for (start, end, text) in &reps {
        if start >= end || *end > out.len() {
            return Err("configuration offsets changed".into());
        }
        out = format!("{}{}{}", &out[..*start], text, &out[*end..]);
    }
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
        let spans = j.effective_spans();
        let frags = j.fragments();
        let current = fs::read_to_string(&j.file).map_err(|e| e.to_string())?;
        if j.phase != "active"
            || frags.is_empty()
            || frags
                .iter()
                .any(|(_, injected)| current.matches(injected).count() != 1)
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
        let eff = state.effective();
        let mut sites: Vec<Site> = Vec::new();
        for sp in &spans {
            let mut site = eff
                .sites
                .iter()
                .find(|s| s.id == sp.site_id)
                .cloned()
                .ok_or("Rooster site missing; restore first")?;
            site.waf.get_or_insert_with(Default::default).mode = mode;
            sites.push(site);
        }
        let listener = eff
            .plugins
            .http_guard
            .listen_http
            .ok_or("listener missing")?
            .to_string();
        let site_ids: Vec<String> = spans.iter().map(|sp| sp.site_id.clone()).collect();
        let new_raw = config_with_sites(&raw, &sites, &listener)?;
        if let Err(e) = apply(&state, &raw, &new_raw, &rt)
            .and_then(|_| verify(&state, &site_ids, &listener, mode, &rt))
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
    if row.locs.is_empty() {
        return Err("site has no onboarding locations".into());
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
    // 逐 location 校验代理回环、生成站点与注入片段。主 location(吮底或
    // 首个)用块 id 作站点 id,其余用 -l<ordinal>,与发现层保持一致。
    #[derive(Clone)]
    struct Prepared {
        start: usize,
        end: usize,
        site_id: String,
        upstream: String,
        original: String,
        injected: String,
        fixups: Vec<Fixup>,
        context_fingerprint: String,
    }
    let listener_port = listener
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| a.port());
    let mut sites: Vec<Site> = Vec::new();
    let mut prepared: Vec<Prepared> = Vec::new();
    for (i, plan) in row.locs.iter().enumerate() {
        let authority = plan
            .upstream
            .parse::<http::Uri>()
            .ok()
            .and_then(|u| u.authority().cloned())
            .ok_or("invalid upstream")?;
        let loopback = authority.host().eq_ignore_ascii_case("localhost")
            || authority
                .host()
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback());
        if loopback && authority.port_u16() == listener_port {
            return Err("upstream would form a proxy loop".into());
        }
        let site_id = plan.site_id(&id, i == 0);
        if eff.sites.iter().any(|s| s.id == site_id) {
            return Err(format!("Rooster site id already exists: {site_id}"));
        }
        let original = source
            .get(plan.proxy.start..plan.proxy.end)
            .ok_or("configuration offsets changed")?
            .to_string();
        let injected = injection(plan, &site_id, &listener)?;
        // https 上游默认 skip-verify：nginx 本就不校验上游证书，接入不应
        // 改变现有转发语义（内网自签源站若无此项会直接 502）。
        let skip_verify = plan.upstream.starts_with("https://");
        let site: Site = serde_json::from_value(json!({"id": site_id, "server-names": row.domains, "tls": {"mode": "terminate", "skip-verify": skip_verify}, "upstream": plan.upstream, "upstream-connect-timeout": format!("{}ms", plan.connect_timeout.as_millis()), "waf": {"mode": mode_name(mode)}})).map_err(|e| e.to_string())?;
        sites.push(site);
        prepared.push(Prepared {
            start: plan.proxy.start,
            end: plan.proxy.end,
            site_id,
            upstream: plan.upstream.clone(),
            original,
            injected,
            fixups: plan.fixups.clone(),
            context_fingerprint: plan_fingerprint(plan),
        });
    }
    // 多段注入从后往前拼接,前面的字节偏移不被破坏。prepared 按文档序
    // (location 顺序)生成,主 location 被提前后不一定仍在最前。
    let replacements = prepared
        .iter()
        .flat_map(|p| {
            std::iter::once((p.start, p.end, p.injected.clone())).chain(p.fixups.iter().map(|f| {
                (f.start, f.end, f.injected.clone())
            }))
        })
        .collect::<Vec<_>>();
    let changed = splice(&source, &replacements)?;
    let site_ids: Vec<String> = prepared.iter().map(|p| p.site_id.clone()).collect();
    let new_raw = config_with_sites(&raw, &sites, &listener)?;
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
        original: None,
        injected: None,
        upstream: String::new(),
        spans: prepared
            .into_iter()
            .map(|p| JournalSpan {
                site_id: p.site_id,
                upstream: p.upstream,
                context_fingerprint: Some(p.context_fingerprint),
                original: p.original,
                injected: p.injected,
                fixups: p.fixups,
            })
            .collect(),
        phase: "prepared".into(),
        original_hash: hash_content(&source),
        listener: listener.clone(),
    };
    save_journal(&state, &j)?;
    let outcome = (|| {
        apply(&state, &raw, &new_raw, &rt)?;
        verify(&state, &site_ids, &listener, mode, &rt)?;
        for (path, dumped) in &files {
            let current = fs::read_to_string(path).map_err(|e| e.to_string())?;
            if current != *dumped && format!("{current}\n") != *dumped {
                return Err("Nginx configuration changed; aborted".into());
            }
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
    ids: &[String],
    listener: &str,
    mode: WafMode,
    rt: &tokio::runtime::Handle,
) -> Result<()> {
    if !state.httpguard.stats().iter().any(|s| {
        s["listening_http"] == true && ids.iter().any(|i| s["id"].as_str() == Some(i.as_str()))
    }) {
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
    // 每个 location 的路由头都要验证,防止注入片段路由到不存在的站点。
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| e.to_string())?;
        for id in ids {
            let response = client
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
        }
        Ok(())
    })
}
fn plan_fingerprint(plan: &LocPlan) -> String {
    hash_content(&json!({
        "upstream": plan.upstream, "host": plan.proxy_host, "port": plan.proxy_port,
        "uri": plan.proxy_uri, "location": plan.location_path, "redirect-off": plan.redirect_off,
        "timeout-ms": plan.connect_timeout.as_millis().to_string(),
        "own-headers": plan.own_headers,
        "headers": plan.headers.iter().map(Node::words).collect::<Vec<_>>()
    }).to_string())
}

fn spans_match_site(site: &NginxSite, spans: &[JournalSpan]) -> bool {
    site.locs.len() == spans.len() && site.locs.iter().enumerate().zip(spans).all(|((i, plan), sp)| {
        plan.site_id(&site.id, i == 0) == sp.site_id
            && plan.upstream == sp.upstream
            && sp.context_fingerprint.as_ref().is_none_or(|f| *f == plan_fingerprint(plan))
    })
}

fn restore_all(j: &Journal, source: &str) -> String {
    let mut restored = source.to_string();
    for (original, injected) in j.fragments() {
        restored = restored.replacen(&injected, &original, 1);
    }
    restored
}
fn restored_site(
    files: &BTreeMap<PathBuf, String>,
    j: &Journal,
    current: &str,
) -> Result<Option<NginxSite>> {
    // IDs belong to dump paths, not canonical write targets (sites-enabled is often a symlink).
    let Some(row) = discover_sites(files)?.into_iter().find(|s| s.id == j.id) else {
        return Ok(None);
    };
    let mut restored = files.clone();
    restored.insert(PathBuf::from(row.file), restore_all(j, current));
    Ok(discover_sites(&restored)?.into_iter().find(|s| s.id == j.id))
}
fn restore_fragment(j: &Journal) -> Result<()> {
    let source = fs::read_to_string(&j.file).map_err(|e| e.to_string())?;
    let counts: Vec<usize> = j
        .fragments()
        .iter()
        .map(|(_, injected)| source.matches(injected).count())
        .collect();
    if !counts.is_empty() && counts.iter().all(|c| *c == 1) {
        return atomic_write(&j.file, restore_all(j, &source).as_bytes(), false);
    }
    if counts.iter().all(|c| *c == 0)
        && j.phase == "prepared"
        && hash_content(&source) == j.original_hash
    {
        return Ok(());
    }
    Err("injected configuration was edited or removed; recovery backup retained, manual reconciliation required".into())
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
    let spans = j.effective_spans();
    if spans.is_empty() {
        return Err("recovery record has no injection spans; reconcile manually".into());
    }
    // Validate exact fragments before preparing changes; preserve other site edits.
    let counts: Vec<usize> = j
        .fragments()
        .iter()
        .map(|(_, injected)| source.matches(injected).count())
        .collect();
    if !counts.iter().all(|c| *c == 1)
        && !(j.phase == "prepared" && hash_content(&source) == j.original_hash)
    {
        return Err(
            "injection drift detected; use the private .conf.backup to reconcile manually".into(),
        );
    }
    let (mut file, _) = rooster_config::parse_and_validate(raw).map_err(|e| e.to_string())?;
    let ids: std::collections::HashSet<String> =
        spans.iter().map(|sp| sp.site_id.clone()).collect();
    file.managed.sites.retain(|s| !ids.contains(&s.id));
    let new_raw = patch(
        raw,
        &[Seg::K("managed")],
        "sites",
        &serde_json::to_value(file.managed.sites).map_err(|e| e.to_string())?,
    )?;
    let previous_phase = j.phase.clone();
    j.original_hash = hash_content(&restore_all(&j, &source));
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
        let restored = restore_all(&j, &source);
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
        for conf in ["server { location / { proxy_pass http://backend; } }", "server { location / { proxy_pass http://$upstream:3000; } }", "server { location / { rewrite ^ /a; proxy_pass http://127.0.0.1:3000; } }", "server { location / { proxy_pass http://127.0.0.1:3000/x?a=1; } }"] { assert!(!rows(conf)[0].supported, "{conf}"); }
    }
    #[test]
    fn server_level_hop_quality_proxy_directives_stay_supported() {
        let r = rows("server { listen 443 ssl; proxy_connect_timeout 60s; proxy_send_timeout 600s; proxy_read_timeout 600s; proxy_buffering on; proxy_request_buffering off; location / { proxy_pass http://127.0.0.1:3001; } }");
        assert!(r[0].supported, "{:?}", r[0].reason);
    }
    #[test]
    fn server_level_semantic_directives_decline_with_directive_name() {
        for (conf, directive) in [
            ("server { proxy_next_upstream error timeout; location / { proxy_pass http://127.0.0.1:3001; } }", "proxy_next_upstream"),
            ("server { proxy_intercept_errors on; location / { proxy_pass http://127.0.0.1:3001; } }", "proxy_intercept_errors"),
            ("server { proxy_redirect http://old.example/ http://new.example/; location / { proxy_pass http://127.0.0.1:3001; } }", "proxy_redirect"),
            ("server { set $flag 1; location / { proxy_pass http://127.0.0.1:3001; } }", "set"),
        ] {
            let r = rows(conf);
            assert!(!r[0].supported, "{conf}");
            assert_eq!(
                r[0].reason.as_deref(),
                Some(format!("server 级 {directive} 需要手动接入").as_str()),
                "{conf}"
            );
        }
    }
    #[test]
    fn proxy_pass_uri_prefix_is_preserved_on_the_loopback_hop() {
        // nginx 用 proxy_pass 的 URI 前缀替换 location 前缀;接入后这段替换仍在
        // Nginx 里发生,Rooster 收到的已经是改写后的路径,所以站点上游不带前缀。
        let r = rows("server { location /app/ { proxy_pass http://127.0.0.1:3006/api/; } }");
        assert!(r[0].supported, "{}", r[0].reason.clone().unwrap_or_default());
        assert_eq!(r[0].locs[0].upstream, "http://127.0.0.1:3006");
        assert_eq!(r[0].locs[0].proxy_uri, "/api/");
        let inj = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
        assert!(inj.contains("proxy_pass http://127.0.0.1:18080/api/;"), "{inj}");
        assert!(inj.contains("proxy_redirect \"http://127.0.0.1:3006/api/\" \"/app/\";"), "{inj}");
    }
    #[test]
    fn inherited_proxy_variables_are_literalized_per_location() {
        for (main, server) in [
            ("http { include /etc/nginx/sites-enabled/*; }", "proxy_set_header Host $proxy_host; proxy_set_header X-Port ${proxy_port};"),
            ("http { include /etc/nginx/headers.conf; include /etc/nginx/sites-enabled/*; }", ""),
        ] {
            let r = rows_in(&[
                ("/etc/nginx/nginx.conf", main),
                ("/etc/nginx/headers.conf", "proxy_set_header Host $proxy_host; proxy_set_header X-Port ${proxy_port};"),
                ("/etc/nginx/sites-enabled/a.conf", &format!("server {{ {server} location / {{ proxy_pass http://127.0.0.1:3001; }} location /api/ {{ proxy_pass https://127.0.0.1:443; }} }}")),
            ]);
            assert!(r[0].supported, "{:?}", r[0].reason);
            for (plan, host, port) in [(&r[0].locs[0], "127.0.0.1:3001", "3001"), (&r[0].locs[1], "127.0.0.1:443", "443")] {
                assert!(plan.fixups.is_empty());
                let inj = injection(plan, &r[0].id, LISTEN).unwrap();
                assert!(inj.contains(&format!("proxy_set_header Host {host};")), "{inj}");
                assert!(inj.contains(&format!("proxy_set_header X-Port {port};")), "{inj}");
                assert!(!mentions_proxy_vars(&inj), "{inj}");
            }
        }
    }
    #[test]
    fn uri_redirect_mapping_preserves_prefix_and_off() {
        for modifier in ["", "^~ ", "= "] {
            let r = rows(&format!("server {{ location {modifier}/app/ {{ proxy_pass https://127.0.0.1:3443/api/; }} }}"));
            assert!(r[0].supported, "{:?}", r[0].reason);
            let inj = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
            assert!(inj.contains("proxy_redirect \"https://127.0.0.1:3443/api/\" \"/app/\";"), "{inj}");
        }
        let r = rows_in(&[
            ("/etc/nginx/nginx.conf", "http { upstream g { server 127.0.0.1:3001; } include /etc/nginx/sites-enabled/*; }"),
            ("/etc/nginx/sites-enabled/a.conf", "server { location /app/ { proxy_pass http://g/api/; } }"),
        ]);
        assert!(r[0].supported, "{:?}", r[0].reason);
        assert!(injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap().contains("proxy_redirect \"http://g/api/\" \"/app/\";"));
        let r = rows("server { location /app/ { proxy_pass http://127.0.0.1:3001/api/; proxy_redirect off; } }");
        assert!(r[0].supported);
        assert!(!injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap().contains("proxy_redirect"));
    }
    #[test]
    fn empty_and_large_glob_includes_remain_supported() {
        let mut files = BTreeMap::from([(
            PathBuf::from("/etc/nginx/nginx.conf"),
            "http { include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }".to_string(),
        )]);
        for i in 0..17 {
            files.insert(PathBuf::from(format!("/etc/nginx/sites-enabled/{i}.conf")), "server { location / { proxy_pass http://127.0.0.1:3001; } }".into());
        }
        let r = discover_sites(&files).unwrap();
        assert_eq!(r.len(), 17);
        assert!(r.iter().all(|s| s.supported), "{:?}", r.iter().map(|s| &s.reason).collect::<Vec<_>>());
        files.insert(PathBuf::from("/etc/nginx/nginx.conf"), "http { include /etc/nginx/missing.conf; include /etc/nginx/sites-enabled/*; }".into());
        assert!(discover_sites(&files).unwrap().iter().all(|s| !s.supported));
    }
    #[test]
    fn inherited_proxy_variables_outside_headers_stay_manual() {
        let r = rows("server { add_header X-Backend $proxy_host; location / { proxy_pass http://127.0.0.1:3001; } }");
        assert!(!r[0].supported);
        let r = rows_in(&[
            ("/etc/nginx/nginx.conf", "http { add_header X-Backend $proxy_port; include /etc/nginx/sites-enabled/*; }"),
            ("/etc/nginx/sites-enabled/a.conf", "server { location / { proxy_pass http://127.0.0.1:3001; } }"),
        ]);
        assert!(!r[0].supported);
    }
    #[test]
    fn http_level_headers_from_included_files_are_materialized() {
        // sites-enabled 文件自身没有 http{},继承必须沿主配置的 include 链解析。
        let r = rows_in(&[
            (
                "/etc/nginx/nginx.conf",
                "http { include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }",
            ),
            (
                "/etc/nginx/conf.d/00-proxy.conf",
                "proxy_set_header Host $http_host;\nproxy_set_header X-Inherited yes;",
            ),
            (
                "/etc/nginx/sites-enabled/a.conf",
                "server { location / { proxy_pass http://127.0.0.1:3001; } }",
            ),
        ]);
        assert!(r[0].supported, "{}", r[0].reason.clone().unwrap_or_default());
        let inj = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
        // 不物化就会让 Nginx 停止继承,上游会丢掉 Host 与自定义头。
        assert!(inj.contains("proxy_set_header Host $http_host;"), "{inj}");
        assert!(inj.contains("proxy_set_header X-Inherited yes;"), "{inj}");
        assert!(!inj.contains("proxy_set_header Host \"127.0.0.1:3001\""), "{inj}");
    }
    #[test]
    fn http_level_proxy_settings_beyond_headers_stay_manual() {
        let r = rows_in(&[
            (
                "/etc/nginx/nginx.conf",
                "http { proxy_bind 10.0.0.1; include /etc/nginx/sites-enabled/*; }",
            ),
            (
                "/etc/nginx/sites-enabled/a.conf",
                "server { location / { proxy_pass http://127.0.0.1:3001; } }",
            ),
        ]);
        assert!(!r[0].supported);
        assert!(
            r[0].reason.as_deref().is_some_and(|s| s.contains("HTTP 层")),
            "reason={:?}",
            r[0].reason
        );
    }
    #[test]
    fn location_include_of_proxy_params_onboards_and_literals_proxy_host() {
        // Debian 的 proxy_params 用 $proxy_host:接入后它会变成回环守卫地址,
        // 必须就地展开并字面量化,且不去改共享文件。
        let files = BTreeMap::from([
            (
                PathBuf::from("/etc/nginx/nginx.conf"),
                "http { include /etc/nginx/sites-enabled/*; }".to_string(),
            ),
            (
                PathBuf::from("/etc/nginx/proxy_params"),
                "proxy_set_header Host $proxy_host;\nproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n".to_string(),
            ),
            (
                PathBuf::from("/etc/nginx/sites-enabled/a.conf"),
                "upstream g { server 10.0.0.7:8080; }\nserver { location / { include /etc/nginx/proxy_params; proxy_pass http://g; } }\nserver { location / { include /etc/nginx/proxy_params; proxy_pass http://g; } }".to_string(),
            ),
        ]);
        let r = discover_sites(&files).unwrap();
        assert!(r[0].supported, "{}", r[0].reason.clone().unwrap_or_default());
        // include 里的 proxy_set_header 算本层指令,不再叠加 http 层继承头。
        assert!(r[0].locs[0].own_headers);
        assert_eq!(r[0].locs[0].fixups.len(), 1);
        let fix = &r[0].locs[0].fixups[0];
        assert_eq!(fix.original, "include /etc/nginx/proxy_params;");
        assert!(fix.injected.contains("proxy_set_header Host g;"), "{}", fix.injected);
        assert!(
            fix.injected
                .contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"),
            "{}",
            fix.injected
        );
        let inj = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
        // 已有 Host 指令时不再叠加(同名指令会重复发出)。
        assert!(!inj.contains("proxy_set_header Host"), "{inj}");
        let changed = splice(
            &files[&PathBuf::from("/etc/nginx/sites-enabled/a.conf")],
            &[
                vec![(
                    r[0].locs[0].proxy.start,
                    r[0].locs[0].proxy.end,
                    inj.clone(),
                )],
                r[0].locs[0]
                    .fixups
                    .iter()
                    .map(|f| (f.start, f.end, f.injected.clone()))
                    .collect::<Vec<_>>(),
            ]
            .concat(),
        )
        .unwrap();
        assert!(parse(&changed).is_ok(), "{changed}");
        assert!(changed.contains("proxy_set_header Host g;"), "{changed}");
        // 恢复:注入片段与补充改写都回到原文。
        let j = Journal {
            id: r[0].id.clone(),
            instance: Instance {
                binary: "/usr/sbin/nginx".into(),
                args: vec![],
                running: true,
                pid: Some(1),
            },
            file: "/etc/nginx/sites-enabled/a.conf".into(),
            original: None,
            injected: None,
            upstream: String::new(),
            spans: vec![JournalSpan {
                site_id: r[0].id.clone(),
                upstream: r[0].locs[0].upstream.clone(),
                context_fingerprint: Some(plan_fingerprint(&r[0].locs[0])),
                original: files[&PathBuf::from("/etc/nginx/sites-enabled/a.conf")][r[0].locs[0].proxy.start..r[0].locs[0].proxy.end].to_string(),
                injected: inj,
                fixups: r[0].locs[0].fixups.clone(),
            }],
            phase: "active".into(),
            original_hash: String::new(),
            listener: LISTEN.into(),
        };
        assert_eq!(restore_all(&j, &changed), files[&PathBuf::from("/etc/nginx/sites-enabled/a.conf")]);
        let restored = restored_site(&files, &j, &changed).unwrap().unwrap();
        assert!(restored.supported, "{:?}", restored.reason);
        assert_eq!(restored.locs[0].upstream, r[0].locs[0].upstream);
        assert_eq!(restored.locs[0].fixups[0].original, fix.original);
        let other = injection(&r[1].locs[0], &r[1].id, LISTEN).unwrap();
        let both = changed.replacen("proxy_pass http://g;", &other, 1);
        let mut attached_files = files.clone();
        attached_files.insert(j.file.clone(), both.clone());
        let restored = restored_site(&attached_files, &j, &both).unwrap().unwrap();
        assert!(restored.supported, "{:?}", restored.reason);
        assert_eq!(restored.id, r[0].id);
        assert!(restore_all(&j, &both).contains(&other));
        assert!(!discover_sites(&attached_files).unwrap()[1].supported);
    }
    #[test]
    fn same_file_proxy_host_header_is_literalized_in_place() {
        let r = rows("server { location / { proxy_set_header Host $proxy_host; proxy_pass http://127.0.0.1:3001; } }");
        assert!(r[0].supported, "{}", r[0].reason.clone().unwrap_or_default());
        assert_eq!(r[0].locs[0].fixups.len(), 1);
        let fix = &r[0].locs[0].fixups[0];
        assert_eq!(fix.original, "proxy_set_header Host $proxy_host;");
        assert!(fix.injected.contains("proxy_set_header Host 127.0.0.1:3001;"), "{fix:?}");
    }
    #[test]
    fn proxy_vars_outside_set_header_stay_manual() {
        let r = rows("server { location / { add_header X-Backend $proxy_host; proxy_pass http://127.0.0.1:3001; } }");
        assert!(!r[0].supported);
        assert!(
            r[0].reason.as_deref().is_some_and(|s| s.contains("$proxy_host")),
            "reason={:?}",
            r[0].reason
        );
    }
    #[test]
    fn unresolvable_include_stays_manual() {
        let r = rows("server { location / { include /etc/nginx/snippets/unknown.conf; proxy_pass http://127.0.0.1:3001; } }");
        assert!(!r[0].supported);
        assert!(
            r[0].reason.as_deref().is_some_and(|s| s.contains("include")),
            "reason={:?}",
            r[0].reason
        );
    }
    #[test]
    fn multi_location_servers_onboard_each_proxy_location() {
        // 常见形态:吮底代理 + 分路径代理到另一上游 + 静态目录。不再整体拒绝:
        // 两个代理 location 各自接入,静态目录留在 Nginx 并计数透出。
        let r = rows("server { location / { proxy_pass http://127.0.0.1:3000; } location /api { proxy_pass http://127.0.0.1:4000; } location /static { root /www; } }");
        assert!(r[0].supported, "{}", r[0].reason.clone().unwrap_or_default());
        assert_eq!(r[0].upstream.as_deref(), Some("http://127.0.0.1:3000"));
        assert_eq!(r[0].extra_locations.len(), 1);
        assert_eq!(r[0].extra_locations[0].location, "location /api");
        assert_eq!(r[0].extra_locations[0].upstream, "http://127.0.0.1:4000");
        assert_eq!(r[0].bypassed_locations, 1);
        assert_eq!(r[0].locs.len(), 2);
        // 主站点用块 id,其余追加 -l<ordinal>;注入片段各自独立且可解析。
        let id0 = r[0].locs[0].site_id(&r[0].id, true);
        let id1 = r[0].locs[1].site_id(&r[0].id, false);
        assert_eq!(id0, r[0].id);
        assert_eq!(id1, format!("{}-l1", r[0].id));
        let inj0 = injection(&r[0].locs[0], &id0, LISTEN).unwrap();
        let inj1 = injection(&r[0].locs[1], &id1, LISTEN).unwrap();
        assert!(inj0.contains(&format!("X-Rooster-Site \"{id0}\"")));
        assert!(inj1.contains(&format!("X-Rooster-Site \"{id1}\"")));
        assert!(inj1.contains("proxy_redirect http://127.0.0.1:4000/ /;"));
        assert!(parse(&inj0).is_ok() && parse(&inj1).is_ok());
    }
    #[test]
    fn multi_location_splice_roundtrip_restores_original() {
        let source = "server { location /api { proxy_pass http://127.0.0.1:4000; } location / { proxy_pass http://127.0.0.1:3000; } }";
        let r = rows(source);
        assert!(r[0].supported);
        // 主 location(吮底 /)排在首位但文档序在后:拼接必须不依赖 locs 顺序。
        assert_eq!(r[0].locs[0].proxy.words, ["proxy_pass", "http://127.0.0.1:3000"]);
        let replacements = r[0]
            .locs
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let site_id = p.site_id(&r[0].id, i == 0);
                (
                    p.proxy.start,
                    p.proxy.end,
                    injection(p, &site_id, LISTEN).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let changed = splice(source, &replacements).unwrap();
        assert!(parse(&changed).is_ok(), "{changed}");
        assert_eq!(changed.matches("rooster-waf begin").count(), 2);
        // 恢复 = 逐段 replacen,结果与原文一致。
        let spans: Vec<JournalSpan> = replacements
            .into_iter()
            .map(|(start, end, injected)| JournalSpan {
                site_id: String::new(),
                upstream: String::new(),
                context_fingerprint: None,
                original: source[start..end].to_string(),
                injected,
                fixups: Vec::new(),
            })
            .collect();
        let j = Journal {
            id: r[0].id.clone(),
            instance: Instance { binary: PathBuf::new(), args: vec![], running: false, pid: None },
            file: PathBuf::new(),
            original: None,
            injected: None,
            upstream: String::new(),
            spans: spans.clone(),
            phase: "active".into(),
            original_hash: String::new(),
            listener: String::new(),
        };
        assert_eq!(restore_all(&j, &changed), source);
        // 旧版单 location 日志迁移:spans 为空时 original/injected 变成单元素 spans。
        let legacy = Journal {
            original: Some("proxy_pass http://a;".into()),
            injected: Some("# rooster-waf begin x".into()),
            upstream: "http://a".into(),
            spans: vec![],
            ..j
        };
        assert_eq!(legacy.effective_spans().len(), 1);
        assert_eq!(legacy.effective_spans()[0].site_id, legacy.id);
    }
    #[test]
    fn inherited_headers_and_comments_are_preserved() {
        let source = "server { proxy_set_header Host $host; proxy_set_header X-Secret 'hello; world'; location / { # proxy_pass fake;\n proxy_pass http://127.0.0.1:3000; } }";
        let r = rows(source);
        let injected = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
        assert!(injected.contains("X-Secret 'hello; world'"));
        assert!(injected.contains("proxy_set_header Host $host;"));
        let p = &r[0].locs[0].proxy;
        assert_eq!(&source[p.start..p.end], "proxy_pass http://127.0.0.1:3000;");
        assert!(parse(&injected).is_ok());
    }
    #[test]
    fn local_source_headers_are_not_duplicated_and_default_names_are_valid() {
        let source = "server { location / { proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; proxy_pass http://127.0.0.1:3000; } }";
        let r = rows(source);
        assert!(r[0].supported);
        assert_eq!(r[0].domains, ["_"]);
        let injected = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
        assert!(!injected.contains("proxy_set_header X-Forwarded-For"));
        assert!(!injected.contains("proxy_set_header X-Forwarded-Proto"));
        assert!(injected.contains("proxy_redirect http://127.0.0.1:3000/ /;"));
    }
    #[test]
    fn stable_ids_across_injection() {
        let source = "server { location / { proxy_pass http://127.0.0.1:3000; } } server { location / { proxy_pass http://127.0.0.1:4000; } }";
        let before = rows(source);
        let p = &before[0].locs[0].proxy;
        let new = splice(
            source,
            &[(p.start, p.end, injection(&before[0].locs[0], &before[0].id, LISTEN).unwrap())],
        )
        .unwrap();
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
        assert_eq!(r[0].locs[0].proxy_host, "llm_gateway");
        let injected = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
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
        let injected = injection(&r[0].locs[0], &r[0].id, LISTEN).unwrap();
        assert!(injected.contains("proxy_redirect https://firewall_backend/ /;"));
        let literal = rows(
            "server { location / { proxy_pass https://10.0.0.9:8443; } }",
        );
        assert!(literal[0].supported);
        assert_eq!(literal[0].upstream.as_deref(), Some("https://10.0.0.9:8443"));
        assert_eq!(literal[0].locs[0].proxy_host, "10.0.0.9:8443");
    }
    #[test]
    fn unsafe_extra_location_reports_itself_and_declines() {
        // /api 自己有 proxy_pass 但含不支持的指令 → 整块拒绝,原因指向具体 location。
        // (无 proxy_pass 的 location 不拦截,见 multi_location_servers_onboard_each_proxy_location。)
        let r = rows_in(&[
            (
                "/etc/nginx/nginx.conf",
                "http { upstream g { server 10.0.0.5:8080; } }",
            ),
            (
                "/etc/nginx/sites-enabled/a.conf",
                "server { location / { proxy_pass http://g; } location /api { rewrite ^ /a; proxy_pass http://127.0.0.1:4000; } }",
            ),
        ]);
        assert!(!r[0].supported);
        assert_eq!(
            r[0].reason.as_deref(),
            Some("location /api 含重写、缓存或其他复杂指令，需要手动接入")
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
/// 子站点 id（`nginx-<hash>-lN`）也归入托管:删除必须走恢复流程。
pub fn is_managed(state: &AgentState, id: &str) -> bool {
    id.starts_with("nginx-")
        && journal_path(state, block_id_of(id)).is_ok_and(|p| p.exists())
}

/// 子站点 id `nginx-<hash>-lN` → 块 id `nginx-<hash>`;主站点原样返回。
fn block_id_of(id: &str) -> &str {
    match id.rsplit_once("-l") {
        Some((head, digits)) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => id,
    }
}

#[cfg(test)]
#[path = "nginx_tests.rs"]
mod regression_tests;

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
        let source = format!("# preserved comment\nuser root root; worker_processes 1; pid {}/nginx.pid; error_log {}/error.log; events {{ worker_connections 64; }} http {{ access_log off; proxy_set_header Host $host; proxy_set_header X-Inherited 'kept; value'; proxy_set_header X-Observed-Client $remote_addr; server {{ listen 127.0.0.1:{port}; server_name a.test; location / {{ include {}/proxy_params; proxy_pass http://{upstream}; }} }} server {{ listen 127.0.0.1:{port}; server_name b.test; location / {{ proxy_pass http://{upstream}; }} }} }}\n", dir.display(), dir.display(), dir.display());
        fs::write(dir.join("proxy_params"), format!("include {}/nested_params;\n", dir.display())).unwrap();
        fs::write(dir.join("nested_params"), "proxy_set_header Host $host; proxy_set_header X-Inherited 'kept; value'; proxy_set_header X-Observed-Client $remote_addr;\n").unwrap();
        let conf = dir.join("nginx.conf");
        let canonical = dir.join("nginx-real.conf");
        fs::write(&canonical, &source).unwrap();
        std::os::unix::fs::symlink(&canonical, &conf).unwrap();
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
        // 阶段 1 只加载 scanner-ua 一条签名:CRS 默认开启会拦下自探针,
        // 让“自检失败→回滚”这条路径根本走不到,必须显式关掉。
        let raw = format!("local:\n  agent:\n    node-name: nginx-test\n    data-dir: {}\nmanaged:\n  plugins:\n    http-guard:\n      enabled: true\n      listen-http: 127.0.0.1:{guard_port}\n  waf:\n    crs:\n      enabled: false\n    signatures: [scanner-ua]\n", dir.display());
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
        let primary = &j.effective_spans()[0];
        let tampered = attached_source.replacen(
            &primary.injected,
            &primary.injected.replace("X-Rooster-Site", "X-Changed-Site"),
            1,
        );
        fs::write(&conf, &tampered).unwrap();
        assert!(change_async(state.clone(), &scanned.sites[0], WafMode::Off)
            .await
            .unwrap_err()
            .contains("drift"));
        assert_eq!(fs::read_to_string(&conf).unwrap(), tampered);
        fs::write(&conf, &attached_source).unwrap();
        // 接入后新增非 proxy location:留在 Nginx(计入 bypassed),接入状态不变。
        let extended = attached_source.replace(
            "server_name a.test;",
            "server_name a.test; location /bypass { return 200 unguarded; }",
        );
        fs::write(&conf, &extended).unwrap();
        let snapshot_state = state.clone();
        let with_bypass = tokio::task::spawn_blocking(move || snapshot(&snapshot_state))
            .await
            .unwrap()
            .unwrap();
        let bypassed = with_bypass
            .sites
            .iter()
            .find(|s| s.id == scanned.sites[0].id)
            .unwrap();
        assert_eq!(bypassed.status, "attached");
        assert_eq!(bypassed.bypassed_locations, 1);
        // 接入后新增 proxy location 不在 spans 内 → 漂移,防止其绕过 WAF 却仍显示已接入。
        let extended = attached_source.replace(
            "server_name a.test;",
            "server_name a.test; location /api2 { proxy_pass http://127.0.0.1:9999; }",
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
        assert!(conf.is_symlink());
        state.httpguard.apply(Default::default()).await;
        business.abort();
        drop(fixture);
    }
}
