//! 域名解析缓存:host 为域名时缓存 A/AAAA 结果,
//! 过期后重新解析;所有缓存地址连接失败时强制刷新一次再重试。
//!
//! 说明:workspace 中的 hickory-resolver 关闭了 default-features
//! (仅开 tokio-runtime),`system-config` 特性不可用,因此这里手工
//! 解析 `/etc/resolv.conf` 的 `nameserver` 行构造 resolver;读不到或
//! 为空时回退公共 DNS(1.1.1.1 / 8.8.8.8)。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// 单次上游 connect 的超时,避免多地址轮询把连接建立拖得过长。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 记录缺 TTL 时的兜底值;同时把 TTL 钳在 [1s, 24h]。
const DEFAULT_TTL: u32 = 30;
const MAX_TTL: u32 = 24 * 3600;

struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

pub(crate) struct DnsCache {
    resolver: TokioAsyncResolver,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

fn build_resolver() -> TokioAsyncResolver {
    let mut config = ResolverConfig::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("nameserver") {
                continue;
            }
            if let Some(ns) = fields.next() {
                if let Ok(ip) = ns.parse::<IpAddr>() {
                    let addr = SocketAddr::new(ip, 53);
                    config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
                    config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
                }
            }
        }
    }
    if config.name_servers().is_empty() {
        tracing::warn!(
            "no usable nameserver in /etc/resolv.conf, falling back to 1.1.1.1/8.8.8.8"
        );
        for ip in [IpAddr::from([1, 1, 1, 1]), IpAddr::from([8, 8, 8, 8])] {
            let addr = SocketAddr::new(ip, 53);
            config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
        }
    }
    let mut opts = ResolverOpts::default();
    opts.cache_size = 1024;
    TokioAsyncResolver::tokio(config, opts)
}

impl DnsCache {
    pub(crate) fn new() -> Self {
        Self {
            resolver: build_resolver(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// 解析 host → 地址列表(附加端口)。IP 字面量直通;域名走 TTL 缓存。
    /// `force = true` 时跳过缓存读、强制刷新(连接全失败后的重试路径)。
    /// 解析失败但存在过期缓存时回退返回旧值(优于直接报错)。
    pub(crate) async fn resolve(
        &self,
        host: &str,
        port: u16,
        force: bool,
    ) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let now = Instant::now();
        if !force {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(host) {
                if entry.expires_at > now {
                    return Ok(entry
                        .addrs
                        .iter()
                        .map(|ip| SocketAddr::new(*ip, port))
                        .collect());
                }
            }
        }

        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => {
                let addrs: Vec<IpAddr> = lookup.iter().collect();
                if addrs.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("dns lookup for {host} returned no addresses"),
                    ));
                }
                // 取应答中各记录 TTL 的最小值作为缓存有效期。
                let ttl = lookup
                    .as_lookup()
                    .records()
                    .iter()
                    .map(|r| r.ttl())
                    .min()
                    .unwrap_or(DEFAULT_TTL)
                    .clamp(1, MAX_TTL);
                self.cache.lock().unwrap().insert(
                    host.to_string(),
                    CacheEntry {
                        addrs: addrs.clone(),
                        expires_at: now + Duration::from_secs(ttl as u64),
                    },
                );
                Ok(addrs
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect())
            }
            Err(e) => {
                // 过期缓存兜底:上游 DNS 短暂故障时维持转发。
                let stale = self
                    .cache
                    .lock()
                    .unwrap()
                    .get(host)
                    .map(|entry| {
                        entry
                            .addrs
                            .iter()
                            .map(|ip| SocketAddr::new(*ip, port))
                            .collect::<Vec<_>>()
                    });
                if let Some(addrs) = stale {
                    tracing::warn!(host = %host, error = %e, "dns refresh failed, using stale cache");
                    return Ok(addrs);
                }
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("dns lookup for {host} failed: {e}"),
                ))
            }
        }
    }
}

/// 依次尝试解析出的地址;全部失败则强制重新解析一次再试一轮
/// (覆盖「缓存里的地址全部失联」的场景)。
pub(crate) async fn connect_upstream(
    dns: &DnsCache,
    host: &str,
    port: u16,
) -> io::Result<tokio::net::TcpStream> {
    let mut last_err: Option<String> = None;
    for force in [false, true] {
        let addrs = match dns.resolve(host, port, force).await {
            Ok(a) => a,
            Err(e) => {
                last_err = Some(e.to_string());
                break;
            }
        };
        for addr in &addrs {
            match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
                .await
            {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last_err = Some(format!("connect {addr}: {e}")),
                Err(_) => last_err = Some(format!("connect {addr}: timeout")),
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "all upstream addresses for {host}:{port} failed: {}",
            last_err.unwrap_or_else(|| "no addresses".to_string())
        ),
    ))
}
