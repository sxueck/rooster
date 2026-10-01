//! 插件框架类型。
//!
//! 只定义挂载点与动作契约;内置插件(ssh-guard / http-guard)的
//! 实现和 WASM 宿主分别接入。所有 `Ban` 动作统一交给
//! 封禁管理器执行。

use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    OnL4Accept,
    OnTlsClientHello,
    OnHttpRequestHeaders,
    OnHttpRequestBody,
    OnHttpResponseHeaders,
    OnLogLine,
    OnTick,
}

/// 插件在 hook 中可返回的动作。
#[derive(Debug, Clone)]
pub enum PluginAction {
    Continue,
    Deny { status: Option<u16> },
    Ban {
        ip: String,
        ttl: Duration,
        reason: String,
        global: bool,
    },
    Tag { key: String, value: String },
    RateLimit { key: String, rate: String },
}

/// `on_l4_accept` 收到的连接元数据。
#[derive(Debug, Clone)]
pub struct ConnMeta {
    pub peer: SocketAddr,
    pub listen: SocketAddr,
    pub rule: String,
}

pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn hooks(&self) -> &'static [Hook];
}
