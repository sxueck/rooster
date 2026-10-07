//! nftables 封装(crate `rooster-nft`)。
//!
//! 直接通过 netlink 操作 `table inet rooster`,不调用 `nft` 命令行:
//! - [`NftHandle`]:底层 netlink 句柄(建表、set 元素增删查、ssh meter、删表);
//! - [`NftBanManager`]:实现 [`BanManager`],nft 内核 set + redb 持久化 +
//!   白名单拒封与重启对账。
//!
//! 模块划分:`consts`(uapi 常量)→ `codec`(nlattr/nlmsghdr 编解码)→
//! `builders`(消息构造与 dump 解析)→ `netlink`(socket 循环与句柄)→
//! `manager`(封禁管理器)。

pub mod builders;
pub mod codec;
pub mod consts;
pub mod manager;
pub mod netlink;
#[cfg(test)]
pub(crate) mod testutil;

pub use manager::NftBanManager;
pub use netlink::NftHandle;

use std::time::Duration;

/// nftables 表名(`table inet rooster`)。
pub const TABLE: &str = "rooster";
/// 常驻白名单 set(IPv4, interval)。
pub const SET_ALLOW_V4: &str = "allow_v4";
/// 常驻白名单 set(IPv6, interval)。
pub const SET_ALLOW_V6: &str = "allow_v6";
/// 封禁 set(IPv4, interval + timeout)。
pub const SET_BLOCK_V4: &str = "block_v4";
/// 封禁 set(IPv6, interval + timeout)。
pub const SET_BLOCK_V6: &str = "block_v6";
/// 地理封锁 set(IPv4, interval)。
pub const SET_GEO_V4: &str = "geo_block_v4";
/// 地理封锁 set(IPv6, interval)。
pub const SET_GEO_V6: &str = "geo_block_v6";

/// 封禁范围:本节点或全网联动。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BanScope {
    Local,
    Global,
}

/// 一条封禁记录。
///
/// 运行时状态存 redb,内核侧由 nftables set timeout 过期。
/// `expires_at` 由 [`BanManager::list_bans`] / 持久化层填充(unix 秒),
/// 新建封禁时为 `None`。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BanEntry {
    pub ip: String,
    pub ttl: Duration,
    pub reason: String,
    pub plugin: String,
    pub node: String,
    pub scope: BanScope,
    /// 首次封禁时间(unix 秒);旧账本按原始 TTL 还原。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub started_at: Option<u64>,
    /// 绝对到期时间(unix 秒);`list_bans` 填充,持久化时必填。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("invalid ip or cidr: {0}")]
    InvalidAddress(String),
    #[error("netlink error: {0}")]
    Netlink(String),
    #[error("ban refused: {0}")]
    Refused(String),
}

/// 底层 netlink socket 抽象(真实实现为 libc AF_NETLINK;测试用 mock)。
pub trait NetlinkSocket: Send {
    /// 发送一个完整缓冲(单条或多条拼接的 netlink 消息)。
    fn send(&mut self, buf: &[u8]) -> Result<(), NftError>;
    /// 接收一段字节;返回长度,0 表示对端关闭。
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NftError>;
}

/// 封禁管理器。实现方负责维护 nftables set 与 redb 记录的一致性。
pub trait BanManager: Send + Sync {
    /// 落一条封禁:白名单命中拒绝([`NftError::Refused`]),否则写内核 +
    /// redb。重复封禁同一 IP 视为延长。
    fn apply_ban(&self, entry: &BanEntry) -> Result<(), NftError>;
    /// 解除封禁;目标不存在也返回 `Ok(())`。
    fn remove_ban(&self, ip: &str) -> Result<(), NftError>;
    /// 列出活跃封禁(`expires_at` 填充,`ttl` 为剩余秒数);顺带清理过期行。
    fn list_bans(&self) -> Result<Vec<BanEntry>, NftError>;
    /// 全量替换内核白名单 set(allow_v4/allow_v6)。
    fn set_allowlist(&self, nets: &[ipnet::IpNet]) -> Result<(), NftError>;
    /// ssh 新连接速率限制(nftables meter,netlink 下发)。
    fn set_ssh_limit(&self, port: u16, rate: &str, burst: u32) -> Result<(), NftError>;
}
