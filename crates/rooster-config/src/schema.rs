//! Agent `config.yaml` 的类型定义。
//!
//! 顶层分为 `local` 与 `managed` 两层;进程级配置(agent、management、
//! hub、security.admin-allowlist)只允许出现在 local 层。
//! 字段大量使用 `Option` + `#[serde(default)]`,让部分配置(模板片段、
//! 单条 forward 的 PUT body)可以被独立反序列化。

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::ConfigError;

// ---------------------------------------------------------------------------
// 顶层结构

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AgentConfigFile {
    #[serde(default)]
    pub local: LocalConfig,
    #[serde(default)]
    pub managed: ManagedConfig,
}

/// local 层:本机专属配置与覆盖项,面板单节点修改默认写到这里。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalConfig {
    #[serde(default)]
    pub agent: AgentSection,
    #[serde(default)]
    pub management: ManagementSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub: Option<HubSection>,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub events: EventsSection,
    /// 远程升级执行方式。
    #[serde(default)]
    pub upgrade: UpgradeSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GlobalGeoipConfig>,
    /// 单节点加固覆盖项;与 managed 层递归合并(local 优先)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardening: Option<HardeningConfig>,
    /// local 层也可以有转发规则;与 managed 层按 `id` 合并。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<ForwardRule>,
    /// local 层的 WASM 插件覆盖项;与 managed 层按 `id` 合并。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wasm_plugins: Vec<WasmPlugin>,
}

/// managed 层:由 Hub 模板下发,面板中只读。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ManagedConfig {
    #[serde(default)]
    pub plugins: PluginsConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GlobalGeoipConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<Site>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<ForwardRule>,
    /// 不带 id 的列表:合并时取并集。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wasm_plugins: Vec<WasmPlugin>,
    /// 由 Hub 模板下发的加固配置;所有子项默认关闭,必须显式启用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardening: Option<HardeningConfig>,
}

// ---------------------------------------------------------------------------
// local:进程级配置

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AgentSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
}

impl AgentSection {
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/rooster"))
    }

    pub fn log_level(&self) -> &str {
        self.log_level.as_deref().unwrap_or("info")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ManagementSection {
    /// 默认只绑定回环地址。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<SocketAddr>,
    /// bcrypt 哈希;明文在首次启动时自动哈希回写。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_listen: Option<SocketAddr>,
}

impl ManagementSection {
    pub fn listen(&self) -> SocketAddr {
        self.listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9870)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HubSection {
    pub url: String,
    /// 一次性注册 token(install.sh 写入);注册成功后可删。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecuritySection {
    /// 白名单优先级最高,任何封禁都无法覆盖。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admin_allowlist: Vec<String>,
    /// 需确认变更的回滚时限,默认 60s。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub apply_confirm_timeout: Option<Duration>,
    /// 升级包 Ed25519 公钥(`ed25519:<base64>`);设置后作为本地锚点,
    /// 升级帧携带的公钥必须与之匹配(强化路径)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_public_key: Option<String>,
    /// 是否把 Hub 地址自动加入封禁豁免名单,默认 true。
    ///
    /// 需要关掉它的典型场景:Agent 经 NAT/portproxy 回连 Hub 时,
    /// 节点看到的 Hub 地址同时也是所有外部客户端的源地址 —— 默认豁免
    /// 会把这整个地址变成“封不掉”,反代等于失去封禁能力。置 false
    /// 后仅保留 admin-allowlist 与本机地址豁免。
    #[serde(default = "default_true")]
    pub hub_address_exempt: bool,
}

impl SecuritySection {
    pub fn apply_confirm_timeout(&self) -> Duration {
        self.apply_confirm_timeout.unwrap_or(Duration::from_secs(60))
    }
}

/// 手写 Default:`security:` 整段缺失时,上层字段级 `#[serde(default)]` 走的是
/// 类型默认值,不会经过 `hub_address_exempt` 的 `default = "default_true"`。
/// 不在这里写 true,Hub 豁免会在“没配 security”的节点上静默失效。
impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            admin_allowlist: Vec::new(),
            apply_confirm_timeout: None,
            upgrade_public_key: None,
            hub_address_exempt: default_true(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EventsSection {
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub retention: Option<Duration>,
}

// ---------------------------------------------------------------------------
// 加固(hardening):L4/L7 强化措施。全部子项 opt-in —— 缺省 = 不启用。
//
// 设计约束(docs/hardening-plan.md):蜜罐/扫描检测必须排除真实监听端口,
// 该检查在 validate_effective 做;L7 各项缺省时沿用现行为(不设显式阈值)。

/// 加固配置:全部子项 opt-in;未知字段直接拒(拼写错误不得静默变成
/// 「未配置」),缺省值在消费侧 accessor 应用。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HardeningConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub honeypot: Option<HoneypotConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_guard: Option<PortGuardConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_limit: Option<ConnLimitConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag_guard: Option<FlagGuardConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow_loris: Option<SlowLorisConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_hello: Option<ClientHelloGuardConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_cap: Option<BodyCapConfig>,
}

/// 蜜罐端口:命中即把源 IP 投入封禁队列(经 BanManager 落地)。
///
/// 字段全部 None 保持(不在反序列化时填默认):`local.hardening` 是
/// managed 模板之上的部分覆盖,填了默认值的字段会在 merge 时静默覆盖
/// 模板;默认一律在消费侧 accessor 里应用。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HoneypotConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 高危端口清单;缺省 [`honeypot_ports_of`]。与真实监听端口冲突时
    /// 配置校验直接报错,不会带病下发。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
    /// 命中暂存集的元素存活时长(判定的聚合窗口)。默认 5m。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub hit_window: Option<Duration>,
    /// 封禁时长。默认 1h。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub ban_time: Option<Duration>,
}

impl HoneypotConfig {
    pub fn hit_window_or_default(&self) -> Duration {
        self.hit_window.unwrap_or_else(|| dur(300))
    }

    pub fn ban_time_or_default(&self) -> Duration {
        self.ban_time.unwrap_or_else(|| dur(3600))
    }
}

/// 通用端口扫描检测(sshguard 的泛化):窗口内对未监听端口的
/// 新建连接次数超阈值 → 封禁。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PortGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 窗口内允许命中未监听端口的次数上限;超过即封。默认 30。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hits: Option<u32>,
    /// 统计窗口(find time)。默认 60s。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub find_time: Option<Duration>,
    /// 额外放行端口(主机上非 rooster 管理的真实监听,如打印机/数据库)。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_open_ports: Vec<u16>,
    /// 封禁时长。默认 30m。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub ban_time: Option<Duration>,
}

impl PortGuardConfig {
    pub fn max_hits_or_default(&self) -> u32 {
        self.max_hits.unwrap_or(30)
    }

    pub fn find_time_or_default(&self) -> Duration {
        self.find_time.unwrap_or_else(|| dur(60))
    }

    pub fn ban_time_or_default(&self) -> Duration {
        self.ban_time.unwrap_or_else(|| dur(1800))
    }
}

/// 全局 L4 新建连接限速(每源 IP,所有端口);超限者进封禁队列。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConnLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `N/(second|minute|hour)`,如 `60/second`。默认 `60/second`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// 突发宽容(令牌桶 burst)。默认 20。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    /// 超限后的封禁时长。默认 30m。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub ban_time: Option<Duration>,
}

impl ConnLimitConfig {
    pub fn rate_or_default(&self) -> &str {
        self.rate.as_deref().unwrap_or("60/second")
    }

    pub fn burst_or_default(&self) -> u32 {
        self.burst.unwrap_or(20)
    }

    pub fn ban_time_or_default(&self) -> Duration {
        self.ban_time.unwrap_or_else(|| dur(1800))
    }
}

/// ct state invalid 与 TCP flag 异常(NULL / SYN+FIN / XMAS)直接丢弃。
/// 同样 deny_unknown_fields:`enable` 拼错不得静默变成「未配置」。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FlagGuardConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Slowloris / 慢读防护(终止模式的 HTTP 数据面)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SlowLorisConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 请求头读取超时。默认 15s。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub header_timeout: Option<Duration>,
    /// 请求体两个数据块之间的最大空闲(WAF 检测缓冲阶段)。默认 15s。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub body_idle_timeout: Option<Duration>,
    /// 每 IP 并发连接上限(明文 80 与 TLS 443 合计,按 socket 对端计)。默认 64。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_conns_per_ip: Option<u32>,
}

impl SlowLorisConfig {
    pub fn header_timeout_or_default(&self) -> Duration {
        self.header_timeout.unwrap_or_else(|| dur(15))
    }

    pub fn body_idle_or_default(&self) -> Duration {
        self.body_idle_timeout.unwrap_or_else(|| dur(15))
    }

    pub fn max_conns_or_default(&self) -> u32 {
        self.max_conns_per_ip.unwrap_or(64).max(1)
    }
}

/// TLS ClientHello 窥探阶段的速率与大小上限(握手洪水防护)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ClientHelloGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 单条连接可缓冲的 ClientHello 最大字节数;超过直接断开。默认 16 KiB。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<usize>,
    /// 每源 IP 的 TLS 新建连接速率。默认 `30/minute`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// 突发宽容。默认 10。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

impl ClientHelloGuardConfig {
    pub fn max_size_or_default(&self) -> usize {
        self.max_size.unwrap_or(16 * 1024).max(517)
    }

    pub fn rate_or_default(&self) -> &str {
        self.rate.as_deref().unwrap_or("30/minute")
    }

    pub fn burst_or_default(&self) -> u32 {
        self.burst.unwrap_or(10)
    }
}

/// 全局请求体硬上限(WAF 之前的资源保护);站点可用
/// `sites[].max-body-size` 单独放宽/收紧。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BodyCapConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 默认 32 MiB。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
}

impl BodyCapConfig {
    pub fn max_size_or_default(&self) -> u64 {
        self.max_size.unwrap_or(32 * 1024 * 1024).max(1024)
    }
}

fn dur(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn default_honeypot_ports() -> Vec<u16> {
    [23u16, 135, 137, 139, 445, 1433, 1521, 2049, 3306, 3389, 4444, 5900, 6379, 7547, 8081,
     9200, 11211, 27017, 27018, 50000]
        .into_iter()
        .collect()
}

/// 蜜罐默认端口表(仅当 `ports` 未显式给出时生效)。
pub fn honeypot_ports_of(cfg: &HoneypotConfig) -> Vec<u16> {
    cfg.ports.clone().unwrap_or_else(default_honeypot_ports)
}

/// 远程升级执行方式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeMethod {
    /// `systemctl restart rooster`(生产默认)。
    #[default]
    Systemd,
    /// 直接 exit(0),交给外部监督进程重启(开发/容器)。
    Exit,
    /// 只下载校验替换,不重启(测试)。
    None,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UpgradeSection {
    #[serde(default)]
    pub method: UpgradeMethod,
}

// ---------------------------------------------------------------------------
// forwards

fn default_forward_proto() -> ForwardProto {
    ForwardProto::Tcp
}

fn default_proxy_protocol() -> ProxyProtocol {
    ProxyProtocol::None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForwardRule {
    pub id: String,
    #[serde(default = "default_forward_proto")]
    pub proto: ForwardProto,
    /// `[addr:]port`;缺省 addr 为 0.0.0.0。
    pub listen: SocketAddr,
    /// `host:port`,host 可以是域名(按 TTL 重新解析)。
    pub target: String,
    #[serde(default = "default_proxy_protocol")]
    pub proxy_protocol: ProxyProtocol,
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub udp_idle_timeout: Option<Duration>,
    /// 前置 LB 场景:接受客户端发来的 PROXY protocol 头,ACL 与限速
    /// 以头部中的真实源地址为准。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_proxy_protocol: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<AclConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ForwardLimits>,
    /// 在 local 层写 `{ id: x, disabled: true }` 可屏蔽模板中的同名项。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProto {
    Tcp,
    Udp,
    #[serde(rename = "tcp+udp")]
    TcpUdp,
}

impl ForwardProto {
    /// 该规则占用的传输层协议集合,用于端口冲突检测。
    pub fn protocols(&self) -> &'static [ &'static str] {
        match self {
            ForwardProto::Tcp => &["tcp"],
            ForwardProto::Udp => &["udp"],
            ForwardProto::TcpUdp => &["tcp", "udp"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    None,
    V1,
    V2,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AclConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForwardLimits {
    /// `N/(second|minute|hour)`,如 `30/minute`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_rate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_conns_per_ip: Option<u32>,
}

// ---------------------------------------------------------------------------
// managed:插件与 WAF

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PluginsConfig {
    #[serde(default)]
    pub ssh_guard: SshGuardConfig,
    #[serde(default)]
    pub http_guard: HttpGuardConfig,
}

fn default_duration_10m() -> Option<Duration> {
    Some(Duration::from_secs(600))
}

fn default_duration_1h() -> Option<Duration> {
    Some(Duration::from_secs(3600))
}

fn default_duration_7d() -> Option<Duration> {
    Some(Duration::from_secs(7 * 24 * 3600))
}

fn default_ssh_port() -> u16 {
    22
}

fn default_max_retry() -> u32 {
    5
}

fn default_ban_time_factor() -> u32 {
    2
}

fn default_conn_rate() -> String {
    "10/minute".to_string()
}

fn default_conn_burst() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SshGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// sshd 实际监听端口。
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub source: SshLogSource,
    #[serde(default = "default_max_retry")]
    pub max_retry: u32,
    #[serde(default = "default_duration_10m", with = "humantime_serde")]
    pub find_time: Option<Duration>,
    #[serde(default = "default_duration_1h", with = "humantime_serde")]
    pub ban_time: Option<Duration>,
    /// 递增封禁:ban_time × factor^n。
    #[serde(default = "default_ban_time_factor")]
    pub ban_time_factor: u32,
    #[serde(default = "default_duration_7d", with = "humantime_serde")]
    pub ban_time_max: Option<Duration>,
    #[serde(default = "default_conn_rate")]
    pub conn_rate: String,
    #[serde(default = "default_conn_burst")]
    pub conn_burst: u32,
}

impl Default for SshGuardConfig {
    fn default() -> Self {
        serde_norway::from_str("{}").unwrap()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshLogSource {
    #[default]
    Journald,
    File,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HttpGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_http: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_https: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoipConfig>,    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeConfig>,
}

const DEFAULT_GEOIP_DATABASE: &str = "dbip-country-lite";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct GlobalGeoipConfig {
    // Keep absent fields unset so local overrides do not erase managed settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<bool>,
}

impl GlobalGeoipConfig {
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn database(&self) -> &str {
        self.database.as_deref().unwrap_or(DEFAULT_GEOIP_DATABASE)
    }

    pub fn auto_update(&self) -> bool {
        self.auto_update.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GeoipConfig {
    #[serde(default = "default_geoip_database")]
    pub database: String,
    #[serde(default = "default_true")]
    pub auto_update: bool,
    /// 库不可用(缺失 / 下载失败 / 解析失败)时的降级策略。
    /// 默认 false = fail-closed:配置了 geo 规则却查不到库时拒绝启动
    /// (前提不满足即拒绝启动);置 true 才降级放行。
    #[serde(default)]
    pub fail_open: bool,
}

fn default_geoip_database() -> String {
    DEFAULT_GEOIP_DATABASE.to_string()
}

fn default_true() -> bool {
    true
}

impl Default for GeoipConfig {
    fn default() -> Self {
        serde_norway::from_str("{}").unwrap()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AcmeConfig {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WafConfig {
    #[serde(default)]
    pub crs: CrsConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
}

fn default_paranoia_level() -> u8 {
    1
}

fn default_inbound_threshold() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CrsConfig {
    /// 默认开启：内嵌 CRS 子集随二进制分发，不联网也能加载；要缩小
    /// 覆盖面的节点显式写 `enabled: false`。默认关闭会让所有未显式配置的
    /// 节点只剩 10 条内置签名，面板报“CRS 未生效、覆盖面不足”。
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    #[serde(default = "default_inbound_threshold")]
    pub inbound_anomaly_threshold: u32,
}

impl Default for CrsConfig {
    fn default() -> Self {
        serde_norway::from_str("{}").unwrap()
    }
}

// ---------------------------------------------------------------------------
// managed:站点

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Site {
    pub id: String,
    pub server_names: Vec<String>,
    pub tls: SiteTls,
    pub upstream: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf: Option<SiteWafConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limit: Vec<RateLimitRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<ProxyProtocol>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ja4_deny: Vec<String>,
    /// 80 端口访问本站点时 301 到 https(默认关闭)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_https: Option<bool>,
    /// 本站点请求体硬上限(bytes);仅当 `hardening.body-cap` 启用时生效,
    /// 未配置则用全局 `hardening.body-cap.max-size`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteTls {
    #[serde(default)]
    pub mode: TlsMode,
    #[serde(default)]
    pub acme: bool,
    /// 本地证书来源;cert 与 acme 二选一,同时配置时本地证书优先。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    /// `https://` 上游跳过证书与 hostname 校验(默认校验)。
    /// 仅用于自签证书的内网上游;置 true 时任何能劫持到该连接的对端
    /// 都能冒充源站(安全项)。对本站点的所有 https 上游生效。
    #[serde(default)]
    pub skip_verify: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Passthrough,
    Terminate,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteWafConfig {
    #[serde(default)]
    pub mode: WafMode,
    /// 按规则 ID 排除,处理误报。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    #[default]
    Off,
    Detect,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RateLimitRule {
    /// `ip`、`ip+path` 或 `header:<name>`。
    pub key: String,
    /// `N/second` 等。
    pub rate: String,
    #[serde(default)]
    pub burst: u32,
    #[serde(default)]
    pub on_exceed: OnExceed,
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub ban_after: Option<Duration>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnExceed {
    #[default]
    Reject,
    Ban,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GeoRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

// ---------------------------------------------------------------------------
// managed:WASM 插件

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WasmPlugin {
    pub id: String,
    pub file: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<WasmLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<OnError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WasmLimits {
    /// 如 `16MiB`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// 如 `5ms`。
    #[serde(default, with = "humantime_serde", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnError {
    #[default]
    FailOpen,
    FailClosed,
}

// ---------------------------------------------------------------------------
// 合并结果

/// `local` 与 `managed` 合并后的生效配置。
/// 字段全部 `#[serde(default)]`:合并产物中允许缺失任何未配置的部分。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct EffectiveConfig {
    #[serde(default)]
    pub agent: AgentSection,
    #[serde(default)]
    pub management: ManagementSection,
    #[serde(default)]
    pub hub: Option<HubSection>,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub events: EventsSection,
    #[serde(default)]
    pub upgrade: UpgradeSection,
    #[serde(default)]
    pub hardening: HardeningConfig,
    #[serde(default)]
    pub geoip: Option<GlobalGeoipConfig>,
    #[serde(default)]
    pub forwards: Vec<ForwardRule>,
    #[serde(default)]
    pub plugins: PluginsConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub sites: Vec<Site>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub wasm_plugins: Vec<WasmPlugin>,
}

impl EffectiveConfig {
    pub fn attribution_geoip(&self) -> GlobalGeoipConfig {
        let mut global = self.geoip.clone().unwrap_or_else(|| {
            self.plugins.http_guard.geoip.as_ref().map(|legacy| GlobalGeoipConfig {
                enabled: None,
                database: Some(legacy.database.clone()),
                auto_update: Some(legacy.auto_update),
            }).unwrap_or_default()
        });
        if let Some(http) = &self.plugins.http_guard.geoip {
            // One shared file cannot have independent update policies; HTTP wins.
            if global.database() == http.database {
                global.auto_update = Some(http.auto_update);
            }
        }
        global
    }

    pub fn http_geoip(&self) -> GeoipConfig {
        self.plugins.http_guard.geoip.clone().unwrap_or_else(|| {
            let global = self.attribution_geoip();
            // Disabling attribution must not disable configured HTTP country rules.
            GeoipConfig {
                database: global.database().to_string(),
                auto_update: global.auto_update(),
                fail_open: false,
            }
        })
    }
}

impl AgentConfigFile {
    /// 分层合并:map 递归(local 覆盖)、带 id 列表按 id 合并、其余列表并集。
    /// 通过 serde_json::Value 做通用合并,再反序列化为强类型,
    /// 保证合并规则只在这一处实现。
    pub fn merge_effective(&self) -> Result<EffectiveConfig, ConfigError> {
        let local = serde_json::to_value(&self.local).map_err(|e| ConfigError::Merge(e.to_string()))?;
        let managed =
            serde_json::to_value(&self.managed).map_err(|e| ConfigError::Merge(e.to_string()))?;
        let merged = crate::merge::merge_values(&managed, &local);
        let mut effective: EffectiveConfig = serde_json::from_value(merged)
            .map_err(|e| ConfigError::Merge(e.to_string()))?;
        let global = effective.attribution_geoip();
        effective.geoip = Some(GlobalGeoipConfig {
            enabled: Some(global.enabled()),
            database: Some(global.database().to_string()),
            auto_update: Some(global.auto_update()),
        });
        Ok(effective)
    }
}
