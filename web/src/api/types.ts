/** Shared API types for the Rooster hub & node management surfaces (no `any`). */

export class ApiError extends Error {
  readonly status: number
  readonly payload: unknown
  constructor(status: number, message: string, payload: unknown = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }
}

export interface ReqOpts {
  method?: string
  body?: unknown
  raw?: { body: BodyInit; headers: Record<string, string> }
}

// ---------------- auth ----------------
export interface LoginResp {
  token: string
  expires_at: number
}

// ---------------- overview ----------------
export interface IpCount {
  ip: string
  count: number
}
export interface RuleCount {
  rule_id: string
  count: number
}
export interface CountryCount {
  country: string
  count: number
}
export interface TrendPoint {
  /** bucket start, epoch seconds (hour-aligned) */
  hour: number
  count: number
}
export interface OverviewResp {
  nodes_total: number
  nodes_online: number
  global_bans: number
  bans_24h: number
  top_attack_ips: IpCount[]
  top_rules: RuleCount[]
  top_countries: CountryCount[]
  trend_24h: TrendPoint[]
}

// ---------------- nodes ----------------
export interface NodeInfo {
  id: string
  labels: Record<string, string>
  version: string
  online: boolean
  last_seen: number
  config_hash: string
  pending_template: string | null
}
export interface NodesResp {
  nodes: NodeInfo[]
}
export interface RegisterTokenResp {
  token: string
  expires_at: number
  install_cmd: string
}
export interface OkResp {
  ok: boolean
}

// ---------------- node management (passthrough) ----------------
/** Agent emits the hyphenated key "rollback-in" (seconds until auto-rollback). */
export interface ConfirmInfo {
  token: string
  'rollback-in': number
}
export interface NodeConfigResp {
  hash: string
  raw: string
  /** agent 返回合并后配置的 JSON 对象(非 YAML 文本),敏感字段已脱敏 */
  effective: Record<string, unknown>
}
export interface ConfigWriteResp {
  hash: string
  confirm: ConfirmInfo | null
}
/** 内置插件 ssh-guard 的 effective 配置(agent GET /plugins/ssh-guard 原样回填) */
export interface SshGuardPluginConfig {
  enabled: boolean
  port: number
  source: 'journald' | 'file'
  'max-retry': number
  'find-time': string
  'ban-time': string
  'ban-time-factor': number
  'ban-time-max': string
  'conn-rate': string
  'conn-burst': number
}
export interface Layers {
  managed: Record<string, string>
  local: Record<string, string>
  effective: Record<string, string>
}
export interface ForwardRule {
  id: string
  proto: 'tcp' | 'udp' | 'tcp+udp'
  listen: string
  target: string
  'proxy-protocol'?: boolean
  'udp-idle-timeout'?: number
  'accept-proxy-protocol'?: boolean
  acl?: { allow: string[] }
  limits?: { 'conn-rate'?: number; 'max-conns-per-ip'?: number }
  disabled?: boolean
  [k: string]: unknown
}
export interface BanEntry {
  ip: string
  reason: string
  plugin: string
  node: string
  scope: 'local' | 'global'
  expires_at: number
  ttl_secs: number
}
export interface NodeBansResp {
  bans: BanEntry[]
}
/** 生效白名单条目来源：admin=管理员配置，hub=Hub 地址豁免，local=节点本地（如 loopback）。 */
export interface AllowlistEffectiveEntry {
  cidr: string
  source: 'admin' | 'hub' | 'local'
}
export interface AllowlistResp {
  'admin-allowlist': string[]
  /** 管理员 ∪ Hub ∪ 本地合并后的实际生效集合（旧节点可能不返回） */
  effective?: AllowlistEffectiveEntry[]
  /** Hub 地址被自动豁免时为 true */
  hub_address_exempt?: boolean
}
/** nftables 封禁引擎可用性；available=false 时节点侧封禁管理整体降级（bans 接口 503）。 */
export interface BanEngineStatus {
  available: boolean
  reason: string | null
}
export interface NodeStats {
  forwards: Record<string, number>
  http: Record<string, number>
  bans: number
  /** 旧节点可能不返回该字段 */
  ban_engine?: BanEngineStatus
}
export type WafMode = 'off' | 'detect' | 'block'
export interface Site {
  id: string
  'server-names': string[]
  upstream: string
  tls?: Record<string, unknown>
  waf?: { mode?: WafMode; exclusions?: string[] } | null
  'rate-limit'?: Record<string, unknown>
  geo?: Record<string, unknown>
  'proxy-protocol'?: boolean
  'ja4-deny'?: string[]
  'redirect-https'?: boolean
  [k: string]: unknown
}
/** Skipped rule entry of the WAF load report. */
export interface WafSkippedRule {
  line: number
  reason: string
}
export type WafCrsSource = 'builtin-embedded' | 'local-dir'
/** CRS 规则集装载状态；enabled=false 或 rules_present=false 表示 CRS 实际没生效，只剩内置签名。 */
export interface WafCrsStatus {
  enabled: boolean
  configured_paranoia_level: number
  rules_present: boolean
  source: WafCrsSource | null
  dir: string | null
  embedded_files: number
}
export interface WafReport {
  loaded: number
  /** 真正没加载上的规则(覆盖面损失)。 */
  skipped: WafSkippedRule[]
  /** 不支持的辅助指令条数(SecMarker 等),不进加载率分母。 */
  ignored_directives?: number | null
  paranoia_level: number
  unmodelled_targets: number
  crs: WafCrsStatus | null
}
export interface WafReportResp {
  /** null when the http-guard is disabled. */
  report: WafReport | null
  threshold: number
}
/** 一条当前生效的 WAF 规则（GET /management/waf/rules）。 */
export interface WafRule {
  id: number
  phase: number
  msg: string
  severity: string
  tags: string[]
  min_pl: number
}
export interface WafRulesResp {
  rules: WafRule[]
  total: number
  paranoia: number
  threshold: number
  by_severity: Record<string, number>
  by_phase: Record<string, number>
}
export interface HistoryResp {
  files: string[]
}
export interface HistoryFileResp {
  name: string
  raw: string
}

export interface WasmManifest {
  name: string
  version: string
  hooks: string[]
  config_schema: Record<string, unknown>
}
export interface WasmPlugin {
  id: string
  file: string
  hooks: string[]
  sites: string[]
  limits: Record<string, unknown>
  on_error: string
  config: Record<string, unknown>
  /** null for a plugin that failed to load. */
  manifest: WasmManifest | null
  status: string
}
/** Response of per-rule writes (forwards / sites / wasm): `{hash, id}`. */
export interface WriteRuleResp {
  hash: string
  id: string
}
export interface NodeWasmResp {
  plugins: WasmPlugin[]
}

// ---------------- events ----------------
export type RoosterEvent =
  | { kind: 'ban'; ip: string; reason: string; plugin: string; scope: string; ttl_secs: number }
  | {
      kind: 'block'
      ip: string
      rule_id: string
      site: string
      /** 被攻击路径；旧事件可能缺失 */
      path?: string | null
      /** 本次命中的全部规则 id；旧事件可能缺失 */
      hits?: number[]
      /** 累计异常评分；旧事件可能缺失 */
      score?: number | null
    }
  | { kind: 'config_changed'; hash: string }
  | { kind: 'config_invalid'; error: string; line: number }
  | { kind: 'config_rolled_back'; reason: string }
  | { kind: 'auth_temp_ban'; peer: string }

export interface EventRecord {
  node_id: string
  ts: number
  event: RoosterEvent
}
export interface NodeStatusMsg {
  type: 'node_status'
  node_id: string
  online: boolean
}
export type WsPush = EventRecord | NodeStatusMsg
export interface EventsResp {
  events: EventRecord[]
  offline_nodes: string[]
}
export interface EventsQuery {
  node?: string
  plugin?: string
  ip?: string
  rule_id?: string
  /** integer unix seconds */
  since?: number
  until?: number
  limit?: number
}

// ---------------- templates & rollouts ----------------
export interface Template {
  id: string
  name: string
  selector: Record<string, string>
  yaml: string
  updated_at: number
}
export interface TemplatesResp {
  templates: Template[]
}
export interface TemplatePreviewNode {
  node_id: string
  status: string
  diff: string
}
export interface TemplatePreviewResp {
  nodes: TemplatePreviewNode[]
}
export interface RolloutResult {
  node_id: string
  status: string
  error?: string
}
export interface RolloutRun {
  id: string
  template_id: string
  kind: string
  started_at: number
  status: string
  results: RolloutResult[]
}
export interface RolloutsResp {
  runs: RolloutRun[]
}
export interface RolloutKickResp {
  run_id: string
}

// ---------------- global bans ----------------
export interface GlobalBan {
  ip: string
  reason: string
  source_node: string
  expires_at: number
  ttl_secs: number
}
export interface GlobalBansResp {
  bans: GlobalBan[]
}
export interface BanPolicy {
  id: string
  match: { plugin?: string; event?: string; severity?: string }
  min_nodes?: number
  threshold?: number
  window_secs?: number
  ttl_secs: number
}
export interface BanPoliciesResp {
  policies: BanPolicy[]
}

// ---------------- upgrades ----------------
export interface UpgradeEntry {
  version: string
  size: number
  uploaded_at: number
}
export interface UpgradesResp {
  upgrades: UpgradeEntry[]
}

// ---------------- wasm registry ----------------
export interface WasmRegistryEntry {
  name: string
  size: number
  uploaded_at: number
}
export interface WasmRegistryResp {
  plugins: WasmRegistryEntry[]
}

// ---------------- audit ----------------
export interface AuditEntry {
  ts: number
  operator: string
  node: string
  method: string
  path: string
  body_digest: string
  status: number
}
export interface AuditResp {
  entries: AuditEntry[]
}

/** 加固(hardening)单段形态:仅 enabled 必填,可选字段按段适用(时长为 humantime 字符串) */
export interface HardeningSectionConfig {
  enabled: boolean
  ports?: number[]
  'hit-window'?: string
  'ban-time'?: string
  'max-hits'?: number
  'find-time'?: string
  'extra-open-ports'?: number[]
  rate?: string
  burst?: number
  'header-timeout'?: string
  'body-idle-timeout'?: string
  'max-conns-per-ip'?: number
  'max-size'?: number
}
/** GET/PUT /management/hardening 的整体配置(稀疏:未配置段缺省/为 null,全部默认关闭) */
export interface HardeningConfig {
  honeypot?: HardeningSectionConfig | null
  'port-guard'?: HardeningSectionConfig | null
  'conn-limit'?: HardeningSectionConfig | null
  'flag-guard'?: HardeningSectionConfig | null
  'slow-loris'?: HardeningSectionConfig | null
  'client-hello'?: HardeningSectionConfig | null
  'body-cap'?: HardeningSectionConfig | null
}
