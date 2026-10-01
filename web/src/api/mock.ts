/**
 * Mock backend: implements every hub/node endpoint against in-memory state,
 * plus a fake WebSocket stream. Routed by method + path regex so client.ts
 * can switch between mock and real fetch with a single env flag.
 *
 * Contract parity: this fixture mirrors the REAL backend byte-for-byte —
 * same paths/methods, kebab-case keys ("rollback-in"), epoch-SECOND numbers,
 * bare-array GETs, per-id PUT routes returning {hash, id}, empty-body
 * confirm, and auto-roll-back on unconfirmed writes. It must fail where the
 * real backend fails (no bulk PUT /forwards or /sites here).
 */
import {
  ApiError,
  type ReqOpts,
  type LoginResp,
  type OverviewResp,
  type NodesResp,
  type NodeInfo,
  type RegisterTokenResp,
  type OkResp,
  type NodeConfigResp,
  type ConfigWriteResp,
  type Layers,
  type ForwardRule,
  type BanEntry,
  type NodeBansResp,
  type AllowlistResp,
  type NodeStats,
  type Site,
  type BanEngineStatus,
  type AllowlistEffectiveEntry,
  type WafReportResp,
  type WafSkippedRule,
  type WafCrsStatus,
  type WafRule,
  type WafRulesResp,
  type HistoryResp,
  type HistoryFileResp,
  type WasmPlugin,
  type NodeWasmResp,
  type WriteRuleResp,
  type EventRecord,
  type RoosterEvent,
  type WsPush,
  type EventsResp,
  type Template,
  type TemplatesResp,
  type TemplatePreviewResp,
  type RolloutRun,
  type RolloutsResp,
  type RolloutKickResp,
  type GlobalBan,
  type GlobalBansResp,
  type BanPolicy,
  type BanPoliciesResp,
  type UpgradeEntry,
  type UpgradesResp,
  type WasmRegistryEntry,
  type WasmRegistryResp,
  type AuditEntry,
  type AuditResp,
} from './types'
import { toUnifiedDiff } from '../utils/diff'

// ---------------- helpers ----------------
const nowSec = () => Math.floor(Date.now() / 1000)
const secIn = (secs: number) => nowSec() + secs
const rand = (n: number) => Math.floor(Math.random() * n)
const pick = <T>(arr: readonly T[]): T => arr[rand(arr.length)]
const hex = (n: number) =>
  Array.from({ length: n }, () => '0123456789abcdef'[rand(16)]).join('')
const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
const bodyOf = <T>(opts: ReqOpts): T => (opts.body ?? {}) as T
const rawSize = (opts: ReqOpts): number => {
  const b = opts.raw?.body
  return b !== undefined && typeof b === 'object' && b !== null && 'size' in b
    ? Number((b as Blob).size)
    : 0
}

// ---------------- state types ----------------
interface MockNodeState {
  info: NodeInfo
  config: { raw: string; effective: string; hash: string }
  layersManaged: Record<string, string>
  layersLocal: Record<string, string>
  forwards: ForwardRule[]
  bans: BanEntry[]
  allowlist: string[]
  events: EventRecord[]
  stats: NodeStats
  sites: Site[]
  banEngine: BanEngineStatus
  waf: WafReportResp
  wafRules: WafRulesResp
  history: { name: string; raw: string }[]
  wasm: WasmPlugin[]
}

// ---------------- config yaml ----------------
const RULE_IDS = ['920-100', '913-110', '942-100', '930-120', '911-100'] as const
const REASONS = ['WAF 高危命中', '端口扫描', '暴力破解', 'CC 攻击', 'GeoIP 黑名单'] as const
const SITE_NAMES = ['portal.example.com', 'api.example.com', 'cdn.example.com'] as const

function buildConfig(subnet: string, threshold: number, extraAllow = ''): string {
  return `server:
  listen: "0.0.0.0:9443"
  hub: "https://hub.example.com"
log:
  level: info
storage:
  path: /var/lib/rooster/rooster.db
waf:
  enabled: true
  threshold: ${threshold}
  allowlist:
    - 10.0.0.0/8
    - 127.0.0.1/32${extraAllow}
forwards:
  - id: web
    listen: "0.0.0.0:80"
    target: "${subnet}.10:8080"
    proto: tcp
  - id: web-tls
    listen: "0.0.0.0:443"
    target: "${subnet}.10:8443"
    proto: tcp
  - id: dns
    listen: "0.0.0.0:53"
    target: "${subnet}.53:5353"
    proto: udp
plugins:
  - id: geo-filter
    file: geo_filter.wasm
    hooks: [pre_forward]
    on_error: pass
    config:
      default_action: allow
      blocked: [KP, SD]
  - id: rate-limit
    file: rate_limit.wasm
    hooks: [pre_forward, pre_response]
    on_error: pass
    config:
      rps: 200
      burst: 400
`
}

function buildWasm(subnet: string): WasmPlugin[] {
  return [
    {
      id: 'geo-filter',
      file: 'geo_filter.wasm',
      hooks: ['pre_forward'],
      sites: ['*'],
      limits: { mem_pages: 64 },
      on_error: 'pass',
      config: { default_action: 'allow', blocked: ['KP', 'SD'] },
      manifest: {
        name: 'geo-filter',
        version: '1.2.0',
        hooks: ['pre_forward'],
        config_schema: {
          type: 'object',
          properties: {
            default_action: {
              type: 'string',
              title: '默认动作',
              description: '未命中地区规则时的动作',
              enum: ['allow', 'deny'],
              default: 'allow',
            },
            blocked: {
              type: 'array',
              title: '封禁地区',
              description: 'ISO-3166 国家/地区代码',
              items: { type: 'string' },
            },
            strict: { type: 'boolean', title: '严格模式', default: false },
          },
        },
      },
      status: 'active',
    },
    {
      id: 'rate-limit',
      file: 'rate_limit.wasm',
      hooks: ['pre_forward', 'pre_response'],
      sites: ['portal.example.com', 'api.example.com'],
      limits: { mem_pages: 32 },
      on_error: 'pass',
      config: { rps: 200, burst: 400, scope: 'ip' },
      manifest: {
        name: 'rate-limit',
        version: '0.9.3',
        hooks: ['pre_forward', 'pre_response'],
        config_schema: {
          type: 'object',
          properties: {
            rps: { type: 'integer', title: '每秒请求数', default: 200 },
            burst: { type: 'integer', title: '突发容量', default: 400 },
            scope: {
              type: 'string',
              title: '统计维度',
              enum: ['ip', 'site', 'global'],
              default: 'ip',
            },
            dry_run: { type: 'boolean', title: '仅记录不拦截', default: false },
          },
        },
      },
      status: 'active',
    },
    {
      id: 'header-clean',
      file: 'header_clean.wasm',
      hooks: ['pre_response'],
      sites: ['*'],
      limits: { mem_pages: 16 },
      on_error: 'pass',
      config: { strip: ['Server', 'X-Powered-By'], add_via: true },
      manifest: {
        name: 'header-clean',
        version: '1.0.1',
        hooks: ['pre_response'],
        config_schema: {
          type: 'object',
          properties: {
            strip: {
              type: 'array',
              title: '移除的响应头',
              items: { type: 'string' },
            },
            add_via: { type: 'boolean', title: '追加 Via 头', default: true },
          },
        },
      },
      status: 'active',
    },
    {
      // 加载失败的插件：manifest 为 null（契约如此），面板不得崩溃
      id: 'geo-filter-fallback',
      file: 'geo_filter_broken.wasm',
      hooks: ['pre_forward'],
      sites: [`${subnet}.10`],
      limits: {},
      on_error: 'block',
      config: { default_action: 'deny' },
      manifest: null,
      status: 'error',
    },
  ]
}

// CRS 规则集三种形态：内置签名 / 本地目录 / 目录存在但没有规则文件（CRS 实际未生效）
const CRS_BUILTIN: WafCrsStatus = {
  enabled: true,
  configured_paranoia_level: 1,
  rules_present: true,
  source: 'builtin-embedded',
  dir: '/var/lib/rooster/rules/crs-builtin',
  embedded_files: 44,
}
const CRS_LOCAL: WafCrsStatus = {
  enabled: true,
  configured_paranoia_level: 2,
  rules_present: true,
  source: 'local-dir',
  dir: '/etc/rooster/rules/crs',
  embedded_files: 0,
}
const CRS_MISSING: WafCrsStatus = {
  enabled: true,
  configured_paranoia_level: 1,
  rules_present: false,
  source: 'local-dir',
  dir: '/var/lib/rooster/rules/crs',
  embedded_files: 0,
}
// nftables 不可用的节点：bans 管理接口整体 503（与真实 agent 降级行为一致）
const NFT_DOWN: BanEngineStatus = {
  available: false,
  reason: 'nftables unavailable: /run/nftables.sock: connect: no such file or directory (os error 2)',
}

function buildWafReport(threshold: number, crs: WafCrsStatus): WafReportResp {
  const loaded = 37
  const skipped: WafSkippedRule[] = [
    { line: 214, reason: 'GeoIP 数据库未加载（DB-IP Lite 未配置），规则 950-geo 跳过' },
    { line: 87, reason: '依赖规则 920-220 未加载，规则 951-ja4 跳过' },
    { line: 132, reason: '规则语法错误：未闭合的引号，规则 953-experiment 跳过' },
  ]
  return {
    report: {
      loaded,
      skipped,
      paranoia_level: crs.configured_paranoia_level,
      unmodelled_targets: 31 + rand(12),
      crs,
    },
    threshold,
  }
}

const WAF_MSGS = [
  'SQL Injection Attack Detected via libinjection',
  'Cross-site Scripting (XSS) Attack Detected',
  'OS File Access Attempt (/etc/passwd)',
  'Remote Command Execution: Unix Command Injection',
  'PHP Injection Attack: PHP Open Tag Found',
  'Request Missing a User-Agent Header',
] as const

function buildWafRules(threshold: number, crs: WafCrsStatus): WafRulesResp {
  if (!crs.enabled || !crs.rules_present) {
    return { rules: [], total: 0, paranoia: 0, threshold, by_severity: {}, by_phase: {} }
  }
  const sevs = ['CRITICAL', 'ERROR', 'WARNING', 'NOTICE'] as const
  const rules: WafRule[] = Array.from({ length: 37 }, (_, i) => {
    const minPl = (i % 2) + 1
    const tag = i % 3 === 0 ? 'attack-sqli' : i % 3 === 1 ? 'attack-xss' : 'attack-rce'
    return {
      id: 920100 + i,
      phase: (i % 5) + 1,
      msg: WAF_MSGS[i % WAF_MSGS.length],
      severity: sevs[i % 4],
      tags: [`paranoia-level/${minPl}`, tag],
      min_pl: minPl,
    }
  })
  const bySev: Record<string, number> = {}
  const byPhase: Record<string, number> = {}
  for (const r of rules) {
    bySev[r.severity] = (bySev[r.severity] ?? 0) + 1
    byPhase[String(r.phase)] = (byPhase[String(r.phase)] ?? 0) + 1
  }
  return {
    rules,
    total: rules.length,
    paranoia: crs.configured_paranoia_level,
    threshold,
    by_severity: bySev,
    by_phase: byPhase,
  }
}

const BLOCK_PATHS = [
  '/login',
  '/api/v1/search',
  '/wp-admin/setup-config.php',
  '/?id=1%27%20OR%20%271',
  '/admin/config',
] as const

function randEvent(): RoosterEvent {
  const r = Math.random()
  const ip = `45.${rand(255)}.${rand(255)}.${rand(255)}`
  if (r < 0.38) {
    const ruleId = pick(RULE_IDS)
    const hits = [Number(ruleId.replace(/[^0-9]/g, ''))]
    if (Math.random() < 0.6) hits.push(941100 + rand(40))
    if (Math.random() < 0.4) hits.push(932100 + rand(40))
    return {
      kind: 'block',
      ip,
      rule_id: ruleId,
      site: pick(SITE_NAMES),
      path: Math.random() < 0.8 ? pick(BLOCK_PATHS) : null,
      hits,
      score: Math.random() < 0.85 ? 5 + rand(45) : null,
    }
  }
  if (r < 0.68)
    return {
      kind: 'ban',
      ip,
      reason: pick(REASONS),
      plugin: pick(['waf', 'ratelimit', 'geo-filter']),
      scope: 'node',
      ttl_secs: pick([300, 600, 3600]),
    }
  if (r < 0.8) return { kind: 'auth_temp_ban', peer: `203.0.113.${rand(254)}` }
  if (r < 0.9) return { kind: 'config_changed', hash: hex(8) }
  if (r < 0.96)
    return {
      kind: 'config_invalid',
      error: 'yaml: mapping values are not allowed in this context',
      line: 10 + rand(40),
    }
  return { kind: 'config_rolled_back', reason: '操作员未在时限内确认' }
}

// ---------------- state ----------------
function buildNode(d: {
  id: string
  labels: Record<string, string>
  version: string
  online: boolean
  subnet: string
  threshold: number
  pending: string | null
  httpGuard: boolean
  crs?: WafCrsStatus
  banEngine?: BanEngineStatus
}): MockNodeState {
  const raw = buildConfig(d.subnet, d.threshold)
  const effExtra = '\n    - 192.168.8.0/24'
  const effective = buildConfig(d.subnet, d.threshold + 10, effExtra)
  const forwards: ForwardRule[] = [
    { id: 'web', listen: '0.0.0.0:80', target: `${d.subnet}.10:8080`, proto: 'tcp' },
    { id: 'web-tls', listen: '0.0.0.0:443', target: `${d.subnet}.10:8443`, proto: 'tcp' },
    { id: 'dns', listen: '0.0.0.0:53', target: `${d.subnet}.53:5353`, proto: 'udp' },
  ]
  const bans: BanEntry[] = Array.from({ length: 3 + rand(2) }, (_, i) => {
    const ttl = pick([300, 600, 3600, 86400])
    return {
      ip: `${pick([103, 185, 194])}.${rand(255)}.${rand(255)}.${rand(254) + 1}`,
      reason: pick(REASONS),
      plugin: pick(['waf', 'ratelimit', 'geo-filter', 'auth']),
      node: d.id,
      scope: i === 0 ? 'global' : 'local',
      expires_at: secIn(ttl - i * 60),
      ttl_secs: ttl,
    }
  })
  const events: EventRecord[] = Array.from({ length: 10 }, (_, i) => ({
    node_id: d.id,
    ts: nowSec() - (i * 480 + rand(240)),
    event: randEvent(),
  }))
  const history = [
    { name: 'config-2025-09-12T0830.yaml', raw: buildConfig(d.subnet, d.threshold - 20) },
    { name: 'config-2025-09-01T1400.yaml', raw: buildConfig(d.subnet, d.threshold - 10) },
    { name: 'config-2025-08-15T0910.yaml', raw: buildConfig(d.subnet, d.threshold) },
  ]
  return {
    info: {
      id: d.id,
      labels: { ...d.labels },
      version: d.version,
      online: d.online,
      last_seen: secIn(d.online ? -rand(30) : -900 - rand(3600)),
      config_hash: hex(8),
      pending_template: d.pending,
    },
    config: { raw, effective, hash: hex(8) },
    layersManaged: { 'tpl-default': buildConfig(d.subnet, d.threshold) },
    layersLocal: {
      'operator-edit': `# 节点本地手动调整\nwaf:\n  threshold: ${d.threshold + 10}\n  allowlist:\n    - 10.0.0.0/8\n    - 127.0.0.1/32${effExtra}\n`,
    },
    forwards,
    bans,
    allowlist: ['10.0.0.0/8', '127.0.0.1/32', '192.168.8.0/24'],
    events,
    banEngine: d.banEngine ?? { available: true, reason: null },
    stats: {
      forwards: {
        web: 90_000 + rand(200_000),
        'web-tls': 40_000 + rand(120_000),
        dns: 200_000 + rand(500_000),
      },
      http: {
        '2xx': 100_000 + rand(400_000),
        '4xx': 1_000 + rand(20_000),
        '5xx': rand(400),
        blocked: 500 + rand(9_000),
      },
      bans: bans.length,
      ban_engine: d.banEngine ?? { available: true, reason: null },
    },
    sites: [
      {
        id: 'portal',
        'server-names': ['portal.example.com', 'www.example.com'],
        upstream: `${d.subnet}.10:8080`,
        waf: { mode: 'block' },
      },
      {
        id: 'api',
        'server-names': ['api.example.com'],
        upstream: `${d.subnet}.11:9000`,
        waf: { mode: 'detect' },
      },
      {
        id: 'static',
        'server-names': ['cdn.example.com'],
        upstream: `${d.subnet}.12:8000`,
        waf: { mode: 'off' },
      },
    ],
    waf: d.httpGuard
      ? buildWafReport(d.threshold, d.crs ?? CRS_BUILTIN)
      : { report: null, threshold: d.threshold },
    wafRules: d.httpGuard
      ? buildWafRules(d.threshold, d.crs ?? CRS_BUILTIN)
      : { rules: [], total: 0, paranoia: 0, threshold: d.threshold, by_severity: {}, by_phase: {} },
    history,
    wasm: buildWasm(d.subnet),
  }
}

const state = {
  nodes: [
    buildNode({ id: 'edge-bj-01', labels: { role: 'edge', region: 'cn-north', dc: 'bj-1' }, version: '0.4.2', online: true, subnet: '10.0', threshold: 60, pending: null, httpGuard: true }),
    buildNode({ id: 'edge-sh-01', labels: { role: 'edge', region: 'cn-east', dc: 'sh-1' }, version: '0.4.2', online: true, subnet: '10.6', threshold: 70, pending: 'tpl-default', httpGuard: true, crs: CRS_LOCAL }),
    buildNode({ id: 'edge-fra-01', labels: { role: 'edge', region: 'eu-west', dc: 'fra-1' }, version: '0.4.1', online: false, subnet: '10.7', threshold: 60, pending: 'tpl-default', httpGuard: true, crs: CRS_MISSING }),
    // http-guard 未启用：waf report 为 null；nftables 不可用：bans 接口 503
    buildNode({ id: 'core-bj-01', labels: { role: 'internal', region: 'cn-north' }, version: '0.4.2', online: true, subnet: '10.8', threshold: 40, pending: null, httpGuard: false, banEngine: NFT_DOWN }),
  ],
  templates: [
    {
      id: 'tpl-default',
      name: '默认边缘配置',
      selector: { role: 'edge' },
      yaml: buildConfig('10.0', 60),
      updated_at: secIn(-4 * 86400),
    },
    {
      id: 'tpl-internal',
      name: '内部节点配置',
      selector: { role: 'internal' },
      yaml: buildConfig('10.8', 40),
      updated_at: secIn(-6 * 86400),
    },
  ] as Template[],
  rollouts: [] as RolloutRun[],
  globalBans: [
    { ip: '185.220.101.34', reason: 'Tor 出口节点', source_node: 'edge-bj-01', expires_at: secIn(86400), ttl_secs: 86400 },
    { ip: '103.4.217.11', reason: 'CC 攻击', source_node: 'edge-sh-01', expires_at: secIn(3600), ttl_secs: 3600 },
    { ip: '194.26.29.156', reason: '端口扫描', source_node: 'edge-fra-01', expires_at: secIn(7200), ttl_secs: 7200 },
    { ip: '45.155.205.233', reason: '暴力破解', source_node: 'core-bj-01', expires_at: secIn(600), ttl_secs: 600 },
    { ip: '141.98.10.60', reason: 'WAF 高危命中', source_node: 'edge-bj-01', expires_at: secIn(86400), ttl_secs: 86400 },
  ] as GlobalBan[],
  policies: [
    { id: 'pol-login-brute', match: { plugin: 'auth', event: 'auth_fail' }, min_nodes: 2, threshold: 10, window_secs: 300, ttl_secs: 3600 },
    { id: 'pol-waf-high', match: { plugin: 'waf', event: 'block', severity: 'high' }, threshold: 20, window_secs: 600, ttl_secs: 86400 },
    { id: 'pol-scan', match: { event: 'port_scan' }, min_nodes: 3, ttl_secs: 7200 },
  ] as BanPolicy[],
  upgrades: [
    { version: '0.5.0-rc1', size: 17_884_221, uploaded_at: secIn(-86400) },
    { version: '0.4.3', size: 16_200_124, uploaded_at: secIn(-12 * 86400) },
  ] as UpgradeEntry[],
  wasmRegistry: [
    { name: 'geo_filter.wasm', size: 246_802, uploaded_at: secIn(-25 * 86400) },
    { name: 'rate_limit.wasm', size: 118_337, uploaded_at: secIn(-13 * 86400) },
    { name: 'header_clean.wasm', size: 64_112, uploaded_at: secIn(-4 * 86400) },
  ] as WasmRegistryEntry[],
  audit: [] as AuditEntry[],
}

// seed: one completed rollout + audit history
state.rollouts.push({
  id: 'ro-' + hex(6),
  template_id: 'tpl-default',
  kind: 'template',
  started_at: nowSec() - 26 * 3600,
  status: 'completed',
  results: state.nodes.map((n) => ({
    node_id: n.info.id,
    status: n.info.id === 'core-bj-01' ? 'skipped' : 'applied',
    error: n.info.id === 'core-bj-01' ? '选择器不匹配' : undefined,
  })),
})
{
  const paths = [
    ['PUT', '/nodes/edge-bj-01/management/config'],
    ['POST', '/nodes/edge-sh-01/management/bans'],
    ['PUT', '/templates/tpl-default'],
    ['POST', '/templates/tpl-default/rollout'],
    ['DELETE', '/global-bans/103.4.217.99'],
    ['POST', '/wasm-plugins'],
    ['PUT', '/nodes/core-bj-01/management/forwards/web'],
  ]
  for (let i = 0; i < 42; i++) {
    const [method, path] = paths[i % paths.length]
    state.audit.push({
      ts: nowSec() - (i * 420 + rand(300)),
      operator: 'admin@mock',
      node: path.startsWith('/nodes/') ? path.split('/')[2] : '-',
      method,
      path,
      body_digest: hex(12),
      status: 200,
    })
  }
}

const trend24: OverviewResp['trend_24h'] = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String((new Date().getHours() - 23 + i + 48) % 24).padStart(2, '0')}:00`,
  count: 20 + rand(180),
}))

// ---------------- websocket mock ----------------
const wsSubs = new Set<(m: WsPush) => void>()

function pushEvent(nodeId: string, ev: RoosterEvent): void {
  const rec: EventRecord = { node_id: nodeId, ts: nowSec(), event: ev }
  const st = state.nodes.find((n) => n.info.id === nodeId)
  if (st) {
    st.events.unshift(rec)
    if (st.events.length > 60) st.events.length = 60
  }
  for (const fn of wsSubs) fn(rec)
}

export function connectMockWs(onMsg: (m: WsPush) => void): () => void {
  wsSubs.add(onMsg)
  const evTimer = window.setInterval(() => {
    const online = state.nodes.filter((n) => n.info.online)
    if (online.length === 0) return
    pushEvent(pick(online).info.id, randEvent())
  }, 2400)
  const stTimer = window.setInterval(() => {
    if (Math.random() < 0.2) {
      const st = pick(state.nodes)
      st.info.online = !st.info.online
      st.info.last_seen = secIn(0)
      onMsg({ type: 'node_status', node_id: st.info.id, online: st.info.online })
    }
  }, 5000)
  return () => {
    wsSubs.delete(onMsg)
    window.clearInterval(evTimer)
    window.clearInterval(stTimer)
  }
}

// ---------------- shared internals ----------------
function nodeState(id: string): MockNodeState {
  const st = state.nodes.find((n) => n.info.id === id)
  if (!st) throw new ApiError(404, '节点不存在')
  return st
}
function requireOnline(id: string): MockNodeState {
  const st = nodeState(id)
  if (!st.info.online) {
    throw new ApiError(503, '节点离线，管理请求无法转发', {
      error: 'node offline',
      last_seen: st.info.last_seen,
    })
  }
  return st
}
/** 封禁引擎降级的节点：bans 管理接口整体 503，body 带 ban_engine 详情（与真实 agent 一致） */
function requireBanEngine(st: MockNodeState): void {
  if (!st.banEngine.available) {
    throw new ApiError(503, 'nftables ban management unavailable on this node', {
      error: 'nftables ban management unavailable on this node',
      ban_engine: st.banEngine,
    })
  }
}

function matches(n: MockNodeState, selector: Record<string, string>): boolean {
  return Object.entries(selector).every(([k, v]) => n.info.labels[k] === v)
}
function targetNodes(selector: Record<string, string>): MockNodeState[] {
  return selector && Object.keys(selector).length > 0
    ? state.nodes.filter((n) => matches(n, selector))
    : state.nodes.slice()
}
function allEvents(): EventRecord[] {
  return state.nodes
    .flatMap((n) => n.events)
    .sort((a, b) => b.ts - a.ts)
}

/** confirm/auto-roll-back，与真实 agent 一致：PUT config 与 PUT allowlist 共用 */
const pendingConfirms = new Map<
  string,
  { token: string; timer: number; undo: () => void }
>()

function armConfirm(
  id: string,
  undo: () => void,
  rollbackIn: number,
): ConfigWriteResp['confirm'] {
  const token = 'cfm-' + hex(10)
  const timer = window.setTimeout(() => {
    const p = pendingConfirms.get(id)
    if (!p || p.token !== token) return
    pendingConfirms.delete(id)
    p.undo()
    pushEvent(id, { kind: 'config_rolled_back', reason: '操作员未在时限内确认' })
  }, rollbackIn * 1000)
  pendingConfirms.set(id, { token, timer, undo })
  return { token, 'rollback-in': rollbackIn }
}

function startRollout(kind: string, subject: string, targets: MockNodeState[]): string {
  const runId = 'ro-' + hex(6)
  const run: RolloutRun = {
    id: runId,
    template_id: subject,
    kind,
    started_at: nowSec(),
    status: 'running',
    results: targets.map((t) => ({ node_id: t.info.id, status: 'pending' })),
  }
  state.rollouts.unshift(run)
  let i = 0
  const timer = window.setInterval(() => {
    if (i >= run.results.length) {
      run.status = 'completed'
      window.clearInterval(timer)
      return
    }
    const r = run.results[i++]
    const target = targets[i - 1]
    if (Math.random() < 0.85) {
      r.status = 'applied'
      if (kind === 'template') target.info.pending_template = subject
    } else {
      r.status = 'failed'
      r.error = 'mock: 节点确认超时'
    }
    if (i >= run.results.length) run.status = 'completed'
  }, 1500)
  return runId
}

function overview(): OverviewResp {
  const events = allEvents()
  const ipCount = new Map<string, number>()
  const ruleCount = new Map<string, number>()
  let bans24 = 0
  for (const e of events) {
    if (e.event.kind === 'block') {
      ipCount.set(e.event.ip, (ipCount.get(e.event.ip) ?? 0) + 1)
      ruleCount.set(e.event.rule_id, (ruleCount.get(e.event.rule_id) ?? 0) + 1)
      bans24++
    } else if (e.event.kind === 'ban') {
      ipCount.set(e.event.ip, (ipCount.get(e.event.ip) ?? 0) + 1)
      bans24++
    }
  }
  const topIps: OverviewResp['top_attack_ips'] = [...ipCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => ({ ip, count }))
  const topRules: OverviewResp['top_rules'] = [...ruleCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([rule_id, count]) => ({ rule_id, count }))
  const countries: OverviewResp['top_countries'] = [
    { country: 'CN', count: 3200 + rand(900) },
    { country: 'US', count: 2100 + rand(700) },
    { country: 'RU', count: 1500 + rand(500) },
    { country: 'DE', count: 800 + rand(300) },
    { country: 'NL', count: 640 + rand(200) },
    { country: 'SG', count: 410 + rand(120) },
  ]
  return {
    nodes_total: state.nodes.length,
    nodes_online: state.nodes.filter((n) => n.info.online).length,
    global_bans: state.globalBans.length,
    bans_24h: bans24 + 120 + rand(300),
    top_attack_ips: topIps,
    top_rules: topRules,
    top_countries: countries,
    trend_24h: trend24,
  }
}

// ---------------- routing ----------------
interface MockRoute {
  method: string
  re: RegExp
  fn: (m: RegExpExecArray, opts: ReqOpts, url: URL) => unknown
}
const routes: MockRoute[] = []
function route(method: string, re: RegExp, fn: MockRoute['fn']): void {
  routes.push({ method, re, fn })
}

// ---- auth / overview ----
route('POST', /^\/auth\/login$/, (_m, opts) => {
  const { secret_key } = bodyOf<{ secret_key?: string }>(opts)
  if (!secret_key || secret_key.length < 4) throw new ApiError(401, '认证失败：secret_key 无效')
  return { token: 'mock-' + hex(24), expires_at: secIn(12 * 3600) } satisfies LoginResp
})
route('GET', /^\/overview$/, () => overview())

// ---- nodes ----
route('GET', /^\/nodes$/, () => ({ nodes: state.nodes.map((n) => n.info) }) satisfies NodesResp)
route('POST', /^\/nodes\/register-tokens$/, () => {
  const token = 'ntok-' + hex(20)
  return {
    token,
    expires_at: secIn(3600),
    install_cmd: `curl -fsSL https://get.rooster.example.com/install.sh | sudo -E bash -s -- --hub https://hub.example.com --token ${token}`,
  } satisfies RegisterTokenResp
})
route('PUT', /^\/nodes\/([^/]+)\/labels$/, (m, opts) => {
  const st = nodeState(decodeURIComponent(m[1]))
  st.info.labels = { ...st.info.labels, ...bodyOf<{ labels: Record<string, string> }>(opts).labels }
  return { ok: true } satisfies OkResp
})
route('DELETE', /^\/nodes\/([^/]+)$/, (m) => {
  const id = decodeURIComponent(m[1])
  nodeState(id)
  state.nodes = state.nodes.filter((n) => n.info.id !== id)
  return { ok: true } satisfies OkResp
})

// ---- node management passthrough ----
route('GET', /^\/nodes\/([^/]+)\/management\/config$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return { hash: st.config.hash, raw: st.config.raw, effective: st.config.effective } satisfies NodeConfigResp
})
route('PUT', /^\/nodes\/([^/]+)\/management\/config$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  const st = requireOnline(id)
  const yaml = String(bodyOf<{ yaml: string }>(opts).yaml ?? '')
  if (yaml === st.config.raw) return { hash: st.config.hash, confirm: null } satisfies ConfigWriteResp
  const prev = { ...st.config }
  st.config = { raw: yaml, effective: yaml, hash: hex(8) }
  const confirm = armConfirm(
    id,
    () => {
      st.config = { raw: prev.raw, effective: prev.effective, hash: prev.hash }
    },
    10,
  )
  pushEvent(id, { kind: 'config_changed', hash: st.config.hash })
  return { hash: st.config.hash, confirm } satisfies ConfigWriteResp
})
route('GET', /^\/nodes\/([^/]+)\/management\/layers$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  const layers: Layers = {
    managed: st.layersManaged,
    local: st.layersLocal,
    effective: { merged: st.config.effective },
  }
  return layers
})
// 真实 agent：GET /forwards 返回裸数组；无批量 PUT；PUT /forwards/{id} 返回 {hash, id}
route('GET', /^\/nodes\/([^/]+)\/management\/forwards$/, (m) => requireOnline(decodeURIComponent(m[1])).forwards)
route('PUT', /^\/nodes\/([^/]+)\/management\/forwards\/([^/]+)$/, (m, opts) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  const fwdId = decodeURIComponent(m[2])
  const rule = bodyOf<ForwardRule>(opts)
  if (!rule.target) throw new ApiError(400, "missing field `target`")
  const i = st.forwards.findIndex((f) => f.id === fwdId)
  if (i >= 0) st.forwards[i] = { ...rule, id: fwdId }
  else st.forwards.push({ ...rule, id: fwdId })
  return { hash: hex(8), id: fwdId } satisfies WriteRuleResp
})
route('DELETE', /^\/nodes\/([^/]+)\/management\/forwards\/([^/]+)$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  st.forwards = st.forwards.filter((f) => f.id !== decodeURIComponent(m[2]))
  return null // 204
})
route('GET', /^\/nodes\/([^/]+)\/management\/bans$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  requireBanEngine(st)
  return { bans: st.bans } satisfies NodeBansResp
})
route('POST', /^\/nodes\/([^/]+)\/management\/bans$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  const st = requireOnline(id)
  requireBanEngine(st)
  const b = bodyOf<{ ip: string; ttl_secs: number; reason: string }>(opts)
  st.bans.unshift({
    ip: b.ip,
    reason: b.reason || '手动封禁',
    plugin: 'panel',
    node: id,
    scope: 'local',
    expires_at: secIn(b.ttl_secs),
    ttl_secs: b.ttl_secs,
  })
  return { ok: true, ip: b.ip, ttl_secs: b.ttl_secs }
})
route('DELETE', /^\/nodes\/([^/]+)\/management\/bans\/([^/]+)$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  requireBanEngine(st)
  st.bans = st.bans.filter((b) => b.ip !== decodeURIComponent(m[2]))
  return null // 204
})
route('GET', /^\/nodes\/([^/]+)\/management\/allowlist$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  // effective = 管理员 ∪ Hub 地址豁免 ∪ 节点本地（如 loopback）
  const HUB_CIDR = '192.168.131.1/32'
  const LOCAL_CIDR = '127.0.0.1/32'
  const effective: AllowlistEffectiveEntry[] = st.allowlist.map((cidr) => ({ cidr, source: 'admin' }))
  if (!st.allowlist.includes(LOCAL_CIDR)) effective.push({ cidr: LOCAL_CIDR, source: 'local' })
  if (!st.allowlist.includes(HUB_CIDR)) effective.push({ cidr: HUB_CIDR, source: 'hub' })
  return {
    'admin-allowlist': st.allowlist,
    effective,
    hub_address_exempt: true,
  } satisfies AllowlistResp
})
route('PUT', /^\/nodes\/([^/]+)\/management\/allowlist$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  const st = requireOnline(id)
  const next = bodyOf<{ cidrs: string[] }>(opts).cidrs
  if (
    next.length === st.allowlist.length &&
    next.every((c, i) => c === st.allowlist[i])
  ) {
    return { hash: hex(8), confirm: null } satisfies ConfigWriteResp
  }
  const prev = st.allowlist
  st.allowlist = next
  const confirm = armConfirm(
    id,
    () => {
      st.allowlist = prev
    },
    10,
  )
  return { hash: hex(8), confirm } satisfies ConfigWriteResp
})
route('GET', /^\/nodes\/([^/]+)\/management\/events$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return st.events.slice()
})
route('GET', /^\/nodes\/([^/]+)\/management\/stats$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return { ...st.stats, bans: st.bans.length } satisfies NodeStats
})
// 真实 agent：GET /sites 返回裸数组；PUT /sites/{id} 返回 {hash, id}；DELETE 204
route('GET', /^\/nodes\/([^/]+)\/management\/sites$/, (m) => requireOnline(decodeURIComponent(m[1])).sites)
route('PUT', /^\/nodes\/([^/]+)\/management\/sites\/([^/]+)$/, (m, opts) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  const siteId = decodeURIComponent(m[2])
  const site = bodyOf<Site>(opts)
  if (!Array.isArray(site['server-names'])) throw new ApiError(400, "missing field `server-names`")
  const i = st.sites.findIndex((s) => s.id === siteId)
  if (i >= 0) st.sites[i] = { ...site, id: siteId }
  else st.sites.push({ ...site, id: siteId })
  return { hash: hex(8), id: siteId } satisfies WriteRuleResp
})
route('DELETE', /^\/nodes\/([^/]+)\/management\/sites\/([^/]+)$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  st.sites = st.sites.filter((s) => s.id !== decodeURIComponent(m[2]))
  return null // 204
})
route('GET', /^\/nodes\/([^/]+)\/management\/waf\/report$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return st.waf satisfies WafReportResp
})
route('GET', /^\/nodes\/([^/]+)\/management\/waf\/rules$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return st.wafRules satisfies WafRulesResp
})
route('GET', /^\/nodes\/([^/]+)\/management\/history$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return { files: st.history.map((f) => f.name) } satisfies HistoryResp
})
route('GET', /^\/nodes\/([^/]+)\/management\/history\/([^/]+)$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  const name = decodeURIComponent(m[2])
  const f = st.history.find((x) => x.name === name)
  if (!f) throw new ApiError(404, '历史文件不存在')
  return { name: f.name, raw: f.raw } satisfies HistoryFileResp
})
route('POST', /^\/nodes\/([^/]+)\/management\/apply\/confirm$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  requireOnline(id)
  const p = pendingConfirms.get(id)
  const tok = bodyOf<{ token: string }>(opts).token
  if (!p || p.token !== tok) throw new ApiError(404, '确认令牌无效或已过期（可能已回滚）')
  window.clearTimeout(p.timer)
  pendingConfirms.delete(id)
  return null // 200 空响应体
})
route('GET', /^\/nodes\/([^/]+)\/management\/wasm$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  return { plugins: st.wasm } satisfies NodeWasmResp
})
route('PUT', /^\/nodes\/([^/]+)\/management\/wasm\/([^/]+)$/, (m, opts) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  const id = decodeURIComponent(m[2])
  const plugin = bodyOf<WasmPlugin>(opts)
  const i = st.wasm.findIndex((p) => p.id === id)
  if (i < 0) throw new ApiError(404, '插件不存在')
  st.wasm[i] = { ...plugin, id }
  return { hash: hex(8), id } satisfies WriteRuleResp
})
route('DELETE', /^\/nodes\/([^/]+)\/management\/wasm\/([^/]+)$/, (m) => {
  const st = requireOnline(decodeURIComponent(m[1]))
  st.wasm = st.wasm.filter((p) => p.id !== decodeURIComponent(m[2]))
  return null // 204
})

// ---- templates & rollouts ----
route('GET', /^\/templates$/, () => ({ templates: state.templates }) satisfies TemplatesResp)
route('PUT', /^\/templates\/([^/]+)$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  const b = bodyOf<{ name: string; selector: Record<string, string>; yaml: string }>(opts)
  const t = state.templates.find((x) => x.id === id)
  if (t) {
    t.name = b.name
    t.selector = b.selector
    t.yaml = b.yaml
    t.updated_at = nowSec()
  } else {
    state.templates.push({ id, name: b.name, selector: b.selector, yaml: b.yaml, updated_at: nowSec() })
  }
  return { ok: true } satisfies OkResp
})
route('DELETE', /^\/templates\/([^/]+)$/, (m) => {
  const id = decodeURIComponent(m[1])
  state.templates = state.templates.filter((t) => t.id !== id)
  return { ok: true } satisfies OkResp
})
route('POST', /^\/templates\/([^/]+)\/preview$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  const tpl = state.templates.find((t) => t.id === id)
  if (!tpl) throw new ApiError(404, '模板不存在')
  const selector = bodyOf<{ selector?: Record<string, string> }>(opts).selector ?? tpl.selector
  const nodes = targetNodes(selector).map((n) => {
    if (!n.info.online) return { node_id: n.info.id, status: 'offline', diff: '' }
    const diff = toUnifiedDiff(n.config.raw, tpl.yaml)
    return { node_id: n.info.id, status: diff === '' ? 'unchanged' : 'changed', diff }
  })
  return { nodes } satisfies TemplatePreviewResp
})
route('POST', /^\/templates\/([^/]+)\/rollout$/, (m, opts) => {
  const id = decodeURIComponent(m[1])
  const tpl = state.templates.find((t) => t.id === id)
  if (!tpl) throw new ApiError(404, '模板不存在')
  const b = bodyOf<{ selector?: Record<string, string>; concurrency?: number; auto_confirm_delay_secs?: number }>(opts)
  const selector = b.selector && Object.keys(b.selector).length > 0 ? b.selector : tpl.selector
  const targets = targetNodes(selector).filter((n) => n.info.online)
  const runId = startRollout('template', id, targets)
  return { run_id: runId } satisfies RolloutKickResp
})
route('GET', /^\/rollouts$/, () => ({ runs: state.rollouts }) satisfies RolloutsResp)
route('GET', /^\/rollouts\/([^/]+)$/, (m) => {
  const run = state.rollouts.find((r) => r.id === decodeURIComponent(m[1]))
  if (!run) throw new ApiError(404, '下发任务不存在')
  return run
})

// ---- global bans ----
route('GET', /^\/global-bans$/, () => ({ bans: state.globalBans }) satisfies GlobalBansResp)
route('POST', /^\/global-bans$/, (_m, opts) => {
  const b = bodyOf<{ ip: string; ttl_secs: number; reason: string }>(opts)
  if (state.globalBans.some((x) => x.ip === b.ip)) throw new ApiError(409, '该 IP 已在全局黑名单中')
  const gb: GlobalBan = {
    ip: b.ip,
    reason: b.reason || '手动封禁',
    source_node: 'panel',
    expires_at: secIn(b.ttl_secs),
    ttl_secs: b.ttl_secs,
  }
  state.globalBans.unshift(gb)
  return gb
})
route('DELETE', /^\/global-bans\/([^/]+)$/, (m) => {
  state.globalBans = state.globalBans.filter((b) => b.ip !== decodeURIComponent(m[1]))
  return { ok: true } satisfies OkResp
})
route('GET', /^\/global-ban-policies$/, () => ({ policies: state.policies }) satisfies BanPoliciesResp)
route('PUT', /^\/global-ban-policies$/, (_m, opts) => {
  state.policies = bodyOf<{ policies: BanPolicy[] }>(opts).policies
  return { ok: true } satisfies OkResp
})

// ---- events query ----
route('GET', /^\/events$/, (_m, _opts, url) => {
  const q = url.searchParams
  const limit = Math.min(1000, Number(q.get('limit') ?? 200) || 200)
  const node = q.get('node') ?? ''
  const plugin = q.get('plugin') ?? ''
  const ip = q.get('ip') ?? ''
  const rule = q.get('rule_id') ?? ''
  // hub 以 u64 unix 秒解析 since/until：非数字直接 400（与真实行为一致）
  const sinceRaw = q.get('since')
  const untilRaw = q.get('until')
  const parseSecs = (raw: string | null, key: string): number => {
    if (raw === null || raw === '') return 0
    if (!/^\d+$/.test(raw)) throw new ApiError(400, `${key}: invalid digit found in string`)
    return Number(raw)
  }
  const since = parseSecs(sinceRaw, 'since')
  const until = parseSecs(untilRaw, 'until')
  const events = allEvents().filter((e) => {
    if (node && e.node_id !== node) return false
    if (ip && !(('ip' in e.event && e.event.ip === ip) || ('peer' in e.event && e.event.peer === ip))) return false
    if (rule && !('rule_id' in e.event && e.event.rule_id === rule)) return false
    if (plugin && !('plugin' in e.event && e.event.plugin === plugin)) return false
    if (since && e.ts < since) return false
    if (until && e.ts > until) return false
    return true
  })
  return {
    events: events.slice(0, limit),
    offline_nodes: state.nodes.filter((n) => !n.info.online).map((n) => n.info.id),
  } satisfies EventsResp
})

// ---- upgrades ----
route('GET', /^\/upgrades$/, () => ({ upgrades: state.upgrades }) satisfies UpgradesResp)
route('POST', /^\/upgrades$/, (_m, opts) => {
  const headers = opts.raw?.headers ?? {}
  const version = headers['x-rooster-version'] ?? ''
  if (!version) throw new ApiError(400, '缺少 x-rooster-version 头')
  if (!headers['x-rooster-signature']) throw new ApiError(400, '缺少 x-rooster-signature 签名头')
  const size = rawSize(opts)
  const entry: UpgradeEntry = { version, size, uploaded_at: nowSec() }
  state.upgrades.unshift(entry)
  return entry
})
route('POST', /^\/upgrades\/([^/]+)\/rollout$/, (m, opts) => {
  const version = decodeURIComponent(m[1])
  if (!state.upgrades.some((u) => u.version === version)) throw new ApiError(404, '版本不存在')
  const b = bodyOf<{ selector?: Record<string, string>; batch_size?: number; wait_secs?: number }>(opts)
  const targets = targetNodes(b.selector ?? {}).filter((n) => n.info.online)
  const runId = startRollout('upgrade', version, targets)
  return { run_id: runId } satisfies RolloutKickResp
})

// ---- audit ----
route('GET', /^\/audit$/, (_m, _opts, url) => {
  const q = url.searchParams
  const limit = Math.min(500, Number(q.get('limit') ?? 50) || 50)
  const offset = Math.max(0, Number(q.get('offset') ?? 0) || 0)
  return { entries: state.audit.slice(offset, offset + limit) } satisfies AuditResp
})

// ---- wasm registry ----
route('GET', /^\/wasm-plugins$/, () => ({ plugins: state.wasmRegistry }) satisfies WasmRegistryResp)
route('POST', /^\/wasm-plugins$/, (_m, opts) => {
  const name = opts.raw?.headers?.['x-rooster-name'] ?? ''
  if (!name.endsWith('.wasm')) throw new ApiError(400, 'x-rooster-name 必须以 .wasm 结尾')
  const size = rawSize(opts)
  const entry: WasmRegistryEntry = { name, size, uploaded_at: nowSec() }
  state.wasmRegistry = [entry, ...state.wasmRegistry.filter((p) => p.name !== name)]
  return entry
})
route('DELETE', /^\/wasm-plugins\/([^/]+)$/, (m) => {
  const name = decodeURIComponent(m[1])
  state.wasmRegistry = state.wasmRegistry.filter((p) => p.name !== name)
  return { ok: true } satisfies OkResp
})

// ---------------- entry ----------------
export async function handle<T>(path: string, opts: ReqOpts = {}): Promise<T> {
  await delay(60 + rand(140))
  const method = (opts.method ?? 'GET').toUpperCase()
  const url = new URL('http://mock.local' + path)
  for (const r of routes) {
    if (r.method !== method) continue
    const m = r.re.exec(url.pathname)
    if (m) {
      const result = await r.fn(m, opts, url)
      if (method !== 'GET' && path !== '/auth/login') {
        const nodeMatch = /\/nodes\/([^/]+)/.exec(path)
        state.audit.unshift({
          ts: nowSec(),
          operator: 'admin@mock',
          node: nodeMatch ? decodeURIComponent(nodeMatch[1]) : '-',
          method,
          path,
          body_digest: hex(12),
          status: 200,
        })
        if (state.audit.length > 200) state.audit.length = 200
      }
      return result as T
    }
  }
  throw new ApiError(404, `mock 未实现：${method} ${path}`)
}

// keep type imports used
export type { AuditEntry, AuditResp }
