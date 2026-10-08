/**
 * Central HTTP client for the Rooster hub. Every panel call goes through here
 * so contract fixes stay one-file. Set VITE_ROOSTER_MOCK=1 to route all
 * calls to the in-memory mock backend instead of real fetch.
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
  type SshGuardPluginConfig,
  type HardeningSectionConfig,
  type HardeningConfig,
  type ConfigWriteResp,
  type Layers,
  type ForwardRule,
  type NodeBansResp,
  type NodeBanHistoryResp,
  type NodeHoneypotHistoryResp,
  type AllowlistResp,
  type NodeStats,
  type NodeNetwork,
  type Site,
  type WafReportResp,
  type WafRulesResp,
  type HistoryResp,
  type HistoryFileResp,
  type WasmPlugin,
  type NodeWasmResp,
  type WriteRuleResp,
  type EventsResp,
  type EventsQuery,
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
import { handle as mockHandle } from './mock'

export const MOCK_MODE = String(import.meta.env.VITE_ROOSTER_MOCK ?? '0') === '1'

const HUB_KEY = 'rooster_hub'
const TOKEN_KEY = 'rooster_token'

export function getHub(): string {
  return localStorage.getItem(HUB_KEY) ?? ''
}
export function setHub(hub: string): void {
  localStorage.setItem(HUB_KEY, hub)
}
/**
 * token 存 localStorage:有效期由 hub 的 session-ttl(30d)按绝对时间戳控制,
 * 关浏览器与 Hub 重启(redb 落盘)都不必重新登录。代价是 token 明文留在
 * 浏览器磁盘上(XSS / 共用机器可读);过期后的 401 会把它抹掉。
 */
export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? ''
}
export function setToken(token: string): void {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

/** wss://<hub>/v0/ws?token=... — hub origin (https://) rewritten to ws(s)://. */
export function wsUrl(): string {
  const hub = getHub().replace(/\/+$/, '')
  const base =
    hub !== ''
      ? hub.replace(/^http/, 'ws')
      : location.protocol.replace(/^http/, 'ws') + '//' + location.host
  return `${base}/v0/ws?token=${encodeURIComponent(getToken())}`
}

let unauthorizedHandler: (() => void) | null = null
export function onUnauthorized(fn: () => void): void {
  unauthorizedHandler = fn
}

function extractError(fallback: string, payload: unknown): string {
  if (payload && typeof payload === 'object' && 'error' in payload) {
    const err = (payload as { error: unknown }).error
    if (typeof err === 'string' && err !== '') return err
  }
  return fallback || '请求失败'
}

async function request<T>(path: string, opts: ReqOpts = {}): Promise<T> {
  if (MOCK_MODE) return mockHandle<T>(path, opts)

  const hub = getHub().replace(/\/+$/, '')
  const base = hub !== '' ? `${hub}/v0` : '/v0'
  const headers: Record<string, string> = { Authorization: `Bearer ${getToken()}` }
  let body: BodyInit | undefined
  if (opts.raw) {
    for (const [k, v] of Object.entries(opts.raw.headers)) headers[k] = v
    body = opts.raw.body
  } else if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }

  let resp: Response
  try {
    resp = await fetch(base + path, { method: opts.method ?? 'GET', headers, body })
  } catch (e) {
    throw new ApiError(0, `无法连接 Hub（${hub || '同源代理'}）：${String(e)}`)
  }

  if (resp.status === 401 && path !== '/auth/login') {
    setToken('')
    unauthorizedHandler?.()
    throw new ApiError(401, '未登录或会话已过期')
  }
  const text = await resp.text()
  let payload: unknown = null
  if (text !== '') {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = text
    }
  }
  if (!resp.ok) throw new ApiError(resp.status, extractError(resp.statusText, payload), payload)
  return payload as T
}

// ---------------- auth ----------------
export async function login(hub: string, secretKey: string): Promise<LoginResp> {
  setHub(hub.trim().replace(/\/+$/, ''))
  return request<LoginResp>('/auth/login', { method: 'POST', body: { secret_key: secretKey } })
}

// ---------------- overview ----------------
export function getOverview(): Promise<OverviewResp> {
  return request<OverviewResp>('/overview')
}

// ---------------- nodes ----------------
export function getNodes(): Promise<NodesResp> {
  return request<NodesResp>('/nodes')
}
export function registerNodeToken(): Promise<RegisterTokenResp> {
  return request<RegisterTokenResp>('/nodes/register-tokens', { method: 'POST', body: {} })
}
export function putNodeLabels(id: string, labels: Record<string, string>): Promise<OkResp> {
  return request<OkResp>(`/nodes/${encodeURIComponent(id)}/labels`, {
    method: 'PUT',
    body: { labels },
  })
}
export function deleteNode(id: string): Promise<OkResp> {
  return request<OkResp>(`/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// ---------------- node management passthrough ----------------
export function getNodeConfig(id: string): Promise<NodeConfigResp> {
  return request<NodeConfigResp>(`/nodes/${encodeURIComponent(id)}/management/config`)
}
export function putNodeConfig(id: string, yaml: string): Promise<ConfigWriteResp> {
  return request<ConfigWriteResp>(`/nodes/${encodeURIComponent(id)}/management/config`, {
    method: 'PUT',
    body: { yaml },
  })
}
// 内置插件(当前仅 ssh-guard)表单直改:agent 侧 managed.plugins 子树写
export function getNodePlugin(id: string, name: string): Promise<SshGuardPluginConfig> {
  return request<SshGuardPluginConfig>(
    `/nodes/${encodeURIComponent(id)}/management/plugins/${encodeURIComponent(name)}`,
  )
}
export function putNodePlugin(
  id: string,
  name: string,
  cfg: SshGuardPluginConfig,
): Promise<ConfigWriteResp> {
  return request<ConfigWriteResp>(
    `/nodes/${encodeURIComponent(id)}/management/plugins/${encodeURIComponent(name)}`,
    { method: 'PUT', body: cfg },
  )
}
/** 加固配置(managed.hardening):整段 PUT,所有子项默认关闭 */
export function getNodeHardening(id: string): Promise<HardeningConfig> {
  return request<HardeningConfig>(`/nodes/${encodeURIComponent(id)}/management/hardening`)
}
export function putNodeHardening(id: string, cfg: HardeningConfig): Promise<ConfigWriteResp> {
  return request<ConfigWriteResp>(`/nodes/${encodeURIComponent(id)}/management/hardening`, {
    method: 'PUT',
    body: cfg,
  })
}
export function getLayers(id: string): Promise<Layers> {
  return request<Layers>(`/nodes/${encodeURIComponent(id)}/management/layers`)
}
export function getForwards(id: string): Promise<ForwardRule[]> {
  return request<ForwardRule[]>(`/nodes/${encodeURIComponent(id)}/management/forwards`)
}
/** PUT /forwards/{id} — body is one rule, id taken from the path. No bulk route exists. */
export function putForward(id: string, fwdId: string, rule: ForwardRule): Promise<WriteRuleResp> {
  return request<WriteRuleResp>(
    `/nodes/${encodeURIComponent(id)}/management/forwards/${encodeURIComponent(fwdId)}`,
    { method: 'PUT', body: rule },
  )
}
export function deleteForward(id: string, fwdId: string): Promise<null> {
  return request<null>(
    `/nodes/${encodeURIComponent(id)}/management/forwards/${encodeURIComponent(fwdId)}`,
    { method: 'DELETE' },
  )
}
export function getNodeBans(id: string): Promise<NodeBansResp> {
  return request<NodeBansResp>(`/nodes/${encodeURIComponent(id)}/management/bans`)
}
export function getNodeBanHistory(id: string): Promise<NodeBanHistoryResp> {
  return request<NodeBanHistoryResp>(`/nodes/${encodeURIComponent(id)}/ban-history`)
}
export function getNodeHoneypotHistory(id: string): Promise<NodeHoneypotHistoryResp> {
  return request<NodeHoneypotHistoryResp>(`/nodes/${encodeURIComponent(id)}/honeypot-history`)
}
export function addNodeBan(
  id: string,
  ban: { ip: string; ttl_secs: number; reason: string },
): Promise<OkResp> {
  return request<OkResp>(`/nodes/${encodeURIComponent(id)}/management/bans`, {
    method: 'POST',
    body: ban,
  })
}
export function deleteNodeBan(id: string, ip: string): Promise<OkResp> {
  return request<OkResp>(
    `/nodes/${encodeURIComponent(id)}/management/bans/${encodeURIComponent(ip)}`,
    { method: 'DELETE' },
  )
}
export function getAllowlist(id: string): Promise<AllowlistResp> {
  return request<AllowlistResp>(`/nodes/${encodeURIComponent(id)}/management/allowlist`)
}
/** Same confirm/auto-roll-back mechanism as PUT /config. */
export function putAllowlist(id: string, cidrs: string[]): Promise<ConfigWriteResp> {
  return request<ConfigWriteResp>(`/nodes/${encodeURIComponent(id)}/management/allowlist`, {
    method: 'PUT',
    body: { cidrs },
  })
}
export function getNodeStats(id: string): Promise<NodeStats> {
  return request<NodeStats>(`/nodes/${encodeURIComponent(id)}/management/stats`)
}
export function getNodeNetwork(id: string): Promise<NodeNetwork> {
  return request<NodeNetwork>(`/nodes/${encodeURIComponent(id)}/management/network`)
}
export function getSites(id: string): Promise<Site[]> {
  return request<Site[]>(`/nodes/${encodeURIComponent(id)}/management/sites`)
}
/** PUT /sites/{id} — body is one site, id taken from the path. */
export function putSite(id: string, siteId: string, site: Site): Promise<WriteRuleResp> {
  return request<WriteRuleResp>(
    `/nodes/${encodeURIComponent(id)}/management/sites/${encodeURIComponent(siteId)}`,
    { method: 'PUT', body: site },
  )
}
export function deleteSite(id: string, siteId: string): Promise<null> {
  return request<null>(
    `/nodes/${encodeURIComponent(id)}/management/sites/${encodeURIComponent(siteId)}`,
    { method: 'DELETE' },
  )
}
export function getWafReport(id: string): Promise<WafReportResp> {
  return request<WafReportResp>(`/nodes/${encodeURIComponent(id)}/management/waf/report`)
}
export function getWafRules(id: string): Promise<WafRulesResp> {
  return request<WafRulesResp>(`/nodes/${encodeURIComponent(id)}/management/waf/rules`)
}
export function getHistory(id: string): Promise<HistoryResp> {
  return request<HistoryResp>(`/nodes/${encodeURIComponent(id)}/management/history`)
}
export function getHistoryFile(id: string, name: string): Promise<HistoryFileResp> {
  return request<HistoryFileResp>(
    `/nodes/${encodeURIComponent(id)}/management/history/${encodeURIComponent(name)}`,
  )
}
export function postApplyConfirm(id: string, token: string): Promise<null> {
  return request<null>(
    `/nodes/${encodeURIComponent(id)}/management/apply/confirm`,
    { method: 'POST', body: { token } },
  )
}
export function getNodeWasm(id: string): Promise<NodeWasmResp> {
  return request<NodeWasmResp>(`/nodes/${encodeURIComponent(id)}/management/wasm`)
}
export function putNodeWasm(id: string, pluginId: string, plugin: WasmPlugin): Promise<WriteRuleResp> {
  return request<WriteRuleResp>(
    `/nodes/${encodeURIComponent(id)}/management/wasm/${encodeURIComponent(pluginId)}`,
    { method: 'PUT', body: plugin },
  )
}
export function deleteNodeWasm(id: string, pluginId: string): Promise<null> {
  return request<null>(
    `/nodes/${encodeURIComponent(id)}/management/wasm/${encodeURIComponent(pluginId)}`,
    { method: 'DELETE' },
  )
}

// ---------------- templates & rollouts ----------------
export function getTemplates(): Promise<TemplatesResp> {
  return request<TemplatesResp>('/templates')
}
export function putTemplate(
  id: string,
  body: { name: string; selector: Record<string, string>; yaml: string },
): Promise<OkResp> {
  return request<OkResp>(`/templates/${encodeURIComponent(id)}`, { method: 'PUT', body })
}
export function deleteTemplate(id: string): Promise<OkResp> {
  return request<OkResp>(`/templates/${encodeURIComponent(id)}`, { method: 'DELETE' })
}
export function previewTemplate(
  id: string,
  selector?: Record<string, string>,
): Promise<TemplatePreviewResp> {
  return request<TemplatePreviewResp>(`/templates/${encodeURIComponent(id)}/preview`, {
    method: 'POST',
    body: selector ? { selector } : {},
  })
}
export function rolloutTemplate(
  id: string,
  body: { selector?: Record<string, string>; concurrency?: number; auto_confirm_delay_secs?: number },
): Promise<RolloutKickResp> {
  return request<RolloutKickResp>(`/templates/${encodeURIComponent(id)}/rollout`, {
    method: 'POST',
    body,
  })
}
export function getRollouts(): Promise<RolloutsResp> {
  return request<RolloutsResp>('/rollouts')
}
export function getRollout(runId: string): Promise<RolloutRun> {
  return request<RolloutRun>(`/rollouts/${encodeURIComponent(runId)}`)
}

// ---------------- global bans ----------------
export function getGlobalBans(): Promise<GlobalBansResp> {
  return request<GlobalBansResp>('/global-bans')
}
export function addGlobalBan(ban: { ip: string; ttl_secs: number; reason: string }): Promise<GlobalBan> {
  return request<GlobalBan>('/global-bans', { method: 'POST', body: ban })
}
export function deleteGlobalBan(ip: string): Promise<OkResp> {
  return request<OkResp>(`/global-bans/${encodeURIComponent(ip)}`, { method: 'DELETE' })
}
export function getBanPolicies(): Promise<BanPoliciesResp> {
  return request<BanPoliciesResp>('/global-ban-policies')
}
export function putBanPolicies(policies: BanPolicy[]): Promise<OkResp> {
  return request<OkResp>('/global-ban-policies', { method: 'PUT', body: { policies } })
}

// ---------------- events query ----------------
export function queryEvents(q: EventsQuery): Promise<EventsResp> {
  const p = new URLSearchParams()
  if (q.node) p.set('node', q.node)
  if (q.plugin) p.set('plugin', q.plugin)
  if (q.ip) p.set('ip', q.ip)
  if (q.rule_id) p.set('rule_id', q.rule_id)
  if (q.since !== undefined) p.set('since', String(Math.floor(q.since)))
  if (q.until !== undefined) p.set('until', String(Math.floor(q.until)))
  if (q.limit !== undefined) p.set('limit', String(q.limit))
  const qs = p.toString()
  return request<EventsResp>(`/events${qs ? '?' + qs : ''}`)
}
export function getNodeEvents(nodeId: string, limit = 100): Promise<EventsResp> {
  return queryEvents({ node: nodeId, limit })
}

// ---------------- upgrades ----------------
export function getUpgrades(): Promise<UpgradesResp> {
  return request<UpgradesResp>('/upgrades')
}
export function uploadUpgrade(file: File, version: string, signature: string): Promise<UpgradeEntry> {
  return request<UpgradeEntry>('/upgrades', {
    method: 'POST',
    raw: {
      body: file,
      headers: { 'x-rooster-version': version, 'x-rooster-signature': signature },
    },
  })
}
export function rolloutUpgrade(
  version: string,
  body: { selector: Record<string, string>; node_id?: string; batch_size: number; wait_secs: number },
): Promise<RolloutKickResp> {
  return request<RolloutKickResp>(`/upgrades/${encodeURIComponent(version)}/rollout`, {
    method: 'POST',
    body,
  })
}

// ---------------- audit ----------------
export function getAudit(limit: number, offset: number): Promise<AuditResp> {
  return request<AuditResp>(`/audit?limit=${limit}&offset=${offset}`)
}

// ---------------- wasm registry ----------------
export function getWasmRegistry(): Promise<WasmRegistryResp> {
  return request<WasmRegistryResp>('/wasm-plugins')
}
export function uploadWasmPlugin(file: File): Promise<WasmRegistryEntry> {
  return request<WasmRegistryEntry>('/wasm-plugins', {
    method: 'POST',
    raw: { body: file, headers: { 'x-rooster-name': file.name } },
  })
}
export function deleteWasmRegistry(name: string): Promise<OkResp> {
  return request<OkResp>(`/wasm-plugins/${encodeURIComponent(name)}`, { method: 'DELETE' })
}

// re-exports commonly needed alongside client calls
export type { NodeInfo, AuditEntry, WasmPlugin, Site, ForwardRule, BanPolicy, SshGuardPluginConfig, HardeningSectionConfig, HardeningConfig }

export interface NginxSite {
  id: string; domains: string[]; listen: string[]; file: string
  upstream: string | null; supported: boolean; reason: string | null
  mode: 'off' | 'detect' | 'block'
  status: 'discovered' | 'attached' | 'needs-recovery'
  fingerprint: string
}
export interface NginxSnapshot { running: boolean; sites: NginxSite[] }
export function getNginxSites(id: string): Promise<NginxSnapshot> {
  return request<NginxSnapshot>(`/nodes/${encodeURIComponent(id)}/management/nginx/sites`)
}
export function setNginxWaf(id: string, siteId: string, mode: 'off' | 'detect' | 'block', fingerprint: string): Promise<{ id: string; mode: string; status: string }> {
  return request(`/nodes/${encodeURIComponent(id)}/management/nginx/sites/${encodeURIComponent(siteId)}/waf`, { method: 'PUT', body: { mode, fingerprint } })
}
