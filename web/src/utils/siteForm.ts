/**
 * Site 表单 <-> 管理 API JSON 的双向转换。
 *
 * 字段集合以 `crates/rooster-config/src/schema.rs` 的 `Site`/`SiteTls`/
 * `SiteWafConfig`/`RateLimitRule`/`GeoRule` 为准(kebab-case 线名)。
 * Agent 的 `PUT /sites/{id}` 会先反序列化成 `Site` 再重新序列化落盘,
 * 未建模的键会被丢弃 —— 所以这里必须覆盖全部站点字段,不保留 JSON 兜底。
 */
import type { Site, WafMode } from '../api/types'

export type TlsMode = 'passthrough' | 'terminate'
export type ProxyProtocol = 'none' | 'v1' | 'v2'
export type OnExceed = 'reject' | 'ban'

export interface RateLimitDraft {
  key: string
  rate: string
  burst: string
  onExceed: OnExceed
  banAfter: string
}

/** 表单态:列表类字段用文本承载(逗号/空格/换行分隔),数字用文本避免中途吞字符。 */
export interface SiteDraft {
  id: string
  names: string
  upstream: string
  tlsMode: TlsMode
  acme: boolean
  cert: string
  key: string
  skipVerify: boolean
  wafMode: WafMode
  exclusions: string
  rateLimit: RateLimitDraft[]
  geoDeny: string
  geoAllow: string
  proxyProtocol: ProxyProtocol
  ja4Deny: string
  redirectHttps: boolean
  connectTimeout: string
  maxBodySize: string
}

export const WAF_MODE_OPTIONS: { label: string; value: WafMode }[] = [
  { label: '关闭（off）', value: 'off' },
  { label: '监控（detect，只记录不拦截）', value: 'detect' },
  { label: '阻断（block）', value: 'block' },
]

export const TLS_MODE_OPTIONS: { label: string; value: TlsMode }[] = [
  { label: 'TLS 透传（passthrough）', value: 'passthrough' },
  { label: '在本机终止（terminate）', value: 'terminate' },
]

export const PROXY_PROTOCOL_OPTIONS: { label: string; value: ProxyProtocol }[] = [
  { label: '不启用', value: 'none' },
  { label: 'PROXY protocol v1', value: 'v1' },
  { label: 'PROXY protocol v2', value: 'v2' },
]

export const ON_EXCEED_OPTIONS: { label: string; value: OnExceed }[] = [
  { label: '拒绝（reject）', value: 'reject' },
  { label: '封禁（ban）', value: 'ban' },
]

const LIST_SEP = /[\s,;]+/

export function splitList(text: string): string[] {
  const out: string[] = []
  for (const raw of text.split(LIST_SEP)) {
    const v = raw.trim()
    if (v !== '' && !out.includes(v)) out.push(v)
  }
  return out
}

/** 规则 id 列表:接受 `942100, 942130` 这类混合分隔写法。 */
export function parseRuleIds(text: string): number[] {
  const out: number[] = []
  for (const n of splitList(text)) {
    if (/^\d+$/.test(n) && !out.includes(Number(n))) out.push(Number(n))
  }
  return out.sort((a, b) => a - b)
}

/** 非法 token(非纯数字),用于保存前的报错。 */
export function invalidRuleIds(text: string): string[] {
  return splitList(text).filter((n) => !/^\d+$/.test(n))
}

/** 旧 Agent / TS 宽松类型可能把 exclusions 写成字符串数组,统一成 number[]。 */
export function normalizeRuleIds(value: unknown): number[] {
  if (!Array.isArray(value)) return []
  const out: number[] = []
  for (const v of value) {
    const n = Number(v)
    if (Number.isInteger(n) && n > 0 && !out.includes(n)) out.push(n)
  }
  return out.sort((a, b) => a - b)
}

function str(v: unknown): string {
  if (typeof v === 'string') return v
  if (v === undefined || v === null) return ''
  return String(v)
}

/** 有值则写键,无值则删键:可选字段不下发时才能命中 Rust 侧 `#[serde(default)]`。 */
function setOrDelete(obj: Record<string, unknown>, key: string, value: unknown, present: boolean) {
  if (present) obj[key] = value
  else delete obj[key]
}

/** 线格式兼容:旧配置可能写布尔(true=v1),新配置用枚举。 */
function draftProxyProtocol(v: unknown): ProxyProtocol {
  if (v === 'v2') return 'v2'
  if (v === 'v1' || v === true) return 'v1'
  return 'none'
}

function bool(v: unknown, fallback = false): boolean {
  return typeof v === 'boolean' ? v : fallback
}

export function emptyDraft(): SiteDraft {
  return {
    id: '',
    names: '',
    upstream: '127.0.0.1:80',
    tlsMode: 'passthrough',
    acme: false,
    cert: '',
    key: '',
    skipVerify: false,
    wafMode: 'off',
    exclusions: '',
    rateLimit: [],
    geoDeny: '',
    geoAllow: '',
    proxyProtocol: 'none',
    ja4Deny: '',
    redirectHttps: false,
    connectTimeout: '',
    maxBodySize: '',
  }
}

export function siteToDraft(site: Site): SiteDraft {
  const tls = (site.tls ?? {}) as Record<string, unknown>
  const waf = (site.waf ?? {}) as Record<string, unknown>
  const geo = (site.geo ?? {}) as Record<string, unknown>
  const rl = Array.isArray(site['rate-limit']) ? (site['rate-limit'] as unknown[]) : []
  const pp = site['proxy-protocol']
  return {
    id: site.id ?? '',
    names: (site['server-names'] ?? []).join(', '),
    upstream: site.upstream ?? '',
    tlsMode: tls.mode === 'terminate' ? 'terminate' : 'passthrough',
    acme: bool(tls.acme),
    cert: str(tls.cert),
    key: str(tls.key),
    skipVerify: bool(tls['skip-verify']),
    wafMode: waf.mode === 'block' || waf.mode === 'detect' ? (waf.mode as WafMode) : 'off',
    exclusions: normalizeRuleIds(waf.exclusions).join(', '),
    rateLimit: rl.map(rateLimitToDraft),
    geoDeny: normalizeCountryList(geo.deny).join(', '),
    geoAllow: normalizeCountryList(geo.allow).join(', '),
    // 布尔形态是旧线格式;枚举取小写,其余按未启用
    proxyProtocol: draftProxyProtocol(pp),
    ja4Deny: (Array.isArray(site['ja4-deny']) ? site['ja4-deny'] : []).map(str).filter(Boolean).join(', '),
    redirectHttps: bool(site['redirect-https'], false),
    connectTimeout: str(site['upstream-connect-timeout']),
    maxBodySize: site['max-body-size'] === undefined ? '' : str(site['max-body-size']),
  }
}

function normalizeCountryList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.map(str).filter((v) => v !== '')
}

function rateLimitToDraft(raw: unknown): RateLimitDraft {
  const r = (raw ?? {}) as Record<string, unknown>
  return {
    key: str(r.key) || 'ip',
    rate: str(r.rate),
    burst: r.burst === undefined || r.burst === 0 ? '' : str(r.burst),
    onExceed: r['on-exceed'] === 'ban' ? 'ban' : 'reject',
    banAfter: str(r['ban-after']),
  }
}

export interface DraftError {
  field: string
  message: string
}

/** 保存前的最小校验:只拦「一定会被 Agent 拒绝」的输入。 */
export function validateDraft(draft: SiteDraft): DraftError[] {
  const errors: DraftError[] = []
  if (draft.id.trim() === '') errors.push({ field: 'ID', message: '站点 id 不能为空' })
  if (splitList(draft.names).length === 0)
    errors.push({ field: 'DOMAINS', message: '至少填一个域名(server_name)' })
  if (draft.upstream.trim() === '')
    errors.push({ field: 'UPSTREAM', message: '上游地址不能为空' })
  const badIds = invalidRuleIds(draft.exclusions)
  if (badIds.length > 0)
    errors.push({ field: 'WAF EXCLUSIONS', message: `规则 id 必须是数字：${badIds.join('、')}` })
  if (draft.tlsMode === 'terminate' && !draft.acme && (draft.cert.trim() === '') !== (draft.key.trim() === ''))
    errors.push({ field: 'TLS', message: '本地证书需要同时填写 cert 与 key' })
  for (const r of draft.rateLimit) {
    if (r.key.trim() === '' || r.rate.trim() === '')
      errors.push({ field: 'RATE LIMIT', message: '限速行的 key 与 rate 都不能为空（rate 形如 5/second）' })
    if (r.burst.trim() !== '' && !/^\d+$/.test(r.burst.trim()))
      errors.push({ field: 'RATE LIMIT', message: `burst 必须是整数：${r.burst}` })
  }
  if (draft.maxBodySize.trim() !== '' && !/^\d+$/.test(draft.maxBodySize.trim()))
    errors.push({ field: 'MAX BODY SIZE', message: '请求体上限必须是字节数' })
  return errors
}

/** 表单态 -> PUT /sites/{id} 的 body。空可选字段一律不下发,保持落盘 YAML 干净。 */
export function draftToSite(draft: SiteDraft, base: Site | null): Site {
  // base 只用来保留面板未建模的键(Agent 会丢未建模键,这里保留是为了
  // 面板先于 Rust 字段更新时不吃数据)。
  const site: Record<string, unknown> = base ? { ...base } : {}
  site.id = draft.id.trim()
  site['server-names'] = splitList(draft.names)
  site.upstream = draft.upstream.trim()

  const tls: Record<string, unknown> = { mode: draft.tlsMode }
  if (draft.tlsMode === 'terminate') {
    if (draft.acme) tls.acme = true
    if (draft.cert.trim() !== '') tls.cert = draft.cert.trim()
    if (draft.key.trim() !== '') tls.key = draft.key.trim()
  }
  if (draft.skipVerify) tls['skip-verify'] = true
  site.tls = tls

  const waf: Record<string, unknown> = { mode: draft.wafMode }
  const exclusions = parseRuleIds(draft.exclusions)
  if (exclusions.length > 0) waf.exclusions = exclusions
  site.waf = waf
  const rateLimit = draft.rateLimit
    .filter((r) => r.key.trim() !== '' || r.rate.trim() !== '')
    .map((r) => {
      const row: Record<string, unknown> = { key: r.key.trim(), rate: r.rate.trim() }
      if (r.burst.trim() !== '' && Number(r.burst) !== 0) row.burst = Number(r.burst)
      if (r.onExceed === 'ban') row['on-exceed'] = 'ban'
      if (r.banAfter.trim() !== '') row['ban-after'] = r.banAfter.trim()
      return row
    })
  setOrDelete(site, 'rate-limit', rateLimit, rateLimit.length > 0)


  const deny = splitList(draft.geoDeny)
  const allow = splitList(draft.geoAllow)
  if (deny.length > 0 || allow.length > 0) {
    const geo: Record<string, unknown> = {}
    if (deny.length > 0) geo.deny = deny
    if (allow.length > 0) geo.allow = allow
    site.geo = geo
  } else delete site.geo

  setOrDelete(site, 'proxy-protocol', draft.proxyProtocol, draft.proxyProtocol !== 'none')

  const ja4 = splitList(draft.ja4Deny)
  setOrDelete(site, 'ja4-deny', ja4, ja4.length > 0)
  setOrDelete(site, 'redirect-https', true, draft.redirectHttps)
  const timeout = draft.connectTimeout.trim()
  setOrDelete(site, 'upstream-connect-timeout', timeout, timeout !== '')
  const bodySize = draft.maxBodySize.trim()
  setOrDelete(site, 'max-body-size', Number(bodySize), bodySize !== '')

  // SAFETY: keys are built from the kebab-case wire names of `Site` in
  // crates/rooster-config/src/schema.rs; TS can't verify string keys.
  return site as unknown as Site
}

/** 把命中的规则 id 并入站点排除表(误报加白),不改动其它字段。 */
export function withExclusions(site: Site, ids: number[]): Site {
  const waf = { ...((site.waf ?? {}) as Record<string, unknown>) }
  const merged = normalizeRuleIds([...normalizeRuleIds(waf.exclusions), ...ids])
  waf.exclusions = merged
  return { ...site, waf }
}
