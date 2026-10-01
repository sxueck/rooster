import { ApiError } from '../api/types'
import type { RoosterEvent } from '../api/types'

export function errMsg(e: unknown): string {
  if (e instanceof ApiError) {
    const p = e.payload
    if (p && typeof p === 'object' && 'last_seen' in p) {
      return `${e.message}（最后心跳：${String((p as { last_seen: unknown }).last_seen)}）`
    }
    return e.message
  }
  if (e instanceof Error) return e.message
  return String(e)
}

/**
 * Normalise a wire timestamp to a Date. Hub/agent emit epoch SECONDS (number or
 * all-digit string); anything below 1e12 is seconds, above is already ms. ISO
 * strings pass through `new Date`. Returns null for unparseable input.
 */
export function toDate(ts: number | string): Date | null {
  const n = typeof ts === 'number' ? ts : /^\d+$/.test(ts) ? Number(ts) : NaN
  const ms = Number.isFinite(n) ? (n < 1e12 ? n * 1000 : n) : NaN
  const d = Number.isFinite(ms) ? new Date(ms) : new Date(ts)
  return Number.isNaN(d.getTime()) ? null : d
}

export function fmtTime(ts: number | string): string {
  const d = toDate(ts)
  if (!d) return String(ts)
  return d.toLocaleString('zh-CN', { hour12: false })
}

export function fmtRelative(ts: number | string): string {
  const d = toDate(ts)
  if (!d) return String(ts)
  const secs = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  if (secs < 60) return '刚刚'
  if (secs < 3600) return `${Math.floor(secs / 60)} 分钟前`
  if (secs < 86400) return `${Math.floor(secs / 3600)} 小时前`
  return `${Math.floor(secs / 86400)} 天前`
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

export function fmtDuration(secs: number): string {
  if (secs < 60) return `${secs}s`
  const m = Math.floor(secs / 60)
  const s = secs % 60
  if (m < 60) return `${m}m${s}s`
  return `${Math.floor(m / 60)}h${m % 60}m`
}

export function eventKindLabel(kind: string): string {
  switch (kind) {
    case 'ban':
      return '封禁'
    case 'block':
      return '拦截'
    case 'config_changed':
      return '配置变更'
    case 'config_invalid':
      return '配置错误'
    case 'config_rolled_back':
      return '配置回滚'
    case 'auth_temp_ban':
      return '认证封禁'
    default:
      return kind
  }
}

export function eventTagType(kind: string): 'success' | 'warning' | 'error' | 'info' | 'default' {
  switch (kind) {
    case 'block':
    case 'config_invalid':
      return 'error'
    case 'ban':
    case 'config_rolled_back':
    case 'auth_temp_ban':
      return 'warning'
    case 'config_changed':
      return 'info'
    default:
      return 'default'
  }
}

export function eventSummary(ev: RoosterEvent): string {
  switch (ev.kind) {
    case 'ban':
      return `封禁 ${ev.ip}（${ev.plugin}，${fmtDuration(ev.ttl_secs)}）：${ev.reason}`
    case 'block': {
      // 新版 block 事件带 path / hits / score；旧数据缺失时保持原样，不显示 undefined
      const hitN = ev.hits?.length ?? 0
      const rule = hitN > 1 ? `${ev.rule_id} 等 ${hitN} 条` : String(ev.rule_id)
      let s = `拦截 ${ev.ip}，命中规则 ${rule} @ ${ev.site}`
      if (ev.path) s += `，路径 ${ev.path}`
      if (ev.score !== null && ev.score !== undefined) s += `，异常评分 ${ev.score}`
      return s
    }
    case 'config_changed':
      return `配置已变更，hash=${ev.hash}`
    case 'config_invalid':
      return `配置无效：${ev.error}（第 ${ev.line} 行）`
    case 'config_rolled_back':
      return `配置已回滚：${ev.reason}`
    case 'auth_temp_ban':
      return `认证失败临时封禁 ${ev.peer}`
  }
  const k = (ev as { kind?: string }).kind
  return k ? JSON.stringify(ev) : String(ev)
}

