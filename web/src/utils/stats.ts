import type { SiteHttpStat } from '../api/types'

/**
 * 顶部指标条的 HTTP 合计。agent 的 `GET /stats` 里 `http` 是**按站点的数组**
 * （见 crates/rooster-agent/src/httpguard.rs 的 `stats()`），旧面板把它当成
 * `{ blocked: number }` 这样的 map 读，结果恒为 0 —— 口径只在这里算一次。
 */
export function siteTotals(http: SiteHttpStat[] | null | undefined): {
  requests: number
  blocked: number
} {
  let requests = 0
  let blocked = 0
  for (const s of http ?? []) {
    requests += s.requests
    blocked += s.blocked
  }
  return { requests, blocked }
}
