// 面板统计口径回归：agent 的 GET /stats 里 forwards / http 是数组（不是 id→数字
// 的 map）。旧面板按 map 读，转发流量与 HTTP 统计永远是 0/空——这里把两侧都钉住。
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'vite'

let server
let siteTotals
let mockHandle

before(async () => {
  server = await createServer({
    mode: 'production',
    server: { middlewareMode: true, hmr: false },
    optimizeDeps: { noDiscovery: true, include: [] },
    logLevel: 'error',
  })
  ;({ siteTotals } = await server.ssrLoadModule('/src/utils/stats.ts'))
  mockHandle = (await server.ssrLoadModule('/src/api/mock.ts')).handle
})

after(async () => {
  await server.close()
})

// 字段名逐字对照 crates/rooster-agent/src/forward.rs 的 stats_of() 与
// httpguard.rs 的 stats()；改名即视为口径变化，两处都要跟着改。
const AGENT_STATS = {
  forwards: [
    {
      id: 'ssh',
      proto: 'tcp',
      listening: false,
      conns_total: 0,
      conns_active: 0,
      udp_sessions: 0,
      bytes_in: 0,
      bytes_out: 0,
    },
  ],
  http: [
    {
      id: 'nginx-portal-l1',
      requests: 1200,
      blocked: 37,
      conns_passthrough: 4,
      bytes_in: 90,
      bytes_out: 640,
      listening_http: true,
      listening_https: false,
    },
    {
      id: 'portal',
      requests: 800,
      blocked: 0,
      conns_passthrough: 0,
      bytes_in: 10,
      bytes_out: 20,
      listening_http: true,
      listening_https: true,
    },
  ],
  bans: 3,
}

test('siteTotals 按站点数组求和', () => {
  assert.deepEqual(siteTotals(AGENT_STATS.http), { requests: 2000, blocked: 37 })
})

test('siteTotals 容忍空数组与缺失字段', () => {
  assert.deepEqual(siteTotals([]), { requests: 0, blocked: 0 })
  assert.deepEqual(siteTotals(null), { requests: 0, blocked: 0 })
  assert.deepEqual(siteTotals(undefined), { requests: 0, blocked: 0 })
})

test('mock 的 /stats 与 agent 同为数组形状', async () => {
  const stats = await mockHandle('/nodes/edge-bj-01/management/stats')
  assert.ok(Array.isArray(stats.forwards), 'forwards 必须是数组')
  assert.ok(Array.isArray(stats.http), 'http 必须是数组')
  assert.ok(stats.forwards.length > 0 && 'listening' in stats.forwards[0])
  assert.ok(stats.http.length > 0 && 'requests' in stats.http[0])
  // bind 失败的规则必须可见（转发流量为 0 的唯一解释入口）
  assert.ok(stats.forwards.some((f) => f.listening === false))
})
