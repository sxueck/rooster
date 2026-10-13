// 分页条行为：封禁详情与历史事件的“一长串到底”由 RTable :page-size 与 RPager 收敛。
// SSR 渲染即可断言，不需要浏览器。
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'vite'
import { createSSRApp, h } from 'vue'
import { renderToString } from '@vue/server-renderer'

let server
let RTable
let RPager

before(async () => {
  server = await createServer({
    mode: 'production',
    server: { middlewareMode: true, hmr: false },
    optimizeDeps: { noDiscovery: true, include: [] },
    logLevel: 'error',
  })
  RTable = (await server.ssrLoadModule('/src/ui/RTable.vue')).default
  RPager = (await server.ssrLoadModule('/src/ui/RPager.vue')).default
})

after(async () => {
  await server.close()
})

const cols = [{ title: 'IP', key: 'ip' }]
const rowKey = (r) => r.ip
const rowsOf = (n) => Array.from({ length: n }, (_, i) => ({ ip: `10.0.0.${i}` }))

function render(node) {
  return renderToString(createSSRApp({ render: () => node }))
}

test('RTable 超过 pageSize 才出现分页条，且只渲染当前页的行', async () => {
  const html = await render(
    h(RTable, { columns: cols, rows: rowsOf(25), rowKey, pageSize: 10 }),
  )
  assert.match(html, /1–10 \/ 25/)
  assert.equal((html.match(/<td/g) ?? []).length, 10)
})

test('行数不足一页时不渲染分页条', async () => {
  const html = await render(h(RTable, { columns: cols, rows: rowsOf(5), rowKey, pageSize: 10 }))
  assert.doesNotMatch(html, /rp-pager/)
  assert.equal((html.match(/<td/g) ?? []).length, 5)
})

test('RPager 区间文案（EventsTab 的非表格列表复用同一组件）', async () => {
  const html = await render(h(RPager, { page: 2, pageCount: 4, pageSize: 30, total: 100 }))
  assert.match(html, /31–60 \/ 100/)
  // 首页时左箭头禁用
  const first = await render(h(RPager, { page: 1, pageCount: 4, pageSize: 30, total: 100 }))
  assert.match(first, /disabled/)
})
