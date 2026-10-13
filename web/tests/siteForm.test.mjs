// 站点表单 <-> 管理 API JSON 的往返：面板替代手写 YAML/JSON 后，
// 下发的键必须与 crates/rooster-config/src/schema.rs 的 Site 线名一致。
// 纯函数用 vite ssrLoadModule 载入 TS 源码即可断言，不需要浏览器。
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'vite'

let server
let mod

before(async () => {
  server = await createServer({
    mode: 'production',
    server: { middlewareMode: true, hmr: false },
    optimizeDeps: { noDiscovery: true, include: [] },
    logLevel: 'error',
  })
  mod = await server.ssrLoadModule('/src/utils/siteForm.ts')
})

after(async () => {
  await server.close()
})

const RICH = {
  id: 'portal',
  'server-names': ['portal.example.com', 'www.example.com'],
  upstream: '10.0.0.10:8080',
  tls: { mode: 'terminate', acme: true, 'skip-verify': true },
  waf: { mode: 'block', exclusions: [942100, 942130] },
  'rate-limit': [
    { key: 'ip', rate: '5/second', burst: 10 },
    { key: 'header:X-User', rate: '2/minute', 'on-exceed': 'ban', 'ban-after': '5m' },
  ],
  geo: { deny: ['RU', 'CN'] },
  'proxy-protocol': 'v2',
  'ja4-deny': ['t13d1516h1'],
  'redirect-https': true,
  'upstream-connect-timeout': '60s',
  'max-body-size': 262144,
}

test('规则 id 解析：混合分隔、去重、排序、剔除非数字', () => {
  assert.deepEqual(mod.parseRuleIds('942130, 942100 942100;949110 x'), [942100, 942130, 949110])
  assert.deepEqual(mod.invalidRuleIds('942100, foo'), ['foo'])
  assert.deepEqual(mod.normalizeRuleIds(['7', 3, 'x', -1, 3]), [3, 7])
  assert.deepEqual(mod.normalizeRuleIds(undefined), [])
})

test('站点全字段往返：表单编辑不吃掉任何已建模字段', () => {
  const back = mod.draftToSite(mod.siteToDraft(RICH), RICH)
  assert.deepEqual(back, RICH)
})

test('旧面板写过的字符串规则 id 会被归一成数字', () => {
  const site = mod.draftToSite(mod.siteToDraft({ ...RICH, waf: { mode: 'block', exclusions: ['942130', 942100] } }), null)
  assert.deepEqual(site.waf.exclusions, [942100, 942130])
})

test('空可选字段不下发，命中 Rust 侧 serde default', () => {
  const site = mod.draftToSite(mod.emptyDraft(), null)
  assert.deepEqual(site, {
    id: '',
    'server-names': [],
    upstream: '127.0.0.1:80',
    tls: { mode: 'passthrough' },
    waf: { mode: 'off' },
  })
  for (const k of ['geo', 'rate-limit', 'proxy-protocol', 'ja4-deny', 'redirect-https', 'upstream-connect-timeout', 'max-body-size']) {
    assert.ok(!(k in site), `${k} 不应下发`)
  }
})

test('切回 passthrough 后不再下发 acme/cert/key', () => {
  const d = mod.siteToDraft({ ...RICH, tls: { mode: 'terminate', acme: true, cert: '/a.pem', key: '/b.pem', 'skip-verify': true } })
  d.tlsMode = 'passthrough'
  const site = mod.draftToSite(d, RICH)
  assert.deepEqual(site.tls, { mode: 'passthrough', 'skip-verify': true })
})

test('校验拦住一定会被 Agent 拒绝的输入', () => {
  const d = mod.siteToDraft(RICH)
  assert.deepEqual(mod.validateDraft(d), [])
  d.id = ''
  d.names = ' , '
  d.upstream = ' '
  d.exclusions = '942100, libinjection'
  d.tlsMode = 'terminate'
  d.acme = false
  d.cert = '/tmp/a.pem'
  d.key = ''
  d.rateLimit = [{ key: 'ip', rate: '', burst: 'x', onExceed: 'reject', banAfter: '' }]
  const fields = mod.validateDraft(d).map((e) => e.field)
  for (const f of ['ID', 'DOMAINS', 'UPSTREAM', 'WAF EXCLUSIONS', 'TLS', 'RATE LIMIT']) {
    assert.ok(fields.includes(f), `应当报错 ${f}，实际 ${fields.join(',')}`)
  }
})

test('加白只并入 exclusions，其它字段原样保留', () => {
  const merged = mod.withExclusions(RICH, [942100, 10001])
  assert.deepEqual(merged.waf, { mode: 'block', exclusions: [10001, 942100, 942130] })
  assert.equal(merged.upstream, RICH.upstream)
  assert.deepEqual(merged['server-names'], RICH['server-names'])
  // 幂等：重复加白不产生重复条目
  assert.deepEqual(mod.withExclusions(merged, [10001]).waf.exclusions, [10001, 942100, 942130])
})
