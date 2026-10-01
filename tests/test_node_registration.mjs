import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { test } from 'node:test'

const require = createRequire(new URL('../web/package.json', import.meta.url))
const ts = require('typescript')
const vue = require('vue')
const source = readFileSync(new URL('../web/src/pages/Nodes.vue', import.meta.url), 'utf8')
  .match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1]
const code = ts.transpileModule(`${source}\nexport { openRegister, regShow, reg, regRemain, nodes };`, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText

function harness() {
  let now = 1_700_000_000_000
  let snapshot = [{ id: 'existing', online: true }]
  let fetchNodes = async () => ({ nodes: snapshot })
  let fetchToken = async () => ({ token: 'one-time', expires_at: (now + 60_000) / 1000 })
  let unmount
  let nextTimer = 0
  let calls = 0
  const timers = new Map()
  const notices = []
  const modules = {
    vue: { ...vue, onMounted() {}, onUnmounted(fn) { unmount = fn } },
    'vue-router': { useRouter: () => ({}) },
    '../ui': {
      useMessage: () => Object.fromEntries(['success', 'warning', 'error'].map((kind) =>
        [kind, (text) => notices.push([kind, text])])),
      useDialog: () => ({}),
    },
    '../api/client': {
      getNodes: () => { calls += 1; return fetchNodes() },
      registerNodeToken: () => fetchToken(),
    },
    '../components/KvEditor.vue': {},
    '../utils/format': {
      toDate: (value) => new Date(value * 1000),
      errMsg: (error) => String(error),
    },
  }
  const exports = {}
  new Function('require', 'exports', 'window', 'Date', code)(
    (name) => { assert.ok(name in modules, `Unexpected import: ${name}`); return modules[name] },
    exports,
    {
      setInterval(fn, delay) { const id = ++nextTimer; timers.set(id, { fn, delay }); return id },
      clearInterval(id) { timers.delete(id) },
    },
    { now: () => now },
  )
  return {
    ...exports, timers, notices,
    get calls() { return calls },
    advance(ms) { now += ms },
    snapshot(value) { snapshot = value },
    fetchNodes(fn) { fetchNodes = fn },
    fetchToken(fn) { fetchToken = fn },
    unmount() { unmount() },
    async tick(delay) {
      for (const timer of [...timers.values()]) if (timer.delay === delay) await timer.fn()
    },
  }
}

function deferred() {
  let resolve
  const promise = new Promise((done) => { resolve = done })
  return { promise, resolve }
}

test('expiry closes the modal at the absolute deadline, not a second early', async () => {
  const h = harness()
  await h.openRegister()
  h.advance(59_500)
  await h.tick(1000)
  assert.equal(h.regRemain.value, 1)
  assert.equal(h.regShow.value, true)
  h.advance(500)
  await h.tick(1000)
  assert.equal(h.regShow.value, false)
  assert.equal(h.reg.value, null)
  assert.equal(h.timers.size, 0)
  assert.equal(h.notices[0][0], 'warning')
})

test('only a new online node completes registration and refreshes the list', async () => {
  const h = harness()
  await h.openRegister()
  await h.tick(2000)
  assert.equal(h.regShow.value, true)
  h.snapshot([{ id: 'existing', online: true }, { id: 'new', online: false }])
  await h.tick(2000)
  assert.equal(h.regShow.value, true)
  h.snapshot([{ id: 'existing', online: true }, { id: 'new', online: true }])
  await h.tick(2000)
  assert.equal(h.regShow.value, false)
  assert.equal(h.nodes.value.find((node) => node.id === 'new').online, true)
  assert.equal(h.timers.size, 0)
  assert.deepEqual(h.notices, [['success', '节点 new 已就绪']])
})

test('manual close and unmount stop all timers and clear the token', async () => {
  for (const close of [(h) => { h.regShow.value = false }, (h) => h.unmount()]) {
    const h = harness()
    await h.openRegister()
    close(h)
    assert.equal(h.timers.size, 0)
    assert.equal(h.reg.value, null)
  }
})

test('closing while token generation is pending ignores its late response', async () => {
  const h = harness()
  const pending = deferred()
  h.fetchToken(() => pending.promise)
  const opening = h.openRegister()
  await Promise.resolve()
  h.regShow.value = false
  pending.resolve({ token: 'late', expires_at: 1_700_000_060 })
  await opening
  assert.equal(h.reg.value, null)
  assert.equal(h.timers.size, 0)
})

test('polling is serialized and ignores responses after close or reopen', async () => {
  const h = harness()
  await h.openRegister()
  const pending = deferred()
  h.fetchNodes(() => pending.promise)
  const polling = h.tick(2000)
  const calls = h.calls
  await h.tick(2000)
  assert.equal(h.calls, calls)
  h.regShow.value = false
  h.fetchNodes(async () => ({ nodes: [{ id: 'baseline', online: true }] }))
  await h.openRegister()
  pending.resolve({ nodes: [{ id: 'late', online: true }] })
  await polling
  assert.equal(h.regShow.value, true)
  assert.equal(h.nodes.value[0].id, 'baseline')
  assert.equal(h.notices.length, 0)
})

test('transient polling failures retry without notification spam', async () => {
  const h = harness()
  await h.openRegister()
  h.fetchNodes(async () => { throw new Error('offline') })
  await h.tick(2000)
  assert.equal(h.regShow.value, true)
  assert.equal(h.notices.length, 0)
  h.fetchNodes(async () => ({ nodes: [{ id: 'ready', online: true }] }))
  await h.tick(2000)
  assert.equal(h.regShow.value, false)
})

test('an already expired token never arms timers', async () => {
  const h = harness()
  h.fetchToken(async () => ({ token: 'expired', expires_at: 1_699_999_999 }))
  await h.openRegister()
  assert.equal(h.regShow.value, false)
  assert.equal(h.timers.size, 0)
})
