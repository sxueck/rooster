import assert from 'node:assert/strict'
import { after, before, beforeEach, test } from 'node:test'
import { createServer } from 'vite'
import { createPinia } from 'pinia'

let server
let api
let useAuthStore
let calls
const originalFetch = globalThis.fetch
const originalStorage = globalThis.localStorage
const values = new Map()

before(async () => {
  globalThis.localStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  }
  server = await createServer({
    mode: 'production',
    server: { middlewareMode: true, hmr: false },
    optimizeDeps: { noDiscovery: true, include: [] },
    logLevel: 'error',
  })
  api = await server.ssrLoadModule('/src/api/client.ts')
  assert.equal(api.MOCK_MODE, false)
  useAuthStore = (await server.ssrLoadModule('/src/stores/auth.ts')).useAuthStore
})

beforeEach(() => {
  values.clear()
  calls = []
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    return Response.json({ token: 'session-token', expires_at: Math.floor(Date.now() / 1000) + 3600 })
  }
})

after(async () => {
  globalThis.fetch = originalFetch
  if (originalStorage === undefined) delete globalThis.localStorage
  else globalThis.localStorage = originalStorage
  await server?.close()
})

test('login accepts same-origin and normalizes HTTP(S) origins', async () => {
  for (const [hub, origin] of [
    ['', ''],
    ['  https://hub.example.com/  ', 'https://hub.example.com'],
    ['http://localhost:9443', 'http://localhost:9443'],
    ['https://[::1]:9443/', 'https://[::1]:9443'],
  ]) {
    const result = await api.login(hub, 'test-secret')
    assert.equal(result.token, 'session-token')
    assert.equal(api.getHub(), origin)
    assert.equal(calls.at(-1).url, `${origin}/v0/auth/login`)
    assert.deepEqual(JSON.parse(calls.at(-1).options.body), { secret_key: 'test-secret' })
  }
})

test('invalid Hub addresses fail before fetch or persisted Hub changes', async () => {
  api.setHub('https://previous.example.com')
  for (const hub of [
    'https://hub.example.com/login',
    'https://hub.example.com/v0',
    'https://hub.example.com/login/..',
    'https://hub.example.com\\\\',
    'https://@hub.example.com',
    'https://hub.example.com/?x=1',
    'https://hub.example.com/?',
    'https://hub.example.com/#login',
    'https://hub.example.com/#',
    'https://user:password@hub.example.com',
    'ftp://hub.example.com',
    'hub.example.com',
    'https:hub.example.com',
    'https://hu\tb.example.com',
  ]) {
    await assert.rejects(api.login(hub, 'wrong-secret'), /Hub 地址/)
    assert.equal(api.getHub(), 'https://previous.example.com')
  }
  assert.equal(calls.length, 0)
})

test('2xx HTML, empty and malformed login responses cannot count as success', async () => {
  const now = Math.floor(Date.now() / 1000)
  const responses = [
    () => new Response('<!doctype html><html></html>', { headers: { 'content-type': 'text/html' } }),
    () => new Response(null, { status: 204 }),
    ...[
      null, [], {}, { token: 'session-token' },
      { token: '', expires_at: now + 3600 },
      { token: '   ', expires_at: now + 3600 },
      { token: 123, expires_at: now + 3600 },
      { token: 'session-token', expires_at: String(now + 3600) },
      { token: 'session-token', expires_at: now },
      { token: 'session-token', expires_at: now - 1 },
      { token: 'session-token', expires_at: now + 0.5 },
      { token: 'session-token', expires_at: 1e30 },
    ].map((payload) => () => Response.json(payload)),
  ]
  api.setToken('existing-session')
  for (const response of responses) {
    globalThis.fetch = async () => response()
    await assert.rejects(api.login('', 'wrong-secret'), /Hub 登录响应无效/)
    assert.equal(api.getToken(), 'existing-session')
  }
})

test('auth store persists only validated sessions', async () => {
  const auth = useAuthStore(createPinia())
  globalThis.fetch = async () => new Response('<!doctype html><html></html>')
  await assert.rejects(auth.login('', 'wrong-secret'), /Hub 登录响应无效/)
  assert.equal(auth.token, '')
  assert.equal(api.getToken(), '')

  const expires_at = Math.floor(Date.now() / 1000) + 3600
  globalThis.fetch = async () => Response.json({ token: 'validated-session', expires_at })
  await auth.login('https://hub.example.com/', 'test-secret')
  assert.equal(auth.token, 'validated-session')
  assert.equal(api.getToken(), 'validated-session')
  assert.equal(auth.hub, 'https://hub.example.com')
})

test('invalid credentials still reject even with an existing session', async () => {
  api.setToken('existing-session')
  globalThis.fetch = async () => Response.json({ error: 'invalid credentials' }, { status: 401 })
  await assert.rejects(api.login('', 'wrong-secret'), (error) => {
    assert.equal(error.status, 401)
    assert.equal(error.message, 'invalid credentials')
    return true
  })
  assert.equal(api.getToken(), 'existing-session')
})
