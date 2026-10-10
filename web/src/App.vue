<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth'
import { useEventsStore } from './stores/events'
import { MOCK_MODE, getHub } from './api/client'
import RollbackModal from './components/RollbackModal.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const events = useEventsStore()

const isPlain = computed(() => route.meta.plain === true)

interface NavItem {
  path: string
  zh: string
  en: string
}
interface NavGroup {
  label: string
  items: NavItem[]
}
const NAV: NavGroup[] = [
  {
    label: 'CLUSTER',
    items: [
      { path: '/', zh: '总览', en: 'OVERVIEW' },
      { path: '/nodes', zh: '节点管理', en: 'NODES' },
    ],
  },
  {
    label: 'CONFIG',
    items: [{ path: '/templates', zh: '配置模板', en: 'TEMPLATES' }],
  },
  {
    label: 'SECURITY',
    items: [
      { path: '/bans', zh: '全局黑名单', en: 'GLOBAL BANS' },
      { path: '/events', zh: '事件查询', en: 'EVENTS' },
      { path: '/waf', zh: 'WAF 规则报告', en: 'WAF REPORT' },
    ],
  },
  {
    label: 'DELIVERY',
    items: [
      { path: '/wasm', zh: 'WASM 插件', en: 'PLUGINS' },
      { path: '/upgrade', zh: '版本升级', en: 'UPGRADE' },
    ],
  },
  {
    label: 'AUDIT',
    items: [{ path: '/audit', zh: '审计日志', en: 'AUDIT LOG' }],
  },
]

function isActive(item: NavItem): boolean {
  if (item.path === '/') return route.path === '/'
  return route.path === item.path || route.path.startsWith(item.path + '/')
}

const crumb = computed(() => {
  for (const g of NAV) {
    for (const it of g.items) {
      if (isActive(it)) return `${g.label} · ${it.en}`
    }
  }
  return String(route.meta.title ?? '')
})

// ops clock in the status strip
const now = ref(new Date())
const clock = window.setInterval(() => (now.value = new Date()), 1000)
onUnmounted(() => window.clearInterval(clock))
const clockText = computed(() => now.value.toTimeString().slice(0, 8))

const hubOrigin = computed(() => getHub() || location.host)

watch(
  () => auth.token,
  (t) => {
    if (t) events.connect()
    else events.disconnect()
  },
  { immediate: true },
)

async function logout() {
  await auth.logout()
  void router.push('/login')
}
</script>

<template>
  <router-view v-if="isPlain" />
  <div v-else class="shell">
    <aside class="rail">
      <div class="brand">
        <span class="brand-mark">▚</span>
        <div>
          <div class="brand-name">ROOSTER</div>
          <div class="micro">OPS CONSOLE</div>
        </div>
      </div>
      <nav class="nav">
        <template v-for="g in NAV" :key="g.label">
          <div class="nav-group micro">{{ g.label }}</div>
          <RouterLink
            v-for="it in g.items"
            :key="it.path"
            :to="it.path"
            class="nav-item"
            :class="{ 'nav-on': isActive(it) }"
          >
            <span class="nav-zh">{{ it.zh }}</span>
            <span class="nav-en">{{ it.en }}</span>
          </RouterLink>
        </template>
      </nav>
      <div class="rail-foot">
        <span class="ws" :class="{ 'ws-on': events.connected }">
          <span class="ws-dot" />{{ events.connected ? 'LIVE' : 'OFFLINE' }}
        </span>
        <span v-if="MOCK_MODE" class="mock-badge micro">MOCK</span>
        <button class="logout" @click="logout">退出</button>
      </div>
    </aside>

    <div class="col">
      <header class="strip">
        <span class="micro">{{ crumb }}</span>
        <span class="strip-sep">/</span>
        <span class="strip-hub num">{{ hubOrigin }}</span>
        <span class="spacer" />
        <span class="strip-clock num">{{ clockText }}</span>
      </header>
      <main class="content">
        <router-view />
      </main>
    </div>
    <RollbackModal />
  </div>
</template>

<style scoped>
.shell {
  display: flex;
  height: 100vh;
  overflow: hidden;
}
.rail {
  width: 208px;
  flex: none;
  display: flex;
  flex-direction: column;
  background: var(--panel);
  border-right: 1px solid var(--line-strong);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px 12px;
  border-bottom: 1px solid var(--line);
}
.brand-mark {
  font-size: 20px;
  color: var(--danger);
  line-height: 1;
}
.brand-name {
  font-family: var(--mono);
  font-weight: 700;
  font-size: 15px;
  letter-spacing: 0.06em;
  line-height: 1.2;
}
.nav {
  flex: 1;
  overflow-y: auto;
  padding: 10px 0 14px;
}
.nav-group {
  padding: 12px 16px 4px;
}
.nav-item {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  padding: 6px 16px 6px 14px;
  border-left: 2px solid transparent;
  color: var(--sub);
  text-decoration: none;
}
.nav-item:hover {
  background: var(--tint);
  color: var(--ink);
  text-decoration: none;
}
.nav-on {
  border-left-color: var(--ink);
  background: var(--tint);
  color: var(--ink);
}
.nav-zh {
  font-size: 13px;
  font-weight: 500;
}
.nav-on .nav-zh {
  font-weight: 650;
}
.nav-en {
  font-family: var(--mono);
  font-size: 9.5px;
  letter-spacing: 0.05em;
  color: var(--faint);
}
.rail-foot {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-top: 1px solid var(--line);
}
.ws {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.05em;
  color: var(--faint);
}
.ws-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--faint);
}
.ws-on { color: var(--ok); }
.ws-on .ws-dot {
  background: var(--ok);
  animation: ws-pulse 1.8s ease-in-out infinite;
}
@keyframes ws-pulse { 50% { opacity: 0.35; } }
.mock-badge {
  color: var(--warn);
  border: 1px solid #e2cf9e;
  background: var(--warn-tint);
  border-radius: 3px;
  padding: 0 4px;
}
.logout {
  margin-left: auto;
  border: none;
  background: none;
  font-size: 12px;
  color: var(--faint);
  cursor: pointer;
  padding: 2px 4px;
}
.logout:hover { color: var(--danger); }

.col {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.strip {
  height: 30px;
  flex: none;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 18px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
}
.strip-sep { color: var(--line-strong); }
.strip-hub {
  font-size: 11px;
  color: var(--faint);
}
.strip-clock {
  font-size: 11px;
  color: var(--sub);
  font-variant-numeric: tabular-nums;
}
.content {
  flex: 1;
  overflow-y: auto;
}
</style>
