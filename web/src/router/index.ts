import { createRouter, createWebHistory } from 'vue-router'
import { getToken, hasSession } from '../api/client'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    /** English uppercase micro label shown in the page header */
    kicker?: string
    plain?: boolean
    public?: boolean
  }
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('../pages/Login.vue'),
      meta: { title: '登录', plain: true, public: true },
    },
    { path: '/', name: 'overview', component: () => import('../pages/Overview.vue'), meta: { title: '总览', kicker: 'OVERVIEW' } },
    { path: '/nodes', name: 'nodes', component: () => import('../pages/Nodes.vue'), meta: { title: '节点管理', kicker: 'NODES' } },
    { path: '/nodes/:id', name: 'node-detail', component: () => import('../pages/NodeDetail.vue'), meta: { title: '节点详情', kicker: 'NODE DETAIL' } },
    { path: '/templates', name: 'templates', component: () => import('../pages/Templates.vue'), meta: { title: '配置模板', kicker: 'TEMPLATES' } },
    { path: '/bans', name: 'bans', component: () => import('../pages/GlobalBans.vue'), meta: { title: '全局黑名单', kicker: 'GLOBAL BANS' } },
    { path: '/events', name: 'events', component: () => import('../pages/EventsQuery.vue'), meta: { title: '事件查询', kicker: 'EVENTS' } },
    { path: '/wasm', name: 'wasm', component: () => import('../pages/Wasm.vue'), meta: { title: 'WASM 插件', kicker: 'PLUGINS' } },
    { path: '/waf', name: 'waf', component: () => import('../pages/Waf.vue'), meta: { title: 'WAF 规则报告', kicker: 'WAF REPORT' } },
    { path: '/upgrade', name: 'upgrade', component: () => import('../pages/Upgrade.vue'), meta: { title: '版本升级', kicker: 'UPGRADE' } },
    { path: '/audit', name: 'audit', component: () => import('../pages/Audit.vue'), meta: { title: '审计日志', kicker: 'AUDIT LOG' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (getToken()) return true
  // 本地存储是空的 ≠ 没有会话:cookie 按 host 存、与端口无关,
  // 从 :443 还是 :9443 进来都是同一个会话,先问 Hub 一句再赶人。
  if (await hasSession()) return true
  return { name: 'login', query: { redirect: to.fullPath } }
})

export default router
