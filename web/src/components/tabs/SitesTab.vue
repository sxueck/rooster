<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import { RButton, RInput, RModal, RPanel, RTable, RTag, useMessage, type RColumn } from '../../ui'
import { deleteSite, getSites, putSite, getNginxSites, setNginxWaf } from '../../api/client'
import type { Site, NginxSite } from '../../api/client'
import type { WafMode } from '../../api/types'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const sites = ref<Site[]>([])
const editShow = ref(false)
/** path id of the site being edited; empty = creating a new one */
const editId = ref('')
const editText = ref('')
const nginxSites = ref<NginxSite[]>([])
const scanning = ref(false)
const scanError = ref('')
const scanned = ref(false)
const nginxRunning = ref(false)
const busy = ref('')
const attachShow = ref(false)
const attachSite = ref<NginxSite | null>(null)

const nginxCols: RColumn<NginxSite>[] = [
  { title: 'DOMAINS / LISTEN', key: 'domains', render: (r) => h('div', [h('div', r.domains.join(', ') || '默认站点'), h('small', { class: 'muted' }, r.listen.join(', '))]) },
  { title: 'CONFIG', key: 'file', mono: true },
  { title: 'UPSTREAM', key: 'upstream', mono: true },
  { title: 'STATUS', key: 'status', render: (r) => h('div', [hTag(r.status === 'attached' ? (r.mode === 'block' ? 'ok' : 'warn') : 'muted', r.status === 'attached' ? (r.mode === 'block' ? '已接入 · 阻断' : '已接入 · 监控') : r.status === 'needs-recovery' ? '需要恢复' : '未接入'), r.reason ? h('small', { class: 'muted', style: 'display:block;max-width:260px' }, r.reason) : null]) },
  { title: 'ACTIONS', key: 'actions', render: (r) => h('span', { class: 'row-tight' }, r.status === 'attached' ? [
    nginxButton(r.mode === 'block' ? '切换监控' : '开启阻断', r, r.mode === 'block' ? 'detect' : 'block'), nginxButton('关闭并恢复', r, 'off'),
  ] : r.status === 'needs-recovery' ? [nginxButton('恢复原配置', r, 'off')] : [
    h(RButton, { variant: 'link', disabled: !r.supported || busy.value !== '', onClick: () => { attachSite.value = r; attachShow.value = true } }, { default: () => '启用 WAF' }),
  ]) },
]
function nginxButton(label: string, row: NginxSite, mode: WafMode) {
  return h(RButton, { variant: 'link', loading: busy.value === row.id, disabled: busy.value !== '', onClick: () => changeNginx(row, mode) }, { default: () => label })
}
async function scanNginx() {
  scanning.value = true; scanError.value = ''
  try { const value = await getNginxSites(props.nodeId); nginxSites.value = value.sites; nginxRunning.value = value.running; scanned.value = true }
  catch (e) { scanError.value = errMsg(e); nginxSites.value = []; scanned.value = false }
  finally { scanning.value = false }
}
async function changeNginx(row: NginxSite, mode: WafMode) {
  busy.value = row.id
  try {
    await setNginxWaf(props.nodeId, row.id, mode, row.fingerprint); attachShow.value = false
    message.success(mode === 'off' ? '已恢复 Nginx 原转发配置' : mode === 'block' ? 'WAF 已接入并通过阻断自检' : 'WAF 已接入，当前只监控')
    await Promise.all([load(), scanNginx()])
  } catch (e) { message.error(errMsg(e)); await Promise.all([load(), scanNginx()]) }
  finally { busy.value = '' }
}

interface SiteRow {
  id: string
  names: string
  upstream: string
  waf: string
  wafTone: 'muted' | 'warn' | 'ok'
  index: number
}

/** WAF 是 mode 枚举：off/缺省=关闭，detect=监控，block=阻断。 */
function wafLabel(waf: Site['waf']): { label: string; tone: 'muted' | 'warn' | 'ok' } {
  const mode: WafMode | undefined = waf?.mode
  if (mode === 'detect') return { label: '监控', tone: 'warn' }
  if (mode === 'block') return { label: '阻断', tone: 'ok' }
  return { label: '关闭', tone: 'muted' }
}

const cols: RColumn<SiteRow>[] = [
  { title: 'ID', key: 'id', width: 130, mono: true },
  { title: 'DOMAINS', key: 'names' },
  { title: 'UPSTREAM', key: 'upstream', width: 180, mono: true },
  {
    title: 'WAF',
    key: 'waf',
    width: 100,
    render: (r) => hTag(r.wafTone, r.waf),
  },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 150,
    render: (r) =>
      h('span', { class: 'row-tight' }, [
        ...(nginxSites.value.some((n) => n.id === r.id) ? [h('small', { class: 'muted' }, '由 Nginx 接入管理')] : [
          hBtn(sites.value[r.index]?.waf?.mode === 'block' ? '切换监控' : '开启阻断', () => changeSiteMode(r.index)),
          hBtn('JSON 编辑', () => openEdit(r.index)), hBtn('删除', () => removeSite(r.index), 'danger'),
        ]),
      ]),
  },
]

function hTag(tone: 'muted' | 'warn' | 'ok', label: string) {
  return h(RTag, { tone }, { default: () => label })
}
function hBtn(label: string, onClick: () => void, tone?: 'danger') {
  return h(RButton, { variant: 'link', tone, onClick }, { default: () => label })
}

const rows = ref<SiteRow[]>([])
function rebuildRows() {
  rows.value = sites.value.map((s, i) => {
    const waf = wafLabel(s.waf)
    return {
      id: s.id,
      names: (s['server-names'] ?? []).join(', '),
      upstream: String(s.upstream ?? ''),
      waf: waf.label,
      wafTone: waf.tone,
      index: i,
    }
  })
}

async function load() {
  try {
    sites.value = await getSites(props.nodeId)
    rebuildRows()
  } catch (e) {
    message.error(errMsg(e))
  }
}

async function changeSiteMode(i: number) {
  const site = sites.value[i]; if (!site) return
  const mode: WafMode = site.waf?.mode === 'block' ? 'detect' : 'block'
  try { await putSite(props.nodeId, site.id, { ...site, waf: { ...site.waf, mode } }); await load(); message.success('站点 WAF 模式已保存，请确认流量已接入') }
  catch (e) { message.error(errMsg(e)) }
}
function openEdit(i: number) {
  editId.value = sites.value[i].id
  editText.value = JSON.stringify(sites.value[i], null, 2)
  editShow.value = true
}

function addSite() {
  const draft: Site = {
    id: `site-${sites.value.length + 1}`,
    'server-names': [],
    upstream: '127.0.0.1:80',
  }
  editId.value = ''
  editText.value = JSON.stringify(draft, null, 2)
  editShow.value = true
}

async function saveEdit() {
  let obj: Site
  try {
    obj = JSON.parse(editText.value) as Site
  } catch (e) {
    message.error('JSON 解析失败：' + errMsg(e))
    return
  }
  const siteId = String(obj.id ?? editId.value ?? '').trim()
  if (siteId === '') {
    message.error('站点缺少 id（PUT /sites/{id} 以路径 id 为准）')
    return
  }
  try {
    await putSite(props.nodeId, siteId, obj)
    editShow.value = false
    message.success('站点已保存')
    await load()
  } catch (e) {
    message.error(errMsg(e))
  }
}

async function removeSite(i: number) {
  const siteId = sites.value[i].id
  try {
    await deleteSite(props.nodeId, siteId)
    message.success(`已删除站点 ${siteId}`)
    await load()
  } catch (e) {
    message.error(errMsg(e))
  }
}

onMounted(() => { void load(); void scanNginx() })
</script>

<template>
  <!-- 单根节点:RTabs 靠 v-show 切换面板,Vue 会忽略多根(fragment)组件上的 v-show -->
  <div>
    <RPanel title="Nginx 站点" kicker="DISCOVERY" flush>
      <template #actions><RButton size="sm" :loading="scanning" :disabled="busy !== ''" @click="scanNginx">扫描 Nginx</RButton></template>
      <p v-if="scanError" class="muted" style="padding: 0 16px">{{ scanError }}</p>
      <p v-else-if="scanned && !nginxRunning" class="muted" style="padding: 0 16px">已读取配置，但 Nginx 未运行，不能快捷接入。</p>
      <p v-else-if="scanned && nginxSites.length === 0" class="muted" style="padding: 0 16px">未发现 HTTP server 配置。</p>
      <RTable :columns="nginxCols" :rows="nginxSites" :row-key="(r: NginxSite) => r.id" />
    </RPanel>
    <RModal v-model:show="attachShow" title="启用站点 WAF" kicker="NGINX · WAF" :width="560">
      <p>{{ attachSite?.domains.join(', ') || '默认站点' }}</p>
      <p class="muted">将备份并调整 {{ attachSite?.file }} 的转发目标，经过本机 Rooster 检测后再访问原上游。证书继续由 Nginx 管理。校验或接入失败会恢复配置。</p>
      <p class="muted">监控模式只记录日志；阻断模式会拒绝命中的请求。当前请求体检测上限为 128 KiB。此操作不会自动启用全局 CRS。</p>
      <template #footer>
        <RButton variant="ghost" :disabled="busy !== ''" @click="attachShow = false">取消</RButton>
        <RButton :loading="busy !== ''" @click="attachSite && changeNginx(attachSite, 'detect')">接入并监控</RButton>
        <RButton tone="primary" :loading="busy !== ''" @click="attachSite && changeNginx(attachSite, 'block')">接入并阻断</RButton>
      </template>
    </RModal>
    <RPanel title="站点列表" kicker="SITES" flush>
      <template #actions>
        <RButton size="sm" tone="primary" @click="addSite">新增站点</RButton>
      </template>
      <RTable :columns="cols" :rows="rows" :row-key="(r: SiteRow) => r.id" />
    </RPanel>

    <RModal
      v-model:show="editShow"
      kicker="SITE · JSON"
      :title="editId ? '站点 JSON 编辑' : '新增站点（JSON）'"
      :width="560"
    >
      <RInput v-model="editText" type="textarea" :auto-rows="[12, 22]" mono />
      <p class="muted" style="margin: 8px 0 0; font-size: 12px">
        保存时以 JSON 中的 id 作为 PUT /sites/{id} 的路径 id。waf.mode 取值：off / detect / block。
      </p>
      <template #footer>
        <RButton variant="ghost" @click="editShow = false">取消</RButton>
        <RButton tone="primary" @click="saveEdit">保存</RButton>
      </template>
    </RModal>
  </div>
</template>
