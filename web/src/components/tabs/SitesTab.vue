<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import {
  RButton,
  RField,
  RInput,
  RModal,
  RPanel,
  RSelect,
  RSwitch,
  RTable,
  RTag,
  useMessage,
  type RColumn,
} from '../../ui'
import { deleteSite, getSites, putSite, getNginxSites, setNginxWaf } from '../../api/client'
import type { Site, NginxSite } from '../../api/client'
import type { WafMode } from '../../api/types'
import {
  ON_EXCEED_OPTIONS,
  PROXY_PROTOCOL_OPTIONS,
  TLS_MODE_OPTIONS,
  WAF_MODE_OPTIONS,
  draftToSite,
  emptyDraft,
  normalizeRuleIds,
  siteToDraft,
  validateDraft,
  type OnExceed,
  type ProxyProtocol,
  type SiteDraft,
  type TlsMode,
} from '../../utils/siteForm'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const sites = ref<Site[]>([])
const editShow = ref(false)
/** path id of the site being edited; empty = creating a new one */
const editId = ref('')
const draft = ref<SiteDraft>(emptyDraft())
/** 编辑中的原站点:用于保留面板尚未建模的键。 */
const baseSite = ref<Site | null>(null)
const rawMode = ref(false)
const rawText = ref('')
const saving = ref(false)
const nginxSites = ref<NginxSite[]>([])

/** 发现层按 server 块出 行，同域名的 80 跳转块无转发不可接入，折叠进主行避免占屏。 */
interface NginxGroupRow {
  [key: string]: unknown
  key: string
  main: NginxSite
  folded: NginxSite[]
}
/** Enable WAF 的门控以 Agent 分类结果为准；未上线该字段的旧 Agent 退回 reason 为空。 */
function attachable(s: NginxSite): boolean {
  return s.supported ?? s.reason === null
}
/** 有（或可能有）转发的块各自占行，显示自己的 reason；只有确认无转发的
 *  跳转/ACME/静态块才折进首行——否则被拒绝的原因会被同域名的另一行盖掉。 */
function foldable(s: NginxSite): boolean {
  return s.has_proxy_pass === undefined ? !s.upstream : !s.has_proxy_pass
}
const nginxRows = computed<NginxGroupRow[]>(() => {
  const groups = new Map<string, NginxSite[]>()
  for (const s of nginxSites.value) {
    const k = s.domains[0] || '_'
    const g = groups.get(k)
    if (g) g.push(s)
    else groups.set(k, [s])
  }
  const rows: NginxGroupRow[] = []
  for (const [key, list] of groups) {
    const mains = list.filter((s) => attachable(s) || !foldable(s))
    const shown = mains.length > 0 ? mains : [list[0]]
    shown.forEach((main, i) => {
      // 可接管块与被拒绝的转发块都必须占行保留操作入口；其余折进首行。
      const folded = i === 0 ? list.filter((s) => !shown.includes(s)) : []
      rows.push({ key: i === 0 ? key : `${key}:${main.id}`, main, folded })
    })
  }
  return rows
})
const scanning = ref(false)
const scanError = ref('')
const scanned = ref(false)
/** nginx 未安装/未找到：不当作错误展示，直接给“暂无数据”。 */
const scanMissing = ref(false)
const nginxRunning = ref(false)
const busy = ref('')
const attachShow = ref(false)
const attachSite = ref<NginxSite | null>(null)

const nginxCols: RColumn<NginxGroupRow>[] = [
  { title: 'DOMAINS / LISTEN', key: 'domains', render: (r) => h('div', [
    h('div', r.main.domains.join(', ') || '默认站点'),
    h('small', { class: 'muted' }, r.main.listen.join(', ')),
    ...r.folded.map((f) => h('small', { class: 'muted', style: 'display:block' }, `+ ${f.listen.join(', ') || '—'} · 跳转/ACME`)),
  ]) },
  { title: 'CONFIG', key: 'file', mono: true, render: (r) => r.main.file },
  { title: 'UPSTREAM', key: 'upstream', mono: true, render: (r) => h('div', [
    h('div', r.main.upstream ?? ''),
    ...(r.main.extra_locations ?? []).map((x) => h('small', { class: 'muted', style: 'display:block' }, `${x.location} → ${x.upstream}`)),
    r.main.bypassed_locations ? h('small', { class: 'muted', style: 'display:block' }, `另有 ${r.main.bypassed_locations} 个 location 不经 WAF`) : null,
  ]) },
  { title: 'STATUS', key: 'status', width: 150, render: (r) => statusCell(r) },
  { title: 'ACTIONS', key: 'actions', render: (r) => { const m = r.main; return h('span', { class: 'row-tight' }, m.status === 'attached' ? [
    nginxButton(m.mode === 'block' ? '切换监控' : '开启阻断', m, m.mode === 'block' ? 'detect' : 'block'), nginxButton('关闭并恢复', m, 'off'),
  ] : m.status === 'needs-recovery' ? [nginxButton('恢复原配置', m, 'off')] : [
    h(
      RButton,
      {
        variant: 'link',
        disabled: !attachable(m) || busy.value !== '',
        onClick: () => { attachSite.value = m; attachShow.value = true },
      },
      { default: () => '启用 WAF' },
    ),
  ]) } },
]
function nginxButton(label: string, row: NginxSite, mode: WafMode) {
  return h(RButton, { variant: 'link', loading: busy.value === row.id, disabled: busy.value !== '', onClick: () => changeNginx(row, mode) }, { default: () => label })
}
async function scanNginx() {
  scanning.value = true; scanError.value = ''; scanMissing.value = false
  try { const value = await getNginxSites(props.nodeId); nginxSites.value = value.sites; nginxRunning.value = value.running; scanned.value = true }
  catch (e) {
    const msg = errMsg(e)
    if (/not found on this host/i.test(msg)) scanMissing.value = true
    else scanError.value = msg
    nginxSites.value = []; scanned.value = false
  }
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
  /** 误报加白的规则条数 */
  excl: number
  index: number
}

/** WAF 是 mode 枚举：off/缺省=关闭，detect=监控，block=阻断。 */
function wafLabel(waf: Site['waf']): { label: string; tone: 'muted' | 'warn' | 'ok' } {
  const mode: WafMode | undefined = waf?.mode
  if (mode === 'detect') return { label: '监控', tone: 'warn' }
  if (mode === 'block') return { label: '阻断', tone: 'ok' }
  return { label: '关闭', tone: 'muted' }
}

/** rooster 站点是否由 Nginx 接入托管(含多 location 子站点 id `nginx-<hash>-lN`)。 */
function isNginxManaged(id: string): boolean {
  return nginxSites.value.some((n) => n.id === id || id.startsWith(`${n.id}-l`))
}

const cols: RColumn<SiteRow>[] = [
  { title: 'ID', key: 'id', width: 130, mono: true },
  { title: 'DOMAINS', key: 'names' },
  { title: 'UPSTREAM', key: 'upstream', width: 180, mono: true },
  {
    title: 'WAF',
    key: 'waf',
    width: 110,
    render: (r) =>
      h('div', [
        hTag(r.wafTone, r.waf),
        r.excl > 0 ? h('small', { class: 'muted', style: 'display:block' }, `加白 ${r.excl} 条`) : null,
      ]),
  },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 150,
    render: (r) =>
      h('span', { class: 'row-tight' }, [
        ...(isNginxManaged(r.id) ? [h('small', { class: 'muted' }, '由 Nginx 接入管理')] : [
          hBtn(sites.value[r.index]?.waf?.mode === 'block' ? '切换监控' : '开启阻断', () => changeSiteMode(r.index)),
          hBtn('编辑', () => openEdit(r.index)), hBtn('删除', () => removeSite(r.index), 'danger'),
        ]),
      ]),
  },
]

function hTag(tone: 'muted' | 'warn' | 'ok', label: string) {
  return h(RTag, { tone }, { default: () => label })
}
/** 状态单元格：一个紧凑标签 + 未接入原因直接写明（“为什么不能一键启用 WAF”是这一页唯一的关键问题）。 */
function statusCell(r: NginxGroupRow) {
  const m = r.main
  const attached = m.status === 'attached'
  const label = attached ? (m.mode === 'block' ? '阻断' : '监控') : m.status === 'needs-recovery' ? '待恢复' : '未接入'
  const tone = attached ? (m.mode === 'block' ? 'ok' : 'warn') : 'muted'
  const reason = !attached && m.reason ? h('small', { class: 'muted status-reason' }, m.reason) : null
  return reason ? h('div', [hTag(tone, label), reason]) : hTag(tone, label)
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
      excl: normalizeRuleIds(s.waf?.exclusions).length,
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
  const site = sites.value[i]
  if (!site) return
  editId.value = site.id
  baseSite.value = site
  draft.value = siteToDraft(site)
  rawMode.value = false
  rawText.value = ''
  editShow.value = true
}

function addSite() {
  const d = emptyDraft()
  d.id = `site-${sites.value.length + 1}`
  editId.value = ''
  baseSite.value = null
  draft.value = d
  rawMode.value = false
  rawText.value = ''
  editShow.value = true
}

/** 表单 <-> JSON 双向同步:进入 JSON 时序列化当前表单,回到表单时解析回去。 */
function setRawMode(toJson: boolean) {
  if (toJson === rawMode.value) return
  if (toJson) {
    rawText.value = JSON.stringify(draftToSite(draft.value, baseSite.value), null, 2)
    rawMode.value = true
    return
  }
  try {
    draft.value = siteToDraft(JSON.parse(rawText.value) as Site)
    rawMode.value = false
  } catch (e) {
    message.error('JSON 解析失败，无法回到表单：' + errMsg(e))
  }
}

function addRateRow() {
  draft.value.rateLimit.push({ key: 'ip', rate: '5/second', burst: '', onExceed: 'reject', banAfter: '' })
}

function removeRateRow(i: number) {
  draft.value.rateLimit.splice(i, 1)
}

async function saveEdit() {
  let obj: Site
  if (rawMode.value) {
    try {
      obj = JSON.parse(rawText.value) as Site
    } catch (e) {
      message.error('JSON 解析失败：' + errMsg(e))
      return
    }
  } else {
    const errors = validateDraft(draft.value)
    if (errors.length > 0) {
      message.error(errors.map((e) => `${e.field}：${e.message}`).join('；'))
      return
    }
    obj = draftToSite(draft.value, baseSite.value)
  }
  const siteId = String(obj.id ?? editId.value ?? '').trim()
  if (siteId === '') {
    message.error('站点缺少 id（PUT /sites/{id} 以路径 id 为准）')
    return
  }
  saving.value = true
  try {
    await putSite(props.nodeId, siteId, obj)
    editShow.value = false
    message.success('站点已保存')
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
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
      <p v-else-if="scanMissing" class="muted" style="padding: 0 16px">暂无数据</p>
      <p v-else-if="scanned && !nginxRunning" class="muted" style="padding: 0 16px">已读取配置，但 Nginx 未运行，不能快捷接入。</p>
      <p v-else-if="scanned && nginxSites.length === 0" class="muted" style="padding: 0 16px">未发现 HTTP server 配置。</p>
      <RTable v-if="!scanMissing" :columns="nginxCols" :rows="nginxRows" :row-key="(r: NginxGroupRow) => r.key" empty-text="暂无数据" />
    </RPanel>
    <RModal v-model:show="attachShow" title="启用站点 WAF" kicker="NGINX · WAF" :width="560">
      <p>{{ attachSite?.domains.join(', ') || '默认站点' }}</p>
      <p class="muted">将备份并调整 {{ attachSite?.file }} 的转发目标，经过本机 Rooster 检测后再访问原上游。证书继续由 Nginx 管理。校验或接入失败会恢复配置。</p>
      <p class="muted">监控模式只记录日志；阻断模式会拒绝命中的请求。当前请求体检测上限为 128 KiB。</p>
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
      kicker="SITE · 配置"
      :title="editId ? '编辑站点' : '新增站点'"
      :width="720"
    >
      <div class="row-tight" style="margin-bottom: 14px">
        <RButton size="sm" :tone="rawMode ? 'default' : 'primary'" @click="setRawMode(false)">表单</RButton>
        <RButton size="sm" :tone="rawMode ? 'primary' : 'default'" @click="setRawMode(true)">高级 JSON</RButton>
        <span class="muted mode-hint">站点字段已全部表单化；JSON 视图用于核对将要下发的内容。</span>
      </div>

      <RInput v-if="rawMode" v-model="rawText" type="textarea" :auto-rows="[14, 24]" mono />

      <div v-else class="form">
        <div class="cols-2">
          <RField inline :label-width="120" label="ID">
            <RInput v-model="draft.id" :disabled="editId !== ''" mono />
          </RField>
          <RField inline :label-width="100" label="UPSTREAM">
            <RInput v-model="draft.upstream" mono placeholder="127.0.0.1:8080" />
          </RField>
        </div>
        <RField inline :label-width="120" label="DOMAINS" hint="逗号或空格分隔；留空即默认站点">
          <RInput v-model="draft.names" />
        </RField>

        <p class="micro sec">TLS</p>
        <RField inline :label-width="120" label="MODE">
          <RSelect
            :model-value="draft.tlsMode"
            :options="TLS_MODE_OPTIONS"
            :width="240"
            @update:model-value="(v: string | null) => { if (v !== null) draft.tlsMode = v as TlsMode }"
          />
        </RField>
        <template v-if="draft.tlsMode === 'terminate'">
          <RField inline :label-width="120" label="CERT" hint="与 KEY 同时填写则优先于 ACME">
            <RInput v-model="draft.cert" mono placeholder="/etc/ssl/fullchain.pem" />
          </RField>
          <RField inline :label-width="120" label="KEY">
            <RInput v-model="draft.key" mono placeholder="/etc/ssl/privkey.pem" />
          </RField>
          <RField inline :label-width="120" label="ACME" hint="未填本地证书时用 HTTP-01 自动签发">
            <RSwitch v-model="draft.acme" />
          </RField>
        </template>

        <p class="micro sec">WAF</p>
        <RField inline :label-width="120" label="MODE">
          <RSelect
            :model-value="draft.wafMode"
            :options="WAF_MODE_OPTIONS"
            :width="300"
            @update:model-value="(v: string | null) => { if (v !== null) draft.wafMode = v as WafMode }"
          />
        </RField>
        <RField inline :label-width="120" label="EXCLUSIONS" hint="误报加白的规则 id，逗号分隔；事件页「加白」也写这里">
          <RInput v-model="draft.exclusions" mono placeholder="942100, 942130" />
        </RField>

        <p class="micro sec">请求控制</p>
        <div class="cols-2">
          <RField inline :label-width="120" label="CONNECT TO" hint="形如 60s">
            <RInput v-model="draft.connectTimeout" mono placeholder="10s" />
          </RField>
          <RField inline :label-width="110" label="MAX BODY" hint="字节；仅 hardening.body-cap 启用时生效">
            <RInput v-model="draft.maxBodySize" mono placeholder="131072" />
          </RField>
          <RField inline :label-width="120" label="PROXY PROTOCOL">
            <RSelect
              :model-value="draft.proxyProtocol"
              :options="PROXY_PROTOCOL_OPTIONS"
              :width="180"
              @update:model-value="(v: string | null) => { if (v !== null) draft.proxyProtocol = v as ProxyProtocol }"
            />
          </RField>
          <RField inline :label-width="110" label="REDIRECT HTTPS" hint="80 端口访问本站点时 301 到 https">
            <RSwitch v-model="draft.redirectHttps" />
          </RField>
        </div>

        <p class="micro sec">限速</p>
        <div v-for="(r, i) in draft.rateLimit" :key="i" class="rl-row">
          <RInput v-model="r.key" mono :width="110" placeholder="ip" />
          <RInput v-model="r.rate" mono :width="120" placeholder="5/second" />
          <RInput v-model="r.burst" mono :width="74" placeholder="burst" />
          <RSelect
            :model-value="r.onExceed"
            :options="ON_EXCEED_OPTIONS"
            :width="120"
            size="sm"
            @update:model-value="(v: string | null) => { if (v !== null) r.onExceed = v as OnExceed }"
          />
          <RInput v-model="r.banAfter" mono :width="96" placeholder="ban-after" />
          <RButton size="sm" variant="link" tone="danger" @click="removeRateRow(i)">删除</RButton>
        </div>
        <div>
          <RButton size="sm" variant="link" @click="addRateRow">添加限速规则</RButton>
          <span class="muted mode-hint">key 取 ip / ip+path / header:&lt;名&gt;；rate 形如 5/second。</span>
        </div>

        <p class="micro sec">GeoIP / JA4</p>
        <div class="cols-2">
          <RField inline :label-width="120" label="GEO DENY" hint="逗号分隔的国家码">
            <RInput v-model="draft.geoDeny" mono placeholder="RU, CN" />
          </RField>
          <RField inline :label-width="110" label="GEO ALLOW" hint="只允许这些国家码">
            <RInput v-model="draft.geoAllow" mono />
          </RField>
        </div>
        <RField inline :label-width="120" label="JA4 DENY" hint="逗号分隔的 JA4 指纹">
          <RInput v-model="draft.ja4Deny" mono />
        </RField>
      </div>

      <template #footer>
        <RButton variant="ghost" @click="editShow = false">取消</RButton>
        <RButton tone="primary" :loading="saving" @click="saveEdit">保存</RButton>
      </template>
    </RModal>
  </div>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.sec {
  margin: 10px 0 0;
  padding-top: 10px;
  border-top: 1px solid var(--line);
  color: var(--faint);
}
.mode-hint {
  font-size: 12px;
}
.rl-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-bottom: 6px;
}
.status-reason {
  display: block;
  max-width: 260px;
  margin-top: 4px;
  line-height: 1.5;
}
</style>
