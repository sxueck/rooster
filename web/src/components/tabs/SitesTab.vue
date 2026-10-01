<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import { RButton, RInput, RModal, RPanel, RTable, RTag, useMessage, type RColumn } from '../../ui'
import { deleteSite, getSites, putSite } from '../../api/client'
import type { Site } from '../../api/client'
import type { WafMode } from '../../api/types'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const sites = ref<Site[]>([])
const editShow = ref(false)
/** path id of the site being edited; empty = creating a new one */
const editId = ref('')
const editText = ref('')

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
        hBtn('JSON 编辑', () => openEdit(r.index)),
        hBtn('删除', () => removeSite(r.index), 'danger'),
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

onMounted(load)
</script>

<template>
  <!-- 单根节点:RTabs 靠 v-show 切换面板,Vue 会忽略多根(fragment)组件上的 v-show -->
  <div>
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
