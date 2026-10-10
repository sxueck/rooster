<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import {
  RAlert,
  RButton,
  RField,
  RInput,
  RNumberInput,
  RPageHeader,
  RPanel,
  RSelect,
  RTable,
  RTag,
  useMessage,
  type RColumn,
  type SelectOption,
} from '../ui'
import { getNodes, queryEvents } from '../api/client'
import type { EventRecord, EventsQuery } from '../api/types'
import { errMsg, eventKindLabel, eventSummary, eventTagType, fmtTime } from '../utils/format'

const message = useMessage()

// eventTagType（naive 语义）→ RTag tone
const KIND_TONE = { success: 'ok', warning: 'warn', error: 'danger', info: 'info', default: 'muted' } as const

const nodeOptions = ref<SelectOption[]>([])
const fNode = ref<string | null>(null)
const fPlugin = ref('')
const fIp = ref('')
const fRule = ref('')
const sinceText = ref('')
const untilText = ref('')
const fLimit = ref(200)
const rows = ref<EventRecord[]>([])
const offline = ref<string[]>([])
const loading = ref(false)

onMounted(async () => {
  try {
    const nodes = (await getNodes()).nodes
    nodeOptions.value = nodes.map((n) => ({ label: n.id, value: n.id }))
  } catch (e) {
    message.error(errMsg(e))
  }
})

async function run() {
  loading.value = true
  try {
    const q: EventsQuery = { limit: fLimit.value }
    if (fNode.value) q.node = fNode.value
    if (fPlugin.value.trim() !== '') q.plugin = fPlugin.value.trim()
    if (fIp.value.trim() !== '') q.ip = fIp.value.trim()
    if (fRule.value.trim() !== '') q.rule_id = fRule.value.trim()
    if (sinceText.value.trim() !== '') {
      // hub 以 u64 unix 秒反序列化 since/until，不能用 ISO 字符串
      q.since = Math.floor(new Date(sinceText.value).getTime() / 1000)
    }
    if (untilText.value.trim() !== '') {
      // hub 以 u64 unix 秒反序列化 since/until，不能用 ISO 字符串
      q.until = Math.floor(new Date(untilText.value).getTime() / 1000)
    }
    const resp = await queryEvents(q)
    rows.value = resp.events
    offline.value = resp.offline_nodes
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

const cols: RColumn[] = [
  { title: 'TS', key: 'ts', width: 175, render: (r) => fmtTime(r.ts) },
  { title: 'NODE', key: 'node_id', width: 130, mono: true },
  {
    title: 'KIND',
    key: 'kind',
    width: 100,
    render: (r) =>
      h(
        RTag,
        { tone: KIND_TONE[eventTagType(r.event.kind)] },
        { default: () => eventKindLabel(r.event.kind) },
      ),
  },
  { title: 'SUMMARY', key: 'summary', render: (r) => eventSummary(r.event) },
  {
    title: 'JSON',
    key: 'raw',
    width: 100,
    render: (r) => h('details', {}, [h('summary', { class: 'muted', style: 'cursor:pointer' }, 'JSON'), h('pre', { class: 'mono', style: 'margin:4px 0 0' }, JSON.stringify(r.event, null, 2))]),
  },
]
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="SECURITY · EVENTS" title="事件查询" sub="按节点 / 插件 / IP / 规则 / 时间范围检索安全事件" />

    <RPanel class="mb" kicker="QUERY">
      <div class="row">
        <RField inline label="节点">
          <RSelect v-model="fNode" :options="nodeOptions" clearable placeholder="全部" :width="160" />
        </RField>
        <RField inline label="插件">
          <RInput v-model="fPlugin" mono placeholder="waf / ratelimit" :width="140" />
        </RField>
        <RField inline label="IP">
          <RInput v-model="fIp" mono placeholder="1.2.3.4" :width="140" />
        </RField>
        <RField inline label="规则">
          <RInput v-model="fRule" mono placeholder="942-100" :width="120" />
        </RField>
        <RField inline label="时间范围">
          <div class="row-tight">
            <RInput v-model="sinceText" type="text" mono placeholder="2026-09-30T00:00" :width="170" />
            <span class="muted">–</span>
            <RInput v-model="untilText" type="text" mono placeholder="2026-09-30T00:00" :width="170" />
          </div>
        </RField>
        <RField inline label="条数">
          <RNumberInput
            :model-value="fLimit"
            :min="1"
            :max="1000"
            :width="110"
            @update:model-value="(v: number | null) => { if (v !== null) fLimit = v }"
          />
        </RField>
        <RButton tone="primary" :loading="loading" @click="run">查询</RButton>
      </div>
    </RPanel>

    <RAlert v-if="offline.length > 0" tone="warn" class="mb">
      以下节点离线，结果可能不完整：{{ offline.join('、') }}
    </RAlert>

    <RPanel kicker="RESULTS" :title="`查询结果（${rows.length} 条）`" flush>
      <RTable
        :columns="cols"
        :rows="rows"
        :loading="loading"
        :row-key="(r: EventRecord) => r.ts + r.node_id"
        :page-size="20"
      />
    </RPanel>
  </div>
</template>
