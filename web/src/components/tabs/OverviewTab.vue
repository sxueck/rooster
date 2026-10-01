<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RMetric, RMetricStrip, RPanel, RTable, useMessage, type RColumn } from '../../ui'
import { getNodeStats } from '../../api/client'
import type { NodeInfo, NodeStats } from '../../api/types'
import { errMsg, fmtTime, fmtRelative } from '../../utils/format'

const props = defineProps<{ nodeId: string; node: NodeInfo | null }>()
const message = useMessage()
const stats = ref<NodeStats | null>(null)

/** type alias (not interface) so the array is assignable to RTable's Record rows prop */
type KvRow = {
  k: string
  v: number
}
const fwdCols: RColumn<KvRow>[] = [
  { title: 'FORWARD', key: 'k', mono: true },
  { title: 'CONN/PKTS', key: 'v', width: 140, align: 'right', mono: true },
]
const httpCols: RColumn<KvRow>[] = [
  { title: 'HTTP CLASS', key: 'k', mono: true },
  { title: 'REQUESTS', key: 'v', width: 140, align: 'right', mono: true },
]

const fwdRows = computed<KvRow[]>(() =>
  Object.entries(stats.value?.forwards ?? {}).map(([k, v]) => ({ k, v: Number(v) })),
)
const httpRows = computed<KvRow[]>(() =>
  Object.entries(stats.value?.http ?? {}).map(([k, v]) => ({ k, v: Number(v) })),
)

onMounted(async () => {
  try {
    stats.value = await getNodeStats(props.nodeId)
  } catch (e) {
    message.error(errMsg(e))
  }
})
</script>

<template>
  <div>
    <RMetricStrip class="mb">
      <RMetric label="CURRENT BANS" :value="stats?.bans ?? 0" />
      <RMetric label="FORWARD RULES" :value="fwdRows.length" />
      <RMetric label="BLOCKED REQ" :value="Number(stats?.http?.blocked ?? 0)" />
      <RMetric label="CONFIG HASH" :value="node?.config_hash ?? '-'" />
    </RMetricStrip>

    <RPanel title="转发流量" kicker="FORWARD · TRAFFIC" flush class="mb">
      <RTable :columns="fwdCols" :rows="fwdRows" :row-key="(r: KvRow) => r.k" />
    </RPanel>

    <RPanel title="HTTP 统计" kicker="HTTP · STATS" flush>
      <RTable :columns="httpCols" :rows="httpRows" :row-key="(r: KvRow) => r.k" />
    </RPanel>

    <p v-if="node" class="muted" style="margin-top: 12px">
      版本 {{ node.version }}　最后心跳 {{ fmtTime(node.last_seen) }}（{{ fmtRelative(node.last_seen) }}）
    </p>
  </div>
</template>
