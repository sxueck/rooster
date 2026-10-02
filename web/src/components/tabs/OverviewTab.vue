<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RMetric, RMetricStrip, RPanel, RTable, useMessage, type RColumn } from '../../ui'
import { getNodeNetwork, getNodeStats } from '../../api/client'
import type { NodeInfo, NodeNetwork, NodeNetworkInterface, NodeStats } from '../../api/types'
import { errMsg, fmtTime, fmtRelative } from '../../utils/format'

const props = defineProps<{ nodeId: string; node: NodeInfo | null }>()
const message = useMessage()
const stats = ref<NodeStats | null>(null)
const network = ref<NodeNetwork | null>(null)
const networkError = ref(false)

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
type InterfaceRow = Pick<NodeNetworkInterface, 'name' | 'addresses' | 'state' | 'rx_bytes' | 'tx_bytes'>
const interfaceRows = computed<InterfaceRow[]>(() => network.value?.interfaces ?? [])
const interfaceCols: RColumn<InterfaceRow>[] = [
  { title: 'INTERFACE', key: 'name', mono: true },
  { title: 'IP', key: 'addresses', render: (row) => row.addresses.join(', ') || '—' },
  { title: 'STATE', key: 'state' },
  { title: 'RX · 累计', key: 'rx_bytes', align: 'right', render: (row) => formatBytes(row.rx_bytes) },
  { title: 'TX · 累计', key: 'tx_bytes', align: 'right', render: (row) => formatBytes(row.tx_bytes) },
]

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = -1
  do {
    size /= 1024
    unit += 1
  } while (size >= 1024 && unit < units.length - 1)
  return `${size.toFixed(1)} ${units[unit]}`
}

onMounted(async () => {
  const [statsResult, networkResult] = await Promise.allSettled([
    getNodeStats(props.nodeId),
    getNodeNetwork(props.nodeId),
  ])
  if (statsResult.status === 'fulfilled') stats.value = statsResult.value
  else message.error(errMsg(statsResult.reason))
  if (networkResult.status === 'fulfilled') network.value = networkResult.value
  else networkError.value = true
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

    <RPanel title="节点网络接口" kicker="FIREWALL · NETWORK" flush class="mb">
      <div class="network-summary">
        <span class="muted">Hub 连接 IP</span>
        <span class="num">{{ network?.connection_ip ?? '—' }}</span>
        <span class="muted">接口流量为当前累计计数，不含历史速率</span>
      </div>
      <p v-if="networkError" class="muted network-empty">节点离线或暂时无法读取网络状态</p>
      <p v-else-if="network && !network.interfaces.length" class="muted network-empty">未发现网络接口</p>
      <RTable v-else :columns="interfaceCols" :rows="interfaceRows" :row-key="(r: InterfaceRow) => r.name" />
    </RPanel>

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

<style scoped>
.network-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  align-items: baseline;
  padding: 12px 14px;
  border-bottom: 1px solid var(--line);
}
.network-empty {
  padding: 0 14px;
}
</style>
