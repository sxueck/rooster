<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { RMetric, RMetricStrip, RPanel, RTable, RTag, useMessage, type RColumn } from '../../ui'
import { getNodeNetwork, getNodeStats } from '../../api/client'
import type {
  ForwardStat,
  NodeInfo,
  NodeNetwork,
  NodeNetworkInterface,
  NodeStats,
  SiteHttpStat,
} from '../../api/types'
import { errMsg, fmtBytes, fmtTime, fmtRelative } from '../../utils/format'
import { siteTotals } from '../../utils/stats'

const props = defineProps<{ nodeId: string; node: NodeInfo | null }>()
const message = useMessage()
const stats = ref<NodeStats | null>(null)
const network = ref<NodeNetwork | null>(null)
const networkError = ref(false)

function stateTag(up: boolean, on = 'UP', off = 'DOWN') {
  return h(RTag, { tone: up ? 'ok' : 'danger' }, { default: () => (up ? on : off) })
}

const fwdCols: RColumn<ForwardStat>[] = [
  { title: 'RULE', key: 'id', mono: true },
  { title: 'PROTO', key: 'proto', width: 90, mono: true },
  { title: 'LISTEN', key: 'listening', width: 90, render: (r) => stateTag(r.listening) },
  {
    title: 'CONN ACT/TOT',
    key: 'conns_total',
    width: 140,
    align: 'right',
    mono: true,
    sortable: true,
    render: (r) => `${r.conns_active} / ${r.conns_total}`,
  },
  { title: 'UDP SESS', key: 'udp_sessions', width: 100, align: 'right', mono: true },
  {
    title: 'IN ↓',
    key: 'bytes_in',
    width: 110,
    align: 'right',
    mono: true,
    sortable: true,
    render: (r) => fmtBytes(r.bytes_in),
  },
  {
    title: 'OUT ↑',
    key: 'bytes_out',
    width: 110,
    align: 'right',
    mono: true,
    sortable: true,
    render: (r) => fmtBytes(r.bytes_out),
  },
]

const httpCols: RColumn<SiteHttpStat>[] = [
  { title: 'SITE', key: 'id', mono: true },
  { title: 'REQ', key: 'requests', width: 110, align: 'right', mono: true, sortable: true },
  { title: 'BLOCKED', key: 'blocked', width: 110, align: 'right', mono: true, sortable: true },
  { title: 'PASSTHRU', key: 'conns_passthrough', width: 110, align: 'right', mono: true },
  {
    title: 'IN ↓',
    key: 'bytes_in',
    width: 110,
    align: 'right',
    mono: true,
    render: (r) => fmtBytes(r.bytes_in),
  },
  {
    title: 'OUT ↑',
    key: 'bytes_out',
    width: 110,
    align: 'right',
    mono: true,
    render: (r) => fmtBytes(r.bytes_out),
  },
  { title: ':80', key: 'listening_http', width: 70, render: (r) => stateTag(r.listening_http, 'ON', 'OFF') },
  { title: ':443', key: 'listening_https', width: 70, render: (r) => stateTag(r.listening_https, 'ON', 'OFF') },
]

const fwdRows = computed<ForwardStat[]>(() => stats.value?.forwards ?? [])
const httpRows = computed<SiteHttpStat[]>(() => stats.value?.http ?? [])
const totals = computed(() => siteTotals(stats.value?.http))
type InterfaceRow = Pick<NodeNetworkInterface, 'name' | 'addresses' | 'state' | 'rx_bytes' | 'tx_bytes'>
const interfaceRows = computed<InterfaceRow[]>(() => network.value?.interfaces ?? [])
const interfaceCols: RColumn<InterfaceRow>[] = [
  { title: 'INTERFACE', key: 'name', mono: true },
  { title: 'IP', key: 'addresses', render: (row) => row.addresses.join(', ') || '—' },
  { title: 'STATE', key: 'state' },
  { title: 'RX · 累计', key: 'rx_bytes', align: 'right', render: (row) => fmtBytes(row.rx_bytes) },
  { title: 'TX · 累计', key: 'tx_bytes', align: 'right', render: (row) => fmtBytes(row.tx_bytes) },
]

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
      <RMetric label="CURRENT BANS" :value="stats?.bans ?? '—'" />
      <RMetric label="FORWARD RULES" :value="fwdRows.length" />
      <RMetric label="HTTP REQ" :value="totals.requests" />
      <RMetric label="BLOCKED REQ" :value="totals.blocked" />
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
      <p class="scope-note">
        只统计 Rooster 用户态 L4 转发规则（config <span class="mono">forwards</span>）：LISTEN=DOWN
        表示监听 bind 失败（端口已被 sshd / nginx 占用），连接数与字节数永远为 0。经 Nginx →
        Rooster 回环的 WAF 流量不计入本表，见下方 HTTP 统计；纯 iptables/nftables DNAT
        转发的流量不经过 Rooster 进程，面板无法感知。
      </p>
      <RTable
        :columns="fwdCols"
        :rows="fwdRows"
        :row-key="(r: ForwardStat) => r.id"
        :page-size="10"
        empty-text="NO FORWARD RULES · 未配置 L4 转发规则"
      />
    </RPanel>

    <RPanel title="HTTP 统计" kicker="HTTP · STATS" flush>
      <p class="scope-note">
        按站点计数：80/443 直接反代、TLS 透传，以及 Nginx WAF 接入后的 127.0.0.1 回环站点都记在这里。
        列表为空 = 该节点没有任何已配置站点（未开 http-guard，也没有 Nginx 接入）。
      </p>
      <RTable
        :columns="httpCols"
        :rows="httpRows"
        :row-key="(r: SiteHttpStat) => r.id"
        :page-size="10"
        empty-text="NO SITES · 暂无站点统计"
      />
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
.scope-note {
  padding: 10px 14px;
  margin: 0;
  border-bottom: 1px solid var(--line);
  font-size: 12px;
  line-height: 1.6;
  color: var(--faint);
}
</style>
