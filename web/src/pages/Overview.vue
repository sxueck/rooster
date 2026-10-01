<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  RButton,
  RMetric,
  RMetricStrip,
  RPageHeader,
  RPanel,
  RTable,
  useMessage,
  type RColumn,
} from '../ui'
import { getOverview } from '../api/client'
import type { CountryCount, IpCount, OverviewResp, RuleCount } from '../api/types'
import TrendChart from '../components/TrendChart.vue'
import GeoFooter from '../components/GeoFooter.vue'
import { errMsg } from '../utils/format'

const message = useMessage()
const data = ref<OverviewResp | null>(null)
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    data.value = await getOverview()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    loading.value = false
  }
}
onMounted(load)

const ipCols: RColumn<IpCount>[] = [
  { title: 'ATTACK IP', key: 'ip', mono: true },
  { title: 'COUNT', key: 'count', width: 90, align: 'right', mono: true },
]
const ruleCols: RColumn<RuleCount>[] = [
  { title: 'RULE', key: 'rule_id', mono: true },
  { title: 'COUNT', key: 'count', width: 90, align: 'right', mono: true },
]
const countryCols: RColumn<CountryCount>[] = [
  { title: 'COUNTRY', key: 'country', mono: true },
  { title: 'COUNT', key: 'count', width: 90, align: 'right', mono: true },
]
</script>

<template>
  <div class="page">
    <RPageHeader kicker="CLUSTER · OVERVIEW" title="总览" sub="集群状态与近 24 小时攻击态势">
      <template #extra>
        <RButton size="sm" :loading="loading" @click="load">刷新</RButton>
      </template>
    </RPageHeader>

    <RMetricStrip style="margin: 16px 0">
      <RMetric label="NODES TOTAL" :value="data?.nodes_total ?? '-'" />
      <RMetric label="ONLINE" :value="data?.nodes_online ?? '-'" />
      <RMetric label="GLOBAL BANS" :value="data?.global_bans ?? '-'" />
      <RMetric label="BANS 24H" :value="data?.bans_24h ?? '-'" />
    </RMetricStrip>

    <RPanel title="24 小时攻击趋势" kicker="TREND · 24H" style="margin-bottom: 16px">
      <TrendChart v-if="data" :data="data.trend_24h" />
    </RPanel>

    <div class="cols-3">
      <RPanel title="Top 攻击 IP" kicker="TOP · SOURCES" flush>
        <RTable :columns="ipCols" :rows="data?.top_attack_ips ?? []" :row-key="(r: IpCount) => r.ip" />
      </RPanel>
      <RPanel title="Top 命中规则" kicker="TOP · RULES" flush>
        <RTable :columns="ruleCols" :rows="data?.top_rules ?? []" :row-key="(r: RuleCount) => r.rule_id" />
      </RPanel>
      <RPanel title="Top 攻击来源国家/地区" kicker="TOP · GEO" flush>
        <RTable
          :columns="countryCols"
          :rows="data?.top_countries ?? []"
          :row-key="(r: CountryCount) => r.country"
        />
        <div class="geo-note"><GeoFooter /></div>
      </RPanel>
    </div>
  </div>
</template>

<style scoped>
.geo-note {
  padding: 0 14px;
}
</style>
