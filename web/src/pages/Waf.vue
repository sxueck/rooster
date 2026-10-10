<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from 'vue'
import {
  RAlert,
  REmpty,
  RMetric,
  RMetricStrip,
  RPageHeader,
  RPanel,
  RInput,
  RSelect,
  RTable,
  RTag,
  useMessage,
  type RColumn,
  type SelectOption,
} from '../ui'
import { getNodes, getWafReport, getWafRules } from '../api/client'
import { ApiError } from '../api/types'
import type { NodeInfo, WafReportResp, WafRule, WafRulesResp, WafSkippedRule } from '../api/types'
import { errMsg } from '../utils/format'

const message = useMessage()
const nodeOptions = ref<SelectOption[]>([])
const nodeId = ref<string | null>(null)
const report = ref<WafReportResp | null>(null)
const rules = ref<WafRulesResp | null>(null)
const loading = ref(false)
const rulesLoading = ref(false)

// 规则表过滤：关键字（id / msg 子串）+ severity + phase
const keyword = ref('')
const fSeverity = ref<string | null>(null)
const fPhase = ref<string | null>(null)

const skipCols: RColumn[] = [
  { title: 'LINE', key: 'line', width: 90, align: 'right' },
  { title: 'REASON', key: 'reason', mono: true },
]

const SEV_ORDER = ['CRITICAL', 'ERROR', 'WARNING', 'NOTICE'] as const
const SEV_TONE: Record<string, 'ok' | 'danger' | 'warn' | 'info' | 'muted'> = {
  CRITICAL: 'danger',
  ERROR: 'warn',
  WARNING: 'info',
  NOTICE: 'muted',
}

const ruleCols: RColumn<WafRule>[] = [
  { title: 'ID', key: 'id', width: 100, align: 'right', mono: true, sortable: true },
  { title: 'PHASE', key: 'phase', width: 70, align: 'right', mono: true },
  {
    title: 'SEVERITY',
    key: 'severity',
    width: 110,
    render: (r) => h(RTag, { tone: SEV_TONE[r.severity] ?? 'muted' }, { default: () => r.severity }),
  },
  { title: 'PL', key: 'min_pl', width: 60, align: 'right', mono: true },
  { title: 'MSG', key: 'msg' },
  { title: 'TAGS', key: 'tags', mono: true, render: (r) => r.tags.join(' ') },
]

const counts = computed(() => {
  // report 为 null 表示 http-guard 未启用
  const r = report.value?.report ?? null
  return {
    loaded: r?.loaded ?? null,
    skipped: r?.skipped ?? [],
    directives: r?.ignored_directives ?? null,
    paranoia: r?.paranoia_level ?? null,
    unmodelled: r?.unmodelled_targets ?? null,
    threshold: report.value?.threshold ?? null,
  }
})

const crs = computed(() => report.value?.report?.crs ?? null)
/** CRS 实际生效：enabled 且规则文件在位，否则只有内置签名在跑 */
const crsEffective = computed(() => !!crs.value && crs.value.enabled && crs.value.rules_present)
const crsLabel = computed<string | null>(() => {
  if (report.value?.report == null) return null
  const c = crs.value
  if (!c || !c.enabled || !c.rules_present) return '未生效'
  if (c.source === 'local-dir') return '本地目录'
  if (c.source === 'builtin-embedded') return '内置规则集'
  return '未生效'
})
const crsNote = computed(() => {
  const c = crs.value
  if (!c || !crsEffective.value) return ''
  return c.source === 'local-dir' ? (c.dir ?? '') : `内置 ${c.embedded_files} 个签名文件`
})

const severityOptions = computed<SelectOption[]>(() => {
  const bs = rules.value?.by_severity ?? {}
  return SEV_ORDER.filter((s) => (bs[s] ?? 0) > 0).map((s) => ({
    label: `${s}（${bs[s]}）`,
    value: s,
  }))
})
const phaseOptions = computed<SelectOption[]>(() => {
  const bp = rules.value?.by_phase ?? {}
  return Object.keys(bp)
    .filter((p) => bp[p] > 0)
    .sort((a, b) => Number(a) - Number(b))
    .map((p) => ({ label: `PHASE ${p}（${bp[p]}）`, value: p }))
})

// 不显式标注 WafRule[]：经 ref 解包的类型才带隐式索引签名，才能赋给 RTable 的 rows
const filteredRules = computed(() => {
  const all = rules.value?.rules ?? []
  const kw = keyword.value.trim().toLowerCase()
  return all.filter((r) => {
    if (fSeverity.value && r.severity !== fSeverity.value) return false
    if (fPhase.value && String(r.phase) !== fPhase.value) return false
    if (kw !== '' && !String(r.id).includes(kw) && !r.msg.toLowerCase().includes(kw)) return false
    return true
  })
})

onMounted(async () => {
  try {
    const nodes: NodeInfo[] = (await getNodes()).nodes
    nodeOptions.value = nodes.map((n) => ({
      label: `${n.id}${n.online ? '' : '（离线）'}`,
      value: n.id,
    }))
    if (nodeOptions.value.length > 0) {
      // 深链支持：/waf?node=<id> 直接打开某节点的报告（面板里“看这台机器的规则”
      // 最常用的入口，也便于告警回复里贴链接）。非法 id 回退到首个节点。
      const want = new URLSearchParams(location.search).get('node')
      nodeId.value =
        want && nodeOptions.value.some((o) => o.value === want)
          ? want
          : (nodeOptions.value[0]!.value as string)
      await load()
    }
  } catch (e) {
    message.error(errMsg(e))
  }
})

async function load() {
  if (!nodeId.value) return
  loading.value = true
  rulesLoading.value = true
  try {
    // 报告与规则集互相独立，各自失败各自提示，不互相拖垮
    const [rp, rr] = await Promise.allSettled([getWafReport(nodeId.value), getWafRules(nodeId.value)])
    if (rp.status === 'fulfilled') report.value = rp.value
    else {
      report.value = null
      message.error(errMsg(rp.reason))
    }
    if (rr.status === 'fulfilled') rules.value = rr.value
    else {
      rules.value = null
      // 旧版 Agent 没有 /waf/rules 端点：面板照常展示报告，规则表置空即可，
      // 不该每切一个老节点就弹一个 “Not Found”。
      if (!(rr.reason instanceof ApiError && rr.reason.status === 404)) {
        message.error(errMsg(rr.reason))
      }
    }
  } finally {
    loading.value = false
    rulesLoading.value = false
  }
}

// 切节点必须重拉数据：RSelect 只绑了 v-model,不会有 change 回调;
// 用显式的 onNode 而不是 watch,避免 watch 语义在组件实例上不确定。
function onNode(v: string | null) {
  nodeId.value = v
  void load()
}

// 双保险:除显式 handler 外也 watch nodeId,任何写入路径(深链、程序化赋值)
// 都会重拉数据。load() 幂等,重复触发只是多一次 GET。
watch(nodeId, () => void load())
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="SECURITY · WAF REPORT" title="WAF 规则报告" sub="各节点规则加载情况：生效规则集 / 跳过 / 阈值">
      <template #extra>
        <RSelect
          :model-value="nodeId"
          @update:model-value="onNode"
          :options="nodeOptions"
          placeholder="选择节点"
          :width="220"
        />
      </template>
    </RPageHeader>

    <RAlert v-if="report?.report != null && !crsEffective" tone="warn" class="mb">
      CRS 规则集未生效：节点上没有可用的 CRS 规则集，当前仅运行内置签名，覆盖面显著不足。
    </RAlert>

    <RMetricStrip class="mb">
      <RMetric label="LOADED RULES" :value="counts.loaded" />
      <RMetric label="PARANOIA LEVEL" :value="counts.paranoia" />
      <RMetric label="SCORE THRESHOLD" :value="counts.threshold" />
      <RMetric label="CRS RULESET" :value="crsLabel" :tone="crsEffective ? 'ok' : 'warn'">
        <span v-if="crsNote" class="mono">{{ crsNote }}</span>
      </RMetric>
      <RMetric label="SKIPPED RULES" :value="counts.skipped.length" :tone="counts.skipped.length > 0 ? 'warn' : 'ink'" />
      <RMetric label="IGNORED DIRECTIVES" :value="counts.directives" hint="SecMarker 等辅助指令,不算规则损失" />
      <RMetric label="UNMODELLED TARGETS" :value="counts.unmodelled" hint="目标变量未建模,这些规则永远不会命中" />
    </RMetricStrip>

    <RPanel title="生效规则" kicker="ACTIVE RULESET" flush class="mb">
      <template #actions>
        <RInput v-model="keyword" placeholder="按 ID / MSG 过滤" mono :width="200" />
        <RSelect v-model="fSeverity" :options="severityOptions" placeholder="全部 SEVERITY" clearable :width="170" />
        <RSelect v-model="fPhase" :options="phaseOptions" placeholder="全部 PHASE" clearable :width="150" />
      </template>
      <RTable
        :columns="ruleCols"
        :rows="filteredRules"
        :loading="rulesLoading"
        :row-key="(r: WafRule) => r.id"
        :page-size="50"
        empty-text="无匹配规则"
      />
    </RPanel>

    <RPanel :title="`规则加载报告：${nodeId ?? ''}`" kicker="LOAD REPORT" flush>
      <REmpty v-if="report?.report == null" text="http-guard 未启用：该节点未返回规则加载报告。" />
      <template v-else>
        <div v-if="counts.skipped.length === 0" class="muted skip-none">没有跳过的规则。</div>
        <RTable
          v-else
          :columns="skipCols"
          :rows="counts.skipped"
          :loading="loading"
          :row-key="(r: WafSkippedRule) => r.line + ':' + r.reason"
        />
      </template>
    </RPanel>
  </div>
</template>

<style scoped>
.skip-none {
  padding: 10px 14px 0;
}
</style>
