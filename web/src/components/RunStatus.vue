<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref } from 'vue'
import { RProgress, RSpinner, RTable, RTag, type RColumn } from '../ui'
import { getRollout } from '../api/client'
import type { RolloutRun, RolloutResult } from '../api/types'

const props = defineProps<{ runId: string }>()
const run = ref<RolloutRun | null>(null)
let timer = 0

function statusLabel(s: string): string {
  switch (s) {
    case 'running':
      return '进行中'
    case 'completed':
      return '已完成'
    case 'pending':
      return '待执行'
    case 'applied':
      return '已应用'
    case 'failed':
      return '失败'
    case 'skipped':
      return '跳过'
    case 'done':
      return '已结束'
    case 'upgraded':
      return '升级成功'
    case 'version-unchanged':
      return '版本未变化'
    case 'unresponsive':
      return '节点未响应'
    case 'offline':
      return '节点离线'
    case 'sent':
      return '已下发'
    default:
      return s
  }
}

const cols: RColumn<RolloutResult>[] = [
  { title: 'NODE', key: 'node_id', width: 180, mono: true },
  {
    title: 'STATUS',
    key: 'status',
    width: 100,
    render: (r) =>
      h(
        RTag,
        {
          tone:
            r.status === 'applied' || r.status === 'upgraded'
              ? 'ok'
              : r.status === 'failed' || r.status === 'unresponsive'
                ? 'danger'
                : r.status === 'skipped' || r.status === 'version-unchanged' || r.status === 'offline'
                  ? 'warn'
                  : 'muted',
        },
        { default: () => statusLabel(r.status) },
      ),
  },
  { title: 'ERROR', key: 'error', render: (r) => (r.error ? r.error : '-') },
]

async function poll() {
  try {
    run.value = await getRollout(props.runId)
  } catch {
    /* 拉取失败时保留上次结果，下一轮重试 */
  }
  if (run.value && run.value.status === 'running') {
    timer = window.setTimeout(poll, 1500)
  }
}

const pct = computed(() => {
  const r = run.value
  if (!r || r.results.length === 0) return 0
  const done = r.results.filter((x) => x.status !== 'pending').length
  return Math.round((done / r.results.length) * 100)
})

onMounted(poll)
onUnmounted(() => window.clearTimeout(timer))
</script>

<template>
  <RSpinner v-if="!run" />
  <div v-else>
    <RProgress
      :percentage="pct"
      :tone="run.status === 'failed' ? 'danger' : 'ok'"
      class="run-progress"
    />
    <div class="row meta">
      <span class="micro">RUN</span>
      <code class="mono">{{ run.id }}</code>
      <template v-if="run.template_id">
        <span class="micro">TEMPLATE</span>
        <span class="num">{{ run.template_id }}</span>
      </template>
      <template v-else-if="run.version">
        <span class="micro">VERSION</span>
        <span class="num">{{ run.version }}</span>
      </template>
      <span class="micro">KIND</span>
      <span>{{ run.kind === 'template' ? '模板下发' : '版本升级' }}</span>
      <span class="micro">STATUS</span>
      <span>{{ statusLabel(run.status) }}</span>
    </div>
    <RTable
      :columns="cols"
      :rows="run.results"
      :row-key="(r: RolloutResult) => r.node_id"
      empty-text="NO RESULTS · 暂无结果"
    />
  </div>
</template>

<style scoped>
.run-progress {
  margin-bottom: 10px;
}
.meta {
  font-size: 12px;
  color: var(--faint);
  margin: 0 0 10px;
}
</style>
