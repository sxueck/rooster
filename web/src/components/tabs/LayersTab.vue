<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RPanel, useMessage } from '../../ui'
import { getLayers } from '../../api/client'
import type { Layers } from '../../api/types'
import DiffView from '../DiffView.vue'
import { errMsg } from '../../utils/format'
import { diffLines } from '../../utils/diff'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()
const layers = ref<Layers | null>(null)

const SECTIONS: Array<{ key: keyof Layers; title: string; color: string }> = [
  { key: 'managed', title: '托管层（模板 / Hub 下发）', color: 'var(--info)' },
  { key: 'local', title: '本地层（节点手动修改）', color: 'var(--ok)' },
  { key: 'effective', title: '生效层（合并结果）', color: 'var(--warn)' },
]

function sectionText(sec: Record<string, string> | undefined): string {
  return Object.entries(sec ?? {})
    .map(([k, v]) => `# ==== ${k} ====\n${v}`)
    .join('\n\n')
}

const localAll = computed(() => sectionText(layers.value?.local))
const effAll = computed(() => sectionText(layers.value?.effective))
const diffViewLines = computed(() => diffLines(localAll.value, effAll.value))

onMounted(async () => {
  try {
    layers.value = await getLayers(props.nodeId)
  } catch (e) {
    message.error(errMsg(e))
  }
})
</script>

<template>
  <div>
    <div class="cols-3">
      <RPanel v-for="s in SECTIONS" :key="s.key" :title="s.title">
        <template #actions>
          <span class="layer-dot" :style="{ background: s.color }" />
        </template>
        <div v-for="(v, k) in layers?.[s.key] ?? {}" :key="k" class="layer-entry">
          <div class="muted mono">{{ k }}</div>
          <pre class="pre-block layer-yaml">{{ v }}</pre>
        </div>
        <div v-if="Object.keys(layers?.[s.key] ?? {}).length === 0" class="muted">（空）</div>
      </RPanel>
    </div>

    <RPanel kicker="DIFF · LOCAL → EFFECTIVE" title="本地层 → 生效层 差异" style="margin-top: 16px">
      <DiffView :lines="diffViewLines" />
    </RPanel>
  </div>
</template>

<style scoped>
.layer-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.layer-entry {
  margin-bottom: 10px;
}
.layer-entry:last-child {
  margin-bottom: 0;
}
.layer-yaml {
  max-height: 260px;
}
</style>
