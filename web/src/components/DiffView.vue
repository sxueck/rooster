<script setup lang="ts">
import { computed } from 'vue'
import { REmpty } from '../ui'
import { diffLines, parseUnified } from '../utils/diff'
import type { DiffLine } from '../utils/diff'

const props = defineProps<{
  /** unified-diff text (e.g. from template preview) */
  diff?: string
  /** pre-computed lines */
  lines?: DiffLine[]
  /** or two files to diff (old → new) */
  oldFile?: string
  newFile?: string
}>()

const view = computed<DiffLine[]>(() => {
  if (props.lines) return props.lines
  if (props.diff !== undefined) return parseUnified(props.diff)
  if (props.oldFile !== undefined && props.newFile !== undefined) {
    return diffLines(props.oldFile, props.newFile)
  }
  return []
})

function prefix(t: DiffLine['type']): string {
  if (t === 'add') return '+'
  if (t === 'del') return '-'
  if (t === 'hunk') return '@'
  return ' '
}
</script>

<template>
  <div>
    <REmpty v-if="view.length === 0" text="NO DIFF · 无差异" />
    <pre v-else class="diff-view mono"><span
      v-for="(l, i) in view"
      :key="i"
      class="dl"
      :class="'dl-' + l.type"
    >{{ prefix(l.type) }}{{ l.text }}
</span></pre>
  </div>
</template>

<style scoped>
.diff-view {
  margin: 0;
  overflow: auto;
  max-height: 60vh;
  font-size: 12px;
  line-height: 1.55;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius);
}
.dl {
  display: block;
  padding: 0 10px;
  white-space: pre-wrap;
  word-break: break-all;
}
.dl-add {
  background: var(--ok-tint);
  color: var(--ok);
}
.dl-del {
  background: var(--danger-tint);
  color: var(--danger);
}
.dl-hunk {
  background: var(--info-tint);
  color: var(--info);
}
</style>
