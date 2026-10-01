<script setup lang="ts">
import { computed } from 'vue'
import type { TrendPoint } from '../api/types'
import { toDate } from '../utils/format'

/** wire format is epoch seconds; render as local HH:mm */
function hourLabel(ts: TrendPoint['hour']): string {
  if (typeof ts !== 'number') return String(ts)
  const d = toDate(ts)
  return d ? d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false }) : String(ts)
}

const props = defineProps<{ data: TrendPoint[] }>()
const W = 760
const H = 220
const PAD_L = 40
const PAD_B = 26
const PAD_T = 12

const max = computed(() => Math.max(1, ...props.data.map((d) => d.count)))
const bars = computed(() => {
  const n = props.data.length || 1
  const iw = (W - PAD_L - 4) / n
  return props.data.map((d, i) => {
    const h = Math.max(1, Math.round(((H - PAD_B - PAD_T) * d.count) / max.value))
    return {
      x: +(PAD_L + i * iw + 2).toFixed(1),
      y: H - PAD_B - h,
      w: +Math.max(4, iw - 5).toFixed(1),
      h,
      d,
    }
  })
})
const grid = computed(() =>
  [0.5, 1].map((f) => ({
    y: +(H - PAD_B - (H - PAD_B - PAD_T) * f).toFixed(1),
    v: Math.round(max.value * f),
  })),
)
const xlabels = computed(() =>
  props.data
    .map((d, i) => ({ d, i }))
    .filter(({ i }) => i % 4 === 1)
    .map(({ d, i }) => {
      const n = props.data.length || 1
      const iw = (W - PAD_L - 4) / n
      return { x: +(PAD_L + i * iw + iw / 2).toFixed(1), text: hourLabel(d.hour) }
    }),
)
</script>

<template>
  <svg :viewBox="`0 0 ${W} ${H}`" class="trend">
    <line
      v-for="(g, i) in grid"
      :key="'g' + i"
      :x1="PAD_L"
      :x2="W - 4"
      :y1="g.y"
      :y2="g.y"
      style="stroke: var(--line)"
    />
    <text
      v-for="(g, i) in grid"
      :key="'gt' + i"
      :x="PAD_L - 6"
      :y="g.y + 4"
      text-anchor="end"
      class="tick"
    >
      {{ g.v }}
    </text>
    <rect
      v-for="(b, i) in bars"
      :key="'b' + i"
      :x="b.x"
      :y="b.y"
      :width="b.w"
      :height="b.h"
      style="fill: var(--ok)"
      opacity="0.85"
    >
      <title>{{ hourLabel(b.d.hour) }} — {{ b.d.count }} 次</title>
    </rect>
    <text v-for="(l, i) in xlabels" :key="'x' + i" :x="l.x" :y="H - 8" text-anchor="middle" class="tick">
      {{ l.text }}
    </text>
  </svg>
</template>

<style scoped>
.trend {
  width: 100%;
  display: block;
}
.tick {
  fill: var(--faint);
  font-size: 10px;
}
</style>
