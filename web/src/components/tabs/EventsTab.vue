<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RPanel, RTag, useMessage } from '../../ui'
import { useEventsStore } from '../../stores/events'
import { getNodeEvents } from '../../api/client'
import type { EventRecord } from '../../api/types'
import { errMsg, eventKindLabel, eventSummary, eventTagType, fmtTime } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()
const store = useEventsStore()

const history = ref<EventRecord[]>([])
const live = computed(() => store.feed.filter((f) => f.node_id === props.nodeId).slice(0, 60))

// naive tag type → ops RTag tone（一次性映射，其余逻辑不动）
const TONE_MAP: Record<string, 'ok' | 'danger' | 'warn' | 'info' | 'muted'> = {
  success: 'ok',
  error: 'danger',
  warning: 'warn',
  info: 'info',
  default: 'muted',
}

async function load() {
  try {
    history.value = (await getNodeEvents(props.nodeId, 100)).events
  } catch (e) {
    message.error(errMsg(e))
  }
}

function renderList(items: EventRecord[]) {
  return items.map((it) => ({
    key: it.ts + JSON.stringify(it.event),
    ts: fmtTime(it.ts),
    kind: it.event.kind,
    label: eventKindLabel(it.event.kind),
    tone: TONE_MAP[eventTagType(it.event.kind)] ?? 'muted',
    summary: eventSummary(it.event),
  }))
}

onMounted(load)
</script>

<template>
  <div class="cols-2">
    <RPanel kicker="LIVE · WEBSOCKET" title="实时事件（WebSocket）">
      <div v-if="live.length === 0" class="muted">暂无实时事件，等待推送…</div>
      <div v-for="it in renderList(live)" :key="it.key + '-live'" class="ev-item">
        <span class="ev-ts mono">{{ it.ts }}</span>
        <RTag :tone="it.tone">{{ it.label }}</RTag>
        <span class="ev-text">{{ it.summary }}</span>
      </div>
    </RPanel>
    <RPanel kicker="HISTORY · GET /events" title="历史事件（GET /events）">
      <div v-if="history.length === 0" class="muted">无历史事件</div>
      <div v-for="it in renderList(history)" :key="it.key + '-his'" class="ev-item">
        <span class="ev-ts mono">{{ it.ts }}</span>
        <RTag :tone="it.tone">{{ it.label }}</RTag>
        <span class="ev-text">{{ it.summary }}</span>
      </div>
    </RPanel>
  </div>
</template>

<style scoped>
.ev-item {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 5px 0;
  border-bottom: 1px dashed var(--line);
  font-size: 12.5px;
}
.ev-ts {
  color: var(--faint);
  flex: none;
}
.ev-text {
  flex: 1;
}
</style>
