<script setup lang="ts">
/** Modal with hairline ops chrome. v-model:show, slots: default + footer. */
import { watch, onUnmounted } from 'vue'

const props = withDefaults(
  defineProps<{
    show: boolean
    title?: string
    kicker?: string
    width?: number
    maskClosable?: boolean
  }>(),
  { width: 560, maskClosable: true },
)
const emit = defineEmits<{ (e: 'update:show', v: boolean): void }>()

function close() {
  emit('update:show', false)
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && props.show) close()
}
watch(
  () => props.show,
  (v) => {
    if (v) document.addEventListener('keydown', onKey)
    else document.removeEventListener('keydown', onKey)
  },
)
onUnmounted(() => document.removeEventListener('keydown', onKey))
</script>

<template>
  <Teleport to="body">
    <div v-if="show" class="rmo-mask" @mousedown="maskClosable && close()">
      <div class="rmo" :style="{ width: width + 'px' }" @mousedown.stop>
        <header class="rmo-head">
          <span v-if="kicker" class="micro">{{ kicker }}</span>
          <span v-else-if="title" class="micro">DETAIL</span>
          <h3 v-if="title" class="rmo-title">{{ title }}</h3>
          <button class="rmo-x" aria-label="close" @click="close">×</button>
        </header>
        <div class="rmo-body"><slot /></div>
        <footer v-if="$slots.footer" class="rmo-foot"><slot name="footer" /></footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.rmo-mask {
  position: fixed;
  inset: 0;
  z-index: 3800;
  background: rgba(20, 24, 28, 0.42);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 8vh 16px 16px;
  overflow: auto;
}
.rmo {
  max-width: calc(100vw - 32px);
  background: var(--panel);
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
}
.rmo-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-head);
}
.rmo-title {
  margin: 0;
  font-size: 13.5px;
  font-weight: 600;
}
.rmo-x {
  margin-left: auto;
  border: none;
  background: none;
  font-size: 18px;
  line-height: 1;
  color: var(--faint);
  cursor: pointer;
  padding: 2px 6px;
}
.rmo-x:hover { color: var(--ink); }
.rmo-body { padding: 16px; }
.rmo-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 10px 16px;
  border-top: 1px solid var(--line);
}
</style>
