<script setup lang="ts">
/**
 * Line tabs with lazy-visit semantics (replaces naive NTabs + show:lazy).
 * Usage:
 *   <RTabs v-model="tab" :items="[{key:'overview',label:'概况'}, ...]">
 *     <template #default="{ seen }">
 *       <OverviewTab v-if="seen('overview')" v-show="tab === 'overview'" />
 *     </template>
 *   </RTabs>
 * `seen(key)` is true once the tab has been activated → mount on first visit,
 * keep mounted afterwards (v-show switches).
 * 面板组件必须是单根节点:Vue 会忽略 fragment 组件上的 v-show,面板切不走。
 */
import { ref, watch } from 'vue'

export interface RTabItem {
  key: string
  label: string
  badge?: string | number
}

const props = defineProps<{
  modelValue: string
  items: RTabItem[]
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: string): void }>()

const visited = ref<Set<string>>(new Set([props.modelValue]))
watch(
  () => props.modelValue,
  (k) => {
    visited.value = new Set(visited.value).add(k)
  },
)
function seen(key: string): boolean {
  return visited.value.has(key)
}
</script>

<template>
  <div>
    <div class="rtb-bar" role="tablist">
      <button
        v-for="it in items"
        :key="it.key"
        class="rtb"
        :class="{ 'rtb-on': modelValue === it.key }"
        role="tab"
        :aria-selected="modelValue === it.key"
        @click="emit('update:modelValue', it.key)"
      >
        {{ it.label }}<span v-if="it.badge !== undefined" class="rtb-badge num">{{ it.badge }}</span>
      </button>
    </div>
    <div class="rtb-body">
      <slot :seen="seen" />
    </div>
  </div>
</template>

<style scoped>
.rtb-bar {
  display: flex;
  gap: 2px;
  border-bottom: 1px solid var(--line-strong);
  overflow-x: auto;
}
.rtb {
  appearance: none;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  padding: 7px 13px;
  font-size: 12.5px;
  color: var(--sub);
  cursor: pointer;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.rtb:hover { color: var(--ink); }
.rtb-on {
  color: var(--ink);
  font-weight: 600;
  border-bottom-color: var(--ink);
}
.rtb-badge {
  font-size: 10.5px;
  color: var(--faint);
  background: var(--tint);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 0 4px;
}
.rtb-body { padding-top: 14px; }
</style>
