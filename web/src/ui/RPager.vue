<script setup lang="ts">
/**
 * 分页条：RTable 内部分页与长列表（如节点历史事件）共用同一套页码/区间文案。
 * page 从 1 开始；只有一页时整条隐藏。
 */
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    page: number
    /** 总页数，由调用方算：Math.max(1, ceil(total / pageSize)) */
    pageCount: number
    pageSize: number
    total: number
  }>(),
  { page: 1, pageCount: 1, pageSize: 0, total: 0 },
)
const emit = defineEmits<{ (e: 'update:page', page: number): void }>()

const rangeText = computed(() => {
  if (props.total === 0) return '0'
  const start = (props.page - 1) * props.pageSize + 1
  const end = Math.min(props.total, props.page * props.pageSize)
  return `${start}–${end} / ${props.total}`
})
</script>

<template>
  <div v-if="pageCount > 1" class="rp-pager">
    <button class="rp-pg" :disabled="page <= 1" @click="emit('update:page', page - 1)">‹</button>
    <span class="rp-pg-text num">{{ rangeText }}</span>
    <button class="rp-pg" :disabled="page >= pageCount" @click="emit('update:page', page + 1)">›</button>
  </div>
</template>

<style scoped>
.rp-pager {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding: 7px 10px;
  border-top: 1px solid var(--line);
}
.rp-pg {
  width: 22px;
  height: 22px;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  background: var(--panel);
  cursor: pointer;
  line-height: 1;
  color: var(--sub);
}
.rp-pg:hover:not(:disabled) { background: var(--tint); }
.rp-pg:disabled { opacity: 0.4; cursor: not-allowed; }
.rp-pg-text {
  font-size: 11.5px;
  color: var(--faint);
}
</style>
