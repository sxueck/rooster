<script setup lang="ts">
/** Sparse-state line: NO DATA · 暂无. */
withDefaults(defineProps<{ text?: string }>(), { text: 'NO DATA · 暂无数据' })
</script>

<template>
  <div class="rem">{{ text }}</div>
</template>

<style scoped>
.rem {
  padding: 22px 0;
  text-align: center;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 0.08em;
  color: var(--faint);
}
</style>
