<script setup lang="ts">
/** Ops spinner: rotating hairline ring. Optional slot renders beside it. */
withDefaults(defineProps<{ label?: string }>(), {})
</script>

<template>
  <span class="rsp">
    <span class="rsp-ring" :aria-label="label ?? 'loading'" />
    <span v-if="$slots.default" class="rsp-text"><slot /></span>
  </span>
</template>

<style scoped>
.rsp {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.rsp-ring {
  width: 14px;
  height: 14px;
  border: 1.5px solid var(--line-strong);
  border-top-color: var(--ink);
  border-radius: 50%;
  animation: rsp-rot 0.8s linear infinite;
  flex: none;
}
.rsp-text { font-size: 12.5px; color: var(--sub); }
@keyframes rsp-rot { to { transform: rotate(360deg); } }
</style>
