<script setup lang="ts">
/** Thin hairline progress bar. */
withDefaults(
  defineProps<{
    percentage: number
    tone?: 'ok' | 'danger' | 'info' | 'warn'
  }>(),
  { tone: 'ok' },
)
</script>

<template>
  <div class="rp-bar">
    <div class="rp-fill" :class="`rp-${tone}`" :style="{ width: Math.min(100, Math.max(0, percentage)) + '%' }" />
  </div>
</template>

<style scoped>
.rp-bar {
  height: 4px;
  background: var(--line);
  border-radius: 2px;
  overflow: hidden;
}
.rp-fill {
  height: 100%;
  border-radius: 2px;
  transition: width 0.25s ease;
}
.rp-ok { background: var(--ok); }
.rp-danger { background: var(--danger); }
.rp-info { background: var(--info); }
.rp-warn { background: var(--warn); }
</style>
