<script setup lang="ts">
/** Small status chip: hairline box, monospace, optional leading dot. */
withDefaults(
  defineProps<{
    tone?: 'muted' | 'ok' | 'warn' | 'danger' | 'info'
    dot?: boolean
    pulse?: boolean
  }>(),
  { tone: 'muted', dot: false, pulse: false },
)
</script>

<template>
  <span class="rtg" :class="`rtg-${tone}`">
    <span v-if="dot" class="rtg-dot" :class="{ 'rtg-pulse': pulse }" />
    <slot />
  </span>
</template>

<style scoped>
.rtg {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 1px 7px;
  font-family: var(--mono);
  font-size: 11px;
  line-height: 16px;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  color: var(--sub);
  background: var(--panel);
  white-space: nowrap;
}
.rtg-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  flex: none;
}
.rtg-pulse { animation: rtg-pulse 1.6s ease-in-out infinite; }
@keyframes rtg-pulse { 50% { opacity: 0.35; } }
.rtg-ok { color: var(--ok); border-color: #bcd9c4; background: var(--ok-tint); }
.rtg-warn { color: var(--warn); border-color: #e2cf9e; background: var(--warn-tint); }
.rtg-danger { color: var(--danger); border-color: #e6bfc2; background: var(--danger-tint); }
.rtg-info { color: var(--info); border-color: #b7d0e9; background: var(--info-tint); }
.rtg-muted { color: var(--sub); }
</style>
