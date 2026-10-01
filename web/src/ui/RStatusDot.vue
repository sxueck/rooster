<script setup lang="ts">
/** Status dot + text, the reference-image pattern: ● node-01 online */
withDefaults(
  defineProps<{
    tone?: 'ok' | 'danger' | 'warn' | 'info' | 'muted'
    pulse?: boolean
  }>(),
  { tone: 'muted', pulse: false },
)
</script>

<template>
  <span class="sd" :class="`sd-${tone}`">
    <span class="sd-dot" :class="{ 'sd-pulse': pulse }" />
    <slot />
  </span>
</template>

<style scoped>
.sd {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 12.5px;
  color: var(--ink);
  white-space: nowrap;
}
.sd-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--faint);
  flex: none;
}
.sd-pulse { animation: sd-pulse 1.6s ease-in-out infinite; }
@keyframes sd-pulse { 50% { opacity: 0.35; } }
.sd-ok .sd-dot { background: var(--ok); }
.sd-ok { color: var(--ok); }
.sd-danger .sd-dot { background: var(--danger); }
.sd-danger { color: var(--danger); }
.sd-warn .sd-dot { background: var(--warn); }
.sd-warn { color: var(--warn); }
.sd-info .sd-dot { background: var(--info); }
.sd-info { color: var(--info); }
.sd-muted .sd-dot { background: var(--faint); }
.sd-muted { color: var(--faint); }
</style>
