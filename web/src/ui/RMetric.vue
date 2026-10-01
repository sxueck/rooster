<script setup lang="ts">
/** Big monospace metric (reference-image pattern): micro label above, num below. */
withDefaults(
  defineProps<{
    /** English uppercase micro label, e.g. 'LAST SEEN' */
    label: string
    value: string | number | null | undefined
    /** small unit rendered after the number, e.g. 'secs' / 'nodes' */
    suffix?: string
    tone?: 'ink' | 'ok' | 'warn' | 'danger' | 'info' | 'muted'
  }>(),
  { suffix: '', tone: 'ink' },
)
</script>

<template>
  <div class="rm">
    <div class="micro rm-label">{{ label }}</div>
    <div class="rm-value num" :class="`rm-${tone}`">
      {{ value === null || value === undefined || value === '' ? '—' : value }}<span
        v-if="suffix && value !== null && value !== undefined && value !== ''"
        class="rm-suffix"
        >{{ suffix }}</span
      >
    </div>
    <div v-if="$slots.default" class="rm-note">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.rm { min-width: 0; }
.rm-label { margin-bottom: 3px; }
.rm-value {
  font-size: 21px;
  font-weight: 600;
  line-height: 1.25;
  color: var(--ink);
  word-break: break-all;
}
.rm-suffix {
  font-size: 11px;
  font-weight: 400;
  color: var(--faint);
  margin-left: 5px;
}
.rm-note {
  margin-top: 2px;
  font-size: 11.5px;
  color: var(--faint);
}
.rm-ok { color: var(--ok); }
.rm-warn { color: var(--warn); }
.rm-danger { color: var(--danger); }
.rm-info { color: var(--info); }
.rm-muted { color: var(--faint); }
</style>
