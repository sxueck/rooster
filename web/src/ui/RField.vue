<script setup lang="ts">
/** Form field: micro label above (or beside, `inline`) the control. */
withDefaults(
  defineProps<{
    label: string
    inline?: boolean
    labelWidth?: number
    hint?: string
  }>(),
  { inline: false, labelWidth: 110 },
)
</script>

<template>
  <div class="rfd" :class="inline ? 'rfd-inline' : ''" :style="inline ? { '--lw': labelWidth + 'px' } : undefined">
    <span class="rfd-label micro">{{ label }}</span>
    <div class="rfd-ctrl">
      <slot />
      <span v-if="hint" class="rfd-hint">{{ hint }}</span>
    </div>
  </div>
</template>

<style scoped>
.rfd {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}
.rfd-label { line-height: 1.4; }
.rfd-inline {
  flex-direction: row;
  align-items: center;
  gap: 8px;
}
.rfd-inline .rfd-label {
  width: var(--lw);
  flex: none;
  text-align: right;
}
.rfd-ctrl { min-width: 0; }
.rfd-hint {
  font-size: 11.5px;
  color: var(--faint);
  margin-left: 8px;
}
</style>
