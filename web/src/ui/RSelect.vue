<script setup lang="ts">
/** Styled native select — zero dropdown bugs, ops look. v-model: string | null. */
import type { SelectOption } from './types'

withDefaults(
  defineProps<{
    modelValue: string | number | null
    options: SelectOption[]
    placeholder?: string
    clearable?: boolean
    disabled?: boolean
    width?: number | string
    size?: 'sm' | 'md'
  }>(),
  { placeholder: '选择…', clearable: false, disabled: false, size: 'md' },
)
const emit = defineEmits<{ (e: 'update:modelValue', v: string | null): void }>()

function onChange(ev: Event) {
  const v = (ev.target as HTMLSelectElement).value
  emit('update:modelValue', v === '' ? null : v)
}
</script>

<template>
  <span class="rsel" :class="size === 'sm' ? 'rsel-sm' : ''" :style="typeof width === 'number' ? { width: width + 'px' } : width ? { width } : undefined">
    <select :value="modelValue ?? ''" :disabled="disabled" @change="onChange">
      <option v-if="clearable || modelValue === null" value="">{{ placeholder }}</option>
      <option v-for="o in options" :key="String(o.value)" :value="String(o.value)">{{ o.label }}</option>
    </select>
    <span class="rsel-caret">▾</span>
  </span>
</template>

<style scoped>
.rsel {
  display: inline-block;
  position: relative;
  vertical-align: middle;
}
.rsel select {
  appearance: none;
  width: 100%;
  font-family: var(--sans);
  font-size: 12.5px;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  padding: 4px 26px 4px 9px;
  outline: none;
  cursor: pointer;
}
.rsel select:focus { border-color: var(--ink); }
.rsel select:disabled { background: var(--tint); color: var(--faint); cursor: not-allowed; }
.rsel-caret {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--faint);
  font-size: 10px;
  pointer-events: none;
}
.rsel-sm select { height: 24px; padding-top: 1px; padding-bottom: 1px; font-size: 12px; }
</style>
