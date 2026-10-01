<script setup lang="ts">
/** Number input with clamping. v-model (number | null). */
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    modelValue: number | null
    min?: number
    max?: number
    placeholder?: string
    disabled?: boolean
    width?: number | string
    size?: 'sm' | 'md'
  }>(),
  { min: -Infinity, max: Infinity, disabled: false, size: 'md' },
)
const emit = defineEmits<{ (e: 'update:modelValue', v: number | null): void }>()

const styleWidth = computed(() =>
  props.width === undefined ? undefined : typeof props.width === 'number' ? props.width + 'px' : props.width,
)

function onInput(ev: Event) {
  const raw = (ev.target as HTMLInputElement).value
  if (raw === '') {
    emit('update:modelValue', null)
    return
  }
  const n = Number(raw)
  if (!Number.isFinite(n)) return
  emit('update:modelValue', Math.min(props.max, Math.max(props.min, n)))
}
</script>

<template>
  <input
    class="rn"
    :class="size === 'sm' ? 'rn-sm' : ''"
    type="number"
    :value="modelValue ?? ''"
    :min="min"
    :max="max"
    :placeholder="placeholder"
    :disabled="disabled"
    :style="styleWidth ? { width: styleWidth } : undefined"
    @input="onInput"
  />
</template>

<style scoped>
.rn {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  padding: 4px 8px;
  width: 110px;
  outline: none;
}
.rn:focus { border-color: var(--ink); }
.rn:disabled { background: var(--tint); color: var(--faint); }
.rn-sm { height: 24px; padding: 1px 6px; }
.rn::-webkit-outer-spin-button,
.rn::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
.rn[type='number'] { -moz-appearance: textfield; appearance: textfield; }
</style>
