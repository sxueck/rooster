<script setup lang="ts">
/** v-model boolean checkbox with inline label slot. */
withDefaults(
  defineProps<{ modelValue: boolean; disabled?: boolean }>(),
  { disabled: false },
)
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()
function onChange(ev: Event) {
  emit('update:modelValue', (ev.target as HTMLInputElement).checked)
}
</script>

<template>
  <label class="rck" :class="{ 'rck-off': disabled }">
    <input type="checkbox" :checked="modelValue" :disabled="disabled" @change="onChange" />
    <span><slot /></span>
  </label>
</template>

<style scoped>
.rck {
  display: inline-flex;
  align-items: baseline;
  gap: 7px;
  font-size: 12.5px;
  color: var(--ink);
  cursor: pointer;
  user-select: none;
}
.rck input { accent-color: var(--ink); }
.rck-off { opacity: 0.5; cursor: not-allowed; }
</style>
