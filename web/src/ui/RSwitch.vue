<script setup lang="ts">
/** v-model boolean switch, square ops style. */
const props = withDefaults(
  defineProps<{ modelValue: boolean; disabled?: boolean }>(),
  { disabled: false },
)
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()
function toggle() {
  if (!props.disabled) emit('update:modelValue', !props.modelValue)
}
</script>

<template>
  <button
    class="rsw"
    :class="{ 'rsw-on': modelValue, 'rsw-off': disabled }"
    role="switch"
    :aria-checked="modelValue"
    @click="toggle"
  >
    <span class="rsw-knob" />
  </button>
</template>

<style scoped>
.rsw {
  width: 34px;
  height: 18px;
  border-radius: 9px;
  border: 1px solid var(--line-strong);
  background: var(--tint);
  position: relative;
  cursor: pointer;
  padding: 0;
  transition: background 0.15s, border-color 0.15s;
  vertical-align: middle;
}
.rsw-on {
  background: var(--ok);
  border-color: var(--ok);
}
.rsw-knob {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #fff;
  transition: left 0.15s;
}
.rsw-on .rsw-knob { left: 18px; }
.rsw-off { opacity: 0.5; cursor: not-allowed; }
</style>
