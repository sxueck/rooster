<script setup lang="ts">
/**
 * Ops input. v-model (modelValue). type: text | password | textarea.
 * For textarea, `rows` fixes height; `autoRows: [min, max]` grows with content.
 * `mono` renders monospace text (IDs, YAML, commands).
 */
import { computed, nextTick, ref, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    modelValue: string
    type?: 'text' | 'password' | 'textarea'
    placeholder?: string
    disabled?: boolean
    readonly?: boolean
    mono?: boolean
    rows?: number
    autoRows?: [number, number]
    width?: number | string
  }>(),
  { type: 'text', mono: false, rows: 0, disabled: false, readonly: false },
)
const emit = defineEmits<{
  (e: 'update:modelValue', v: string): void
  (e: 'keyup', ev: KeyboardEvent): void
}>()

const showPwd = ref(false)
const ta = ref<HTMLTextAreaElement | null>(null)

function onInput(ev: Event) {
  emit('update:modelValue', (ev.target as HTMLInputElement).value)
}
function onKeyup(ev: KeyboardEvent) {
  emit('keyup', ev)
}

const styleWidth = computed(() =>
  props.width === undefined ? undefined : typeof props.width === 'number' ? props.width + 'px' : props.width,
)

function resize() {
  const el = ta.value
  if (!el || !props.autoRows) return
  const [min, max] = props.autoRows
  const cs = getComputedStyle(el)
  const lh = parseFloat(cs.lineHeight) || 18
  const pad = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom)
  const minH = lh * min + pad
  const maxH = lh * max + pad
  el.style.height = 'auto'
  el.style.height = Math.min(maxH, Math.max(minH, el.scrollHeight)) + 'px'
}
watch(() => props.modelValue, () => nextTick(resize))
watch(() => props.autoRows, () => nextTick(resize), { deep: true })
</script>

<template>
  <span class="ri" :style="{ width: type === 'textarea' ? (styleWidth ?? '100%') : styleWidth }">
    <textarea
      v-if="type === 'textarea'"
      ref="ta"
      class="ri-field ri-textarea"
      :class="{ 'ri-mono': mono }"
      :value="modelValue"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      :rows="rows || 4"
      :style="autoRows ? { height: 'auto' } : undefined"
      @input="onInput"
      @keyup="onKeyup"
    />
    <template v-else>
      <input
        class="ri-field"
        :class="{ 'ri-mono': mono }"
        :type="type === 'password' && !showPwd ? 'password' : 'text'"
        :value="modelValue"
        :placeholder="placeholder"
        :disabled="disabled"
        :readonly="readonly"
        @input="onInput"
        @keyup="onKeyup"
      />
      <button
        v-if="type === 'password'"
        class="ri-eye"
        type="button"
        :title="showPwd ? '隐藏' : '显示'"
        @click="showPwd = !showPwd"
      >
        {{ showPwd ? '●●' : '○○' }}
      </button>
    </template>
  </span>
</template>

<style scoped>
.ri {
  display: inline-block;
  position: relative;
  vertical-align: middle;
}
.ri-field {
  width: 100%;
  font-family: var(--sans);
  font-size: 12.5px;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  padding: 4px 9px;
  line-height: 1.5;
  outline: none;
  transition: border-color 0.12s;
}
.ri-field:focus { border-color: var(--ink); }
.ri-field:disabled {
  background: var(--tint);
  color: var(--faint);
  cursor: not-allowed;
}
.ri-field::placeholder { color: #b3bac2; }
.ri-mono {
  font-family: var(--mono);
  font-size: 12px;
}
.ri-textarea {
  resize: vertical;
  display: block;
}
.ri-eye {
  position: absolute;
  right: 4px;
  top: 50%;
  transform: translateY(-50%);
  border: none;
  background: none;
  color: var(--faint);
  font-size: 9px;
  cursor: pointer;
  letter-spacing: -1px;
}
.ri-eye:hover { color: var(--ink); }
</style>
