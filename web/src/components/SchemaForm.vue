<script setup lang="ts">
import { computed } from 'vue'
import { REmpty, RInput, RNumberInput, RSelect, RSwitch } from '../ui'

/**
 * Simple form generated from a plugin manifest's JSON config_schema.
 * Supports string / enum / number / boolean / string-array properties.
 */
interface PropSchema {
  type?: string
  title?: string
  description?: string
  enum?: string[]
  default?: unknown
  items?: { type?: string }
}

const props = defineProps<{
  /** null = manifest 缺失，渲染空表单 */
  schema: Record<string, unknown> | null
  modelValue: Record<string, unknown>
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: Record<string, unknown>): void }>()

const entries = computed<Array<[string, PropSchema]>>(() => {
  const p = (props.schema?.properties ?? {}) as Record<string, PropSchema>
  return Object.entries(p)
})

function val(key: string, s: PropSchema): unknown {
  const v = props.modelValue[key]
  if (v !== undefined) return v
  return s.default ?? (s.type === 'boolean' ? false : s.type === 'array' ? [] : '')
}

function set(key: string, v: unknown) {
  emit('update:modelValue', { ...props.modelValue, [key]: v })
}

function arrText(v: unknown): string {
  return Array.isArray(v) ? v.map(String).join(', ') : String(v ?? '')
}
function arrParse(s: string): string[] {
  return s
    .split(/[,，]/)
    .map((x) => x.trim())
    .filter((x) => x !== '')
}
</script>

<template>
  <div>
    <div v-for="[key, s] in entries" :key="key" class="sf-row">
      <div class="sf-label">
        <div class="micro">{{ s.title ?? key }}</div>
        <div class="sf-desc">
          {{ s.description ?? key }}
          <code v-if="s.type" class="mono">({{ s.type }})</code>
        </div>
      </div>
      <div class="sf-ctrl">
        <RSelect
          v-if="s.type === 'string' && s.enum"
          :model-value="String(val(key, s))"
          :options="s.enum.map((o) => ({ label: o, value: o }))"
          @update:model-value="(v) => set(key, v)"
        />
        <RSwitch
          v-else-if="s.type === 'boolean'"
          :model-value="Boolean(val(key, s))"
          @update:model-value="(v: boolean) => set(key, v)"
        />
        <RNumberInput
          v-else-if="s.type === 'number' || s.type === 'integer'"
          :model-value="Number(val(key, s))"
          :width="'100%'"
          @update:model-value="(v: number | null) => set(key, v ?? 0)"
        />
        <RInput
          v-else-if="s.type === 'array'"
          :model-value="arrText(val(key, s))"
          placeholder="逗号分隔多个值"
          @update:model-value="(v: string) => set(key, arrParse(v))"
        />
        <RInput
          v-else
          :model-value="String(val(key, s))"
          @update:model-value="(v: string) => set(key, v)"
        />
      </div>
    </div>
    <REmpty v-if="entries.length === 0" text="该插件未声明 config_schema" />
  </div>
</template>

<style scoped>
.sf-row {
  display: grid;
  grid-template-columns: 180px 1fr;
  gap: 12px;
  align-items: start;
  margin-bottom: 12px;
}
.sf-desc {
  font-size: 12px;
  color: var(--faint);
  margin-top: 2px;
}
</style>
