<script setup lang="ts">
import { ref, watch } from 'vue'
import { RButton, RInput } from '../ui'

const props = defineProps<{ modelValue: Record<string, string> }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: Record<string, string>): void }>()

interface Row {
  k: string
  v: string
}
const rows = ref<Row[]>([])

function fromObj(obj: Record<string, string>): Row[] {
  return Object.entries(obj ?? {}).map(([k, v]) => ({ k, v }))
}
function toObj(rs: Row[]): Record<string, string> {
  const o: Record<string, string> = {}
  for (const r of rs) {
    const k = r.k.trim()
    if (k !== '') o[k] = r.v
  }
  return o
}

watch(
  () => props.modelValue,
  (v) => {
    if (JSON.stringify(v ?? {}) !== JSON.stringify(toObj(rows.value))) {
      rows.value = fromObj(v ?? {})
    }
  },
  { immediate: true },
)

function changed() {
  emit('update:modelValue', toObj(rows.value))
}
</script>

<template>
  <div>
    <div v-for="(r, i) in rows" :key="i" class="kv-row">
      <RInput v-model="r.k" placeholder="键" mono @update:model-value="changed" />
      <RInput v-model="r.v" placeholder="值" mono @update:model-value="changed" />
      <RButton
        variant="link"
        tone="danger"
        @click="() => { rows.splice(i, 1); changed() }"
      >
        删除
      </RButton>
    </div>
    <RButton dashed block size="sm" @click="() => { rows.push({ k: '', v: '' }); changed() }">
      + 添加键值对
    </RButton>
  </div>
</template>

<style scoped>
.kv-row {
  display: grid;
  grid-template-columns: 1fr 1fr auto;
  gap: 8px;
  margin-bottom: 8px;
  align-items: center;
}
</style>
