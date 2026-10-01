<script setup lang="ts">
/**
 * Hairline data table replacing naive NDataTable.
 * - columns: RColumn<T>[] (render may return VNode | string | number)
 * - selectable + v-model:checked (row keys)
 * - sortable columns (click header: asc → desc → off)
 * - optional internal pagination via pageSize
 * - maxHeight turns on scroll + sticky header
 * Rows stay `any` here: vue-tsc 2.2 mis-handles generic SFCs; pages keep
 * typing at their own `RColumn<Row>[]` declarations.
 */
import { computed, ref, watch, type VNode } from 'vue'
import type { RColumn } from './types'
import RSpinner from './RSpinner.vue'

const props = withDefaults(
  defineProps<{
    columns: RColumn[]
    rows: Record<string, unknown>[]
    rowKey: (row: any) => string | number
    loading?: boolean
    selectable?: boolean
    checked?: string[]
    pageSize?: number
    maxHeight?: string
    emptyText?: string
  }>(),
  { loading: false, selectable: false, pageSize: 0, emptyText: 'NO DATA · 暂无数据' },
)
const emit = defineEmits<{ (e: 'update:checked', keys: string[]): void }>()

const checkedSet = computed(() => new Set(props.checked ?? []))

// ---- sorting ----
const sort = ref<{ key: string; dir: 1 | -1 } | null>(null)
function toggleSort(col: RColumn) {
  if (!col.sortable) return
  if (!sort.value || sort.value.key !== col.key) sort.value = { key: col.key, dir: 1 }
  else if (sort.value.dir === 1) sort.value = { key: col.key, dir: -1 }
  else sort.value = null
}
const sorted = computed(() => {
  const s = sort.value
  if (!s) return props.rows
  const col = props.columns.find((c) => c.key === s.key)
  if (!col) return props.rows
  return [...props.rows].sort((a, b) => {
    const va = a[s.key]
    const vb = b[s.key]
    if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * s.dir
    return String(va ?? '').localeCompare(String(vb ?? '')) * s.dir
  })
})

// ---- pagination ----
const page = ref(1)
const pageCount = computed(() =>
  props.pageSize > 0 ? Math.max(1, Math.ceil(sorted.value.length / props.pageSize)) : 1,
)
watch(
  () => sorted.value.length,
  () => {
    if (page.value > pageCount.value) page.value = 1
  },
)
const visible = computed(() => {
  if (props.pageSize <= 0) return sorted.value
  const start = (page.value - 1) * props.pageSize
  return sorted.value.slice(start, start + props.pageSize)
})
const rangeText = computed(() => {
  const n = sorted.value.length
  if (props.pageSize <= 0 || n === 0) return `${n}`
  const start = (page.value - 1) * props.pageSize + 1
  const end = Math.min(n, page.value * props.pageSize)
  return `${start}–${end} / ${n}`
})

// ---- selection ----
const allOnPage = computed(() => visible.value.every((r) => checkedSet.value.has(String(props.rowKey(r)))))
function toggleAll() {
  const keys = visible.value.map((r) => String(props.rowKey(r)))
  const cur = new Set(props.checked ?? [])
  if (allOnPage.value) keys.forEach((k) => cur.delete(k))
  else keys.forEach((k) => cur.add(k))
  emit('update:checked', [...cur])
}
function toggleRow(row: any) {
  const key = String(props.rowKey(row))
  const cur = new Set(props.checked ?? [])
  if (cur.has(key)) cur.delete(key)
  else cur.add(key)
  emit('update:checked', [...cur])
}

// ---- cell rendering ----
function cellValue(row: any, col: RColumn, index: number): VNode | string {
  const raw = col.render
    ? col.render(row, index)
    : ((row as Record<string, unknown>)[col.key] as VNode | string | number | null)
  if (raw === null || raw === undefined) return ''
  if (typeof raw === 'object') return raw as VNode
  return String(raw)
}
const Cell = (cellProps: { v: VNode | string }) =>
  typeof cellProps.v === 'string' ? cellProps.v : (cellProps.v as VNode)
</script>

<template>
  <div class="rt-wrap" :class="{ 'rt-scroll': !!maxHeight }" :style="maxHeight ? { maxHeight } : undefined">
    <table class="rt">
      <thead>
        <tr>
          <th v-if="selectable" class="rt-check">
            <input type="checkbox" :checked="visible.length > 0 && allOnPage" @change="toggleAll" />
          </th>
          <th
            v-for="col in columns"
            :key="col.key"
            :class="[col.sortable ? 'rt-sortable' : '', sort?.key === col.key ? 'rt-sorted' : '']"
            :style="{
              width: col.width ? typeof col.width === 'number' ? col.width + 'px' : col.width : undefined,
              textAlign: col.align ?? 'left',
            }"
            @click="toggleSort(col)"
          >
            {{ col.title }}<span v-if="col.sortable" class="rt-arrow">{{
              sort?.key === col.key ? (sort.dir === 1 ? '▲' : '▼') : ''
            }}</span>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(row, i) in visible" :key="rowKey(row)">
          <td v-if="selectable" class="rt-check">
            <input
              type="checkbox"
              :checked="checkedSet.has(String(rowKey(row)))"
              @change="toggleRow(row)"
            />
          </td>
          <td
            v-for="col in columns"
            :key="col.key"
            :class="col.mono ? 'rt-mono' : ''"
            :style="{ textAlign: col.align ?? 'left' }"
          >
            <Cell :v="cellValue(row, col, (page - 1) * pageSize + i)" />
          </td>
        </tr>
        <tr v-if="visible.length === 0 && !loading">
          <td :colspan="columns.length + (selectable ? 1 : 0)" class="rt-empty">
            {{ emptyText }}
          </td>
        </tr>
      </tbody>
    </table>
    <div v-if="loading" class="rt-loading"><RSpinner /></div>
    <div v-if="pageSize > 0 && sorted.length > pageSize" class="rt-pager">
      <button class="rt-pg" :disabled="page <= 1" @click="page -= 1">‹</button>
      <span class="rt-pg-text num">{{ rangeText }}</span>
      <button class="rt-pg" :disabled="page >= pageCount" @click="page += 1">›</button>
    </div>
  </div>
</template>

<style scoped>
.rt-wrap {
  position: relative;
  background: var(--panel);
}
.rt-scroll { overflow: auto; }
.rt {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
.rt thead th {
  position: sticky;
  top: 0;
  z-index: 1;
  background: var(--panel);
  font-family: var(--mono);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--faint);
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--line-strong);
  white-space: nowrap;
}
.rt-sortable { cursor: pointer; user-select: none; }
.rt-sortable:hover { color: var(--ink); }
.rt-sorted { color: var(--ink); }
.rt-arrow { font-size: 8px; margin-left: 3px; }
.rt tbody td {
  padding: 6px 10px;
  border-bottom: 1px solid var(--line);
  vertical-align: middle;
  color: var(--ink);
}
.rt tbody tr:last-child td { border-bottom: none; }
.rt tbody tr:hover td { background: var(--tint); }
.rt-mono {
  font-family: var(--mono);
  font-size: 12px;
}
.rt-check { width: 30px; text-align: center !important; }
.rt-check input { accent-color: var(--ink); }
.rt-empty {
  text-align: center !important;
  color: var(--faint);
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 0.06em;
  padding: 26px 0 !important;
}
.rt-loading {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 40px;
  background: rgba(255, 255, 255, 0.6);
}
.rt-pager {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding: 7px 10px;
  border-top: 1px solid var(--line);
}
.rt-pg {
  width: 22px;
  height: 22px;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  background: var(--panel);
  cursor: pointer;
  line-height: 1;
  color: var(--sub);
}
.rt-pg:hover:not(:disabled) { background: var(--tint); }
.rt-pg:disabled { opacity: 0.4; cursor: not-allowed; }
.rt-pg-text {
  font-size: 11.5px;
  color: var(--faint);
}
</style>
