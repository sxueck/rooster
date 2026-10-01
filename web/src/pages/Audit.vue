<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import { RButton, RPageHeader, RPanel, RTable, RTag, type RColumn } from '../ui'
import { getAudit } from '../api/client'
import type { AuditEntry } from '../api/types'
import { errMsg, fmtTime } from '../utils/format'

const entries = ref<AuditEntry[]>([])
const limit = ref(20)
const offset = ref(0)
const loading = ref(false)

const cols: RColumn[] = [
  { title: 'TS', key: 'ts', width: 175, render: (r) => fmtTime(r.ts) },
  { title: 'OPERATOR', key: 'operator', width: 140 },
  { title: 'NODE', key: 'node', width: 140, mono: true },
  {
    title: 'METHOD',
    key: 'method',
    width: 90,
    render: (r) =>
      h(
        RTag,
        { tone: r.method === 'GET' ? 'muted' : r.method === 'DELETE' ? 'danger' : 'info' },
        { default: () => r.method },
      ),
  },
  { title: 'PATH', key: 'path', mono: true },
  { title: 'BODY HASH', key: 'body_digest', width: 130, mono: true },
  {
    title: 'STATUS',
    key: 'status',
    width: 80,
    align: 'right',
    render: (r) =>
      h(
        RTag,
        { tone: r.status < 400 ? 'ok' : 'danger' },
        { default: () => String(r.status) },
      ),
  },
]

async function load() {
  loading.value = true
  try {
    entries.value = (await getAudit(limit.value, offset.value)).entries
  } catch (e) {
    console.warn(errMsg(e))
  } finally {
    loading.value = false
  }
}

function next() {
  offset.value += limit.value
  void load()
}
function prev() {
  offset.value = Math.max(0, offset.value - limit.value)
  void load()
}

onMounted(load)
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="SECURITY · AUDIT LOG" title="审计日志" sub="面板写操作记录">
      <template #extra>
        <RButton size="sm" :disabled="offset === 0" @click="prev">上一页</RButton>
        <RButton size="sm" :disabled="entries.length < limit" @click="next">下一页</RButton>
        <span class="muted num" style="margin-left: 8px">offset {{ offset }}</span>
      </template>
    </RPageHeader>

    <RPanel flush>
      <RTable
        :columns="cols"
        :rows="entries"
        :loading="loading"
        :row-key="(r: AuditEntry) => r.ts + r.path"
      />
    </RPanel>
  </div>
</template>
