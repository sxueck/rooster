<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import {
  RButton,
  RField,
  RInput,
  RNumberInput,
  RPageHeader,
  RPanel,
  RTable,
  useMessage,
  type RColumn,
} from '../ui'
import {
  addGlobalBan,
  deleteGlobalBan,
  getBanPolicies,
  getGlobalBans,
  putBanPolicies,
} from '../api/client'
import type { BanPolicy, GlobalBan } from '../api/types'
import { errMsg, fmtDuration, fmtTime } from '../utils/format'

const message = useMessage()

const bans = ref<GlobalBan[]>([])
const policies = ref<BanPolicy[]>([])
const form = ref({ ip: '', ttl_secs: 86400, reason: '' })
const adding = ref(false)
const savingPolicies = ref(false)

const banCols: RColumn[] = [
  { title: 'IP', key: 'ip', width: 150, mono: true },
  { title: 'REASON', key: 'reason' },
  { title: 'SOURCE', key: 'source_node', width: 130 },
  { title: 'EXPIRES', key: 'expires_at', width: 170, render: (r) => fmtTime(r.expires_at) },
  { title: 'TTL', key: 'ttl_secs', width: 90, render: (r) => fmtDuration(r.ttl_secs) },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 80,
    render: (r) =>
      h(
        RButton,
        { variant: 'link', tone: 'danger', onClick: () => removeBan(r.ip) },
        { default: () => '解封' },
      ),
  },
]

async function load() {
  try {
    bans.value = (await getGlobalBans()).bans
    policies.value = (await getBanPolicies()).policies
  } catch (e) {
    message.error(errMsg(e))
  }
}
onMounted(load)

async function addBan() {
  if (form.value.ip.trim() === '') {
    message.error('请填写 IP')
    return
  }
  adding.value = true
  try {
    await addGlobalBan({ ...form.value, ip: form.value.ip.trim() })
    message.success(`已加入全局黑名单：${form.value.ip}`)
    form.value = { ip: '', ttl_secs: 86400, reason: '' }
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    adding.value = false
  }
}

async function removeBan(ip: string) {
  try {
    await deleteGlobalBan(ip)
    message.success(`已解封 ${ip}`)
    await load()
  } catch (e) {
    message.error(errMsg(e))
  }
}

// ---- 策略编辑 ----
function addPolicy() {
  policies.value.push({
    id: `pol-${Math.random().toString(36).slice(2, 6)}`,
    match: {},
    ttl_secs: 3600,
  })
}
function removePolicy(i: number) {
  policies.value.splice(i, 1)
}
function matchVal(p: BanPolicy, key: 'plugin' | 'event' | 'severity'): string {
  return p.match[key] ?? ''
}
function setMatch(p: BanPolicy, key: 'plugin' | 'event' | 'severity', v: string) {
  const m = { ...p.match }
  if (v === '') delete m[key]
  else m[key] = v
  p.match = m
}
async function savePolicies() {
  savingPolicies.value = true
  try {
    await putBanPolicies(policies.value.map((p) => ({ ...p, match: { ...p.match } })))
    message.success(`已保存 ${policies.value.length} 条策略`)
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    savingPolicies.value = false
  }
}
</script>

<template>
  <div class="page">
    <RPageHeader kicker="SECURITY · GLOBAL BANS" title="全局黑名单" sub="跨节点封禁与联动策略" />

    <RPanel class="mb" title="手动封禁" kicker="ADD BAN">
      <div class="row">
        <RField inline label="IP">
          <RInput v-model="form.ip" mono placeholder="1.2.3.4" :width="160" />
        </RField>
        <RField inline label="TTL SECS">
          <RNumberInput
            :model-value="form.ttl_secs"
            :min="1"
            :width="140"
            @update:model-value="(v: number | null) => { if (v !== null) form.ttl_secs = v }"
          />
        </RField>
        <RField inline label="REASON">
          <RInput v-model="form.reason" placeholder="手动封禁" :width="200" />
        </RField>
        <RButton tone="danger" :loading="adding" @click="addBan">加入黑名单</RButton>
      </div>
    </RPanel>

    <RPanel class="mb" kicker="ACTIVE BANS" flush>
      <RTable :columns="banCols" :rows="bans" :row-key="(r: GlobalBan) => r.ip" />
    </RPanel>

    <RPanel kicker="POLICIES" title="联动策略（满足条件时自动全局封禁）">
      <template #actions>
        <RButton size="sm" @click="addPolicy">+ 新增策略</RButton>
      </template>
      <div v-for="(p, i) in policies" :key="p.id + '-' + i" class="pol-row">
        <RInput v-model="p.id" placeholder="策略 ID" :width="150" />
        <RInput
          :model-value="matchVal(p, 'plugin')"
          placeholder="plugin"
          :width="110"
          @update:model-value="(v: string) => setMatch(p, 'plugin', v)"
        />
        <RInput
          :model-value="matchVal(p, 'event')"
          placeholder="event"
          :width="110"
          @update:model-value="(v: string) => setMatch(p, 'event', v)"
        />
        <RInput
          :model-value="matchVal(p, 'severity')"
          placeholder="severity"
          :width="100"
          @update:model-value="(v: string) => setMatch(p, 'severity', v)"
        />
        <RNumberInput
          :model-value="p.min_nodes ?? null"
          size="sm"
          :min="1"
          placeholder="min_nodes"
          :width="110"
          @update:model-value="(v: number | null) => (p.min_nodes = v ?? undefined)"
        />
        <RNumberInput
          :model-value="p.threshold ?? null"
          size="sm"
          :min="1"
          placeholder="threshold"
          :width="110"
          @update:model-value="(v: number | null) => (p.threshold = v ?? undefined)"
        />
        <RNumberInput
          :model-value="p.window_secs ?? null"
          size="sm"
          :min="1"
          placeholder="窗口(秒)"
          :width="110"
          @update:model-value="(v: number | null) => (p.window_secs = v ?? undefined)"
        />
        <RNumberInput
          :model-value="p.ttl_secs"
          size="sm"
          :min="1"
          placeholder="封禁时长(秒)"
          :width="130"
          @update:model-value="(v: number | null) => { if (v !== null) p.ttl_secs = v }"
        />
        <RButton variant="link" tone="danger" @click="removePolicy(i)">删除</RButton>
      </div>
      <div v-if="policies.length === 0" class="muted">暂无策略</div>
      <template #footer>
        <RButton tone="primary" :loading="savingPolicies" @click="savePolicies">保存策略</RButton>
      </template>
    </RPanel>
  </div>
</template>

<style scoped>
.pol-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
</style>
