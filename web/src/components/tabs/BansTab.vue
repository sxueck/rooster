<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import {
  RAlert,
  RButton,
  RField,
  RInput,
  RNumberInput,
  RPanel,
  RTable,
  useMessage,
  type RColumn,
} from '../../ui'
import { addNodeBan, deleteNodeBan, getNodeBans, getNodeStats } from '../../api/client'
import { ApiError, type BanEngineStatus, type BanEntry } from '../../api/types'
import { errMsg, fmtDuration, fmtTime } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const bans = ref<BanEntry[]>([])
const form = ref({ ip: '', ttl_secs: 3600, reason: '' })
const adding = ref(false)

// 节点侧 nftables 封禁引擎可用性；available=false 时页顶 banner 降级提示
const banEngine = ref<BanEngineStatus | null>(null)
const engineDown = computed(() => banEngine.value?.available === false)

/** 503 + ban_engine payload：节点侧封禁引擎降级，交给 banner 承接而非弹错误 */
function banEngineOf(e: unknown): BanEngineStatus | null {
  if (e instanceof ApiError && e.status === 503) {
    const p = e.payload as { ban_engine?: BanEngineStatus } | null
    if (p && typeof p === 'object' && p.ban_engine && p.ban_engine.available === false) {
      return p.ban_engine
    }
  }
  return null
}

const cols: RColumn<BanEntry>[] = [
  { title: 'IP', key: 'ip', width: 150, mono: true },
  { title: 'REASON', key: 'reason' },
  { title: 'SOURCE', key: 'plugin', width: 100 },
  { title: 'SCOPE', key: 'scope', width: 80 },
  { title: 'EXPIRES', key: 'expires_at', width: 170, render: (r) => fmtTime(r.expires_at) },
  { title: 'TTL', key: 'ttl_secs', width: 90, render: (r) => fmtDuration(r.ttl_secs) },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 80,
    render: (r) =>
      h(
        RButton,
        { variant: 'link', tone: 'danger', disabled: engineDown.value, onClick: () => remove(r.ip) },
        { default: () => '解封' },
      ),
  },
]

async function load() {
  try {
    bans.value = (await getNodeBans(props.nodeId)).bans
  } catch (e) {
    const be = banEngineOf(e)
    if (be) {
      banEngine.value = be
      return
    }
    message.error(errMsg(e))
  }
}

async function add() {
  if (form.value.ip.trim() === '') {
    message.error('请填写 IP')
    return
  }
  adding.value = true
  try {
    await addNodeBan(props.nodeId, { ...form.value, ip: form.value.ip.trim() })
    message.success(`已封禁 ${form.value.ip}`)
    form.value = { ip: '', ttl_secs: 3600, reason: '' }
    await load()
  } catch (e) {
    const be = banEngineOf(e)
    if (be) {
      banEngine.value = be
      return
    }
    message.error(errMsg(e))
  } finally {
    adding.value = false
  }
}

async function remove(ip: string) {
  try {
    await deleteNodeBan(props.nodeId, ip)
    message.success(`已解封 ${ip}`)
    await load()
  } catch (e) {
    const be = banEngineOf(e)
    if (be) {
      banEngine.value = be
      return
    }
    message.error(errMsg(e))
  }
}

onMounted(async () => {
  // 先探封禁引擎可用性（stats 里的 ban_engine），拉不到不阻塞封禁列表
  try {
    banEngine.value = (await getNodeStats(props.nodeId)).ban_engine ?? null
  } catch {
    /* stats 不可用时仅忽略，由 bans 请求的错误路径兑底 */
  }
  await load()
})
</script>

<template>
  <!-- 单根节点:RTabs 靠 v-show 切换面板,Vue 会忽略多根(fragment)组件上的 v-show -->
  <div>
    <!-- 节点侧降级（nftables 不可用），不是面板故障：banner 承接 503，不把错误原文糊在页面中央 -->
    <RAlert v-if="engineDown" tone="warn" style="margin-bottom: 16px">
      封禁引擎不可用（节点侧降级，非面板故障）：{{ banEngine?.reason ?? '原因未知' }}。封禁的查看与增删暂不可用。
    </RAlert>

    <RPanel title="手动封禁" kicker="MANUAL BAN" style="margin-bottom: 16px">
      <div class="row">
        <RField inline :label-width="80" label="IP">
          <RInput v-model="form.ip" placeholder="1.2.3.4" :width="160" />
        </RField>
        <RField inline :label-width="80" label="TTL SECS">
          <RNumberInput v-model="form.ttl_secs" :min="1" :width="130" />
        </RField>
        <RField inline :label-width="80" label="REASON">
          <RInput v-model="form.reason" placeholder="手动封禁" :width="200" />
        </RField>
        <RButton tone="danger" :loading="adding" :disabled="engineDown" @click="add">封禁</RButton>
      </div>
    </RPanel>

    <RPanel title="封禁列表" kicker="ACTIVE BANS" flush>
      <RTable
        :columns="cols"
        :rows="bans"
        :row-key="(r: BanEntry) => r.ip"
        empty-text="NO BANS · 暂无封禁"
      />
    </RPanel>
  </div>
</template>
