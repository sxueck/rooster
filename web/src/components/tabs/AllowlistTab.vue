<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { RAlert, RButton, RInput, RPanel, RTable, RTag, useMessage, type RColumn } from '../../ui'
import { getAllowlist, putAllowlist } from '../../api/client'
import type { AllowlistEffectiveEntry } from '../../api/types'
import { armRollback, confirmRollbackIn } from '../rollback'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const text = ref('')
const saving = ref(false)
const effective = ref<AllowlistEffectiveEntry[]>([])
const hubExempt = ref(false)

const SRC_LABEL: Record<string, string> = { admin: '管理员', hub: 'Hub', local: '本地' }
const SRC_TONE: Record<string, 'ok' | 'warn' | 'info' | 'muted'> = {
  admin: 'info',
  hub: 'warn',
  local: 'muted',
}

const effCols: RColumn<AllowlistEffectiveEntry>[] = [
  { title: 'CIDR', key: 'cidr', mono: true },
  {
    title: 'SOURCE',
    key: 'source',
    width: 120,
    render: (r) =>
      h(RTag, { tone: SRC_TONE[r.source] ?? 'muted' }, { default: () => SRC_LABEL[r.source] ?? r.source }),
  },
]

const hubCidrs = computed(() =>
  effective.value.filter((e) => e.source === 'hub').map((e) => e.cidr).join('、'),
)

async function load() {
  try {
    const resp = await getAllowlist(props.nodeId)
    text.value = resp['admin-allowlist'].join('\n')
    effective.value = resp.effective ?? []
    hubExempt.value = resp.hub_address_exempt ?? false
  } catch (e) {
    message.error(errMsg(e))
  }
}

async function save() {
  const cidrs = text.value
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s !== '')
  saving.value = true
  try {
    // 与 PUT /config 相同的 confirm 机制：不确认会在倒计时后自动回滚
    const resp = await putAllowlist(props.nodeId, cidrs)
    if (resp.confirm) {
      const secs = confirmRollbackIn(resp.confirm)
      // 在确认前不能宣称已持久化，交由全局回滚确认弹窗驱动
      armRollback(props.nodeId, resp.confirm.token, secs, resp.hash)
      window.setTimeout(() => void load(), (Math.max(1, secs) + 1) * 1000)
    } else {
      message.success(`白名单已保存（${cidrs.length} 条）`)
    }
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <!-- 单根节点:RTabs 靠 v-show 切换面板,Vue 会忽略多根(fragment)组件上的 v-show -->
  <div>
    <RPanel kicker="ADMIN ALLOWLIST" title="管理员白名单（每行一个 CIDR）">
      <RInput
        v-model="text"
        type="textarea"
        placeholder="10.0.0.0/8"
        :auto-rows="[10, 20]"
        mono
      />
      <template #footer>
        <RButton tone="primary" :loading="saving" @click="save">保存白名单</RButton>
      </template>
    </RPanel>

    <RPanel
      v-if="effective.length > 0 || hubExempt"
      kicker="EFFECTIVE ALLOWLIST"
      title="生效白名单（管理员 + Hub + 本地合并）"
      flush
      style="margin-top: 16px"
    >
      <RTable
        :columns="effCols"
        :rows="effective"
        :row-key="(r: AllowlistEffectiveEntry) => r.cidr"
        empty-text="节点未返回生效白名单"
      />
      <div v-if="hubExempt" class="hub-warn">
        <RAlert tone="warn">
          Hub 地址{{ hubCidrs ? ` ${hubCidrs}` : '' }}被自动豁免：在 NAT / portproxy 拓扑下该地址同时也是客户端源地址，这部分流量封不掉。
        </RAlert>
      </div>
    </RPanel>
  </div>
</template>

<style scoped>
.hub-warn {
  padding: 0 14px 12px;
}
</style>
