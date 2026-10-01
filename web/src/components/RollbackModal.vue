<script setup lang="ts">
import { ref, watch, onUnmounted } from 'vue'
import { RAlert, RButton, RCheckbox, RModal, RResult, RSpinner, useMessage } from '../ui'
import { rollback, closeRollback } from './rollback'
import { getNodeConfig, postApplyConfirm } from '../api/client'
import { errMsg, fmtTime } from '../utils/format'

const message = useMessage()
let timer = 0
let pollTimer = 0

/** health check of the freshly written config: 'checking' | 'ok' | 'fail' */
const check = ref<'checking' | 'ok' | 'fail'>('checking')
const checkError = ref('')
const forceKeep = ref(false)

function stopTimers() {
  if (timer) {
    window.clearInterval(timer)
    timer = 0
  }
  if (pollTimer) {
    window.clearInterval(pollTimer)
    pollTimer = 0
  }
}

/** Poll GET config until the deadline; 保留 requires a read that returns the expected hash. */
function startHealthPoll() {
  if (!rollback.expectedHash || pollTimer) return
  check.value = 'checking'
  checkError.value = ''
  const poll = async () => {
    if (rollback.phase !== 'counting' || !rollback.expectedHash) return
    try {
      const cfg = await getNodeConfig(rollback.nodeId)
      if (cfg.hash === rollback.expectedHash) {
        check.value = 'ok'
        checkError.value = ''
      } else {
        check.value = 'fail'
        checkError.value = `节点返回 hash=${cfg.hash}，期望 ${rollback.expectedHash}`
      }
    } catch (e) {
      check.value = 'fail'
      checkError.value = errMsg(e)
    }
  }
  void poll()
  pollTimer = window.setInterval(() => void poll(), 1500)
}

watch(
  () => rollback.visible,
  (visible) => {
    stopTimers()
    forceKeep.value = false
    if (!visible) return
    check.value = rollback.expectedHash ? 'checking' : 'ok'
    checkError.value = ''
    if (rollback.expectedHash) startHealthPoll()
    timer = window.setInterval(() => {
      if (rollback.phase !== 'counting') return
      rollback.remain = Math.max(0, Math.ceil(rollback.deadline - Date.now() / 1000))
      if (rollback.remain <= 0) {
        rollback.phase = 'rolled'
        stopTimers()
      }
    }, 1000)
  },
  { immediate: true },
)

const canKeep = () => check.value === 'ok' || forceKeep.value

async function keep() {
  if (!canKeep()) return
  rollback.phase = 'confirming'
  try {
    await postApplyConfirm(rollback.nodeId, rollback.token)
    rollback.phase = 'kept'
    message.success('已确认，变更保留')
  } catch (e) {
    rollback.phase = 'rolled'
    message.warning(errMsg(e))
  } finally {
    stopTimers()
  }
}

onUnmounted(stopTimers)
</script>

<template>
  <RModal
    kicker="ROLLBACK"
    :title="rollback.phase === 'counting' || rollback.phase === 'confirming' ? '变更确认' : '变更结果'"
    :show="rollback.visible"
    :width="520"
    :mask-closable="rollback.phase !== 'confirming'"
    @update:show="(v: boolean) => { if (!v) closeRollback() }"
  >
    <template v-if="rollback.phase === 'counting' || rollback.phase === 'confirming'">
      <p style="font-size: 14px">
        变更已生效，请在 <b class="num t-danger count">{{ Math.max(0, rollback.remain) }}</b> 秒内确认，
        否则将于 <b class="mono">{{ fmtTime(rollback.deadline) }}</b> 自动回滚。
      </p>
      <p class="mono muted" style="margin-bottom: 8px">
        节点：{{ rollback.nodeId }}　确认令牌：{{ rollback.token }}
      </p>

      <div v-if="rollback.expectedHash" class="health">
        <RSpinner v-if="check === 'checking'">
          <span class="muted">正在校验节点是否已读到新配置（hash {{ rollback.expectedHash }}）…</span>
        </RSpinner>
        <template v-else-if="check === 'fail'">
          <RAlert tone="warn">
            健康校验未通过：保留将确认一份 Agent 自己读不回配置（{{ checkError }}）。
          </RAlert>
          <div style="margin-top: 8px">
            <RCheckbox v-model="forceKeep">我已确认节点可达，仍要保留（强制）</RCheckbox>
          </div>
        </template>
        <span v-else class="t-ok health-ok">健康校验通过：节点已读到新配置。</span>
      </div>

      <RButton
        tone="primary"
        block
        :disabled="!canKeep()"
        :loading="rollback.phase === 'confirming'"
        @click="keep"
      >
        确认保留
      </RButton>
      <RButton variant="ghost" block style="margin-top: 8px" @click="closeRollback">
        关闭（不确认，配置将自动回滚）
      </RButton>
    </template>
    <RResult
      v-else-if="rollback.phase === 'kept'"
      tone="ok"
      title="变更已保留"
      desc="确认已提交，配置不会被回滚。"
    >
      <template #footer>
        <RButton @click="closeRollback">关闭</RButton>
      </template>
    </RResult>
    <RResult
      v-else
      tone="warn"
      title="配置已自动回滚"
      :desc="`节点 ${rollback.nodeId} 未在时限内确认，已恢复到上一版本配置。`"
    >
      <template #footer>
        <RButton @click="closeRollback">关闭</RButton>
      </template>
    </RResult>
  </RModal>
</template>

<style scoped>
.count {
  font-size: 20px;
}
.health {
  margin-bottom: 12px;
}
.health-ok {
  font-size: 12.5px;
}
</style>
