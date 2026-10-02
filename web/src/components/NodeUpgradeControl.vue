<script setup lang="ts">
import { computed, ref } from 'vue'
import { getUpgrades, rolloutUpgrade } from '../api/client'
import type { UpgradeEntry } from '../api/types'
import { RButton, RField, RModal, RSelect, useMessage } from '../ui'
import RunStatus from './RunStatus.vue'
import { errMsg } from '../utils/format'

const props = defineProps<{ nodeId: string; online: boolean }>()
const message = useMessage()
const show = ref(false)
const runShow = ref(false)
const loading = ref(false)
const starting = ref(false)
const versions = ref<UpgradeEntry[]>([])
const selected = ref<string | null>(null)
const runId = ref('')
const options = computed(() => versions.value.map((v) => ({ label: v.version, value: v.version })))

async function open() {
  if (!props.online) {
    message.warning('节点离线，无法下发升级')
    return
  }
  loading.value = true
  try {
    versions.value = (await getUpgrades()).upgrades
    if (versions.value.length === 0) {
      message.warning('尚无可用升级包，请先在“版本升级”页面上传')
      return
    }
    selected.value = versions.value[0]?.version ?? null
    show.value = true
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

async function upgrade() {
  if (!selected.value) return
  starting.value = true
  try {
    const result = await rolloutUpgrade(selected.value, {
      selector: {},
      node_id: props.nodeId,
      batch_size: 1,
      wait_secs: 30,
    })
    runId.value = result.run_id
    show.value = false
    runShow.value = true
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    starting.value = false
  }
}
</script>

<template>
  <span class="control">
    <RButton variant="link" tone="warn" :loading="loading" :disabled="!online" @click="open">升级 Agent</RButton>
    <RModal v-model:show="show" kicker="NODE UPGRADE" :title="`升级节点 ${nodeId}`" :width="440">
      <div class="stack">
        <RField label="AGENT VERSION">
          <RSelect v-model="selected" :options="options" placeholder="选择版本" width="100%" />
        </RField>
        <p class="muted">升级将重启该节点的 Agent，期间节点可能短暂离线。</p>
      </div>
      <template #footer>
        <RButton variant="ghost" @click="show = false">取消</RButton>
        <RButton tone="warn" :loading="starting" :disabled="!selected" @click="upgrade">开始升级</RButton>
      </template>
    </RModal>
    <RModal v-model:show="runShow" kicker="UPGRADE RUN" title="升级进度" :width="720">
      <RunStatus v-if="runShow" :run-id="runId" />
    </RModal>
  </span>
</template>

<style scoped>
.stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
</style>
