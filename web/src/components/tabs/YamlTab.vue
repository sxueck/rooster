<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RButton, RInput, RPanel, RTag, useMessage } from '../../ui'
import { getNodeConfig, putNodeConfig } from '../../api/client'
import { armRollback, confirmRollbackIn } from '../rollback'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const yaml = ref('')
const hash = ref('')
const saving = ref(false)
const dirty = ref(false)

async function load() {
  try {
    const cfg = await getNodeConfig(props.nodeId)
    yaml.value = cfg.raw
    hash.value = cfg.hash
    dirty.value = false
  } catch (e) {
    message.error(errMsg(e))
  }
}

async function save() {
  saving.value = true
  try {
    const resp = await putNodeConfig(props.nodeId, yaml.value)
    hash.value = resp.hash
    if (resp.confirm) {
      // Agent emits "rollback-in"；读取需容忍连字符键
      const secs = confirmRollbackIn(resp.confirm)
      // 弹出全局回滚确认倒计时（携带期望 hash 供健康校验）
      armRollback(props.nodeId, resp.confirm.token, secs, resp.hash)
      // 倒计时结束后可能已回滚，回来时重新拉取
      window.setTimeout(() => void load(), (Math.max(1, secs) + 1) * 1000)
    } else {
      message.success(`已保存，hash=${resp.hash}`)
    }
    dirty.value = false
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <RPanel kicker="CONFIG · RAW YAML" title="YAML 配置（raw）">
    <template #actions>
      <RTag>HASH {{ hash || '-' }}</RTag>
    </template>
    <RInput
      v-model="yaml"
      type="textarea"
      :auto-rows="[18, 32]"
      mono
      @update:model-value="dirty = true"
    />
    <template #footer>
      <div class="row-tight">
        <RButton tone="primary" :loading="saving" :disabled="!dirty" @click="save">
          保存配置（PUT config）
        </RButton>
        <RButton variant="ghost" :disabled="!dirty" @click="load">放弃修改</RButton>
      </div>
    </template>
  </RPanel>
</template>
