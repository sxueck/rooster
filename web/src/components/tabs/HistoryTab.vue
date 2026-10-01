<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RButton, RPanel, useMessage } from '../../ui'
import { getHistory, getHistoryFile, getNodeConfig } from '../../api/client'
import DiffView from '../DiffView.vue'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

/** 后端只返回文件名字符串，无 mtime。 */
const files = ref<string[]>([])
const selected = ref('')
const fileRaw = ref('')
const currentRaw = ref('')
const mode = ref<'diff' | 'raw'>('diff')

async function load() {
  try {
    files.value = (await getHistory(props.nodeId)).files
    currentRaw.value = (await getNodeConfig(props.nodeId)).raw
  } catch (e) {
    message.error(errMsg(e))
  }
}

async function pick(name: string) {
  selected.value = name
  try {
    fileRaw.value = (await getHistoryFile(props.nodeId, name)).raw
  } catch (e) {
    message.error(errMsg(e))
  }
}

onMounted(load)
</script>

<template>
  <div class="his">
    <RPanel title="历史版本" flush class="his-left">
      <button
        v-for="name in files"
        :key="name"
        class="his-item"
        :class="{ on: selected === name }"
        @click="pick(name)"
      >
        <span class="his-name mono">{{ name }}</span>
      </button>
      <div v-if="files.length === 0" class="muted list-empty">无历史文件</div>
    </RPanel>

    <RPanel>
      <template #header>
        <span class="mono">{{ selected || '选择左侧文件' }}</span>
      </template>
      <template #actions>
        <div v-if="selected" class="row-tight seg">
          <RButton
            size="sm"
            :variant="mode === 'diff' ? 'outline' : 'ghost'"
            :tone="mode === 'diff' ? 'primary' : 'default'"
            @click="mode = 'diff'"
          >
            与当前对比
          </RButton>
          <RButton
            size="sm"
            :variant="mode === 'raw' ? 'outline' : 'ghost'"
            :tone="mode === 'raw' ? 'primary' : 'default'"
            @click="mode = 'raw'"
          >
            原文
          </RButton>
        </div>
      </template>
      <div v-if="!selected" class="muted">点击左侧历史文件查看内容并与当前配置对比</div>
      <template v-else>
        <DiffView v-if="mode === 'diff'" :old-file="fileRaw" :new-file="currentRaw" />
        <pre v-else class="pre-block raw-view">{{ fileRaw }}</pre>
      </template>
    </RPanel>
  </div>
</template>

<style scoped>
.his {
  display: grid;
  grid-template-columns: 320px 1fr;
  gap: 16px;
}
.his-left {
  align-self: start;
}
.list-empty {
  padding: 10px 12px;
}
.seg {
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 2px;
}
.his-item {
  display: block;
  width: 100%;
  text-align: left;
  padding: 8px 12px;
  background: none;
  border: none;
  border-left: 2px solid transparent;
  border-bottom: 1px solid var(--line);
  font-family: inherit;
  color: var(--ink);
  cursor: pointer;
}
.his-item:hover {
  background: var(--tint);
}
.his-item.on {
  border-left-color: var(--ink);
  background: var(--tint);
}
.his-name {
  font-size: 12.5px;
}
.raw-view {
  max-height: 60vh;
}
</style>
