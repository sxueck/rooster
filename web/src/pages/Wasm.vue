<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import {
  RAlert,
  RButton,
  REmpty,
  RInput,
  RModal,
  RPageHeader,
  RPanel,
  RSelect,
  RTable,
  RTag,
  useMessage,
  type RColumn,
  type SelectOption,
} from '../ui'
import {
  deleteNodeWasm,
  deleteWasmRegistry,
  getNodeWasm,
  getNodes,
  getWasmRegistry,
  putNodeWasm,
  uploadWasmPlugin,
} from '../api/client'
import type { NodeInfo, WasmPlugin, WasmRegistryEntry } from '../api/types'
import SchemaForm from '../components/SchemaForm.vue'
import { errMsg, fmtBytes, fmtTime } from '../utils/format'

const message = useMessage()

// ---- 注册表 ----
const registry = ref<WasmRegistryEntry[]>([])
const uploading = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)

const regCols: RColumn[] = [
  { title: 'FILE NAME', key: 'name', mono: true },
  { title: 'SIZE', key: 'size', width: 110, align: 'right', render: (r) => fmtBytes(r.size) },
  { title: 'UPLOADED', key: 'uploaded_at', width: 175, render: (r) => fmtTime(r.uploaded_at) },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 80,
    render: (r) =>
      h(
        RButton,
        { variant: 'link', tone: 'danger', onClick: () => removeRegistry(r.name) },
        { default: () => '删除' },
      ),
  },
]

async function loadRegistry() {
  try {
    registry.value = (await getWasmRegistry()).plugins
  } catch (e) {
    message.error(errMsg(e))
  }
}

function pickFile() {
  fileInput.value?.click()
}
async function onFile(e: Event) {
  const input = e.target as HTMLInputElement
  const f = input.files?.[0]
  input.value = ''
  if (!f) return
  uploading.value = true
  try {
    await uploadWasmPlugin(f)
    message.success(`已上传 ${f.name}`)
    await loadRegistry()
  } catch (err) {
    message.error(errMsg(err))
  } finally {
    uploading.value = false
  }
}
async function removeRegistry(name: string) {
  try {
    await deleteWasmRegistry(name)
    message.success(`已删除 ${name}`)
    await loadRegistry()
  } catch (e) {
    message.error(errMsg(e))
  }
}

// ---- 节点插件管理 ----
const nodeOptions = ref<SelectOption[]>([])
const nodeId = ref<string | null>(null)
const plugins = ref<WasmPlugin[]>([])
const nodeLoading = ref(false)

const pluginCols: RColumn[] = [
  { title: 'ID', key: 'id', width: 140 },
  { title: 'FILE', key: 'file', mono: true },
  { title: 'HOOKS', key: 'hooks', render: (r) => r.hooks.join(', ') },
  { title: 'SITES', key: 'sites', render: (r) => r.sites.join(', ') },
  {
    title: 'STATUS',
    key: 'status',
    width: 90,
    render: (r) =>
      h(
        RTag,
        { tone: r.status === 'active' ? 'ok' : 'muted' },
        { default: () => r.status },
      ),
  },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 130,
    render: (r) =>
      h('span', { class: 'row-tight' }, [
        h(RButton, { variant: 'link', onClick: () => openEdit(r) }, { default: () => '配置' }),
        h(RButton, { variant: 'link', tone: 'danger', onClick: () => removePlugin(r) }, { default: () => '卸载' }),
      ]),
  },
]

onMounted(async () => {
  await loadRegistry()
  try {
    const nodes: NodeInfo[] = (await getNodes()).nodes
    nodeOptions.value = nodes.map((n) => ({
      label: `${n.id}${n.online ? '' : '（离线）'}`,
      value: n.id,
    }))
  } catch (e) {
    message.error(errMsg(e))
  }
})

async function loadNodePlugins() {
  if (!nodeId.value) return
  nodeLoading.value = true
  try {
    plugins.value = (await getNodeWasm(nodeId.value)).plugins
  } catch (e) {
    plugins.value = []
    message.error(errMsg(e))
  } finally {
    nodeLoading.value = false
  }
}

const editing = ref<WasmPlugin | null>(null)
const editConfig = ref<Record<string, unknown>>({})
/** manifest 缺失（插件未加载成功）时，退化为整只插件 JSON 编辑，仍可修 file/hooks/sites */
const editingJson = ref('')
const editManifest = computed(() => editing.value?.manifest ?? null)
const saving = ref(false)

function openEdit(p: WasmPlugin) {
  editing.value = p
  editConfig.value = JSON.parse(JSON.stringify(p.config ?? {})) as Record<string, unknown>
  editingJson.value = JSON.stringify(p, null, 2)
}
async function saveEdit() {
  if (!editing.value || !nodeId.value) return
  let plugin: WasmPlugin = editing.value
  if (!editManifest.value) {
    try {
      plugin = JSON.parse(editingJson.value) as WasmPlugin
    } catch (e) {
      message.error('JSON 解析失败：' + errMsg(e))
      return
    }
    // 路径 id 为准，不接受 JSON 里改动 id
    plugin = { ...plugin, id: editing.value.id }
  }
  saving.value = true
  try {
    await putNodeWasm(nodeId.value, plugin.id, {
      ...plugin,
      config: editManifest.value ? editConfig.value : (plugin.config ?? {}),
    })
    message.success(`插件 ${plugin.id} 配置已写入节点`)
    editing.value = null
    await loadNodePlugins()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
  }
}
async function removePlugin(p: WasmPlugin) {
  if (!nodeId.value) return
  try {
    await deleteNodeWasm(nodeId.value, p.id)
    message.success(`已卸载 ${p.id}`)
    await loadNodePlugins()
  } catch (e) {
    message.error(errMsg(e))
  }
}
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="DELIVERY · WASM" title="WASM 插件" sub="插件仓库上传 + 按节点下发配置（经管理通道透传）" />

    <RPanel class="mb" title="插件仓库" kicker="REGISTRY" flush>
      <template #actions>
        <RButton size="sm" tone="primary" :loading="uploading" @click="pickFile">上传 .wasm</RButton>
      </template>
      <input ref="fileInput" type="file" accept=".wasm" style="display: none" @change="onFile" />
      <RTable :columns="regCols" :rows="registry" :row-key="(r: WasmRegistryEntry) => r.name" />
    </RPanel>

    <RPanel title="节点插件配置" kicker="NODE PLUGINS" flush>
      <template #actions>
        <div class="row-tight">
          <RSelect
            v-model="nodeId"
            :options="nodeOptions"
            placeholder="选择节点"
            :width="220"
            @update:model-value="loadNodePlugins"
          />
          <RButton size="sm" :disabled="!nodeId" :loading="nodeLoading" @click="loadNodePlugins">
            刷新
          </RButton>
        </div>
      </template>
      <REmpty v-if="!nodeId" text="SELECT NODE · 请先选择节点" />
      <RTable
        v-else
        :columns="pluginCols"
        :rows="plugins"
        :loading="nodeLoading"
        :row-key="(r: WasmPlugin) => r.id"
      />
    </RPanel>

    <RModal
      :show="editing !== null"
      :width="640"
      kicker="PLUGIN CONFIG"
      :title="`配置插件：${editing?.id ?? ''}（manifest schema 驱动）`"
      @update:show="(v: boolean) => { if (!v) editing = null }"
    >
      <RAlert v-if="editing && !editManifest" tone="warn" style="margin-bottom: 12px">
        插件未加载（status：{{ editing.status }}），manifest 缺失，无法按 schema 生成表单。可直接编辑下方
        JSON 修正 file / hooks / sites 后保存。
      </RAlert>
      <SchemaForm
        v-if="editing && editManifest"
        :schema="editManifest.config_schema ?? null"
        v-model="editConfig"
      />
      <RInput
        v-if="editing && !editManifest"
        v-model="editingJson"
        type="textarea"
        :auto-rows="[10, 20]"
        mono
      />
      <p v-if="editing && editManifest" class="muted">
        {{ editManifest.name }} v{{ editManifest.version }}　hooks:
        {{ editManifest.hooks.join(', ') }}
      </p>
      <template #footer>
        <RButton variant="ghost" @click="editing = null">取消</RButton>
        <RButton tone="primary" :loading="saving" @click="saveEdit">保存到节点</RButton>
      </template>
    </RModal>
  </div>
</template>
