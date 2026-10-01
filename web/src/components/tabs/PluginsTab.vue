<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import {
  RAlert,
  RButton,
  RInput,
  RModal,
  RPanel,
  RTable,
  RTag,
  useMessage,
  type RColumn,
} from '../../ui'
import { getNodeConfig, getNodeWasm, putNodeWasm } from '../../api/client'
import type { WasmPlugin } from '../../api/client'
import SchemaForm from '../SchemaForm.vue'
import { errMsg, extractYamlSection } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const plugins = ref<WasmPlugin[]>([])
const effectiveSection = ref('')
const editing = ref<WasmPlugin | null>(null)
const editConfig = ref<Record<string, unknown>>({})
/** manifest 缺失（插件未加载成功）时，退化为整只插件 JSON 编辑，仍可修 file/hooks/sites */
const editingJson = ref('')
const editManifest = computed(() => editing.value?.manifest ?? null)
const saving = ref(false)

const editShow = computed({
  get: () => editing.value !== null,
  set: (v: boolean) => {
    if (!v) editing.value = null
  },
})

const cols: RColumn<WasmPlugin>[] = [
  { title: 'ID', key: 'id', width: 140, mono: true },
  { title: 'FILE', key: 'file', render: (r) => h('code', { class: 'mono' }, r.file) },
  { title: 'HOOKS', key: 'hooks', render: (r) => r.hooks.join(', ') },
  { title: 'SITES', key: 'sites', render: (r) => r.sites.join(', ') },
  {
    title: 'STATUS',
    key: 'status',
    width: 90,
    render: (r) =>
      h(RTag, { tone: r.status === 'active' ? 'ok' : 'muted' }, { default: () => r.status }),
  },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 100,
    render: (r) =>
      h(RButton, { variant: 'link', onClick: () => openEdit(r) }, { default: () => '配置' }),
  },
]

async function load() {
  try {
    plugins.value = (await getNodeWasm(props.nodeId)).plugins
    const cfg = await getNodeConfig(props.nodeId)
    effectiveSection.value = extractYamlSection(cfg.effective, 'plugins')
  } catch (e) {
    message.error(errMsg(e))
  }
}

function openEdit(p: WasmPlugin) {
  editing.value = p
  editConfig.value = JSON.parse(JSON.stringify(p.config ?? {})) as Record<string, unknown>
  editingJson.value = JSON.stringify(p, null, 2)
}

async function save() {
  if (!editing.value) return
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
    await putNodeWasm(props.nodeId, plugin.id, {
      ...plugin,
      config: editManifest.value ? editConfig.value : (plugin.config ?? {}),
    })
    message.success(`插件 ${plugin.id} 配置已保存`)
    editing.value = null
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <RPanel title="已加载插件" kicker="LOADED PLUGINS" flush style="margin-bottom: 16px">
      <RTable
        :columns="cols"
        :rows="plugins"
        :row-key="(r: WasmPlugin) => r.id"
        empty-text="NO PLUGINS · 暂无插件"
      />
    </RPanel>

    <RPanel title="effective 配置中的 plugins 段（只读）" kicker="EFFECTIVE YAML">
      <pre class="mono pre-block">{{ effectiveSection || '（无）' }}</pre>
    </RPanel>

    <RModal
      v-model:show="editShow"
      kicker="PLUGIN CONFIG"
      :title="`配置插件：${editing?.id ?? ''}（schema 驱动）`"
      :width="640"
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
      <p class="muted" v-if="editing && editManifest">
        manifest：{{ editManifest.name }} v{{ editManifest.version }}　hooks:
        {{ editManifest.hooks.join(', ') }}
      </p>
      <template #footer>
        <RButton variant="ghost" @click="editing = null">取消</RButton>
        <RButton tone="primary" :loading="saving" @click="save">保存</RButton>
      </template>
    </RModal>
  </div>
</template>
