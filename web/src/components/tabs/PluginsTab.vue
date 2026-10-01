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
import { getNodeConfig, getNodePlugin, getNodeWasm, putNodePlugin, putNodeWasm } from '../../api/client'
import type { SshGuardPluginConfig, WasmPlugin } from '../../api/client'
import SchemaForm from '../SchemaForm.vue'
import { armRollback, confirmRollbackIn } from '../rollback'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const plugins = ref<WasmPlugin[]>([])
const effectiveSection = ref('')
/** 内置插件 ssh-guard:effective 回填的表单模型 */
const sshForm = ref<Record<string, unknown>>({})
const sshLoaded = ref(false)
const sshUnsupported = ref('')
const sshEnabled = computed(() => sshForm.value.enabled === true)
const sshSaving = ref(false)
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
    // agent 的 effective 是 JSON 对象,取 plugins 子树展示(旧代码误当 YAML 文本 split 导致崩页)
    const p = cfg.effective.plugins
    effectiveSection.value = p === undefined ? '' : JSON.stringify(p, null, 2)
  } catch (e) {
    message.error(errMsg(e))
  }
  // 内置插件单独容错:旧版 agent 无 /plugins 端点时仅禁用卡片,不炸整页
  try {
    sshForm.value = (await getNodePlugin(props.nodeId, 'ssh-guard')) as unknown as Record<
      string,
      unknown
    >
    sshLoaded.value = true
    sshUnsupported.value = ''
  } catch (e) {
    sshLoaded.value = false
    sshUnsupported.value = errMsg(e)
  }
}

/** ssh-guard 表单 schema(与 agent 端 SshGuardConfig 字段对齐) */
const SSHGUARD_SCHEMA: Record<string, unknown> = {
  properties: {
    enabled: {
      type: 'boolean',
      title: '启用 ssh-guard',
      description: '关闭后立即停止日志采集与 nftables 限速规则',
    },
    port: { type: 'number', title: 'SSH 端口', description: 'sshd 实际监听端口' },
    source: {
      type: 'string',
      title: '日志源',
      enum: ['journald', 'file'],
      description: 'journald 不可用时自动回退 tail /var/log/auth.log',
    },
    'max-retry': {
      type: 'number',
      title: '失败次数阈值',
      description: '统计窗口内认证失败达到该次数即封禁',
    },
    'find-time': { type: 'string', title: '统计窗口', description: '如 10m、5m' },
    'ban-time': {
      type: 'string',
      title: '基础封禁时长',
      description: '如 1h;重复违规按倍数递增',
    },
    'ban-time-factor': { type: 'number', title: '递增倍数', description: 'ban-time × factor^n' },
    'ban-time-max': { type: 'string', title: '封禁上限', description: '如 7days' },
    'conn-rate': {
      type: 'string',
      title: '连接速率限制',
      description: 'nftables meter 侧执行,如 10/minute',
    },
    'conn-burst': { type: 'number', title: '突发容忍', description: '令牌桶 burst' },
  },
}

async function saveSshGuard() {
  if (!sshLoaded.value) return
  sshSaving.value = true
  try {
    const resp = await putNodePlugin(
      props.nodeId,
      'ssh-guard',
      sshForm.value as unknown as SshGuardPluginConfig,
    )
    const conf = resp.confirm
    if (conf) {
      // ssh_guard 段是确认-回滚类变更:弹全局倒计时,超时未确认自动回滚
      const secs = confirmRollbackIn(conf)
      armRollback(props.nodeId, conf.token, secs, resp.hash)
      window.setTimeout(() => void load(), (Math.max(1, secs) + 1) * 1000)
    } else {
      message.success('ssh-guard 配置已保存并热生效')
    }
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    sshSaving.value = false
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
    <RPanel title="内置插件 · ssh-guard" kicker="BUILTIN PLUGINS" style="margin-bottom: 16px">
      <template #actions>
        <RTag :tone="sshEnabled ? 'ok' : 'muted'">{{ sshEnabled ? '已启用' : '未启用' }}</RTag>
      </template>
      <RAlert v-if="sshUnsupported" tone="warn">
        读取内置插件配置失败：{{ sshUnsupported }}（agent 版本过旧？）可临时使用「高级 ·
        YAML」。
      </RAlert>
      <SchemaForm v-if="sshLoaded" v-model="sshForm" :schema="SSHGUARD_SCHEMA" />
      <p class="muted" style="margin-top: 8px">
        保存写入 managed.plugins.ssh-guard：注释保留、原子落盘、热生效；涉及
        nftables 的变更保存后会弹出回滚确认倒计时。
      </p>
      <template #footer>
        <div class="row-tight">
          <RButton tone="primary" :loading="sshSaving" :disabled="!sshLoaded" @click="saveSshGuard">
            保存 ssh-guard 配置
          </RButton>
          <RButton variant="ghost" :disabled="!sshLoaded" @click="load">放弃修改</RButton>
        </div>
      </template>
    </RPanel>

    <RPanel title="WASM 插件（已加载）" kicker="WASM PLUGINS" flush style="margin-bottom: 16px">
      <RTable
        :columns="cols"
        :rows="plugins"
        :row-key="(r: WasmPlugin) => r.id"
        empty-text="NO WASM PLUGINS · 暂无 WASM 插件（内置插件见上方卡片）"
      />
    </RPanel>

    <RPanel title="effective 配置中的 plugins 段（只读）" kicker="EFFECTIVE JSON">
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
