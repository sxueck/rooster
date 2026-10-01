<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import {
  RButton,
  RCheckbox,
  RInput,
  RModal,
  RPageHeader,
  RPanel,
  RStatusDot,
  RTable,
  RTag,
  useDialog,
  useMessage,
  type RColumn,
} from '../ui'
import { deleteNode, getNodes, putNodeLabels, registerNodeToken } from '../api/client'
import type { NodeInfo, RegisterTokenResp } from '../api/types'
import KvEditor from '../components/KvEditor.vue'
import { errMsg, fmtRelative, fmtTime, toDate } from '../utils/format'

const router = useRouter()
const message = useMessage()
const dialog = useDialog()

const loading = ref(false)
const nodes = ref<NodeInfo[]>([])
const checked = ref<string[]>([])

async function load() {
  loading.value = true
  try {
    nodes.value = (await getNodes()).nodes
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    loading.value = false
  }
}
onMounted(load)

const cols = computed<RColumn[]>(() => [
  {
    title: 'NODE',
    key: 'id',
    width: 200,
    render: (row) =>
      h('span', { class: 'row-tight' }, [
        h(RStatusDot, { tone: row.online ? 'ok' : 'muted', pulse: row.online }),
        h(
          RButton,
          { variant: 'link', onClick: () => router.push(`/nodes/${row.id}`) },
          { default: () => row.id },
        ),
      ]),
  },
  {
    title: 'LABELS',
    key: 'labels',
    render: (row) =>
      h(
        'span',
        {},
        Object.entries(row.labels).map(([k, v]) =>
          h(RTag, { key: k }, { default: () => `${k}=${v}` }),
        ),
      ),
  },
  { title: 'VERSION', key: 'version', width: 90, mono: true },
  { title: 'CONFIG HASH', key: 'config_hash', width: 120, mono: true },
  {
    title: 'PENDING TPL',
    key: 'pending_template',
    width: 130,
    render: (row) => (row.pending_template ? h(RTag, { tone: 'warn' }, { default: () => row.pending_template }) : '—'),
  },
  {
    title: 'LAST SEEN',
    key: 'last_seen',
    width: 190,
    render: (row) =>
      h('span', { class: 'num' }, [
        fmtTime(row.last_seen),
        h('span', { class: 'muted', style: 'margin-left:6px' }, fmtRelative(row.last_seen)),
      ]),
  },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 150,
    render: (row) =>
      h('span', { class: 'row-tight' }, [
        h(RButton, { variant: 'link', onClick: () => openLabelDialog([row.id]) }, { default: () => '编辑标签' }),
        h(RButton, { variant: 'link', tone: 'danger', onClick: () => confirmRevoke(row) }, { default: () => '注销' }),
      ]),
  },
])

// ---- 注册新节点 ----
const regShow = ref(false)
const regLoading = ref(false)
const reg = ref<RegisterTokenResp | null>(null)
const regRemain = ref(0)
let regTimer = 0
let regPollTimer = 0
let regSession = 0

function stopRegistration() {
  regSession += 1
  window.clearInterval(regTimer)
  window.clearInterval(regPollTimer)
  reg.value = null
}
watch(regShow, (show) => {
  if (!show) stopRegistration()
}, { flush: 'sync' })

// 安装命令可选项:按需拼到 install_cmd 后(见 install.sh 的同名 flag)。
const optUnsigned = ref(false)
const optName = ref('')
const installCmd = computed(() => {
  const base = reg.value?.install_cmd ?? ''
  const args: string[] = []
  if (optUnsigned.value) args.push('--allow-unsigned')
  const name = optName.value.trim()
  if (name) args.push(`--name '${name.replace(/'/g, "'\\''")}'`)
  return args.length ? `${base} ${args.join(' ')}` : base
})

async function openRegister() {
  if (regLoading.value) return
  stopRegistration()
  const session = regSession
  regShow.value = true
  optUnsigned.value = false
  optName.value = ''
  regLoading.value = true
  try {
    const baseline = (await getNodes()).nodes
    if (session !== regSession) return
    nodes.value = baseline
    const token = await registerNodeToken()
    if (session !== regSession) return
    reg.value = token
    startRegCountdown()
    if (regShow.value) startRegPolling(new Set(baseline.map((node) => node.id)), session)
  } catch (e) {
    if (session !== regSession) return
    message.error(errMsg(e))
    regShow.value = false
  } finally {
    regLoading.value = false
  }
}
function startRegCountdown() {
  window.clearInterval(regTimer)
  const tick = () => {
    if (!reg.value) return
    regRemain.value = Math.max(0, Math.ceil(((toDate(reg.value.expires_at)?.getTime() ?? 0) - Date.now()) / 1000))
    if (regRemain.value === 0) {
      regShow.value = false
      message.warning('注册令牌已过期，请重新注册节点')
    }
  }
  tick()
  if (regShow.value) regTimer = window.setInterval(tick, 1000)
}
function startRegPolling(existingIds: Set<string>, session: number) {
  let pending = false
  regPollTimer = window.setInterval(async () => {
    if (pending || session !== regSession) return
    pending = true
    try {
      const current = (await getNodes()).nodes
      if (session !== regSession) return
      nodes.value = current
      // API does not expose token consumption; detect new online nodes against the opening snapshot.
      const ready = current.find((node) => !existingIds.has(node.id) && node.online)
      if (ready) {
        regShow.value = false
        message.success(`节点 ${ready.id} 已就绪`)
      }
    } catch {
      // Transient polling failures retry while the registration token is valid.
    } finally {
      pending = false
    }
  }, 2000)
}
async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    message.success('已复制到剪贴板')
  } catch {
    message.warning('复制失败，请手动选择复制')
  }
}

// ---- 标签编辑（单个 / 批量） ----
const labelShow = ref(false)
const labelTargets = ref<string[]>([])
const labelValue = ref<Record<string, string>>({})
const labelSaving = ref(false)

function openLabelDialog(ids: string[]) {
  labelTargets.value = ids
  labelValue.value = {}
  labelShow.value = true
}
async function applyLabels() {
  labelSaving.value = true
  try {
    await Promise.all(labelTargets.value.map((id) => putNodeLabels(id, { ...labelValue.value })))
    message.success(`已更新 ${labelTargets.value.length} 个节点的标签`)
    labelShow.value = false
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    labelSaving.value = false
  }
}

function confirmRevoke(node: NodeInfo) {
  dialog.warning({
    title: '注销节点',
    content: `确定要注销节点 ${node.id} 吗？该节点的注册令牌将被吊销，需重新注册才能加入。`,
    positiveText: '注销',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteNode(node.id)
        message.success(`节点 ${node.id} 已注销`)
        await load()
      } catch (e) {
        message.error(errMsg(e))
      }
    },
  })
}

function fmtRemain(s: number): string {
  const m = Math.floor(s / 60)
  const ss = s % 60
  return `${String(m).padStart(2, '0')}:${String(ss).padStart(2, '0')}`
}

onUnmounted(stopRegistration)
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="CLUSTER · NODES" title="节点管理" sub="集群节点列表 / 注册 / 标签">
      <template #extra>
        <RButton size="sm" :disabled="checked.length === 0" @click="openLabelDialog(checked)">
          批量编辑标签（{{ checked.length }}）
        </RButton>
        <RButton size="sm" tone="primary" :loading="regLoading" @click="openRegister">注册新节点</RButton>
      </template>
    </RPageHeader>

    <RPanel flush>
      <RTable
        v-model:checked="checked"
        :columns="cols"
        :rows="nodes"
        selectable
        :loading="loading"
        :row-key="(r: NodeInfo) => r.id"
        empty-text="NO NODES · 暂无节点"
      />
    </RPanel>

    <!-- 注册新节点 -->
    <RModal v-model:show="regShow" kicker="REGISTER" title="注册新节点" :width="640">
      <p v-if="regLoading" class="muted">正在生成注册令牌…</p>
      <template v-else-if="reg">
        <p class="muted">
          注册令牌有效期剩余 <b class="num count">{{ fmtRemain(regRemain) }}</b>
        </p>
        <div class="kv-line">
          <span class="micro">TOKEN</span>
          <code class="mono token">{{ reg.token }}</code>
        </div>
        <div class="micro cmd-label">OPTIONS</div>
        <div class="reg-opts">
          <span class="muted">自签 Hub 自动使用 CA 指纹验证，首次使用前请确认面板可信</span>
          <RCheckbox v-model="optUnsigned">允许未签名二进制</RCheckbox>
          <RInput v-model="optName" placeholder="节点名（默认 hostname）" style="max-width: 200px" />
        </div>
        <div class="micro cmd-label">INSTALL CMD</div>
        <pre class="pre-block">{{ installCmd }}</pre>
        <p class="muted" style="margin-top: 10px">
          在目标主机上以 root 运行安装命令，节点将自动注册并出现在列表中。
        </p>
      </template>
      <template #footer>
        <RButton variant="ghost" @click="() => reg && copy(reg.token)">复制 Token</RButton>
        <RButton variant="ghost" @click="() => reg && copy(installCmd)">复制安装命令</RButton>
        <RButton tone="primary" @click="regShow = false">关闭</RButton>
      </template>
    </RModal>

    <!-- 标签编辑 -->
    <RModal v-model:show="labelShow" kicker="LABELS" :title="`编辑标签（${labelTargets.length} 个节点）`" :width="520">
      <p class="muted" style="margin-bottom: 10px">
        目标节点：{{ labelTargets.join('、') }}　标签将合并到现有标签。
      </p>
      <KvEditor v-model="labelValue" />
      <template #footer>
        <RButton variant="ghost" @click="labelShow = false">取消</RButton>
        <RButton tone="primary" :loading="labelSaving" @click="applyLabels">应用</RButton>
      </template>
    </RModal>
  </div>
</template>

<style scoped>
.count {
  color: var(--danger);
  font-size: 14px;
}
.kv-line {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 10px 0;
}
.token {
  word-break: break-all;
  background: var(--tint);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 2px 6px;
}
.cmd-label {
  margin-bottom: 4px;
}
.reg-opts {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
/* tag chips in the LABELS column flow inline with small gaps */
:deep(.rt tbody td .rtg + .rtg) {
  margin-left: 6px;
}
</style>
