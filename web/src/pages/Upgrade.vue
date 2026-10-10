<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import {
  RButton,
  RField,
  RInput,
  RModal,
  RNumberInput,
  RPageHeader,
  RPanel,
  RTable,
  useDialog,
  useMessage,
  type RColumn,
} from '../ui'
import { getNodes, getUpgrades, rolloutUpgrade, uploadUpgrade, deleteUpgrade } from '../api/client'
import type { NodeInfo, UpgradeEntry } from '../api/types'
import KvEditor from '../components/KvEditor.vue'
import RunStatus from '../components/RunStatus.vue'
import { errMsg, fmtBytes, fmtTime } from '../utils/format'

const message = useMessage()
const dialog = useDialog()

const upgrades = ref<UpgradeEntry[]>([])
const loading = ref(false)
const deleting = ref('')

const cols: RColumn<UpgradeEntry>[] = [
  { title: 'VERSION', key: 'version', width: 140, mono: true },
  {
    title: 'SIZE',
    key: 'size',
    width: 110,
    align: 'right',
    render: (r) => h('span', { class: 'num' }, fmtBytes(r.size)),
  },
  { title: 'UPLOADED', key: 'uploaded_at', width: 175, render: (r) => fmtTime(r.uploaded_at) },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 130,
    render: (r) =>
      h('span', { class: 'row-tight' }, [
        h(RButton, { variant: 'link', tone: 'warn', onClick: () => openRollout(r.version) }, { default: () => '下发' }),
        h(
          RButton,
          { variant: 'link', tone: 'danger', loading: deleting.value === r.version, onClick: () => confirmDelete(r.version) },
          { default: () => '删除' },
        ),
      ]),
  },
]

async function load() {
  loading.value = true
  try {
    upgrades.value = (await getUpgrades()).upgrades
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    loading.value = false
  }
}
onMounted(load)

// ---- 上传 ----
const upForm = ref({ version: '', signature: '' })
const upFile = ref<File | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)

function pickFile() {
  fileInput.value?.click()
}
function onFile(e: Event) {
  const input = e.target as HTMLInputElement
  const f = input.files?.[0] ?? null
  input.value = ''
  if (f) {
    upFile.value = f
    if (upForm.value.version === '') upForm.value.version = f.name.replace(/\.bin$/, '')
  }
}
async function upload() {
  if (!upFile.value) {
    message.error('请选择要上传的二进制文件')
    return
  }
  if (upForm.value.version.trim() === '') {
    message.error('请填写版本号')
    return
  }
  uploading.value = true
  try {
    await uploadUpgrade(upFile.value, upForm.value.version.trim(), upForm.value.signature.trim())
    message.success(`版本 ${upForm.value.version} 已上传`)
    upFile.value = null
    upForm.value = { version: '', signature: '' }
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    uploading.value = false
  }
}

// ---- 下发 ----
const rolloutDlg = ref<{
  show: boolean
  version: string
  selector: Record<string, string>
  batch_size: number
  wait_secs: number
}>({ show: false, version: '', selector: {}, batch_size: 2, wait_secs: 30 })
const runDlg = ref<{ show: boolean; runId: string }>({ show: false, runId: '' })
const rolling = ref(false)

function confirmDelete(version: string) {
  dialog.warning({
    title: '删除升级包',
    content: `确定删除版本 ${version} 的升级包吗？已下发到节点的升级不受影响；离线节点的待下发升级会被取消。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      deleting.value = version
      try {
        await deleteUpgrade(version)
        message.success(`已删除升级包 ${version}`)
        await load()
      } catch (e) {
        message.error(errMsg(e))
      } finally {
        deleting.value = ''
      }
    },
  })
}

async function openRollout(version: string) {
  try {
    const nodes: NodeInfo[] = (await getNodes()).nodes
    if (nodes.length > 0) rolloutDlg.value.selector = { ...(nodes[0]!.labels) }
  } catch {
    /* 选择器默认为空即可 */
  }
  rolloutDlg.value.version = version
  rolloutDlg.value.show = true
}
async function doRollout() {
  const d = rolloutDlg.value
  rolling.value = true
  try {
    const resp = await rolloutUpgrade(d.version, {
      selector: d.selector,
      batch_size: d.batch_size,
      wait_secs: d.wait_secs,
    })
    d.show = false
    runDlg.value = { show: true, runId: resp.run_id }
    message.success(`升级任务已创建：${resp.run_id}`)
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    rolling.value = false
  }
}
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="DELIVERY · UPGRADE" title="版本升级" sub="上传签名二进制 → 分批下发升级" />

    <RPanel title="上传升级包" kicker="UPLOAD" style="margin-bottom: 16px">
      <div class="row">
        <RField inline :label-width="46" label="FILE">
          <RButton @click="pickFile">{{ upFile ? upFile.name : '选择二进制文件…' }}</RButton>
        </RField>
        <RField inline :label-width="76" label="VERSION">
          <RInput v-model="upForm.version" placeholder="0.5.0" :width="140" />
        </RField>
        <RField inline :label-width="92" label="SIGNATURE">
          <RInput v-model="upForm.signature" placeholder="base64 签名" :width="280" />
        </RField>
        <RButton tone="primary" :loading="uploading" @click="upload">上传</RButton>
      </div>
      <input ref="fileInput" type="file" style="display: none" @change="onFile" />
    </RPanel>

    <RPanel title="版本列表" kicker="VERSIONS" flush>
      <RTable
        :columns="cols"
        :rows="upgrades"
        :loading="loading"
        :row-key="(r: UpgradeEntry) => r.version"
        empty-text="NO VERSIONS · 暂无版本"
      />
    </RPanel>

    <!-- 下发参数 -->
    <RModal v-model:show="rolloutDlg.show" kicker="ROLLOUT" :width="520" :title="`下发升级 ${rolloutDlg.version}`">
      <div class="stack">
        <RField label="TARGET SELECTOR">
          <KvEditor v-model="rolloutDlg.selector" />
        </RField>
        <RField label="BATCH SIZE">
          <RNumberInput v-model="rolloutDlg.batch_size" :min="1" :width="160" />
        </RField>
        <RField label="BATCH WAIT (S)">
          <RNumberInput v-model="rolloutDlg.wait_secs" :min="0" :width="160" />
        </RField>
      </div>
      <template #footer>
        <RButton variant="ghost" @click="rolloutDlg.show = false">取消</RButton>
        <RButton tone="warn" :loading="rolling" @click="doRollout">开始升级</RButton>
      </template>
    </RModal>

    <!-- 升级进度 -->
    <RModal v-model:show="runDlg.show" kicker="UPGRADE RUN" title="升级进度" :width="720">
      <RunStatus v-if="runDlg.show" :run-id="runDlg.runId" />
    </RModal>
  </div>
</template>
