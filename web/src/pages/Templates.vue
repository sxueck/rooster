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
  RTag,
  useDialog,
  useMessage,
  type RColumn,
} from '../ui'
import {
  deleteTemplate,
  getRollouts,
  getTemplates,
  previewTemplate,
  putTemplate,
  rolloutTemplate,
} from '../api/client'
import type { RolloutRun, Template, TemplatePreviewNode } from '../api/types'
import KvEditor from '../components/KvEditor.vue'
import DiffView from '../components/DiffView.vue'
import RunStatus from '../components/RunStatus.vue'
import { errMsg, fmtTime } from '../utils/format'

const message = useMessage()
const dialog = useDialog()

const templates = ref<Template[]>([])
const runs = ref<RolloutRun[]>([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    templates.value = (await getTemplates()).templates
    runs.value = (await getRollouts()).runs
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    loading.value = false
  }
}
onMounted(load)

// ---- 列表 ----
const tplCols: RColumn<Template>[] = [
  { title: 'ID', key: 'id', width: 140, mono: true },
  { title: 'NAME', key: 'name', width: 160 },
  {
    title: 'SELECTOR',
    key: 'selector',
    render: (r) =>
      h(
        'span',
        {},
        Object.entries(r.selector).map(([k, v]) =>
          h(RTag, { key: k, style: 'margin-right:6px' }, { default: () => `${k}=${v}` }),
        ),
      ),
  },
  { title: 'UPDATED', key: 'updated_at', width: 180, render: (r) => fmtTime(r.updated_at) },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 260,
    render: (r) =>
      h('span', { class: 'row-tight' }, [
        h(RButton, { variant: 'link', onClick: () => openEdit(r) }, { default: () => '编辑' }),
        h(RButton, { variant: 'link', onClick: () => doPreview(r) }, { default: () => '预览' }),
        h(RButton, { variant: 'link', tone: 'warn', onClick: () => openRollout(r) }, { default: () => '下发' }),
        h(RButton, { variant: 'link', tone: 'danger', onClick: () => confirmDelete(r) }, { default: () => '删除' }),
      ]),
  },
]

const runCols: RColumn<RolloutRun>[] = [
  { title: 'RUN ID', key: 'id', width: 130, mono: true },
  { title: 'TEMPLATE', key: 'template_id', width: 140 },
  { title: 'KIND', key: 'kind', width: 80, render: (r) => (r.kind === 'template' ? '模板' : r.kind) },
  { title: 'STARTED', key: 'started_at', width: 170, render: (r) => fmtTime(r.started_at) },
  {
    title: 'STATUS',
    key: 'status',
    width: 90,
    render: (r) =>
      h(
        RTag,
        { tone: r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'danger' : 'info' },
        { default: () => (r.status === 'completed' ? '已完成' : r.status === 'failed' ? '失败' : '进行中') },
      ),
  },
]

// ---- 编辑器 ----
const editor = ref<{
  show: boolean
  isEdit: boolean
  form: { id: string; name: string; selector: Record<string, string>; yaml: string }
}>({ show: false, isEdit: false, form: { id: '', name: '', selector: {}, yaml: '' } })
const saving = ref(false)

function openCreate() {
  editor.value = { show: true, isEdit: false, form: { id: '', name: '', selector: {}, yaml: '' } }
}
function openEdit(t: Template) {
  editor.value = { show: true, isEdit: true, form: { id: t.id, name: t.name, selector: { ...t.selector }, yaml: t.yaml } }
}
async function saveTemplate() {
  const f = editor.value.form
  if (f.id.trim() === '' || f.name.trim() === '') {
    message.error('请填写模板 ID 与名称')
    return
  }
  saving.value = true
  try {
    await putTemplate(f.id.trim(), { name: f.name.trim(), selector: f.selector, yaml: f.yaml })
    message.success('模板已保存')
    editor.value.show = false
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
  }
}
function confirmDelete(t: Template) {
  dialog.warning({
    title: '删除模板',
    content: `确定删除模板 ${t.id}（${t.name}）吗？已下发的配置不受影响。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteTemplate(t.id)
        message.success('模板已删除')
        await load()
      } catch (e) {
        message.error(errMsg(e))
      }
    },
  })
}

// ---- 预览 ----
const preview = ref<{ show: boolean; data: TemplatePreviewNode[] }>({ show: false, data: [] })

async function doPreview(t: Template) {
  try {
    preview.value = { show: true, data: (await previewTemplate(t.id)).nodes }
  } catch (e) {
    message.error(errMsg(e))
  }
}
function previewStatusType(s: string): 'ok' | 'warn' | 'danger' | 'info' {
  if (s === 'changed') return 'warn'
  if (s === 'unchanged') return 'ok'
  if (s === 'offline') return 'danger'
  return 'info'
}
function previewStatusLabel(s: string): string {
  if (s === 'changed') return '有变更'
  if (s === 'unchanged') return '无差异'
  if (s === 'offline') return '离线'
  return s
}

// ---- 下发 ----
const rolloutDlg = ref<{
  show: boolean
  tpl: Template | null
  concurrency: number
  delay: number
  selector: Record<string, string>
}>({ show: false, tpl: null, concurrency: 4, delay: 0, selector: {} })
const runDlg = ref<{ show: boolean; runId: string }>({ show: false, runId: '' })
const rolling = ref(false)

function openRollout(t: Template) {
  rolloutDlg.value = { show: true, tpl: t, concurrency: 4, delay: 0, selector: { ...t.selector } }
}
async function doRollout() {
  const d = rolloutDlg.value
  if (!d.tpl) return
  rolling.value = true
  try {
    const resp = await rolloutTemplate(d.tpl.id, {
      selector: d.selector,
      concurrency: d.concurrency,
      auto_confirm_delay_secs: d.delay,
    })
    d.show = false
    runDlg.value = { show: true, runId: resp.run_id }
    message.success(`下发任务已创建：${resp.run_id}`)
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    rolling.value = false
  }
}
</script>

<template>
  <div class="page page-wide">
    <RPageHeader kicker="CONFIG · TEMPLATES" title="配置模板" sub="模板管理 / 预览 / 灰度下发 / 下发记录">
      <template #extra>
        <RButton size="sm" tone="primary" @click="openCreate">新建模板</RButton>
      </template>
    </RPageHeader>

    <RPanel title="模板列表" kicker="REGISTRY" flush style="margin-bottom: 16px">
      <RTable
        :columns="tplCols"
        :rows="templates"
        :loading="loading"
        :row-key="(r: Template) => r.id"
        empty-text="NO TEMPLATES · 暂无模板"
      />
    </RPanel>

    <RPanel title="下发记录" kicker="ROLLOUT RUNS" flush>
      <RTable
        :columns="runCols"
        :rows="runs"
        :row-key="(r: RolloutRun) => r.id"
        :page-size="8"
        empty-text="NO RUNS · 暂无下发记录"
      />
      <template #footer>
        <details>
          <summary class="muted" style="cursor: pointer">查看各运行结果明细</summary>
          <div v-for="run in runs" :key="'detail-' + run.id" style="margin-top: 10px">
            <p class="mono muted">{{ run.id }} → {{ run.template_id }}（{{ run.status }}）</p>
            <RTag
              v-for="res in run.results"
              :key="run.id + res.node_id"
              style="margin-right: 6px"
              :tone="res.status === 'applied' ? 'ok' : res.status === 'failed' ? 'danger' : 'muted'"
              :title="res.error ?? ''"
            >
              {{ res.node_id }}: {{ res.status }}
            </RTag>
          </div>
        </details>
      </template>
    </RPanel>

    <!-- 模板编辑器 -->
    <RModal
      v-model:show="editor.show"
      kicker="TEMPLATE EDIT"
      :width="720"
      :title="editor.isEdit ? `编辑模板 ${editor.form.id}` : '新建模板'"
    >
      <div class="stack">
        <RField label="ID">
          <RInput v-model="editor.form.id" :disabled="editor.isEdit" placeholder="tpl-my-config" />
        </RField>
        <RField label="NAME">
          <RInput v-model="editor.form.name" placeholder="边缘默认配置" />
        </RField>
        <RField label="SELECTOR">
          <KvEditor v-model="editor.form.selector" />
        </RField>
        <RField label="YAML">
          <RInput v-model="editor.form.yaml" type="textarea" :auto-rows="[12, 24]" mono />
        </RField>
      </div>
      <template #footer>
        <RButton variant="ghost" @click="editor.show = false">取消</RButton>
        <RButton tone="primary" :loading="saving" @click="saveTemplate">保存</RButton>
      </template>
    </RModal>

    <!-- 预览 diff -->
    <RModal v-model:show="preview.show" kicker="PREVIEW" title="下发预览（按节点）" :width="860">
      <div style="max-height: 62vh; overflow: auto">
        <div v-for="n in preview.data" :key="n.node_id" style="margin-bottom: 16px">
          <p style="margin: 0 0 6px">
            <code class="mono">{{ n.node_id }}</code>
            <RTag :tone="previewStatusType(n.status)" style="margin-left: 8px">
              {{ previewStatusLabel(n.status) }}
            </RTag>
          </p>
          <DiffView v-if="n.diff" :diff="n.diff" />
        </div>
      </div>
    </RModal>

    <!-- 下发参数 -->
    <RModal v-model:show="rolloutDlg.show" kicker="ROLLOUT" :width="520" :title="`下发模板 ${rolloutDlg.tpl?.id ?? ''}`">
      <div class="stack">
        <RField label="SELECTOR OVERRIDE">
          <KvEditor v-model="rolloutDlg.selector" />
        </RField>
        <RField label="CONCURRENCY">
          <RNumberInput v-model="rolloutDlg.concurrency" :min="1" :max="64" :width="160" />
        </RField>
        <RField label="AUTO-CONFIRM DELAY (S)">
          <RNumberInput v-model="rolloutDlg.delay" :min="0" :width="160" />
        </RField>
      </div>
      <template #footer>
        <RButton variant="ghost" @click="rolloutDlg.show = false">取消</RButton>
        <RButton tone="warn" :loading="rolling" @click="doRollout">开始下发</RButton>
      </template>
    </RModal>

    <!-- 下发进度 -->
    <RModal v-model:show="runDlg.show" kicker="ROLLOUT RUN" title="下发进度" :width="720">
      <RunStatus v-if="runDlg.show" :run-id="runDlg.runId" />
    </RModal>
  </div>
</template>
