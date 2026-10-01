<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import {
  RButton,
  RField,
  RInput,
  RModal,
  RPanel,
  RSelect,
  RTable,
  useMessage,
  type RColumn,
  type SelectOption,
} from '../../ui'
import { deleteForward, getForwards, putForward } from '../../api/client'
import type { ForwardRule } from '../../api/client'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

const forwards = ref<ForwardRule[]>([])
const dlg = ref<{
  show: boolean
  isEdit: boolean
  form: ForwardRule
}>({ show: false, isEdit: false, form: { id: '', listen: '', target: '', proto: 'tcp' } })
const saving = ref(false)

const protoOptions: SelectOption[] = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
  { label: 'TCP+UDP', value: 'tcp+udp' },
]

const cols: RColumn<ForwardRule>[] = [
  { title: 'ID', key: 'id', width: 120, mono: true },
  { title: 'LISTEN', key: 'listen', mono: true },
  { title: 'TARGET', key: 'target', mono: true },
  { title: 'PROTO', key: 'proto', width: 100, mono: true },
  {
    title: 'ACTIONS',
    key: 'actions',
    width: 140,
    render: (r) =>
      h('span', { class: 'row-tight' }, [
        h(RButton, { variant: 'link', onClick: () => openEdit(r) }, { default: () => '编辑' }),
        h(RButton, { variant: 'link', tone: 'danger', onClick: () => remove(r) }, { default: () => '删除' }),
      ]),
  },
]

async function load() {
  try {
    forwards.value = await getForwards(props.nodeId)
  } catch (e) {
    message.error(errMsg(e))
  }
}

function openCreate() {
  dlg.value = { show: true, isEdit: false, form: { id: '', listen: '', target: '', proto: 'tcp' } }
}
function openEdit(f: ForwardRule) {
  dlg.value = { show: true, isEdit: true, form: { ...f } }
}

async function save() {
  if (dlg.value.form.id.trim() === '') {
    message.error('请填写转发 ID')
    return
  }
  saving.value = true
  try {
    // 新增/编辑均走 PUT /forwards/{id}（agent 无批量路由）
    await putForward(props.nodeId, dlg.value.form.id.trim(), dlg.value.form)
    message.success('转发已保存')
    dlg.value.show = false
    await load()
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

async function remove(f: ForwardRule) {
  try {
    await deleteForward(props.nodeId, f.id)
    forwards.value = forwards.value.filter((x) => x.id !== f.id)
    message.success(`已删除转发 ${f.id}`)
  } catch (e) {
    message.error(errMsg(e))
  }
}

onMounted(load)
</script>

<template>
  <!-- 单根节点:RTabs 靠 v-show 切换面板,Vue 会忽略多根(fragment)组件上的 v-show -->
  <div>
    <RPanel title="转发规则" kicker="FORWARDS" flush>
      <template #actions>
        <RButton size="sm" tone="primary" @click="openCreate">新增转发</RButton>
      </template>
      <RTable :columns="cols" :rows="forwards" :row-key="(r: ForwardRule) => r.id" />
    </RPanel>

    <RModal v-model:show="dlg.show" kicker="FORWARD" :title="dlg.isEdit ? '编辑转发' : '新增转发'" :width="480">
      <div class="form">
        <RField inline :label-width="80" label="ID">
          <RInput v-model="dlg.form.id" :disabled="dlg.isEdit" placeholder="web" mono />
        </RField>
        <RField inline :label-width="80" label="LISTEN">
          <RInput v-model="dlg.form.listen" placeholder="0.0.0.0:8080" mono />
        </RField>
        <RField inline :label-width="80" label="TARGET">
          <RInput v-model="dlg.form.target" placeholder="10.0.0.10:80" mono />
        </RField>
        <RField inline :label-width="80" label="PROTO">
          <RSelect
            :model-value="dlg.form.proto"
            :options="protoOptions"
            :width="180"
            @update:model-value="(v: string | null) => { if (v !== null) dlg.form.proto = v as ForwardRule['proto'] }"
          />
        </RField>
      </div>
      <template #footer>
        <RButton variant="ghost" @click="dlg.show = false">取消</RButton>
        <RButton tone="primary" :loading="saving" @click="save">保存</RButton>
      </template>
    </RModal>
  </div>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 2px;
}
</style>
