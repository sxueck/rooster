<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { RAlert, RButton, RPanel, RSwitch, RTag, useMessage } from '../../ui'
import { getNodeHardening, putNodeHardening } from '../../api/client'
import type { HardeningConfig } from '../../api/client'
import { ApiError } from '../../api/types'
import SchemaForm from '../SchemaForm.vue'
import { armRollback, confirmRollbackIn } from '../rollback'
import { errMsg } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()

/** 每段:标题 + 该段除 enabled 外的字段 schema(SchemaForm 渲染子对象) */
interface SectionDef {
  key: keyof HardeningConfig
  title: string
  fields: Record<string, unknown>
}

const SECTIONS: SectionDef[] = [
  {
    key: 'honeypot',
    title: '蜜罐端口',
    fields: {
      properties: {
        ports: { type: 'array', title: '端口清单', description: '逗号分隔;留空用内置高危端口表(23,135,137,139,445,…20 项)' },
        'hit-window': { type: 'string', title: '命中聚合窗口', default: '5m', description: '启用后未填写则用默认 5m' },
        'ban-time': { type: 'string', title: '封禁时长', default: '1h', description: '启用后未填写则用默认 1h' },
      },
    },
  },
  {
    key: 'port-guard',
    title: '端口扫描检测',
    fields: {
      properties: {
        'max-hits': { type: 'number', title: '命中次数上限', default: 30, description: '窗口内未监听端口命中阈值,启用后未填写默认 30' },
        'find-time': { type: 'string', title: '统计窗口', default: '60s', description: '启用后未填写则用默认 60s' },
        'extra-open-ports': { type: 'array', title: '额外放行端口', description: '本机真实监听但非 rooster 管理的端口' },
        'ban-time': { type: 'string', title: '封禁时长', default: '30m', description: '启用后未填写则用默认 30m' },
      },
    },
  },
  {
    key: 'conn-limit',
    title: '全局连接限速',
    fields: {
      properties: {
        rate: { type: 'string', title: '速率', default: '60/second', description: '启用后未填写默认 60/second' },
        burst: { type: 'number', title: '突发容忍', default: 20, description: '令牌桶 burst,启用后未填写默认 20' },
        'ban-time': { type: 'string', title: '封禁时长', default: '30m', description: '启用后未填写则用默认 30m' },
      },
    },
  },
  { key: 'flag-guard', title: 'TCP 异常标志', fields: { properties: {} } },
  {
    key: 'slow-loris',
    title: '慢速攻击防护',
    fields: {
      properties: {
        'header-timeout': { type: 'string', title: '请求头超时', default: '15s', description: '启用后未填写则用默认 15s' },
        'body-idle-timeout': { type: 'string', title: '请求体空闲超时', default: '15s', description: '启用后未填写则用默认 15s' },
        'max-conns-per-ip': { type: 'number', title: '每 IP 并发上限', default: 64, description: '启用后未填写默认 64' },
      },
    },
  },
  {
    key: 'client-hello',
    title: 'TLS ClientHello',
    fields: {
      properties: {
        'max-size': { type: 'number', title: '最大字节数', default: 16384, description: '超过即断开,启用后未填写默认 16 KiB' },
        rate: { type: 'string', title: '速率', default: '30/minute', description: '启用后未填写默认 30/minute' },
        burst: { type: 'number', title: '突发容忍', default: 10, description: '启用后未填写默认 10' },
      },
    },
  },
  {
    key: 'body-cap',
    title: '请求体硬上限',
    fields: {
      properties: {
        'max-size': { type: 'number', title: '最大字节数', default: 33554432, description: '启用后未填写默认 32 MiB' },
      },
    },
  },
]

/** 原始加载结果(稀疏):未配置段保持缺失,PUT 时原样透传 */
const raw = ref<HardeningConfig>({})
/** 各段表单模型(含 enabled) */
const forms = reactive<Record<string, Record<string, unknown>>>({})
/** 各段是否被用户改过(决定 PUT 时是否下发该段) */
const dirty = reactive<Record<string, boolean>>({})
const loaded = ref(false)
const loadError = ref('')
const saving = ref(false)

function resetForms(cfg: HardeningConfig) {
  raw.value = cfg
  for (const s of SECTIONS) {
    const sub = (cfg as Record<string, unknown>)[s.key] as Record<string, unknown> | null | undefined
    forms[s.key] = sub ? JSON.parse(JSON.stringify(sub)) : {}
    dirty[s.key] = false
  }
}

async function load() {
  try {
    resetForms((await getNodeHardening(props.nodeId)) ?? {})
    loaded.value = true
    loadError.value = ''
  } catch (e) {
    loaded.value = false
    loadError.value = errMsg(e)
  }
}

function isEnabled(key: string): boolean {
  return forms[key]?.enabled === true
}
function setEnabled(key: string, v: boolean) {
  forms[key] = { ...(forms[key] ?? {}), enabled: v }
  dirty[key] = true
}
function touch(key: string, v: Record<string, unknown>) {
  forms[key] = v
  dirty[key] = true
}

/** SchemaForm 数组输入产出字符串数组:整段转 number,非数字返回 null 报错 */
function toPorts(key: string, field: string, vals: unknown): number[] | null {
  if (!Array.isArray(vals)) return []
  const out: number[] = []
  for (const v of vals) {
    const n = Number(v)
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      message.error(`${SECTIONS.find((s) => s.key === key)?.title}:${field} 含非数字/越界端口「${String(v)}」(1-65535)`)
      return null
    }
    out.push(n)
  }
  return out
}

/** 组装整份配置:未触碰且加载时缺失的段不下发键;触碰过的段以表单为准 */
function buildConfig(): HardeningConfig | null {
  const out: Record<string, unknown> = JSON.parse(JSON.stringify(raw.value ?? {}))
  for (const s of SECTIONS) {
    const had = (raw.value as Record<string, unknown>)[s.key] !== undefined
    if (!dirty[s.key] && !had) continue // 未配置且未触碰:不下发
    const form = { ...(forms[s.key] ?? {}) }
    for (const field of ['ports', 'extra-open-ports']) {
      if (form[field] !== undefined) {
        const nums = toPorts(s.key, field, form[field])
        if (nums === null) return null
        form[field] = nums
      }
    }
    out[s.key] = form
  }
  return out as HardeningConfig
}

async function save() {
  if (!loaded.value) return
  const cfg = buildConfig()
  if (cfg === null) return
  saving.value = true
  try {
    const resp = await putNodeHardening(props.nodeId, cfg)
    const conf = resp.confirm
    if (conf) {
      // 涉及 nftables/数据面行为的变更:确认-回滚倒计时,超时自动回滚
      const secs = confirmRollbackIn(conf)
      armRollback(props.nodeId, conf.token, secs, resp.hash)
      window.setTimeout(() => void load(), (Math.max(1, secs) + 1) * 1000)
    } else {
      message.success('加固配置已保存')
    }
    await load()
  } catch (e) {
    message.error(errMsg(e))
    if (e instanceof ApiError && e.status === 422) {
      const p = e.payload as { details?: unknown[] } | null
      const details = p?.details
      if (Array.isArray(details) && details.length > 0) {
        message.error(details.map((d) => (typeof d === 'string' ? d : JSON.stringify(d))).join(';'))
      }
    }
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <RAlert tone="warn" style="margin-bottom: 16px">
      所有加固规则默认关闭，需手动启用；启用前先确认端口未被本机/转发规则监听。
    </RAlert>
    <RAlert v-if="loadError" tone="danger" style="margin-bottom: 16px">
      读取加固配置失败：{{ loadError }}（agent 版本过旧？）
    </RAlert>

    <RPanel
      v-for="s in SECTIONS"
      :key="s.key"
      :title="s.title"
      kicker="HARDENING"
      style="margin-bottom: 16px"
    >
      <template #actions>
        <div class="row-tight">
          <RTag :tone="isEnabled(s.key) ? 'ok' : 'muted'">
            {{ isEnabled(s.key) ? '已启用' : '未启用（默认）' }}
          </RTag>
          <RSwitch :model-value="isEnabled(s.key)" @update:model-value="(v: boolean) => setEnabled(s.key, v)" />
        </div>
      </template>
      <SchemaForm
        v-if="Object.keys(s.fields.properties as Record<string, unknown>).length > 0"
        :schema="s.fields"
        :model-value="forms[s.key] ?? {}"
        @update:model-value="(v: Record<string, unknown>) => touch(s.key, v)"
      />
      <p v-else class="muted">无额外参数：启用后对 TCP 异常标志包（NULL/SYN+FIN/XMAS、ct invalid）直接丢弃。</p>
    </RPanel>

    <RPanel>
      <template #footer>
        <div class="row-tight">
          <RButton tone="primary" :loading="saving" :disabled="!loaded" @click="save">保存加固配置</RButton>
          <RButton variant="ghost" :disabled="!loaded" @click="load">放弃修改</RButton>
        </div>
      </template>
      <p class="muted">
        保存以整份 hardening 配置 PUT：未改动且未启用的段不下发；启用/禁用任一段会弹出回滚确认倒计时。
      </p>
    </RPanel>
  </div>
</template>
