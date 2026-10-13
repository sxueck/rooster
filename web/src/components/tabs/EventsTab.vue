<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RButton, RField, RModal, RPanel, RPager, RInput, RTag, useMessage } from '../../ui'
import { useEventsStore } from '../../stores/events'
import { getNodeEvents, getSites, putSite } from '../../api/client'
import type { EventRecord, RoosterEvent } from '../../api/types'
import { normalizeRuleIds, parseRuleIds, withExclusions } from '../../utils/siteForm'
import { errMsg, eventKindLabel, eventSummary, eventTagType, fmtTime } from '../../utils/format'

const props = defineProps<{ nodeId: string }>()
const message = useMessage()
const store = useEventsStore()

const PAGE_SIZE = 30
// agent 的事件环上限 500（crates/rooster-agent/src/state.rs MAX_EVENTS），
// hub 的 /events limit 允许到 1000；取满环再本地分页，历史不再被截到 100 条。
const HISTORY_LIMIT = 500

const history = ref<EventRecord[]>([])
const historyPage = ref(1)
const livePage = ref(1)
const liveAll = computed(() => store.feed.filter((f) => f.node_id === props.nodeId))

function pagesOf(total: number) {
  return Math.max(1, Math.ceil(total / PAGE_SIZE))
}
function pageOf(items: EventRecord[], page: number) {
  const start = (page - 1) * PAGE_SIZE
  return items.slice(start, start + PAGE_SIZE)
}
const liveRows = computed(() => pageOf(liveAll.value, livePage.value))
const historyRows = computed(() => pageOf(history.value, historyPage.value))

// 列表变短（feed 挤掉旧事件 / 重新拉取）时把越界的页码拉回第一页
watch([liveAll, history], ([liveTotal, historyTotal]) => {
  if (livePage.value > pagesOf(liveTotal.length)) livePage.value = 1
  if (historyPage.value > pagesOf(historyTotal.length)) historyPage.value = 1
})

// naive tag type → ops RTag tone（一次性映射，其余逻辑不动）
const TONE_MAP: Record<string, 'ok' | 'danger' | 'warn' | 'info' | 'muted'> = {
  success: 'ok',
  error: 'danger',
  warning: 'warn',
  info: 'info',
  default: 'muted',
}

async function load() {
  try {
    history.value = (await getNodeEvents(props.nodeId, HISTORY_LIMIT)).events
  } catch (e) {
    message.error(errMsg(e))
  }
}

function renderList(items: EventRecord[]) {
  return items.map((it) => ({
    key: it.ts + JSON.stringify(it.event),
    ts: fmtTime(it.ts),
    kind: it.event.kind,
    label: eventKindLabel(it.event.kind),
    tone: TONE_MAP[eventTagType(it.event.kind)] ?? 'muted',
    summary: eventSummary(it.event),
    block: blockInfo(it.event),
  }))
}

// ---------------- 误报加白（参雷池「消除误报」）----------------

/** 拦截事件的可加白信息:目标站点 + 本次命中的规则 id。 */
interface BlockInfo {
  site: string
  path: string
  ip: string
  ids: number[]
}

function blockInfo(ev: RoosterEvent): BlockInfo | null {
  if (ev.kind !== 'block') return null
  // 异常评分阈值阻断时 rule_id 不是数字，hits 才是清单。
  const ids = normalizeRuleIds([...(ev.hits ?? []), Number(ev.rule_id)])
  return { site: ev.site, path: ev.path ?? '', ip: ev.ip, ids }
}

const allowShow = ref(false)
const allowSaving = ref(false)
const allowSite = ref('')
const allowPath = ref('')
const allowIp = ref('')
const allowIds = ref('')

function openAllow(info: BlockInfo | null) {
  if (!info) return
  if (info.ids.length === 0) {
    message.error('这条事件没有可用的规则 id')
    return
  }
  allowSite.value = info.site
  allowPath.value = info.path
  allowIp.value = info.ip
  allowIds.value = info.ids.join(', ')
  allowShow.value = true
}

async function saveAllow() {
  const ids = parseRuleIds(allowIds.value)
  if (ids.length === 0) {
    message.error('至少要有一条规则 id')
    return
  }
  allowSaving.value = true
  try {
    const list = await getSites(props.nodeId)
    const site = list.find((s) => s.id === allowSite.value)
    if (!site) {
      message.error(`节点上没有站点 ${allowSite.value}，无法写入排除表`)
      return
    }
    const before = normalizeRuleIds(site.waf?.exclusions).length
    const next = withExclusions(site, ids)
    await putSite(props.nodeId, site.id, next)
    const after = normalizeRuleIds(next.waf?.exclusions).length
    message.success(`已为站点 ${site.id} 加白规则 ${ids.join('/')}（新增 ${after - before} 条）`)
    allowShow.value = false
  } catch (e) {
    message.error(errMsg(e))
  } finally {
    allowSaving.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="cols-2">
    <RPanel kicker="LIVE · WEBSOCKET" title="实时事件（WebSocket）">
      <div v-if="liveAll.length === 0" class="muted">暂无实时事件，等待推送…</div>
      <div v-for="it in renderList(liveRows)" :key="it.key + '-live'" class="ev-item">
        <span class="ev-ts mono">{{ it.ts }}</span>
        <RTag :tone="it.tone">{{ it.label }}</RTag>
        <span class="ev-text">{{ it.summary }}</span>
        <RButton v-if="it.block" size="sm" variant="link" @click="openAllow(it.block)">加白</RButton>
      </div>
      <RPager
        v-model:page="livePage"
        :page-count="pagesOf(liveAll.length)"
        :page-size="PAGE_SIZE"
        :total="liveAll.length"
      />
    </RPanel>
    <RPanel kicker="HISTORY · GET /events" title="历史事件（GET /events）">
      <div v-if="history.length === 0" class="muted">无历史事件</div>
      <div v-for="it in renderList(historyRows)" :key="it.key + '-his'" class="ev-item">
        <span class="ev-ts mono">{{ it.ts }}</span>
        <RTag :tone="it.tone">{{ it.label }}</RTag>
        <span class="ev-text">{{ it.summary }}</span>
        <RButton v-if="it.block" size="sm" variant="link" @click="openAllow(it.block)">加白</RButton>
      </div>
      <RPager
        v-model:page="historyPage"
        :page-count="pagesOf(history.length)"
        :page-size="PAGE_SIZE"
        :total="history.length"
      />
    </RPanel>

    <RModal v-model:show="allowShow" kicker="FALSE POSITIVE · 加白" title="消除误报：加白本次命中的规则" :width="560">
      <div class="form">
        <RField inline :label-width="90" label="SITE"><span class="mono">{{ allowSite }}</span></RField>
        <RField inline :label-width="90" label="PATH"><span class="mono">{{ allowPath || '—' }}</span></RField>
        <RField inline :label-width="90" label="SOURCE IP"><span class="mono">{{ allowIp }}</span></RField>
        <RField inline :label-width="90" label="RULE IDS" hint="逗号分隔；保存时并入该站点的 waf.exclusions">
          <RInput v-model="allowIds" mono />
        </RField>
        <p class="muted" style="font-size: 12px; margin: 0">
          加白作用于整个站点（不区分路径），写入后热加载即生效。若只想暂停检测，把站点 WAF 改为监控（detect）。
          由 Nginx 接入托管的站点需在站点页把 WAF 交回 Rooster 管理后才能改排除表。
        </p>
      </div>
      <template #footer>
        <RButton variant="ghost" @click="allowShow = false">取消</RButton>
        <RButton tone="primary" :loading="allowSaving" @click="saveAllow">保存加白</RButton>
      </template>
    </RModal>
  </div>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.ev-item {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 5px 0;
  border-bottom: 1px dashed var(--line);
  font-size: 12.5px;
}
.ev-ts {
  color: var(--faint);
  flex: none;
}
.ev-text {
  flex: 1;
}
</style>
