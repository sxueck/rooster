<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { RButton, RPageHeader, RPanel, RResult, RStatusDot, RTabs, RTag } from '../ui'
import { getNodes } from '../api/client'
import type { NodeInfo } from '../api/types'
import OverviewTab from '../components/tabs/OverviewTab.vue'
import PluginsTab from '../components/tabs/PluginsTab.vue'
import HardeningTab from '../components/tabs/HardeningTab.vue'
import SitesTab from '../components/tabs/SitesTab.vue'
import ForwardsTab from '../components/tabs/ForwardsTab.vue'
import BansTab from '../components/tabs/BansTab.vue'
import AllowlistTab from '../components/tabs/AllowlistTab.vue'
import EventsTab from '../components/tabs/EventsTab.vue'
import LayersTab from '../components/tabs/LayersTab.vue'
import HistoryTab from '../components/tabs/HistoryTab.vue'
import YamlTab from '../components/tabs/YamlTab.vue'
import NodeUpgradeControl from '../components/NodeUpgradeControl.vue'
import { errMsg, fmtRelative } from '../utils/format'

const route = useRoute()
const router = useRouter()
const nodeId = computed(() => String(route.params.id))
const node = ref<NodeInfo | null>(null)
const notFound = ref(false)
const tab = ref('overview')

const tabItems = [
  { key: 'overview', label: '概况' },
  { key: 'plugins', label: '插件' },
  { key: 'hardening', label: '加固' },
  { key: 'sites', label: '站点' },
  { key: 'forwards', label: '转发' },
  { key: 'bans', label: '封禁' },
  { key: 'allowlist', label: '白名单' },
  { key: 'events', label: '事件' },
  { key: 'layers', label: '配置' },
  { key: 'history', label: '历史' },
  { key: 'yaml', label: '高级 · YAML' },
]

async function loadNode() {
  try {
    const list = (await getNodes()).nodes
    node.value = list.find((n) => n.id === nodeId.value) ?? null
    notFound.value = node.value === null
  } catch (e) {
    notFound.value = true
    console.warn(errMsg(e))
  }
}
onMounted(loadNode)
</script>

<template>
  <div class="page page-wide">
    <RResult v-if="notFound" tone="danger" glyph="404" title="节点不存在" desc="该节点可能已被注销">
      <template #footer>
        <RButton tone="primary" @click="router.push('/nodes')">返回节点列表</RButton>
      </template>
    </RResult>

    <template v-else>
      <RPageHeader kicker="CLUSTER · NODE DETAIL" :title="nodeId" sub="节点详情">
        <template #extra>
          <NodeUpgradeControl v-if="node" :node-id="node.id" :online="node.online" />
          <RButton variant="ghost" size="sm" @click="router.back()">← 返回</RButton>
          <RStatusDot :tone="node?.online ? 'ok' : 'muted'" :pulse="!!node?.online">
            {{ node?.online ? '在线' : '离线' }}
          </RStatusDot>
          <RTag v-if="node">v{{ node.version }}</RTag>
          <RTag v-if="node?.pending_template" tone="warn">待下发：{{ node.pending_template }}</RTag>
          <RTag v-if="node">心跳 {{ fmtRelative(node.last_seen) }}</RTag>
        </template>
      </RPageHeader>

      <RPanel>
        <template v-if="node">
          <RTag v-for="(v, k) in node.labels" :key="k" class="label-tag">{{ k }}={{ v }}</RTag>
          <span class="muted num">config_hash: {{ node.config_hash }}</span>
        </template>
      </RPanel>

      <RTabs v-model="tab" :items="tabItems" class="detail-tabs">
        <template #default="{ seen }">
          <OverviewTab v-if="seen('overview')" v-show="tab === 'overview'" :node-id="nodeId" :node="node" />
          <PluginsTab v-if="seen('plugins')" v-show="tab === 'plugins'" :node-id="nodeId" />
          <HardeningTab v-if="seen('hardening')" v-show="tab === 'hardening'" :node-id="nodeId" />
          <SitesTab v-if="seen('sites')" v-show="tab === 'sites'" :node-id="nodeId" />
          <ForwardsTab v-if="seen('forwards')" v-show="tab === 'forwards'" :node-id="nodeId" />
          <BansTab v-if="seen('bans')" v-show="tab === 'bans'" :node-id="nodeId" />
          <AllowlistTab v-if="seen('allowlist')" v-show="tab === 'allowlist'" :node-id="nodeId" />
          <EventsTab v-if="seen('events')" v-show="tab === 'events'" :node-id="nodeId" />
          <LayersTab v-if="seen('layers')" v-show="tab === 'layers'" :node-id="nodeId" />
          <HistoryTab v-if="seen('history')" v-show="tab === 'history'" :node-id="nodeId" />
          <YamlTab v-if="seen('yaml')" v-show="tab === 'yaml'" :node-id="nodeId" />
        </template>
      </RTabs>
    </template>
  </div>
</template>

<style scoped>
.label-tag {
  margin-right: 8px;
}
.detail-tabs {
  margin-top: 12px;
}
</style>
