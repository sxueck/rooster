<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { RButton, RField, RInput, RPanel, useMessage } from '../ui'
import { useAuthStore } from '../stores/auth'
import { useEventsStore } from '../stores/events'
import { errMsg } from '../utils/format'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const events = useEventsStore()
const message = useMessage()

// hub 与 token 预填/持久于 localStorage；secret_key 只在本次请求中使用，永不落盘。
const hub = ref(auth.hub)
const secret = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  if (secret.value === '') {
    error.value = '请输入 secret_key'
    return
  }
  loading.value = true
  try {
    await auth.login(hub.value, secret.value)
    events.connect()
    message.success('登录成功')
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.push(redirect)
  } catch (e) {
    error.value = errMsg(e)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="wrap">
    <RPanel class="card" kicker="ROOSTER · OPS CONSOLE">
      <template #header>
        <div class="brand">
          <span class="brand-mark">▚</span>
          <div>
            <div class="brand-name">ROOSTER</div>
            <div class="micro">PORT PROTECTION · HUB</div>
          </div>
        </div>
      </template>

      <div class="stack">
        <details class="advanced">
          <summary class="micro">高级选项 · Hub 地址</summary>
          <RField label="HUB · 地址">
            <RInput
              v-model="hub"
              mono
              width="100%"
              placeholder="https://hub.example.com（留空 = 使用本站代理）"
              @keyup.enter="submit"
            />
          </RField>
        </details>
        <RField label="SECRET_KEY · 密钥">
          <RInput
            v-model="secret"
            type="password"
            mono
            width="100%"
            placeholder="管理员密钥"
            @keyup.enter="submit"
          />
        </RField>
        <div v-if="error" class="err mono">{{ error }}</div>
        <RButton tone="primary" block :loading="loading" @click="submit">登 录</RButton>
      </div>

      <p class="muted note">
        Hub 地址与登录 token 保存在本机 localStorage，会话有效期 1 个月（Hub 重启不掉线）；secret_key 仅用于本次登录，不会被存储。
      </p>
    </RPanel>
  </div>
</template>

<style scoped>
.wrap {
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg);
}
.card {
  width: 400px;
  max-width: calc(100vw - 32px);
}
.advanced {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.advanced summary {
  cursor: pointer;
  width: fit-content;
}
.advanced summary:hover {
  color: var(--ink);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand-mark {
  font-size: 22px;
  color: var(--danger);
  line-height: 1;
}
.brand-name {
  font-family: var(--mono);
  font-weight: 700;
  font-size: 16px;
  letter-spacing: 0.06em;
  line-height: 1.2;
}
.stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.err {
  font-size: 12px;
  color: var(--danger);
  border: 1px solid #e6bfc2;
  border-left: 3px solid var(--danger);
  background: #fff7f7;
  border-radius: 3px;
  padding: 6px 10px;
}
.note {
  margin-top: 14px;
  line-height: 1.6;
}
</style>
