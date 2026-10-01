<script setup lang="ts">
/** Outcome block (kept / rolled back / not found). tone: ok | warn | danger | info */
withDefaults(
  defineProps<{
    tone?: 'ok' | 'warn' | 'danger' | 'info'
    glyph?: string
    title: string
    desc?: string
  }>(),
  { tone: 'info' },
)
</script>

<template>
  <div class="rr">
    <div class="rr-glyph" :class="`rr-${tone}`">{{ glyph ?? (tone === 'ok' ? '✓' : tone === 'warn' ? '!' : tone === 'danger' ? '✕' : 'i') }}</div>
    <div class="micro rr-kicker">{{ tone === 'ok' ? 'SUCCESS' : tone === 'warn' ? 'WARNING' : tone === 'danger' ? 'NOTICE' : 'INFO' }}</div>
    <h3 class="rr-title">{{ title }}</h3>
    <p v-if="desc" class="rr-desc">{{ desc }}</p>
    <div v-if="$slots.footer" class="rr-foot"><slot name="footer" /></div>
  </div>
</template>

<style scoped>
.rr {
  padding: 28px 16px;
  text-align: center;
}
.rr-glyph {
  width: 36px;
  height: 36px;
  line-height: 34px;
  margin: 0 auto 10px;
  border-radius: 50%;
  border: 1px solid currentColor;
  font-family: var(--mono);
  font-size: 16px;
}
.rr-ok { color: var(--ok); background: var(--ok-tint); }
.rr-warn { color: var(--warn); background: var(--warn-tint); }
.rr-danger { color: var(--danger); background: var(--danger-tint); }
.rr-info { color: var(--info); background: var(--info-tint); }
.rr-kicker { margin-bottom: 4px; }
.rr-title {
  margin: 0 0 6px;
  font-size: 15px;
  font-weight: 600;
}
.rr-desc {
  margin: 0 auto;
  max-width: 460px;
  color: var(--sub);
  font-size: 12.5px;
}
.rr-foot { margin-top: 16px; }
</style>
