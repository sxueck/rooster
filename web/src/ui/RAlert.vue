<script setup lang="ts">
/** Inline alert strip: left tone rule + dense text. */
withDefaults(
  defineProps<{ tone?: 'info' | 'warn' | 'danger' | 'ok' }>(),
  { tone: 'info' },
)
</script>

<template>
  <div class="ral" :class="`ral-${tone}`" role="alert">
    <span class="micro ral-tag">{{ tone === 'danger' ? 'ERROR' : tone === 'warn' ? 'WARN' : tone === 'ok' ? 'OK' : 'INFO' }}</span>
    <div class="ral-text"><slot /></div>
  </div>
</template>

<style scoped>
.ral {
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 8px 12px;
  border: 1px solid var(--line);
  border-left-width: 3px;
  border-radius: var(--radius);
  background: var(--panel);
  font-size: 12.5px;
  line-height: 1.6;
}
.ral-text { min-width: 0; }
.ral-tag { flex: none; }
.ral-info { border-left-color: var(--info); }
.ral-warn { border-left-color: var(--warn); background: #fffdf6; }
.ral-danger { border-left-color: var(--danger); background: #fff7f7; }
.ral-ok { border-left-color: var(--ok); }
</style>
