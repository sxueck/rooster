<script setup lang="ts">
/** White hairline panel replacing naive NCard. kicker = English micro label. */
withDefaults(
  defineProps<{
    title?: string
    kicker?: string
    /** remove body padding (tables, full-bleed content) */
    flush?: boolean
  }>(),
  { flush: false },
)
</script>

<template>
  <section class="rp">
    <header v-if="title || kicker || $slots.actions || $slots.header" class="rp-head">
      <slot name="header">
        <span v-if="kicker" class="micro">{{ kicker }}</span>
        <h3 v-if="title" class="rp-title">{{ title }}</h3>
      </slot>
      <div class="rp-actions">
        <slot name="actions" />
      </div>
    </header>
    <div class="rp-body" :class="{ 'rp-flush': flush }">
      <slot />
    </div>
    <footer v-if="$slots.footer" class="rp-foot">
      <slot name="footer" />
    </footer>
  </section>
</template>

<style scoped>
.rp {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius);
}
.rp-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-head);
  border-radius: var(--radius) var(--radius) 0 0;
}
.rp-title {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--ink);
  white-space: nowrap;
}
.rp-actions {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
}
.rp-body { padding: 14px; }
.rp-flush { padding: 0; }
.rp-foot {
  padding: 10px 14px;
  border-top: 1px solid var(--line);
}
</style>
