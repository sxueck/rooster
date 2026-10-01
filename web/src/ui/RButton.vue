<script setup lang="ts">
/**
 * Ops button. variant: outline (default) | ghost (was naive `quaternary`)
 * | link (was naive `text: true`). tone: default | primary (dark ink CTA)
 * | ok | warn | danger | info.
 */
const props = withDefaults(
  defineProps<{
    variant?: 'outline' | 'ghost' | 'link'
    tone?: 'default' | 'primary' | 'ok' | 'warn' | 'danger' | 'info'
    size?: 'sm' | 'md'
    block?: boolean
    dashed?: boolean
    loading?: boolean
    disabled?: boolean
    title?: string
  }>(),
  { variant: 'outline', tone: 'default', size: 'md', loading: false, disabled: false },
)
const emit = defineEmits<{ (e: 'click', ev: MouseEvent): void }>()

function onClick(ev: MouseEvent) {
  if (props.disabled || props.loading) return
  ;(ev.currentTarget as HTMLElement).blur()
  emit('click', ev)
}
</script>

<template>
  <button
    class="rb"
    :class="[
      `rb-${variant}`,
      tone !== 'default' ? `rb-${tone}` : '',
      size === 'sm' ? 'rb-sm' : '',
      block ? 'rb-block' : '',
      dashed ? 'rb-dashed' : '',
      loading ? 'rb-loading' : '',
    ]"
    :disabled="disabled || loading"
    :title="title"
    @click="onClick"
  >
    <span v-if="loading" class="rb-spin" />
    <slot />
  </button>
</template>

<style scoped>
.rb {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 28px;
  padding: 0 12px;
  font-family: var(--sans);
  font-size: 12.5px;
  line-height: 1;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  cursor: pointer;
  white-space: nowrap;
  user-select: none;
}
.rb:hover:not(:disabled) { background: var(--tint); }
.rb:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.rb-sm {
  height: 24px;
  padding: 0 9px;
  font-size: 12px;
}
.rb-block { width: 100%; }
.rb-dashed { border-style: dashed; color: var(--sub); }

/* dark ink CTA */
.rb-primary {
  background: var(--ink);
  border-color: var(--ink);
  color: #fff;
}
.rb-primary:hover:not(:disabled) { background: #000; }

/* tone outlines */
.rb-danger { color: var(--danger); border-color: #e3b1b5; }
.rb-danger:hover:not(:disabled) { background: var(--danger-tint); }
.rb-warn { color: var(--warn); border-color: #dcc48f; }
.rb-warn:hover:not(:disabled) { background: var(--warn-tint); }
.rb-ok { color: var(--ok); border-color: #a9d3b6; }
.rb-ok:hover:not(:disabled) { background: var(--ok-tint); }
.rb-info { color: var(--info); border-color: #a8c8e8; }
.rb-info:hover:not(:disabled) { background: var(--info-tint); }

.rb-ghost {
  border-color: transparent;
  background: transparent;
  color: var(--sub);
}
.rb-ghost:hover:not(:disabled) { background: var(--tint); }

.rb-link {
  border-color: transparent;
  background: transparent;
  padding: 0 2px;
  height: auto;
  color: var(--link);
}
.rb-link:hover:not(:disabled) { text-decoration: underline; background: none; }
.rb-link.rb-danger { color: var(--danger); }
.rb-link.rb-warn { color: var(--warn); }

.rb-spin {
  width: 10px;
  height: 10px;
  border: 1.5px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: rb-rot 0.7s linear infinite;
  flex: none;
}
@keyframes rb-rot { to { transform: rotate(360deg); } }
</style>
