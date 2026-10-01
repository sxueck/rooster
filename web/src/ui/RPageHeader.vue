<script setup lang="ts">
/** Page header: English micro kicker, Chinese title, optional sub + actions. */
withDefaults(
  defineProps<{
    kicker?: string
    title: string
    sub?: string
  }>(),
  { kicker: '' },
)
</script>

<template>
  <div class="rh">
    <div class="rh-left">
      <div v-if="kicker" class="micro">{{ kicker }}</div>
      <div class="rh-line">
        <h1 class="rh-title">{{ title }}</h1>
        <span v-if="sub" class="rh-sub">{{ sub }}</span>
      </div>
    </div>
    <div class="rh-actions">
      <slot name="extra" />
    </div>
  </div>
</template>

<style scoped>
.rh {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 12px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--line-strong);
}
.rh-line {
  display: flex;
  align-items: baseline;
  gap: 12px;
  flex-wrap: wrap;
}
.rh-title {
  margin: 0;
  font-size: 19px;
  font-weight: 650;
  letter-spacing: -0.01em;
}
.rh-sub {
  color: var(--faint);
  font-size: 12.5px;
}
.rh-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
}
</style>
