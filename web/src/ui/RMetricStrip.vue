<script setup lang="ts">
/** Horizontal metric strip with hairline separators (reference-image layout). */
</script>

<template>
  <div class="rs">
    <slot />
  </div>
</template>

<style scoped>
.rs {
  display: grid;
  grid-auto-flow: column;
  grid-auto-columns: minmax(0, 1fr);
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius);
}
.rs :deep(> *) {
  padding: 12px 16px;
  border-left: 1px solid var(--line);
  min-width: 0;
}
.rs :deep(> *:first-child) {
  border-left: none;
}
@media (max-width: 900px) {
  .rs { grid-auto-flow: row; }
  .rs :deep(> *) { border-left: none; border-top: 1px solid var(--line); }
  .rs :deep(> *:first-child) { border-top: none; }
}
</style>
