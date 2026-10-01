/**
 * Ambient shim so plain TypeScript language servers (without the Vue plugin)
 * can resolve `*.vue` imports from `.ts` files. vue-tsc resolves real SFCs
 * first, so precise prop typing is unaffected.
 */
declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>
  export default component
}
