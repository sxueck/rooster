/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** '1' = mock 后端；'0' = 真实 API */
  readonly VITE_ROOSTER_MOCK: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
