import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev server proxies /v0 to a local hub (https://127.0.0.1:9443, dev CA).
// Leave the hub field empty on the login page in dev to use this proxy;
// otherwise the panel talks to the hub origin directly.
// preview 用同一份代理配置,这样 `vite preview` 跑生产构建产物时也能连本地 hub。
const proxy = {
  '/v0': {
    target: 'https://127.0.0.1:9443',
    changeOrigin: true,
    ws: true,
    // dev-only self-signed hub cert
    secure: false,
  },
}

export default defineConfig({
  plugins: [vue()],
  server: { proxy },
  preview: { proxy },
  build: {
    outDir: 'dist',
  },
})
