# Rooster Web Panel

Rooster hub 的管理面板（Vue 3 + TypeScript + Vite + Pinia + vue-router + Naive UI）。

## 开发

```bash
npm install
npm run dev        # 默认使用 mock 数据（VITE_ROOSTER_MOCK=1），无需真实 hub
```

- 默认 dev 走 `src/api/mock.ts`（3+ 节点、模板、封禁、事件、审计等假数据），登录页任意 ≥4 字符的 secret_key 即可进入。
- 连接真实 hub：把 `.env.development` 里 `VITE_ROOSTER_MOCK` 改为 `0`，然后启动本地 hub （`127.0.0.1:9443`，dev server 已配置 `/v0` → `http://127.0.0.1:9443` 的代理，含 WebSocket）， 登录页 Hub 地址留空即走同源代理；或填 `https://<hub>` 直连。
- 生产构建固定使用真实 fetch（`.env.production` 中 `VITE_ROOSTER_MOCK=0`）。
- 登录页 Hub 地址留空时使用本站代理；手填地址只接受 HTTP(S) origin（协议、主机、可选端口），例如 `https://hub.example.com:9443`，不能带 `/login`、`/v0`、查询参数或账号信息。
- 登录响应必须包含非空 token 和尚未到期的整数 `expires_at`；代理返回 200 HTML、空响应或异常 JSON 均会报错，不会显示登录成功。Hub 的 SPA 页面回退仅接受 GET/HEAD，错误路径上的 POST 不再返回页面。

## 构建

```bash
npm test           # 登录地址与响应校验的回归测试
npm run build      # vue-tsc 类型检查 + vite 打包，输出到 dist/
npm run preview    # 本地预览构建产物
```

## 结构

- `src/api/client.ts` — 所有 REST 调用集中在此（含 401 处理、WS 地址推导）
- `src/api/mock.ts` — mock 后端 + 模拟 WebSocket 推送
- `src/stores/` — auth（hub→localStorage，token→sessionStorage，secret 不落盘）、events（WS 事件流）
- `src/components/rollback.ts` + `RollbackModal.vue` — 全局回滚确认倒计时
- `src/pages/` — 总览 / 节点 / 模板 / 全局黑名单 / 事件 / WASM / WAF / 升级 / 审计
- GeoIP 数据来源：DB-IP Lite（CC BY 4.0）
