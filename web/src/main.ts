import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { onUnauthorized } from './api/client'
import './style.css'

onUnauthorized(() => {
  const to = router.currentRoute.value
  if (to.meta.public) return
  void router.push({ name: 'login', query: { reason: 'expired', redirect: to.fullPath } })
})

createApp(App).use(createPinia()).use(router).mount('#app')
