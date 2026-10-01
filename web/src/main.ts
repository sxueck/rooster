import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { onUnauthorized } from './api/client'
import './style.css'

onUnauthorized(() => {
  void router.push('/login')
})

createApp(App).use(createPinia()).use(router).mount('#app')
