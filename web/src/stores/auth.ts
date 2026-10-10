import { defineStore } from 'pinia'
import {
  login as apiLogin,
  logout as apiLogout,
  getHub,
  getToken,
  setToken,
} from '../api/client'
import { useEventsStore } from './events'

/**
 * hub origin and token persisted in localStorage (expiry is the hub-side
 * session-ttl, not the storage), secret_key never stored anywhere.
 */
export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: getToken(),
    hub: getHub(),
  }),
  actions: {
    async login(hub: string, secretKey: string) {
      const resp = await apiLogin(hub, secretKey)
      setToken(resp.token)
      this.token = resp.token
      this.hub = getHub()
      return resp
    },
    async logout() {
      try {
        await apiLogout()
      } catch {
        // Hub 不可达也要把本地会话关掉
      }
      setToken('')
      this.token = ''
      useEventsStore().disconnect()
    },
  },
})
