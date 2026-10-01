import { defineStore } from 'pinia'
import { login as apiLogin, getHub, getToken, setToken } from '../api/client'
import { useEventsStore } from './events'

/**
 * hub origin persisted in localStorage, token kept in sessionStorage
 * (cleared when the tab closes), secret_key never stored anywhere.
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
    logout() {
      setToken('')
      this.token = ''
      useEventsStore().disconnect()
    },
  },
})
