import { defineStore } from 'pinia'
import { MOCK_MODE, wsUrl } from '../api/client'
import { connectMockWs } from '../api/mock'
import type { EventRecord, NodeStatusMsg, WsPush } from '../api/types'

let sock: WebSocket | null = null
let closeMock: (() => void) | null = null
// reconnect backoff state (module level so two components can't double-schedule)
let reconnectTimer = 0
let attempts = 0
const RECONNECT_MAX_MS = 30_000

function isStatusMsg(m: WsPush): m is NodeStatusMsg {
  return (m as { type?: string }).type === 'node_status'
}

export const useEventsStore = defineStore('events', {
  state: () => ({
    feed: [] as EventRecord[],
    status: {} as Record<string, boolean>,
    connected: false,
  }),
  actions: {
    ingest(msg: WsPush) {
      if (isStatusMsg(msg)) {
        this.status[msg.node_id] = msg.online
        return
      }
      this.feed.unshift(msg)
      if (this.feed.length > 500) this.feed.length = 500
    },
    scheduleReconnect() {
      if (reconnectTimer) return
      const delay = Math.min(RECONNECT_MAX_MS, 1000 * 2 ** attempts)
      attempts += 1
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = 0
        this.connect()
      }, delay)
    },
    cancelReconnect() {
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer)
        reconnectTimer = 0
      }
      attempts = 0
    },
    connect() {
      // already open, a socket is pending, or a reconnect is armed: do not duplicate
      if (this.connected || sock || reconnectTimer) return
      if (MOCK_MODE) {
        this.connected = true
        closeMock = connectMockWs((m) => this.ingest(m))
        return
      }
      // re-read the session token on every attempt (wsUrl picks up a new session)
      try {
        sock = new WebSocket(wsUrl())
      } catch {
        sock = null
        this.connected = false
        this.scheduleReconnect()
        return
      }
      sock.onopen = () => {
        attempts = 0
        this.connected = true
      }
      sock.onmessage = (ev: MessageEvent) => {
        try {
          this.ingest(JSON.parse(String(ev.data)) as WsPush)
        } catch {
          /* 非 JSON 消息，忽略 */
        }
      }
      sock.onclose = () => {
        sock = null
        this.connected = false
        this.scheduleReconnect()
      }
      sock.onerror = () => {
        // onclose always follows onerror; only reflect reality here
        this.connected = false
      }
    },
    disconnect() {
      this.cancelReconnect()
      if (closeMock) {
        closeMock()
        closeMock = null
      }
      if (sock) {
        const s = sock
        sock = null
        s.onclose = null
        s.onerror = null
        try {
          s.close()
        } catch {
          /* noop */
        }
      }
      this.connected = false
    },
  },
})
