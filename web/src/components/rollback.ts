import { reactive } from 'vue'

/**
 * Global rollback-confirmation state. Any management write that returns
 * `confirm: {token, "rollback-in"}` arms this; RollbackModal renders the
 * countdown, health-checks the expected hash and posts apply/confirm
 * before the deadline.
 */
export interface RollbackState {
  visible: boolean
  nodeId: string
  token: string
  /** epoch seconds — the real auto-rollback deadline, always finite. */
  deadline: number
  remain: number
  /** config hash expected to be live after the write, if the caller knows it. */
  expectedHash: string | null
  phase: 'counting' | 'confirming' | 'kept' | 'rolled'
}

export const rollback = reactive<RollbackState>({
  visible: false,
  nodeId: '',
  token: '',
  deadline: 0,
  remain: 0,
  expectedHash: null,
  phase: 'counting',
})

/** Tolerant read of the confirm countdown: agent emits "rollback-in". */
export function confirmRollbackIn(confirm: unknown): number {
  if (!confirm || typeof confirm !== 'object') return 0
  const v = (confirm as Record<string, unknown>)['rollback-in'] ??
    (confirm as Record<string, unknown>).rollback_in
  const n = typeof v === 'number' ? v : Number(v)
  return Number.isFinite(n) ? n : 0
}

export function armRollback(
  nodeId: string,
  token: string,
  rollbackIn: number,
  expectedHash: string | null = null,
): void {
  // Non-finite or non-positive countdown = already expired / immediate:
  // never arm "forever", surface the real (immediate) deadline.
  const secs = Number.isFinite(rollbackIn) && rollbackIn > 0 ? Math.floor(rollbackIn) : 0
  rollback.nodeId = nodeId
  rollback.token = token
  rollback.expectedHash = expectedHash
  rollback.deadline = Math.floor(Date.now() / 1000) + secs
  rollback.remain = secs
  rollback.phase = 'counting'
  rollback.visible = true
}

export function closeRollback(): void {
  rollback.visible = false
}
