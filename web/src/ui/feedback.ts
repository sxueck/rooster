/**
 * Imperative feedback primitives (toast + confirm dialog), naive-ui-free.
 * Exposes `useMessage()` / `useDialog()` with the same call shape the pages
 * used before, so page logic stays untouched:
 *   message.success('...')            dialog.warning({ title, content, ... })
 * Hosts are appended to <body> on first use — no provider wiring needed.
 */
import './feedback.css'

export type Tone = 'success' | 'error' | 'warning' | 'info'

// ---------------- message ----------------

let msgWrap: HTMLElement | null = null

function msgHost(): HTMLElement {
  if (msgWrap) return msgWrap
  msgWrap = document.createElement('div')
  msgWrap.className = 'rf-msg-wrap'
  document.body.appendChild(msgWrap)
  return msgWrap
}

function pushMessage(tone: Tone, text: string): void {
  const host = msgHost()
  const el = document.createElement('div')
  el.className = `rf-msg rf-msg-${tone}`
  const ts = document.createElement('span')
  ts.className = 'rf-msg-ts'
  ts.textContent = new Date().toTimeString().slice(0, 8)
  const body = document.createElement('span')
  body.textContent = text
  el.append(ts, body)
  host.appendChild(el)
  requestAnimationFrame(() => el.classList.add('rf-in'))
  window.setTimeout(() => {
    el.classList.add('rf-out')
    window.setTimeout(() => el.remove(), 220)
  }, 3600)
  while (host.children.length > 5) host.firstElementChild?.remove()
}

export interface MessageApi {
  success(text: string): void
  error(text: string): void
  warning(text: string): void
  info(text: string): void
}

export function useMessage(): MessageApi {
  return {
    success: (t) => pushMessage('success', t),
    error: (t) => pushMessage('error', t),
    warning: (t) => pushMessage('warning', t),
    info: (t) => pushMessage('info', t),
  }
}

// ---------------- dialog ----------------

export interface DialogOptions {
  title: string
  content?: string
  positiveText?: string
  negativeText?: string
  onPositiveClick?: () => void | boolean | Promise<void | boolean>
}

function openConfirm(tone: Tone, opts: DialogOptions): void {
  const mask = document.createElement('div')
  mask.className = 'rf-dlg-mask'
  const box = document.createElement('div')
  box.className = 'rf-dlg'
  const positive = opts.positiveText ?? '确定'
  const negative = opts.negativeText ?? '取消'
  box.innerHTML = `
    <div class="rf-dlg-head micro">CONFIRM</div>
    <div class="rf-dlg-title"></div>
    <div class="rf-dlg-body"></div>
    <div class="rf-dlg-foot">
      <button class="rf-btn rf-btn-ghost" data-act="neg"></button>
      <button class="rf-btn" data-act="pos"></button>
    </div>`
  const q = (sel: string): HTMLElement => {
    const el = box.querySelector<HTMLElement>(sel)
    if (!el) throw new Error(`dialog template missing ${sel}`)
    return el
  }
  q('.rf-dlg-title').textContent = opts.title
  q('.rf-dlg-body').textContent = opts.content ?? ''
  const negBtn = q('[data-act=neg]')
  const posBtn = q('[data-act=pos]')
  negBtn.textContent = negative
  posBtn.textContent = positive
  posBtn.classList.add(tone === 'error' || tone === 'warning' ? 'rf-btn-danger' : 'rf-btn-primary')
  const close = () => {
    mask.classList.add('rf-out')
    window.setTimeout(() => mask.remove(), 160)
    document.removeEventListener('keydown', onKey)
  }
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') close()
  }
  negBtn.addEventListener('click', close)
  mask.addEventListener('mousedown', (e) => {
    if (e.target === mask) close()
  })
  posBtn.addEventListener('click', async () => {
    const r = await opts.onPositiveClick?.()
    if (r !== false) close()
  })
  document.addEventListener('keydown', onKey)
  mask.appendChild(box)
  mask.classList.add('rf-in')
  document.body.appendChild(mask)
  posBtn.focus()
}

export interface DialogApi {
  warning(opts: DialogOptions): void
  error(opts: DialogOptions): void
}

export function useDialog(): DialogApi {
  return {
    warning: (o) => openConfirm('warning', o),
    error: (o) => openConfirm('error', o),
  }
}
