import type { VNode } from 'vue'

/** One column of RTable. `render` may return a VNode, string or number. */
export interface RColumn<T = any> {
  key: string
  /** Header text — English uppercase micro label preferred (e.g. 'LAST SEEN'). */
  title: string
  width?: number | string
  align?: 'left' | 'right' | 'center'
  /** Cell falls back to monospace when no custom render is given. */
  mono?: boolean
  sortable?: boolean
  render?: (row: T, index: number) => VNode | string | number
}

export interface SelectOption {
  label: string
  value: string | number
}
