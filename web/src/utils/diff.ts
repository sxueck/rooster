/** Minimal line-based diff (LCS with common prefix/suffix trim) + unified-diff helpers. */

export interface DiffLine {
  type: 'ctx' | 'add' | 'del' | 'hunk'
  text: string
}

export function diffLines(a: string, b: string): DiffLine[] {
  const al = a.split('\n')
  const bl = b.split('\n')
  const out: DiffLine[] = []

  let start = 0
  while (start < al.length && start < bl.length && al[start] === bl[start]) start++
  let ae = al.length - 1
  let be = bl.length - 1
  while (ae >= start && be >= start && al[ae] === bl[be]) {
    ae--
    be--
  }

  for (let i = 0; i < start; i++) out.push({ type: 'ctx', text: al[i] })

  const asub = al.slice(start, ae + 1)
  const bsub = bl.slice(start, be + 1)
  const n = asub.length
  const m = bsub.length

  if (n * m > 400_000) {
    // Too large for DP: keep order, mark wholesale replacement.
    for (const t of asub) out.push({ type: 'del', text: t })
    for (const t of bsub) out.push({ type: 'add', text: t })
  } else {
    const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0))
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        dp[i][j] = asub[i] === bsub[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
      }
    }
    let i = 0
    let j = 0
    while (i < n && j < m) {
      if (asub[i] === bsub[j]) {
        out.push({ type: 'ctx', text: asub[i] })
        i++
        j++
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        out.push({ type: 'del', text: asub[i] })
        i++
      } else {
        out.push({ type: 'add', text: bsub[j] })
        j++
      }
    }
    while (i < n) out.push({ type: 'del', text: asub[i++] })
    while (j < m) out.push({ type: 'add', text: bsub[j++] })
  }

  for (let k = ae + 1; k < al.length; k++) out.push({ type: 'ctx', text: al[k] })
  return out
}

/** Render DiffLines as unified-diff style text with @@ hunk headers. */
export function toUnifiedDiff(a: string, b: string, context = 3): string {
  const lines = diffLines(a, b)
  const changed = lines.map((l, i) => (l.type === 'ctx' ? -1 : i)).filter((i) => i >= 0)
  if (changed.length === 0) return ''

  const ranges: Array<[number, number]> = []
  let s = Math.max(0, changed[0] - context)
  let e = Math.min(lines.length - 1, changed[0] + context)
  for (const i of changed.slice(1)) {
    if (i - context <= e + 1) {
      e = Math.min(lines.length - 1, i + context)
    } else {
      ranges.push([s, e])
      s = Math.max(0, i - context)
      e = Math.min(lines.length - 1, i + context)
    }
  }
  ranges.push([s, e])

  const out: string[] = ['--- a/config', '+++ b/config']
  for (const [hs, he] of ranges) {
    const seg = lines.slice(hs, he + 1)
    const aCount = seg.filter((l) => l.type !== 'add').length
    const bCount = seg.filter((l) => l.type !== 'del').length
    out.push(`@@ -${hs + 1},${aCount} +${hs + 1},${bCount} @@`)
    for (const l of seg) {
      out.push((l.type === 'add' ? '+' : l.type === 'del' ? '-' : ' ') + l.text)
    }
  }
  return out.join('\n')
}

/** Parse unified-diff text (server-provided or generated) into colored lines. */
export function parseUnified(text: string): DiffLine[] {
  const out: DiffLine[] = []
  for (const line of text.split('\n')) {
    if (line.startsWith('--- ') || line.startsWith('+++ ')) continue
    if (line.startsWith('@@')) out.push({ type: 'hunk', text: line })
    else if (line.startsWith('+')) out.push({ type: 'add', text: line.slice(1) })
    else if (line.startsWith('-')) out.push({ type: 'del', text: line.slice(1) })
    else out.push({ type: 'ctx', text: line.replace(/^ /, '') })
  }
  return out
}
