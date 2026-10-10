# Rooster ops UI — component contract (for page migration)

Design language: hairline dividers, uppercase English micro labels, monospace data, dense flat panels. Chinese stays for body text, buttons, titles; **table column titles and section kickers are English uppercase**.

Import everything from the barrel only:

```ts
import { RButton, RTable, useMessage, type RColumn } from '../ui'   // pages
import { ... } from '../../ui'                                       // tabs/components
```

Never import `naive-ui` — it is being removed.

## Reference pages (read first)

- `src/pages/Nodes.vue` — table + selection + modals + h() render cells
- `src/pages/Login.vue` — forms with RField/RInput
- `src/App.vue` — shell

## naive-ui → ops mapping

| old | new | notes |
| --- | --- | --- |
| `NPageHeader title sub` | `RPageHeader kicker title sub` | kicker = English uppercase, e.g. `kicker="SECURITY · EVENTS"`; actions in `#extra` slot |
| `NCard title / #header-extra / #footer` | `RPanel title kicker / #actions / #footer` | `flush` prop removes body padding (for tables) |
| `NDataTable` | `RTable` | `columns: RColumn[]`, `:rows`, `:row-key`, `:loading`, `selectable` + `v-model:checked`, `:page-size` (internal pagination), `:max-height`, `empty-text` |
| `NStatistic label value` | `RMetric label value suffix tone` | label must be English uppercase; wrap row in `RMetricStrip` for the hairline strip layout |
| `NTag type size bordered` | `RTag tone dot` | tone: `muted\|ok\|warn\|danger\|info`; old `type:'success'`→`tone:'ok'`, `'error'`→`'danger'`, `'warning'`→`'warn'`, `'info'`→`'info'`, `'default'`→omit |
| `NButton text:true type:'primary'` | `RButton variant="link"` | `type:'error'`→`tone="danger"`, `type:'warning'`→`tone="warn"` |
| `NButton quaternary` | `RButton variant="ghost"` | |
| `NButton type:'primary'` (solid) | `RButton tone="primary"` | |
| `NButton size:'small'` | `RButton size="sm"` | |
| `NModal :show @update:show` + inner NCard | `RModal v-model:show kicker title :width` | slots: default + `#footer` |
| `NInput v-model:value` | `RInput v-model` | `class="mono"`→`mono` prop; `:autosize="{minRows,maxRows}"`→`:auto-rows="[min,max]"`; `type="textarea"` same; `@keyup.enter` supported |
| `NInputNumber` | `RNumberInput v-model :min :max :width` | width as number px |
| `NSelect :options v-model:value` | `RSelect v-model :options placeholder clearable :width` | options `{label,value}` same |
| `NSwitch` | `RSwitch v-model` | |
| `NCheckbox v-model:checked` | `RCheckbox v-model` | |
| `NProgress type:line :percentage :status` | `RProgress :percentage tone` | tone `'success'`→`'ok'`, `'error'`→`'danger'` |
| `NAlert type` | `RAlert tone` | `error`→`danger`, `warning`→`warn` |
| `NEmpty description` | `REmpty text` | |
| `NSpin size` | `RSpinner` | optional default slot = inline text beside ring |
| `NResult status title desc #footer` | `RResult tone glyph title desc #footer` | `success`→`tone:'ok'`, `warning`→`'warn'`, `404`→`tone:'danger' glyph:'404'` |
| `NTabs/NTabPane display-directive="show:lazy"` | `RTabs v-model :items` + scoped `{ seen }` | see below |
| `NSpace` | `<div class="row">` / `.row-tight` | |
| `NGrid :cols NGi` | `<div class="cols-2\|3\|4">` | |
| `NForm/NFormItem` | plain divs + `RField label` (English uppercase label) | inline filter rows: `class="row"` + `RField inline label-width` |
| `NDatePicker type="datetimerange"` | two `RInput type="text" mono` for `datetime-local` values | convert with `new Date(v).getTime()`; empty string = unset |
| `NList/NListItem clickable` | plain buttons with hairline rows (see HistoryTab target below) | |
| `NButtonGroup + NRadioGroup` | segmented control: `.seg` utility or RButton row | |
| `useMessage()/useDialog()` from naive | same names from `'../ui'` | identical call API (`dialog.warning({title,content,positiveText,negativeText,onPositiveClick})`) |
| `zhCN/dateZhCN` | delete | no locale provider anymore |

## RTable column shape

```ts
import type { RColumn } from '../ui'
const cols: RColumn[] = [
  { title: 'NODE', key: 'id', width: 200, mono: true, sortable: true,
    render: (row) => h(RTag, { tone: 'ok', dot: true }, { default: () => row.id }) },
]
```

`render` returns VNode | string | number; no render → raw `row[key]` (auto stringified; `mono` flag for data columns). Alignment: `align: 'right'` for numeric columns.

## RTabs lazy pattern (NodeDetail)

```vue
<RTabs v-model="tab" :items="[{ key: 'overview', label: '概况' }, ...]">
  <template #default="{ seen }">
    <OverviewTab v-if="seen('overview')" v-show="tab === 'overview'" :node-id="nodeId" :node="node" />
  </template>
</RTabs>
```

## Page skeleton

```vue
<div class="page page-wide">
  <RPageHeader kicker="DOMAIN · NAME" title="中文标题" sub="一句话说明">
    <template #extra>…buttons…</template>
  </RPageHeader>
  <RPanel title="中文区块名" kicker="SECTION" flush>
    <template #actions>…</template>
    <RTable … />
  </RPanel>
</div>
```

## Style rules

- Use CSS vars from `src/style.css` (`--ink --sub --faint --line --line-strong --panel --tint --ok --danger --warn --info --mono`). No hardcoded greys/greens.
- Data (ids, hashes, IPs, timestamps, numbers, commands) → `class="mono"` or `class="num"` / RTable `mono: true`.
- Section/table headers: English uppercase micro labels. Buttons & prose: Chinese.
- Status: `RStatusDot` (dot + text) for online/offline/live states; `RTag` for categorical chips.
- Keep ALL business logic, API calls, event handling identical — visual layer only.
- Do not touch files outside your batch. Do not run `npm run build` / `vue-tsc -b` (parallel forks share the tsbuildinfo; the orchestrator integrates). You may run `npx vue-tsc --noEmit` and filter output to your own files.
