import { useMemo, useState } from 'react'
import { useScanResult } from '../api/useScanResult'
import FileGroup from './code-config/FileGroup'
import FilterBar from './code-config/FilterBar'
import {
  TIERS,
  allLanguages,
  applyFilters,
  buildRows,
  groupByFile,
  summarize,
  type Filters,
} from './code-config/model'

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

export default function CodeConfig() {
  const { data, error } = useScanResult()
  const rows = useMemo(() => (data ? buildRows(data) : []), [data])
  const languages = useMemo(() => allLanguages(rows), [rows])
  // undefined until the user touches a filter: everything is shown by default, whatever the data holds.
  const [override, setOverride] = useState<Filters>()

  if (error) return <p>Failed to load scan: {error}</p>
  if (!data) return <p className="text-paper/50">Loading</p>
  if (rows.length === 0) {
    return <p className="text-paper/50">No code or config findings in this scan.</p>
  }

  const filters: Filters = override ?? {
    languages: new Set(languages),
    tiers: new Set(TIERS),
    includeTestCode: true,
    includeNonCrypto: true,
  }
  const visible = applyFilters(rows, filters)
  const groups = groupByFile(visible)
  const s = summarize(visible)

  return (
    <>
      <h1 className="mb-2 font-head text-4xl font-bold leading-tight">Code &amp; Config</h1>
      <p className="mb-8 font-sub text-lg italic text-paper/70">
        {plural(s.findings, 'finding', 'findings')} in {plural(s.files, 'file', 'files')}
        {` · ${s.byTier.CRITICAL} critical, ${s.byTier.MEDIUM} medium, ${s.byTier.UNKNOWN} unknown, ${s.byTier.SAFE} safe`}
        {` · ${plural(s.warnings, 'warning', 'warnings')}, ${plural(s.libraries, 'library', 'libraries')}, ${s.testCode} in test code`}
      </p>
      <FilterBar languages={languages} filters={filters} onChange={setOverride} />
      {groups.length === 0 ? (
        <p className="text-paper/50">No findings match the current filters.</p>
      ) : (
        groups.map((g) => <FileGroup key={g.file} group={g} />)
      )}
    </>
  )
}
