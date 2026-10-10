import { useMemo } from 'react'
import SortableTable, { type Column } from '../components/SortableTable'
import { summarize, useCbom, type StandardRow } from './cbom/model'

const columns: Column<StandardRow>[] = [
  { header: 'Standard', sort: (r) => r.standard, cell: (r) => r.standard },
  { header: 'Algorithm', sort: (r) => r.algorithm, cell: (r) => r.algorithm },
  { header: 'Purpose', sort: (r) => r.purpose, cell: (r) => r.purpose },
  {
    header: 'Components recommending it',
    sort: (r) => r.count,
    cell: (r) => (r.count > 0 ? r.count : <span className="text-paper/40">0, never recommended</span>),
  },
  { header: 'Recommended replacements', sort: (r) => r.targets.join(), cell: (r) => r.targets.join(', ') },
]

export default function Cbom() {
  const { data, error } = useCbom()
  const summary = useMemo(() => (data ? summarize(data.cbom.components) : undefined), [data])

  if (error) return <p>Failed to load CBOM: {error}</p>
  if (!data || !summary) return <p className="text-paper/50">Loading</p>
  const { cbom, validation } = data

  return (
    <div className="space-y-6">
      <header>
        <h1 className="mb-1 font-head text-2xl">CBOM</h1>
        <p className="mb-3 font-sub italic text-paper/60">
          CycloneDX {cbom.specVersion}, {cbom.components.length} components,{' '}
          {validation.valid ? 'strict validation passes' : `${validation.errors.length} validation errors`}
        </p>
        <a href="/api/cbom" download="cbom.json" className="border border-aqua px-3 py-1 text-[10px] uppercase tracking-widest text-aqua">
          Download cbom.json
        </a>
        {!validation.valid && (
          <ul className="mt-3 space-y-1 text-xs text-paper/60">
            {validation.errors.map((e) => <li key={e}>{e}</li>)}
          </ul>
        )}
      </header>
      <section className="bg-panel p-4">
        <h2 className="mb-3 text-[10px] uppercase tracking-widest text-paper/60">Components by type</h2>
        <ul className="flex flex-wrap gap-x-8 gap-y-2 text-xs">
          {summary.byType.map(([type, count]) => (
            <li key={type}><span className="font-head text-2xl">{count}</span> <span className="text-paper/60">{type}</span></li>
          ))}
        </ul>
      </section>
      <section className="bg-panel p-4">
        <h2 className="mb-3 text-[10px] uppercase tracking-widest text-paper/60">Standards cited by the recommendations</h2>
        <SortableTable rows={summary.standards} columns={columns} />
        <p className="mt-3 font-sub text-sm italic text-paper/60">
          Each count is the components whose first migration target cites that standard, as quantumtrace:recommendedStandard.
        </p>
      </section>
    </div>
  )
}
