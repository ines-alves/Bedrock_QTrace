import { useMemo } from 'react'
import Cta from '../components/Cta'
import PageHeader from '../components/PageHeader'
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
      <PageHeader
        title={`${cbom.components.length} components, ${validation.valid ? 'valid CycloneDX 1.6' : `${validation.errors.length} validation errors`}.`}
        lead="The inventory every other tool can read, with the NIST standard to migrate to."
      >
        <Cta primary href="/api/cbom" download="cbom.json">Download cbom.json</Cta>
        <Cta to="/roadmap">See the migration plan</Cta>
      </PageHeader>
      {!validation.valid && (
        <ul className="space-y-1 text-sm text-paper/60">
          {validation.errors.map((e) => <li key={e}>{e}</li>)}
        </ul>
      )}
      <section className="glass p-5">
        <h2 className="mb-3 font-head text-xl font-semibold">What it contains</h2>
        <ul className="flex flex-wrap gap-x-12 gap-y-4 text-lg">
          {summary.byType.map(([type, count]) => (
            <li key={type}><span className="font-head text-5xl font-bold">{count}</span> <span className="text-paper/60">{type}</span></li>
          ))}
        </ul>
      </section>
      <section className="glass p-5">
        <h2 className="mb-3 font-head text-xl font-semibold">Standards it cites</h2>
        <SortableTable large rows={summary.standards} columns={columns} />
      </section>
    </div>
  )
}
