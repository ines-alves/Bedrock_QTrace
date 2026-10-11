import { useMemo } from 'react'
import { useScanResult } from '../api/useScanResult'
import { algorithmName } from '../components/algorithmName'
import Cta from '../components/Cta'
import PageHeader from '../components/PageHeader'
import { PHASES, buildRoadmap, plural } from './roadmap/model'

export default function Roadmap() {
  const { data, error } = useScanResult()
  const phases = useMemo(() => (data ? buildRoadmap(data) : []), [data])

  if (error) return <p>Failed to load scan: {error}</p>
  if (!data) return <p className="text-paper/50">Loading</p>
  if (!data.roadmap?.length) return <p className="text-paper/50">This scan has no migration roadmap.</p>

  return (
    <div className="space-y-6">
      <PageHeader
        title={`${data.roadmap.length} actions, ${phases[0].length} to fix first.`}
        lead="Ordered by urgency. The dates are planning targets, not deadlines."
      >
        <Cta primary href="/api/report.md" download="quantumtrace-report.md">Download the report</Cta>
        <Cta href="/api/cbom" download="quantumtrace-cbom.json">Download the CBOM</Cta>
      </PageHeader>
      {phases.map((entries, phase) => (
        <section key={phase} className="glass p-5">
          <h2 className="mb-3 font-head text-xl font-semibold">
            {PHASES[phase]} ({entries.length})
          </h2>
          {entries.length === 0 && <p className="text-base text-paper/50">No actions in this phase.</p>}
          <ul className="space-y-1 text-lg">
            {entries.map(({ item, assets, standards }) => (
              <li key={item.action} className="border-b border-paper/10 py-4">
                <div className="flex flex-wrap items-baseline gap-x-3">
                  <span className="font-medium">{item.action}</span>
                  {standards.map((s) => (
                    <span key={s} className="rounded-full border border-aqua px-3 py-1 text-sm font-medium text-aqua">{s}</span>
                  ))}
                  <span className="text-base text-paper/60">{plural(item.occurrence_count, 'occurrence')}, {plural(assets.length, 'asset')}</span>
                </div>
                <details className="mt-1">
                  <summary className="cursor-pointer text-base text-paper/60">Affected assets</summary>
                  <ul className="mt-2 space-y-1 text-base text-paper/70">
                    {assets.map((a) => <li key={a.asset_id}>{algorithmName(a.canonical_name)}</li>)}
                  </ul>
                </details>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  )
}
