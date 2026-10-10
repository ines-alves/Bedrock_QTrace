import { useMemo } from 'react'
import { useScanResult } from '../api/useScanResult'
import { PHASES, buildRoadmap, plural } from './roadmap/model'

export default function Roadmap() {
  const { data, error } = useScanResult()
  const phases = useMemo(() => (data ? buildRoadmap(data) : []), [data])

  if (error) return <p>Failed to load scan: {error}</p>
  if (!data) return <p className="text-paper/50">Loading</p>
  if (!data.roadmap?.length) return <p className="text-paper/50">This scan has no migration roadmap.</p>

  return (
    <div className="space-y-6">
      <header>
        <h1 className="mb-1 font-head text-2xl">Roadmap</h1>
        <p className="font-sub italic text-paper/60">
          {data.roadmap.length} actions in four phases. Phases order the work; they are not regulatory deadlines.
        </p>
      </header>
      {phases.map((entries, phase) => (
        <section key={phase} className="bg-panel p-4">
          <h2 className="mb-3 text-[10px] uppercase tracking-widest text-paper/60">
            Phase {phase}: {PHASES[phase]} ({entries.length} actions)
          </h2>
          {entries.length === 0 && <p className="text-xs text-paper/40">No actions in this phase.</p>}
          <ul className="space-y-3 text-xs">
            {entries.map(({ item, assets, standards }) => (
              <li key={item.action} className="border-b border-paper/5 pb-3">
                <div className="flex flex-wrap items-baseline gap-x-3">
                  <span className="font-medium">{item.action}</span>
                  {standards.map((s) => (
                    <span key={s} className="border border-aqua px-2 py-0.5 text-[10px] uppercase tracking-widest text-aqua">{s}</span>
                  ))}
                  <span className="text-paper/50">{plural(item.occurrence_count, 'occurrence')}, {plural(assets.length, 'asset')}</span>
                </div>
                <details className="mt-1">
                  <summary className="cursor-pointer text-paper/50">Affected assets</summary>
                  <ul className="mt-1 space-y-0.5 text-paper/70">
                    {assets.map((a) => <li key={a.asset_id}>{a.canonical_name}</li>)}
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
