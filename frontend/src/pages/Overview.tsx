import { useState } from 'react'
import type { components } from '../api/schema'
import { useScanResult, type ScanResult } from '../api/useScanResult'
import SortableTable, { type Column } from '../components/SortableTable'
import TierBadge from '../components/TierBadge'
import Actions from './overview/Actions'
import { ScoreGauge, SourceBars, TierDonut } from './overview/charts'
import ScoringPanel from './overview/ScoringPanel'

type Asset = components['schemas']['CryptoAsset']
type Row = { rank: number; id: string; asset?: Asset }

const TOP = 10
const MISSING = 'asset missing from result'

const detail = (a: Asset) =>
  [a.usage, a.key_size ?? a.curve ?? a.parameter_set].filter((v) => v != null).join(' ')

const columns: Column<Row>[] = [
  { header: '#', sort: (r) => r.rank, cell: (r) => r.rank },
  { header: 'Tier', sort: (r) => r.asset?.tier ?? '', cell: (r) => (r.asset ? <TierBadge tier={r.asset.tier} /> : '') },
  {
    header: 'Asset',
    sort: (r) => r.asset?.canonical_name ?? r.id,
    cell: (r) => (r.asset ? r.asset.canonical_name : <span className="text-paper/60">{r.id} ({MISSING})</span>),
  },
  { header: 'Detail', sort: (r) => (r.asset ? detail(r.asset) : ''), cell: (r) => (r.asset ? detail(r.asset) : '') },
  {
    header: 'Sources',
    sort: (r) => (r.asset?.occurrences ?? []).length,
    cell: (r) => [...new Set((r.asset?.occurrences ?? []).map((o) => o.source_type))].join(', '),
  },
  { header: 'Occurrences', sort: (r) => (r.asset?.occurrences ?? []).length, cell: (r) => (r.asset?.occurrences ?? []).length },
  { header: 'Risk points', sort: (r) => r.asset?.risk_points ?? 0, cell: (r) => r.asset?.risk_points.toFixed(1) ?? '' },
]

function Tile({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="bg-panel p-4">
      <p className="text-[10px] uppercase tracking-widest text-paper/60">{label}</p>
      <p className="font-head text-4xl">{value}</p>
      <p className="mt-1 font-sub text-sm italic text-paper/60">{note}</p>
    </div>
  )
}

export default function Overview() {
  const { data, error } = useScanResult()
  const [scanned, setScanned] = useState<ScanResult>()
  const result = scanned ?? data

  if (error) return <p>Failed to load scan: {error}</p>
  if (!result) return <p className="text-paper/50">Loading</p>

  const { summary, assets } = result
  const errors = result.errors ?? []
  const scoredTotal = Object.values(summary.counts_by_tier).reduce((a, b) => a + b, 0)
  const byId = new Map(assets.map((a) => [a.asset_id, a]))
  const top: Row[] = summary.top_risks.slice(0, TOP).map((id, i) => ({ rank: i + 1, id, asset: byId.get(id) }))

  return (
    <div className="space-y-6">
      <header>
        <h1 className="mb-1 font-head text-2xl">Overview</h1>
        <p className="mb-4 font-sub italic text-paper/60">
          {assets.length} assets detected, {result.findings.length} findings, scan {result.scan_id}
        </p>
        <Actions onScanned={setScanned} />
        {errors.length > 0 && (
          <details className="mt-3 text-xs text-paper/80">
            <summary className="cursor-pointer">{errors.length} scan errors</summary>
            <ul className="mt-1 space-y-1 text-paper/60">
              {errors.map((e, i) => (
                <li key={i}>{e.detector}: {e.message}{e.path ? ` (${e.path})` : ''}</li>
              ))}
            </ul>
          </details>
        )}
      </header>

      {assets.length === 0 ? (
        <p className="text-paper/60">This scan found no cryptographic assets.</p>
      ) : (
        <>
          <section className="grid gap-4 md:grid-cols-3">
            <div className="flex flex-col items-center bg-panel p-4">
              <p className="self-start text-[10px] uppercase tracking-widest text-paper/60">Quantum risk score, higher is worse</p>
              <ScoreGauge score={summary.score} grade={summary.grade} />
            </div>
            <Tile label="Readiness" value={`${summary.readiness_pct.toFixed(1)}%`}
              note="Share of classified scored assets that are SAFE, UNKNOWN excluded" />
            <Tile label="Harvest now, decrypt later" value={String(summary.hndl_exposed_count)}
              note={`Exposed assets, of ${scoredTotal} scored. ${assets.length - scoredTotal} detected assets have no scoreable evidence`} />
          </section>

          <section className="grid gap-4 lg:grid-cols-2">
            <div className="bg-panel p-4">
              <h2 className="mb-3 text-[10px] uppercase tracking-widest text-paper/60">Scored assets by tier</h2>
              <TierDonut counts={summary.counts_by_tier} />
            </div>
            <div className="bg-panel p-4">
              <h2 className="mb-3 text-[10px] uppercase tracking-widest text-paper/60">By source</h2>
              <SourceBars bySource={summary.counts_by_source} scores={summary.score_by_source} />
              <p className="mt-3 font-sub text-sm italic text-paper/60">An asset seen by two sources counts in both rows.</p>
            </div>
          </section>

          <section className="bg-panel p-4">
            <h2 className="mb-3 text-[10px] uppercase tracking-widest text-paper/60">Top {Math.min(TOP, summary.top_risks.length)} risks</h2>
            <SortableTable rows={top} columns={columns} />
          </section>
        </>
      )}

      <ScoringPanel />
    </div>
  )
}
