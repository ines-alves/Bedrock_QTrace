import { useState } from 'react'
import type { components } from '../api/schema'
import { useScanResult } from '../api/useScanResult'
import { algorithmName } from '../components/algorithmName'
import Cta from '../components/Cta'
import PageHeader from '../components/PageHeader'
import SortableTable, { type Column } from '../components/SortableTable'
import TierBadge from '../components/TierBadge'
import { ScoreGauge, SourceBars, TierDonut } from './overview/charts'
import { testCodeShare, testOnlyIds, topRisks, type Row } from './overview/model'
import ScoringPanel from './overview/ScoringPanel'

type Asset = components['schemas']['CryptoAsset']

const TOP = 10
const MISSING = 'asset missing from result'

const detail = (a: Asset) =>
  [a.usage, a.key_size ?? a.curve ?? a.parameter_set].filter((v) => v != null).join(' ')

const columns: Column<Row>[] = [
  { header: '#', sort: (r) => r.rank, cell: (r) => r.rank },
  { header: 'Tier', sort: (r) => r.asset?.tier ?? '', cell: (r) => (r.asset ? <TierBadge tier={r.asset.tier} /> : '') },
  {
    header: 'Asset',
    sort: (r) => (r.asset ? algorithmName(r.asset.canonical_name) : r.id),
    cell: (r) => (r.asset ? algorithmName(r.asset.canonical_name) : <span className="text-paper/60">{r.id} ({MISSING})</span>),
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

const heading = 'mb-3 font-head text-xl font-semibold'

export default function Overview() {
  const { data: result, error } = useScanResult()
  // Test code is hidden from the ranked list until asked for.
  const [includeTests, setIncludeTests] = useState(false)

  if (error) return <p>Failed to load scan: {error}</p>
  if (!result) return <p className="text-paper/50">Loading</p>

  const { summary, assets } = result
  const errors = result.errors ?? []
  const testOnly = testOnlyIds(assets, result.findings)
  const top = topRisks(summary.top_risks, assets, testOnly, includeTests, TOP)
  const tests = testCodeShare(assets, testOnly)

  return (
    <div className="space-y-8">
      <PageHeader
        title={`${Math.round(summary.readiness_pct)}% of assessed assets are quantum-safe.`}
        lead={`${summary.counts_by_tier.CRITICAL} critical assets need a fix, and ${summary.hndl_exposed_count} are exposed to harvest now, decrypt later.`}
      >
        <Cta primary to="/roadmap">See the migration plan</Cta>
        <Cta href="/api/cbom" download="quantumtrace-cbom.json">Download the CBOM</Cta>
      </PageHeader>
      {tests.count > 0 && (
        <p className="text-sm text-paper/60">
          The score, tier counts and readiness are the engine's totals over every scored asset. They include
          {` ${tests.count} test-code-only ${tests.count === 1 ? 'asset' : 'assets'}`}
          {` (${(['CRITICAL', 'MEDIUM', 'UNKNOWN', 'SAFE'] as const).filter((t) => tests.byTier[t]).map((t) => `${tests.byTier[t]} ${t.toLowerCase()}`).join(', ')})`}
          {' '}and do not change with the test code toggle.
        </p>
      )}
      {errors.length > 0 && (
        <details className="text-sm text-paper/80">
          <summary className="cursor-pointer">{errors.length} scan errors</summary>
          <ul className="mt-1 space-y-1 text-paper/60">
            {errors.map((e, i) => (
              <li key={i}>{e.detector}: {e.message}{e.path ? ` (${e.path})` : ''}</li>
            ))}
          </ul>
        </details>
      )}

      {assets.length === 0 ? (
        <p className="text-paper/60">This scan found no cryptographic assets. Scan a folder with code, cloud files or a capture.</p>
      ) : (
        <>
          <section className="grid gap-4 lg:grid-cols-2">
            <div className="glass p-6">
              <h2 className={heading}>Risk score</h2>
              <div className="flex justify-center">
                <ScoreGauge score={summary.score} grade={summary.grade} />
              </div>
            </div>
            <div className="glass p-6">
              <h2 className={heading}>Assets by tier</h2>
              <TierDonut counts={summary.counts_by_tier} />
            </div>
          </section>

          <section className="glass p-6">
            <h2 className={heading}>Risk by source</h2>
            <SourceBars bySource={summary.counts_by_source} scores={summary.score_by_source} />
          </section>

          <section className="glass p-6">
            <h2 className={heading}>The {top.rows.length} biggest risks</h2>
            <div className="mb-3 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-paper/70">
              <label className="flex cursor-pointer items-center gap-2">
                <input type="checkbox" checked={includeTests} onChange={(e) => setIncludeTests(e.target.checked)} />
                Include test code
              </label>
              <span role="status">
                {includeTests
                  ? `Showing ${top.rows.length} of ${top.ranked} ranked assets, test code included.`
                  : `Showing ${top.rows.length} of ${top.ranked - top.hidden} ranked assets. ${top.hidden} test-code-only ${top.hidden === 1 ? 'asset is' : 'assets are'} hidden.`}
              </span>
            </div>
            {top.rows.length === 0 ? (
              <p className="text-paper/60">Every ranked asset is in test code. Include test code to list them.</p>
            ) : (
              <SortableTable rows={top.rows} columns={columns} />
            )}
            <div className="pt-4"><Cta to="/roadmap">Open the full roadmap</Cta></div>
          </section>
        </>
      )}

      <ScoringPanel grade={summary.grade} />
    </div>
  )
}
