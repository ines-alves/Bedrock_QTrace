import type { components } from '../api/schema'
import { useScanResult } from '../api/useScanResult'
import SortableTable, { type Column } from '../components/SortableTable'
import TierBadge from '../components/TierBadge'

type Asset = components['schemas']['CryptoAsset']

const tierOrder = { CRITICAL: 0, MEDIUM: 1, UNKNOWN: 2, SAFE: 3 }

const columns: Column<Asset>[] = [
  { header: 'Tier', sort: (a) => tierOrder[a.tier], cell: (a) => <TierBadge tier={a.tier} /> },
  { header: 'Asset', sort: (a) => a.canonical_name, cell: (a) => a.canonical_name },
  { header: 'Type', sort: (a) => a.asset_type, cell: (a) => a.asset_type },
  { header: 'Threat', sort: (a) => a.threat, cell: (a) => a.threat },
  { header: 'Occurrences', sort: (a) => a.occurrences.length, cell: (a) => a.occurrences.length },
]

export default function Overview() {
  const { data, error } = useScanResult()
  if (error) return <p>Failed to load scan: {error}</p>
  if (!data) return <p className="text-paper/50">Loading</p>

  return (
    <>
      <h1 className="mb-1 font-head text-2xl">
        Grade {data.summary.grade} · {data.summary.score}
      </h1>
      <p className="mb-6 font-sub italic text-paper/60">{data.assets.length} assets, {data.findings.length} findings</p>
      <SortableTable rows={data.assets} columns={columns} />
    </>
  )
}
