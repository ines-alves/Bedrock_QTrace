import type { components } from '../../api/schema'
import type { ScanResult } from '../../api/useScanResult'

type Asset = components['schemas']['CryptoAsset']
type Item = components['schemas']['RoadmapItem']

export const PHASES = [
  'Resolve first',
  'Key exchange and encryption',
  'Signatures and authentication',
  'Symmetric and hashes',
]

export type Entry = { item: Item; assets: Asset[]; standards: string[] }

export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

// A roadmap action cites a standard only when it contains one of the asset's own recommendations,
// so a certificate renewal never inherits the standard of the asset's key migration.
const standardsOf = (a: Asset, action: string) =>
  a.recommendations.filter((r) => action.includes(r.action)).map((r) => r.standard)

export function buildRoadmap(result: ScanResult): Entry[][] {
  const byId = new Map(result.assets.map((a) => [a.asset_id, a]))
  const phases: Entry[][] = PHASES.map(() => [])
  for (const item of result.roadmap ?? []) {
    const assets = item.asset_ids.flatMap((id) => byId.get(id) ?? [])
    const standards = [...new Set(assets.flatMap((a) => standardsOf(a, item.action)).filter((s) => s != null))].sort()
    phases[item.phase].push({ item, assets, standards })
  }
  return phases
}
