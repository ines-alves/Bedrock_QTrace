import type { components } from '../../api/schema'

type Asset = components['schemas']['CryptoAsset']
type Finding = components['schemas']['Finding']
type Tier = components['schemas']['Tier']

export type Row = { rank: number; id: string; asset?: Asset }

export type TopRisks = {
  rows: Row[]
  // Ranked ids left out because the asset is test-code-only and the toggle is off.
  hidden: number
  ranked: number
}

// The engine sets in_test_code_only from code findings alone, so a key file under tests/ is never
// flagged. An asset is test-only when the flag says so or when every finding behind it is test code.
export function testOnlyIds(assets: Asset[], findings: Finding[]): Set<string> {
  const inTests = new Map(findings.map((f) => [f.id, f.in_test_code]))
  return new Set(
    assets
      .filter((a) => a.in_test_code_only || (a.finding_ids.length > 0 && a.finding_ids.every((id) => inTests.get(id) === true)))
      .map((a) => a.asset_id),
  )
}

// Ranked ids in the engine's order. Test-code-only assets are dropped unless asked for, and ranks are
// counted after the drop so the list reads 1, 2, 3 whatever is hidden.
export function topRisks(ids: string[], assets: Asset[], testOnly: Set<string>, includeTests: boolean, limit: number): TopRisks {
  const byId = new Map(assets.map((a) => [a.asset_id, a]))
  const shown = includeTests ? ids : ids.filter((id) => !testOnly.has(id))
  return {
    rows: shown.slice(0, limit).map((id, i) => ({ rank: i + 1, id, asset: byId.get(id) })),
    hidden: ids.length - shown.length,
    ranked: ids.length,
  }
}

// The engine's score, tier counts and readiness cover every scored asset, test code included.
// A scored asset is one with risk points to lose (max_points above zero), as the engine counts them.
export function testCodeShare(assets: Asset[], testOnly: Set<string>): { count: number; byTier: Partial<Record<Tier, number>> } {
  const byTier: Partial<Record<Tier, number>> = {}
  let count = 0
  for (const a of assets) {
    if (!testOnly.has(a.asset_id) || a.max_points <= 0) continue
    count += 1
    byTier[a.tier] = (byTier[a.tier] ?? 0) + 1
  }
  return { count, byTier }
}
