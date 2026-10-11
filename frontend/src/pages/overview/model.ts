import type { components } from '../../api/schema'

type Asset = components['schemas']['CryptoAsset']
type Finding = components['schemas']['Finding']
type Tier = components['schemas']['Tier']

export type Row = { rank: number; id: string; asset?: Asset }

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

// Test-code-only scored assets in a result that includes test code, by tier. A scored asset is one with
// risk points to lose (max_points above zero), as the engine counts them.
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
