import type { components } from '../../api/schema'
import type { ScanResult } from '../../api/useScanResult'

export type Tier = components['schemas']['Tier']
export type Finding = components['schemas']['Finding']
export type Asset = components['schemas']['CryptoAsset']
export type Recommendation = components['schemas']['Recommendation']

// Same order as the Overview page.
export const TIER_ORDER: Record<Tier, number> = { CRITICAL: 0, MEDIUM: 1, UNKNOWN: 2, SAFE: 3 }
export const TIERS: Tier[] = ['CRITICAL', 'MEDIUM', 'UNKNOWN', 'SAFE']

// Kind is decided from the finding, never from the asset: the real engine wraps hygiene-only and
// library findings in UNKNOWN assets, while the handmade sample leaves them in no asset.
export type RowKind = 'crypto' | 'warning' | 'library'

export type Row = {
  key: string
  kind: RowKind
  finding: Finding
  asset?: Asset
  tier?: Tier
  recommendation?: Recommendation
  flags: string[]
}

export type FileGroup = {
  file: string
  rows: Row[]
  worstTier?: Tier
}

export type Filters = {
  languages: Set<string>
  tiers: Set<Tier>
  includeTestCode: boolean
  includeNonCrypto: boolean
}

const SOURCES = new Set(['code', 'config', 'keyfile'])

export function languageOf(f: Finding): string {
  return f.language ?? 'config'
}

function flagsOf(f: Finding): string[] {
  const flags = f.extra?.hygiene_flags
  return Array.isArray(flags) ? flags.filter((x): x is string => typeof x === 'string') : []
}

function kindOf(f: Finding): RowKind {
  if (f.extra?.hygiene_only === true) return 'warning'
  if (f.kind_hint === 'library') return 'library'
  return 'crypto'
}

// Lower priority number is more urgent.
function topRecommendation(asset?: Asset): Recommendation | undefined {
  const recs = asset?.recommendations ?? []
  return recs.reduce<Recommendation | undefined>((best, r) => (!best || r.priority < best.priority ? r : best), undefined)
}

export function buildRows(data: ScanResult): Row[] {
  const assetsByFinding = new Map<string, Asset[]>()
  for (const asset of data.assets) {
    for (const id of asset.finding_ids ?? []) {
      const list = assetsByFinding.get(id) ?? []
      list.push(asset)
      assetsByFinding.set(id, list)
    }
  }

  const rows: Row[] = []
  for (const f of data.findings) {
    if (!SOURCES.has(f.location.source_type)) continue
    const kind = kindOf(f)
    const flags = flagsOf(f)
    if (kind !== 'crypto') {
      rows.push({ key: f.id, kind, finding: f, flags })
      continue
    }
    const assets = assetsByFinding.get(f.id) ?? []
    if (assets.length === 0) {
      rows.push({ key: f.id, kind, finding: f, tier: 'UNKNOWN', flags })
      continue
    }
    for (const asset of assets) {
      rows.push({
        key: `${f.id}:${asset.asset_id}`,
        kind,
        finding: f,
        asset,
        tier: asset.tier,
        recommendation: topRecommendation(asset),
        flags,
      })
    }
  }
  return rows
}

export function allLanguages(rows: Row[]): string[] {
  return [...new Set(rows.map((r) => languageOf(r.finding)))].sort()
}

export function applyFilters(rows: Row[], filters: Filters): Row[] {
  return rows.filter((r) => {
    if (!filters.languages.has(languageOf(r.finding))) return false
    if (!filters.includeTestCode && r.finding.in_test_code) return false
    if (r.kind !== 'crypto') return filters.includeNonCrypto
    return r.tier !== undefined && filters.tiers.has(r.tier)
  })
}

export function groupByFile(rows: Row[]): FileGroup[] {
  const byFile = new Map<string, Row[]>()
  for (const r of rows) {
    const file = r.finding.location.file ?? r.finding.location.resource_id ?? '(unknown file)'
    const list = byFile.get(file) ?? []
    list.push(r)
    byFile.set(file, list)
  }

  const groups: FileGroup[] = []
  for (const [file, list] of byFile) {
    list.sort(
      (a, b) =>
        (a.finding.location.line ?? 0) - (b.finding.location.line ?? 0) ||
        a.finding.raw_name.localeCompare(b.finding.raw_name) ||
        a.key.localeCompare(b.key),
    )
    let worstTier: Tier | undefined
    for (const r of list) {
      if (r.tier && (!worstTier || TIER_ORDER[r.tier] < TIER_ORDER[worstTier])) worstTier = r.tier
    }
    groups.push({ file, rows: list, worstTier })
  }

  // Files with a tier come first, worst tier first, then by path.
  groups.sort(
    (a, b) =>
      (a.worstTier ? TIER_ORDER[a.worstTier] : 99) - (b.worstTier ? TIER_ORDER[b.worstTier] : 99) ||
      a.file.localeCompare(b.file),
  )
  return groups
}

export type Summary = {
  files: number
  findings: number
  warnings: number
  libraries: number
  testCode: number
  byTier: Record<Tier, number>
}

// Counts distinct finding ids so a finding shown under two assets is not counted twice.
export function summarize(rows: Row[]): Summary {
  const seen = new Set<string>()
  const files = new Set<string>()
  const s: Summary = {
    files: 0,
    findings: 0,
    warnings: 0,
    libraries: 0,
    testCode: 0,
    byTier: { CRITICAL: 0, MEDIUM: 0, UNKNOWN: 0, SAFE: 0 },
  }
  const tierSeen = new Map<string, Tier>()
  for (const r of rows) {
    files.add(r.finding.location.file ?? r.finding.location.resource_id ?? '')
    if (seen.has(r.finding.id)) {
      // Second asset of the same finding: only the worst tier counts.
      const prev = tierSeen.get(r.finding.id)
      if (r.tier && prev && TIER_ORDER[r.tier] < TIER_ORDER[prev]) {
        s.byTier[prev] -= 1
        s.byTier[r.tier] += 1
        tierSeen.set(r.finding.id, r.tier)
      }
      continue
    }
    seen.add(r.finding.id)
    s.findings += 1
    if (r.finding.in_test_code) s.testCode += 1
    if (r.kind === 'warning') s.warnings += 1
    else if (r.kind === 'library') s.libraries += 1
    else if (r.tier) {
      s.byTier[r.tier] += 1
      tierSeen.set(r.finding.id, r.tier)
    }
  }
  s.files = files.size
  return s
}

// Whitelist of evidence keys shown under a snippet; nothing else from `extra` is rendered.
export function provenance(f: Finding): string[] {
  const notes: string[] = []
  const extra = f.extra ?? {}
  const source = extra.key_size_source
  const from = extra.resolved_from_line
  if (typeof source === 'string') {
    notes.push(typeof from === 'number' ? `size via ${source}, line ${from}` : `size via ${source}`)
  } else if (typeof from === 'number') {
    notes.push(`resolved from line ${from}`)
  }
  if (typeof extra.mode_source === 'string') notes.push(`mode via ${extra.mode_source}`)
  if (typeof extra.usage_source === 'string') notes.push(`usage via ${extra.usage_source}`)
  if (extra.hand_rolled === true) notes.push('hand-rolled')
  return notes
}
