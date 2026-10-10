import { useEffect, useState } from 'react'

type Property = { name: string; value: string }
export type Component = {
  type: string
  name: string
  cryptoProperties?: { assetType: string }
  properties?: Property[]
}
type Cbom = { specVersion: string; components: Component[] }
type Validation = { valid: boolean; errors: string[] }

export const STANDARDS = [
  { id: 'NIST FIPS 203', algorithm: 'ML-KEM', purpose: 'Key encapsulation' },
  { id: 'NIST FIPS 204', algorithm: 'ML-DSA', purpose: 'Digital signatures' },
  { id: 'NIST FIPS 205', algorithm: 'SLH-DSA', purpose: 'Hash-based signatures' },
]
export const NO_STANDARD = 'No standard cited'

const fetchJson = <T,>(url: string): Promise<T> =>
  fetch(url).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`${url}: HTTP ${r.status}`))))

export function useCbom() {
  const [data, setData] = useState<{ cbom: Cbom; validation: Validation }>()
  const [error, setError] = useState<string>()
  useEffect(() => {
    Promise.all([fetchJson<Cbom>('/api/cbom'), fetchJson<Validation>('/api/validate')])
      .then(([cbom, validation]) => setData({ cbom, validation }))
      .catch((e: Error) => setError(e.message))
  }, [])
  return { data, error }
}

const prop = (c: Component, name: string) => c.properties?.find((p) => p.name === `quantumtrace:${name}`)?.value

export const assetType = (c: Component) => (c.type === 'library' ? 'library' : (c.cryptoProperties?.assetType ?? 'unknown'))

export type StandardRow = { standard: string; algorithm: string; purpose: string; count: number; targets: string[] }

export function summarize(components: Component[]) {
  const byType = new Map<string, number>()
  const cited = new Map<string, { count: number; targets: Set<string> }>()
  for (const c of components) {
    byType.set(assetType(c), (byType.get(assetType(c)) ?? 0) + 1)
    const target = prop(c, 'recommendedReplacement')
    if (!target) continue
    const key = prop(c, 'recommendedStandard') ?? NO_STANDARD
    const row = cited.get(key) ?? { count: 0, targets: new Set<string>() }
    row.count += 1
    row.targets.add(target)
    cited.set(key, row)
  }
  const row = (standard: string, algorithm: string, purpose: string): StandardRow => ({
    standard,
    algorithm,
    purpose,
    count: cited.get(standard)?.count ?? 0,
    targets: [...(cited.get(standard)?.targets ?? [])].sort(),
  })
  const known = new Set(STANDARDS.map((s) => s.id))
  const standards = [
    ...STANDARDS.map((s) => row(s.id, s.algorithm, s.purpose)),
    ...[...cited.keys()].filter((k) => !known.has(k)).sort().map((k) => row(k, '', '')),
  ]
  return { byType: [...byType].sort((a, b) => b[1] - a[1]), standards }
}
