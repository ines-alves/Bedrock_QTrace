import { useEffect, useState } from 'react'

// /api/scoring returns an untyped dict, so the shape of kb/scoring.yaml is typed here.
type Policy = {
  tier_weights: Record<string, number>
  exposure: Record<string, number>
  broken_multiplier: number
  occurrence: { cap: number; log_divisor: number }
  grade_bands: { grade: string; minimum: number; maximum: number }[]
  hndl_floor: { score: number; condition: string }
  aes_192_tier: string
}

const words = (key: string) => key.replace(/_/g, ' ')

function Table({ title, rows }: { title: string; rows: [string, string | number][] }) {
  return (
    <div>
      <h3 className="mb-1 text-[10px] uppercase tracking-widest text-paper/60">{title}</h3>
      <table className="w-full text-xs">
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k} className="border-b border-paper/5">
              <td className="py-1 pr-4">{words(k)}</td>
              <td className="py-1 text-right font-head">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function ScoringPanel() {
  const [policy, setPolicy] = useState<Policy>()
  const [error, setError] = useState<string>()

  useEffect(() => {
    fetch('/api/scoring')
      .then(async (r) => {
        const body = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`)
        setPolicy(body)
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  return (
    <details className="bg-panel p-4">
      <summary className="cursor-pointer font-head text-lg">How is the score calculated?</summary>
      {error && <p className="mt-3 text-xs text-paper/60">Scoring data is unavailable: {error}</p>}
      {!error && !policy && <p className="mt-3 text-xs text-paper/60">Loading scoring data</p>}
      {policy && (
        <div className="mt-3 space-y-4 text-xs text-paper/80">
          <p className="font-sub text-sm italic">
            Each scored asset earns risk points: tier weight, times the broken multiplier if it is classically broken,
            times its highest exposure factor, times an occurrence factor of 1 + log2(1 + min(occurrences, cap)) / divisor,
            times the evidence confidence. The score is 100 times the sum of risk points over the sum of the maximum
            possible points, from 0 (best) to 100 (worst). If a harvest-now-decrypt-later exposed asset was negotiated,
            the score is at least {policy.hndl_floor.score}.
          </p>
          <div className="grid gap-6 md:grid-cols-3">
            <Table title="Tier weights" rows={Object.entries(policy.tier_weights)} />
            <Table title="Exposure factors" rows={Object.entries(policy.exposure)} />
            <Table title="Grade bands" rows={policy.grade_bands.map((b) => [b.grade, `${b.minimum} to ${b.maximum}`])} />
            <Table title="Other" rows={[
              ['broken multiplier', policy.broken_multiplier],
              ['occurrence cap', policy.occurrence.cap],
              ['occurrence divisor', policy.occurrence.log_divisor],
              ['AES-192 tier', policy.aes_192_tier],
              ['HNDL floor condition', words(policy.hndl_floor.condition)],
            ]} />
          </div>
        </div>
      )}
    </details>
  )
}
