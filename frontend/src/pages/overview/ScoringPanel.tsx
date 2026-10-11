import { useEffect, useState } from 'react'

// /api/scoring returns an untyped dict, so the part of kb/scoring.yaml used here is typed in this file.
type Policy = {
  tier_weights: Record<string, number>
  exposure: { negotiated_key_exchange: number; test_only: number }
  broken_multiplier: number
  grade_bands: { grade: string; minimum: number; maximum: number }[]
  hndl_floor: { score: number }
}

const pill = 'rounded-full border px-3 py-1 text-sm'

export default function ScoringPanel({ grade }: { grade: string }) {
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
    <details className="glass p-6">
      <summary className="cursor-pointer font-head text-xl font-semibold">How is the score calculated?</summary>
      {error && <p className="mt-4 text-paper/60">Scoring data is unavailable: {error}</p>}
      {!error && !policy && <p className="mt-4 text-paper/60">Loading</p>}
      {policy && (
        <ol className="mt-5 space-y-6 text-lg">
          <li>
            <p className="font-head font-semibold">1. Every asset earns points by tier</p>
            <p className="mt-2 flex flex-wrap gap-2">
              {Object.entries(policy.tier_weights).map(([tier, points]) => (
                <span key={tier} className={`${pill} border-paper/25`}>{tier.toLowerCase()} {points}</span>
              ))}
            </p>
          </li>
          <li>
            <p className="font-head font-semibold">2. Danger multiplies the points</p>
            <p className="mt-2 text-paper/70">
              x{policy.broken_multiplier} if it is already broken today. Up to x{policy.exposure.negotiated_key_exchange} if it
              protects a live key exchange or a public load balancer. x{policy.exposure.test_only} if it only appears in tests.
            </p>
          </li>
          <li>
            <p className="font-head font-semibold">3. The score is the share of the worst case</p>
            <p className="mt-2 text-paper/70">From 0 (best) to 100 (worst). A live key exchange exposed to harvest now, decrypt later never scores below {policy.hndl_floor.score}.</p>
            <p className="mt-3 flex flex-wrap gap-2">
              {policy.grade_bands.map((b) => (
                <span key={b.grade} className={`${pill} ${b.grade === grade ? 'border-aqua bg-aqua text-on-accent' : 'border-paper/25'}`}>
                  {b.grade} {b.minimum} to {b.maximum}
                </span>
              ))}
            </p>
          </li>
        </ol>
      )}
    </details>
  )
}
