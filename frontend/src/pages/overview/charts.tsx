import type { components } from '../../api/schema'

type Tier = components['schemas']['Tier']
type Grade = components['schemas']['RiskSummary']['grade']

// Severity colours are used inside the Overview charts only. TierBadge keeps its fill and outline style.
const TIER_COLOR: Record<Tier, string> = {
  CRITICAL: '#ee6368',
  MEDIUM: '#f28c28',
  UNKNOWN: '#aabbcc',
  SAFE: '#4caf82',
}

const TIERS: Tier[] = ['CRITICAL', 'MEDIUM', 'UNKNOWN', 'SAFE']

const GRADE_COLOR: Record<Grade, string> = {
  A: TIER_COLOR.SAFE,
  B: TIER_COLOR.SAFE,
  C: TIER_COLOR.MEDIUM,
  D: TIER_COLOR.MEDIUM,
  E: TIER_COLOR.CRITICAL,
  F: TIER_COLOR.CRITICAL,
}

export function ScoreGauge({ score, grade }: { score: number; grade: Grade }) {
  return (
    <svg viewBox="0 0 100 60" role="img" aria-label={`Risk score ${score} of 100, grade ${grade}`} className="w-full max-w-xs text-paper">
      <path d="M10 50 A40 40 0 0 1 90 50" pathLength={100} fill="none" stroke="currentColor" strokeOpacity={0.12} strokeWidth={8} />
      <path d="M10 50 A40 40 0 0 1 90 50" pathLength={100} fill="none" stroke={GRADE_COLOR[grade]} strokeWidth={8}
        strokeDasharray={`${score} 100`} />
      <text x="50" y="44" textAnchor="middle" fontSize="20" className="fill-paper font-head">{score}</text>
      <text x="50" y="57" textAnchor="middle" fontSize="8" fill={GRADE_COLOR[grade]} className="font-head">Grade {grade}</text>
      <text x="10" y="58" textAnchor="middle" fontSize="5" className="fill-paper/60">0</text>
      <text x="90" y="58" textAnchor="middle" fontSize="5" className="fill-paper/60">100</text>
    </svg>
  )
}

const GAP = 0.8

export function TierDonut({ counts }: { counts: Record<string, number> }) {
  const total = TIERS.reduce((sum, t) => sum + (counts[t] ?? 0), 0)
  const present = TIERS.filter((t) => (counts[t] ?? 0) > 0)
  const segments = present.map((t, i) => ({
    tier: t,
    share: (100 * counts[t]) / total,
    offset: (100 * present.slice(0, i).reduce((sum, p) => sum + counts[p], 0)) / total,
  }))

  return (
    <div className="flex items-center gap-6">
      <svg viewBox="0 0 42 42" role="img" aria-label="Scored assets by tier" className="w-40 shrink-0">
        <defs>
          <pattern id="unknown-hatch" width="2" height="2" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="2" stroke={TIER_COLOR.UNKNOWN} strokeWidth="1" />
          </pattern>
        </defs>
        {segments.map((s) => (
          <circle key={s.tier} cx="21" cy="21" r="15.9155" fill="none" strokeWidth="6" pathLength={100}
            stroke={s.tier === 'UNKNOWN' ? 'url(#unknown-hatch)' : TIER_COLOR[s.tier]}
            strokeDasharray={`${Math.max(s.share - GAP, 0.1)} 100`} strokeDashoffset={-s.offset}
            transform="rotate(-90 21 21)" />
        ))}
        <text x="21" y="22.5" textAnchor="middle" fontSize="8" className="fill-paper font-head">{total}</text>
        <text x="21" y="28" textAnchor="middle" fontSize="3" className="fill-paper/60">scored</text>
      </svg>
      <ul className="space-y-1 text-xs">
        {TIERS.map((t) => (
          <li key={t} className="flex items-center gap-2">
            <span className="inline-block h-2.5 w-2.5" style={{ background: TIER_COLOR[t] }} />
            <span className="w-20 text-paper/70">{t}</span>
            <span className="font-head text-base">{counts[t] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function SourceBars({ bySource, scores }: { bySource: Record<string, Record<string, number>>; scores: Record<string, number> }) {
  const rows = Object.entries(bySource).map(([source, counts]) => ({
    source,
    counts,
    total: TIERS.reduce((sum, t) => sum + (counts[t] ?? 0), 0),
  }))
  const widest = Math.max(...rows.map((r) => r.total))

  return (
    <div className="space-y-2 text-xs">
      {rows.map((r) => (
        <div key={r.source} className="flex items-center gap-3">
          <span className="w-24 shrink-0 text-paper/70">{r.source}</span>
          <div className="flex h-5 gap-px overflow-hidden rounded-full" style={{ width: `${(100 * r.total) / widest}%` }}>
            {TIERS.filter((t) => (r.counts[t] ?? 0) > 0).map((t) => (
              <div key={t} title={`${t}: ${r.counts[t]}`} className="overflow-hidden text-center text-[10px] leading-5 text-on-accent"
                style={{ flexGrow: r.counts[t], background: TIER_COLOR[t] }}>
                {r.counts[t]}
              </div>
            ))}
          </div>
          <span className="ml-auto shrink-0 text-paper/60">score <span className="font-head text-base text-paper">{scores[r.source]}</span></span>
        </div>
      ))}
    </div>
  )
}
