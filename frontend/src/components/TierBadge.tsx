import type { components } from '../api/schema'

type Tier = components['schemas']['Tier']

// CRITICAL is always red; the other tiers differ by fill and outline.
const style: Record<Tier, string> = {
  CRITICAL: 'bg-critical text-ink',
  MEDIUM: 'border border-steel text-steel',
  SAFE: 'bg-jade text-ink',
  UNKNOWN: 'border border-dashed border-paper/40 text-paper/60',
}

export default function TierBadge({ tier }: { tier: Tier }) {
  return <span className={`rounded-full px-2.5 py-0.5 text-[10px] uppercase tracking-widest ${style[tier]}`}>{tier}</span>
}
