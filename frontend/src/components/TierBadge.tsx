import type { components } from '../api/schema'

type Tier = components['schemas']['Tier']

// Critical is red, medium orange, safe jade; unknown stays an outline because it is not a verdict.
const style: Record<Tier, string> = {
  CRITICAL: 'bg-critical text-on-accent',
  MEDIUM: 'bg-medium text-on-accent',
  SAFE: 'bg-jade text-on-accent',
  UNKNOWN: 'border border-dashed border-paper/40 text-paper/60',
}

export default function TierBadge({ tier }: { tier: Tier }) {
  return <span className={`rounded-full px-2.5 py-0.5 text-[10px] uppercase tracking-widest ${style[tier]}`}>{tier}</span>
}
