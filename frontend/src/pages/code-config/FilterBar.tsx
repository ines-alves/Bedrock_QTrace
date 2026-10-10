import { TIERS, type Filters, type Tier } from './model'

type Props = {
  languages: string[]
  filters: Filters
  onChange: (next: Filters) => void
}

function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}

const chip = (on: boolean) =>
  `cursor-pointer select-none border px-2 py-1 text-[10px] uppercase tracking-widest ${
    on ? 'border-aqua text-aqua' : 'border-paper/20 text-paper/40'
  }`

export default function FilterBar({ languages, filters, onChange }: Props) {
  return (
    <div className="mb-6 flex flex-wrap items-center gap-x-6 gap-y-3 text-xs">
      <div className="flex items-center gap-2">
        <span className="text-paper/50">Language</span>
        {languages.map((l) => (
          <button key={l} type="button" aria-pressed={filters.languages.has(l)} className={chip(filters.languages.has(l))}
            onClick={() => onChange({ ...filters, languages: toggle(filters.languages, l) })}>
            {l}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-paper/50">Tier</span>
        {TIERS.map((t: Tier) => (
          <button key={t} type="button" aria-pressed={filters.tiers.has(t)} className={chip(filters.tiers.has(t))}
            onClick={() => onChange({ ...filters, tiers: toggle(filters.tiers, t) })}>
            {t}
          </button>
        ))}
      </div>
      <label className="flex cursor-pointer items-center gap-2 text-paper/70">
        <input type="checkbox" checked={filters.includeTestCode}
          onChange={(e) => onChange({ ...filters, includeTestCode: e.target.checked })} />
        Test code
      </label>
      <label className="flex cursor-pointer items-center gap-2 text-paper/70">
        <input type="checkbox" checked={filters.includeNonCrypto}
          onChange={(e) => onChange({ ...filters, includeNonCrypto: e.target.checked })} />
        Warnings and libraries
      </label>
    </div>
  )
}
