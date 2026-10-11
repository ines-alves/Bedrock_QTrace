import TierBadge from '../../components/TierBadge'
import { languageOf, provenance, type FileGroup as Group, type Row } from './model'

const tag = 'rounded-full px-2.5 py-0.5 text-xs'

function Badge({ row }: { row: Row }) {
  if (row.kind === 'warning') return <span className={`${tag} bg-warning text-on-accent`}>Warning</span>
  if (row.kind === 'library') return <span className={`${tag} border border-steel/60 text-steel`}>Library</span>
  return <TierBadge tier={row.tier ?? 'UNKNOWN'} />
}

function details(row: Row): string {
  const f = row.finding
  const parts: string[] = []
  if (f.key_size) parts.push(`${f.key_size}-bit`)
  if (f.curve) parts.push(f.curve)
  if (f.mode) parts.push(f.mode)
  if (f.padding) parts.push(f.padding)
  if (f.usage && f.usage !== 'unknown') parts.push(f.usage)
  return parts.join(' · ')
}

function RowView({ row }: { row: Row }) {
  const f = row.finding
  const notes = provenance(f)
  const rec = row.recommendation
  return (
    <li className="grid grid-cols-[3.5rem_7rem_1fr] gap-x-3 border-b border-paper/10 px-4 py-4 text-sm">
      <span className="text-paper/50">L{f.location.line ?? '?'}</span>
      <span><Badge row={row} /></span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-3">
          <span className="font-medium">{f.raw_name}</span>
          {row.asset && row.asset.canonical_name.toLowerCase() !== f.raw_name.toLowerCase() && (
            <span className="text-paper/50">{row.asset.canonical_name}</span>
          )}
          {details(row) && <span className="text-paper/50">{details(row)}</span>}
          <span className="text-paper/40">{languageOf(f)}</span>
          {f.in_test_code && <span className={`${tag} border border-paper/30 text-paper/60`}>test code</span>}
          {f.confidence < 0.8 && <span className="text-paper/40">confidence {f.confidence.toFixed(1)}</span>}
          {row.flags.map((flag) => (
            <span key={flag} className="text-warning">{flag}</span>
          ))}
        </div>
        {f.location.snippet && (
          <pre className="mt-2 overflow-x-auto rounded-xl bg-ink/60 px-3 py-2 text-paper/80">{f.location.snippet}</pre>
        )}
        {notes.length > 0 && <p className="mt-1 text-paper/40">{notes.join(' · ')}</p>}
        {rec && (
          <p className="mt-2 text-paper/80">
            {rec.action}
            {rec.target_algorithm ? ` (${rec.target_algorithm})` : ''}
            {rec.standard ? `, ${rec.standard}` : ''}
          </p>
        )}
      </div>
    </li>
  )
}

export default function FileGroup({ group }: { group: Group }) {
  return (
    <details open className="glass mb-4 overflow-hidden">
      <summary className="flex cursor-pointer items-center gap-3 bg-paper/5 px-4 py-3 text-sm">
        {group.worstTier && <TierBadge tier={group.worstTier} />}
        <span className="font-medium">{group.file}</span>
        <span className="text-paper/40">{group.rows.length} rows</span>
      </summary>
      <ul>
        {group.rows.map((row) => (
          <RowView key={row.key} row={row} />
        ))}
      </ul>
    </details>
  )
}
