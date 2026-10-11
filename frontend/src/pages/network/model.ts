import type { components } from '../../api/schema'
import type { ScanResult } from '../../api/useScanResult'

export type Session = components['schemas']['TLSSession']
type Finding = components['schemas']['Finding']
export type Row = { session: Session; port: string; version?: Finding }

export const HYBRID_NOTE =
  'Key exchange is post-quantum. The server certificate is encrypted in TLS 1.3, so authentication was not observed.'

// Authentication facts live on the session's version finding, not on the session.
export function buildRows(result: ScanResult): Row[] {
  const versions = new Map<string, Finding>()
  for (const f of result.findings) {
    if (f.session_id && f.detector.endsWith('.version')) versions.set(f.session_id, f)
  }
  return (result.sessions ?? []).map((session) => ({
    session,
    port: session.flow.split('->')[1].split(':').pop() ?? '',
    version: versions.get(session.session_id),
  }))
}

const KEX = {
  pq_hybrid: { label: 'Hybrid PQC', style: 'bg-jade text-on-accent' },
  pq_pure: { label: 'Post-quantum', style: 'bg-jade text-on-accent' },
  classical: { label: 'Classical', style: 'bg-critical text-on-accent' },
  unknown: { label: 'Unknown', style: 'border border-dashed border-paper/40 text-paper/60' },
} as const

export const keyExchange = (s: Session) => ({
  ...KEX[s.pq_status],
  group: s.negotiated_group ?? 'no group negotiated',
})

export function authentication(row: Row): string {
  if (row.session.transport === 'ssh') {
    return `host key algorithm: ${row.session.cert_key} (observed, identity not verified)`
  }
  return row.version?.extra?.certificate_state === 'encrypted'
    ? 'Not observable: certificate encrypted (TLS 1.3)'
    : 'No certificate in capture'
}

// Filter dimensions as 'dimension:value' keys; a key in the off set is hidden.
export const keysOf = (r: Row) => [
  `transport:${r.session.transport}`,
  `service:${r.session.service ?? 'unknown'}`,
  `tier:${r.session.verdict_tier}`,
  `pq:${r.session.pq_status}`,
]
