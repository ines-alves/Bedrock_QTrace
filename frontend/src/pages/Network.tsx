import { useMemo, useState } from 'react'
import { useScanResult } from '../api/useScanResult'
import Cta from '../components/Cta'
import PageHeader from '../components/PageHeader'
import SortableTable, { type Column } from '../components/SortableTable'
import TierBadge from '../components/TierBadge'
import { HYBRID_NOTE, authentication, buildRows, keyExchange, keysOf, type Row } from './network/model'

const chip = (on: boolean) =>
  `cursor-pointer select-none rounded-full border px-3 py-1 text-xs ${
    on ? 'border-aqua text-aqua' : 'border-paper/20 text-paper/40'
  }`

const list = (title: string, items: string[] | undefined) =>
  items?.length ? <p><span className="text-paper/50">{title}: </span>{items.join(', ')}</p> : null

const columns: Column<Row>[] = [
  {
    header: 'Session',
    sort: (r) => r.session.sni ?? r.session.flow,
    cell: (r) => (
      <>
        <div>{r.session.sni ?? r.session.flow.split('->')[1]}</div>
        <div className="text-paper/40">{r.session.flow}</div>
      </>
    ),
  },
  { header: 'Service', sort: (r) => r.session.service ?? '', cell: (r) => `${r.session.service ?? 'unknown'} :${r.port}` },
  { header: 'Version', sort: (r) => r.session.version ?? '', cell: (r) => r.session.version },
  {
    header: 'Key exchange',
    sort: (r) => keyExchange(r.session).label,
    cell: (r) => {
      const k = keyExchange(r.session)
      return (
        <>
          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${k.style}`}>
            {k.label}
          </span>
          <div className="mt-1 text-paper/60">{k.group}</div>
        </>
      )
    },
  },
  { header: 'Authentication', sort: (r) => authentication(r), cell: (r) => authentication(r) },
  { header: 'PQ status', sort: (r) => r.session.pq_status, cell: (r) => r.session.pq_status },
  {
    header: 'Verdict',
    sort: (r) => r.session.verdict_tier,
    cell: (r) => (
      <span title={r.session.pq_status === 'pq_hybrid' ? HYBRID_NOTE : undefined}>
        <TierBadge tier={r.session.verdict_tier} />
      </span>
    ),
  },
  {
    header: 'Detail',
    sort: () => 0,
    cell: ({ session: s }) => (
      <details>
        <summary className="cursor-pointer text-aqua">show</summary>
        <div className="mt-2 space-y-1 text-paper/80">
          {s.transport === 'ssh' && s.peer_banners?.length ? (
            <>
              <p><span className="text-paper/50">client banner: </span>{s.peer_banners[0]}</p>
              <p><span className="text-paper/50">server banner: </span>{s.peer_banners[1]}</p>
            </>
          ) : null}
          {list('offered groups', s.offered_groups)}
          {list('offered ciphers', s.offered_cipher_suites)}
          {list('negotiated cipher', s.negotiated_cipher_suite ? [s.negotiated_cipher_suite] : [])}
          {list('offered signatures', s.offered_sig_schemes)}
          {list('certificate signature', s.cert_sig_alg ? [s.cert_sig_alg] : [])}
        </div>
      </details>
    ),
  },
]

export default function Network() {
  const { data, error } = useScanResult()
  const rows = useMemo(() => (data ? buildRows(data) : []), [data])
  const [off, setOff] = useState<Set<string>>(new Set())

  if (error) return <p>Failed to load scan: {error}</p>
  if (!data) return <p className="text-paper/50">Loading</p>
  if (rows.length === 0) return <p className="text-paper/50">No network sessions in this scan.</p>

  const groups = ['transport', 'service', 'tier', 'pq'].map((d) => ({
    d,
    values: [...new Set(rows.flatMap(keysOf).filter((k) => k.startsWith(`${d}:`)))].sort(),
  }))
  const toggle = (k: string) =>
    setOff((o) => {
      const n = new Set(o)
      if (!n.delete(k)) n.add(k)
      return n
    })
  const only = (dimension: string, keep: string[]) =>
    setOff(new Set(groups.flatMap((g) => (g.d === dimension ? g.values.filter((k) => !keep.includes(k)) : []))))
  const shown = rows.filter((r) => !keysOf(r).some((k) => off.has(k)))
  const tls = rows.filter((r) => r.session.transport === 'tls')
  const pq = tls.filter((r) => r.session.pq_status === 'pq_hybrid' || r.session.pq_status === 'pq_pure')

  return (
    <div className="space-y-6">
      <PageHeader
        title={`${pq.length} of ${tls.length} TLS sessions use post-quantum key exchange.`}
        lead={`${rows.length} sessions in the capture: ${tls.length} TLS, ${rows.length - tls.length} SSH. The rest can be broken by a quantum computer.`}
      >
        <Cta primary onClick={() => only('pq', ['pq:pq_hybrid', 'pq:pq_pure'])}>Show post-quantum sessions</Cta>
        <Cta onClick={() => only('tier', ['tier:CRITICAL'])}>Show critical only</Cta>
        <Cta onClick={() => setOff(new Set())}>Show all</Cta>
      </PageHeader>
      <div className="flex flex-wrap gap-x-6 gap-y-3 text-xs">
        {groups.map(({ d, values }) => (
          <div key={d} className="flex items-center gap-2">
            <span className="text-paper/50">{d}</span>
            {values.map((k) => (
              <button key={k} type="button" aria-pressed={!off.has(k)} className={chip(!off.has(k))} onClick={() => toggle(k)}>
                {k.slice(d.length + 1)}
              </button>
            ))}
          </div>
        ))}
      </div>
      <section className="glass p-5">
        <p className="mb-3 text-paper/70">{shown.length} of {rows.length} sessions shown</p>
        <SortableTable rows={shown} columns={columns} />
      </section>
      <Cta to="/roadmap">See what to fix</Cta>
    </div>
  )
}
