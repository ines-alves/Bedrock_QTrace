import { useMemo, type ReactNode } from 'react'
import { useScanResult } from '../api/useScanResult'
import { algorithmName } from '../components/algorithmName'
import Cta from '../components/Cta'
import PageHeader from '../components/PageHeader'
import SortableTable, { type Column } from '../components/SortableTable'
import TierBadge from '../components/TierBadge'
import { buildCloud, relative, words, type Kms, type Listener } from './cloud/model'

const day = (iso: string) => iso.slice(0, 10)

const kmsColumns: Column<Kms>[] = [
  { header: 'Alias', sort: (k) => k.extra.alias, cell: (k) => k.extra.alias },
  { header: 'Key spec', sort: (k) => algorithmName(k.finding.raw_name), cell: (k) => algorithmName(k.finding.raw_name) },
  { header: 'Usage', sort: (k) => k.extra.key_usage, cell: (k) => k.extra.key_usage },
  { header: 'Origin', sort: (k) => k.extra.origin, cell: (k) => k.extra.origin },
  { header: 'State', sort: (k) => k.extra.state, cell: (k) => k.extra.state },
  { header: 'Rotation', sort: (k) => k.extra.rotation_status, cell: (k) => k.extra.rotation_status },
  { header: 'Flags', sort: (k) => words(k.extra.hygiene_flags), cell: (k) => words(k.extra.hygiene_flags) },
  { header: 'Tier', sort: (k) => k.tier, cell: (k) => <TierBadge tier={k.tier} /> },
]

const isHttp = (l: Listener) => l.extra.listener_protocol === 'HTTP'

const listenerColumns: Column<Listener>[] = [
  {
    header: 'Load balancer',
    sort: (l) => l.extra.lb_name,
    cell: (l) => (
      <>
        <div>{l.extra.lb_name}</div>
        <div className="text-paper/40">{l.extra.lb_type}</div>
      </>
    ),
  },
  {
    header: 'Listener',
    sort: (l) => `${l.extra.listener_protocol}:${l.extra.port}`,
    cell: (l) => (
      <>
        <div>{l.extra.listener_protocol}:{l.extra.port}</div>
        <div className="text-paper/40">{l.extra.public_exposure ? 'public' : 'internal'}</div>
      </>
    ),
  },
  {
    header: 'Policy',
    sort: (l) => l.extra.ssl_policy ?? '',
    cell: (l) =>
      isHttp(l)
        ? l.extra.redirects_to_https ? 'Plaintext HTTP, redirects to HTTPS' : 'Plaintext HTTP, forwards traffic'
        : l.extra.ssl_policy,
  },
  { header: 'Tier', sort: (l) => l.tier, cell: (l) => (isHttp(l) ? '' : <TierBadge tier={l.tier} />) },
  {
    header: 'Certificate',
    sort: (l) => l.cert?.extra.domain ?? '',
    cell: (l) =>
      l.cert && (
        <>
          <div>{l.cert.extra.domain}</div>
          <div className="text-paper/40">{l.cert.extra.key_algorithm}, expires {day(l.cert.extra.not_after)}</div>
        </>
      ),
  },
]

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="glass p-5">
      <h2 className="mb-3 font-head text-xl font-semibold">{title}</h2>
      {children}
    </section>
  )
}

export default function Cloud() {
  const { data, error } = useScanResult()
  const cloud = useMemo(() => (data ? buildCloud(data) : undefined), [data])

  if (error) return <p>Failed to load scan: {error}</p>
  if (!data || !cloud) return <p className="text-paper/50">Loading</p>
  const { kms, listeners, certs, events } = cloud
  if (kms.length + listeners.length + certs.length === 0) {
    return <p className="text-paper/50">No cloud resources in this scan.</p>
  }

  const expired = certs.filter((c) => Date.parse(c.extra.not_after) < Date.parse(data.finished_at)).length

  return (
    <div className="space-y-6">
      <PageHeader
        title={expired > 0 ? `${expired} certificate${expired === 1 ? ' has' : 's have'} already expired.` : 'No certificate has expired.'}
        lead={`${kms.length} KMS keys, ${listeners.length} listeners and ${certs.length} certificates in this scan.`}
      >
        <Cta primary to="/roadmap">See what to fix</Cta>
        <Cta href="/api/cbom" download="quantumtrace-cbom.json">Download the CBOM</Cta>
      </PageHeader>
      <Section title="Listeners and their certificates">
        <SortableTable rows={listeners} columns={listenerColumns} />
      </Section>
      <Section title="KMS keys">
        <SortableTable rows={kms} columns={kmsColumns} />
      </Section>
      <Section title="Expiry timeline">
        <ul className="space-y-2 text-xs">
          {events.map((e) => (
            <li key={e.label} className="grid grid-cols-[6.5rem_9rem_1fr] gap-x-3 border-b border-paper/5 pb-2">
              <span>{day(e.date)}</span>
              <span className="text-paper/60">{relative(e.date, data.finished_at)}</span>
              <span>
                {e.label}
                {e.note && <span className="text-paper/40"> · status {e.note}</span>}
              </span>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  )
}
