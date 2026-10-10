import type { components } from '../../api/schema'
import type { ScanResult } from '../../api/useScanResult'

type Finding = components['schemas']['Finding']
type Tier = components['schemas']['Tier']

type KmsExtra = {
  alias: string
  key_usage: string
  origin: string
  state: string
  rotation_status: string
  valid_to: string | null
  deletion_date: string | null
  hygiene_flags: string[]
}
type AcmExtra = { domain: string; key_algorithm: string; not_after: string; cert_status: string; hygiene_flags: string[] }
type ListenerExtra = {
  lb_name: string
  lb_type: string
  listener_protocol: string
  port: number
  public_exposure: boolean
  ssl_policy?: string
  redirects_to_https?: boolean
  certificate_arns?: string[]
}

export type Kms = { finding: Finding; extra: KmsExtra; tier: Tier }
export type Cert = { finding: Finding; extra: AcmExtra }
export type Listener = { finding: Finding; extra: ListenerExtra; tier: Tier; cert?: Cert }
export type Event = { date: string; label: string; note?: string }

const DAY = 86_400_000
const SEVERITY: Tier[] = ['CRITICAL', 'MEDIUM', 'UNKNOWN', 'SAFE']

export function buildCloud(result: ScanResult) {
  // A finding belongs to its own asset and to component assets, so keep the worst tier.
  const tierOf = new Map<string, Tier>()
  for (const a of result.assets) {
    for (const id of a.finding_ids) {
      const seen = tierOf.get(id)
      if (!seen || SEVERITY.indexOf(a.tier) < SEVERITY.indexOf(seen)) tierOf.set(id, a.tier)
    }
  }
  const by = (detector: string) => result.findings.filter((f) => f.detector === detector)

  const certs: Cert[] = by('cloud.acm').map((finding) => ({ finding, extra: finding.extra as unknown as AcmExtra }))
  const certByArn = new Map(certs.map((c) => [c.finding.location.resource_id, c]))
  const kms: Kms[] = by('cloud.kms').map((finding) => ({
    finding,
    extra: finding.extra as unknown as KmsExtra,
    tier: tierOf.get(finding.id) ?? 'UNKNOWN',
  }))
  const listeners: Listener[] = by('cloud.loadbalancer').map((finding) => {
    const extra = finding.extra as unknown as ListenerExtra
    return { finding, extra, tier: tierOf.get(finding.id) ?? 'UNKNOWN', cert: certByArn.get(extra.certificate_arns?.[0]) }
  })

  const events: Event[] = [
    ...certs.map((c) => ({
      date: c.extra.not_after,
      label: `Certificate ${c.extra.domain} (${c.extra.key_algorithm})`,
      note: c.extra.cert_status,
    })),
    ...kms.flatMap((k): Event[] => [
      ...(k.extra.valid_to ? [{ date: k.extra.valid_to, label: `Key material of ${k.extra.alias} expires` }] : []),
      ...(k.extra.deletion_date
        ? [{ date: k.extra.deletion_date, label: `${k.extra.alias} is scheduled for deletion`, note: k.extra.state }]
        : []),
    ]),
  ].sort((a, b) => a.date.localeCompare(b.date))

  return { kms, listeners, certs, events }
}

// Days are counted from the scan time, not the browser clock, so the page reads the same on any day.
export function relative(date: string, scanTime: string): string {
  const d = Math.floor((Date.parse(date) - Date.parse(scanTime)) / DAY)
  const n = (count: number) => `${count} day${count === 1 ? '' : 's'}`
  if (d < 0) return `expired ${n(-d)} ago`
  return d === 0 ? 'today' : `in ${n(d)}`
}

export const words = (flags: string[]) => flags.map((f) => f.replaceAll('_', ' ')).join(', ')
