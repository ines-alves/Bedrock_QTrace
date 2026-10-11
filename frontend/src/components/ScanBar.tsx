import { useState } from 'react'
import { useScan } from '../api/useScanResult'
import FolderBrowser from './FolderBrowser'

const PRESETS = [
  { path: 'sample-repos', title: 'Code', note: 'Python, Java and Go sources' },
  { path: 'cloud-posture', title: 'Cloud', note: 'KMS keys, certificates, load balancers' },
  { path: 'network-capture', title: 'Network', note: 'Packet capture' },
]
const presetPaths = PRESETS.map((p) => p.path)
const exports = [
  { label: 'CBOM', href: '/api/cbom', file: 'quantumtrace-cbom.json' },
  { label: 'JSON', href: '/api/result', file: 'quantumtrace-result.json' },
  { label: 'Markdown', href: '/api/report.md', file: 'quantumtrace-report.md' },
]

export default function ScanBar() {
  const { data, source, busy, message, scan } = useScan()
  const [selected, setSelected] = useState<string[]>(presetPaths)
  const [browseRoot, setBrowseRoot] = useState(presetPaths[0])
  const extra = selected.filter((p) => !presetPaths.includes(p))
  const toggle = (path: string) =>
    setSelected((s) => (s.includes(path) ? s.filter((p) => p !== path) : [...s, path]))

  return (
    <section aria-label="Scan" className="mb-8 space-y-4 glass p-5">
      <div className="flex flex-wrap items-stretch gap-3">
        {PRESETS.map((p) => {
          const parts = selected.filter((s) => s.startsWith(`${p.path}/`))
          const whole = selected.includes(p.path)
          const state = whole ? 'whole' : parts.length > 0 ? 'partial' : 'off'
          return (
            <button key={p.path} type="button" title={p.note} aria-pressed={state !== 'off'}
              onClick={() => setSelected((s) => (whole ? s.filter((x) => x !== p.path) : [...s.filter((x) => !parts.includes(x)), p.path]))}
              className={`min-w-44 flex-1 rounded-2xl border px-4 py-2 text-center leading-tight ${
                state === 'whole'
                  ? 'border-aqua bg-aqua text-on-accent'
                  : state === 'partial'
                    ? 'border-aqua text-aqua'
                    : 'border-paper/25 text-paper/70 hover:border-paper/60'
              }`}>
              <span className="block font-head text-xl font-semibold">{p.title}</span>
              {state === 'partial' && (
                <span className="block text-base">{`${parts.length} selected part${parts.length === 1 ? '' : 's'}, click for all`}</span>
              )}
            </button>
          )
        })}
        <button type="button" disabled={busy || selected.length === 0} onClick={() => void scan(selected)}
          className="min-w-44 rounded-2xl bg-paper px-6 py-2 font-head text-xl font-bold text-ink hover:bg-aqua disabled:opacity-40">
          {busy ? 'Scanning' : selected.length === 0 ? 'Pick something to scan' : `Scan ${selected.length} selected`}
        </button>
      </div>
      {extra.length > 0 && (
        <ul className="flex flex-wrap gap-2">
          {extra.map((p) => (
            <li key={p} className="flex items-center gap-2 rounded-full border border-aqua px-3 py-1 text-sm text-aqua">
              {p}
              <button type="button" aria-label={`Remove ${p}`} onClick={() => toggle(p)} className="text-paper/70 hover:text-paper">
                x
              </button>
            </li>
          ))}
        </ul>
      )}
      <details>
        <summary className="cursor-pointer text-paper/70">Pick parts: one language, one file, one capture</summary>
        <div className="mt-3 flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <button key={p.path} type="button" aria-pressed={browseRoot === p.path} onClick={() => setBrowseRoot(p.path)}
              className={`rounded-full border px-3 py-1 text-sm ${browseRoot === p.path ? 'border-aqua text-aqua' : 'border-paper/25 text-paper/60'}`}>
              Browse {p.title.toLowerCase()}
            </button>
          ))}
        </div>
        <FolderBrowser key={browseRoot} start={browseRoot} selected={selected} onToggle={toggle} />
      </details>
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-paper/70">
        <p role="status">
          {busy
            ? 'Scanning'
            : message ??
              (source === 'scan' && data
                ? `Live scan: ${data.assets.length} assets, ${data.findings.length} findings.`
                : 'Bundled sample result. Run the scanner to see it live.')}
        </p>
        <div className="flex items-center gap-3">
          <span>Export</span>
          {exports.map((e) => (
            <a key={e.href} href={e.href} download={e.file} className="rounded-full border border-steel px-3 py-1 hover:bg-steel hover:text-on-accent">
              {e.label}
            </a>
          ))}
        </div>
      </div>
    </section>
  )
}
