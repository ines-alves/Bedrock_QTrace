import { useEffect, useRef, useState, type DragEvent } from 'react'
import { useScan } from '../api/useScanResult'
import FolderBrowser from './FolderBrowser'

// The three boxes choose what to look for, for every input: the starter kit, a zip, a link or folders.
const PRESETS = [
  { path: 'sample-repos', id: 'code', title: 'Code', note: 'Source code, dependency manifests, key files, web server config' },
  { path: 'cloud-posture', id: 'cloud', title: 'Cloud', note: 'KMS keys, certificates, load balancers' },
  { path: 'network-capture', id: 'network', title: 'Network', note: 'Packet captures: TLS and SSH sessions' },
]
// One input at a time. Nothing staged means the starter kit. Nothing runs until the Scan button is pressed.
type Staged = { kind: 'zip'; file: File } | { kind: 'github'; url: string } | { kind: 'paths'; paths: string[] }
const exports = [
  { label: 'CBOM (CycloneDX)', href: '/api/cbom', file: 'quantumtrace-cbom.json' },
  { label: 'Result (JSON)', href: '/api/result', file: 'quantumtrace-result.json' },
  { label: 'Report (Markdown)', href: '/api/report.md', file: 'quantumtrace-report.md' },
]

// One button that opens the three downloads, so Export reads as an action and not as a label.
function ExportMenu() {
  const menu = useRef<HTMLDetailsElement>(null)
  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (menu.current?.open && !menu.current.contains(e.target as Node)) menu.current.open = false
    }
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [])
  return (
    <details ref={menu} className="relative">
      <summary className="flex cursor-pointer list-none items-center gap-2 rounded-full border border-steel px-4 py-1 hover:bg-steel hover:text-on-accent [&::-webkit-details-marker]:hidden">
        Export <span aria-hidden className="text-xs">&#9662;</span>
      </summary>
      <ul className="absolute right-0 z-20 mt-2 min-w-52 space-y-1 rounded-2xl border border-paper/20 bg-ink p-2 shadow-lg">
        {exports.map((e) => (
          <li key={e.href}>
            <a href={e.href} download={e.file} onClick={() => { if (menu.current) menu.current.open = false }}
              className="block rounded-xl px-3 py-1.5 hover:bg-paper/10">
              {e.label}
            </a>
          </li>
        ))}
      </ul>
    </details>
  )
}

export default function ScanBar() {
  const { data, source, busy, message, scan, scanGithub, scanZip, clear, scanStarterKit } = useScan()
  const [confirming, setConfirming] = useState(false)
  const [staged, setStaged] = useState<Staged>()
  const [types, setTypes] = useState<string[]>(PRESETS.map((p) => p.id))
  const [link, setLink] = useState('')
  const [dragging, setDragging] = useState(false)
  const [hint, setHint] = useState<string>()
  // undefined until the user opens or closes the panel. Until then it is open only while nothing is scanned,
  // so a new user sees how to scan and nobody else loses space.
  const [chosen, setChosen] = useState<boolean>()
  const open = chosen ?? source === 'none'
  // A scan that succeeds closes the panel, so the results are what you land on.
  const wasBusy = useRef(false)
  useEffect(() => {
    if (wasBusy.current && !busy && !message) setChosen(false)
    wasBusy.current = busy
  }, [busy, message])
  const [browseRoot, setBrowseRoot] = useState(PRESETS[0].path)
  // The newest input replaces the one before it, so only one is ever staged.
  function stage(next: Staged | undefined) {
    setStaged(next)
    setHint(undefined)
    if (next?.kind !== 'github') setLink('')
  }
  function pickZip(file: File | undefined) {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setHint('Only .zip files can be scanned. Zip the repository folder first.')
      return
    }
    stage({ kind: 'zip', file })
  }
  function typeLink(value: string) {
    setStaged(value.trim() ? { kind: 'github', url: value.trim() } : undefined)
    setHint(undefined)
    setLink(value)
  }
  const paths = staged?.kind === 'paths' ? staged.paths : []
  const toggle = (path: string) => {
    const next = paths.includes(path) ? paths.filter((p) => p !== path) : [...paths, path]
    stage(next.length > 0 ? { kind: 'paths', paths: next } : undefined)
  }
  const toggleType = (id: string) =>
    setTypes((current) => (current.includes(id) ? current.filter((t) => t !== id) : [...current, id]))
  const label = !staged
    ? 'Scan starter kit'
    : staged.kind === 'zip'
      ? 'Scan zip'
      : staged.kind === 'github'
        ? 'Scan repo'
        : `Scan ${staged.paths.length} folder${staged.paths.length === 1 ? '' : 's'}`
  async function run() {
    let ok: boolean
    if (!staged) ok = await scanStarterKit(types)
    else if (staged.kind === 'zip') ok = await scanZip(staged.file, types)
    else if (staged.kind === 'github') ok = await scanGithub(staged.url, types)
    else ok = await scan(staged.paths, types)
    if (ok) stage(undefined)
  }

  const statusText = busy
    ? 'Scanning'
    : (message ?? hint) ??
      (source === 'scan' && data
        ? `Live scan of ${data.inputs.join(', ')}: ${data.assets.length} assets, ${data.findings.length} findings.`
        : 'No scan yet. Press Scan to scan the starter kit, or choose a zip, a link or folders first.')

  return (
    <section aria-label="Scan" className="mb-8 glass p-5">
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-paper/70">
        <p role="status" className="min-w-0 text-lg">{statusText}</p>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" aria-expanded={open} aria-controls="scan-panel" onClick={() => setChosen(!open)}
            className="rounded-full bg-paper px-4 py-1 font-head font-semibold text-ink hover:bg-aqua">
            {open ? 'Close' : 'Scan'}
          </button>
          {source !== undefined && source !== 'none' &&
            (confirming ? (
              <span className="flex items-center gap-2">
                <span>Clear this scan?</span>
                <button type="button" disabled={busy} onClick={() => { setConfirming(false); setChosen(undefined); void clear() }}
                  className="rounded-full border border-critical px-3 py-1 text-critical hover:bg-critical hover:text-on-accent">
                  Yes, clear
                </button>
                <button type="button" onClick={() => setConfirming(false)}
                  className="rounded-full border border-paper/30 px-3 py-1 hover:border-paper/60">
                  Cancel
                </button>
              </span>
            ) : (
              <button type="button" disabled={busy} onClick={() => setConfirming(true)}
                className="rounded-full border border-paper/30 px-4 py-1 hover:border-paper/60 disabled:opacity-40">
                Clear
              </button>
            ))}
          {source !== undefined && source !== 'none' && <ExportMenu />}
        </div>
      </div>
      {open && (
        <div id="scan-panel" className="mt-4 space-y-4">
          <p className="text-sm text-paper/60">
            Scans the starter kit, or the zip, GitHub link or folders you choose below. Code, Cloud and Network choose what to look for.
          </p>
          <div className="flex flex-wrap items-stretch gap-3">
            {PRESETS.map((p) => {
              const on = types.includes(p.id)
              return (
                <button key={p.path} type="button" title={p.note} aria-pressed={on} onClick={() => toggleType(p.id)}
                  className={`min-w-44 flex-1 rounded-2xl border px-4 py-2 text-center leading-tight ${
                    on ? 'border-aqua bg-aqua text-on-accent' : 'border-paper/25 text-paper/70 hover:border-paper/60'
                  }`}>
                  <span className="block font-head text-xl font-semibold">{p.title}</span>
                </button>
              )
            })}
            <button type="button" disabled={busy || types.length === 0} onClick={() => void run()}
              className="min-w-56 rounded-2xl bg-paper px-6 py-2 font-head text-xl font-bold text-ink hover:bg-aqua disabled:opacity-40">
              {busy ? 'Scanning' : types.length === 0 ? 'Tick at least one' : label}
            </button>
          </div>
          <div className="flex flex-wrap items-stretch gap-3">
            <label
              onDragOver={(e: DragEvent) => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e: DragEvent) => { e.preventDefault(); setDragging(false); pickZip(e.dataTransfer.files[0]) }}
              className={`flex min-w-64 flex-1 cursor-pointer items-center justify-center gap-2 rounded-2xl border border-dashed px-4 py-2 text-center ${
                dragging || staged?.kind === 'zip' ? 'border-aqua bg-aqua/10 text-aqua' : 'border-paper/30 text-paper/70 hover:border-paper/60'
              } ${busy ? 'pointer-events-none opacity-50' : ''}`}>
              {staged?.kind === 'zip' ? (
                <>
                  <span className="truncate font-medium">{staged.file.name}</span>
                  <button type="button" aria-label="Remove the chosen zip" onClick={(e) => { e.preventDefault(); stage(undefined) }}
                    className="text-paper/70 hover:text-paper">
                    x
                  </button>
                </>
              ) : (
                <>Drop a repository .zip here or <span className="underline">choose a file</span></>
              )}
              <input type="file" accept=".zip,application/zip" className="sr-only"
                onChange={(e) => { pickZip(e.target.files?.[0]); e.target.value = '' }} />
            </label>
            <div className="flex min-w-64 flex-[2] items-stretch gap-2">
              <label htmlFor="github-link" className="sr-only">GitHub repository link</label>
              <input id="github-link" value={link} onChange={(e) => typeLink(e.target.value)} disabled={busy}
                placeholder="Or paste a public GitHub link: https://github.com/owner/repo"
                className="min-w-0 flex-1 rounded-2xl bg-ink/60 px-4 py-2 placeholder:text-paper/40" />
              {link && (
                <button type="button" aria-label="Clear the link" onClick={() => stage(undefined)}
                  className="rounded-2xl border border-paper/30 px-4 hover:border-paper/60">
                  x
                </button>
              )}
            </div>
          </div>
          {paths.length > 0 && (
            <ul className="flex flex-wrap gap-2">
              {paths.map((p) => (
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
            <FolderBrowser key={browseRoot} start={browseRoot} selected={paths} onToggle={toggle} />
          </details>
        </div>
      )}
    </section>
  )
}
