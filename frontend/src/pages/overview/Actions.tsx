import { useState, type FormEvent } from 'react'
import type { ScanResult } from '../../api/useScanResult'

const downloads = [
  { label: 'CBOM', href: '/api/cbom', file: 'quantumtrace-cbom.json' },
  { label: 'JSON', href: '/api/result', file: 'quantumtrace-result.json' },
  { label: 'Markdown', href: '/api/report.md', file: 'quantumtrace-report.md' },
]

export default function Actions({ onScanned }: { onScanned: (result: ScanResult) => void }) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string>()
  const paths = text.split(/[\s,]+/).filter(Boolean)

  async function scan(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setMessage(undefined)
    try {
      const r = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ paths }),
      })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`)
      onScanned(body)
    } catch (e) {
      setMessage(`Scan failed: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-wrap items-start gap-x-8 gap-y-3 text-xs">
      <div className="flex items-center gap-2">
        <span className="uppercase tracking-widest text-paper/60">Download</span>
        {downloads.map((d) => (
          <a key={d.href} href={d.href} download={d.file} className="border border-steel px-3 py-1 uppercase tracking-widest hover:bg-steel hover:text-ink">
            {d.label}
          </a>
        ))}
      </div>
      <form onSubmit={scan} className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
        <label htmlFor="scan-paths" className="uppercase tracking-widest text-paper/60">Scan paths</label>
        <input id="scan-paths" value={text} onChange={(e) => setText(e.target.value)}
          placeholder="sample-repos cloud-posture network-capture"
          className="min-w-64 flex-1 bg-panel px-3 py-1 placeholder:text-paper/40" />
        <button type="submit" disabled={busy || paths.length === 0}
          className="border border-aqua px-3 py-1 uppercase tracking-widest text-aqua disabled:opacity-40">
          {busy ? 'Scanning' : 'Scan'}
        </button>
        {message && <p className="w-full text-paper/80" role="alert">{message}</p>}
      </form>
    </div>
  )
}
