import { createContext, createElement, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import type { components } from './schema'

export type ScanResult = components['schemas']['ScanResult']
type Source = 'none' | 'scan'

// What switching test code on or off changes: findings left out, and scored assets no longer counted.
export type TestCode = { present: boolean; hiddenFindings: number; hiddenAssets: number }

type Scan = {
  // The result every page shows: without test-code findings unless includeTests is on.
  data?: ScanResult
  includeTests: boolean
  setIncludeTests: (on: boolean) => void
  testCode: TestCode
  error?: string
  source?: Source
  busy: boolean
  message?: string
  // The scans resolve to true when the result was stored, so the caller can drop what it had staged.
  scan: (paths: string[], types?: string[]) => Promise<boolean>
  scanGithub: (url: string, types?: string[]) => Promise<boolean>
  scanZip: (file: File, types?: string[]) => Promise<boolean>
  scanStarterKit: (types?: string[]) => Promise<boolean>
  clear: () => Promise<void>
}

const getJson = (url: string) => fetch(url).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))

const ScanContext = createContext<Scan | undefined>(undefined)

// One shared result for every page: a scan started anywhere updates all of them at once.
export function ScanProvider({ children }: { children: ReactNode }) {
  const [full, setData] = useState<ScanResult>()
  // The same scan with test code left out, scored again by the engine on the server, kept with the scan
  // it was made from. It is absent when the scan has no test code, and while it loads.
  const [trimmedFor, setTrimmed] = useState<{ of: ScanResult; result: ScanResult }>()
  const [includeTests, setIncludeTests] = useState(false)
  const [source, setSource] = useState<Source>()
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string>()

  useEffect(() => {
    // Nothing is shown until a scan exists: the source says so before any result is requested.
    getJson('/api/source')
      .then(async (src) => {
        if (src.source !== 'none') setData(await getJson('/api/result'))
        setSource(src.source)
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  useEffect(() => {
    if (!full?.findings.some((f) => f.in_test_code)) return
    let current = true
    getJson('/api/result?include_tests=false')
      .then((body) => current && setTrimmed({ of: full, result: body }))
      .catch((e: Error) => current && setError(e.message))
    return () => {
      current = false
    }
  }, [full])

  const send = useCallback(async (url: string, init: RequestInit): Promise<boolean> => {
    setBusy(true)
    setMessage(undefined)
    try {
      const r = await fetch(url, { method: 'POST', ...init })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`)
      setData(body)
      setSource('scan')
      return true
    } catch (e) {
      setMessage(`Scan failed: ${(e as Error).message}`)
      return false
    } finally {
      setBusy(false)
    }
  }, [])

  // Drops the stored scan on the server; every page then shows the empty state.
  const clear = async () => {
    setBusy(true)
    setMessage(undefined)
    try {
      const r = await fetch('/api/scan', { method: 'DELETE' })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`)
      setData(undefined)
      setSource('none')
    } catch (e) {
      setMessage(`Clear failed: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  const json = (body: object): RequestInit => ({ headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const scan = (paths: string[], types?: string[]) => send('/api/scan', json({ paths, types }))
  const scanStarterKit = (types?: string[]) => send('/api/scan/starter-kit', json({ types }))
  const scanGithub = (url: string, types?: string[]) => send('/api/scan/github', json({ url, types }))
  const scanZip = (file: File, types?: string[]) => {
    const body = new FormData()
    body.append('file', file)
    if (types) body.append('types', types.join(','))
    return send('/api/scan/upload', { body })
  }

  const trimmed = trimmedFor?.of === full ? trimmedFor?.result : undefined
  const present = full?.findings.some((f) => f.in_test_code) ?? false
  const scored = (r?: ScanResult) => r?.assets.filter((a) => a.max_points > 0).length ?? 0
  // Until the trimmed result arrives the full one is shown, so the page never goes blank on a toggle.
  const data = includeTests || !trimmed ? full : trimmed
  const testCode: TestCode = {
    present,
    hiddenFindings: trimmed && full ? full.findings.length - trimmed.findings.length : 0,
    hiddenAssets: trimmed ? scored(full) - scored(trimmed) : 0,
  }

  return createElement(
    ScanContext.Provider,
    {
      value: {
        data, includeTests, setIncludeTests, testCode,
        error, source, busy, message, scan, scanGithub, scanZip, clear, scanStarterKit,
      },
    },
    children,
  )
}

export function useScan(): Scan {
  const value = useContext(ScanContext)
  if (!value) throw new Error('useScan needs a ScanProvider')
  return value
}

export function useScanResult() {
  const { data, error, includeTests, setIncludeTests, testCode } = useScan()
  return { data, error, includeTests, setIncludeTests, testCode }
}
