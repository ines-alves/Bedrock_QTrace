import { createContext, createElement, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import type { components } from './schema'

export type ScanResult = components['schemas']['ScanResult']
type Source = 'none' | 'scan'

type Scan = {
  data?: ScanResult
  error?: string
  source?: Source
  busy: boolean
  message?: string
  scan: (paths: string[]) => Promise<void>
  scanGithub: (url: string) => Promise<void>
  scanZip: (file: File) => Promise<void>
  clear: () => Promise<void>
  scanStarterKit: () => Promise<void>
}

const getJson = (url: string) => fetch(url).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))

const ScanContext = createContext<Scan | undefined>(undefined)

// One shared result for every page: a scan started anywhere updates all of them at once.
export function ScanProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<ScanResult>()
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

  const send = useCallback(async (url: string, init: RequestInit) => {
    setBusy(true)
    setMessage(undefined)
    try {
      const r = await fetch(url, { method: 'POST', ...init })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`)
      setData(body)
      setSource('scan')
    } catch (e) {
      setMessage(`Scan failed: ${(e as Error).message}`)
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
  const scan = (paths: string[]) => send('/api/scan', json({ paths }))
  const scanStarterKit = () => send('/api/scan/starter-kit', {})
  const scanGithub = (url: string) => send('/api/scan/github', json({ url }))
  const scanZip = (file: File) => {
    const body = new FormData()
    body.append('file', file)
    return send('/api/scan/upload', { body })
  }

  return createElement(
    ScanContext.Provider,
    { value: { data, error, source, busy, message, scan, scanGithub, scanZip, clear, scanStarterKit } },
    children,
  )
}

export function useScan(): Scan {
  const value = useContext(ScanContext)
  if (!value) throw new Error('useScan needs a ScanProvider')
  return value
}

export function useScanResult() {
  const { data, error } = useScan()
  return { data, error }
}
