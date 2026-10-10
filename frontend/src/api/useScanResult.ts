import { useEffect, useState } from 'react'
import type { components } from './schema'

export type ScanResult = components['schemas']['ScanResult']

export function useScanResult() {
  const [data, setData] = useState<ScanResult>()
  const [error, setError] = useState<string>()

  useEffect(() => {
    fetch('/api/result')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [])

  return { data, error }
}
