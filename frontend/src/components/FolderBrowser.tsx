import { useEffect, useState, type FormEvent } from 'react'

type Entry = { name: string; path: string; is_dir: boolean }
type Listing = { path: string; parent: string | null; entries: Entry[]; truncated: boolean }

type Props = { start: string; selected: string[]; onToggle: (path: string) => void }

export default function FolderBrowser({ start, selected, onToggle }: Props) {
  const [path, setPath] = useState(start)
  const [listing, setListing] = useState<Listing>()
  const [error, setError] = useState<string>()
  const [typed, setTyped] = useState('')

  useEffect(() => {
    fetch(`/api/browse?path=${encodeURIComponent(path)}`)
      .then(async (r) => {
        const body = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(body.detail ?? `HTTP ${r.status}`)
        setListing(body)
        setError(undefined)
      })
      .catch((e: Error) => setError(e.message))
  }, [path])

  function add(event: FormEvent) {
    event.preventDefault()
    if (typed.trim() && !selected.includes(typed.trim())) onToggle(typed.trim())
    setTyped('')
  }

  return (
    <div className="mt-3 space-y-3 border-t border-paper/10 pt-3">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" disabled={!listing || listing.path === start || listing.parent === null} onClick={() => setPath(listing?.parent ?? '')}
          className="rounded-full border border-paper/30 px-3 py-1 disabled:opacity-30">
          Up
        </button>
        <span className="text-paper/70">{listing ? listing.path : 'Loading'}</span>
      </div>
      {error && <p role="alert" className="text-paper/80">Cannot open this folder: {error}</p>}
      <ul className="grid max-h-64 gap-1 overflow-y-auto sm:grid-cols-2">
        {listing?.entries.map((e) => {
          const on = selected.includes(e.path)
          return (
            <li key={e.path} className="flex items-center justify-between gap-2 rounded-xl bg-ink/60 px-3 py-1.5">
              {e.is_dir ? (
                <button type="button" onClick={() => setPath(e.path)} className="min-w-0 truncate text-left hover:text-aqua">
                  {e.name}/
                </button>
              ) : (
                <span className="min-w-0 truncate text-paper/70">{e.name}</span>
              )}
              <button type="button" aria-pressed={on} onClick={() => onToggle(e.path)}
                className={`shrink-0 rounded-full border px-3 py-0.5 text-xs ${on ? 'border-aqua bg-aqua text-on-accent' : 'border-aqua text-aqua'}`}>
                {on ? 'Added' : 'Add'}
              </button>
            </li>
          )
        })}
      </ul>
      {listing?.truncated && <p className="text-paper/60">Only the first entries are shown. Open a subfolder to see more.</p>}
      <form onSubmit={add} className="flex flex-wrap items-center gap-2">
        <label htmlFor="typed-path" className="text-paper/70">Or type a path</label>
        <input id="typed-path" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="folder/or/file"
          className="min-w-48 flex-1 rounded-xl bg-ink/60 px-3 py-1.5 placeholder:text-paper/40" />
        <button type="submit" disabled={!typed.trim()} className="rounded-full border border-paper/30 px-3 py-1 disabled:opacity-30">Add path</button>
      </form>
    </div>
  )
}
