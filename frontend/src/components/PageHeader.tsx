import type { ReactNode } from 'react'

export default function PageHeader({ title, lead, children }: { title: string; lead?: string; children?: ReactNode }) {
  return (
    <header className="mb-8 space-y-3">
      <h1 className="max-w-4xl font-head text-4xl font-bold leading-tight">{title}</h1>
      {lead && <p className="max-w-2xl text-xl leading-relaxed text-paper/75">{lead}</p>}
      {children && <div className="flex flex-wrap gap-3 pt-1">{children}</div>}
    </header>
  )
}
