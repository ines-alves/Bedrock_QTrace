import { useState, type ReactNode } from 'react'

export type Column<T> = {
  header: string
  sort: (row: T) => string | number
  cell: (row: T) => ReactNode
}

export default function SortableTable<T>({ rows, columns, large = false }: { rows: T[]; columns: Column<T>[]; large?: boolean }) {
  const [sort, setSort] = useState<{ col: number; dir: 1 | -1 }>()

  const shown = sort
    ? [...rows].sort((a, b) => {
        const x = columns[sort.col].sort(a)
        const y = columns[sort.col].sort(b)
        return (x < y ? -1 : x > y ? 1 : 0) * sort.dir
      })
    : rows

  return (
    <table className={`w-full text-left ${large ? 'text-lg' : 'text-sm'}`}>
      <thead>
        <tr className="border-b border-paper/10 text-paper/50">
          {columns.map((c, i) => (
            <th key={c.header} className={`cursor-pointer select-none px-3 font-medium ${large ? 'py-3' : 'py-2'}`}
              onClick={() => setSort({ col: i, dir: sort?.col === i ? (-sort.dir as 1 | -1) : 1 })}>
              {c.header}{sort?.col === i ? (sort.dir === 1 ? ' ▲' : ' ▼') : ''}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {shown.map((row, r) => (
          <tr key={r} className="border-b border-paper/10">
            {columns.map((c) => <td key={c.header} className={`px-3 ${large ? 'py-5' : 'py-2'}`}>{c.cell(row)}</td>)}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
