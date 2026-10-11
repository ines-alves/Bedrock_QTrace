import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

const base = 'inline-block rounded-full px-6 py-3 font-head text-sm font-semibold'
const style = (primary: boolean) =>
  `${base} ${primary ? 'bg-aqua text-on-accent hover:bg-paper hover:text-ink' : 'border border-aqua text-aqua hover:bg-aqua hover:text-on-accent'}`

type Props = { children: ReactNode; primary?: boolean } & (
  | { to: string }
  | { href: string; download?: string }
  | { onClick: () => void }
)

export default function Cta(props: Props) {
  const cls = style(props.primary ?? false)
  if ('to' in props) return <Link to={props.to} className={cls}>{props.children}</Link>
  if ('href' in props) return <a href={props.href} download={props.download} className={cls}>{props.children}</a>
  return <button type="button" onClick={props.onClick} className={cls}>{props.children}</button>
}
