import { NavLink, Route, Routes } from 'react-router-dom'
import CodeConfig from './pages/CodeConfig.tsx'
import Network from './pages/Network.tsx'
import Overview from './pages/Overview.tsx'

const link = ({ isActive }: { isActive: boolean }) =>
  `px-3 py-1 text-xs uppercase tracking-widest ${isActive ? 'text-aqua' : 'text-paper/50'}`

export default function App() {
  return (
    <>
      <nav className="flex gap-2 border-b border-paper/10 px-6 py-3">
        <NavLink to="/" end className={link}>Overview</NavLink>
        <NavLink to="/code-config" className={link}>Code &amp; Config</NavLink>
        <NavLink to="/network" className={link}>Network</NavLink>
      </nav>
      <main className="p-6">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/code-config" element={<CodeConfig />} />
          <Route path="/network" element={<Network />} />
        </Routes>
      </main>
    </>
  )
}
