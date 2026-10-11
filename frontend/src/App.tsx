import { NavLink, Route, Routes } from 'react-router-dom'
import { ScanProvider, useScan } from './api/useScanResult'
import ScanBar from './components/ScanBar.tsx'
import Cbom from './pages/Cbom.tsx'
import Cloud from './pages/Cloud.tsx'
import CodeConfig from './pages/CodeConfig.tsx'
import Network from './pages/Network.tsx'
import Overview from './pages/Overview.tsx'
import Roadmap from './pages/Roadmap.tsx'

const link = ({ isActive }: { isActive: boolean }) =>
  `rounded-full px-4 py-1.5 font-head text-sm font-medium ${isActive ? 'bg-paper/10 text-aqua' : 'text-paper/60 hover:text-paper'}`

function SourceChip() {
  const { source, data } = useScan()
  if (!source || !data) return null
  const live = source === 'scan'
  return (
    <span className={`rounded-full border px-3 py-1 text-xs ${live ? 'border-aqua text-aqua' : 'border-paper/30 text-paper/60'}`}
      title={`Scan ${data.scan_id}`}>
      {live ? `Live scan, ${data.finished_at.slice(0, 16).replace('T', ' ')} UTC` : 'Bundled sample'}
    </span>
  )
}

export default function App() {
  return (
    <ScanProvider>
      <header className="sticky top-0 z-10 flex flex-wrap items-center gap-x-6 border-b border-paper/10 bg-ink/50 px-6 backdrop-blur-xl">
        <span className="py-3 font-head text-lg font-bold">QuantumTrace</span>
        <nav className="flex flex-wrap gap-1">
          <NavLink to="/" end className={link}>Overview</NavLink>
          <NavLink to="/code-config" className={link}>Code &amp; config</NavLink>
          <NavLink to="/network" className={link}>Network</NavLink>
          <NavLink to="/cloud" className={link}>Cloud</NavLink>
          <NavLink to="/cbom" className={link}>CBOM</NavLink>
          <NavLink to="/roadmap" className={link}>Roadmap</NavLink>
        </nav>
        <span className="ml-auto py-2"><SourceChip /></span>
      </header>
      <main className="p-6">
        <ScanBar />
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/code-config" element={<CodeConfig />} />
          <Route path="/network" element={<Network />} />
          <Route path="/cloud" element={<Cloud />} />
          <Route path="/cbom" element={<Cbom />} />
          <Route path="/roadmap" element={<Roadmap />} />
        </Routes>
      </main>
    </ScanProvider>
  )
}
