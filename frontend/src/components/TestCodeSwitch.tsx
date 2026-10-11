import { useScan } from '../api/useScanResult'

// One setting for the whole dashboard: with test code off, the engine's score, tiers and roadmap are for
// the rest of the evidence. Hidden when the scan has no test code, so it never offers a no-op.
export default function TestCodeSwitch() {
  const { includeTests, setIncludeTests, testCode } = useScan()
  if (!testCode.present) return null
  return (
    <button type="button" role="switch" aria-checked={includeTests} onClick={() => setIncludeTests(!includeTests)}
      title={includeTests ? 'Test code is counted in the score and lists' : 'Test code is left out of the score and lists'}
      className="inline-flex items-center gap-3 rounded-full border border-paper/40 px-6 py-3 font-head text-sm font-semibold text-paper/80 hover:border-paper hover:text-paper">
      <span className={`inline-block h-5 w-9 rounded-full p-0.5 ${includeTests ? 'bg-aqua' : 'bg-paper/25'}`}>
        <span className={`block h-4 w-4 rounded-full bg-paper transition-transform ${includeTests ? 'translate-x-4' : ''}`} />
      </span>
      Include test code
    </button>
  )
}
