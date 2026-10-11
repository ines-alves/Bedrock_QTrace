import { useState } from 'react'

export type Theme = 'light' | 'dark'

export function useTheme(): [Theme, (theme: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'))
  function change(next: Theme) {
    setTheme(next)
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem('qt-theme', next)
    } catch {
      // storage can be blocked; the theme still applies for this visit
    }
  }
  return [theme, change]
}
