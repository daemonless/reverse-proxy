// Theme, the way fjord does it: <html data-theme> is what the CSS keys off,
// index.html stamps it before first paint, this keeps it in sync after.
// Storage holds only an explicit choice; none means the OS drives.
export type Theme = 'light' | 'dark'
const KEY = 'fjord-theme'

function stored(): Theme | null {
  try { const v = localStorage.getItem(KEY); return v === 'light' || v === 'dark' ? v : null } catch { return null }
}
function system(): Theme {
  try { return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark' } catch { return 'dark' }
}
function apply(t: Theme) { document.documentElement.setAttribute('data-theme', t); current = t }

let current = $state<Theme>((document.documentElement.getAttribute('data-theme') as Theme) || stored() || system())

export const theme = {
  get value() { return current },
  set(t: Theme) { try { localStorage.setItem(KEY, t) } catch {} apply(t) },
  toggle() { theme.set(current === 'dark' ? 'light' : 'dark') },
}

// Follow the OS while nothing is chosen (a machine that flips at sunset).
try {
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => { if (stored() === null) apply(system()) })
} catch {}
