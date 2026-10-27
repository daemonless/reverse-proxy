// Toasts carry the Undo for destructive actions, per the HIG: no "Are you
// sure?" dialogs.
export type Toast = { id: number; text: string; action?: { label: string; run: () => void }; timer: number }

let items = $state<Toast[]>([])
let seq = 0

export const toasts = {
  get items() { return items },
}

export function toast(text: string, action?: Toast['action'], ms = action ? 8000 : 4000) {
  const id = ++seq
  const timer = window.setTimeout(() => dismiss(id), ms)
  items = [...items, { id, text, action, timer }]
  return id
}

export function dismiss(id: number) {
  const t = items.find((x) => x.id === id)
  if (t) window.clearTimeout(t.timer)
  items = items.filter((x) => x.id !== id)
}
