import type { Hour } from './api'

/** One bar: its start, the checks in it, how many answered. */
export type Slot = { start: Date; checks: number; up: number }

/** The last n hours, oldest first, empty where nothing was checked. */
export function hourSlots(hours: Hour[], n: number, now = new Date()): Slot[] {
  const by = new Map(hours.map((h) => [h[0], h]))
  const top = Math.floor(now.getTime() / 3600000) * 3600
  const out: Slot[] = []
  for (let i = n - 1; i >= 0; i--) {
    const t = top - i * 3600
    const h = by.get(t)
    out.push({ start: new Date(t * 1000), checks: h?.[1] ?? 0, up: h?.[2] ?? 0 })
  }
  return out
}

/** The last n days on this device's clock, oldest first. */
export function daySlots(hours: Hour[], n: number, now = new Date()): Slot[] {
  const key = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
  const by = new Map<string, Slot>()
  for (const h of hours) {
    const d = new Date(h[0] * 1000)
    const k = key(d)
    const s = by.get(k) ?? { start: new Date(d.getFullYear(), d.getMonth(), d.getDate()), checks: 0, up: 0 }
    s.checks += h[1]; s.up += h[2]
    by.set(k, s)
  }
  const out: Slot[] = []
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i)
    out.push(by.get(key(d)) ?? { start: d, checks: 0, up: 0 })
  }
  return out
}

/** 99.95 -> "99.95%", 100 -> "100%", 12.3456 -> "12.3%". */
export function pct(p: number | null | undefined): string {
  if (p == null) return '—'
  if (p === 100) return '100%'
  if (p === 0) return '0%'
  if (p >= 99) return `${(Math.floor(p * 100) / 100).toFixed(2)}%`
  return `${(Math.floor(p * 10) / 10).toFixed(1)}%`
}

/** Whether the history goes back the whole window. */
export function covers(from: string | undefined, days: number, now = new Date()): boolean {
  return !!from && new Date(from).getTime() <= now.getTime() - days * 86400000
}

/** "30 days", or "since 10:06" when the history is younger than that. */
export function span(from: string | undefined, days: number, now = new Date()): string {
  if (!from || covers(from, days, now)) return `${days} days`
  return `since ${when(from, now)}`
}

/** 40 s, 12 min, 3 h 5 min, 2 days */
export function lasted(ms: number): string {
  const m = Math.floor(ms / 60000)
  if (m < 1) return `${Math.max(1, Math.floor(ms / 1000))} s`
  if (m < 60) return `${m} min`
  if (m < 48 * 60) return m % 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m / 60} h`
  return `${Math.floor(m / 1440)} days`
}

/** "14:02" today, "Tue 03:10" this week, "12 Oct 03:10" before. */
export function when(iso: string, now = new Date()): string {
  const d = new Date(iso)
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  if (d.toDateString() === now.toDateString()) return time
  if (now.getTime() - d.getTime() < 6 * 86400000) return `${d.toLocaleDateString([], { weekday: 'short' })} ${time}`
  return `${d.toLocaleDateString([], { day: 'numeric', month: 'short' })} ${time}`
}
