import { get, type Token } from './api'
import { session } from './session.svelte'

// The connected apps: the one that installed this proxy (paired key) and
// any that linked with a code or a key. `value` is the installer, for the
// header's way back; `apps` is everyone, for chips and the home row.
let all = $state<Token[]>([])
let loaded = $state(false)

export const paired = {
  get value() { return all.find((t) => t.paired) ?? null },
  get apps() { return all },
  /** The app that made a host: by the app's id in its ref
   *  ("<app>:<id>:<thing>"), else by the key that made it, else, for a fjord
   *  ref from before ids, the installer; failing all, the ref's first part.
   *  "" for a host made by hand. */
  appFor(h: { ref?: string; by?: string }): string {
    const ref = h.ref ?? ''
    const [kind, id] = ref.split(':')
    const byId = id ? all.find((t) => t.clientId && t.clientId === id) : undefined
    if (byId) return byId.label
    const byKey = h.by ? all.find((t) => t.id === h.by) : undefined
    if (byKey) return byKey.label
    if (kind === 'fjord') return all.find((t) => t.paired)?.label ?? kind
    return kind
  },
  get loaded() { return loaded },
  async load() {
    if (!session.value?.authenticated) return
    try { all = (await get<{ tokens: Token[] }>('/api/v1/tokens')).tokens }
    catch { all = [] }
    loaded = true
  },
}
