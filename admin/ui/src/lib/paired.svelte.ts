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
  /** The app behind a host's ref ("fjord:<id>:<stack>"), by its id. A fjord
   *  ref no id claims is the installer's (made before ids existed). */
  appFor(ref: string): string {
    const [kind, id] = ref.split(':')
    const byId = all.find((t) => t.clientId && t.clientId === id)
    if (byId) return byId.label
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
