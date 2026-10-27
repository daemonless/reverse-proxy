import { get, type TrustInfo } from './api'
import { session } from './session.svelte'

// Does this device trust the proxy? One answer for the header's dot and
// the home page's status row. With public certificates there is nothing
// to trust (needed = false).
/** Who answers at a proxy's /trust/check: this proxy, another proxy that
 *  has the same name (an old DNS record, a second proxy with the same
 *  ending), or nobody this device trusts (null). */
export async function whoAnswers(url: string, instance?: string): Promise<'ours' | 'other' | null> {
  try {
    const r = await fetch(url, { mode: 'cors', cache: 'no-store', signal: AbortSignal.timeout(4000) })
    const j = await r.json().catch(() => ({}))
    // No id to compare with (this page talks to an older admin): take its word.
    if (!instance) return 'ours'
    return j.instance === instance ? 'ours' : 'other'
  } catch { return null }
}

let untrusted = $state(false)
let needed = $state(true)
let checked = $state(false)

export const deviceTrust = {
  get untrusted() { return untrusted },
  get needed() { return needed },
  get checked() { return checked },
  async check() {
    if (!session.value?.authenticated) return
    try {
      const t = await get<TrustInfo>('/api/v1/trust')
      needed = t.needed !== false
      if (!needed) { untrusted = false; checked = true; return }
      if (!t.proxyName || !t.fingerprint) return
      untrusted = (await whoAnswers(`https://${t.proxyName}/trust/check`, t.instance)) !== 'ours'
      checked = true
    } catch {}
  },
}
