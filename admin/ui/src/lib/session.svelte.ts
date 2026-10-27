import { get, type Session } from './api'

let current = $state<Session | null>(null)

export const session = {
  get value() { return current },
  async refresh() {
    // On the plain-HTTP trust page the API is not reachable; anything that
    // is not a session answer means "not signed in".
    try {
      const s = await get<Session>('/api/v1/session')
      current = s && typeof s.authenticated === 'boolean' ? s : { authenticated: false, kind: 'none', setupRequired: false }
    } catch {
      current = { authenticated: false, kind: 'none', setupRequired: false }
    }
    return current
  },
  signedOut() { current = { authenticated: false, kind: 'none', setupRequired: current?.setupRequired ?? false } },
}
