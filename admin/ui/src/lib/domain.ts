// Mirrors the server's suffix rules so the setup screen can explain the
// consequence as the person types.
const privateSuffixes = ['.lan', '.internal', '.home.arpa', '.home', '.test', '.localdomain']

export type Kind = 'empty' | 'incomplete' | 'private' | 'public' | 'mdns'

export function classify(domain: string): Kind {
  const d = domain.trim().toLowerCase().replace(/\.$/, '')
  if (!d) return 'empty'
  if (d.endsWith('.local') || d === 'local') return 'mdns'
  if (!d.includes('.')) return 'incomplete'
  if (privateSuffixes.some((s) => d.endsWith(s) || d === s.slice(1))) return 'private'
  return 'public'
}
