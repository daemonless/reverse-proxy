// What ships in the image and under which license. Every entry was read
// from the component's own LICENSE file or package metadata, not assumed.
export type Credit = { name: string; role: string; license: string; url: string }

export const ourLicense = { name: 'BSD-2-Clause', url: 'https://github.com/daemonless/reverse-proxy/blob/main/LICENSE' }

export const credits: Credit[] = [
  { name: 'Caddy', role: 'The web server and reverse proxy doing the actual work: TLS, routing, certificates', license: 'Apache-2.0', url: 'https://github.com/caddyserver/caddy' },
  { name: 'caddy-dns/cloudflare', role: 'DNS module for Cloudflare', license: 'Apache-2.0', url: 'https://github.com/caddy-dns/cloudflare' },
  { name: 'caddy-dns/route53', role: 'DNS module for Amazon Route 53', license: 'MIT', url: 'https://github.com/caddy-dns/route53' },
  { name: 'caddy-dns/desec', role: 'DNS module for deSEC', license: 'MIT', url: 'https://github.com/caddy-dns/desec' },
  { name: 'caddy-dns/porkbun', role: 'DNS module for Porkbun', license: 'MIT', url: 'https://github.com/caddy-dns/porkbun' },
  { name: 'caddy-dns/hetzner', role: 'DNS module for Hetzner', license: 'MIT', url: 'https://github.com/caddy-dns/hetzner' },
  { name: 'caddy-dns/ovh', role: 'DNS module for OVH', license: 'MIT', url: 'https://github.com/caddy-dns/ovh' },
  { name: 'caddy-dns/gandi', role: 'DNS module for Gandi', license: 'MIT', url: 'https://github.com/caddy-dns/gandi' },
  { name: 'caddy-dns/rfc2136', role: 'DNS module for any RFC 2136 server (BIND, PowerDNS, Knot)', license: 'MIT', url: 'https://github.com/caddy-dns/rfc2136' },
  { name: 'caddy-dns/acmedns', role: 'DNS module for acme-dns', license: 'MIT', url: 'https://github.com/caddy-dns/acmedns' },
  { name: 'caddy-dns/duckdns', role: 'DNS module for DuckDNS (no license file upstream)', license: 'none stated', url: 'https://github.com/caddy-dns/duckdns' },
  { name: 'libdns/duckdns', role: 'DuckDNS client the module uses', license: 'MIT', url: 'https://github.com/libdns/duckdns' },
  { name: 'golang.org/x/crypto', role: 'argon2id password hashing and backup encryption', license: 'BSD-3-Clause', url: 'https://pkg.go.dev/golang.org/x/crypto' },
  { name: 'golang.org/x/sys', role: 'Used by x/crypto', license: 'BSD-3-Clause', url: 'https://pkg.go.dev/golang.org/x/sys' },
  { name: 'skip2/go-qrcode', role: 'The QR code on the trust page', license: 'MIT', url: 'https://github.com/skip2/go-qrcode' },
  { name: 'Svelte', role: 'This user interface', license: 'MIT', url: 'https://svelte.dev' },
  { name: 'FreeBSD', role: 'The operating system inside the image', license: 'BSD-2-Clause', url: 'https://www.freebsd.org' },
  { name: 's6, execline, skalibs', role: 'Process supervision inside the image', license: 'ISC', url: 'https://skarnet.org/software/s6/' },
  { name: 'ca_root_nss', role: 'Public certificate authorities, for the proxy to verify targets', license: 'MPL-2.0', url: 'https://www.freshports.org/security/ca_root_nss' },
]

// Built with (not shipped): Vite (MIT), Tailwind CSS (MIT), TypeScript (Apache-2.0), Go (BSD-3-Clause).
export const buildTools = 'Built with Vite, Tailwind CSS, TypeScript and Go, which are not part of the running image.'
