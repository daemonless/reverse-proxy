// Where to add the one DNS record, per resolver people actually run at
// home. Wording follows each product's own menus; anything we are not sure
// of says so rather than inventing a menu path.
export type Resolver = 'opnsense' | 'pfsense' | 'adguard' | 'pihole' | 'unifi' | 'other'

export const resolvers: { id: Resolver; label: string }[] = [
  { id: 'opnsense', label: 'OPNsense' },
  { id: 'pfsense', label: 'pfSense' },
  { id: 'adguard', label: 'AdGuard Home' },
  { id: 'pihole', label: 'Pi-hole' },
  { id: 'unifi', label: 'UniFi' },
  { id: 'other', label: 'Something else' },
]

/** A step is a sentence, or a sentence and the form fields it fills in. */
export type Step = string | { text: string; fields: [string, string][] }

export type Guide = {
  intro?: string
  steps: Step[]
  /** The guide fills in every value itself; no separate record box. */
  complete?: boolean
  paste?: (domain: string, ip: string) => string
  pasteLabel?: string
  note?: string
}

export const guides: Record<Resolver, Guide> = {
  opnsense: {
    complete: true,
    steps: [
      'Open OPNsense and go to Services → Unbound DNS → Overrides.',
      'Under Host Overrides, click + to add one.',
      { text: 'Fill in the form:', fields: [['Host', '*'], ['Domain', '{DOMAIN}'], ['Type', 'A (IPv4 address)'], ['IP address', '{IP}']] },
      'Untick Add PTR record. It is not needed here.',
      'Click Save, then Apply.',
    ],
    note: 'If Unbound is not your resolver (for example you forward to AdGuard Home), add the record there instead.',
  },
  pfsense: {
    complete: true,
    intro: "pfSense's Host Overrides can't take a wildcard, so the record goes in the resolver's custom options.",
    steps: [
      'Open pfSense and go to Services → DNS Resolver → General Settings.',
      'Click Display Custom Options at the bottom and paste the lines below into the box.',
      'Save, then click Apply Changes.',
    ],
    paste: (domain, ip) => `server:\n  local-zone: "${domain}" redirect\n  local-data: "${domain} A ${ip}"`,
    pasteLabel: 'Custom options',
  },
  adguard: {
    complete: true,
    steps: [
      'Open AdGuard Home and go to Filters → DNS rewrites.',
      'Click Add DNS rewrite.',
      { text: 'Fill in:', fields: [['Domain', '*.{DOMAIN}'], ['Answer', '{IP}']] },
      'Save.',
    ],
  },
  pihole: {
    complete: true,
    intro: "Pi-hole's Local DNS Records can't take a wildcard, so the record goes in a dnsmasq file.",
    steps: [
      'On the Pi-hole machine, create the file /etc/dnsmasq.d/99-reverse-proxy.conf with the line below.',
      'Run: pihole restartdns',
    ],
    paste: (domain, ip) => `address=/${domain}/${ip}`,
    pasteLabel: '/etc/dnsmasq.d/99-reverse-proxy.conf',
    note: 'Pi-hole 6 ignores /etc/dnsmasq.d until you turn on "misc.etc_dnsmasq_d" in Settings → All settings (expert mode).',
  },
  unifi: {
    intro: 'UniFi gateways can hold local DNS records in the Network app; the menu has moved between versions.',
    steps: [
      'Open the UniFi Network app and look for Local DNS Records (recent versions: Settings → Routing → DNS; older: under Networks or the Policy Table).',
      'Add a record: Domain *.{DOMAIN} pointing at {IP}.',
      'If your version refuses a wildcard (*), add two records for now, proxy.{DOMAIN} and the first host you create, both pointing at {IP}.',
    ],
    note: 'If your UniFi gateway forwards DNS to another server (AdGuard Home, Pi-hole), add the record there instead.',
  },
  other: {
    intro: 'Any resolver that lets you add a local name will do.',
    steps: [
      'In your router or DNS server, find the DNS section: Local DNS, Host names, Static DNS entries or similar.',
      'Add an A record for *.{DOMAIN} pointing at {IP}.',
      "If it can't take a wildcard (*), add proxy.{DOMAIN} and each host you create, all pointing at {IP}.",
    ],
    note: 'For a quick test on one computer you can also add the names to its hosts file; other devices will still need the record.',
  },
}


// The short-link record: one plain name ({SHORT}, e.g. go) under the
// network's own domain ({LOCAL}, e.g. lan), so no wildcard tricks: every
// resolver's ordinary form takes it.
export const shortGuides: Record<Resolver, Guide> = {
  opnsense: {
    steps: [
      'Open OPNsense and go to Services → Unbound DNS → Overrides.',
      'Under Host Overrides, click + to add one.',
      { text: 'Fill in the form:', fields: [['Host', '{SHORT}'], ['Domain', '{LOCAL}'], ['Type', 'A (IPv4 address)'], ['IP address', '{IP}']] },
      'Untick Add PTR record, click Save, then Apply.',
    ],
  },
  pfsense: {
    steps: [
      'Open pfSense and go to Services → DNS Resolver → General Settings.',
      'Under Host Overrides at the bottom, click Add.',
      { text: 'Fill in the form:', fields: [['Host', '{SHORT}'], ['Parent domain of host', '{LOCAL}'], ['IP to return for host', '{IP}']] },
      'Save, then click Apply Changes.',
    ],
  },
  adguard: {
    steps: [
      'Open AdGuard Home and go to Filters → DNS rewrites.',
      'Click Add DNS rewrite.',
      { text: 'Fill in:', fields: [['Domain', '{SHORT}.{LOCAL}'], ['Answer', '{IP}']] },
      'Save.',
    ],
  },
  pihole: {
    steps: [
      'Open Pi-hole and go to Local DNS Records (Pi-hole 6: Settings → Local DNS Records; older: Local DNS → DNS Records).',
      { text: 'Add a record:', fields: [['Domain', '{SHORT}.{LOCAL}'], ['IP', '{IP}']] },
      'Click Add.',
    ],
  },
  unifi: {
    steps: [
      'Open the UniFi Network app and go to Local DNS Records (recent versions: Settings → Routing → DNS).',
      { text: 'Add a record:', fields: [['Domain', '{SHORT}.{LOCAL}'], ['IP address', '{IP}']] },
      'Save.',
    ],
  },
  other: {
    steps: [
      'In your router or DNS server, find Local DNS, Host names or Static DNS entries.',
      { text: 'Add a name:', fields: [['Name', '{SHORT}.{LOCAL}'], ['Address', '{IP}']] },
    ],
    note: 'Some routers add their own domain by themselves: then the name is just {SHORT}.',
  },
}
