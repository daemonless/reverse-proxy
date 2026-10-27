// Thin client for the admin API. Cookie sessions ride along automatically;
// a 401 anywhere sends the person to sign in.
export class ApiError extends Error {
  status: number
  field: string
  detail: string
  retryAfter: number
  constructor(status: number, message: string, field = '', detail = '', retryAfter = 0) {
    super(message)
    this.status = status
    this.field = field
    this.detail = detail
    this.retryAfter = retryAfter
  }
}

let onUnauthorized: () => void = () => {}

/** Called on any 401 so the app can send the person to sign in. */
export function setOnUnauthorized(fn: () => void) { onUnauthorized = fn }

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  // No answer at all (the proxy restarting, the network gone) is said as
  // such, not as "Something went wrong".
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError(0, "Can't reach the proxy. It may be restarting: try again in a moment.")
  }
  const text = await res.text()
  let data: any = null
  try { data = text ? JSON.parse(text) : null } catch { data = null }
  if (res.ok && text && data === null) {
    // Not JSON: a redirect landed on a page (the port-80 trust page).
    throw new ApiError(res.status, 'Unexpected answer from the proxy')
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/api/v1/login') && !path.startsWith('/api/v1/setup/')) onUnauthorized()
    throw new ApiError(res.status, data?.error ?? `Request failed (${res.status})`, data?.field ?? '', data?.detail ?? '', data?.retryAfter ?? 0)
  }
  return data as T
}

export const get = <T>(path: string) => api<T>('GET', path)
export const post = <T>(path: string, body?: unknown) => api<T>('POST', path, body ?? {})
export const put = <T>(path: string, body: unknown) => api<T>('PUT', path, body)
export const del = <T>(path: string) => api<T>('DELETE', path)

export type Target = { address: string; port: number; https: boolean; acceptUntrusted: boolean }
export type Host = {
  id: string
  name: string
  extraNames?: string[]
  target: Target
  access: 'home' | 'internet'
  trustedNetworks?: string[]
  ref?: string
  ownOrigin?: boolean
  createdAt: string
  deletedAt?: string
  names: string[]
  url: string
}
export type Health = { reachable: boolean; https: boolean; untrustedCert: boolean; status?: number; self?: boolean }
export type Settings = { domain: string; mode: '' | 'public' | 'private'; trustedNetworks: string[]; shortLinks?: string; localDomain?: string; fallbackUrl?: string }
export type Session = { authenticated: boolean; kind: string; setupRequired: boolean }
export type Status = { version: string; caddy: { running: boolean; version?: string }; setup: { complete: boolean }; domain?: string; mode?: string; hosts?: number; certificates?: string }
export type Token = { id: string; label: string; createdAt: string; lastUsedAt?: string; paired?: boolean; disabled?: boolean; url?: string; clientId?: string; names?: number }
export type FjordSource = { url: string; hasKey: boolean }
export type FjordService = { stack: string; label: string; title: string; state: string; address: string; port: number; webUI: boolean; ref: string; added?: string; addedName?: string }
export type TrustInfo = { domain: string; mode: string; httpPort: number; needed: boolean; instance?: string; proxyName?: string; fingerprint?: string; rootUrl?: string; notAfter?: string }
export type ProviderField = { key: string; label: string; secret: boolean; placeholder?: string; optional?: boolean }
export type FreeName = { suffix: string; signUp: string; steps: string[]; note?: string }
export type Provider = { id: string; label: string; fields: ProviderField[]; help: string; steps?: string[]; url?: string; generic?: boolean; checked?: boolean; free?: FreeName }
/** manual: own root · trial: proving the token · issuing: the real certificate is on its way · ok · failed */
export type CertStatus = { state: 'manual' | 'trial' | 'issuing' | 'ok' | 'failed'; provider?: string; issuer?: string; notAfter?: string; daysLeft?: number; message?: string; detail?: string; since?: string; fix?: 'token' }
export type Certificates = { domain: string; mode: string; providers: Provider[]; provider?: string; status: CertStatus }
export type ProviderGuess = { zone: string; nameservers: string[]; provider?: string }
export type DnsCheck = { name: string; addresses: string[]; proxyAddresses?: string[]; notFound?: boolean; error?: string; short?: { name: string; addresses: string[]; notFound?: boolean } }
