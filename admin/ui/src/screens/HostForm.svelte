<script lang="ts">
  import { focus } from '../lib/focus'
  import { get, post, put, del, ApiError, type Host, type Health, type Settings } from '../lib/api'
  import { link, navigate } from '../lib/router.svelte'
  import { toast } from '../lib/toast.svelte'

  let { id }: { id: string } = $props()
  const editing = $derived(id !== '')

  let settings = $state<Settings | null>(null)
  let name = $state('')
  let nameEdited = $state(false)
  let extraNames = $state('')
  // One field for where the service is: a pasted address as the person
  // opens it today (https://router.home.lan/ui/core/dashboard), host:port,
  // or a bare host. Address, port and HTTPS are read out of it; a missing
  // port is found by looking on 443 and 80.
  let where = $state('')
  let address = $state('')
  let port = $state('')
  let access = $state<'home' | 'internet'>('home')
  let https = $state(false)
  let acceptUntrusted = $state(false)
  let trustedNetworks = $state('')
  let ownOrigin = $state(false)
  let error = $state('')
  let errorField = $state('')
  let busy = $state(false)
  let loaded = $state(false)
  let advancedOpen = $state(false)
  let ref = $state('')

  type Where = { address: string; port: number; https: boolean | null }
  const isIP = (h: string) => /^[0-9.]+$/.test(h) || h.includes(':')
  /** What the text says: a URL, host:port, or a host. port 0 and https
   *  null mean "not said"; the probe fills them in. */
  function parseWhere(text: string): Where {
    let t = text.trim()
    if (!t) return { address: '', port: 0, https: null }
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) t = 'http://' + t
    try {
      const u = new URL(t)
      const scheme = u.protocol.replace(':', '').toLowerCase()
      const said = /^[a-z][a-z0-9+.-]*:\/\//i.test(text.trim())
      const port = u.port ? Number(u.port) : said ? (scheme === 'https' ? 443 : 80) : 0
      return { address: u.hostname.replace(/^\[|\]$/g, ''), port, https: said ? scheme === 'https' : null }
    } catch {
      return { address: t, port: 0, https: null }
    }
  }
  function onWhere() {
    const w = parseWhere(where)
    address = w.address; port = w.port ? String(w.port) : ''
    if (w.https !== null) https = w.https
    if (!nameEdited && !editing && w.address && !isIP(w.address)) name = w.address.split('.')[0].toLowerCase().replace(/[^a-z0-9-]/g, '')
    scheduleProbe()
  }

  let probe = $state<Health | null>(null)
  let probing = $state(false)
  let probeTimer: number | undefined

  async function load() {
    settings = await get<Settings>('/api/v1/settings')
    if (!id) { loaded = true; return }
    {
      const h = await get<Host>(`/api/v1/hosts/${id}`)
      name = h.name; nameEdited = true; extraNames = (h.extraNames ?? []).join(', ')
      address = h.target.address; port = String(h.target.port)
      where = `${h.target.https ? 'https' : 'http'}://${h.target.address}:${h.target.port}`
      access = h.access; https = h.target.https; acceptUntrusted = h.target.acceptUntrusted
      trustedNetworks = (h.trustedNetworks ?? []).join(', ')
      ownOrigin = !!h.ownOrigin
      ref = h.ref ?? ''
      advancedOpen = https || !!h.extraNames?.length || !!h.trustedNetworks?.length || !!h.ownOrigin
      loaded = true
      runProbe()
    }
  }
  load()

  // The probe decides http vs https and whether the target's certificate
  // is self-signed, so the person never has to know.
  function scheduleProbe() {
    window.clearTimeout(probeTimer)
    probe = null
    probeTimer = window.setTimeout(runProbe, 500)
  }
  let triedPorts = $state<number[]>([])
  async function probeAt(addr: string, p: number): Promise<Health | null> {
    try { return await get<Health>(`/api/v1/probe?address=${encodeURIComponent(addr)}&port=${p}`) } catch { return null }
  }
  async function runProbe() {
    const w = parseWhere(where)
    if (!w.address) return
    const ports = w.port >= 1 && w.port <= 65535 ? [w.port] : [443, 80]
    probing = true; probe = null; triedPorts = ports
    try {
      for (const p of ports) {
        const r = await probeAt(w.address, p)
        if (r?.reachable) { port = String(p); probe = r; https = r.https; acceptUntrusted = r.untrustedCert; return }
        if (r && ports.length === 1) probe = r
      }
      if (!probe) probe = { reachable: false, https: false, untrustedCert: false }
    } finally { probing = false }
  }

  const list = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

  async function save(e: SubmitEvent) {
    e.preventDefault(); error = ''; errorField = ''
    if (!address.trim()) { error = 'Say where the service is'; errorField = 'target'; return }
    if (probe?.self) { error = `${address} leads back to this proxy. Use the address the service has, like 192.168.1.20:7878.`; errorField = 'target'; return }
    if (!(Number(port) >= 1)) { error = `Nothing answered at ${address} on 443 or 80. Add the port, like ${address}:8080.`; errorField = 'target'; return }
    busy = true
    const body = {
      name, extraNames: list(extraNames),
      target: { address: address.trim(), port: Number(port), https, acceptUntrusted },
      access, trustedNetworks: list(trustedNetworks), ref, ownOrigin,
    }
    try {
      if (editing) await put(`/api/v1/hosts/${id}`, body)
      else await post('/api/v1/hosts', body)
      navigate('/hosts')
    } catch (err) {
      if (err instanceof ApiError) { error = err.message; errorField = err.field } else error = 'Something went wrong'
    } finally { busy = false }
  }

  async function remove() {
    const label = `${name}.${settings?.domain}`
    await del(`/api/v1/hosts/${id}`)
    navigate('/hosts')
    toast(`Removed ${label}`, { label: 'Undo', run: async () => { await post(`/api/v1/hosts/${id}/restore`); window.dispatchEvent(new CustomEvent('hosts-changed')) } })
  }
</script>

<div class="border-b border-[color:var(--border)]">
  <div class="max-w-[960px] box-border px-5 md:px-8 min-h-14 flex items-center justify-between gap-4 flex-wrap">
    <a href="/hosts" use:link class="inline-flex items-center min-h-10 text-sm text-accent no-underline">
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="mr-1.5"><path d="M12 4l-6 6 6 6"></path></svg>
      Names
    </a>
    <div class="font-semibold text-base">{editing ? 'Edit name' : 'Add a name'}</div>
    <button class="btn-primary min-h-10" form="hostform" disabled={busy || !loaded}>Save</button>
  </div>
</div>

{#if loaded}
<form id="hostform" onsubmit={save} class="max-w-[640px] box-border px-5 md:px-8 py-6 flex flex-col gap-6">
  <div class="card p-7 flex flex-col gap-6">
    <div>
      <div class="flex items-center justify-between gap-3 mb-2">
        <div class="label mb-0">Where is it?</div>
      </div>
      <input id="where" class="input" bind:value={where} oninput={onWhere} use:focus autocomplete="off" spellcheck="false" placeholder="https://router.home.lan/ui/core/dashboard  or  192.168.1.20:7878" required />
      <div class="hint mt-1.5">Paste its address as you open it today. Port and HTTPS are worked out.</div>
      {#if errorField.startsWith('target')}<div class="field-error">{error}</div>{/if}
      <div class="mt-2 text-sm flex items-center gap-2 min-h-6">
        {#if probing}
          <span class="text-muted">Looking{triedPorts.length > 1 ? ' on 443 and 80' : ''}…</span>
        {:else if probe?.self}
          {#if !errorField.startsWith('target')}
          <span class="text-warning">{address} leads back to this proxy, so the name would point at itself. An old DNS entry for {address} probably still points here. Use the address the service has, like <span class="font-mono">192.168.1.20:7878</span>.</span>
          {/if}
        {:else if probe?.reachable}
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="text-success"><path d="M4 10.5l4 4 8-9"></path></svg>
          <span class="text-success-soft-fg">Found it: <span class="font-mono">{https ? 'https' : 'http'}://{address}:{port}</span>{acceptUntrusted ? ', its own certificate, accepted' : ''}.</span>
        {:else if probe && port}
          <span class="text-warning">Nothing answered at {address}, port {port}. You can still save it.</span>
        {:else if probe}
          <span class="text-warning">Nothing answered at {address} on 443 or 80. Add the port, like <span class="font-mono">{address}:8080</span>.</span>
        {/if}
      </div>
    </div>
    <div>
      <label for="name" class="label">Name</label>
      <div class="flex items-center gap-2 flex-wrap">
        <input id="name" class="input flex-1 basis-40 min-w-0" bind:value={name} oninput={() => (nameEdited = true)} autocomplete="off" spellcheck="false" placeholder="radarr" required />
        <span class="text-base text-muted">.{settings?.domain}</span>
      </div>
      {#if errorField === 'name'}<div class="field-error">{error}</div>{/if}
    </div>
  </div>

  <div class="card p-7 flex flex-col gap-4">
    <div class="label mb-0">Who can open it?</div>
    <label class="flex items-start gap-3 min-h-10 cursor-pointer">
      <input type="radio" name="access" value="home" bind:group={access} class="w-5.5 h-5.5 mt-0.5 accent-[color:var(--accent)]" />
      <span class="flex flex-col"><span class="text-sm">Only devices on my home network</span><span class="hint">Recommended</span></span>
    </label>
    <label class="flex items-start gap-3 min-h-10 cursor-pointer">
      <input type="radio" name="access" value="internet" bind:group={access} class="w-5.5 h-5.5 mt-0.5 accent-[color:var(--accent)]" />
      <span class="text-sm">Anyone on the internet</span>
    </label>
    {#if access === 'internet'}
      <div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">Anyone who knows the address can reach this service's sign-in page. Make sure the service has a strong password of its own, and that your router forwards ports 80 and 443 to the proxy.</div>
    {/if}
  </div>

  <details class="card px-7 py-2" bind:open={advancedOpen}>
    <summary class="min-h-10 flex items-center font-semibold text-sm cursor-pointer">Advanced</summary>
    <div class="flex flex-col gap-5 pt-3 pb-5">
      <label class="flex items-start gap-3 cursor-pointer">
        <input type="checkbox" bind:checked={https} class="w-5.5 h-5.5 mt-0.5 accent-[color:var(--accent)]" />
        <span class="flex flex-col"><span class="text-sm">The service uses HTTPS itself</span><span class="hint">Set for you when we detect it.</span></span>
      </label>
      {#if https}
        <label class="flex items-start gap-3 cursor-pointer ml-8">
          <input type="checkbox" bind:checked={acceptUntrusted} class="w-5.5 h-5.5 mt-0.5 accent-[color:var(--accent)]" />
          <span class="flex flex-col"><span class="text-sm">Accept its own certificate</span><span class="hint">Needed for things like UniFi or Proxmox that sign their own.</span></span>
        </label>
      {/if}
      <label class="flex items-start gap-3 cursor-pointer">
        <input type="checkbox" bind:checked={ownOrigin} class="w-5.5 h-5.5 mt-0.5 accent-[color:var(--accent)]" />
        <span class="flex flex-col"><span class="text-sm">The service expects its own address</span><span class="hint">Turn on if signing in fails, or sends you back to the login page (UniFi does this). Leave off otherwise.</span></span>
      </label>
      <div>
        <label for="extra" class="text-sm block mb-1.5">Other names for this service</label>
        <input id="extra" class="input" bind:value={extraNames} autocomplete="off" spellcheck="false" placeholder="movies, films" />
        <div class="hint mt-1.5">Separate with commas. Each becomes another address under .{settings?.domain}.</div>
        {#if errorField === 'extraNames'}<div class="field-error">{error}</div>{/if}
      </div>
      <div>
        <label for="nets" class="text-sm block mb-1.5">Extra networks that count as home, for this service only</label>
        <input id="nets" class="input" bind:value={trustedNetworks} autocomplete="off" spellcheck="false" placeholder="100.64.0.0/10" />
        {#if errorField === 'trustedNetworks'}<div class="field-error">{error}</div>{/if}
      </div>
    </div>
  </details>

  {#if error && !errorField}
    <div class="rounded-lg p-4 bg-danger-soft text-danger text-sm">{error}</div>
  {/if}

  {#if editing}
    <div class="flex justify-start">
      <button type="button" class="btn-danger" onclick={remove}>Remove this name</button>
    </div>
  {/if}
</form>

{/if}
