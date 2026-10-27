<script lang="ts">
  import { get, post, type Host, type Health, type Settings, type Certificates, type CertStatus, type DnsCheck } from '../lib/api'
  import { link, navigate } from '../lib/router.svelte'
  import { deviceTrust } from '../lib/trust.svelte'
  import { paired } from '../lib/paired.svelte'
  import { toast } from '../lib/toast.svelte'

  // The certificate banner: only while something is happening to it.
  let cert = $state<CertStatus | null>(null)
  async function loadCert() {
    try { cert = (await get<Certificates>('/api/v1/certificates')).status } catch { cert = null }
  }

  let hosts = $state<Host[]>([])
  // Removed names (Undo window): shown folded, with Restore.
  let removed = $state<Host[]>([])
  let showRemoved = $state(false)
  let health = $state<Record<string, Health>>({})
  // Status first: does the network find the names, does this device
  // trust the proxy (or are certificates public), is the app that
  // installed it connected. One glance says whether everything is fine.
  let dns = $state<DnsCheck | null>(null)
  const proxyIp = /^[0-9.]+$/.test(location.hostname) ? location.hostname : ''
  const dnsOk = $derived(!!dns && dns.addresses.length > 0 && (proxyIp === '' || dns.addresses.includes(proxyIp)))
  const dnsKnown = $derived(dns !== null)
  // Quiet when everything is fine (one line), rows only for what needs a
  // hand: three green sentences were most of the page for "nothing to do".
  const checking = $derived(!dnsKnown || (deviceTrust.needed && !deviceTrust.checked))
  const dnsIssue = $derived(dnsKnown && !dnsOk)
  const trustIssue = $derived(deviceTrust.needed && deviceTrust.checked && deviceTrust.untrusted)
  const certIssue = $derived(!deviceTrust.needed && cert?.state === 'failed')
  // Still working, but it won't renew until the person acts (a token
  // that stopped working, a CAA record): said now, not days before.
  const certWarn = $derived(!deviceTrust.needed && cert?.state === 'ok' && !!cert.message)
  const certPending = $derived(!deviceTrust.needed && (cert?.state === 'trial' || cert?.state === 'issuing'))
  const pairedIssue = $derived(!!paired.value?.disabled)
  const allGood = $derived(!checking && !dnsIssue && !trustIssue && !certIssue && !certWarn && !certPending && !pairedIssue)
  const goodLine = $derived.by(() => {
    const parts = [`names under ${settings?.domain} point here`]
    parts.push(deviceTrust.needed ? 'this device trusts the proxy' : "certificates come from Let's Encrypt")
    const apps = paired.apps.filter((t) => !t.disabled).map((t) => t.label)
    if (apps.length === 1) parts.push(`${apps[0]} is connected`)
    else if (apps.length > 1) parts.push(`${apps.slice(0, -1).join(', ')} and ${apps[apps.length - 1]} are connected`)
    return parts.join(', ')
  })
  // When each host was first seen down, so the row can say since when.
  let downSince = $state<Record<string, number>>({})
  function noteHealth(h: Record<string, Health>) {
    const next: Record<string, number> = {}
    for (const [id, st] of Object.entries(h)) if (!st.reachable) next[id] = downSince[id] ?? Date.now()
    downSince = next; health = h
  }
  let settings = $state<Settings | null>(null)
  let loaded = $state(false)

  async function load() {
    const [h, s] = await Promise.all([get<{ hosts: Host[] }>('/api/v1/hosts?include=removed'), get<Settings>('/api/v1/settings')])
    if (!s.domain) { navigate('/setup', true); return }
    const all = [...h.hosts].sort((a, b) => a.name.localeCompare(b.name))
    hosts = all.filter((x) => !x.deletedAt); removed = all.filter((x) => !!x.deletedAt); settings = s; loaded = true
    if (s.mode === 'public') loadCert()
    paired.load()
    get<DnsCheck>('/api/v1/dns-check').then((d) => { dns = d }).catch(() => { dns = { name: '', addresses: [], proxyAddresses: [] } })
    noteHealth((await get<{ health: Record<string, Health> }>('/api/v1/hosts/health')).health)
  }
  load()
  async function restore(h: Host) {
    await post(`/api/v1/hosts/${h.id}/restore`)
    toast(`${h.names[0]} is back`)
    load()
  }
  const onChanged = () => load()
  window.addEventListener('hosts-changed', onChanged)
  $effect(() => () => window.removeEventListener('hosts-changed', onChanged))
  const every = setInterval(() => { get<{ health: Record<string, Health> }>('/api/v1/hosts/health').then((r) => noteHealth(r.health)).catch(() => {}) }, 15000)
  $effect(() => () => clearInterval(every))
  const certEvery = setInterval(() => { if (cert && cert.state !== 'ok') loadCert() }, 5000)
  $effect(() => () => clearInterval(certEvery))

  function statusText(h: Host): { text: string; ok: boolean | null } {
    const s = health[h.id]
    if (!s) return { text: 'Checking…', ok: null }
    if (s.self) return { text: `Points back at this proxy · edit it and give the address the service has, not ${h.target.address}`, ok: false }
    if (s.reachable) return { text: `Working · goes to ${h.target.address}, port ${h.target.port}`, ok: true }
    const since = downSince[h.id] ? new Date(downSince[h.id]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
    return { text: `Not responding${since ? ' since ' + since : ''} · check that the service at ${h.target.address}, port ${h.target.port} is running`, ok: false }
  }
</script>

<div class="max-w-[960px] box-border px-5 md:px-8 py-6 flex flex-col gap-6">
  <div class="flex items-center justify-between gap-4 flex-wrap">
    <h1 class="m-0 text-2xl font-bold text-fg">Names</h1>
    {#if hosts.length > 0}
      <a href="/hosts/new" use:link class="btn-primary">Add a name</a>
    {/if}
  </div>

  {#if loaded && settings}
    {#if checking}
      <div class="flex items-center gap-3 text-sm text-muted"><span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-[color:var(--border)]"></span>Checking the network and this device…</div>
    {:else if allGood}
      <div class="flex items-center gap-3 text-sm"><span class="w-3 h-3 rounded-full shrink-0 bg-success"></span><span>All good: {goodLine}.</span></div>
    {:else}
      <!-- Only what needs a hand: the sentence says what is wrong, the
           button goes where it is fixed. -->
      <div class="card overflow-hidden divide-y divide-[color:var(--border)]">
        {#if dnsIssue}
          <div class="flex items-center gap-3 px-6 py-3.5 flex-wrap text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-warning"></span>
            <span class="flex-1 basis-64">Nothing on your network answers for <strong>*.{settings.domain}</strong> yet: names won't open on your devices until the record exists.</span>
            <a href="/settings#dns" use:link class="btn-soft min-h-10 px-3.5 text-sm shrink-0 ml-auto">Add the DNS record</a>
          </div>
        {/if}
        {#if trustIssue}
          <div class="flex items-center gap-3 px-6 py-3.5 flex-wrap text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-warning"></span>
            <span class="flex-1 basis-64">This device doesn't trust the proxy yet: names open with a warning here. Once per device.</span>
            <a href="/trust" use:link class="btn-soft min-h-10 px-3.5 text-sm shrink-0 ml-auto">Trust it</a>
          </div>
        {/if}
        {#if certPending}
          <div class="flex items-center gap-3 px-6 py-3.5 flex-wrap text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-accent animate-pulse"></span>
            <span class="flex-1 basis-64">{cert?.state === 'trial' ? 'Checking your DNS token with a test certificate…' : "Getting your certificate from Let's Encrypt. Names open with a warning until it arrives, usually within a couple of minutes."}</span>
          </div>
        {/if}
        {#if certIssue}
          <div class="flex items-center gap-3 px-6 py-3.5 flex-wrap text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-danger"></span>
            <span class="flex-1 basis-64">{cert?.message ?? 'Could not get a certificate.'}</span>
            <a href="/settings" use:link class="btn-soft min-h-10 px-3.5 text-sm shrink-0 ml-auto">Fix in Settings</a>
          </div>
        {/if}
        {#if certWarn}
          <div class="flex items-center gap-3 px-6 py-3.5 flex-wrap text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-warning"></span>
            <span class="flex-1 basis-64">{cert?.message}</span>
            <a href="/settings#certificates" use:link class="btn-soft min-h-10 px-3.5 text-sm shrink-0 ml-auto">{cert?.fix === 'token' ? 'Fix token' : 'Open Settings'}</a>
          </div>
        {/if}
        {#if pairedIssue && paired.value}
          <div class="flex items-center gap-3 px-6 py-3.5 flex-wrap text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-warning"></span>
            <span class="flex-1 basis-64">{paired.value.label} is disconnected: it can't add or change names until you reconnect it.</span>
            <a href="/settings" use:link class="btn-soft min-h-10 px-3.5 text-sm shrink-0 ml-auto">Reconnect</a>
          </div>
        {/if}
      </div>
    {/if}
  {/if}

  {#if !loaded}
    <div class="text-muted">Loading…</div>
  {:else if hosts.length === 0 && paired.value && !paired.value.disabled}
    <div class="card p-10 flex flex-col items-center text-center gap-4">
      <h2 class="m-0 text-2xl font-bold text-fg">Give an app a name in {paired.value.label}</h2>
      <p class="m-0 hint text-sm max-w-md">It shows up here, like <strong class="text-fg">radarr.{settings?.domain}</strong>, pointed at the app and kept pointed at it. Something not in {paired.value.label} gets a name here instead.</p>
      <div class="flex gap-2 flex-wrap justify-center mt-2">
        <a href="/hosts/new" use:link class="btn-plain min-h-10">Add a name by hand</a>
        {#if paired.value.url}<a href={paired.value.url} class="btn-primary">Open {paired.value.label}</a>{/if}
      </div>
    </div>
  {:else if hosts.length === 0}
    <div class="card p-10 flex flex-col items-center text-center gap-4">
      <h2 class="m-0 text-2xl font-bold text-fg">Put a name in front of your first service</h2>
      <p class="m-0 hint text-sm max-w-md">A name is one address, like <strong class="text-fg">radarr.{settings?.domain}</strong>, that opens one service on your network, over HTTPS.</p>
      <a href="/hosts/new" use:link class="btn-primary mt-2">Add a name</a>
    </div>
  {:else}
    <div class="card overflow-hidden">
      {#each hosts as h, i (h.id)}
        {@const st = statusText(h)}
        <!-- One line per name: the text column shrinks, the chips and
             buttons keep their place on the right. -->
        <div class="flex items-center gap-4 px-5 py-4 text-fg flex-wrap sm:flex-nowrap {i < hosts.length - 1 ? 'border-b border-[color:var(--border)]' : ''}">
          <span class="w-3 h-3 rounded-full shrink-0 box-border {st.ok === true ? 'bg-success' : st.ok === false ? 'border-[3px] border-danger' : 'border-[3px] border-[color:var(--border)]'}"></span>
          <a href="/hosts/{h.id}" use:link class="flex-1 basis-48 min-w-0 flex flex-col gap-0.5 text-fg no-underline hover:underline">
            <span class="font-semibold text-sm break-all">{h.names[0]}</span>
            <span class="text-xs {st.ok === false ? 'text-danger' : 'text-muted'}">{st.text}</span>
          </a>
          <!-- Chips say only what is not the usual: who made the name, and
               a name open to the internet. Home-network-only is the default
               and goes without saying. -->
          <span class="ml-auto shrink-0 flex items-center gap-3 flex-wrap justify-end">
            {#if h.ref}
              <!-- A connected app made this host and keeps it pointed at the
                   app; its ref starts with that app's name. -->
              <span class="chip" title="{paired.appFor(h.ref)} made this name and keeps it pointed at the app. Edit the name here; the address follows the app.">From {paired.appFor(h.ref)}</span>
            {/if}
            {#if h.access === 'internet'}
              <span class="chip bg-warning-soft text-warning-soft-fg font-semibold">Open to the internet</span>
            {/if}
            <span class="flex items-center gap-3 shrink-0">
              <a href={h.url} target="_blank" rel="noopener" class="btn-soft min-h-10 px-3.5 text-sm shrink-0" aria-label="Open {h.names[0]}">Open ↗</a>
              <a href="/hosts/{h.id}" use:link class="min-w-11 min-h-10 grid place-items-center rounded-lg text-muted hover:bg-chip" aria-label="Edit {h.names[0]}">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 4l6 6-6 6"></path></svg>
              </a>
            </span>
          </span>
        </div>
      {/each}
    </div>
  {/if}

  {#if loaded && removed.length}
    <div class="flex flex-col gap-2">
      <button type="button" class="self-start text-accent text-sm min-h-10 cursor-pointer bg-transparent border-0 p-0 hover:underline" onclick={() => (showRemoved = !showRemoved)}>{showRemoved ? 'Hide removed' : `Removed: ${removed.length} ${removed.length === 1 ? 'name' : 'names'}, kept for a day…`}</button>
      {#if showRemoved}
        <div class="card overflow-hidden">
          {#each removed as h, i (h.id)}
            <div class="flex items-center gap-4 px-6 py-4 flex-wrap {i < removed.length - 1 ? 'border-b border-[color:var(--border)]' : ''}">
              <span class="flex-1 basis-[280px] min-w-0 flex flex-col gap-0.5">
                <span class="font-semibold text-base break-all text-muted">{h.names[0]}</span>
                <span class="text-xs text-muted">Went to {h.target.address}, port {h.target.port}</span>
              </span>
              <button type="button" class="btn-soft min-h-10 px-3.5 text-sm shrink-0" onclick={() => restore(h)}>Restore</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>
