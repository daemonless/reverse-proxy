<script lang="ts">
  import { get, put, post, del, ApiError, type Settings, type Token, type Status, type DnsCheck, type TrustInfo, type Certificates } from '../lib/api'
  import { session } from '../lib/session.svelte'
  import { navigate } from '../lib/router.svelte'
  import { toast } from '../lib/toast.svelte'
  import { copyText } from '../lib/copy'
  import { focus } from '../lib/focus'
  import DnsGuide from '../components/DnsGuide.svelte'
  import ShortLinkGuide from '../components/ShortLinkGuide.svelte'
  import CertProvider from '../components/CertProvider.svelte'
  import NetworkChoice, { netName } from '../components/NetworkChoice.svelte'
  import PasswordStrength from '../components/PasswordStrength.svelte'
  import AlertSettings from '../components/AlertSettings.svelte'
  import { strength } from '../lib/password'
  import { credits, ourLicense, buildTools } from '../lib/credits'

  let settings = $state<Settings | null>(null)
  let status = $state<Status | null>(null)
  let tokens = $state<Token[]>([])
  let newNet = $state('')
  let netError = $state('')
  let current = $state(''); let next = $state(''); let nextAgain = $state(''); let weakOk = $state(''); let pwError = $state(''); let pwBusy = $state(false); let editPassword = $state(false)
  let appLabel = $state(''); let freshToken = $state(''); let freshLabel = $state(''); let appError = $state('')
  // Linking a fjord elsewhere: one link to paste there, good for ten
  // minutes, once. The fjord redeems it for a key of its own.
  let pairLink = $state(''); let pairBusy = $state(false)
  async function connectFjord() {
    pairBusy = true; appError = ''; freshToken = ''
    try { pairLink = (await post<{ link: string }>('/api/v1/pair/code', {})).link }
    catch (err) { appError = err instanceof ApiError ? err.message : 'Something went wrong' }
    finally { pairBusy = false }
  }
  async function copyPairLink() { toast((await copyText(pairLink)) ? 'Copied. Paste it into fjord, Settings, Names.' : 'Select the link and copy it by hand') }
  let aboutDialog = $state<HTMLDialogElement | null>(null)
  let trust = $state<TrustInfo | null>(null)
  function loadTrust() { get<TrustInfo>('/api/v1/trust').then((t) => { trust = t }).catch(() => {}) }
  loadTrust()
  // Automatic certificates (public endings only).
  let certs = $state<Certificates | null>(null); let certsOpen = $state(location.hash === '#certificates'); let certsBusy = $state(false)
  function loadCerts() { get<Certificates>('/api/v1/certificates').then((c) => { certs = c }).catch(() => {}) }
  const certLabel = $derived(certs?.providers.find((p) => p.id === certs?.provider)?.label ?? certs?.provider ?? '')
  const certLine = $derived.by(() => {
    const st = certs?.status
    if (!st || st.state === 'manual') return ''
    if (st.state === 'ok' && st.message) return st.message
    if (st.state === 'ok') return `Valid until ${new Date(st.notAfter ?? '').toLocaleDateString()}; it renews itself.`
    if (st.state === 'trial') return 'Checking the token with a test certificate…'
    if (st.state === 'issuing') return 'Getting the certificate from Let\'s Encrypt…'
    return st.message ?? ''
  })
  // Stopping can't be undone (the token is deleted) and puts a warning on
  // every name on every device, so it asks first and says so.
  let stopDialog = $state<HTMLDialogElement | null>(null); let liveNames = $state<number | null>(null)
  async function askStopCerts() {
    liveNames = null
    stopDialog?.showModal()
    try { liveNames = (await get<{ hosts: unknown[] }>('/api/v1/hosts')).hosts.length } catch { liveNames = null }
  }
  async function stopCerts() {
    certsBusy = true
    try { certs = await del<Certificates>('/api/v1/certificates'); stopDialog?.close(); certsOpen = false; loadTrust(); toast('Back to your own root certificate. Devices need to trust the proxy again.') }
    catch (err) { toast(err instanceof ApiError ? err.message : 'Something went wrong') }
    finally { certsBusy = false }
  }
  let editDomain = $state(false); let newDomain = $state(''); let domainError = $state(''); let domainBusy = $state(false)
  let suggestions = $state<string[]>([])
  async function loadSuggestions() {
    try { suggestions = (await get<{ suggestions: string[] }>(`/api/v1/suggest-domain?host=${encodeURIComponent(location.hostname)}`)).suggestions } catch { suggestions = [] }
  }
  async function saveDomain(e: SubmitEvent) {
    e.preventDefault(); domainError = ''; domainBusy = true
    try {
      settings = await put<Settings>('/api/v1/settings', { domain: newDomain, trustedNetworks: settings!.trustedNetworks })
      // A new ending is a new start for the network: the wizard's DNS and
      // trust steps again, not a toast and a folded card. Opened by name,
      // this page's name just stopped existing: go on at the IP address,
      // which opens whatever happens to names (it locked people out).
      editDomain = false
      if (!proxyIp && settings.fallbackUrl) { location.assign(settings.fallbackUrl + '/setup'); return }
      navigate('/setup')
    } catch (err) { domainError = err instanceof ApiError ? err.message : 'Something went wrong' }
    finally { domainBusy = false }
  }
  let backupPass = $state(''); let backupBusy = $state(false); let backupError = $state('')
  // Restore lives beside Download: it used to exist only as small print on
  // the first-run screen, which an install from fjord skips past.
  let restoreOpen = $state(false); let restoreFile = $state<FileList | null>(null); let restorePass = $state('')
  let restoreBusy = $state(false); let restoreError = $state('')
  async function restoreBackup(e: SubmitEvent) {
    e.preventDefault(); restoreError = ''; restoreBusy = true
    try {
      if (!restoreFile?.[0]) throw new Error('Choose the backup file')
      const fd = new FormData(); fd.append('file', restoreFile[0]); fd.append('passphrase', restorePass)
      const res = await fetch('/api/v1/restore', { method: 'POST', body: fd, credentials: 'same-origin' })
      const d = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(d.error ?? 'Restore failed')
      session.signedOut(); navigate('/login', true)
      toast('Restored. Sign in with the password from the backup.')
    } catch (err) { restoreError = err instanceof Error ? err.message : 'Restore failed' }
    finally { restoreBusy = false }
  }
  async function downloadBackup(e: SubmitEvent) {
    e.preventDefault(); backupError = ''; backupBusy = true
    try {
      const res = await fetch('/api/v1/backup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase: backupPass }), credentials: 'same-origin' })
      if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error ?? 'Backup failed') }
      const name = res.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1] ?? 'reverse-proxy-backup.rpbk'
      const url = URL.createObjectURL(await res.blob())
      const a = document.createElement('a'); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url)
      backupPass = ''; toast('Backup downloaded')
    } catch (err) { backupError = err instanceof Error ? err.message : 'Backup failed' }
    finally { backupBusy = false }
  }
  const proxyIp = /^[0-9.]+$/.test(location.hostname) ? location.hostname : ''
  // #dns (from the trust page, or a connected app) lands with the record open.
  let dns = $state<DnsCheck | null>(null); let dnsBusy = $state(false); let dnsOpen = $state(location.hash === '#dns')
  // fjord's Settings has tabs; so does this one: the network (what every
  // device sees) and this proxy. #dns lands on Network, open on the record.
  let tab = $state<'network' | 'proxy'>(location.hash === '#proxy' ? 'proxy' : 'network')
  let dnsOk = $state(false)
  $effect(() => { if (dns) dnsOk = dns.addresses.length > 0 && (proxyIp === '' || dns.addresses.includes(proxyIp)) })
  async function checkDns() {
    dnsBusy = true
    try { dns = await get<DnsCheck>('/api/v1/dns-check') } catch { dns = null }
    finally { dnsBusy = false }
  }

  async function load() {
    ;[settings, status, tokens] = await Promise.all([
      get<Settings>('/api/v1/settings'), get<Status>('/api/v1/status'),
      get<{ tokens: Token[] }>('/api/v1/tokens').then((r) => r.tokens),
    ])
    if (settings.domain) checkDns()
    if (settings.mode === 'public') loadCerts()
  }
  load()

  async function saveNets(nets: string[]) {
    netError = ''
    try { settings = await put<Settings>('/api/v1/settings', { domain: settings!.domain, trustedNetworks: nets }); newNet = '' }
    catch (err) { netError = err instanceof ApiError ? err.message : 'Something went wrong' }
  }
  // Short links: http://go/radarr opens radarr.<ending>. "" is off.
  let shortEdit = $state(false); let shortHow = $state(false); let shortWord = $state(''); let shortError = $state('')
  const proxyAddr = $derived.by(() => { try { return new URL(settings?.fallbackUrl ?? '').hostname } catch { return '' } })
  // Only a result for the word in use counts (not a stale one for go).
  const shortOk = $derived(!!dns?.short && dns.short.name.split('.')[0] === settings?.shortLinks && dns.short.addresses.length > 0 && (!proxyAddr || dns.short.addresses.includes(proxyAddr)))
  async function saveShort(word: string) {
    shortError = ''
    try { settings = { ...settings!, ...(await put<Settings>('/api/v1/settings', { domain: settings!.domain, trustedNetworks: settings!.trustedNetworks, shortLinks: word })) }; shortEdit = false; checkDns(); toast(word ? `Short links: ${word}/` : 'Short links are off') }
    catch (err) { shortError = err instanceof ApiError ? err.message : 'Something went wrong' }
  }
  // Home network: the proxy's own networks (ticked ones can open it and
  // count as home) and networks routed to it, like a VPN.
  let listenError = $state('')
  const allNets = $derived((settings?.networks ?? []).map((n) => n.network))
  const answering = $derived(settings?.listen?.length ? settings.listen : allNets)
  async function toggleNet(n: string, on: boolean) {
    const next = on ? [...answering, n] : answering.filter((x) => x !== n)
    const listen = next.length === allNets.length ? [] : next
    listenError = ''
    try {
      settings = { ...settings!, ...(await put<Settings>('/api/v1/listen', { listen })) }
      toast(on ? `${netName(n)} is home again` : `${netName(n)} can no longer open the proxy`)
    } catch (err) {
      listenError = err instanceof ApiError ? err.message : 'Something went wrong'
      settings = { ...settings! } // the boxes go back to what is saved
    }
  }
  function addNet(e: SubmitEvent) { e.preventDefault(); if (newNet.trim()) saveNets([...settings!.trustedNetworks, newNet.trim()]) }
  function removeNet(n: string) {
    const before = settings!.trustedNetworks
    saveNets(before.filter((x) => x !== n))
    toast(`Removed ${n}`, { label: 'Undo', run: () => saveNets(before) })
  }

  async function changePassword(e: SubmitEvent) {
    e.preventDefault(); pwError = ''
    if (next !== nextAgain) { pwError = 'The two passwords differ.'; return }
    if (strength(next).level === 1 && weakOk !== next) { weakOk = next; return }
    pwBusy = true
    try { await put('/api/v1/password', { current, new: next }); current = ''; next = ''; nextAgain = ''; editPassword = false; toast('Password changed') }
    catch (err) { pwError = err instanceof ApiError ? err.message : 'Something went wrong' }
    finally { pwBusy = false }
  }

  async function addApp(e: SubmitEvent) {
    e.preventDefault(); appError = ''
    try {
      const r = await post<{ token: string }>('/api/v1/tokens', { label: appLabel })
      freshToken = r.token; freshLabel = appLabel; appLabel = ''; pairLink = ''
      tokens = (await get<{ tokens: Token[] }>('/api/v1/tokens')).tokens
    } catch (err) { appError = err instanceof ApiError ? err.message : 'Something went wrong' }
  }
  // The app that installed this proxy (fjord) pairs with it up front; it is
  // shown as a connected service, not as one more key.
  let paired = $derived(tokens.find((t) => t.paired))
  let keys = $derived(tokens.filter((t) => !t.paired))
  // How many names each app made comes with the token list (the proxy
  // counts by the app's id in the refs).
  const namesFrom = (t: Token) => t.names ?? 0
  let fromPaired = $derived(paired ? namesFrom(paired) : 0)
  const came = (n: number) => (n === 0 ? 'no names from it yet' : n === 1 ? '1 name comes from it' : `${n} names come from it`)
  // Kept when disconnected: its key cannot be shown or typed again, so
  // Reconnect is the only way back.
  async function setPaired(t: Token, disabled: boolean) {
    await put(`/api/v1/tokens/${t.id}`, { disabled })
    tokens = tokens.map((x) => (x.id === t.id ? { ...x, disabled } : x))
  }
  async function disconnectPaired(t: Token) {
    await setPaired(t, true)
    toast(`Disconnected ${t.label}. Its names stay; it can't change them.`, { label: 'Undo', run: () => setPaired(t, false) })
  }

  async function removeApp(t: Token) {
    await del(`/api/v1/tokens/${t.id}`)
    tokens = tokens.filter((x) => x.id !== t.id)
    toast(`Disconnected ${t.label}`)
  }

  async function signOut() { await post('/api/v1/logout'); session.signedOut(); navigate('/login', true) }
</script>

<div class="max-w-[720px] box-border px-5 md:px-8 py-6 flex flex-col gap-8">
  <h1 class="m-0 text-2xl font-bold text-fg">Settings</h1>

  {#if settings}
  <div class="flex border-b border-[color:var(--border)] -mt-4 -mb-2" role="tablist">
    {#each [['network', 'Network'], ['proxy', 'This proxy']] as [id, label]}
      <button type="button" role="tab" aria-selected={tab === id} onclick={() => (tab = id as 'network' | 'proxy')}
        class="px-4 py-2 text-sm font-medium -mb-px border-b-2 transition-colors cursor-pointer {tab === id ? 'border-accent text-fg' : 'border-transparent text-muted hover:text-fg-body'}">{label}</button>
    {/each}
  </div>

  {#if tab === 'network'}
  <section class="flex flex-col gap-2.5">
    <h3 class="m-0 text-sm text-muted font-semibold">Ending and certificates</h3>
    <div class="card overflow-hidden">
      <div class="px-6 py-4.5 border-b border-[color:var(--border)] flex flex-col gap-4">
        <div class="flex items-center justify-between gap-4 flex-wrap">
          <span class="flex flex-col"><span class="text-sm">Ending for service names</span><span class="text-sm text-muted break-all">{settings.domain || 'Not set'}</span></span>
          <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => { editDomain = !editDomain; newDomain = settings?.domain ?? ''; domainError = ''; if (editDomain) loadSuggestions() }}>{editDomain ? 'Cancel' : 'Change'}</button>
        </div>
        {#if settings.fallbackUrl && !editDomain}
          <div class="flex items-center justify-between gap-4 flex-wrap">
            <span class="flex flex-col min-w-0"><span class="text-sm">If names ever stop opening</span><span class="hint">This address always opens the proxy. Keep it somewhere safe.</span></span>
            <button type="button" class="chip font-mono cursor-pointer min-h-9 break-all" onclick={async () => toast((await copyText(settings!.fallbackUrl!)) ? 'Copied' : 'Select the text and copy it by hand')}>{settings.fallbackUrl}</button>
          </div>
        {/if}
        {#if editDomain}
          <form onsubmit={saveDomain} class="flex flex-col gap-3">
            <input class="input" bind:value={newDomain} autocomplete="off" spellcheck="false" placeholder="apps.lan" aria-label="New ending" required />
            {#if suggestions.length}
              <div class="flex items-center gap-2 flex-wrap">
                <span class="hint">Suggestions:</span>
                {#each suggestions as sug (sug)}
                  <button type="button" class="chip cursor-pointer min-h-9 {newDomain === sug ? 'bg-accent-soft text-accent-soft-fg font-semibold' : ''}" onclick={() => (newDomain = sug)}>{sug}</button>
                {/each}
              </div>
            {/if}
            <div class="hint">Every service becomes <strong class="text-fg">name.{newDomain || '…'}</strong></div>
            {#if newDomain && newDomain !== settings.domain}
              <div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">Changing the ending renames every host and creates a new root certificate. Your devices will need to trust the proxy again, and the DNS record must point the new ending here.{#if !proxyIp && settings.fallbackUrl}{' '}This page then continues at <strong class="font-mono">{settings.fallbackUrl}</strong>, where your browser warns about the certificate once. That is expected.{/if}</div>
            {/if}
            {#if domainError}<div class="field-error">{domainError}</div>{/if}
            <div class="flex justify-end gap-2">
              <button class="btn-primary" disabled={domainBusy || !newDomain || newDomain === settings.domain}>Save</button>
            </div>
          </form>
        {/if}
      </div>
      {#if settings.domain}
      <div class="px-6 py-4.5 border-b border-[color:var(--border)] flex flex-col gap-4">
        <div class="flex items-center justify-between gap-4 flex-wrap">
          <span class="flex items-center gap-3 text-sm">
            <span class="w-3 h-3 rounded-full shrink-0 box-border {dnsBusy ? 'border-[3px] border-[color:var(--border)]' : dnsOk ? 'bg-success' : 'border-[3px] border-warning'}"></span>
            <span class="flex flex-col">
              <span>Names point at the proxy</span>
              <span class="hint">{dnsOk ? `Your network's DNS sends *.${settings.domain} here.` : `Your network's DNS does not send *.${settings.domain} here yet.`}</span>
            </span>
          </span>
          <!-- Says what it opens: the DNS record and the router guide. -->
          <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => (dnsOpen = !dnsOpen)}>{dnsOpen ? 'Hide' : dnsOk ? 'DNS record' : 'Set up DNS'}</button>
        </div>
        {#if dnsOpen}<DnsGuide domain={settings.domain} onok={() => (dnsOk = true)} />{/if}
      </div>
      {/if}
      <div class="px-6 py-4.5 flex flex-col gap-3">
        <div class="flex items-center justify-between gap-4 flex-wrap">
          <span class="flex flex-col"><span class="text-sm">Secure connection</span>
            {#if settings.mode === 'private'}
              <span class="hint">Your own root certificate; devices trust it once.</span>
            {:else if settings.mode === 'public' && certs?.provider}
              <span class="hint">Automatic certificates via {certLabel}.</span>
              {#if certLine}<span class="text-sm {certs.status.state === 'failed' || (certs.status.state === 'ok' && certs.status.message) ? 'text-warning-soft-fg' : 'text-muted'}">{certLine}</span>{/if}
            {:else if settings.mode === 'public'}
              <span class="hint">Your own root certificate for now. Connect your domain's DNS and certificates become automatic, with no device setup.</span>
            {:else}
              <span class="hint">—</span>
            {/if}
          </span>
          <span class="flex gap-2 flex-wrap">
            {#if settings.mode === 'public'}
              <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => (certsOpen = !certsOpen)}>{certsOpen ? 'Cancel' : certs?.status.fix === 'token' ? 'Fix token' : certs?.provider ? 'Change' : 'Set up'}</button>
            {/if}
            {#if trust?.rootUrl && trust.needed}<a href={trust.rootUrl} download class="btn-soft min-h-10 px-4 text-sm">Download certificate</a>{/if}
          </span>
        </div>
        {#if certsOpen && settings.mode === 'public'}
          <div class="rounded-xl bg-inset border border-[color:var(--border)] p-5 flex flex-col gap-4">
            <CertProvider domain={settings.domain} edit onok={() => { certsOpen = false; loadCerts(); loadTrust() }} />
            {#if certs?.provider}
              <button type="button" class="btn-danger self-start min-h-10 px-3" disabled={certsBusy} onclick={askStopCerts}>Stop automatic certificates</button>
            {/if}
          </div>
        {/if}
        {#if trust?.fingerprint && trust.needed}
          <div class="flex flex-col gap-1">
            <div class="font-mono text-[13px] leading-relaxed break-all text-muted select-all">{trust.fingerprint}</div>
            <div class="hint">Valid until {new Date(trust.notAfter ?? '').toLocaleDateString()}. Keep a backup: a new root means every device trusts the proxy again.</div>
          </div>
        {/if}
      </div>
    </div>
  </section>

  {#if settings.domain}
  <section class="flex flex-col gap-2.5">
    <h3 class="m-0 text-sm text-muted font-semibold">Short links</h3>
    <div class="card px-6 py-5 flex flex-col gap-3">
      <div class="flex items-center justify-between gap-4 flex-wrap">
        <span class="flex flex-col">
          {#if settings.shortLinks}
            <span class="text-sm">Type <strong class="font-mono">{settings.shortLinks}/radarr</strong> in a browser to open <span class="font-mono">radarr.{settings.domain}</span>.</span>
            <span class="hint">Any of your names works, with its path: {settings.shortLinks}/radarr/settings. {settings.shortLinks}/ alone lists them.</span>
          {:else}
            <span class="text-sm">Off. Short links open a name from a short word, like <span class="font-mono">go/radarr</span>.</span>
          {/if}
        </span>
        <span class="flex gap-2 flex-wrap">
          {#if !shortEdit}
            {#if settings.shortLinks}<button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => { shortWord = settings!.shortLinks ?? ''; shortEdit = true; shortError = '' }}>Change</button>{/if}
            <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => saveShort(settings!.shortLinks ? '' : 'go')}>{settings.shortLinks ? 'Turn off' : 'Turn on'}</button>
          {/if}
        </span>
      </div>
      {#if shortEdit}
        <form class="flex gap-2 flex-wrap items-start" onsubmit={(e) => { e.preventDefault(); saveShort(shortWord.trim().toLowerCase()) }}>
          <div class="flex items-center gap-2"><input class="input font-mono w-40" bind:value={shortWord} aria-label="Short word" autocomplete="off" spellcheck="false" required use:focus /><span class="font-mono text-sm text-muted">/radarr</span></div>
          <button class="btn-soft min-h-10 px-4">Save</button>
          <button type="button" class="btn-plain min-h-10 px-3" onclick={() => (shortEdit = false)}>Cancel</button>
        </form>
      {/if}
      {#if shortError}<div class="field-error">{shortError}</div>{/if}
      {#if settings.shortLinks}
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <span class="flex items-center gap-3">
            <span class="w-3 h-3 rounded-full shrink-0 box-border {shortOk ? 'bg-success' : 'border-[3px] border-warning'}"></span>
            <span class="flex flex-col"><span class="text-sm">{settings.shortLinks} points at the proxy</span>
              <span class="hint">{#if shortOk}{dns?.short?.name} reaches this proxy.{:else}Your router needs one more name: <strong class="font-mono text-fg">{settings.shortLinks}</strong> pointing at this proxy{#if proxyAddr}{' '}(<span class="font-mono">{proxyAddr}</span>){/if}.{/if}</span>
            </span>
          </span>
          <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => (shortHow = !shortHow)}>{shortHow ? 'Hide' : 'Router record'}</button>
        </div>
        {#if shortHow}<ShortLinkGuide short={settings.shortLinks} ip={proxyAddr} />{/if}
      {/if}
    </div>
  </section>
  {/if}

  <section class="flex flex-col gap-2.5">
    <h3 class="m-0 text-sm text-muted font-semibold">Home network</h3>
    <div class="card px-6 py-5 flex flex-col gap-3">
      {#if (settings.networks?.length ?? 0) > 1 || settings.listen?.length}
        <div class="hint text-sm">This proxy is on {settings.networks?.length} networks and reaches your apps on all of them. Devices on the ticked ones can open it and your home-only names.</div>
        {#if settings.listenSetBy}
          <div class="text-sm">Only <span class="font-mono">{answering.map(netName).join(', ')}</span>. <span class="text-muted">{settings.listenSetBy} in the container's settings decides this.</span></div>
        {:else}
          <NetworkChoice networks={settings.networks ?? []} here={settings.here ?? ''} chosen={answering} ontoggle={toggleNet} />
        {/if}
        {#if listenError}<div class="field-error">{listenError}</div>{/if}
        <div class="flex flex-col gap-1 mt-2"><span class="text-sm">Also home</span><span class="hint">Networks that reach the proxy through your router, like a VPN.</span></div>
      {:else}
        <div class="hint text-sm">Devices on your network count as home. Add your VPN here so it counts too.</div>
      {/if}
      {#if settings.trustedNetworks.length}
        <div class="flex gap-2 flex-wrap items-center">
          {#each settings.trustedNetworks as n (n)}
            <span class="chip gap-2">{n}<button type="button" class="min-w-6 min-h-6 grid place-items-center rounded-full hover:bg-black/10 cursor-pointer" aria-label="Remove {n}" onclick={() => removeNet(n)}>×</button></span>
          {/each}
        </div>
      {/if}
      <form onsubmit={addNet} class="flex gap-2 flex-wrap">
        <input class="input flex-1 basis-56 min-w-0" bind:value={newNet} placeholder="100.64.0.0/10" autocomplete="off" spellcheck="false" aria-label="Network to add" />
        <button class="btn-soft">Add network</button>
      </form>
      {#if netError}<div class="field-error">{netError}</div>{/if}
    </div>
  </section>

  {:else}
  <AlertSettings />

  <section class="flex flex-col gap-2.5">
    <h3 class="m-0 text-sm text-muted font-semibold">Password</h3>
    <div class="card px-6 py-4.5 flex flex-col gap-4">
      <div class="flex items-center justify-between gap-4 flex-wrap">
        <span class="flex flex-col"><span class="text-sm">Your password</span><span class="text-sm text-muted">For signing in to this proxy.</span></span>
        <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => { editPassword = !editPassword; current = ''; next = ''; nextAgain = ''; pwError = '' }}>{editPassword ? 'Cancel' : 'Change'}</button>
      </div>
      {#if editPassword}
        <form onsubmit={changePassword} class="flex flex-col gap-4">
          <div>
            <label for="current" class="text-sm block mb-1.5">Current password</label>
            <input id="current" type="password" class="input" bind:value={current} autocomplete="current-password" required />
          </div>
          <div>
            <label for="next" class="text-sm block mb-1.5">New password</label>
            <input id="next" type="password" class="input" bind:value={next} autocomplete="new-password" required />
            <PasswordStrength password={next} />
          </div>
          <div>
            <label for="next-again" class="text-sm block mb-1.5">New password again</label>
            <input id="next-again" type="password" class="input" bind:value={nextAgain} autocomplete="new-password" required />
            {#if pwError}<div class="field-error">{pwError}</div>{/if}
          </div>
          {#if strength(next).level === 1 && weakOk === next}
            <div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">This password is weak: {strength(next).why.toLowerCase().replace(/\.$/, '')}. Anyone who can open this page could guess it. Choose another, or use it anyway.</div>
          {/if}
          <div class="flex justify-end"><button class="btn-soft" disabled={pwBusy}>{strength(next).level === 1 && weakOk === next ? 'Use it anyway' : 'Change password'}</button></div>
        </form>
      {/if}
    </div>
  </section>

  <section class="flex flex-col gap-2.5">
    <h3 class="m-0 text-sm text-muted font-semibold">Connected apps</h3>
    <div class="card px-6 py-5 flex flex-col gap-4">
      <!-- One direction: apps push names here with a key. fjord's key comes
           with the install; anything else gets one below. The proxy never
           reaches out to an app. -->
      <div class="hint text-sm">An app with a key adds, changes and removes names here, and nothing else. fjord connects by itself when it installs this proxy. <a class="text-accent" href="/api/v1/openapi.json" target="_blank" rel="noopener">API reference</a></div>
      {#if paired || keys.length}
        <ul class="m-0 p-0 list-none flex flex-col divide-y divide-[color:var(--border)]">
          {#if paired}
            <li class="flex items-center justify-between gap-4 py-3">
              <span class="flex flex-col min-w-0 flex-1">
                {#if paired.disabled}
                  <span class="text-sm flex items-center gap-2">{paired.label}<span class="flex items-center gap-1.5 text-sm text-muted"><span class="w-2 h-2 rounded-full border-2 border-[color:var(--muted)] box-border"></span>Disconnected</span></span>
                  <span class="hint">Installed this proxy. Can't add or change names until reconnected; the {fromPaired === 1 ? 'name' : `${fromPaired} names`} it made still work.</span>
                {:else}
                  <span class="text-sm flex items-center gap-2">{paired.label}<span class="flex items-center gap-1.5 text-sm text-success-soft-fg"><span class="w-2 h-2 rounded-full bg-[color:var(--success)]"></span>Connected</span></span>
                  <span class="hint">Installed this proxy{fromPaired ? `; ${came(fromPaired)}` : ''}.{#if paired.url}&nbsp;·&nbsp;<a class="text-accent" href={paired.url}>Open {paired.label}</a>{/if}</span>
                {/if}
              </span>
              {#if paired.disabled}
                <button type="button" class="btn-primary shrink-0 min-h-10 px-4" onclick={() => { setPaired(paired!, false); toast(`Reconnected ${paired!.label}`) }}>Reconnect</button>
              {:else}
                <button type="button" class="btn-danger shrink-0 min-h-10 px-3" onclick={() => disconnectPaired(paired!)}>Disconnect</button>
              {/if}
            </li>
          {/if}
          {#each keys as t (t.id)}
            <li class="flex items-center justify-between gap-4 py-3">
              <span class="flex flex-col min-w-0 flex-1">
                <!-- Connected once something has called with the key; until
                     then only made. A fjord linked by code has an id and an
                     address; a plain key has neither. -->
                {#if t.lastUsedAt}
                  <span class="text-sm flex items-center gap-2">{t.label}<span class="flex items-center gap-1.5 text-sm text-success-soft-fg"><span class="w-2 h-2 rounded-full bg-[color:var(--success)]"></span>Connected</span></span>
                  <span class="hint">{#if t.clientId}Linked by code; {came(namesFrom(t))}.{:else}By key, last used {new Date(t.lastUsedAt).toLocaleDateString()}.{/if}{#if t.url}&nbsp;·&nbsp;<a class="text-accent" href={t.url}>Open {t.label}</a>{/if}</span>
                {:else}
                  <span class="text-sm flex items-center gap-2">{t.label}<span class="flex items-center gap-1.5 text-sm text-muted"><span class="w-2 h-2 rounded-full border-2 border-[color:var(--muted)] box-border"></span>Not used yet</span></span>
                  <span class="hint">{#if t.clientId}Linked by code; it has not called yet.{:else}A key was made for it; nothing has called with it so far.{/if}</span>
                {/if}
              </span>
              <button type="button" class="btn-danger shrink-0 min-h-10 px-3" onclick={() => removeApp(t)}>Disconnect</button>
            </li>
          {/each}
        </ul>
      {:else}
        <div class="text-sm text-muted">Nothing connected yet.</div>
      {/if}
      {#if freshToken}
        <div class="rounded-lg p-4 bg-success-soft text-success-soft-fg flex flex-col gap-2">
          <div class="font-semibold">The key for {freshLabel}. Paste it where that app asks for this proxy's key; it won't be shown again.</div>
          <code class="font-mono break-all select-all text-sm bg-inset text-fg rounded p-2">{freshToken}</code>
          <div class="flex justify-end"><button type="button" class="btn-plain min-h-10" onclick={() => (freshToken = '')}>Done</button></div>
        </div>
      {/if}
      {#if pairLink}
        <div class="rounded-lg p-4 bg-accent-soft text-accent-soft-fg flex flex-col gap-2">
          <div class="font-semibold">For another fjord, on another machine.</div>
          <div class="text-sm">Open that fjord's Settings, Names tab, paste this link into its Reverse proxy box and press Link. Works once, within ten minutes.</div>
          <code class="font-mono break-all select-all text-sm bg-inset text-fg rounded p-2">{pairLink}</code>
          <div class="flex justify-end gap-2">
            <button type="button" class="btn-plain min-h-10" onclick={() => (pairLink = '')}>Done</button>
            <button type="button" class="btn-soft min-h-10 px-4" onclick={copyPairLink}>Copy</button>
          </div>
        </div>
      {/if}
      <div class="flex gap-2 flex-wrap items-center">
        <button type="button" class="btn-soft" onclick={connectFjord} disabled={pairBusy}>Connect a fjord…</button>
        <span class="hint">Another fjord, on another machine, so its apps get names here too. For a script or anything else, make a key:</span>
      </div>
      <form onsubmit={addApp} class="flex gap-2 flex-wrap">
        <input class="input flex-1 basis-56 min-w-0" bind:value={appLabel} placeholder="What the key is for" autocomplete="off" aria-label="Key label" />
        <button class="btn-soft">Make a key</button>
      </form>
      {#if appError}<div class="field-error">{appError}</div>{/if}
    </div>
  </section>

  <section class="flex flex-col gap-2.5">
    <h3 class="m-0 text-sm text-muted font-semibold">Backup</h3>
    <div class="card px-6 py-5 flex flex-col gap-4">
      <form onsubmit={downloadBackup} class="flex flex-col gap-3">
        <div class="hint text-sm">Names, settings, password and root certificate in one file. A passphrase locks it; the file holds the root's private key.</div>
        <div class="flex gap-2 flex-wrap">
          <input type="password" class="input flex-1 basis-56 min-w-0" bind:value={backupPass} placeholder="Passphrase (optional, 8+ characters)" autocomplete="off" aria-label="Backup passphrase" />
          <button class="btn-soft" disabled={backupBusy}>Download backup</button>
        </div>
        {#if backupError}<div class="field-error">{backupError}</div>{/if}
      </form>
      <div class="border-t border-[color:var(--border)] pt-4 flex flex-col gap-3">
        <div class="flex items-center justify-between gap-4 flex-wrap">
          <span class="flex flex-col"><span class="text-sm">Restore a backup</span><span class="hint">Replaces everything here and signs you out.</span></span>
          <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={() => { restoreOpen = !restoreOpen; restoreError = '' }}>{restoreOpen ? 'Cancel' : 'Restore…'}</button>
        </div>
        {#if restoreOpen}
          <form onsubmit={restoreBackup} class="flex flex-col gap-3">
            <div>
              <label for="rfile" class="hint block mb-1.5">Backup file (.rpbk)</label>
              <input id="rfile" type="file" accept=".rpbk" class="block w-full text-sm" bind:files={restoreFile} required />
            </div>
            <div class="flex gap-2 flex-wrap">
              <input type="password" class="input flex-1 basis-56 min-w-0" bind:value={restorePass} placeholder="Passphrase, if it has one" autocomplete="off" aria-label="Backup passphrase" />
              <button class="btn-danger" disabled={restoreBusy}>Restore and sign out</button>
            </div>
            {#if restoreError}<div class="field-error">{restoreError}</div>{/if}
          </form>
        {/if}
      </div>
    </div>
  </section>

  {/if}

  <div class="flex items-center justify-between gap-4 flex-wrap">
    <span class="hint">Daemonless Reverse Proxy {status?.version ?? ''} · Caddy {status?.caddy.version ?? ''}</span>
    <span class="flex gap-2">
      <button type="button" class="btn-plain" onclick={() => aboutDialog?.showModal()}>About</button>
      <button type="button" class="btn-plain" onclick={signOut}>Sign out</button>
    </span>
  </div>

  <!-- The dialog's 85vh is border-box: the scrolling inside is 2px shorter
       than it, or the dialog scrolls those 2px too (two scrollbars). -->
  <dialog bind:this={stopDialog} class="m-auto w-[min(480px,calc(100vw-2rem))] p-0 rounded-lg border border-[color:var(--border)] bg-card text-fg shadow-2xl backdrop:bg-black/40" aria-labelledby="stop-title">
    <div class="p-7 flex flex-col gap-4">
      <h2 id="stop-title" class="m-0 text-lg">Stop automatic certificates?</h2>
      <p class="m-0 text-sm leading-snug">{liveNames === 1 ? 'Your name' : liveNames ? `Your ${liveNames} names` : 'Your names'} will use the proxy's own certificate. Every phone and computer will show a security warning until you set each one up to trust the proxy.</p>
      <p class="m-0 text-sm leading-snug text-muted">Your {certLabel} token will be deleted. To go back, you'll make a new one.</p>
      <div class="flex justify-end gap-2 flex-wrap">
        <!-- First in the dialog, so it has the focus: Enter keeps things as they are. -->
        <button type="button" class="btn-soft min-h-10 px-4" onclick={() => stopDialog?.close()}>Cancel</button>
        <button type="button" class="btn-danger min-h-10 px-4" disabled={certsBusy} onclick={stopCerts}>Stop certificates</button>
      </div>
    </div>
  </dialog>
  <dialog bind:this={aboutDialog} class="m-auto w-[min(640px,calc(100vw-2rem))] max-h-[85vh] p-0 overflow-hidden rounded-lg border border-[color:var(--border)] bg-card text-fg shadow-2xl backdrop:bg-black/40" aria-labelledby="about-title">
    <div class="p-7 flex flex-col gap-4 max-h-[calc(85vh-2px)] overflow-y-auto">
      <div class="flex items-start justify-between gap-4">
        <div class="flex items-center gap-3">
          <svg width="40" height="40" viewBox="0 0 512 512" aria-hidden="true"><path d="M256,24 C352,24 456,58 456,128 C456,300 362,432 256,500 C150,432 56,300 56,128 C56,58 160,24 256,24 Z" fill="var(--accent)"/><path d="M256,86 L302,172 L274,172 L274,334 L326,306 L326,230 L308,230 C328,180 376,150 376,220 L376,328 C340,366 296,386 274,394 L274,452 L238,452 L238,394 C216,386 172,366 136,328 L136,220 C136,150 184,180 204,230 L186,230 L186,306 L238,334 L238,172 L210,172 Z" fill="#fff" transform="translate(256 256) scale(0.98) translate(-256 -262)"/></svg>
          <div class="flex flex-col"><h2 id="about-title" class="m-0 text-lg">Daemonless Reverse Proxy</h2><span class="hint">{status?.version ?? ''} · Caddy {status?.caddy.version ?? ''}</span></div>
        </div>
        <button type="button" class="min-w-11 min-h-10 grid place-items-center rounded-lg hover:bg-chip cursor-pointer text-lg" aria-label="Close" onclick={() => aboutDialog?.close()}>×</button>
      </div>
      <p class="m-0 text-sm leading-snug text-muted">A daemonless appliance, released under the <a href={ourLicense.url} class="text-accent" target="_blank" rel="noopener">{ourLicense.name}</a> license. It is built from the following software; each name links to its project.</p>
      <ul class="m-0 p-0 list-none divide-y divide-[color:var(--border)]">
        {#each credits as c (c.name)}
          <li class="py-2.5 flex items-baseline justify-between gap-4 flex-wrap">
            <span class="flex flex-col gap-0.5 min-w-0"><a href={c.url} class="text-fg font-semibold no-underline hover:underline" target="_blank" rel="noopener">{c.name}</a><span class="hint">{c.role}</span></span>
            <span class="chip shrink-0">{c.license}</span>
          </li>
        {/each}
      </ul>
      <p class="m-0 hint">{buildTools}</p>
    </div>
  </dialog>

  {/if}
</div>
