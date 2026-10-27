<script lang="ts">
  import { post, put, get, ApiError, type Settings, type Token, type Certificates, type Provider } from '../lib/api'
  import { session } from '../lib/session.svelte'
  import { navigate } from '../lib/router.svelte'
  import { classify } from '../lib/domain'
  import { focus } from '../lib/focus'
  import DnsGuide from '../components/DnsGuide.svelte'
  import CertProvider from '../components/CertProvider.svelte'
  import PasswordStrength from '../components/PasswordStrength.svelte'
  import { strength } from '../lib/password'

  type Step = 'welcome' | 'token' | 'password' | 'kind' | 'free' | 'address' | 'certs' | 'dns' | 'trust' | 'done' | 'restore'
  let step = $state<Step>('welcome')
  let token = $state('')
  let verified = $state(false)
  // The app that installed this proxy (a paired key), for the last step:
  // its apps get names from there, so "add your first host" is the wrong
  // next thing to say to it.
  let pairedWith = $state('')
  let pairedUrl = $state('')
  // Before setup, the app that installed this proxy, from the public
  // status: Verify sends people back to it (Finish setup there opens this
  // page verified) instead of into the log for a 64-character token.
  let installedBy = $state<{ name: string; url: string } | null>(null)
  get<{ installedBy?: { name: string; url: string } }>('/api/v1/status').then((r) => { installedBy = r.installedBy ?? null }).catch(() => {})
  let pasteToken = $state(false)
  $effect(() => {
    if (step !== 'done') return
    get<{ tokens: Token[] }>('/api/v1/tokens').then((r) => { const t = r.tokens.find((t) => t.paired && !t.disabled); pairedWith = t?.label ?? ''; pairedUrl = t?.url ?? '' }).catch(() => { pairedWith = ''; pairedUrl = '' })
  })
  let password = $state('')
  let again = $state('')
  // A weak password is warned about once and then allowed (Fedora does
  // the same): weakOk is the second click, for the password it was given on.
  let weakOk = $state('')
  const weak = $derived(strength(password).level === 1)
  let domain = $state('')
  // A public ending adds the certificates step and, once a provider is
  // connected, drops the trust step: nothing to install by hand.
  let certsConnected = $state(false)
  const isPublic = $derived(classify(domain) === 'public')
  const trustNeeded = $derived(!(isPublic && certsConnected))
  const rail = $derived.by(() => {
    const r: { id: Step; label: string }[] = [{ id: 'token', label: 'Verify' }, { id: 'password', label: 'Password' }, { id: 'address', label: 'Names' }]
    if (isPublic) r.push({ id: 'certs', label: 'Certificates' })
    r.push({ id: 'dns', label: 'Point names' })
    if (trustNeeded) r.push({ id: 'trust', label: 'Trust' })
    return r
  })
  let suggestions = $state<string[]>([])
  // "Just for home" offers only endings that stay at home.
  const homeSuggestions = $derived(suggestions.filter((d) => classify(d) === 'private' && d !== 'home.lan'))
  async function loadSuggestions() {
    try { suggestions = (await get<{ suggestions: string[] }>(`/api/v1/suggest-domain?host=${encodeURIComponent(location.hostname)}`)).suggestions } catch { suggestions = [] }
  }
  let error = $state('')
  let busy = $state(false)
  let restoreFile = $state<FileList | null>(null)
  let restorePass = $state('')
  async function submitRestore(e: SubmitEvent) {
    e.preventDefault(); error = ''; busy = true
    try {
      const fd = new FormData()
      if (!restoreFile?.[0]) throw new Error('Choose the backup file')
      fd.append('file', restoreFile[0]); fd.append('passphrase', restorePass)
      const res = await fetch('/api/v1/restore', { method: 'POST', body: fd, credentials: 'same-origin' })
      const d = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(d.error ?? 'Restore failed')
      await session.refresh()
      navigate('/login', true)
    } catch (err) { error = err instanceof Error ? err.message : 'Restore failed' }
    finally { busy = false }
  }
  let dnsOk = $state(false)
  // Judge the ending only once typing pauses, so "apps.home.la" is not
  // called a public domain on the way to "apps.home.lan".
  let settled = $state('')
  $effect(() => {
    const d = domain
    const t = setTimeout(() => { settled = d }, 600)
    return () => clearTimeout(t)
  })
  const kind = $derived(classify(settled))
  const typing = $derived(settled !== domain)
  // Choosing the kind of names and the free name are part of Names.
  const railIndex = $derived(rail.findIndex((r) => r.id === (step === 'kind' || step === 'free' ? 'address' : step)))
  // A link from the log carries the token in the fragment: verify it at
  // once and drop it from the address bar.
  {
    const m = location.hash.match(/token=([^&]+)/)
    if (m && !session.value?.authenticated) {
      const t = decodeURIComponent(m[1])
      token = t
      history.replaceState(null, '', location.pathname)
      post('/api/v1/setup/token', { token: t }).then(() => { verified = true }).catch(() => { verified = false })
    }
  }
  // Resuming while signed in (the password exists): skip what is done.
  if (session.value?.authenticated) {
    get<Settings>('/api/v1/settings').then((s) => { domain = s.domain; if (!s.domain) loadSuggestions(); resumeAfterAddress(s) })
  }
  async function resumeAfterAddress(s: Settings) {
    if (!s.domain) { step = 'kind'; return }
    if (s.mode === 'public') {
      try { const c = await get<{ provider?: string }>('/api/v1/certificates'); certsConnected = !!c.provider } catch {}
      step = certsConnected ? 'dns' : 'certs'
    } else step = 'dns'
  }

  function fail(err: unknown) { error = err instanceof ApiError ? err.message : 'Something went wrong' }

  async function submitToken(e: SubmitEvent) {
    e.preventDefault(); error = ''; busy = true
    try { await post('/api/v1/setup/token', { token }); step = 'password' } catch (err) { fail(err) } finally { busy = false }
  }
  async function submitPassword(e: SubmitEvent) {
    e.preventDefault(); error = ''
    // A typo here locks you out until reset-password on the command line.
    if (password !== again) { error = 'The two passwords differ.'; return }
    if (weak && weakOk !== password) { weakOk = password; return }
    busy = true
    try {
      await post('/api/v1/setup/password', { password })
      const s = await get<Settings>('/api/v1/settings')
      domain = s.domain; if (!s.domain) loadSuggestions()
      await resumeAfterAddress(s)
      navigate('/setup', true)
      await session.refresh()
    } catch (err) { fail(err) } finally { busy = false }
  }
  async function saveDomain() {
    error = ''; busy = true
    try { const s = await put<Settings>('/api/v1/settings', { domain, trustedNetworks: [] }); domain = s.domain; step = s.mode === 'public' ? 'certs' : 'dns' }
    catch (err) { fail(err) } finally { busy = false }
  }
  function submitAddress(e: SubmitEvent) { e.preventDefault(); saveDomain() }

  // How names look, before any typing: most people don't know what an
  // ending is, but do know whether they want to sign up for something.
  type Choice = 'home' | 'free' | 'own'
  let choice = $state<Choice>('home')
  let freeProviders = $state<Provider[]>([])
  let freeId = $state('')
  let freeName = $state('')
  const free = $derived(freeProviders.find((p) => p.id === freeId)?.free ?? null)
  const freeLabel = $derived(freeProviders.find((p) => p.id === freeId)?.label ?? '')
  const nameOk = $derived(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(freeName))
  async function chooseKind(e: SubmitEvent) {
    e.preventDefault(); error = ''
    if (choice === 'free') {
      if (!freeProviders.length) {
        try { freeProviders = (await get<Certificates>('/api/v1/certificates')).providers.filter((p) => p.free) } catch (err) { fail(err); return }
      }
      if (!freeId && freeProviders.length) freeId = freeProviders[0].id
      step = 'free'
      return
    }
    if (choice === 'home') { domain = 'home.lan'; if (!suggestions.length) loadSuggestions() }
    else domain = ''
    step = 'address'
  }
  function submitFree(e: SubmitEvent) {
    e.preventDefault()
    if (!free || !nameOk) return
    domain = `${freeName}.${free.suffix}`
    saveDomain()
  }
</script>

<div class="box-border px-4 py-10 sm:py-14 flex flex-col items-center gap-6">
  {#if railIndex >= 0}
    <ol class="m-0 p-0 list-none flex items-center gap-2 sm:gap-3 flex-wrap justify-center" aria-label="Setup progress">
      {#each rail as r, i (r.id)}
        <li class="flex items-center gap-2 sm:gap-3">
          <span class="flex items-center gap-2 text-xs {i === railIndex ? 'text-fg font-semibold' : i < railIndex ? 'text-success-soft-fg' : 'text-muted'}">
            <span class="w-6 h-6 rounded-full grid place-items-center text-[13px] {i < railIndex ? 'bg-success text-white' : i === railIndex ? 'bg-accent text-white' : 'bg-chip text-chip-fg'}">{i < railIndex ? '✓' : i + 1}</span>
            <span class="hidden sm:inline">{r.label}</span>
          </span>
          {#if i < rail.length - 1}<span class="w-4 sm:w-8 h-px bg-[color:var(--border)]"></span>{/if}
        </li>
      {/each}
    </ol>
  {/if}

  <div class="card w-full max-w-[600px] box-border p-8 sm:p-10 flex flex-col gap-5">
    {#if step === 'welcome'}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Welcome</h1>
      <p class="m-0 text-base leading-snug">Daemonless Reverse Proxy puts friendly, secure addresses in front of the services on your network: <strong>radarr.home.example.com</strong> instead of an IP and a port, over HTTPS, with no warnings.</p>
      <ol class="m-0 p-0 list-none flex flex-col gap-3">
        {#each ['Pick the ending for your service names.', 'Point names at the proxy with one DNS record (we show you exactly where).', 'Trust the proxy on your devices, once.'] as t, i}
          <li class="flex gap-3.5 items-start">
            <span class="shrink-0 w-8 h-8 rounded-full bg-accent-soft text-accent-soft-fg font-semibold grid place-items-center">{i + 1}</span>
            <span class="text-sm leading-snug pt-1">{t}</span>
          </li>
        {/each}
      </ol>
      <p class="m-0 hint">Takes about five minutes. Everything can be changed later in Settings.</p>
      <div class="flex items-center justify-between gap-4 flex-wrap">
        {#if verified}<span class="flex items-center gap-2 text-success-soft-fg text-sm"><span class="w-3 h-3 rounded-full bg-success"></span>Verified from your link</span>{:else}<span></span>{/if}
        <span class="flex gap-2 flex-wrap">
          <!-- A real button: as small print it was missed, and an install
               from fjord goes straight past this screen. -->
          <button type="button" class="btn-plain" onclick={() => (step = 'restore')}>Restore a backup</button>
          <button type="button" class="btn-primary" onclick={() => (step = verified ? 'password' : 'token')}>Let's start</button>
        </span>
      </div>

    {:else if step === 'restore'}
      <form onsubmit={submitRestore} class="contents">
        <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Restore a backup</h1>
        <p class="m-0 hint text-sm">Names, settings, password and the root your devices trust come back.</p>
        <div>
          <label for="rfile" class="label">Backup file</label>
          <input id="rfile" type="file" accept=".rpbk" class="block w-full text-sm" bind:files={restoreFile} required />
        </div>
        <div>
          <label for="rpass" class="label">Passphrase, if it has one</label>
          <input id="rpass" type="password" class="input" bind:value={restorePass} autocomplete="off" />
          {#if error}<div class="field-error">{error}</div>{/if}
        </div>
        <div class="flex items-center justify-between gap-4 flex-wrap">
          <button type="button" class="btn-plain" onclick={() => { step = 'welcome'; error = '' }}>Back</button>
          <button class="btn-primary" disabled={busy}>Restore</button>
        </div>
      </form>

    {:else if step === 'token' && installedBy && !pasteToken}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Finish setup from {installedBy.name}</h1>
      <p class="m-0 hint text-sm">{installedBy.name} installed this proxy. Open it and press <strong>Finish setup</strong> on the proxy's row: this page opens again, already verified.</p>
      <div class="flex items-center justify-between gap-4 flex-wrap">
        <button type="button" class="btn-plain" onclick={() => (pasteToken = true)}>Paste the token from the log instead</button>
        <a class="btn-primary" href={installedBy.url}>Open {installedBy.name}</a>
      </div>

    {:else if step === 'token'}
      <form onsubmit={submitToken} class="contents">
        <h1 class="m-0 text-2xl font-bold text-fg leading-tight">First, let's make sure it's you</h1>
        <p class="m-0 hint text-sm">The proxy printed a setup token in its log when it started. Paste it here.</p>
        <div>
          <label for="token" class="label">Setup token</label>
          <input id="token" class="input font-mono" bind:value={token} autocomplete="off" spellcheck="false" placeholder="From the log" required use:focus />
          {#if error}<div class="field-error">{error}</div>{/if}
        </div>
        <details class="hint">
          <summary class="cursor-pointer min-h-10 flex items-center">Where is the log?</summary>
          <p class="mt-2">On the machine running the proxy: <code class="font-mono">podman logs reverse-proxy</code> (or <code class="font-mono">docker logs</code>). The token follows "setup token:" near the top.</p>
        </details>
        <div class="flex items-center justify-between gap-4 flex-wrap">
          {#if installedBy}<button type="button" class="btn-plain" onclick={() => (pasteToken = false)}>Back</button>{:else}<span></span>{/if}
          <button class="btn-primary" disabled={busy}>Continue</button>
        </div>
      </form>

    {:else if step === 'password'}
      <form onsubmit={submitPassword} class="contents">
        <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Choose a password</h1>
        <p class="m-0 hint text-sm">A short sentence is easy to remember and hard to guess.</p>
        <div>
          <label for="password" class="label">Password</label>
          <input id="password" type="password" class="input" bind:value={password} autocomplete="new-password" required use:focus />
          <PasswordStrength {password} />
        </div>
        <div>
          <label for="password-again" class="label">Password again</label>
          <input id="password-again" type="password" class="input" bind:value={again} autocomplete="new-password" required />
          {#if error}<div class="field-error">{error}</div>{/if}
        </div>
        {#if weak && weakOk === password}
          <div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">This password is weak: {strength(password).why.toLowerCase().replace(/\.$/, '')}. Anyone who can open this page could guess it. Choose another, or use it anyway.</div>
        {/if}
        <div class="flex justify-end"><button class="btn-primary" disabled={busy}>{weak && weakOk === password ? 'Use it anyway' : 'Continue'}</button></div>
      </form>

    {:else if step === 'kind'}
      <form onsubmit={chooseKind} class="contents">
        <h1 class="m-0 text-2xl font-bold text-fg leading-tight">How should your names look?</h1>
        <p class="m-0 text-sm leading-snug">Every service gets a name, like radarr.home.lan, that opens it securely. Pick the kind that suits you; you can change it later in Settings.</p>
        <div class="flex flex-col gap-2.5" role="radiogroup" aria-label="Kind of names">
          {#each [
            { id: 'home', title: 'Just for home', example: 'radarr.home.lan', text: 'Free, nothing to sign up for, works without the internet. Each phone and computer trusts the proxy once; we walk you through it, with a QR code for phones. Visitors\' devices show a warning.' },
            { id: 'free', title: 'A free name from DuckDNS', example: 'radarr.you.duckdns.org', text: 'Every device trusts it out of the box: no setup on phones, and visitors\' devices just work. One free sign-in; we show you each click.' },
            { id: 'own', title: 'A domain I own', example: 'radarr.home.example.com', text: 'The same as a free name, on your own domain. Works with Cloudflare, Route 53, Porkbun, Hetzner and more.' },
          ] as o (o.id)}
            <label class="flex items-start gap-3 rounded-xl border p-4 cursor-pointer {choice === o.id ? 'border-accent bg-accent-soft/40' : 'border-[color:var(--border)] hover:bg-chip'}">
              <input type="radio" name="kind" value={o.id} bind:group={choice} class="mt-1 accent-[color:var(--accent)]" />
              <span class="flex flex-col gap-1 min-w-0">
                <span class="flex items-baseline justify-between gap-3 flex-wrap"><span class="font-semibold text-fg">{o.title}</span>{#if o.example}<span class="font-mono text-xs text-muted break-all">{o.example}</span>{/if}</span>
                <span class="text-sm leading-snug text-muted">{o.text}</span>
              </span>
            </label>
          {/each}
        </div>
        {#if error}<div class="field-error">{error}</div>{/if}
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <span class="hint">Not sure? Start with "Just for home".</span>
          <button class="btn-primary">Continue</button>
        </div>
      </form>

    {:else if step === 'free'}
      <form onsubmit={submitFree} class="contents">
        <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Get your free name</h1>
        {#if freeProviders.length > 1}
        <div class="flex gap-2 flex-wrap" role="radiogroup" aria-label="Free name service">
          {#each freeProviders as p (p.id)}
            <button type="button" role="radio" aria-checked={freeId === p.id} onclick={() => (freeId = p.id)}
              class="min-h-10 px-4 rounded-lg text-sm cursor-pointer border {freeId === p.id ? 'bg-accent text-white border-accent font-semibold' : 'bg-card text-fg border-[color:var(--border)] hover:bg-chip'}">{p.label} <span class="font-mono {freeId === p.id ? '' : 'text-muted'}">.{p.free?.suffix}</span></button>
          {/each}
        </div>
        {/if}
        {#if free}
          {#if free.note}<p class="m-0 hint">{free.note}</p>{/if}
          <div>
            <label for="free-name" class="label">Your name</label>
            <div class="flex items-center gap-2">
              <input id="free-name" class="input font-mono" bind:value={freeName} oninput={() => (freeName = freeName.toLowerCase().trim())} autocomplete="off" spellcheck="false" placeholder="you" required use:focus />
              <span class="font-mono text-sm text-muted shrink-0">.{free.suffix}</span>
            </div>
            {#if freeName && !nameOk}<div class="field-error">Letters, digits and dashes only, not starting or ending with a dash.</div>{/if}
            <div class="hint mt-2">Your services will be at <span class="font-mono text-fg">radarr.{freeName || 'you'}.{free.suffix}</span></div>
          </div>
          <ol class="m-0 pl-5 list-decimal flex flex-col gap-1.5 text-sm leading-snug">
            {#each free.steps as st, i (i)}
              <li>{st.replace('{name}', freeName || 'your name')}{#if i === 0}{' '}<a href={free.signUp} target="_blank" rel="noopener" class="text-accent">Open {freeLabel}</a>{/if}</li>
            {/each}
            <li>Come back here and click Continue. The next step asks for its token.</li>
          </ol>
        {/if}
        {#if error}<div class="field-error">{error}</div>{/if}
        <div class="flex justify-between gap-2">
          <button type="button" class="btn-plain" onclick={() => { step = 'kind'; error = '' }}>Back</button>
          <button class="btn-primary" disabled={busy || !nameOk}>Continue</button>
        </div>
      </form>

    {:else if step === 'address'}
      <form onsubmit={submitAddress} class="contents">
        {#if choice === 'own'}
          <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Which domain?</h1>
          <p class="m-0 text-sm leading-snug">Names go under a part of your domain that nothing else uses. For example.com, <strong>home.example.com</strong> gives radarr.home.example.com.</p>
        {:else}
          <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Pick an ending for your service names</h1>
          <p class="m-0 text-sm leading-snug">Every service gets a name that ends the same way. You choose the ending now; each service's first part comes when you add it.</p>
        {/if}
        <div class="rounded-xl bg-inset border border-[color:var(--border)] p-5 flex flex-col gap-1.5" aria-live="polite">
          <div class="hint">Your services will be reached at</div>
          {#each ['radarr', 'photos', 'home'] as ex}
            <div class="font-mono text-base sm:text-lg break-all"><span class="text-muted">{ex}.</span><span class="text-fg">{domain || 'apps.home.arpa'}</span></div>
          {/each}
        </div>
        <div>
          <label for="domain" class="label">Ending</label>
          <input id="domain" class="input" bind:value={domain} autocomplete="off" spellcheck="false" placeholder={choice === 'own' ? 'home.example.com' : suggestions[0] ?? 'apps.home.arpa'} required use:focus />
          {#if error}<div class="field-error">{error}</div>{/if}
          {#if homeSuggestions.length && choice === 'home'}
            <div class="mt-3 flex items-center gap-2 flex-wrap">
              <span class="hint">Or one your network already uses:</span>
              {#each homeSuggestions as sug (sug)}
                <button type="button" class="chip hover:brightness-95 cursor-pointer min-h-9 {domain === sug ? 'bg-accent-soft text-accent-soft-fg font-semibold' : ''}" onclick={() => (domain = sug)}>{sug}</button>
              {/each}
            </div>
          {/if}
        </div>
        {#if typing}
          <div class="min-h-14"></div>
        {:else if kind === 'private'}
          <div class="rounded-lg p-4 bg-accent-soft text-accent-soft-fg text-sm leading-snug"><strong>Private ending.</strong> Works without the internet. Each device trusts the proxy once; we'll walk you through it.</div>
        {:else if kind === 'public'}
          <div class="rounded-lg p-4 bg-accent-soft text-accent-soft-fg text-sm leading-snug"><strong>A real domain.</strong> With a token for its DNS, certificates come from Let's Encrypt automatically and no device needs any setup. Nothing becomes reachable from the internet unless you say so.</div>
        {:else if kind === 'mdns'}
          <div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug"><strong>.local often doesn't work:</strong> many devices reserve it for their own discovery. Try .lan or .home.arpa.</div>
        {:else if kind === 'incomplete'}
          <div class="hint">An ending needs at least one dot, like <strong class="text-fg">apps.lan</strong>.</div>
        {/if}
        <div class="flex justify-between gap-2">
          <button type="button" class="btn-plain" onclick={() => { step = 'kind'; error = '' }}>Back</button>
          <button class="btn-primary" disabled={busy || classify(domain) === 'empty' || classify(domain) === 'incomplete' || classify(domain) === 'mdns'}>Continue</button>
        </div>
      </form>

    {:else if step === 'certs'}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Get certificates automatically</h1>
      <p class="m-0 text-sm leading-snug">Every name under <strong>{domain}</strong> gets a certificate from Let's Encrypt that every device already trusts. It renews by itself.</p>
      <CertProvider {domain} onok={() => { certsConnected = true; step = 'dns' }} onskip={() => { certsConnected = false; step = 'dns' }} onback={() => { step = 'kind'; error = '' }} />

    {:else if step === 'dns'}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Point names at the proxy</h1>
      <p class="m-0 hint text-sm">One DNS record sends every name under <strong class="text-fg">{domain}</strong> to this proxy. Add it where your devices get DNS.</p>
      <DnsGuide {domain} onok={() => (dnsOk = true)} />
      <div class="flex items-center justify-between gap-4 flex-wrap">
        <button type="button" class="btn-plain" onclick={() => (step = isPublic ? 'certs' : 'address')}>Back</button>
        <button type="button" class={dnsOk ? 'btn-primary' : 'btn-plain'} onclick={() => (step = trustNeeded ? 'trust' : 'done')}>{dnsOk ? 'Continue' : 'Skip for now'}</button>
      </div>

    {:else if step === 'trust'}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Trust the proxy on your devices</h1>
      <p class="m-0 text-sm leading-snug">Each device needs to trust the proxy's certificate once. After that, every service opens over HTTPS with no warnings. The Trust page walks each kind of device through it, and has a QR code for phones.</p>
      <div class="flex items-center justify-between gap-4 flex-wrap">
        <span class="flex gap-2 flex-wrap"><button type="button" class="btn-plain" onclick={() => (step = 'dns')}>Back</button><button type="button" class="btn-plain" onclick={() => (step = 'done')}>Later</button></span>
        <button type="button" class="btn-primary" onclick={() => navigate('/trust', true)}>Trust this device now</button>
      </div>

    {:else}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">You're set</h1>
      {#if pairedWith}
        <p class="m-0 text-sm leading-snug">{pairedWith} is connected. Give an app a name there and it shows up here, pointed at the app; names it makes follow the app when it moves.</p>
        <div class="flex justify-end gap-2">
          <button type="button" class={pairedUrl ? 'btn-plain' : 'btn-primary'} onclick={() => navigate('/hosts', true)}>See the names</button>
          {#if pairedUrl}<a href={pairedUrl} class="btn-primary">Back to {pairedWith}</a>{/if}
        </div>
      {:else}
        <p class="m-0 text-sm leading-snug">Now put a name in front of your first service. You only need its address and port.</p>
        <div class="flex justify-end"><button type="button" class="btn-primary" onclick={() => navigate('/hosts/new', true)}>Add your first name</button></div>
      {/if}
    {/if}
  </div>
</div>
