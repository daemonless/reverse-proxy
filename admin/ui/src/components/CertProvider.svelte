<script lang="ts">
  import { get, put, ApiError, type Certificates, type Provider, type ProviderGuess, type CertStatus } from '../lib/api'

  // Automatic certificates for a public ending: pick where the domain's DNS
  // lives, paste the token, watch the trial run. Used by setup and Settings.
  // edit (Settings' Change and Fix token): a working setup opens on the
  // form, the saved provider picked; a failed one keeps its details.
  let { domain, onok, onskip, onback, edit = false }: { domain: string; onok?: (status: CertStatus) => void; onskip?: () => void; onback?: () => void; edit?: boolean } = $props()

  let providers = $state<Provider[]>([])
  let status = $state<CertStatus | null>(null)
  let guess = $state<ProviderGuess | null>(null)
  let chosen = $state('')
  let showAll = $state(false)
  let fields = $state<Record<string, string>>({})
  let error = $state(''); let errorField = $state('')
  let busy = $state(false)
  let view = $state<'loading' | 'form' | 'progress' | 'done' | 'failed'>('loading')
  let startedAt = $state(0); let elapsed = $state(0)
  let showDetail = $state(false)

  const zone = $derived(guess?.zone || domain)
  // A free name (you.duckdns.org) has only one possible provider: no
  // "who runs the DNS" question, straight to its token.
  const freeName = $derived(!!guess?.provider && !guess.nameservers?.length && chosen === guess.provider)
  const provider = $derived(providers.find((p) => p.id === chosen) ?? null)
  // Detected first, then the named services, then the generic ones.
  const offered = $derived.by(() => {
    const named = providers.filter((p) => !p.generic)
    const sorted = [...named].sort((a, b) => (a.id === guess?.provider ? -1 : b.id === guess?.provider ? 1 : 0))
    return showAll ? [...sorted, ...providers.filter((p) => p.generic)] : sorted.slice(0, 3)
  })

  function show(st: CertStatus) {
    status = st
    if (st.state === 'trial' || st.state === 'issuing') { view = 'progress'; if (!startedAt) startedAt = st.since ? Date.parse(st.since) : Date.now() }
    else if (st.state === 'ok') view = 'done'
    else if (st.state === 'failed') view = 'failed'
    else view = 'form'
  }

  async function load() {
    const c = await get<Certificates>('/api/v1/certificates')
    providers = c.providers
    if (c.provider) chosen = c.provider
    if (c.status.state === 'manual' || (edit && c.status.state === 'ok')) {
      if (c.status.state !== 'manual') status = c.status
      view = 'form'
      try { guess = await get<ProviderGuess>('/api/v1/certificates/detect'); if (!chosen && guess.provider) chosen = guess.provider } catch { guess = null }
      if (!chosen) showAll = true
    } else show(c.status)
  }
  load()

  // While the trial runs, keep asking; the server moves it along.
  const clock = setInterval(() => { if (view === 'progress') elapsed = Math.max(0, Math.round((Date.now() - startedAt) / 1000)) }, 1000)
  const timer = setInterval(async () => {
    if (view !== 'progress') return
    try { const c = await get<Certificates>('/api/v1/certificates'); show(c.status) } catch {}
  }, 3000)
  $effect(() => () => { clearInterval(timer); clearInterval(clock) })

  async function connect(e: SubmitEvent) {
    e.preventDefault(); error = ''; errorField = ''; busy = true
    try {
      const c = await put<Certificates>('/api/v1/certificates', { provider: chosen, fields })
      startedAt = Date.now(); elapsed = 0
      show(c.status)
    } catch (err) {
      if (err instanceof ApiError) { error = err.message; errorField = err.field } else error = 'Something went wrong'
    } finally { busy = false }
  }
  function retry() { view = 'form'; error = ''; showDetail = false }
  const until = $derived(status?.notAfter ? new Date(status.notAfter).toLocaleDateString() : '')
</script>

{#if view === 'loading'}
  <div class="hint">Loading…</div>

{:else if view === 'form'}
  <form onsubmit={connect} class="flex flex-col gap-5">
    {#if status?.message}
      <div class="flex items-start gap-3 rounded-xl px-5 py-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">
        <span class="w-3 h-3 mt-1.5 rounded-full shrink-0 box-border border-[3px] border-warning"></span>
        <span>{status.message}</span>
      </div>
    {/if}
    <div class="rounded-lg p-4 bg-accent-soft text-accent-soft-fg text-sm leading-snug flex flex-col gap-2">
      <div><strong>Why this step?</strong> Let's Encrypt gives a certificate only to the owner of a domain. To prove you own <strong>{zone}</strong>, the proxy adds a short-lived note to its DNS and removes it again. For that it needs a token, a kind of password, from the company that runs {zone}'s DNS.</div>
      <div>This token is only for the certificate. Your names keep working through your own network as they do today, and nothing is opened to the internet.</div>
    </div>
    {#if freeName}
      <div class="text-sm">Your free name <strong>{zone}</strong> is at {provider?.label}.</div>
    {:else}
    <div class="flex flex-col gap-2">
      <div class="text-sm">Who runs the DNS for <strong>{zone}</strong>?</div>
      {#if guess?.provider && chosen === guess.provider}
        <div class="hint">Found from its nameservers ({guess.nameservers.slice(0, 2).join(', ')}).</div>
      {:else if guess && !guess.provider}
        <div class="hint">Its nameservers ({guess.nameservers.slice(0, 2).join(', ')}) aren't one of the services below. If they're your own server, pick RFC 2136.</div>
      {/if}
      <div class="flex gap-2 flex-wrap" role="radiogroup" aria-label="DNS provider">
        {#each offered as p (p.id)}
          <button type="button" role="radio" aria-checked={chosen === p.id} onclick={() => { chosen = p.id; fields = {}; error = '' }}
            class="min-h-10 px-4 rounded-lg text-sm cursor-pointer border {chosen === p.id ? 'bg-accent text-white border-accent font-semibold' : 'bg-card text-fg border-[color:var(--border)] hover:bg-chip'}">{p.label}</button>
        {/each}
        {#if !showAll}
          <button type="button" class="min-h-10 px-4 rounded-lg text-sm cursor-pointer border border-dashed border-[color:var(--border)] bg-card text-accent" onclick={() => (showAll = true)}>Somewhere else…</button>
        {/if}
      </div>
    </div>
    {/if}

    {#if provider}
      <div class="flex flex-col gap-3">
        {#if provider.steps?.length}
          <div class="text-sm font-semibold">Get a token from {provider.label}</div>
          <ol class="m-0 pl-6 list-decimal flex flex-col gap-2 text-sm leading-snug">
            {#each provider.steps as step, i (i)}
              <li class="pl-1">{step.replaceAll('{zone}', zone)}{#if i === 0 && provider.url}<br /><a href={provider.url} target="_blank" rel="noopener" class="btn-soft inline-flex min-h-10 px-4 mt-2 text-sm no-underline">Open {provider.label} ↗</a>{/if}</li>
            {/each}
          </ol>
        {:else}
          <div class="hint">{provider.help}{#if provider.url} <a href={provider.url} target="_blank" rel="noopener" class="text-accent">Open {provider.label} ↗</a>{/if}</div>
        {/if}
        {#each provider.fields as f (f.key)}
          <div>
            <label for="pf-{f.key}" class="label">{f.label}{#if f.optional} <span class="text-muted font-normal">(optional)</span>{/if}</label>
            {#if f.secret}
              <input id="pf-{f.key}" type="password" class="input font-mono" bind:value={fields[f.key]} autocomplete="off" spellcheck="false" placeholder={f.placeholder ?? ''} required={!f.optional} />
            {:else}
              <input id="pf-{f.key}" class="input font-mono" bind:value={fields[f.key]} autocomplete="off" spellcheck="false" placeholder={f.placeholder ?? ''} required={!f.optional} />
            {/if}
            {#if error && errorField === f.key}<div class="field-error">{error}</div>{/if}
          </div>
        {/each}
        {#if error && !provider.fields.some((f) => f.key === errorField)}<div class="field-error">{error}</div>{/if}
        <div class="hint">{provider.checked ? `Connect checks the token with ${provider.label} right away, then` : 'Connect'} tries it with a test certificate, so a wrong one costs nothing. The token stays on this proxy and is never shown again.</div>
      </div>
    {/if}

    <div class="flex items-center justify-between gap-4 flex-wrap">
      <span class="flex gap-2 flex-wrap">{#if onback}<button type="button" class="btn-plain" onclick={onback}>Back</button>{/if}{#if onskip}<button type="button" class="btn-plain" onclick={onskip}>Skip for now</button>{/if}</span>
      <button class="btn-primary" disabled={busy || !provider}>{busy && provider?.checked ? `Checking with ${provider.label}…` : 'Connect'}</button>
    </div>
    {#if onskip}<div class="hint">Skipping works like a private ending: the proxy signs its own certificates and each device trusts it once.</div>{/if}
  </form>

{:else if view === 'progress'}
  {@const at = status?.state === 'issuing' ? 2 : 1}
  {@const steps = [
    { title: provider?.checked ? `${provider.label} accepted the token` : 'Token saved', detail: '' },
    { title: `Proving you own ${zone}`, detail: `The proxy adds a short note to ${zone}'s DNS at ${provider?.label ?? 'your DNS provider'} and Let's Encrypt checks it with a test certificate. Waiting for the note to show up takes most of the time.` },
    { title: 'Getting the real certificate', detail: "The test worked. Let's Encrypt is issuing the real one; names open with a warning until it arrives." },
    { title: 'Done', detail: '' },
  ]}
  <div role="status" aria-live="polite" class="flex flex-col gap-4">
    <ol class="m-0 p-0 list-none flex flex-col gap-3">
      {#each steps as st, i (i)}
        <li class="flex items-start gap-3">
          {#if i < at}
            <span class="w-6 h-6 rounded-full shrink-0 flex items-center justify-center bg-success text-white"><svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 10.5l4 4 8-9"></path></svg></span>
          {:else if i === at}
            <span class="w-6 h-6 rounded-full shrink-0 box-border border-[3px] border-accent border-t-transparent animate-spin" aria-hidden="true"></span>
          {:else}
            <span class="w-6 h-6 rounded-full shrink-0 box-border border-2 border-[color:var(--border)]" aria-hidden="true"></span>
          {/if}
          <div class="flex flex-col gap-1 min-w-0 pt-0.5">
            <div class="text-sm {i === at ? 'font-semibold text-fg' : i < at ? 'text-fg' : 'text-muted'}">{st.title}{#if i === at}<span class="font-normal text-muted">&nbsp;· {Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, '0')}</span>{/if}</div>
            {#if i === at && st.detail}<div class="hint leading-snug">{st.detail}</div>{/if}
          </div>
        </li>
      {/each}
    </ol>
    <div class="hint">Usually one to three minutes.</div>
    {#if status?.state === 'issuing' && onok}
      <div class="flex justify-end"><button type="button" class="btn-primary" onclick={() => onok?.(status!)}>Continue</button></div>
    {/if}
  </div>

{:else if view === 'done'}
  <div class="flex flex-col gap-3">
    <div class="flex items-center gap-3 rounded-xl px-5 py-4 bg-success-soft text-success-soft-fg text-sm">
      <span class="w-3 h-3 rounded-full shrink-0 bg-success"></span>
      <span>Certificates are automatic from now on.{#if until}{' '}Valid until {until}; it renews itself.{/if} No device setup needed.</span>
    </div>
    {#if onok}<div class="flex justify-end"><button type="button" class="btn-primary" onclick={() => onok?.(status!)}>Continue</button></div>{/if}
  </div>

{:else if view === 'failed'}
  <div class="flex flex-col gap-3">
    <div class="flex items-start gap-3 rounded-xl px-5 py-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">
      <span class="w-3 h-3 mt-1.5 rounded-full shrink-0 box-border border-[3px] border-warning"></span>
      <span>{status?.message}</span>
    </div>
    {#if status?.detail}
      <button type="button" class="btn-plain self-start text-sm text-accent" onclick={() => (showDetail = !showDetail)}>{showDetail ? 'Hide details' : 'Details'}</button>
      {#if showDetail}<pre class="m-0 rounded-lg bg-inset p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-all text-muted">{status.detail}</pre>{/if}
    {/if}
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <span class="flex gap-2 flex-wrap">{#if onback}<button type="button" class="btn-plain" onclick={onback}>Back</button>{/if}{#if onskip}<button type="button" class="btn-plain" onclick={onskip}>Skip for now</button>{/if}</span>
      <button type="button" class="btn-primary" onclick={retry}>Try again</button>
    </div>
  </div>
{/if}
