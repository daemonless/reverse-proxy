<script lang="ts">
  import { route, navigate, link } from './lib/router.svelte'
  import { session } from './lib/session.svelte'
  import { deviceTrust, whoAnswers } from './lib/trust.svelte'
  import { paired } from './lib/paired.svelte'
  import { setOnUnauthorized, get, post, type TrustInfo, type Status } from './lib/api'
  import { theme } from './lib/theme.svelte'
  import Toasts from './Toasts.svelte'
  import Setup from './screens/Setup.svelte'
  import Login from './screens/Login.svelte'
  import Hosts from './screens/Hosts.svelte'
  import HostForm from './screens/HostForm.svelte'
  import Settings from './screens/Settings.svelte'
  import Trust from './screens/Trust.svelte'

  // A 401 from any call means the session is gone.
  setOnUnauthorized(() => { session.signedOut(); navigate('/login', true) })

  let ready = $state(false)
  session.refresh().then(() => { ready = true; checkTrust() })

  // Opened by address (https://192.168.1.5:8443): an IP only ever gets the
  // setup certificate, so the browser says "Not secure" however well the
  // device trusts the proxy. Once it does, go to the proxy's own name.
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$/i.test(location.hostname)
  if (isIP && location.protocol === 'https:' && !location.hash.includes('token=')) {
    get<TrustInfo>('/api/v1/trust').then(async (t) => {
      if (!t.proxyName) return
      // Only to this same proxy: the name can lead to another one.
      if ((await whoAnswers(`https://${t.proxyName}/trust/check`, t.instance)) !== 'ours') return
      location.replace(`https://${t.proxyName}${location.port ? ':' + location.port : ''}${location.pathname}${location.search}${location.hash}`)
    }).catch(() => {})
  }

  // Does this device trust the proxy? A dot on the Trust tab says no.
  // Shared with the home page's status rows (lib/trust).
  const untrusted = $derived(deviceTrust.untrusted)
    const checkTrust = () => { deviceTrust.check(); paired.load() }

  // Where the person may be, given what the server says.
  const screen = $derived.by(() => {
    const s = session.value
    if (!ready || !s) return 'loading'
    const p = route.path
    if (p.startsWith('/trust')) return 'trust'
    if (p === '/link') return 'link'
    if (s.setupRequired) return 'setup'
    if (!s.authenticated) return 'login'
    // The wizard keeps the screen until it hands over itself; a signed-in
    // visit to /setup resumes it (no address yet, or revisiting the guide).
    if (p === '/setup') return 'setup'
    if (p === '/' || p === '/hosts' || p === '/login') return 'hosts'
    if (p === '/hosts/new') return 'host-new'
    if (p.startsWith('/hosts/')) return 'host-edit'
    if (p === '/settings') return 'settings'
    return 'hosts'
  })
  $effect(() => { if (route.path.startsWith('/trust')) return; checkTrust() })
  const hostId = $derived(route.path.startsWith('/hosts/') ? route.path.slice('/hosts/'.length) : '')

  // The shell, fjord's: a sidebar (brand, sections, account) beside the
  // page on wide screens, a top bar with the same sections on phones.
  // Not signed in (sign-in, setup, the trust page): a bare top bar.
  // Signed in, the Trust page is one more section inside the shell; the
  // plain-HTTP trust page (no session) stays bare.
  const withNav = $derived(!!session.value?.authenticated && screen !== 'setup' && screen !== 'link')
  // Always there: with a real domain it says the device is ready.
  const sections = [['/hosts', 'Names'], ['/trust', 'Trust'], ['/settings', 'Settings']]
  const isActive = (href: string) => route.path.startsWith(href) || (href === '/hosts' && screen.startsWith('host'))
  let status = $state<Status | null>(null)
  $effect(() => { if (withNav) get<Status>('/api/v1/status').then((st) => { status = st }).catch(() => {}) })
  async function signOut() { await post('/api/v1/logout'); session.signedOut(); navigate('/login', true) }
  const signInHref = location.protocol === 'https:' ? '/login' : /^[0-9.]+$|:/.test(location.hostname) ? `https://${location.hostname}:8443/login` : `https://${location.hostname}/login`
</script>

{#snippet mark(size: number)}
  <svg width={size} height={size} viewBox="0 0 512 512" aria-hidden="true"><path d="M256,24 C352,24 456,58 456,128 C456,300 362,432 256,500 C150,432 56,300 56,128 C56,58 160,24 256,24 Z" fill="var(--accent)"/><path d="M256,86 L302,172 L274,172 L274,334 L326,306 L326,230 L308,230 C328,180 376,150 376,220 L376,328 C340,366 296,386 274,394 L274,452 L238,452 L238,394 C216,386 172,366 136,328 L136,220 C136,150 184,180 204,230 L186,230 L186,306 L238,334 L238,172 L210,172 Z" fill="#fff" transform="translate(256 256) scale(0.98) translate(-256 -262)"/></svg>
{/snippet}

{#snippet sectionIcon(href: string)}
  {#if href === '/hosts'}
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h10"/></svg>
  {:else if href === '/trust'}
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>
  {:else}
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>
  {/if}
{/snippet}

{#snippet themeButton()}
  <button type="button" onclick={() => theme.toggle()} class="w-8 h-8 grid place-items-center rounded-lg text-muted hover:text-fg hover:bg-chip cursor-pointer" title={theme.value === 'dark' ? 'Light theme' : 'Dark theme'} aria-label={theme.value === 'dark' ? 'Switch to the light theme' : 'Switch to the dark theme'}>
    <!-- Like fjord's: the icon is the theme you switch to. -->
    {#if theme.value === 'dark'}
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
    {:else}
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
    {/if}
  </button>
{/snippet}

<div class="min-h-screen md:flex">
  {#if withNav}
    <aside class="hidden md:flex w-56 shrink-0 flex-col bg-bg border-r border-[color:var(--border)] sticky top-0 h-screen">
      <a href="/hosts" use:link class="flex items-center gap-2.5 text-lg font-bold tracking-widest text-fg no-underline px-5 py-4 border-b border-[color:var(--border)]">
        {@render mark(22)}
        <span><span class="text-accent">P</span>ROXY</span>
      </a>
      <nav class="flex flex-col gap-0.5 p-3" aria-label="Sections">
        {#each sections as [href, label]}
          <a {href} use:link aria-current={isActive(href) ? 'page' : undefined}
             class="relative flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium no-underline transition-colors {isActive(href) ? 'bg-border text-fg' : 'text-muted hover:text-fg'}">
            {@render sectionIcon(href)}
            {label}
            {#if href === '/trust' && untrusted}<span class="ml-auto w-2 h-2 rounded-full bg-warning" title="This device doesn't trust the proxy yet"></span>{/if}
          </a>
        {/each}
      </nav>
      <div class="mt-auto flex flex-col gap-1 px-4 pb-3 text-xs text-dim">
        {#if paired.value?.url && !paired.value.disabled}
          <a href={paired.value.url} class="text-accent no-underline hover:underline py-1">Back to {paired.value.label}</a>
        {/if}
        <div class="flex items-center gap-2">
          <span>Signed in</span>
          <button type="button" onclick={signOut} class="ml-auto hover:text-fg cursor-pointer">Sign out</button>
        </div>
        {#if status?.version}<span title="Caddy {status.caddy?.version ?? ''}">reverse-proxy {status.version}</span>{/if}
      </div>
    </aside>
  {/if}

  <div class="flex-1 min-w-0 flex flex-col">
    <!-- Phones, and anyone not signed in: one bar. -->
    <header class="bg-card border-b border-[color:var(--border)] {withNav ? 'md:hidden' : ''}">
      <div class="max-w-[960px] mx-auto px-4 min-h-14 flex items-center gap-3">
        <a href={session.value?.authenticated ? '/hosts' : '/trust'} use:link class="inline-flex items-center gap-2.5 font-bold tracking-widest text-fg no-underline min-h-10">
          {@render mark(22)}
          <span><span class="text-accent">P</span>ROXY</span>
        </a>
        {#if withNav}
          <nav class="ml-auto flex p-1 rounded-lg bg-chip" aria-label="Sections">
            {#each sections as [href, label]}
              <a {href} use:link aria-current={isActive(href) ? 'page' : undefined}
                 class="relative inline-flex items-center justify-center min-h-8 px-3 rounded-md text-sm no-underline transition-colors {isActive(href) ? 'bg-card text-fg font-semibold shadow-sm' : 'text-muted hover:text-fg'}">{label}{#if href === '/trust' && untrusted}<span class="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-warning"></span>{/if}</a>
            {/each}
          </nav>
          {@render themeButton()}
        {:else if screen === 'trust'}
          <!-- By name the admin answers on 443; by address it is on :8443. -->
          <a href={signInHref} class="ml-auto inline-flex items-center min-h-10 px-3 text-sm text-accent no-underline">Sign in</a>
          {@render themeButton()}
        {:else}
          <span class="ml-auto">{@render themeButton()}</span>
        {/if}
      </div>
    </header>

    <!-- As in fjord: top-right, in a gutter main keeps free (md:pr-8), so
         no page's own top-right button can end up under it. -->
    <main class="relative flex-1 {withNav ? 'md:pr-8' : ''}">
      {#if withNav}
        <span class="hidden md:block absolute top-4 right-4 z-30">{@render themeButton()}</span>
      {/if}
      {#if screen === 'loading'}
        <div class="min-h-[60vh] grid place-items-center text-muted text-sm">Loading…</div>
      {:else if screen === 'setup'}
        <Setup />
      {:else if screen === 'login'}
        <Login />
      {:else if screen === 'hosts'}
        <Hosts />
      {:else if screen === 'host-new'}
        <HostForm id="" />
      {:else if screen === 'host-edit'}
        <HostForm id={hostId} />
      {:else if screen === 'settings'}
        <Settings />
      {:else if screen === 'trust'}
        <Trust />
      {:else if screen === 'link'}
        <!-- Someone opened the pairing link in a browser instead of pasting it
             into fjord: say where it goes. -->
        <div class="max-w-[640px] mx-auto box-border px-4 py-12 flex flex-col gap-4">
          <h1 class="m-0 text-2xl font-bold text-fg leading-tight">This link is for fjord</h1>
          <p class="m-0 text-sm leading-snug">Paste it into the other fjord under Settings, Names, in the Reverse proxy box. It lets that fjord give its apps names here. It works for ten minutes, once.</p>
          <code class="font-mono break-all select-all text-sm bg-inset text-fg rounded p-3">{location.href}</code>
        </div>
      {/if}
    </main>
  </div>
</div>

<Toasts />
