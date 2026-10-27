<script lang="ts">
  import { get, type DnsCheck, type Settings } from '../lib/api'
  import { resolvers, guides, type Resolver } from '../lib/dnsGuides'
  import { toast } from '../lib/toast.svelte'
  import { copyText } from '../lib/copy'
  import ShortLinkGuide from './ShortLinkGuide.svelte'

  // One component for setup and Settings: the record, the router guide,
  // and a check that keeps looking until the record works.
  let { domain, onok }: { domain: string; onok?: () => void } = $props()

  // The proxy's address: the browser's hostname when that is an IP, else
  // what the proxy's own name resolves to (the UI was opened by name).
  const isIP = (h: string) => /^[0-9.]+$/.test(h) || h.includes(':')
  let resolver = $state<Resolver>('opnsense')
  let dns = $state<DnsCheck | null>(null)
  let checking = $state(false)
  let tries = $state(0)
  const ip = $derived(isIP(location.hostname) ? location.hostname : (dns?.proxyAddresses?.[0] ?? ''))
  const ok = $derived(!!dns && dns.addresses.length > 0 && (ip === '' || dns.addresses.includes(ip)))
  const guide = $derived(guides[resolver])
  const waiting = $derived(!!dns && (dns.notFound || dns.addresses.length === 0))
  const fill = (s: string) => s.replaceAll('{DOMAIN}', domain).replaceAll('{IP}', ip || 'the proxy\'s IP address')

  async function check() {
    checking = true
    try { dns = await get<DnsCheck>('/api/v1/dns-check'); tries += 1 } catch { dns = null }
    finally { checking = false }
    if (ok) onok?.()
  }
  check()
  // Records take a moment to apply; keep looking so the person never has
  // to press a button to find out.
  const timer = setInterval(() => { if (!ok) check() }, 5000)
  $effect(() => () => clearInterval(timer))

  // Short links (go/radarr): one more record, for the word alone. The
  // proxy cannot look it up the way a device does (the router's local
  // domain), so the check is the person opening it.
  let short = $state('')
  get<Settings>('/api/v1/settings').then((s) => { short = s.shortLinks ?? '' }).catch(() => {})

  async function copy(text: string, what = '') {
    toast((await copyText(text)) ? (what ? `Copied ${what.toLowerCase()}: ${text}` : 'Copied') : 'Select the text and copy it by hand')
  }
</script>

<div class="flex flex-col gap-5">
  {#if !guide.complete}
  <div class="rounded-xl bg-inset border border-[color:var(--border)] p-5 flex flex-col gap-3">
    <div class="hint">The record, piece by piece. Click a piece to copy it.</div>
    <div class="flex items-stretch gap-2 flex-wrap">
      {#each [['Host', '*'], ['Domain', domain], ['Address', ip || '…']] as [label, value]}
        <button type="button" class="flex flex-col items-start gap-0.5 rounded-lg border border-[color:var(--border)] bg-card px-4 py-2.5 text-left cursor-pointer hover:border-accent min-h-14" onclick={() => copy(value, label)}>
          <span class="text-[12px] uppercase tracking-wide text-muted">{label}</span>
          <span class="font-mono text-base break-all">{value}</span>
        </button>
      {/each}
      <button type="button" class="flex flex-col items-start gap-0.5 rounded-lg border border-dashed border-[color:var(--border)] bg-card px-4 py-2.5 text-left cursor-pointer hover:border-accent min-h-14" onclick={() => copy(`*.${domain}`, 'Full name')}>
        <span class="text-[12px] uppercase tracking-wide text-muted">Full name (AdGuard, UniFi)</span>
        <span class="font-mono text-base break-all">*.{domain}</span>
      </button>
    </div>
  </div>
  {/if}

  <div class="flex flex-col gap-3">
    <div class="text-sm">Where do your devices get DNS?</div>

    <div class="flex gap-2 flex-wrap" role="tablist" aria-label="Resolver">
      {#each resolvers as r (r.id)}
        <button type="button" role="tab" aria-selected={resolver === r.id} onclick={() => (resolver = r.id)}
          class="min-h-10 px-4 rounded-lg text-sm cursor-pointer border {resolver === r.id ? 'bg-accent text-white border-accent font-semibold' : 'bg-card text-fg border-[color:var(--border)] hover:bg-chip'}">{r.label}</button>
      {/each}
    </div>
    <div class="card p-6 flex flex-col gap-4">
      {#if guide.intro}<p class="m-0 text-sm leading-snug text-muted">{guide.intro}</p>{/if}
      <ol class="m-0 p-0 list-none flex flex-col gap-3">
        {#each guide.steps as step, i}
          <li class="flex gap-3.5 items-start">
            <span class="shrink-0 w-8 h-8 rounded-full bg-accent-soft text-accent-soft-fg font-semibold grid place-items-center">{i + 1}</span>
            {#if typeof step === 'string'}
              <span class="text-sm leading-snug pt-1">{fill(step)}</span>
            {:else}
              <div class="flex flex-col gap-2 pt-1 min-w-0 flex-1">
                <span class="text-sm leading-snug">{fill(step.text)}</span>
                <div class="rounded-lg border border-[color:var(--border)] divide-y divide-[color:var(--border)] overflow-hidden">
                  {#each step.fields as [label, value] (label)}
                    <button type="button" class="w-full flex items-center gap-3 px-3 min-h-10 text-left bg-card hover:bg-chip cursor-pointer" onclick={() => copy(fill(value), label)} title="Copy">
                      <span class="w-28 shrink-0 text-sm text-muted">{label}</span>
                      <span class="font-mono text-sm break-all flex-1">{fill(value)}</span>
                      <span class="text-xs text-accent shrink-0">Copy</span>
                    </button>
                  {/each}
                </div>
              </div>
            {/if}
          </li>
        {/each}
      </ol>
      {#if guide.paste}
        {@const text = guide.paste(domain, ip)}
        <div class="flex flex-col gap-2">
          <div class="flex items-center justify-between gap-3"><span class="hint">{guide.pasteLabel}</span><button type="button" class="btn-soft min-h-10 px-3 text-sm" onclick={() => copy(text)}>Copy</button></div>
          <pre class="m-0 rounded-lg bg-[#1d1d1f] text-[#f4f4f2] p-4 font-mono text-[14px] leading-relaxed overflow-x-auto">{text}</pre>
        </div>
      {/if}
      {#if guide.note}<div class="rounded-lg p-4 bg-accent-soft text-accent-soft-fg text-sm leading-snug">{guide.note}</div>{/if}
    </div>
  </div>
  <div role="status" class="flex items-center gap-3 rounded-xl px-5 py-4 text-sm {ok ? 'bg-success-soft text-success-soft-fg' : waiting || dns === null ? 'bg-accent-soft text-accent-soft-fg' : 'bg-warning-soft text-warning-soft-fg'}">
    <span class="w-3 h-3 rounded-full shrink-0 box-border {ok ? 'bg-success' : waiting || dns === null ? 'border-[3px] border-accent border-t-transparent animate-spin' : 'border-[3px] border-warning'}"></span>
    <span class="flex-1">
    {#if ok}
      <span>Names under <strong>{domain}</strong> reach this proxy. You're set.</span>
    {:else if dns === null && checking}
      <span>Checking…</span>
    {:else if dns?.notFound || (dns && dns.addresses.length === 0)}
      <span>Waiting for the record. Once it's saved, this turns green by itself within a few seconds.</span>
    {:else if dns}
      <span>Names under {domain} resolve to {dns.addresses.join(', ')}, not {ip || 'this proxy'}. If another proxy or an old record uses that ending, change the record to point here, or pick a different ending.</span>
    {:else}
      <span>Couldn't check right now; it will try again shortly.</span>
    {/if}
    </span>
    {#if !ok}
      <button type="button" class="btn-soft min-h-10 px-4 text-sm shrink-0" onclick={check} disabled={checking}>{checking ? 'Checking…' : 'Check again'}</button>
    {/if}
  </div>

  {#if short}
    <div class="rounded-xl bg-inset border border-[color:var(--border)] p-5 flex flex-col gap-3">
      <div class="text-sm"><strong>Short links</strong> <span class="hint">(optional)</span>: type <span class="font-mono">{short}/radarr</span> to open radarr.{domain}. Add one more name to your router, the same place as above:</div>
      <ShortLinkGuide {short} {ip} bind:resolver tabs={false} />
    </div>
  {/if}

</div>
