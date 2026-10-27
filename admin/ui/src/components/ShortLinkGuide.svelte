<script lang="ts">
  import { get, type Settings, type DnsCheck } from '../lib/api'
  import { resolvers, shortGuides, type Resolver } from '../lib/dnsGuides'
  import { toast } from '../lib/toast.svelte'
  import { copyText } from '../lib/copy'

  // The router record for short links (go → this proxy), step by step for
  // the resolver the person runs, with a link to try it. resolver is shared
  // with the names guide when both are on the page.
  let { short, ip, resolver = $bindable('opnsense'), tabs = true }: { short: string; ip: string; resolver?: Resolver; tabs?: boolean } = $props()
  let local = $state('')
  get<Settings>('/api/v1/settings').then((s) => { local = s.localDomain ?? '' }).catch(() => {})
  const guide = $derived(shortGuides[resolver])

  // The same live check as the names record: the proxy looks the word up
  // the way devices do (go.lan) and turns green once it points here.
  let check = $state<DnsCheck['short'] | null>(null)
  let proxyIps = $state<string[]>([])
  async function look() {
    try { const d = await get<DnsCheck>('/api/v1/dns-check'); check = d.short ?? null; proxyIps = d.proxyAddresses ?? [] } catch { check = null }
  }
  const here = $derived(ip ? [ip] : proxyIps)
  // Only a result for this word counts: a green go.lan says nothing about
  // goiii (it did, 2026-10-27).
  const current = $derived(check && check.name.split('.')[0] === short ? check : null)
  const ok = $derived(!!current && current.addresses.length > 0 && (here.length === 0 || current.addresses.some((a) => here.includes(a))))
  // Look again as soon as the word changes, every 5 s until it is right,
  // then every 30 s so a record removed later shows too.
  $effect(() => { void short; check = null; look() })
  let ticks = 0
  const timer = setInterval(() => { ticks++; if (!ok || ticks % 6 === 0) look() }, 5000)
  $effect(() => () => clearInterval(timer))
  const fill = (s: string) => s.replaceAll('{SHORT}', short).replaceAll('{LOCAL}', local || 'lan').replaceAll('{IP}', ip || "the proxy's IP address")

  async function copy(text: string, what: string) {
    toast((await copyText(text)) ? `Copied ${what.toLowerCase()}: ${text}` : 'Select the text and copy it by hand')
  }
</script>

<div class="flex flex-col gap-3">
  {#if tabs}
  <div class="flex gap-2 flex-wrap" role="tablist" aria-label="Resolver">
    {#each resolvers as r (r.id)}
      <button type="button" role="tab" aria-selected={resolver === r.id} onclick={() => (resolver = r.id)}
        class="min-h-9 px-3 rounded-lg text-sm cursor-pointer border {resolver === r.id ? 'bg-accent text-white border-accent font-semibold' : 'bg-card text-fg border-[color:var(--border)] hover:bg-chip'}">{r.label}</button>
    {/each}
  </div>
  {/if}
  <ol class="m-0 p-0 list-none flex flex-col gap-3">
    {#each guide.steps as step, i}
      <li class="flex gap-3 items-start">
        <span class="shrink-0 w-7 h-7 rounded-full bg-accent-soft text-accent-soft-fg text-sm font-semibold grid place-items-center">{i + 1}</span>
        {#if typeof step === 'string'}
          <span class="text-sm leading-snug pt-1">{fill(step)}</span>
        {:else}
          <div class="flex flex-col gap-2 pt-1 min-w-0 flex-1">
            <span class="text-sm leading-snug">{fill(step.text)}</span>
            <div class="rounded-lg border border-[color:var(--border)] divide-y divide-[color:var(--border)] overflow-hidden">
              {#each step.fields as [label, value] (label)}
                <button type="button" class="w-full flex items-center gap-3 px-3 min-h-10 text-left bg-card hover:bg-chip cursor-pointer" onclick={() => copy(fill(value), label)} title="Copy">
                  <span class="w-40 shrink-0 text-sm text-muted">{label}</span>
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
  {#if guide.note}<div class="hint text-sm">{fill(guide.note)}</div>{/if}
  {#if !local}<div class="hint text-sm">lan is a guess: use the domain your router gives your network (in OPNsense, System → Settings → General → Domain).</div>{/if}
  {#if current}
    {@const waiting = current.notFound || current.addresses.length === 0}
    <div role="status" class="flex items-center gap-3 rounded-xl px-5 py-4 text-sm {ok ? 'bg-success-soft text-success-soft-fg' : waiting ? 'bg-accent-soft text-accent-soft-fg' : 'bg-warning-soft text-warning-soft-fg'}">
      <span class="w-3 h-3 rounded-full shrink-0 box-border {ok ? 'bg-success' : waiting ? 'border-[3px] border-accent border-t-transparent animate-spin' : 'border-[3px] border-warning'}"></span>
      <span class="flex-1">
        {#if ok}<strong class="font-mono">{short}</strong> reaches this proxy. Try it: <a href="http://{short}/" target="_blank" rel="noopener" class="font-mono underline">http://{short}/</a>
        {:else if waiting}Waiting for <span class="font-mono">{current.name}</span>. Once it's saved, this turns green by itself within a few seconds.
        {:else}<span class="font-mono">{current.name}</span> points at {current.addresses.join(', ')}, not this proxy{#if here.length}{' '}({here.join(', ')}){/if}. Change the record to point here.{/if}
      </span>
    </div>
  {:else}
    <div role="status" class="flex items-center gap-3 rounded-xl px-5 py-4 text-sm bg-accent-soft text-accent-soft-fg">
      <span class="w-3 h-3 rounded-full shrink-0 box-border border-[3px] border-accent border-t-transparent animate-spin"></span>
      <span class="flex-1">Checking <span class="font-mono">{short}</span>…</span>
    </div>
  {/if}
  <div class="text-sm">{#if !ok}Then try it: <a href="http://{short}/" target="_blank" rel="noopener" class="text-accent font-mono">http://{short}/</a> should open this proxy.{/if} Type the http:// the first time; Safari and Firefox otherwise search the web for it.</div>
</div>
