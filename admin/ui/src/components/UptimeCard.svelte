<script lang="ts">
  import { get, type UptimeDetail, type Alerts } from '../lib/api'
  import { link } from '../lib/router.svelte'
  import { daySlots, pct, lasted, when, covers } from '../lib/uptime'
  import UptimeBars from './UptimeBars.svelte'

  // One name's history: 90 days of bars, the percentages, the outages.
  // watch is the form's: saved with the rest of the name.
  let { id, address, port, watch = $bindable(true) }: { id: string; address: string; port: number; watch?: boolean } = $props()
  let u = $state<UptimeDetail | null>(null)
  // Off for every name in Settings: said here, the switch stays this name's.
  let allOff = $state(false)
  async function load() { try { u = await get<UptimeDetail>(`/api/v1/hosts/${id}/uptime`) } catch { u = null } }
  load()
  get<Alerts>('/api/v1/alerts').then((a) => { allOff = !a.enabled }).catch(() => {})
  const checking = $derived(watch && !allOff)
  const every = setInterval(load, 60000)
  $effect(() => () => clearInterval(every))
  const slots = $derived(u ? daySlots(u.hours, 90) : [])
  const outages = $derived(u ? [...u.outages].reverse().slice(0, 10) : [])
  // A window the history doesn't reach is one tile, "Since …", not three
  // that say the same thing for 24 hours, 7 days and 30 days.
  const tiles = $derived.by(() => {
    if (!u) return []
    const t: [string, string][] = []
    if (!covers(u.from, 1)) t.push([u.from ? `Since ${when(u.from)}` : '24 hours', pct(u.day)])
    else {
      t.push(['24 hours', pct(u.day)])
      t.push([covers(u.from, 7) ? '7 days' : `Since ${when(u.from!)}`, pct(u.week)])
      if (covers(u.from, 7)) t.push([covers(u.from, 30) ? '30 days' : `Since ${when(u.from!)}`, pct(u.month)])
    }
    t.push(['Response', u.avgMs == null ? '—' : u.avgMs < 1 ? 'under 1 ms' : `${u.avgMs} ms`])
    return t
  })
</script>

<div class="card p-7 flex flex-col gap-4">
  <div class="flex items-center justify-between gap-3 flex-wrap">
    <label class="flex items-center gap-3 cursor-pointer">
      <input type="checkbox" bind:checked={watch} class="w-5.5 h-5.5 accent-[color:var(--accent)]" />
      <span class="label mb-0">Check that it's up</span>
    </label>
    {#if !checking}
      <span class="text-sm text-muted">Not checked</span>
    {:else if u?.state === 'up'}
      <span class="flex items-center gap-2 text-sm"><span class="w-3 h-3 rounded-full bg-success"></span>Up{u.since ? ` since ${when(u.since)}` : ''}</span>
    {:else if u?.state === 'down'}
      <span class="flex items-center gap-2 text-sm text-danger"><span class="w-3 h-3 rounded-full box-border border-[3px] border-danger"></span>{u.never ? 'Never reached' : `Down since ${when(u.since ?? '')}`}</span>
    {:else}
      <span class="text-sm text-muted">Checking…</span>
    {/if}
  </div>
  {#if allOff}
    <div class="hint">Checks are off for every name. <a href="/settings#proxy" use:link class="text-accent">Turn them on in Settings</a>.</div>
  {:else if !watch}
    <div class="hint">Not checked once a minute, and no alerts. {u && u.hours.length ? 'Its history is kept.' : ''} Save to apply.</div>
  {/if}
  {#if u && u.hours.length}
    <div class="flex flex-col gap-1.5 {checking ? '' : 'opacity-60'}">
      <UptimeBars {slots} unit="day" height={28} />
      <div class="flex justify-between hint"><span>90 days ago</span><span>Today</span></div>
      {#if checking && u.from && !covers(u.from, 90)}<div class="hint">Watching since {when(u.from)}.</div>{/if}
    </div>
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {#each tiles as [k, v] (k)}
        <div class="rounded-lg bg-inset px-3 py-2.5 flex flex-col"><span class="hint">{k}</span><span class="text-base font-semibold tabular-nums">{v}</span></div>
      {/each}
    </div>
    {#if checking && u.never}
      <div class="hint">The proxy has not reached {address}, port {port} since this name was added. Check the address, and that the proxy's network can reach it. No alert is sent until it has answered once.</div>
    {/if}
    {#if outages.length}
      <div class="flex flex-col">
        <div class="text-sm mb-1">Outages</div>
        {#each outages as o (o.start)}
          <div class="flex justify-between gap-3 py-1.5 text-sm border-b border-[color:var(--border)] last:border-b-0">
            <span>{when(o.start)}</span>
            <span class="tabular-nums {o.end ? 'text-muted' : 'text-danger'}">{o.end ? lasted(new Date(o.end).getTime() - new Date(o.start).getTime()) : 'still down'}</span>
          </div>
        {/each}
      </div>
    {:else if checking && u.state !== 'unknown'}
      <div class="hint">No outages. Checked once a minute: down means two checks in a row got no answer.</div>
    {/if}
  {/if}
</div>
