<script lang="ts">
  // The proxy's networks as boxes: switched-on ones can open it and count as
  // home. The one this page came in on stays on (turning it off it would cut
  // the page off). Setup and Settings both use it; the parent saves.
  import type { Network } from '../lib/api'
  import Switch from './Switch.svelte'

  let { networks, here, chosen, ontoggle, disabled = false }: {
    networks: Network[]; here: string; chosen: string[]; ontoggle: (network: string, on: boolean) => void; disabled?: boolean
  } = $props()

  const shut = $derived(networks.map((n) => n.network).filter((n) => !chosen.includes(n)))
</script>

<script lang="ts" module>
  // 192.168.86.0/24 reads as an address; 192.168.86.x reads as a network.
  export function netName(n: string) { const [ip, bits] = n.split('/'); return bits === '24' ? ip.replace(/\.0$/, '.x') : n }
</script>

<div class="flex flex-col divide-y divide-[color:var(--border)] rounded-md border border-[color:var(--border)]">
{#each networks as n (n.network)}
  {@const mine = n.network === here}
  <div class="flex items-center justify-between gap-4 px-4 py-3">
    <span class="flex flex-col gap-0.5 min-w-0"><span class="text-sm font-semibold font-mono text-fg">{netName(n.network)}</span>
      <span class="hint">The proxy is <span class="font-mono">{n.address}</span> here{#if mine}. You're on this network, so it stays on.{/if}</span></span>
    <Switch checked={chosen.includes(n.network)} disabled={mine || !here || disabled} label="Devices on {netName(n.network)} count as home" onchange={(on) => ontoggle(n.network, on)} />
  </div>
{/each}
</div>
{#if !here}<div class="hint">Open this page from one of these networks to change this.</div>{/if}
{#if shut.length}
  <div class="hint">Devices on <span class="font-mono">{shut.map(netName).join(', ')}</span> cannot open the proxy and are never home. It still reaches your apps there.</div>
{/if}
