<script lang="ts">
  // The proxy's networks as boxes: ticked ones can open it and count as
  // home. The one this page came in on stays ticked (unticking it would cut
  // the page off). Setup and Settings both use it; the parent saves.
  import type { Network } from '../lib/api'

  let { networks, here, chosen, ontoggle, disabled = false }: {
    networks: Network[]; here: string; chosen: string[]; ontoggle: (network: string, on: boolean) => void; disabled?: boolean
  } = $props()

  const shut = $derived(networks.map((n) => n.network).filter((n) => !chosen.includes(n)))
</script>

<script lang="ts" module>
  // 192.168.86.0/24 reads as an address; 192.168.86.x reads as a network.
  export function netName(n: string) { const [ip, bits] = n.split('/'); return bits === '24' ? ip.replace(/\.0$/, '.x') : n }
</script>

{#each networks as n (n.network)}
  {@const mine = n.network === here}
  <label class="flex items-start gap-3 min-h-10 {mine || !here || disabled ? 'opacity-80' : 'cursor-pointer'}">
    <input type="checkbox" checked={chosen.includes(n.network)} disabled={mine || !here || disabled} onchange={(e) => ontoggle(n.network, e.currentTarget.checked)} class="w-5.5 h-5.5 mt-0.5 accent-[color:var(--accent)]" />
    <span class="flex flex-col"><span class="text-sm font-mono">{netName(n.network)}</span>
      <span class="hint">The proxy is <span class="font-mono">{n.address}</span> here{#if mine}. You're on this network, so it stays ticked.{/if}</span></span>
  </label>
{/each}
{#if !here}<div class="hint">Open this page from one of these networks to change this.</div>{/if}
{#if shut.length}
  <div class="hint">Devices on <span class="font-mono">{shut.map(netName).join(', ')}</span> cannot open the proxy and are never home. It still reaches your apps there.</div>
{/if}
