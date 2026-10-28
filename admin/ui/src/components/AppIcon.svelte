<script lang="ts">
  import type { Host } from '../lib/api'

  // The app's icon when the app that made the name sent one (fjord does),
  // else its first letter: every name gets a tile, so cards line up.
  let { host, size = 40 }: { host: Host; size?: number } = $props()
  let broken = $state(false)
  const letter = $derived((host.name || host.names[0] || '?').charAt(0).toUpperCase())
  // A steady colour per name, soft enough for either theme.
  const hue = $derived([...host.name].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 360, 7))
</script>

{#if host.icon && !broken}
  <!-- On a light tile in both themes: most app icons are drawn for one. -->
  <span class="shrink-0 grid place-items-center rounded-xl bg-white border border-[color:var(--border)] box-border" style="width:{size}px;height:{size}px;padding:{Math.round(size / 8)}px">
    <img src="/api/v1/hosts/{host.id}/icon?v={host.icon}" alt="" class="w-full h-full object-contain" onerror={() => (broken = true)} />
  </span>
{:else}
  <span class="shrink-0 grid place-items-center rounded-xl font-bold select-none" aria-hidden="true"
    style="width:{size}px;height:{size}px;font-size:{Math.round(size * 0.45)}px;background:oklch(0.88 0.06 {hue});color:oklch(0.35 0.08 {hue})">{letter}</span>
{/if}
