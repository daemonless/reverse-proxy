<script lang="ts">
  import type { Slot } from '../lib/uptime'

  // One thin bar per hour or day: green all answered, red none, amber some,
  // grey nothing checked (the proxy was off, or the name is newer).
  let { slots, unit, height = 20 }: { slots: Slot[]; unit: 'hour' | 'day'; height?: number } = $props()

  function color(s: Slot) {
    if (s.checks === 0) return 'var(--border)'
    if (s.up === s.checks) return 'var(--success)'
    if (s.up === 0) return 'var(--danger)'
    return 'var(--warning)'
  }
  function label(s: Slot) {
    const at = unit === 'hour'
      ? s.start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : s.start.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' })
    if (s.checks === 0) return `${at}: not checked`
    if (s.up === s.checks) return `${at}: up`
    return `${at}: down ${s.checks - s.up} of ${s.checks} checks`
  }
</script>

<!-- 90 bars on a phone: 1 px gaps, and bars that shrink to a hairline. -->
<span class="flex w-full overflow-hidden {slots.length > 40 ? 'gap-px' : 'gap-[2px]'}" style="height:{height}px" role="img" aria-label="{slots.filter((s) => s.checks && s.up < s.checks).length} of the last {slots.length} {unit}s had a failed check">
  {#each slots as s (s.start.getTime())}
    <span class="flex-1 min-w-px rounded-[1px]" style="background:{color(s)}" title={label(s)}></span>
  {/each}
</span>
