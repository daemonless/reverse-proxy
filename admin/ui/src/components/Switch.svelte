<script lang="ts">
  // An on/off switch: one control for one yes/no. Same look as fjord's.
  let { checked, disabled = false, label, onchange }: {
    checked: boolean; disabled?: boolean; label: string; onchange: (on: boolean) => void
  } = $props()
</script>

<button
  type="button"
  role="switch"
  aria-checked={checked}
  aria-label={label}
  {disabled}
  onclick={() => onchange(!checked)}
  class="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border cursor-pointer transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--accent)] disabled:opacity-40 disabled:cursor-not-allowed {checked
    ? 'bg-accent border-[color:var(--accent)]'
    : 'bg-inset border-[color:var(--border)]'}"
>
  <span class="inline-block h-[18px] w-[18px] rounded-full bg-white shadow transition-transform {checked ? 'translate-x-[22px]' : 'translate-x-[2px]'}"></span>
</button>
