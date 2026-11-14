<script lang="ts">
  // One setting: what it is on the left, its control on the right. Rows in
  // a card are split by a line, so each control reads as its own thing.
  import type { Snippet } from 'svelte'
  let { title, children, control }: { title: string; children?: Snippet; control?: Snippet } = $props()
</script>

<div class="flex items-center justify-between gap-4 px-6 py-4">
  <div class="flex flex-col gap-0.5 min-w-0 flex-1">
    <span class="text-sm font-semibold text-fg">{title}</span>
    {#if children}<span class="hint">{@render children()}</span>{/if}
  </div>
  {#if control}<div class="flex items-center gap-2 shrink-0">{@render control()}</div>{/if}
</div>
