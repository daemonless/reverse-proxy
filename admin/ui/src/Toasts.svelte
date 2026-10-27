<script lang="ts">
  import { toasts, dismiss } from './lib/toast.svelte'
</script>

<div class="fixed inset-x-0 bottom-6 flex flex-col items-center gap-2 pointer-events-none px-4" aria-live="polite">
  {#each toasts.items as t (t.id)}
    <!-- fjord's toast: a pill on a card, the action in the accent. -->
    <div class="pointer-events-auto flex items-center gap-3 max-w-lg rounded-full pl-4 pr-2 py-1.5 shadow-2xl border border-[color:var(--border)] bg-card text-fg text-sm" role="status">
      <span class="max-w-md line-clamp-2" title={t.text}>{t.text}</span>
      {#if t.action}
        <button type="button" class="shrink-0 px-2.5 py-1 rounded-full text-sm font-medium text-accent hover:bg-chip cursor-pointer"
          onclick={() => { t.action?.run(); dismiss(t.id) }}>{t.action.label}</button>
      {/if}
      <button type="button" class="shrink-0 w-8 h-8 grid place-items-center rounded-full text-muted hover:text-fg hover:bg-chip cursor-pointer" aria-label="Dismiss"
        onclick={() => dismiss(t.id)}>×</button>
    </div>
  {/each}
</div>
