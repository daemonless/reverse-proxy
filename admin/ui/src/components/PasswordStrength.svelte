<script lang="ts">
  import { strength } from '../lib/password'

  // The meter under a new-password field: four bars, a word, and why.
  let { password }: { password: string } = $props()
  const st = $derived(strength(password))
  const color = $derived(['', 'bg-danger', 'bg-warning', 'bg-success', 'bg-success'][st.level])
</script>

{#if st.level}
  <div class="mt-2 flex flex-col gap-1" aria-live="polite">
    <div class="flex items-center gap-3">
      <div class="flex gap-1 flex-1 max-w-48" aria-hidden="true">
        {#each [1, 2, 3, 4] as i (i)}<span class="h-1.5 flex-1 rounded-full {i <= st.level ? color : 'bg-chip'}"></span>{/each}
      </div>
      <span class="text-xs font-semibold {st.level === 1 ? 'text-danger' : st.level === 2 ? 'text-warning-soft-fg' : 'text-success-soft-fg'}">{st.label}</span>
    </div>
    {#if st.why}<span class="hint">{st.why}</span>{/if}
  </div>
{/if}
