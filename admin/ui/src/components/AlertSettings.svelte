<script lang="ts">
  import { get, put, post, ApiError, type Alerts } from '../lib/api'
  import { toast } from '../lib/toast.svelte'
  import { focus } from '../lib/focus'

  // Where a message goes when a name stops responding, and when it's back.
  // The address is never shown again once saved (an ntfy topic is as good
  // as a password): the row names the server it goes to.
  let alerts = $state<Alerts | null>(null)
  let edit = $state(false)
  let kind = $state<'ntfy' | 'webhook'>('ntfy')
  let url = $state('')
  let error = $state('')
  let busy = $state(false)
  async function load() { try { alerts = await get<Alerts>('/api/v1/alerts') } catch { alerts = null } }
  load()

  function open() { edit = true; kind = alerts?.kind || 'ntfy'; url = ''; error = '' }
  async function save(e: SubmitEvent) {
    e.preventDefault(); busy = true; error = ''
    try { alerts = await put<Alerts>('/api/v1/alerts', { kind, url }); edit = false; toast('Saved. Send a test to see it arrive.') }
    catch (err) { error = err instanceof ApiError ? err.message : 'Something went wrong' }
    finally { busy = false }
  }
  async function test() {
    busy = true; error = ''
    try { await post('/api/v1/alerts/test', edit && url ? { kind, url } : {}); toast('Test sent') }
    catch (err) { error = err instanceof ApiError ? err.message : 'Something went wrong' }
    finally { busy = false }
  }
  // Every name's checks, and so every alert, on or off. History is kept.
  async function setEnabled(on: boolean) {
    busy = true; error = ''
    try { alerts = await put<Alerts>('/api/v1/uptime/enabled', { enabled: on }); toast(on ? 'Checking every name again' : 'Checks are off') }
    catch (err) { error = err instanceof ApiError ? err.message : 'Something went wrong' }
    finally { busy = false }
  }
  async function off() {
    busy = true
    try { alerts = await put<Alerts>('/api/v1/alerts', { kind: '', url: '' }); toast('Alerts are off') } finally { busy = false }
  }
</script>

<section class="flex flex-col gap-2.5">
  <h3 class="m-0 text-sm text-muted font-semibold">Uptime and alerts</h3>
  <div class="card overflow-hidden">
  <div class="px-6 py-4.5 flex items-center justify-between gap-4 flex-wrap {alerts?.enabled ? 'border-b border-[color:var(--border)]' : ''}">
    <span class="flex flex-col flex-1 basis-64 min-w-0">
      <span class="text-sm">{alerts?.enabled === false ? 'Off. Names are not checked, and no alerts are sent.' : 'Every name is checked once a minute.'}</span>
      <span class="hint">{alerts?.enabled === false ? 'Their history is kept for when you turn it on again.' : "Down means two checks in a row got no answer. A name's own page can turn it off for that name."}</span>
    </span>
    {#if alerts}<button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" disabled={busy} onclick={() => setEnabled(!alerts!.enabled)}>{alerts.enabled ? 'Turn off' : 'Turn on'}</button>{/if}
  </div>
  {#if alerts?.enabled}
  <div class="px-6 py-5 flex flex-col gap-4">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <span class="flex flex-col flex-1 basis-64 min-w-0">
        {#if alerts?.kind}
          <span class="text-sm">When a name stops responding, and again when it's back, a message goes to <strong class="break-words">{alerts.kind === 'ntfy' ? 'ntfy' : 'your webhook'} at {alerts.to}</strong>.</span>
        {:else}
          <span class="text-sm">Off. Get a message on your phone when a name stops responding, and again when it's back.</span>
        {/if}
      </span>
      {#if !edit}
        <span class="flex gap-2 flex-wrap">
          {#if alerts?.kind}
            <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" disabled={busy} onclick={test}>Send a test</button>
            <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={open}>Change</button>
            <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" disabled={busy} onclick={off}>Stop alerts</button>
          {:else}
            <button type="button" class="btn-plain min-h-10 px-3 text-sm text-accent" onclick={open}>Set up</button>
          {/if}
        </span>
      {/if}
    </div>
    {#if alerts?.lastError && !edit}
      <div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug break-words">The last alert was not delivered: {alerts.lastError}</div>
    {/if}
    {#if edit}
      <form onsubmit={save} class="flex flex-col gap-3">
        <span class="inline-flex self-start rounded-lg bg-chip p-0.5" role="group" aria-label="Send to">
          {#each [['ntfy', 'ntfy'], ['webhook', 'Webhook']] as [k, label] (k)}
            <button type="button" class="min-h-9 px-3.5 rounded-md border-0 cursor-pointer text-sm {kind === k ? 'bg-card text-fg shadow-sm' : 'bg-transparent text-muted hover:text-fg'}" aria-pressed={kind === k} onclick={() => (kind = k as 'ntfy' | 'webhook')}>{label}</button>
          {/each}
        </span>
        <input class="input font-mono" bind:value={url} use:focus autocomplete="off" spellcheck="false" required aria-label={kind === 'ntfy' ? 'ntfy topic address' : 'Webhook address'}
          placeholder={kind === 'ntfy' ? 'https://ntfy.sh/a-topic-only-you-know' : 'https://hooks.example.com/proxy'} />
        <div class="hint">{#if kind === 'ntfy'}The topic's address, on ntfy.sh or your own ntfy server. Pick a topic nobody would guess: anyone who knows it can read the messages.{:else}Gets a POST with JSON: name, state (down or up), target, since, message.{/if}</div>
        {#if error}<div class="field-error">{error}</div>{/if}
        <div class="flex justify-end gap-2 flex-wrap">
          <button type="button" class="btn-plain min-h-10 px-3" onclick={() => (edit = false)}>Cancel</button>
          <button type="button" class="btn-soft min-h-10 px-4" disabled={busy || !url} onclick={test}>Send a test</button>
          <button class="btn-primary" disabled={busy || !url}>Save</button>
        </div>
      </form>
    {:else if error}
      <div class="field-error">{error}</div>
    {/if}
  </div>
  {:else if error}
    <div class="px-6 pb-4 field-error">{error}</div>
  {/if}
  </div>
</section>
