<script lang="ts">
  import { focus } from '../lib/focus'
  import { post, ApiError } from '../lib/api'
  import { session } from '../lib/session.svelte'
  import { navigate, route } from '../lib/router.svelte'

  let password = $state('')
  let error = $state('')
  let busy = $state(false)
  let wait = $state(0)
  let timer: number | undefined

  function countdown(secs: number) {
    wait = secs
    window.clearInterval(timer)
    timer = window.setInterval(() => { wait -= 1; if (wait <= 0) { window.clearInterval(timer); error = '' } }, 1000)
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault(); error = ''; busy = true
    try {
      await post('/api/v1/login', { password })
      await session.refresh()
      // Signed in where the person was heading (Settings#dns from the trust
      // page, a host link); only a bare visit lands on Hosts.
      if (route.path === '/' || route.path === '/login') navigate('/hosts', true)
    } catch (err) {
      if (err instanceof ApiError) { error = err.message; if (err.retryAfter) countdown(err.retryAfter) }
      else error = 'Something went wrong'
    } finally { busy = false }
  }
</script>

<div class="box-border px-4 py-16 flex flex-col items-center gap-6">
  <div class="card w-full max-w-[420px] box-border p-8 flex flex-col gap-5">
    <form onsubmit={submit} class="contents">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-accent/15 border border-accent/30 flex items-center justify-center text-accent">
          <svg width="22" height="22" viewBox="0 0 512 512" aria-hidden="true"><path d="M256,24 C352,24 456,58 456,128 C456,300 362,432 256,500 C150,432 56,300 56,128 C56,58 160,24 256,24 Z" fill="currentColor"/><path d="M256,86 L302,172 L274,172 L274,334 L326,306 L326,230 L308,230 C328,180 376,150 376,220 L376,328 C340,366 296,386 274,394 L274,452 L238,452 L238,394 C216,386 172,366 136,328 L136,220 C136,150 184,180 204,230 L186,230 L186,306 L238,334 L238,172 L210,172 Z" fill="var(--card)" transform="translate(256 256) scale(0.98) translate(-256 -262)"/></svg>
        </div>
        <div>
          <h1 class="m-0 text-base font-bold text-fg">Sign in to the reverse proxy</h1>
          <p class="m-0 text-sm text-dim">{location.host}</p>
        </div>
      </div>
      <div>
        <label for="password" class="label">Password</label>
        <input id="password" type="password" class="input" bind:value={password} autocomplete="current-password" required use:focus />
        {#if error}<div class="field-error">{wait > 0 ? `Too many attempts. Try again in ${wait} seconds.` : error}</div>{/if}
      </div>
      <div class="flex items-center justify-between gap-4 flex-wrap">
        <details class="hint">
          <summary class="cursor-pointer min-h-10 flex items-center">Forgot it?</summary>
          <p class="mt-2">On the machine running the proxy, run <code class="font-mono">podman exec reverse-proxy reverse-proxy reset-password</code>. It prints a new setup token.</p>
        </details>
        <button class="btn-primary" disabled={busy || wait > 0}>Sign in</button>
      </div>
    </form>
  </div>
</div>
