<script lang="ts">
  import { get, type TrustInfo, type DnsCheck, type Certificates, type CertStatus } from '../lib/api'
  import { devices, guides, detectDevice, detectDistro, type Device, type Distro } from '../lib/trustSteps'
  import { toast } from '../lib/toast.svelte'
  import { whoAnswers } from '../lib/trust.svelte'
  import { copyText } from '../lib/copy'
  import { link } from '../lib/router.svelte'

  let info = $state<TrustInfo | null>(null)
  let device = $state<Device>(detectDevice())
  // The QR is for setting up a phone from a computer; on a phone it is noise.
  const onPhone = detectDevice() === 'iphone' || detectDevice() === 'android'
  let distro = $state<Distro>(detectDistro())
  let reach = $state<'unknown' | 'no-dns' | 'untrusted' | 'trusted' | 'elsewhere'>('unknown')
  // Opened by IP: secure only by name, whatever this device trusts.
  const onAddress = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$/i.test(location.hostname)
  // The admin's port: this page's when it is the admin, else the default.

  let showRemove = $state(false)

  // The trust page is reached on the proxy's IP or its name; that is the
  // address the commands and the QR code must use too.
  const here = location.hostname
  const base = $derived(`http://${here}${info && info.httpPort !== 80 ? ':' + info.httpPort : ''}/trust`)
  const guide = $derived(guides[device])
  // FILE: one certificate file per ending, as the download is named.
  const fill = (t: string) => info ? t.replaceAll('FILE', info.domain.replaceAll('.', '-') + '-proxy-root.crt').replaceAll('DOMAIN', info.domain) : t
  const command = $derived(info?.fingerprint && guide.command ? fill(guide.command(base, info.fingerprint, distro)) : '')
  const qrUrl = $derived(`/trust/qr.png?u=${encodeURIComponent(base)}`)

  // With a real domain, a name that won't open securely is the
  // certificate, not this device.
  let cert = $state<CertStatus | null>(null)
  async function loadCert() { try { cert = (await get<Certificates>('/api/v1/certificates')).status } catch { cert = null } }
  async function load() {
    info = await get<TrustInfo>('/api/v1/trust')
    if (!info.needed) loadCert()
    check()
  }
  load()

  // A fetch over HTTPS to the proxy's own name only succeeds when this
  // device trusts the certificate. When it fails, DNS and trust have to be
  // told apart: on the plain-HTTP trust page a plain-HTTP probe does it;
  // on the HTTPS admin page the browser blocks that (mixed content), so the
  // proxy's own DNS check stands in, since devices normally use the same
  // resolver the proxy does. A name nothing resolves can hang in the
  // resolver for a long time: four seconds is an answer, and the bar must
  // never sit on "Checking" (it did, for as long as the page was open).
  let checking = false
  const probe = (url: string) => whoAnswers(url, info?.instance)
  async function check() {
    if (!info?.proxyName || checking) return
    checking = true
    const name = info.proxyName
    try {
      if (location.protocol === 'http:') {
        // The plain probe goes to a sibling name under the ending (the
        // record is a wildcard): this proxy sends HSTS on its own name, and
        // a browser that has seen it turns the plain probe into HTTPS,
        // which fails on a device that does not trust the root and read as
        // "can't find" when the truth was "doesn't trust".
        const sibling = name.replace(/^[^.]+\./, 'check.')
        const [https, http] = await Promise.all([probe(`https://${name}/trust/check`), probe(`http://${sibling}/trust/check`)])
        reach = https === 'other' || http === 'other' ? 'elsewhere' : https ? 'trusted' : http ? 'untrusted' : 'no-dns'
        return
      }
      const r = await probe(`https://${name}/trust/check`)
      if (r) {
        reach = r === 'ours' ? 'trusted' : 'elsewhere'
        return
      }
      try {
        const d = await get<DnsCheck>('/api/v1/dns-check')
        reach = d.addresses.length > 0 ? 'untrusted' : 'no-dns'
      } catch {
        reach = 'untrusted' // signed out on the HTTPS page: assume DNS is fine
      }
    } finally {
      checking = false
    }
  }
  const timer = setInterval(() => { if (reach !== 'trusted') { check(); if (info && !info.needed) loadCert() } }, 5000)
  $effect(() => () => clearInterval(timer))

  async function copy() {
    toast((await copyText(command)) ? 'Copied' : 'Select the command and copy it by hand')
  }
</script>

<div class="max-w-[960px] box-border px-5 md:px-8 py-6 flex flex-col gap-6">
  <div class="flex flex-col gap-2">
    {#if info && !info.needed}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Is this device ready?</h1>
      <p class="m-0 hint text-base">With your own domain there is nothing to install. Every name under {info.domain} opens securely on any device on your network.</p>
    {:else}
      <h1 class="m-0 text-2xl font-bold text-fg leading-tight">Trust {info?.domain ?? 'this proxy'} on this device</h1>
      <p class="m-0 hint text-base">Do this once and every name under {info?.domain ?? 'your ending'} opens securely, with no warnings.</p>
    {/if}
  </div>

  {#if info && !info.needed}
    {@const pending = cert?.state === 'trial' || cert?.state === 'issuing'}
    <div role="status" class="flex items-center gap-3 flex-wrap rounded-xl px-5 py-4 text-sm {reach === 'trusted' ? 'bg-success-soft text-success-soft-fg' : reach === 'unknown' ? 'bg-accent-soft text-accent-soft-fg' : 'bg-warning-soft text-warning-soft-fg'}">
      <span class="w-3 h-3 rounded-full shrink-0 box-border {reach === 'trusted' ? 'bg-success' : reach === 'unknown' ? 'border-[3px] border-accent animate-pulse' : 'border-[3px] border-warning'}"></span>
      {#if reach === 'trusted'}
        <span class="flex-1 basis-64">This device opens <strong>{info.proxyName}</strong> securely. You're done here.{#if onAddress}
          <span class="block text-sm mt-0.5">This page is open by address, which always says "Not secure". Names like <strong>{info.proxyName}</strong> are the secure ones.</span>{/if}</span>
        <a href="https://{info.proxyName}/" class="btn-primary shrink-0">Open {info.proxyName}</a>
      {:else if reach === 'elsewhere'}
        <span class="flex-1 basis-64">On this device, <strong>{info.proxyName}</strong> leads to a different proxy, not this one. Point the DNS record for {info.domain} at this proxy, or turn the other one off.</span>
        <a href="/settings#dns" use:link class="btn-primary shrink-0 ml-auto">Check the DNS record</a>
      {:else if reach === 'no-dns'}
        <span class="flex-1 basis-64">Nothing on your network answers for <strong>{info.proxyName}</strong> yet. Add the DNS record first, then come back; this page checks again by itself.</span>
        <a href="/settings#dns" use:link class="btn-primary shrink-0 ml-auto">Add the DNS record</a>
      {:else if reach === 'untrusted' && pending}
        <span>The certificate for {info.domain} is still on its way from Let's Encrypt. Names open with a warning until it arrives, usually within a few minutes. This page checks again by itself.</span>
      {:else if reach === 'untrusted' && cert?.state === 'failed'}
        <span class="flex-1 basis-64">The certificate for {info.domain} didn't come through: {cert.message}</span>
        <a href="/settings" use:link class="btn-primary shrink-0 ml-auto">Open certificates</a>
      {:else if reach === 'untrusted'}
        <span>This device can't open <strong>{info.proxyName}</strong> securely yet. This page checks again by itself.</span>
      {:else}
        <span>Checking this device…</span>
      {/if}
    </div>
    <div class="card p-6 flex flex-col gap-3 text-sm leading-snug">
      <h2 class="m-0 text-lg">Why there is nothing to install</h2>
      <p class="m-0">The certificates for {info.domain} come from Let's Encrypt, which phones, computers and TVs already trust. They renew by themselves.</p>
      <p class="m-0">A device only needs to be on your home network, so that <strong>{info.proxyName}</strong> and the other names lead to this proxy.</p>
    </div>
  {:else if info && !info.fingerprint}
    <div class="card p-6 text-sm">Finish setup first; the certificate is created with your address.</div>
  {:else if info}
    <!-- Wraps: on a phone the button goes under the text instead of
         squeezing it into a column of twelve short lines. -->
    <div role="status" class="flex items-center gap-3 flex-wrap rounded-xl px-5 py-4 text-sm {reach === 'trusted' ? 'bg-success-soft text-success-soft-fg' : 'bg-warning-soft text-warning-soft-fg'}">
      <span class="w-3 h-3 rounded-full shrink-0 box-border {reach === 'trusted' ? 'bg-success' : 'border-[3px] border-warning'}"></span>
      {#if reach === 'trusted'}
        <span class="flex-1">This device trusts the proxy. You're done here.{#if onAddress}
          <span class="block text-sm mt-0.5">This page is open by address, which always says "Not secure". Names like <strong>{info.proxyName}</strong> are the secure ones.</span>{/if}</span>
        <a href="https://{info.proxyName}/" class="btn-primary shrink-0">Open {info.proxyName}</a>
      {:else if reach === 'untrusted'}
        <span>This device doesn't trust the proxy yet. This page checks again by itself as you go.</span>
      {:else if reach === 'elsewhere'}
        <span class="flex-1 basis-64">On this device, <strong>{info.proxyName}</strong> leads to a different proxy, not this one. Point the DNS record for {info.domain} at this proxy, or turn the other one off.</span>
        <a href="/settings#dns" use:link class="btn-primary shrink-0 ml-auto">Check the DNS record</a>
      {:else if reach === 'no-dns'}
        <span class="flex-1 basis-64">Nothing on your network answers for <strong>{info.proxyName}</strong> yet. Add the DNS record first, then come back; this page checks again by itself.</span>
        <a href="/settings#dns" use:link class="btn-primary shrink-0 ml-auto">Add the DNS record</a>
      {:else}
        <span>Checking whether this device trusts the proxy…</span>
      {/if}
    </div>

    <div class="flex gap-2 flex-wrap" role="tablist" aria-label="Device">
      {#each devices as d (d.id)}
        <button type="button" role="tab" aria-selected={device === d.id} onclick={() => (device = d.id)}
          class="min-h-10 px-5 rounded-lg text-sm cursor-pointer border {device === d.id ? 'bg-accent text-white border-accent font-semibold' : 'bg-card text-fg border-[color:var(--border)] hover:bg-chip'}">{d.label}</button>
      {/each}
    </div>

    <div class="flex gap-6 flex-wrap items-start">
      <div class="flex-[999] basis-[480px] min-w-0 flex flex-col gap-6">
        <div class="card p-7 flex flex-col gap-5">
          <!-- "A few clicks" only where the steps are clicks: Linux and
               FreeBSD download and then open a terminal. -->
          <div class="font-semibold text-lg">{device === 'windows' || device === 'mac' ? 'With a few clicks' : 'Steps'}</div>
          <ol class="m-0 p-0 list-none flex flex-col gap-4">
            {#each guide.clicks as step, i}
              <li class="flex gap-3.5 items-start">
                <span class="shrink-0 w-8 h-8 rounded-full bg-accent-soft text-accent-soft-fg font-semibold grid place-items-center">{i + 1}</span>
                <span class="text-sm leading-snug pt-1">{step}</span>
              </li>
            {/each}
          </ol>
          {#if guide.note}<div class="rounded-lg p-4 bg-warning-soft text-warning-soft-fg text-sm leading-snug">{guide.note}</div>{/if}
          <a href={info.rootUrl} class="btn-primary self-start" download>Download certificate</a>
        </div>

        {#if guide.command}
          <div class="card p-7 flex flex-col gap-4">
            <div class="flex items-center justify-between gap-3 flex-wrap">
              <div class="font-semibold text-lg">Or paste one command</div>
              <button type="button" class="btn-soft min-h-10 px-4 text-sm" onclick={copy}>Copy</button>
            </div>
            <div class="hint flex items-center gap-3 flex-wrap">
              <span>{guide.where}.</span>
              {#if device === 'linux'}
                <label class="flex items-center gap-2">Distribution
                  <select bind:value={distro} class="input w-auto h-10 text-sm px-2">
                    <option value="debian">Debian / Ubuntu / Mint</option>
                    <option value="fedora">Fedora / RHEL / openSUSE</option>
                    <option value="arch">Arch</option>
                  </select>
                </label>
              {/if}
            </div>
            <div class="rounded-lg bg-[#1d1d1f] p-4">
              <pre class="m-0 font-mono text-[13px] leading-relaxed text-[#f4f4f2] whitespace-pre-wrap [overflow-wrap:anywhere]">{command}</pre>
            </div>
            <div class="hint">It checks the fingerprint and installs nothing if it doesn't match.</div>
          </div>
        {/if}

        {#if guide.browsers}
          <div class="card p-6 flex flex-col gap-2">
            <div class="font-semibold text-sm">Some browsers keep their own list</div>
            <div class="text-sm leading-snug text-muted">{fill(guide.browsers)}</div>
          </div>
        {/if}
      </div>

      <div class="flex-1 basis-[260px] min-w-0 flex flex-col gap-6">
        {#if !onPhone}
          <div class="card p-6 flex flex-col items-center text-center gap-3">
            <div class="font-semibold text-base">Set up a phone</div>
            <img src={qrUrl} alt="QR code for {base}" width="180" height="180" class="rounded-lg" />
            <div class="hint">Point the phone's camera here while it's on your home Wi-Fi.</div>
          </div>
        {/if}
        <div class="card p-6 flex flex-col gap-2">
          <div class="font-semibold text-sm">Check it's the right certificate</div>
          <div class="font-mono text-[13px] leading-relaxed break-all text-muted select-all">{info.fingerprint}</div>
          <div class="hint">Your device shows this when you install it. The command checks it for you.</div>
        </div>
        <button type="button" class="self-start text-accent text-sm min-h-10 cursor-pointer bg-transparent border-0 p-0 hover:underline" onclick={() => (showRemove = !showRemove)}>{showRemove ? 'Hide' : 'Stop trusting this proxy…'}</button>
        {#if showRemove}
          <div class="card p-6 flex flex-col gap-2">
            <div class="font-semibold text-sm">To remove it later</div>
            <ol class="m-0 pl-5 flex flex-col gap-1.5 text-sm leading-snug">
              {#each guide.remove as step}<li>{fill(step)}</li>{/each}
            </ol>
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>
