// Per-device instructions for trusting the root. Every command block
// downloads, checks the fingerprint, and installs only when it matches, so
// a swapped download over plain HTTP installs nothing.
export type Device = 'windows' | 'mac' | 'linux' | 'freebsd' | 'iphone' | 'android'
export type Distro = 'debian' | 'fedora' | 'arch'

export const devices: { id: Device; label: string }[] = [
  { id: 'windows', label: 'Windows' },
  { id: 'mac', label: 'Mac' },
  { id: 'linux', label: 'Linux' },
  { id: 'freebsd', label: 'FreeBSD' },
  { id: 'iphone', label: 'iPhone / iPad' },
  { id: 'android', label: 'Android' },
]

export function detectDevice(ua = navigator.userAgent): Device {
  if (/iPhone|iPad|iPod/.test(ua)) return 'iphone'
  if (/Android/.test(ua)) return 'android'
  if (/Windows/.test(ua)) return 'windows'
  if (/Mac OS X|Macintosh/.test(ua)) return 'mac'
  if (/FreeBSD/.test(ua)) return 'freebsd'
  return 'linux'
}

// Firefox names the distribution (X11; Ubuntu; ...); Chrome does not, so
// Debian stays the default, being the most common.
export function detectDistro(ua = navigator.userAgent): Distro {
  if (/Fedora|Red Hat|CentOS|SUSE/i.test(ua)) return 'fedora'
  if (/Arch|Manjaro/i.test(ua)) return 'arch'
  return 'debian'
}

export type Guide = {
  clicks: string[]          // click-through steps, at most four
  where?: string            // where the command runs
  command?: (base: string, fp: string, distro: Distro) => string
  browsers?: string         // browsers that keep their own trust store
  remove: string[]
  note?: string
}

// `base` is http://<proxy>/trust; `fp` is the colon-separated SHA-256.
// FILE is the certificate's file name, one per ending (apps-lan-proxy-root
// .crt, as the download is named): two proxies on two endings never
// overwrite each other, and a system store keeps both. `dst`, when the
// install copies the file somewhere, is checked first: a different
// certificate already there (an older root of this ending) is said out
// loud before it is replaced.
const shellCheck = (fetchCmd: string, install: string, dst = '') =>
  `if ${fetchCmd}; then
  fp=$(openssl x509 -in FILE -noout -fingerprint -sha256 | cut -d= -f2)
  if [ "$fp" = "FP" ]; then${dst ? `
    if [ -e "${dst}" ] && ! cmp -s FILE "${dst}"; then echo "Replacing an older DOMAIN proxy root at ${dst}."; fi` : ''}
    ${install} && echo "Installed: this device now trusts DOMAIN."
  else
    echo "Fingerprint mismatch: $fp"; echo "Expected:             FP"; echo "Not installed."
  fi
else
  echo "Download failed. If this is the machine running the proxy, it cannot reach its own"
  echo "published ports: run this from another device instead."
fi`

export const guides: Record<Device, Guide> = {
  windows: {
    clicks: [
      'Download the certificate and open it.',
      'Choose Install Certificate, then Local Machine (Windows asks for permission).',
      'Choose "Place all certificates in the following store", Browse, and pick Trusted Root Certification Authorities.',
      'Finish. Windows shows the fingerprint on the way; compare it with the one on this page.',
    ],
    where: 'In PowerShell opened with "Run as administrator"',
    command: (base, fp) => `$f = "$env:TEMP\\FILE.der"
try { Invoke-WebRequest "${base}/root.der" -OutFile $f -TimeoutSec 10 } catch { "Download failed: $_"; return }
$hash = (Get-FileHash $f -Algorithm SHA256).Hash
if ($hash -eq "${fp.replaceAll(':', '')}") { Import-Certificate -FilePath $f -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null; "Installed: this device now trusts DOMAIN." } else { "Fingerprint mismatch: $hash. Not installed." }`,
    browsers: 'Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import the downloaded file and tick "Trust this CA to identify websites". Edge and Chrome use the Windows store and need nothing extra.',
    remove: ['Open "Manage computer certificates" from the Start menu.', 'Trusted Root Certification Authorities → Certificates.', 'Right-click the proxy root and delete it.'],
  },
  mac: {
    clicks: [
      'Download the certificate and open it. Keychain Access adds it to your login keychain.',
      'Double-click it in Keychain Access and open the Trust section.',
      'Set "When using this certificate" to Always Trust, close the window, and enter your password.',
    ],
    where: 'In Terminal',
    command: (base, fp) => shellCheck(
      `curl -fsS --max-time 10 -o FILE ${base}/root.crt`,
      `if security find-certificate -c "DOMAIN proxy root" /Library/Keychains/System.keychain >/dev/null 2>&1; then echo "Replacing an older DOMAIN proxy root in the keychain."; sudo security delete-certificate -c "DOMAIN proxy root" /Library/Keychains/System.keychain >/dev/null 2>&1; fi
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain FILE`,
    ).replaceAll('FP', fp),
    browsers: 'Safari and Chrome use the keychain. Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import the downloaded file and tick "Trust this CA to identify websites".',
    remove: ['Open Keychain Access, search for the proxy root.', 'Delete it (it may be in both login and System).'],
  },
  linux: {
    clicks: [
      'Download the certificate.',
      'Open a terminal in your Downloads folder.',
      'Run the command for your distribution.',
    ],
    where: 'In a terminal',
    command: (base, fp, distro) => {
      const dst = { debian: '/usr/local/share/ca-certificates/FILE', fedora: '/etc/pki/ca-trust/source/anchors/FILE', arch: '' }[distro]
      const install = {
        debian: `sudo cp FILE ${dst} && sudo update-ca-certificates`,
        fedora: `sudo cp FILE ${dst} && sudo update-ca-trust`,
        arch: `sudo trust anchor --store FILE`,
      }[distro]
      return shellCheck(`curl -fsS --max-time 10 -o FILE ${base}/root.crt`, install, dst).replaceAll('FP', fp)
    },
    browsers: 'Chrome and Chromium on Linux keep their own store: install libnss3-tools (or nss-tools) and run  certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "DOMAIN proxy root" -i FILE . Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import and tick "Trust this CA to identify websites".',
    remove: ['Delete the file you copied (FILE in the directory above) and run the same update command again.', 'Chrome: certutil -d sql:$HOME/.pki/nssdb -D -n "DOMAIN proxy root". Firefox: delete it under Authorities.'],
  },
  freebsd: {
    clicks: [
      'Download the certificate.',
      'Open a terminal in your Downloads folder.',
      'Run the command below. As root it just works; otherwise it uses doas or sudo, whichever you have.',
    ],
    where: 'In a terminal',
    command: (base, fp) => shellCheck(
      `fetch -T 10 -o FILE ${base}/root.crt`,
      `if [ "$(id -u)" = 0 ]; then as=""; elif command -v doas >/dev/null; then as=doas; elif command -v sudo >/dev/null; then as=sudo; else echo "Run this as root (no doas or sudo found)."; as=false; fi
    $as cp FILE /usr/local/share/certs/FILE && $as certctl rehash >/dev/null`,
      '/usr/local/share/certs/FILE',
    ).replaceAll('FP', fp),
    browsers: 'Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import and tick "Trust this CA to identify websites". Chromium: certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "DOMAIN proxy root" -i FILE (security/nss).',
    remove: ['As root: rm /usr/local/share/certs/FILE && certctl rehash'],
  },
  iphone: {
    clicks: [
      'Tap Download certificate below (in Safari). Tap Allow, then Close.',
      'Open Settings. Near the top tap Profile Downloaded, then Install (enter your passcode).',
      'Back in Settings go to General → About → Certificate Trust Settings, and switch on the proxy root.',
    ],
    remove: ['Settings → General → VPN & Device Management → the proxy root → Remove Profile.'],
    note: 'Step 3 is the one people miss: installing the profile is not enough on its own.',
  },
  android: {
    clicks: [
      'Tap Download certificate below.',
      'Open Settings → Security (or Security & privacy) → More security settings → Encryption & credentials → Install a certificate → CA certificate.',
      'Tap Install anyway and choose the downloaded file.',
    ],
    remove: ['Settings → Security → Encryption & credentials → Trusted credentials → User tab → the proxy root → Remove.'],
    note: 'Browsers will trust the proxy. Some apps ignore certificates you install yourself; if an app refuses to connect, that is why.',
  },
}
