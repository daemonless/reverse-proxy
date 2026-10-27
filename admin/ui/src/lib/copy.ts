// Copy text to the clipboard. The async Clipboard API needs a secure
// context, and Chrome does not grant that to a page opened through a
// certificate warning or over plain HTTP, which is where the trust page
// lives; the old execCommand path still works there.
export async function copyText(text: string): Promise<boolean> {
  try {
    if (window.isSecureContext && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {}
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'; ta.style.top = '0'; ta.style.left = '0'; ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus(); ta.select(); ta.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
