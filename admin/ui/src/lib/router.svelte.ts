// A few screens, no dependency: the path is state, links call navigate().
let path = $state(location.pathname)

window.addEventListener('popstate', () => { path = location.pathname })

export function navigate(to: string, replace = false) {
  if (to === path) return
  if (replace) history.replaceState(null, '', to)
  else history.pushState(null, '', to)
  // "/settings#dns": the path is what routes; the hash is the screen's.
  path = to.split('#')[0]
}

export const route = {
  get path() { return path },
}

/** Intercepts clicks on same-origin links so the app routes them. */
export function link(node: HTMLAnchorElement) {
  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    const href = node.getAttribute('href')
    if (!href || !href.startsWith('/') || node.target === '_blank') return
    e.preventDefault()
    navigate(href)
  }
  node.addEventListener('click', onClick)
  return { destroy: () => node.removeEventListener('click', onClick) }
}
