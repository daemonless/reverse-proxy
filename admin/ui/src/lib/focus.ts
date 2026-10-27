// Focus the first field of a single-purpose screen on arrival, so typing
// can start at once. An action rather than the autofocus attribute, which
// fights screen readers when a page has more than one landmark.
export function focus(node: HTMLElement) {
  requestAnimationFrame(() => node.focus())
}
