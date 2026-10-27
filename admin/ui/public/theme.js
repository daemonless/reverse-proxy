// Resolve the theme before the stylesheet paints, so a light-mode user sees
// no dark flash. A file, not inline: the admin's Content-Security-Policy
// allows scripts from itself only. The same key as fjord.
(function () {
  var t;
  try { t = localStorage.getItem('fjord-theme'); } catch (e) {}
  if (t !== 'light' && t !== 'dark') {
    t = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  document.documentElement.setAttribute('data-theme', t);
})();
