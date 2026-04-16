// Plausible analytics init — extracted from inline <script> so we can keep
// a strict CSP (script-src 'self' https://plausible.io, no 'unsafe-inline').
window.plausible = window.plausible || function () {
  (plausible.q = plausible.q || []).push(arguments)
}
plausible.init = plausible.init || function (i) { plausible.o = i || {} }
plausible.init()
