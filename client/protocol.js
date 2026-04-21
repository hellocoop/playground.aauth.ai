// ── Protocol flow and log display ──
// Depends on app.js exposures via window: aauthBinding, aauthEphemeral,
// aauthApplyBootstrapResult, aauthWebAuthn, getCurrentPS.
// Built into public/protocol.js by esbuild; loaded as a classic script.

import { fetch as sigFetch } from '@hellocoop/httpsig'
import qrcode from 'qrcode-generator'

// ── Diagnostics ──
//
// Surface silent errors so we don't stare at a blank form wondering why
// bootstrap didn't complete. The global unhandledrejection handler
// catches any async error the ceremony code didn't explicitly catch and
// writes it to the protocol log (and console).

window.addEventListener('unhandledrejection', (ev) => {
  try {
    const msg = ev?.reason?.stack || ev?.reason?.message || String(ev?.reason)
    console.error('[aauth] unhandled rejection:', msg)
    showLog()
    addLogStep('Unhandled error', 'error',
      `<p style="color: var(--error); white-space: pre-wrap;">${escapeHtml(msg)}</p>`)
  } catch { /* last-ditch, don't throw from the error handler */ }
})

function trace(label, extra) {
  try { console.log(`[aauth] ${label}`, extra ?? '') } catch {}
}

// Signed fetch helper exposed for app.js (which can't import sigFetch
// directly since it isn't bundled). Signs with sig=jwt using the current
// ephemeral + a caller-supplied JWT (agent_token or auth_token).
window.aauthSigFetch = async function aauthSigFetch(url, { method = 'GET', headers = {}, body, jwt } = {}) {
  const keyPair = window.aauthEphemeral.get()
  if (!keyPair) throw new Error('no ephemeral key available to sign with')
  if (!jwt) throw new Error('jwt required for sig=jwt scheme')
  const signingKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const hasBody = body !== undefined && body !== null
  const components = hasBody
    ? ['@method', '@authority', '@path', 'content-type', 'signature-key']
    : ['@method', '@authority', '@path', 'signature-key']
  const mergedHeaders = hasBody
    ? { 'Content-Type': 'application/json', ...headers }
    : { ...headers }
  return sigFetch(url, {
    method,
    headers: mergedHeaders,
    body: hasBody ? body : undefined,
    signingKey,
    signingCryptoKey: keyPair.privateKey,
    signatureKey: { type: 'jwt', jwt },
    components,
  })
}

// ── Log rendering ──
//
// Each fieldset (Bootstrap Agent, Authorization Request) renders its
// own inline protocol log so the request/response trail stays next to
// the button that produced it. Each flow calls `setActiveLog('<id>')`
// at entry; subsequent addLogSection/addLogStep/resolveStep/clearLog
// calls target that container. The legacy '#protocol-log' id is still
// honored as a fallback for any unmigrated call site.

let __activeLogContainer = null

function setActiveLog(id) {
  const el = document.getElementById(id)
  if (el) __activeLogContainer = el
}

function currentLog() {
  // Prefer the explicitly-set container. Fall back to the legacy
  // shared log if nothing's been set (shouldn't happen post-refactor,
  // but keeps us safe against any call site we missed).
  return __activeLogContainer || document.getElementById('protocol-log')
}

// The log's collapsible outer wrapper. Hiding/showing lives on the
// wrapper so the <details> disclosure state (open/closed) is preserved
// independently of whether the wrapper is currently visible.
function logWrapper(log) {
  return log?.closest('.protocol-log-wrap') || log
}

function clearLog() {
  const log = currentLog()
  if (!log) return
  log.innerHTML = ''
  logWrapper(log).classList.add('hidden')
}

function showLog() {
  const log = currentLog()
  if (!log) return
  const wrap = logWrapper(log)
  wrap.classList.remove('hidden')
  // Re-open on show: a prior successful run may have auto-closed the
  // details; a fresh start should drop the reader straight into the
  // new steps without a click.
  if (wrap.tagName === 'DETAILS') wrap.open = true
}


function statusIndicatorHtml(status) {
  if (status === 'pending') {
    return '<span class="step-status step-status-pending"><span class="dot"></span><span class="dot"></span><span class="dot"></span></span>'
  }
  if (status === 'success') return '<span class="step-status step-status-success">\u2713</span>'
  return '<span class="step-status step-status-error">\u2717</span>'
}

const CHEVRON_SVG = `<svg class="section-chevron" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5"/></svg>`

let __copyIdCounter = 0
function nextCopyId() { return `copy-tgt-${++__copyIdCounter}` }

// Heuristic: if the step body already contains <details> panels (e.g. formatToken),
// the outer step is redundant as a toggle — just the heading + inline content.
function isExpandable(content) {
  return !!content && !/<details[\s>]/i.test(content)
}

// Visual divider in the protocol log — used to group steps under
// "Bootstrap", "Refresh", and "Authorize" so the reader can tell which
// ceremony a given step belongs to.
function addLogSection(title) {
  const log = currentLog()
  if (!log) return
  showLog()
  const h = document.createElement('div')
  h.className = 'log-section-heading'
  h.textContent = title
  log.appendChild(h)
}

function addLogStep(label, status, content) {
  const log = currentLog()
  if (!log) return null
  showLog()
  const expandable = isExpandable(content)
  const step = expandable ? document.createElement('details') : document.createElement('div')
  step.className = `log-step section-group ${status}${expandable ? '' : ' log-step-static'}`
  if (expandable) step.open = true

  const heading = document.createElement(expandable ? 'summary' : 'div')
  heading.className = 'section-heading'
  heading.innerHTML = `<span class="step-label">${statusIndicatorHtml(status)}<span class="step-text">${label}</span></span>${expandable ? CHEVRON_SVG : ''}`
  step.appendChild(heading)

  const body = document.createElement('div')
  body.style.marginTop = '1rem'
  body.innerHTML = content
  step.appendChild(body)

  log.appendChild(step)
  requestAnimationFrame(() => {
    step.scrollIntoView({ behavior: 'smooth', block: 'start' })
  })
  return step
}

// Update an existing step's status + label in place (instead of removing it).
function resolveStep(step, status, label) {
  if (!step) return
  const isStatic = step.classList.contains('log-step-static')
  step.className = `log-step section-group ${status}${isStatic ? ' log-step-static' : ''}`
  const statusEl = step.querySelector('.step-status')
  const textEl = step.querySelector('.step-text')
  if (statusEl) statusEl.outerHTML = statusIndicatorHtml(status)
  if (textEl) textEl.textContent = label
}

function anotherRequestButton() {
  return `<div class="log-actions"><button type="button" class="btn-outline js-scroll-authz">Another Authorization Request</button></div>`
}

function tokenWrap(innerHtml, extraClass = '') {
  const id = nextCopyId()
  return `<div class="token-wrap">
    <button class="copy-btn copy-btn-float" type="button" data-copy-target="#${id}" aria-label="Copy"></button>
    <div class="token-display${extraClass ? ' ' + extraClass : ''}" id="${id}">${innerHtml}</div>
  </div>`
}

function formatRequest(method, url, headers, body) {
  let inner = `${escapeHtml(method)} ${escapeHtml(url)}\n`
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      inner += `${escapeHtml(k)}: ${escapeHtml(v)}\n`
    }
  }
  if (body) {
    inner += `\n${renderJSON(body)}`
  }
  return tokenWrap(inner)
}

function formatResponse(status, headers, body) {
  let inner = `HTTP ${status}\n`
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      inner += `${escapeHtml(k)}: ${escapeHtml(v)}\n`
    }
  }
  if (body) {
    inner += `\n${renderJSON(body)}`
  }
  return tokenWrap(inner)
}

function formatToken(label, token, decoded) {
  return `
    <details class="section-group">
      <summary class="section-heading"><span>${escapeHtml(label)}</span>${CHEVRON_SVG}</summary>
      ${tokenWrap(renderEncodedJWT(token), 'encoded')}
    </details>
    <details class="section-group" open>
      <summary class="section-heading"><span>Decoded</span>${CHEVRON_SVG}</summary>
      ${tokenWrap(renderJSON(decoded))}
    </details>
  `
}

// Inline variant of formatToken used by Authorization Granted — no outer
// collapsible, since the surrounding "Authorization Granted" step already
// labels the token.
function formatAuthToken(token) {
  return `
    ${tokenWrap(renderEncodedJWT(token), 'encoded')}
    <details class="section-group" open>
      <summary class="section-heading"><span>Decoded</span>${CHEVRON_SVG}</summary>
      ${tokenWrap(renderJSON(decodeJWTPayloadBrowser(token)))}
    </details>
  `
}

// ── Scope collection ──

function getSelectedIdentityScopes() {
  const checkboxes = document.querySelectorAll('#identity-scope-grid input[type="checkbox"]:checked')
  return Array.from(checkboxes).map((cb) => cb.value).join(' ')
}

function getSelectedResourceScopes() {
  const checkboxes = document.querySelectorAll('#resource-scope-grid input[type="checkbox"]:checked')
  return Array.from(checkboxes).map((cb) => cb.value).join(' ')
}

function getHints() {
  const hints = {}
  const fields = ['login-hint', 'domain-hint', 'provider-hint', 'tenant']
  for (const field of fields) {
    // Per-hint checkbox gates whether the hint is sent. This is explicit on/off
    // rather than implicit from value-presence — lets the user keep a value
    // parked in the input while disabling it for a single request.
    const enabled = document.querySelector(`.hint-enable[data-hint-for="${field}"]`)?.checked
    if (!enabled) continue
    const val = document.getElementById(field)?.value?.trim()
    if (val) {
      // Convert kebab-case id to snake_case param name
      hints[field.replace('-', '_')] = val
    }
  }
  return hints
}

// ── Bootstrap ceremony ──
//
// (PS /bootstrap → interaction → bootstrap_token → agent-server
// /bootstrap/challenge → WebAuthn → /bootstrap/verify → agent_token).
// Runs once per (PS, user) pair; the resulting binding_key is stored
// in localStorage so /refresh can reuse the same credentials.
//
// Bootstrap carries no scope. The ceremony establishes only the
// user↔agent-server binding; scopes and claim release happen later
// through the /authorize + PS /token flow.
async function runBootstrap(psUrl, hints) {
  const agentServerOrigin = window.location.origin

  addLogSection('Bootstrap')

  // Step 0: rotate ephemeral. Fresh key each bootstrap so the PS's
  // cnf-bound bootstrap_token is scoped to this ceremony only.
  const { keyPair, publicJwk } = await window.aauthEphemeral.rotate()
  addLogStep('Generate ephemeral key', 'success',
    `<p>Rotated to a fresh Ed25519 keypair. The public key is bound into the PS bootstrap request as <code>Signature-Key: sig=hwk</code>, and will appear in the resulting <code>bootstrap_token.cnf.jwk</code>.</p>` +
    tokenWrap(renderJSON(publicJwk))
  )

  // Step 1: Discover PS metadata to find its /bootstrap endpoint.
  const psMetadataUrl = `${psUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  const psMetaStep = addLogStep(`GET ${psMetadataUrl}`, 'pending',
    formatRequest('GET', psMetadataUrl, null, null)
  )
  let psMetadata
  try {
    const psMetaRes = await fetch(psMetadataUrl)
    psMetadata = await psMetaRes.json()
    if (!psMetaRes.ok) {
      resolveStep(psMetaStep, 'error', `GET ${new URL(psMetadataUrl).pathname} \u2192 ${psMetaRes.status}`)
      addLogStep('PS discovery failed', 'error', formatResponse(psMetaRes.status, null, psMetadata))
      return false
    }
    resolveStep(psMetaStep, 'success', `GET ${new URL(psMetadataUrl).pathname} \u2192 200`)
    addLogStep('Person Server metadata', 'success', formatResponse(200, null, psMetadata))
  } catch (err) {
    resolveStep(psMetaStep, 'error', `GET ${new URL(psMetadataUrl).pathname} (network error)`)
    addLogStep('PS discovery error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return false
  }

  const bootstrapEndpoint = psMetadata.bootstrap_endpoint || `${psUrl.replace(/\/$/, '')}/bootstrap`

  // Step 2: POST PS /bootstrap. Signed with sig=hwk so the PS knows which
  // key to bind into the resulting bootstrap_token.cnf.
  const psBootstrapBody = {
    agent_server: agentServerOrigin,
    ...hints,
  }
  const psBootReqStep = addLogStep(`POST ${new URL(bootstrapEndpoint).pathname}`, 'pending',
    formatRequest('POST', bootstrapEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=hwk;kty="${publicJwk.kty}";crv="${publicJwk.crv}";x="${publicJwk.x}"`,
    }, psBootstrapBody)
  )

  let psBootRes, psBootBody, pollUrl, interactionParams, responseHeaders = {}
  try {
    psBootRes = await sigFetch(bootstrapEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(psBootstrapBody),
      signingKey: publicJwk,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: 'hwk' },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    })
    for (const key of ['location', 'retry-after', 'aauth-requirement']) {
      const v = psBootRes.headers.get(key)
      if (v) responseHeaders[key] = v
    }
    try { psBootBody = await psBootRes.json() } catch { psBootBody = null }
    pollUrl = psBootRes.headers.get('location') || psBootBody?.location || psBootBody?.pending_url
    const reqHeader = psBootRes.headers.get('aauth-requirement') || ''
    const fromHeader = parseInteractionHeader(reqHeader)
    interactionParams = {
      requirement: fromHeader.requirement || psBootBody?.requirement,
      code: fromHeader.code || psBootBody?.code,
      url: fromHeader.url || psMetadata.interaction_endpoint || psBootBody?.interaction_url,
    }
    const reqStatus = psBootRes.ok ? 'success' : 'error'
    resolveStep(psBootReqStep, reqStatus, `POST ${new URL(bootstrapEndpoint).pathname} \u2192 ${psBootRes.status}`)
  } catch (err) {
    resolveStep(psBootReqStep, 'error', `POST ${new URL(bootstrapEndpoint).pathname} (network error)`)
    addLogStep('PS /bootstrap failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return false
  }

  if (psBootRes.status !== 202 || !pollUrl) {
    addLogStep('Unexpected PS /bootstrap response', 'error',
      formatResponse(psBootRes.status, responseHeaders, psBootBody))
    return false
  }

  // Step 3: show interaction + poll until bootstrap_token arrives.
  //
  // Render order matters — the log reads top-down as a protocol trace:
  //   POST /aauth/bootstrap → 202        (already above)
  //   GET  /aauth/pending/:code          (the request we're about to make)
  //   Person Server interaction UI       (what the user does next)
  // The long-poll is conceptually the response to the 202 above. Surfacing
  // it before the QR-code block matches how the bytes actually flow.
  const absolutePollUrl = new URL(pollUrl, bootstrapEndpoint).href
  const pollPath = new URL(absolutePollUrl).pathname
  const pollStep = addLogStep(`GET ${pollPath} (long-poll)`, 'pending',
    `<p>Long-polling the PS pending URL. <code>Prefer: wait=30</code> asks the PS to hold the request for up to 30s and return as soon as state changes. On 202 the client loops immediately.</p>` +
    formatRequest('GET', absolutePollUrl, {
      'Prefer': 'wait=30',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=hwk;kty="${publicJwk.kty}";crv="${publicJwk.crv}";x="${publicJwk.x}"`,
    }, null)
  )
  const interactionStep = addLogStep('User Consent at Person Server', 'pending',
    formatResponse(psBootRes.status, responseHeaders, psBootBody) +
    renderInteraction(interactionParams, absolutePollUrl)
  )
  savePendingBootstrap({
    pollUrl: absolutePollUrl,
    bootstrapEndpoint,
    psUrl,
  })

  const pending = await pollForBootstrapToken(absolutePollUrl, keyPair, publicJwk, interactionStep, pollStep)
  trace('pollForBootstrapToken returned', pending ? { hasToken: !!pending.bootstrap_token } : null)
  if (!pending) return false

  addLogStep('Bootstrap Token Received', 'success',
    formatToken('Bootstrap Token (aa-bootstrap+jwt)', pending.bootstrap_token, decodeJWTPayloadBrowser(pending.bootstrap_token))
  )

  // Step 4: exchange with our own agent server /bootstrap/challenge.
  return await completeAgentServerBootstrap(pending.bootstrap_token, publicJwk, keyPair, { psUrl })
}

// Poll the PS pending URL for the bootstrap_token. Polls are signed with
// the ephemeral key + sig=hwk (same key bound into the PS's record).
//
// We send `Prefer: wait=30` (RFC 7240 + IETF draft long-polling): the PS
// holds the request for up to 30s and returns as soon as state changes.
// On 202 we loop immediately; on network error we back off briefly so a
// dead connection doesn't spin.
// pollStep is created by the caller so the log rows can be ordered as
// "202 response → GET /pending (long-poll) → User Consent at PS". When
// called from a resume path that doesn't pre-create the step, fall back
// to creating it inline so the poll still renders as a log entry.
async function pollForBootstrapToken(absolutePollUrl, keyPair, publicJwk, interactionStep, pollStep) {
  const pollPath = new URL(absolutePollUrl).pathname
  if (!pollStep) {
    // Single log entry for the whole long-poll. Each HTTP attempt isn't
    // surfaced (would flood the log at ~30s cadence) — we just show the
    // request shape once and resolve when the poll terminates.
    pollStep = addLogStep(`GET ${pollPath} (long-poll)`, 'pending',
      `<p>Long-polling the PS pending URL. <code>Prefer: wait=30</code> asks the PS to hold the request for up to 30s and return as soon as state changes. On 202 the client loops immediately.</p>` +
      formatRequest('GET', absolutePollUrl, {
        'Prefer': 'wait=30',
        'Signature-Input': 'sig=("@method" "@authority" "@path" "signature-key");created=...',
        'Signature': 'sig=:...:',
        'Signature-Key': `sig=hwk;kty="${publicJwk.kty}";crv="${publicJwk.crv}";x="${publicJwk.x}"`,
      }, null)
    )
  }
  while (true) {
    try {
      const res = await sigFetch(absolutePollUrl, {
        method: 'GET',
        headers: { Prefer: 'wait=30' },
        signingKey: publicJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: 'hwk' },
        components: ['@method', '@authority', '@path', 'signature-key'],
      })
      if (res.status === 200) {
        trace('poll 200 received')
        clearPendingBootstrap()
        const body = await res.json().catch(() => null)
        const token = body?.bootstrap_token
        if (!token) {
          trace('poll 200 missing bootstrap_token', body)
          resolveStep(pollStep, 'error', `GET ${pollPath} \u2192 200 (no bootstrap_token)`)
          resolveStep(interactionStep, 'error', 'Pending returned no bootstrap_token')
          addLogStep('Bad /pending response', 'error', formatResponse(200, null, body))
          return null
        }
        trace('poll token extracted, length', token.length)
        resolveStep(pollStep, 'success', `GET ${pollPath} \u2192 200`)
        resolveStep(interactionStep, 'success', 'User Consent Completed')
        // Bootstrap carries no scope, so the PS cannot bundle an auth_token
        // here — only a bootstrap_token. scope/claims are negotiated later
        // at /authorize + PS /token.
        return { bootstrap_token: token, raw: body }
      }
      if (res.status === 403) {
        clearPendingBootstrap()
        resolveStep(pollStep, 'error', `GET ${pollPath} \u2192 403`)
        resolveStep(interactionStep, 'error', 'Consent Denied')
        addLogStep('User denied consent', 'error',
          formatResponse(403, null, await res.json().catch(() => null)) + anotherRequestButton())
        return null
      }
      if (res.status === 408) {
        clearPendingBootstrap()
        resolveStep(pollStep, 'error', `GET ${pollPath} \u2192 408`)
        resolveStep(interactionStep, 'error', 'Consent Timed Out')
        addLogStep('Interaction timed out', 'error',
          formatResponse(408, null, null) + anotherRequestButton())
        return null
      }
      // 202 → loop immediately (server already held up to 30s)
    } catch (err) {
      console.log('Bootstrap poll error:', err.message)
      await new Promise((r) => setTimeout(r, 5000))
    }
  }
}

async function completeAgentServerBootstrap(bootstrapToken, publicJwk, keyPair, ctx = {}) {
  trace('completeAgentServerBootstrap entered')
  // Belt-and-suspenders: pollForBootstrapToken clears the pending-bootstrap
  // key on success, but clear again here so any post-poll error path
  // (e.g. agent-server /bootstrap/challenge rejecting the token) doesn't
  // leave a stale pending entry that would be resumed on next reload.
  clearPendingBootstrap()

  // POST /bootstrap/challenge. Server verifies bootstrap_token, returns
  // WebAuthn options + a transaction id tied to the already-validated claims.
  // Pass the generated three-word handle so the server can mint
  // aauth:{handle}@host on first bootstrap for this (PS, user). Ignored
  // on subsequent bootstraps — server uses the binding's stored aauth_sub.
  // Lazy generation: no name exists on a fresh install or post-Reset
  // until we actually need one here.
  const agentLocal = window.aauthGetOrGenerateAgentName()
  const challengeEndpoint = `${window.location.origin}/bootstrap/challenge`
  const challengeBody = { bootstrap_token: bootstrapToken, ephemeral_jwk: publicJwk, agent_local: agentLocal }
  const challengeReqStep = addLogStep(`POST ${new URL(challengeEndpoint).pathname}`, 'pending',
    formatRequest('POST', challengeEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${bootstrapToken.substring(0, 20)}..."`,
    }, {
      bootstrap_token: bootstrapToken.substring(0, 20) + '...',
      ephemeral_jwk: publicJwk,
      agent_local: agentLocal,
    })
  )

  let challengeData
  try {
    // Signed with sig=jwt using the bootstrap_token itself: the PS set
    // bootstrap_token.cnf.jwk = our ephemeral, so the library verifies the
    // HTTP signature against that key, which we hold privately. Acts as a
    // transient agent_token for this one hop.
    const res = await sigFetch(challengeEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(challengeBody),
      signingKey: publicJwk,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: bootstrapToken },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    })
    challengeData = await res.json()
    if (!res.ok) {
      resolveStep(challengeReqStep, 'error', `POST /bootstrap/challenge \u2192 ${res.status}`)
      addLogStep('Agent server rejected bootstrap_token', 'error',
        formatResponse(res.status, null, challengeData))
      return false
    }
    resolveStep(challengeReqStep, 'success', `POST /bootstrap/challenge \u2192 200`)
    addLogStep(`WebAuthn ${challengeData.webauthn_type === 'register' ? 'Registration' : 'Assertion'} Challenge`, 'success',
      formatResponse(200, null, challengeData))
  } catch (err) {
    resolveStep(challengeReqStep, 'error', 'POST /bootstrap/challenge (network error)')
    addLogStep('Agent server /bootstrap/challenge failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return false
  }

  // Run the WebAuthn ceremony.
  let webauthnResponse
  try {
    const opts = challengeData.webauthn_options
    if (challengeData.webauthn_type === 'register') {
      const parsed = window.aauthWebAuthn.parseCreationOptions(opts)
      const cred = await navigator.credentials.create({ publicKey: parsed })
      webauthnResponse = window.aauthWebAuthn.serializeCredential(cred)
    } else {
      const parsed = window.aauthWebAuthn.parseRequestOptions(opts)
      const cred = await navigator.credentials.get({ publicKey: parsed })
      webauthnResponse = window.aauthWebAuthn.serializeAssertion(cred)
    }
  } catch (err) {
    addLogStep('WebAuthn ceremony failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return false
  }

  addLogStep('WebAuthn Attestation Completed', 'success',
    `<p>Browser returned a WebAuthn ${challengeData.webauthn_type === 'register' ? 'attestation' : 'assertion'} bound to the challenge.</p>`
  )

  // POST /bootstrap/verify — also signed with sig=jwt + bootstrap_token.
  const verifyEndpoint = `${window.location.origin}/bootstrap/verify`
  const verifyBody = {
    bootstrap_tx_id: challengeData.bootstrap_tx_id,
    webauthn_response: webauthnResponse,
  }
  const verifyStep = addLogStep(`POST ${new URL(verifyEndpoint).pathname}`, 'pending',
    formatRequest('POST', verifyEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${bootstrapToken.substring(0, 20)}..."`,
    }, {
      bootstrap_tx_id: challengeData.bootstrap_tx_id,
      webauthn_response: '(credential)',
    })
  )

  let result
  try {
    const res = await sigFetch(verifyEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyBody),
      signingKey: publicJwk,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: bootstrapToken },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    })
    result = await res.json()
    if (!res.ok) {
      resolveStep(verifyStep, 'error', `POST /bootstrap/verify \u2192 ${res.status}`)
      addLogStep('Bootstrap verification failed', 'error', formatResponse(res.status, null, result))
      return false
    }
    resolveStep(verifyStep, 'success', `POST /bootstrap/verify \u2192 200`)
  } catch (err) {
    resolveStep(verifyStep, 'error', 'POST /bootstrap/verify (network error)')
    addLogStep('Agent server /bootstrap/verify failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return false
  }

  // Save the (PS, user_sub) binding so /refresh can reuse the WebAuthn
  // credential we just registered/asserted. user_sub is the pairwise
  // identifier from the bootstrap_token — opaque to us, but stable per
  // (PS, agent_server) pair so the server can look up the binding.
  const bootstrapPayload = decodeJWTPayloadBrowser(bootstrapToken) || {}
  const bindingKey = await deriveBindingKeyBrowser(result.ps, bootstrapPayload.sub || '')
  window.aauthBinding.saveBinding({
    binding_key: bindingKey,
    ps_url: result.ps,
    user_sub: bootstrapPayload.sub || '',
  })

  window.aauthApplyBootstrapResult(result)

  addLogStep('Agent Token Minted', 'success',
    formatToken('Agent Token (aa-agent+jwt)', result.agent_token, decodeJWTPayloadBrowser(result.agent_token))
  )

  return { result }
}

// Mirror of server-side deriveBindingKey: sha-256(ps_url + "|" + user_sub).
async function deriveBindingKeyBrowser(psUrl, userSub) {
  const data = new TextEncoder().encode(`${psUrl}|${userSub}`)
  const hash = await crypto.subtle.digest('SHA-256', data)
  const bytes = new Uint8Array(hash)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ── Refresh ceremony ──
//
// Uses the stored binding_key to ask the agent server for a fresh agent +
// resource token pair under a rotated ephemeral key. No PS involvement.

// No scope parameter: see runBootstrap above.
//
// Ephemeral lifecycle: we STAGE a new keypair (not yet persisted) and
// sign both /refresh/challenge and /refresh/verify with the OLD keypair
// (which matches agent_token.cnf.jwk). The server mints fresh tokens
// bound to the new pubkey; only on success do we commit the staged key
// and replace the old one in IndexedDB. If anything fails, the old key
// stays active and the agent_token (if still valid) remains usable.
async function runRefresh() {
  const { bindingKey } = window.aauthBinding.get()
  if (!bindingKey) return null

  const oldKeyPair = window.aauthEphemeral.get()
  const agentToken = localStorage.getItem('aauth-agent-token')
  if (!oldKeyPair || !agentToken) {
    addLogStep('Cannot refresh', 'error',
      '<p>No ephemeral key + agent_token pair present locally. Full bootstrap required.</p>')
    return null
  }

  addLogSection('Refresh')

  const { publicJwk: newPublicJwk } = await window.aauthEphemeral.stage()
  addLogStep('Stage new ephemeral key', 'success',
    `<p>Generated a fresh Ed25519 keypair but did not persist it. The current /refresh calls are signed with the <em>old</em> ephemeral (bound to the existing <code>agent_token.cnf.jwk</code>); the new key will be committed only after <code>/refresh/verify</code> succeeds.</p>` +
    tokenWrap(renderJSON(newPublicJwk))
  )

  const oldSigningJwk = await crypto.subtle.exportKey('jwk', oldKeyPair.publicKey)
  const refreshChallengeEndpoint = `${window.location.origin}/refresh/challenge`
  const refreshChallengeBody = { binding_key: bindingKey, new_ephemeral_jwk: newPublicJwk }

  const reqStep = addLogStep(`POST ${new URL(refreshChallengeEndpoint).pathname}`, 'pending',
    formatRequest('POST', refreshChallengeEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`,
    }, refreshChallengeBody)
  )

  let challengeData
  try {
    const res = await sigFetch(refreshChallengeEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(refreshChallengeBody),
      signingKey: oldSigningJwk,
      signingCryptoKey: oldKeyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: agentToken },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    })
    challengeData = await res.json()
    if (!res.ok) {
      resolveStep(reqStep, 'error', `POST /refresh/challenge \u2192 ${res.status}`)
      addLogStep('Refresh rejected', 'error', formatResponse(res.status, null, challengeData))
      window.aauthEphemeral.discardStaged()
      // Binding is stale — drop it so the next Continue does a full bootstrap.
      window.aauthBinding.clearBinding()
      return null
    }
    resolveStep(reqStep, 'success', 'POST /refresh/challenge \u2192 200')
  } catch (err) {
    resolveStep(reqStep, 'error', 'POST /refresh/challenge (network error)')
    addLogStep('Refresh network error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    window.aauthEphemeral.discardStaged()
    return null
  }

  let webauthnResponse
  try {
    const parsed = window.aauthWebAuthn.parseRequestOptions(challengeData.webauthn_options)
    const cred = await navigator.credentials.get({ publicKey: parsed })
    webauthnResponse = window.aauthWebAuthn.serializeAssertion(cred)
  } catch (err) {
    addLogStep('WebAuthn assertion failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    window.aauthEphemeral.discardStaged()
    return null
  }

  addLogStep('WebAuthn Assertion Completed', 'success',
    `<p>Browser returned a WebAuthn assertion against the stored credential for this binding.</p>`)

  const refreshVerifyEndpoint = `${window.location.origin}/refresh/verify`
  const refreshVerifyBody = {
    refresh_tx_id: challengeData.refresh_tx_id,
    webauthn_response: webauthnResponse,
  }
  const verifyStep = addLogStep(`POST ${new URL(refreshVerifyEndpoint).pathname}`, 'pending',
    formatRequest('POST', refreshVerifyEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`,
    }, {
      refresh_tx_id: challengeData.refresh_tx_id,
      webauthn_response: '(assertion)',
    })
  )

  let result
  try {
    const res = await sigFetch(refreshVerifyEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(refreshVerifyBody),
      signingKey: oldSigningJwk,
      signingCryptoKey: oldKeyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: agentToken },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    })
    result = await res.json()
    if (!res.ok) {
      resolveStep(verifyStep, 'error', `POST /refresh/verify \u2192 ${res.status}`)
      addLogStep('Refresh verify failed', 'error', formatResponse(res.status, null, result))
      window.aauthEphemeral.discardStaged()
      return null
    }
    resolveStep(verifyStep, 'success', 'POST /refresh/verify \u2192 200')
  } catch (err) {
    resolveStep(verifyStep, 'error', 'POST /refresh/verify (network error)')
    addLogStep('Refresh verify network error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    window.aauthEphemeral.discardStaged()
    return null
  }

  // Server accepted. Promote the staged ephemeral to current + persist it.
  await window.aauthEphemeral.commitStaged()

  window.aauthApplyBootstrapResult(result)
  addLogStep('Agent Token Refreshed', 'success',
    formatToken('Agent Token (aa-agent+jwt)', result.agent_token, decodeJWTPayloadBrowser(result.agent_token))
  )
  return result
}

// ── Main flows: Bootstrap button + Continue button ──
//
// Two independent entry points, mutually exclusive in the UI:
//
//   startBootstrap — pre-bootstrap. Establishes the (PS, user) binding
//                    and mints an agent_token. No scope, no /authorize.
//
//   startAuthorize — post-bootstrap. Uses the existing binding; refreshes
//                    agent_token if expired, then runs /authorize → PS
//                    /token → API call. Repeatable with different scopes.

async function startBootstrap() {
  const psUrl = (window.getCurrentPS?.() || '').trim()
  if (!psUrl) {
    alert('Please choose or enter a Person Server URL')
    return
  }

  // Route all log calls during bootstrap to the log container inside
  // the Bootstrap Agent fieldset. Kept set until startAuthorize takes
  // over; refresh (which fires from inside startAuthorize) keeps its
  // steps here too since it's part of the agent-identity lifecycle.
  setActiveLog('bootstrap-log')
  clearLog()
  showLog()

  const hints = getHints()

  // Fresh bootstrap — drop any stale binding/token before starting.
  window.aauthBinding.clearBinding()
  localStorage.removeItem('aauth-agent-token')

  await runBootstrap(psUrl, hints)
}

async function startAuthorize() {
  const { bindingKey, bindingPs } = window.aauthBinding.get()
  if (!bindingKey || !bindingPs) {
    alert('No agent binding found. Bootstrap first.')
    return
  }

  // The combined identity + resource scope string sent at /authorize.
  // Resource scopes are validated server-side against SCOPE_DESCRIPTIONS;
  // identity scopes pass through resource_token → PS /token and are
  // applied as claim-release rules by the PS.
  const combined = getCombinedScope()
  if (!combined) {
    alert('Select at least one scope')
    return
  }

  // Authorization steps render in the Authorization Request fieldset's
  // own log. Refresh (if agent_token is expired) still uses the bootstrap
  // log since that's where the agent-identity card lives; we swap
  // active back to authz-log after the refresh completes.
  setActiveLog('authz-log')
  clearLog()
  showLog()

  const hints = getHints()

  let agentTokenValid = false
  const savedAgentToken = localStorage.getItem('aauth-agent-token')
  if (savedAgentToken) {
    try {
      const p = decodeJWTPayloadBrowser(savedAgentToken)
      agentTokenValid = p && p.exp > Math.floor(Date.now() / 1000)
    } catch { /* invalid token */ }
  }

  if (!agentTokenValid) {
    const refreshed = await runRefresh()
    if (!refreshed) return
  }

  await runAuthorizationAgainstPS(bindingPs, combined, hints)
}

// Identity + resource scopes concatenated into one space-delimited string.
// No identity vs. resource distinction at the wire.
function getCombinedScope() {
  const identity = (getSelectedIdentityScopes() || '').split(/\s+/).filter(Boolean)
  const resource = (getSelectedResourceScopes() || '').split(/\s+/).filter(Boolean)
  const all = Array.from(new Set([...identity, ...resource]))
  return all.join(' ')
}

async function runAuthorizationAgainstPS(psUrl, scope, hints) {
  const keyPair = window.aauthEphemeral.get()
  const agentToken = localStorage.getItem('aauth-agent-token')
  if (!agentToken || !keyPair) {
    addLogStep('Missing agent_token or ephemeral key', 'error',
      '<p>Bootstrap must complete before authorization.</p>')
    return
  }

  addLogSection('Authorization')

  // Mint a fresh resource_token via /authorize. This is an httpsig call
  // (RFC 9421) signed by the ephemeral key, with the agent_token carried
  // in Signature-Key: sig=jwt — mirrors how we call the PS /token. The
  // agent_token is authentication, not request data, so it belongs in a
  // header, not the body.
  const authzEndpoint = `${window.location.origin}/authorize`
  const authzBody = { ps: psUrl, scope }
  const signingJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)

  const authzReqStep = addLogStep(`POST ${new URL(authzEndpoint).pathname}`, 'pending',
    formatRequest('POST', authzEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`,
    }, authzBody)
  )
  let authzData
  try {
    const res = await sigFetch(authzEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authzBody),
      signingKey: signingJwk,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: agentToken },
      components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    })
    authzData = await res.json()
    if (!res.ok) {
      resolveStep(authzReqStep, 'error', `POST /authorize \u2192 ${res.status}`)
      addLogStep('Authorization request failed', 'error', formatResponse(res.status, null, authzData))
      return
    }
    resolveStep(authzReqStep, 'success', 'POST /authorize \u2192 200')
  } catch (err) {
    resolveStep(authzReqStep, 'error', 'POST /authorize (network error)')
    addLogStep('Network error', 'error', `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return
  }

  addLogStep('Resource Token Created', 'success',
    formatToken('Resource Token (aa-resource+jwt)', authzData.resource_token, authzData.resource_token_decoded))

  const psMetadata = authzData.ps_metadata
  const resourceToken = authzData.resource_token
  const tokenEndpoint = psMetadata.token_endpoint
  const psRequestBody = {
    resource_token: resourceToken,
    capabilities: ['interaction'],
    ...hints,
  }

  const psReqStep = addLogStep(`POST ${new URL(tokenEndpoint).pathname}`, 'pending',
    formatRequest('POST', tokenEndpoint, {
      'Content-Type': 'application/json',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`,
    }, psRequestBody)
  )

  try {
    const signingJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
    const psRes = await sigFetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(psRequestBody),
      signingKey: signingJwk,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: agentToken },
      components: ['@method', '@authority', '@path', 'signature-key'],
    })

    const responseHeaders = {}
    for (const key of ['location', 'retry-after', 'aauth-requirement']) {
      const val = psRes.headers.get(key)
      if (val) responseHeaders[key] = val
    }

    let psBody
    try { psBody = await psRes.json() } catch { psBody = null }

    const psPath = new URL(tokenEndpoint).pathname
    resolveStep(psReqStep, psRes.ok ? 'success' : 'error', `POST ${psPath} \u2192 ${psRes.status}`)

    if (psRes.status === 200 && psBody?.auth_token) {
      addLogStep('Authorization Granted', 'success',
        formatAuthToken(psBody.auth_token) +
        anotherRequestButton()
      )
      // await callDemoResourceApi(psBody.auth_token)
    } else if (psRes.status === 202) {
      // Interaction required. This can still happen on a scope upgrade.
      const reqHeader = psRes.headers.get('aauth-requirement') || ''
      const fromHeader = parseInteractionHeader(reqHeader)
      const interaction = {
        requirement: fromHeader.requirement || psBody?.requirement,
        code: fromHeader.code || psBody?.code,
        url: fromHeader.url || psMetadata.interaction_endpoint,
      }
      const pollUrl = psRes.headers.get('location') || psBody?.location
      const interactionStep = addLogStep('Interaction Required', 'pending',
        formatResponse(202, responseHeaders, psBody) +
        renderInteraction(interaction, pollUrl)
      )
      if (pollUrl) {
        // Persist enough state to resume polling after the user returns
        // from wallet.hello-beta.net via same-tab redirect. Without this,
        // the return trip would drop the user at the Continue form with
        // no indication the authorize poll is still alive at the PS.
        savePendingAuthorize({
          pollUrl: new URL(pollUrl, tokenEndpoint).href,
          tokenEndpoint,
          psUrl,
          scope,
        })
        startAuthTokenPolling(pollUrl, tokenEndpoint, interactionStep)
      }
    } else {
      addLogStep('Person Server Response', psRes.ok ? 'success' : 'error',
        formatResponse(psRes.status, responseHeaders, psBody))
    }
  } catch (err) {
    resolveStep(psReqStep, 'error', `POST ${new URL(tokenEndpoint).pathname} (network error)`)
    addLogStep('Person Server Call Failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
  }
}

// ── Interaction handling (unchanged) ──

function parseInteractionHeader(header) {
  const result = {}
  const parts = header.split(';').map(s => s.trim())
  for (const part of parts) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const key = part.substring(0, eq).trim()
    let val = part.substring(eq + 1).trim()
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1)
    result[key] = val
  }
  return result
}

function renderInteraction(interaction, pollUrl) {
  if (!interaction.url || !interaction.code) {
    const missing = []
    if (!interaction.url) missing.push('interaction_endpoint (PS metadata) or url (header)')
    if (!interaction.code) missing.push('code')
    return `<p style="color: var(--muted);">Interaction required but missing: ${escapeHtml(missing.join(', '))}.</p>`
  }

  const callbackUrl = `${window.location.origin}/`
  // Same-device URL: include ?callback= so the PS redirects the user back
  // here after consent. QR-code URL: omit it — the other device can't
  // redirect back to this browser anyway, and a shorter URL makes a
  // denser, more scannable code.
  const sameDeviceUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}&callback=${encodeURIComponent(callbackUrl)}`
  const qrUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}`
  const qrId = `qr-${Math.random().toString(36).slice(2, 9)}`
  const urlId = nextCopyId()
  const html = `
    <div class="interaction-box">
      <p>The Person Server requires user interaction.</p>
      <div class="interaction-code">${escapeHtml(interaction.code)}</div>
      <div class="interaction-actions">
        <a class="interaction-link" href="${escapeHtml(sameDeviceUrl)}">Open Person Server</a>
        <div class="interaction-url-row">
          <code class="interaction-url" id="${urlId}">${escapeHtml(sameDeviceUrl)}</code>
          <button class="copy-btn" type="button" data-copy="${escapeHtml(sameDeviceUrl)}" aria-label="Copy"></button>
        </div>
      </div>
      <div class="interaction-or"><span>OR</span></div>
      <p class="qr-caption">Scan with another device to continue</p>
      <div class="qr-code" id="${qrId}"></div>
      <div class="interaction-approved" aria-hidden="true">
        <svg class="interaction-check" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5"/></svg>
      </div>
    </div>
  `

  setTimeout(() => {
    const qrContainer = document.getElementById(qrId)
    if (!qrContainer) return
    try {
      const qr = qrcode(0, 'M')
      qr.addData(qrUrl)
      qr.make()
      qrContainer.innerHTML = qr.createSvgTag({ scalable: true, margin: 0 })
    } catch (err) {
      qrContainer.textContent = `(QR generation failed: ${err.message})`
    }
  }, 0)

  return html
}

// ── Pending-bootstrap state (survives same-tab redirect to PS) ──

const PENDING_KEY = 'aauth-pending-bootstrap'

function savePendingBootstrap(state) {
  try { localStorage.setItem(PENDING_KEY, JSON.stringify({ ...state, startedAt: Date.now() })) } catch {}
}

function clearPendingBootstrap() {
  try { localStorage.removeItem(PENDING_KEY) } catch {}
}

// Idempotency guard — both app.js's init IIFE and the window-load fallback
// (below) call resumePendingInteraction; the second call is a safety net
// for environments where the IIFE silently no-ops after a redirect-back.
// Without this, we'd poll twice in parallel and race on /pending.
let _resumeInteractionPolling = false

async function resumePendingInteraction() {
  let saved
  try { saved = JSON.parse(localStorage.getItem(PENDING_KEY) || 'null') } catch { saved = null }
  if (!saved?.pollUrl) return false

  // Stale (>10 min) → give up. PS pending sessions expire ~5–10 min; a
  // pending older than that is almost always leftover from a prior tab
  // that was closed or a flow that errored past the poll. Reviving it
  // would re-consume an already-spent bootstrap_token and fail with
  // jti-replay at the agent server.
  if (Date.now() - (saved.startedAt || 0) > 10 * 60 * 1000) {
    clearPendingBootstrap()
    return false
  }
  const kp = window.aauthEphemeral.get()
  if (!kp) {
    clearPendingBootstrap()
    return false
  }

  if (_resumeInteractionPolling) return false
  _resumeInteractionPolling = true

  // Resumed bootstrap — log into the same fieldset as the original
  // startBootstrap run so the user sees the full round trip (go to PS,
  // return, mint agent token) in one contiguous section log.
  setActiveLog('bootstrap-log')
  showLog()
  addLogSection('Bootstrap (resumed)')
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey)
  const interactionStep = addLogStep('Resuming bootstrap interaction', 'pending',
    `<div class="token-display">Polling ${escapeHtml(saved.pollUrl)}</div>`
  )
  const pending = await pollForBootstrapToken(saved.pollUrl, kp, publicJwk, interactionStep)
  if (!pending) return true
  addLogStep('Bootstrap Token Received', 'success',
    formatToken('Bootstrap Token (aa-bootstrap+jwt)', pending.bootstrap_token, decodeJWTPayloadBrowser(pending.bootstrap_token))
  )
  await completeAgentServerBootstrap(pending.bootstrap_token, publicJwk, kp, { psUrl: saved.psUrl })
  // Bootstrap is a standalone flow now; don't auto-chain into /authorize.
  // The user clicks Continue when they're ready to authorize with their
  // chosen scopes.
  return true
}
window.resumePendingInteraction = resumePendingInteraction

// ── Pending-authorize state (survives same-tab redirect to wallet) ──

const PENDING_AUTHZ_KEY = 'aauth-pending-authorize'

function savePendingAuthorize(state) {
  try { localStorage.setItem(PENDING_AUTHZ_KEY, JSON.stringify({ ...state, startedAt: Date.now() })) } catch {}
}

function clearPendingAuthorize() {
  try { localStorage.removeItem(PENDING_AUTHZ_KEY) } catch {}
}

// Called on page load: if we have a persisted pending-authorize, resume
// polling the PS for auth_token. Mirrors resumePendingInteraction for
// bootstrap. Mounted after app.js init so ephemeral key + agent token
// are already restored.
async function resumePendingAuthorize() {
  let saved
  try { saved = JSON.parse(localStorage.getItem(PENDING_AUTHZ_KEY) || 'null') } catch { saved = null }
  if (!saved?.pollUrl) return false

  // 10-min freshness window — same rationale as pending-bootstrap.
  if (Date.now() - (saved.startedAt || 0) > 10 * 60 * 1000) {
    clearPendingAuthorize()
    return false
  }

  const keyPair = window.aauthEphemeral.get()
  const agentToken = localStorage.getItem('aauth-agent-token')
  if (!keyPair || !agentToken) {
    clearPendingAuthorize()
    return false
  }

  // Resumed authorize — pick up the log inside the Authorization
  // Request fieldset where the original Continue click logged.
  setActiveLog('authz-log')
  showLog()
  addLogSection('Authorization (resumed)')
  const interactionStep = addLogStep('Resuming authorize interaction', 'pending',
    `<div class="token-display">Polling ${escapeHtml(saved.pollUrl)}</div>`
  )
  startAuthTokenPolling(saved.pollUrl, saved.tokenEndpoint, interactionStep)
  return true
}
window.resumePendingAuthorize = resumePendingAuthorize

// ── Fallback resume trigger ──
//
// app.js's init IIFE calls window.resumePendingInteraction / Authorize after
// restoring binding + keypair. That path has silently no-op'd after some
// page-load timing shifts, leaving the playground blank after a same-tab
// redirect back from the PS. Fire the resume calls again on window 'load'
// so the behavior doesn't depend on the IIFE's good behavior. The resume
// functions guard against double-polling (see `_resumeInteractionPolling`)
// and staleness, so a redundant call here is a safe no-op.
function fireFallbackResume() {
  // Small delay so app.js has had a chance to set ephemeralKeyPair from IDB.
  setTimeout(() => {
    try { window.resumePendingInteraction?.() } catch (err) { console.error('[aauth] fallback resumePendingInteraction threw:', err) }
    try { window.resumePendingAuthorize?.() } catch (err) { console.error('[aauth] fallback resumePendingAuthorize threw:', err) }
  }, 200)
}
if (document.readyState === 'complete') {
  fireFallbackResume()
} else {
  window.addEventListener('load', fireFallbackResume, { once: true })
}

// ── Auth-token polling (for PS /token interaction flow) ──
//
// Same long-poll pattern as pollForBootstrapToken: send `Prefer: wait=30`
// and loop immediately on 202. Agent token + ephemeral key are snapshotted
// once at start; the polling is signed with sig=jwt using them.

async function startAuthTokenPolling(pollUrl, baseUrl, interactionStep) {
  const absolutePollUrl = new URL(pollUrl, baseUrl).href
  const keyPair = window.aauthEphemeral.get()
  const agentToken = localStorage.getItem('aauth-agent-token')
  if (!keyPair || !agentToken) return
  const signingJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)

  const pollPath = new URL(absolutePollUrl).pathname
  const pollStep = addLogStep(`GET ${pollPath} (long-poll)`, 'pending',
    `<p>Long-polling the PS pending URL for the auth_token. <code>Prefer: wait=30</code> asks the PS to hold the request for up to 30s; on 202 the client loops immediately.</p>` +
    formatRequest('GET', absolutePollUrl, {
      'Prefer': 'wait=30',
      'Signature-Input': 'sig=("@method" "@authority" "@path" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`,
    }, null)
  )

  while (true) {
    try {
      const res = await sigFetch(absolutePollUrl, {
        method: 'GET',
        headers: { Prefer: 'wait=30' },
        signingKey: signingJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: 'jwt', jwt: agentToken },
        components: ['@method', '@authority', '@path', 'signature-key'],
      })
      if (res.status === 200) {
        clearPendingAuthorize()
        const body = await res.json()
        resolveStep(pollStep, 'success', `GET ${pollPath} \u2192 200`)
        resolveStep(interactionStep, 'success', 'Interaction Completed')
        addLogStep('Authorization Granted', 'success',
          (body.auth_token ? formatAuthToken(body.auth_token) : '') +
          anotherRequestButton())
        // if (body.auth_token) await callDemoResourceApi(body.auth_token)
        return
      }
      if (res.status === 403 || res.status === 408) {
        clearPendingAuthorize()
        const body = await res.json().catch(() => null)
        const label = res.status === 403 ? 'Interaction Denied' : 'Interaction Timed Out'
        resolveStep(pollStep, 'error', `GET ${pollPath} \u2192 ${res.status}`)
        resolveStep(interactionStep, 'error', label)
        addLogStep(`Authorization ${res.status === 403 ? 'Denied' : 'Timed Out'}`, 'error',
          formatResponse(res.status, null, body) + anotherRequestButton())
        return
      }
      // 202 → loop immediately (server already held up to 30s)
    } catch (err) {
      console.log('Poll error:', err.message)
      await new Promise((r) => setTimeout(r, 5000))
    }
  }
}

function decodeJWTPayloadBrowser(jwt) {
  try {
    const parts = jwt.split('.')
    return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}

// ── Wire up Bootstrap + Continue buttons ──

document.getElementById('bootstrap-btn')?.addEventListener('click', startBootstrap)
document.getElementById('authz-btn').addEventListener('click', startAuthorize)

document.addEventListener('click', (e) => {
  const btn = e.target.closest('.js-scroll-authz')
  if (!btn) return
  // Clear the authz section's log but preserve binding / tokens — user
  // wants a fresh authorization flow, not a full reset.
  setActiveLog('authz-log')
  clearLog()
  const section = document.getElementById('authz-section')
  if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' })
})

// ── Close the loop: call the demo resource API with the minted auth_token ──
//
// Demonstrates that the playground.demo scope actually gates something. We
// present the auth_token as a bearer token to the playground's own
// /api/demo endpoint — the token is verified there against the PS's JWKS
// and must carry `playground.demo` in scope.

async function callDemoResourceApi(authToken) {
  const endpoint = `${window.location.origin}/api/demo`
  const keyPair = window.aauthEphemeral.get()
  if (!keyPair) {
    addLogStep('Demo API Call Failed', 'error',
      '<p>Missing ephemeral key — cannot sign /api/demo.</p>')
    return
  }
  const reqStep = addLogStep(`GET ${new URL(endpoint).pathname}`, 'pending',
    `<p>Calling the resource's demo endpoint. The request is signed per RFC 9421 with <code>sig=jwt;jwt="&lt;auth_token&gt;"</code>: the server verifies the HTTP signature against <code>auth_token.cnf.jwk</code> (our ephemeral), then separately verifies the auth_token itself against the PS JWKS and checks that <code>scope</code> covers <code>playground.demo</code>.</p>` +
    formatRequest('GET', endpoint, {
      'Signature-Input': 'sig=("@method" "@authority" "@path" "signature-key");created=...',
      'Signature': 'sig=:...:',
      'Signature-Key': `sig=jwt;jwt="${authToken?.substring(0, 20)}..."`,
    }, null)
  )
  try {
    const signingJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
    const res = await sigFetch(endpoint, {
      method: 'GET',
      signingKey: signingJwk,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: authToken },
      components: ['@method', '@authority', '@path', 'signature-key'],
    })
    const body = await res.json().catch(() => null)
    resolveStep(reqStep, res.ok ? 'success' : 'error', `GET /api/demo \u2192 ${res.status}`)
    addLogStep(
      res.ok ? 'Demo API Called' : 'Demo API Call Failed',
      res.ok ? 'success' : 'error',
      formatResponse(res.status, null, body) + anotherRequestButton(),
    )
  } catch (err) {
    resolveStep(reqStep, 'error', 'GET /api/demo (network error)')
    addLogStep('Demo API Call Failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>` + anotherRequestButton())
  }
}
window.aauthCallDemoResourceApi = callDemoResourceApi
