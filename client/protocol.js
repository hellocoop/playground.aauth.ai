// ── Protocol flow and log display ──
// Depends on app.js exposures via window: aauthBinding, aauthEphemeral,
// aauthApplyBootstrapResult, aauthWebAuthn, getCurrentPS.
// Built into public/protocol.js by esbuild; loaded as a classic script.

import { fetch as sigFetch } from '@hellocoop/httpsig'
import qrcode from 'qrcode-generator'

// ── Log rendering ──

function clearLog() {
  document.getElementById('protocol-log').innerHTML = ''
  document.getElementById('log-section').classList.add('hidden')
}

function showLog() {
  document.getElementById('log-section').classList.remove('hidden')
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

function addLogStep(label, status, content) {
  const log = document.getElementById('protocol-log')
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

// ── Scope collection ──

function getSelectedScopes() {
  const checkboxes = document.querySelectorAll('#authz-section input[type="checkbox"]:checked')
  return Array.from(checkboxes).map(cb => cb.value).join(' ')
}

function getHints() {
  const hints = {}
  const fields = ['login-hint', 'domain-hint', 'provider-hint', 'tenant']
  for (const field of fields) {
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
// /bootstrap/challenge → WebAuthn → /bootstrap/verify → agent_token +
// resource_token). Runs once per (PS, user) pair; the resulting binding_key
// is stored in localStorage so /refresh can reuse the same credentials.

async function runBootstrap(psUrl, scope, hints) {
  const agentServerOrigin = window.location.origin

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
    scope,
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
  const absolutePollUrl = new URL(pollUrl, bootstrapEndpoint).href
  const interactionStep = addLogStep('User Consent at Person Server', 'pending',
    formatResponse(psBootRes.status, responseHeaders, psBootBody) +
    renderInteraction(interactionParams, absolutePollUrl)
  )
  savePendingBootstrap({
    pollUrl: absolutePollUrl,
    bootstrapEndpoint,
    psUrl,
    scope,
  })

  const bootstrapToken = await pollForBootstrapToken(absolutePollUrl, keyPair, publicJwk, interactionStep)
  if (!bootstrapToken) return false

  addLogStep('Bootstrap Token Received', 'success',
    formatToken('Bootstrap Token (aa-bootstrap+jwt)', bootstrapToken, decodeJWTPayloadBrowser(bootstrapToken))
  )

  // Step 4: exchange with our own agent server /bootstrap/challenge.
  return await completeAgentServerBootstrap(bootstrapToken, publicJwk, keyPair)
}

// Poll the PS pending URL for the bootstrap_token. Polls are signed with
// the ephemeral key + sig=hwk (same key bound into the PS's record).
async function pollForBootstrapToken(absolutePollUrl, keyPair, publicJwk, interactionStep) {
  return new Promise((resolve) => {
    const intv = setInterval(async () => {
      try {
        const res = await sigFetch(absolutePollUrl, {
          method: 'GET',
          signingKey: publicJwk,
          signingCryptoKey: keyPair.privateKey,
          signatureKey: { type: 'hwk' },
          components: ['@method', '@authority', '@path', 'signature-key'],
        })
        if (res.status === 200) {
          clearInterval(intv)
          clearPendingBootstrap()
          const body = await res.json().catch(() => null)
          const token = body?.bootstrap_token
          if (!token) {
            resolveStep(interactionStep, 'error', 'Pending returned no bootstrap_token')
            addLogStep('Bad /pending response', 'error', formatResponse(200, null, body))
            resolve(null)
            return
          }
          resolveStep(interactionStep, 'success', 'User Consent Completed')
          resolve(token)
        } else if (res.status === 403) {
          clearInterval(intv)
          clearPendingBootstrap()
          resolveStep(interactionStep, 'error', 'Consent Denied')
          addLogStep('User denied consent', 'error',
            formatResponse(403, null, await res.json().catch(() => null)) + anotherRequestButton())
          resolve(null)
        } else if (res.status === 408) {
          clearInterval(intv)
          clearPendingBootstrap()
          resolveStep(interactionStep, 'error', 'Consent Timed Out')
          addLogStep('Interaction timed out', 'error',
            formatResponse(408, null, null) + anotherRequestButton())
          resolve(null)
        }
        // 202 = keep polling
      } catch (err) {
        console.log('Bootstrap poll error:', err.message)
      }
    }, 5000)
  })
}

async function completeAgentServerBootstrap(bootstrapToken, publicJwk, keyPair) {
  // POST /bootstrap/challenge. Server verifies bootstrap_token, returns
  // WebAuthn options + a transaction id tied to the already-validated claims.
  // Pass the generated three-word handle so the server can mint
  // aauth:{handle}@host on first bootstrap for this (PS, user). Ignored
  // on subsequent bootstraps — server uses the binding's stored aauth_sub.
  const agentLocal = localStorage.getItem('aauth-agent-name') || ''
  const challengeReqStep = addLogStep('POST /bootstrap/challenge', 'pending',
    formatRequest('POST', '/bootstrap/challenge', { 'Content-Type': 'application/json' }, {
      bootstrap_token: bootstrapToken.substring(0, 20) + '...',
      ephemeral_jwk: publicJwk,
      agent_local: agentLocal,
    })
  )

  let challengeData
  try {
    const res = await fetch('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: bootstrapToken, ephemeral_jwk: publicJwk, agent_local: agentLocal }),
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

  // POST /bootstrap/verify.
  const verifyStep = addLogStep('POST /bootstrap/verify', 'pending',
    formatRequest('POST', '/bootstrap/verify', { 'Content-Type': 'application/json' }, {
      bootstrap_tx_id: challengeData.bootstrap_tx_id,
      webauthn_response: '(credential)',
    })
  )

  let result
  try {
    const res = await fetch('/bootstrap/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bootstrap_tx_id: challengeData.bootstrap_tx_id,
        webauthn_response: webauthnResponse,
      }),
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
  addLogStep('Resource Token Minted', 'success',
    formatToken('Resource Token (aa-resource+jwt)', result.resource_token, result.resource_token_decoded)
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

async function runRefresh(scope) {
  const { bindingKey } = window.aauthBinding.get()
  if (!bindingKey) return null

  const { keyPair, publicJwk } = await window.aauthEphemeral.rotate()
  addLogStep('Generate ephemeral key', 'success',
    `<p>Rotated ephemeral Ed25519 keypair; new public key will be bound into the refreshed tokens.</p>` +
    tokenWrap(renderJSON(publicJwk))
  )

  const reqStep = addLogStep('POST /refresh/challenge', 'pending',
    formatRequest('POST', '/refresh/challenge', { 'Content-Type': 'application/json' }, {
      binding_key: bindingKey,
      new_ephemeral_jwk: publicJwk,
      scope,
    })
  )

  let challengeData
  try {
    const res = await fetch('/refresh/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ binding_key: bindingKey, new_ephemeral_jwk: publicJwk, scope }),
    })
    challengeData = await res.json()
    if (!res.ok) {
      resolveStep(reqStep, 'error', `POST /refresh/challenge \u2192 ${res.status}`)
      addLogStep('Refresh rejected', 'error', formatResponse(res.status, null, challengeData))
      // Binding is stale — drop it so the next Continue does a full bootstrap.
      window.aauthBinding.clearBinding()
      return null
    }
    resolveStep(reqStep, 'success', 'POST /refresh/challenge \u2192 200')
  } catch (err) {
    resolveStep(reqStep, 'error', 'POST /refresh/challenge (network error)')
    addLogStep('Refresh network error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
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
    return null
  }

  addLogStep('WebAuthn Assertion Completed', 'success',
    `<p>Browser returned a WebAuthn assertion against the stored credential for this binding.</p>`)

  const verifyStep = addLogStep('POST /refresh/verify', 'pending',
    formatRequest('POST', '/refresh/verify', { 'Content-Type': 'application/json' }, {
      refresh_tx_id: challengeData.refresh_tx_id,
      webauthn_response: '(assertion)',
    })
  )

  let result
  try {
    const res = await fetch('/refresh/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refresh_tx_id: challengeData.refresh_tx_id,
        webauthn_response: webauthnResponse,
      }),
    })
    result = await res.json()
    if (!res.ok) {
      resolveStep(verifyStep, 'error', `POST /refresh/verify \u2192 ${res.status}`)
      addLogStep('Refresh verify failed', 'error', formatResponse(res.status, null, result))
      return null
    }
    resolveStep(verifyStep, 'success', 'POST /refresh/verify \u2192 200')
  } catch (err) {
    resolveStep(verifyStep, 'error', 'POST /refresh/verify (network error)')
    addLogStep('Refresh verify network error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return null
  }

  window.aauthApplyBootstrapResult(result)
  addLogStep('Agent Token Refreshed', 'success',
    formatToken('Agent Token (aa-agent+jwt)', result.agent_token, decodeJWTPayloadBrowser(result.agent_token))
  )
  return result
}

// ── Main flow: Continue button ──
//
// Decides what to do based on current state:
//   no binding                         → full bootstrap
//   binding + valid agent_token        → /authorize with selected scope
//   binding + expired/missing token    → /refresh then /authorize

async function startAuthorization() {
  const psUrl = (window.getCurrentPS?.() || '').trim()
  if (!psUrl) {
    alert('Please choose or enter a Person Server URL')
    return
  }

  const scope = getSelectedScopes()
  if (!scope) {
    alert('Select at least one scope')
    return
  }

  clearLog()
  showLog()

  const hints = getHints()
  const { bindingKey, bindingPs } = window.aauthBinding.get()

  // If the user switched PS, the existing binding doesn't apply → full bootstrap.
  const haveUsableBinding = bindingKey && bindingPs === psUrl

  let agentTokenValid = false
  const savedAgentToken = localStorage.getItem('aauth-agent-token')
  if (savedAgentToken) {
    try {
      const p = decodeJWTPayloadBrowser(savedAgentToken)
      agentTokenValid = p && p.exp > Math.floor(Date.now() / 1000)
    } catch { /* invalid token */ }
  }

  if (!haveUsableBinding) {
    // Full bootstrap — also drops any stale binding/token.
    window.aauthBinding.clearBinding()
    localStorage.removeItem('aauth-agent-token')
    const ok = await runBootstrap(psUrl, scope, hints)
    if (!ok) return
  } else if (!agentTokenValid) {
    const refreshed = await runRefresh(scope)
    if (!refreshed) return
  }

  // At this point agent_token is valid and current (either freshly minted
  // or already valid). Now run the standard resource-token / PS /token flow.
  await runAuthorizationAgainstPS(psUrl, scope, hints)
}

async function runAuthorizationAgainstPS(psUrl, scope, hints) {
  const keyPair = window.aauthEphemeral.get()
  const agentToken = localStorage.getItem('aauth-agent-token')
  if (!agentToken || !keyPair) {
    addLogStep('Missing agent_token or ephemeral key', 'error',
      '<p>Bootstrap must complete before authorization.</p>')
    return
  }

  // Mint a fresh resource_token via /authorize for the currently selected
  // scope. /authorize now authenticates via agent_token signature (no
  // session required), which means every Continue click can request a
  // different scope against the same binding.
  const authzReqStep = addLogStep('POST /authorize', 'pending',
    formatRequest('POST', '/authorize', { 'Content-Type': 'application/json' }, {
      ps: psUrl, scope, agent_token: '(agent token)'
    })
  )
  let authzData
  try {
    const res = await fetch('/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ps: psUrl, scope, agent_token: agentToken }),
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
        formatResponse(200, responseHeaders, psBody) +
        formatToken('Auth Token', psBody.auth_token, decodeJWTPayloadBrowser(psBody.auth_token)) +
        anotherRequestButton()
      )
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
  const fullUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}&callback=${encodeURIComponent(callbackUrl)}`
  const qrId = `qr-${Math.random().toString(36).slice(2, 9)}`
  const urlId = nextCopyId()
  const html = `
    <div class="interaction-box">
      <p>The Person Server requires user interaction.</p>
      <div class="interaction-code">${escapeHtml(interaction.code)}</div>
      <div class="interaction-actions">
        <a class="interaction-link" href="${escapeHtml(fullUrl)}">Open Person Server</a>
        <div class="interaction-url-row">
          <code class="interaction-url" id="${urlId}">${escapeHtml(fullUrl)}</code>
          <button class="copy-btn" type="button" data-copy="${escapeHtml(fullUrl)}" aria-label="Copy"></button>
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
      qr.addData(fullUrl)
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

async function resumePendingInteraction() {
  let saved
  try { saved = JSON.parse(localStorage.getItem(PENDING_KEY) || 'null') } catch { saved = null }
  if (!saved?.pollUrl) return false

  // Stale (>1h) → give up. The ephemeral key we were using was rotated out too.
  if (Date.now() - (saved.startedAt || 0) > 3600 * 1000) {
    clearPendingBootstrap()
    return false
  }
  const kp = window.aauthEphemeral.get()
  if (!kp) {
    clearPendingBootstrap()
    return false
  }

  showLog()
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey)
  const interactionStep = addLogStep('Resuming bootstrap interaction', 'pending',
    `<div class="token-display">Polling ${escapeHtml(saved.pollUrl)}</div>`
  )
  const token = await pollForBootstrapToken(saved.pollUrl, kp, publicJwk, interactionStep)
  if (!token) return true
  addLogStep('Bootstrap Token Received', 'success',
    formatToken('Bootstrap Token (aa-bootstrap+jwt)', token, decodeJWTPayloadBrowser(token))
  )
  const res = await completeAgentServerBootstrap(token, publicJwk, kp)
  if (res) {
    await runAuthorizationAgainstPS(saved.psUrl, saved.scope || 'openid', {})
  }
  return true
}
window.resumePendingInteraction = resumePendingInteraction

// ── Auth-token polling (for scope-upgrade flows on PS /token) ──

function startAuthTokenPolling(pollUrl, baseUrl, interactionStep) {
  const absolutePollUrl = new URL(pollUrl, baseUrl).href
  const keyPair = window.aauthEphemeral.get()
  const agentToken = localStorage.getItem('aauth-agent-token')
  if (!keyPair || !agentToken) return
  const intv = setInterval(async () => {
    try {
      const signingJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
      const res = await sigFetch(absolutePollUrl, {
        method: 'GET',
        signingKey: signingJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: 'jwt', jwt: agentToken },
        components: ['@method', '@authority', '@path', 'signature-key'],
      })
      if (res.status === 200) {
        clearInterval(intv)
        const body = await res.json()
        resolveStep(interactionStep, 'success', 'Interaction Completed')
        addLogStep('Authorization Granted', 'success',
          formatResponse(200, null, body) +
          (body.auth_token ? formatToken('Auth Token', body.auth_token, decodeJWTPayloadBrowser(body.auth_token)) : '') +
          anotherRequestButton())
      } else if (res.status === 403 || res.status === 408) {
        clearInterval(intv)
        const body = await res.json().catch(() => null)
        const label = res.status === 403 ? 'Interaction Denied' : 'Interaction Timed Out'
        resolveStep(interactionStep, 'error', label)
        addLogStep(`Authorization ${res.status === 403 ? 'Denied' : 'Timed Out'}`, 'error',
          formatResponse(res.status, null, body) + anotherRequestButton())
      }
    } catch (err) {
      console.log('Poll error:', err.message)
    }
  }, 5000)
}

function decodeJWTPayloadBrowser(jwt) {
  try {
    const parts = jwt.split('.')
    return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}

// ── Wire up Continue button ──

document.getElementById('authz-btn').addEventListener('click', startAuthorization)

document.addEventListener('click', (e) => {
  const btn = e.target.closest('.js-scroll-authz')
  if (!btn) return
  const section = document.getElementById('authz-section')
  if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' })
})
