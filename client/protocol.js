// ── Protocol flow and log display ──
// Depends on app.js globals: sessionId, agentToken, ephemeralKeyPair
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

function statusIndicator(status) {
  return status === 'success' ? '\u2713' : status === 'pending' ? '\u2026' : '\u2717'
}

function addLogStep(label, status, content) {
  const log = document.getElementById('protocol-log')
  const step = document.createElement('details')
  step.className = `log-step ${status}`
  step.open = true

  const summary = document.createElement('summary')
  summary.innerHTML = `<span class="step-label">${statusIndicator(status)} ${label}</span>`
  step.appendChild(summary)

  const body = document.createElement('div')
  body.style.marginTop = '0.5rem'
  body.innerHTML = content
  step.appendChild(body)

  log.appendChild(step)
  step.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  return step
}

// Update an existing step's status + label in place (instead of removing it).
// Lets a "pending" request entry stay visible after the response arrives, so
// the user can still expand and inspect what was sent.
function resolveStep(step, status, label) {
  if (!step) return
  step.className = `log-step ${status}`
  const labelSpan = step.querySelector('.step-label')
  if (labelSpan) labelSpan.textContent = `${statusIndicator(status)} ${label}`
}

function formatRequest(method, url, headers, body) {
  let html = `<div class="token-display">${escapeHtml(method)} ${escapeHtml(url)}\n`
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      html += `${escapeHtml(k)}: ${escapeHtml(v)}\n`
    }
  }
  if (body) {
    html += `\n${renderJSON(body)}`
  }
  html += '</div>'
  return html
}

function formatResponse(status, headers, body) {
  let html = `<div class="token-display">HTTP ${status}\n`
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      html += `${escapeHtml(k)}: ${escapeHtml(v)}\n`
    }
  }
  if (body) {
    html += `\n${renderJSON(body)}`
  }
  html += '</div>'
  return html
}

function formatToken(label, token, decoded) {
  return `
    <details>
      <summary class="detail-summary">${escapeHtml(label)}</summary>
      <div class="token-display encoded">${renderEncodedJWT(token)}</div>
    </details>
    <details open>
      <summary class="detail-summary">Decoded</summary>
      <div class="token-display">${renderJSON(decoded)}</div>
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

// ── Main authorization flow ──

async function startAuthorization() {
  // PS selection is owned by app.js (radio presets + custom URL with
  // localStorage persistence). It exposes getCurrentPS() on window.
  const psUrl = (window.getCurrentPS?.() || '').trim()
  if (!psUrl) {
    alert('Please choose or enter a Person Server URL')
    return
  }

  clearLog()
  showLog()

  const scope = getSelectedScopes()
  if (!scope) {
    addLogStep('Error', 'error', '<p>No scopes selected</p>')
    return
  }

  const hints = getHints()

  // Step 1+2: Call our server to validate PS and create resource token
  const authzReqStep = addLogStep('POST /authorize', 'pending',
    formatRequest('POST', '/authorize', { 'Content-Type': 'application/json' }, {
      ps: psUrl, scope, agent_token: '(agent token)'
    })
  )

  let authzData
  try {
    const res = await fetch('/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Id': sessionId,
      },
      body: JSON.stringify({ ps: psUrl, scope, agent_token: agentToken }),
    })
    authzData = await res.json()

    if (!res.ok) {
      resolveStep(authzReqStep, 'error', `POST /authorize \u2192 ${res.status}`)
      addLogStep('Authorization request failed', 'error',
        `<p style="color: var(--error)">${escapeHtml(authzData.error || 'Unknown error')}</p>` +
        (authzData.ps_metadata_url ? `<p>Tried: ${escapeHtml(authzData.ps_metadata_url)}</p>` : '')
      )
      return
    }
  } catch (err) {
    resolveStep(authzReqStep, 'error', 'POST /authorize (network error)')
    addLogStep('Network error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return
  }

  // Request succeeded — keep the request entry visible, finalize its status
  resolveStep(authzReqStep, 'success', 'POST /authorize \u2192 200')

  // Step 1: PS Discovery
  addLogStep('Discover Person Server', 'success',
    formatRequest('GET', authzData.ps_metadata_url, null, null) +
    '<label style="margin-top: 0.5rem;">Response</label>' +
    formatResponse(200, null, authzData.ps_metadata)
  )

  // Step 2: Resource Token
  addLogStep('Resource Token Created', 'success',
    formatToken('Resource Token (aa-resource+jwt)', authzData.resource_token, authzData.resource_token_decoded)
  )

  // Step 3: Call PS token endpoint
  const tokenEndpoint = authzData.ps_metadata.token_endpoint

  // Declare what we can do. The playground supports the interaction flow
  // (renders the AAuth-Requirement code/QR and polls Location). The
  // AAuth-Capabilities *header* is scoped to resource requests by the
  // spec (line 1731); for the direct PS path with no mission, the spec
  // doesn't define a transport, so we send capabilities as a body
  // parameter — without this the PS fails closed with "user_unreachable"
  // when the user has no registered mobile device.
  const psRequestBody = {
    resource_token: authzData.resource_token,
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

  // Sign the PS token request per RFC 9421 (HTTP Message Signatures) using
  // @hellocoop/httpsig. Components match the Wallet's REQUIRED_COMPONENTS
  // (svr/src/aauth/verify.js) — the library's DEFAULT_COMPONENTS_BODY also
  // includes content-type, which we omit here to keep signing minimal.
  // signingKey: public JWK for alg detection; signingCryptoKey: actual signer.
  try {
    const signingJwk = await crypto.subtle.exportKey('jwk', ephemeralKeyPair.publicKey)
    const psRes = await sigFetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(psRequestBody),
      signingKey: signingJwk,
      signingCryptoKey: ephemeralKeyPair.privateKey,
      signatureKey: { type: 'jwt', jwt: agentToken },
      components: ['@method', '@authority', '@path', 'signature-key'],
    })

    // Capture response headers we care about
    const responseHeaders = {}
    for (const key of ['location', 'retry-after', 'aauth-requirement']) {
      const val = psRes.headers.get(key)
      if (val) responseHeaders[key] = val
    }

    let psBody
    try {
      psBody = await psRes.json()
    } catch {
      psBody = null
    }

    // Resolve the request step in place (don't remove it — keep the
    // request body visible alongside whatever response steps follow).
    const psPath = new URL(tokenEndpoint).pathname
    const reqStatus = psRes.ok ? 'success' : 'error'
    resolveStep(psReqStep, reqStatus, `POST ${psPath} \u2192 ${psRes.status}`)

    if (psRes.status === 200 && psBody?.auth_token) {
      // Direct grant
      addLogStep('Authorization Granted', 'success',
        formatResponse(200, responseHeaders, psBody) +
        formatToken('Auth Token', psBody.auth_token,
          decodeJWTPayloadBrowser(psBody.auth_token))
      )
    } else if (psRes.status === 202) {
      // Interaction required. Per spec the PS sends `AAuth-Requirement:
      // requirement=interaction; url="..."; code="..."`, but real-world
      // PSes (Hellō wallet) put code/requirement/location in the JSON body
      // and rely on the agent finding the URL from PS metadata's
      // `interaction_endpoint`. Try header first, fall back to body.
      const reqHeader = psRes.headers.get('aauth-requirement') || ''
      const fromHeader = parseInteractionHeader(reqHeader)
      const interaction = {
        requirement: fromHeader.requirement || psBody?.requirement,
        code: fromHeader.code || psBody?.code,
        url: fromHeader.url || authzData.ps_metadata?.interaction_endpoint,
      }
      const pollUrl = psRes.headers.get('location') || psBody?.location

      const interactionStep = addLogStep('Interaction Required', 'pending',
        formatResponse(202, responseHeaders, psBody) +
        renderInteraction(interaction, pollUrl)
      )

      // Start polling if we have a poll URL
      if (pollUrl) {
        startPolling(pollUrl, tokenEndpoint, interactionStep)
      }
    } else {
      addLogStep('Person Server Response', psRes.ok ? 'success' : 'error',
        formatResponse(psRes.status, responseHeaders, psBody)
      )
    }
  } catch (err) {
    // Network/CORS failure — finalize the request step as error and add
    // a separate step with the diagnostic.
    const psPath = new URL(tokenEndpoint).pathname
    resolveStep(psReqStep, 'error', `POST ${psPath} (network error)`)

    const isCors = err instanceof TypeError && err.message.includes('fetch')
    addLogStep('Person Server Call Failed', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>` +
      (isCors ? '<p style="color: var(--muted); font-size: 0.85rem;">This may be a CORS issue. The Person Server must include Access-Control-Allow-Origin headers to allow browser requests.</p>' : '')
    )
  }
}

// ── Interaction handling ──

function parseInteractionHeader(header) {
  const result = {}
  // Parse: requirement=interaction; url="https://..."; code="ABCD1234"
  const parts = header.split(';').map(s => s.trim())
  for (const part of parts) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const key = part.substring(0, eq).trim()
    let val = part.substring(eq + 1).trim()
    // Remove quotes
    if (val.startsWith('"') && val.endsWith('"')) {
      val = val.slice(1, -1)
    }
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

  // Per spec: append `callback=<url>` so the PS redirects the user back
  // to the agent after consent. We use the playground's origin (no path)
  // — restoreInteractionState() reads the saved pending state on load and
  // resumes polling, no special callback handler is needed.
  const callbackUrl = `${window.location.origin}/`
  const fullUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}&callback=${encodeURIComponent(callbackUrl)}`
  const qrId = `qr-${Math.random().toString(36).slice(2, 9)}`

  const html = `
    <div class="interaction-box">
      <p>The Person Server requires user interaction.</p>
      <div class="interaction-code">${escapeHtml(interaction.code)}</div>
      <div class="interaction-actions">
        <a class="interaction-link" href="${escapeHtml(fullUrl)}">
          Open Person Server &rarr;
        </a>
        <code class="interaction-url">${escapeHtml(fullUrl)}</code>
      </div>
      <div class="qr-code" id="${qrId}"></div>
      <p class="qr-caption">Or scan with another device to continue</p>
    </div>
  `

  // Generate QR code after the element is in the DOM.
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

let pollInterval = null

// localStorage key used to remember an in-flight interaction across page
// navigations (so a same-tab redirect to the PS and back resumes polling).
const PENDING_KEY = 'aauth-pending-interaction'

function savePendingInteraction(absolutePollUrl, baseUrl) {
  try {
    localStorage.setItem(PENDING_KEY, JSON.stringify({
      pollUrl: absolutePollUrl,
      tokenEndpoint: baseUrl,
      startedAt: Date.now(),
    }))
  } catch { /* storage might be disabled */ }
}

function clearPendingInteraction() {
  try { localStorage.removeItem(PENDING_KEY) } catch {}
}

function startPolling(pollUrl, baseUrl, interactionStep) {
  if (pollInterval) clearInterval(pollInterval)

  // Resolve relative poll URL against the PS base
  const absolutePollUrl = new URL(pollUrl, baseUrl).href

  // Persist so we can resume after a same-tab redirect to the PS and back.
  savePendingInteraction(absolutePollUrl, baseUrl)

  pollInterval = setInterval(async () => {
    try {
      // Polls MUST be signed (RFC 9421 HTTP Message Signatures) with the
      // ephemeral key + agent-token Signature-Key, same as the POST to
      // the PS token endpoint. Wallet returns 401 (missing Signature-Input)
      // for unsigned polls.
      const signingJwk = await crypto.subtle.exportKey('jwk', ephemeralKeyPair.publicKey)
      const res = await sigFetch(absolutePollUrl, {
        method: 'GET',
        signingKey: signingJwk,
        signingCryptoKey: ephemeralKeyPair.privateKey,
        signatureKey: { type: 'jwt', jwt: agentToken },
        components: ['@method', '@authority', '@path', 'signature-key'],
      })

      if (res.status === 200) {
        clearInterval(pollInterval)
        pollInterval = null
        clearPendingInteraction()
        const body = await res.json()
        resolveStep(interactionStep, 'success', 'Interaction Completed')
        addLogStep('Authorization Granted', 'success',
          formatResponse(200, null, body) +
          (body.auth_token ? formatToken('Auth Token', body.auth_token,
            decodeJWTPayloadBrowser(body.auth_token)) : '')
        )
      } else if (res.status === 403) {
        clearInterval(pollInterval)
        pollInterval = null
        clearPendingInteraction()
        resolveStep(interactionStep, 'error', 'Interaction Denied')
        addLogStep('Authorization Denied', 'error',
          formatResponse(403, null, await res.json().catch(() => null)))
      } else if (res.status === 408) {
        clearInterval(pollInterval)
        pollInterval = null
        clearPendingInteraction()
        resolveStep(interactionStep, 'error', 'Interaction Timed Out')
        addLogStep('Authorization Timed Out', 'error',
          formatResponse(408, null, null))
      }
      // 202 = still pending, keep polling
    } catch (err) {
      // Network error during poll — keep trying
      console.log('Poll error:', err.message)
    }
  }, 5000)
}

// Resume a polling cycle that was started before the user navigated away
// to the PS for consent. Called from app.js after the session + agent
// token + ephemeral key have all been restored.
function resumePendingInteraction() {
  let saved
  try {
    saved = JSON.parse(localStorage.getItem(PENDING_KEY) || 'null')
  } catch { saved = null }
  if (!saved || !saved.pollUrl) return false

  // Stale (>1h) — agent token is gone anyway, drop it.
  if (Date.now() - (saved.startedAt || 0) > 3600 * 1000) {
    clearPendingInteraction()
    return false
  }

  // Need agent token + ephemeral key to sign the polls. If they aren't
  // restored yet (or ever), give up cleanly.
  if (!agentToken || !ephemeralKeyPair) {
    clearPendingInteraction()
    return false
  }

  showLog()
  const step = addLogStep('Resuming after Person Server interaction', 'pending',
    `<div class="token-display">Polling ${escapeHtml(saved.pollUrl)}</div>`
  )
  startPolling(saved.pollUrl, saved.tokenEndpoint, step)
  return true
}
window.resumePendingInteraction = resumePendingInteraction

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
