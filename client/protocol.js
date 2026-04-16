// ── Protocol flow and log display ──
// Depends on app.js globals: sessionId, agentToken, ephemeralKeyPair
// Built into public/protocol.js by esbuild; loaded as a classic script.

import { fetch as sigFetch } from '@hellocoop/httpsig'

// ── Log rendering ──

function clearLog() {
  document.getElementById('protocol-log').innerHTML = ''
  document.getElementById('log-section').classList.add('hidden')
}

function showLog() {
  document.getElementById('log-section').classList.remove('hidden')
}

function addLogStep(label, status, content) {
  const log = document.getElementById('protocol-log')
  const step = document.createElement('details')
  step.className = `log-step ${status}`
  step.open = true

  const summary = document.createElement('summary')
  const indicator = status === 'success' ? '\u2713' : status === 'pending' ? '\u2026' : '\u2717'
  summary.innerHTML = `<span class="step-label">${indicator} ${label}</span>`
  step.appendChild(summary)

  const body = document.createElement('div')
  body.style.marginTop = '0.5rem'
  body.innerHTML = content
  step.appendChild(body)

  log.appendChild(step)
  step.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  return step
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
  const psUrl = document.getElementById('ps-url').value.trim()
  if (!psUrl) {
    alert('Please enter a Person Server URL')
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
  addLogStep('Requesting authorization...', 'pending',
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
      // Remove pending step, show error
      document.getElementById('protocol-log').lastChild.remove()
      addLogStep('Authorization request failed', 'error',
        `<p style="color: var(--error)">${escapeHtml(authzData.error || 'Unknown error')}</p>` +
        (authzData.ps_metadata_url ? `<p>Tried: ${escapeHtml(authzData.ps_metadata_url)}</p>` : '')
      )
      return
    }
  } catch (err) {
    document.getElementById('protocol-log').lastChild.remove()
    addLogStep('Network error', 'error',
      `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`)
    return
  }

  // Remove pending step, show completed steps
  document.getElementById('protocol-log').lastChild.remove()

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
  const psRequestBody = { resource_token: authzData.resource_token, ...hints }

  addLogStep('Calling Person Server...', 'pending',
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

    // Remove pending step
    document.getElementById('protocol-log').lastChild.remove()

    if (psRes.status === 200 && psBody?.auth_token) {
      // Direct grant
      addLogStep('Authorization Granted', 'success',
        formatResponse(200, responseHeaders, psBody) +
        formatToken('Auth Token', psBody.auth_token,
          decodeJWTPayloadBrowser(psBody.auth_token))
      )
    } else if (psRes.status === 202) {
      // Interaction required
      const reqHeader = psRes.headers.get('aauth-requirement') || ''
      const interaction = parseInteractionHeader(reqHeader)
      const pollUrl = psRes.headers.get('location')

      addLogStep('Interaction Required', 'pending',
        formatResponse(202, responseHeaders, psBody) +
        renderInteraction(interaction, pollUrl)
      )

      // Start polling if we have a poll URL
      if (pollUrl) {
        startPolling(pollUrl, tokenEndpoint)
      }
    } else {
      addLogStep('Person Server Response', psRes.ok ? 'success' : 'error',
        formatResponse(psRes.status, responseHeaders, psBody)
      )
    }
  } catch (err) {
    document.getElementById('protocol-log').lastChild.remove()

    // Check for CORS error (typically shows as TypeError: Failed to fetch)
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
    return '<p style="color: var(--muted);">Interaction required but no URL/code provided.</p>'
  }

  const fullUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}`

  let html = `
    <div class="interaction-box">
      <p>The Person Server requires user interaction.</p>
      <div class="interaction-code">${escapeHtml(interaction.code)}</div>
      <div id="qr-code"></div>
      <div style="margin-top: 0.75rem;">
        <a href="${escapeHtml(fullUrl)}" target="_blank" rel="noopener">
          <button>Go to Person Server</button>
        </a>
      </div>
    </div>
  `

  // Generate QR code after rendering (needs the DOM element)
  setTimeout(() => {
    const qrContainer = document.getElementById('qr-code')
    if (qrContainer && typeof qrcode !== 'undefined') {
      const qr = qrcode(0, 'M')
      qr.addData(fullUrl)
      qr.make()
      qrContainer.innerHTML = qr.createSvgTag(4)
    }
  }, 0)

  return html
}

let pollInterval = null

function startPolling(pollUrl, baseUrl) {
  if (pollInterval) clearInterval(pollInterval)

  // Resolve relative poll URL against the PS base
  const absolutePollUrl = new URL(pollUrl, baseUrl).href

  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(absolutePollUrl)

      if (res.status === 200) {
        clearInterval(pollInterval)
        pollInterval = null
        const body = await res.json()
        addLogStep('Authorization Granted', 'success',
          formatResponse(200, null, body) +
          (body.auth_token ? formatToken('Auth Token', body.auth_token,
            decodeJWTPayloadBrowser(body.auth_token)) : '')
        )
      } else if (res.status === 403) {
        clearInterval(pollInterval)
        pollInterval = null
        addLogStep('Authorization Denied', 'error',
          formatResponse(403, null, await res.json().catch(() => null)))
      } else if (res.status === 408) {
        clearInterval(pollInterval)
        pollInterval = null
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
