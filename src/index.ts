import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Env, BootstrapTokenPayload, Binding, BootstrapTransaction, RefreshTransaction } from './types'
import { verifySigJwt, ourJwksVerifier, psJwksVerifier } from './httpsig-verify'
import {
  importSigningKey,
  getPublicJWK,
  signJWT,
  generateJTI,
  computeJwkThumbprint,
  decodeJWTPayload,
  verifyJWT,
  base64urlEncode,
  sanitizeCnfJwk,
} from './crypto'
import {
  deriveBindingKey,
  getBinding,
  putBinding,
  createRegistrationOptionsForBinding,
  createAuthenticationOptionsForBinding,
  verifyAndStoreRegistration,
  verifyAssertion,
} from './webauthn'

type HonoEnv = { Bindings: Env }

const app = new Hono<HonoEnv>()

app.use('*', cors())

// ── Resource scope metadata ──
//
// Resource scopes describe operations an agent can perform at this resource
// (the playground, wearing its resource hat). Identity scopes (openid,
// profile, email, ...) live on a different axis — those are requested at
// bootstrap and arrive back as named claims on the auth_token, not on the
// scope field. Only the values in this map are valid at /authorize.
const SCOPE_DESCRIPTIONS: Record<string, string> = {
  'playground.demo': 'Run the playground demo endpoint',
}

// ── Well-known endpoints ──

app.get('/.well-known/aauth-agent.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    client_name: c.env.AGENT_NAME,
    name: c.env.AGENT_NAME,
    logo_uri: c.env.AGENT_LOGO_URI ?? `${origin}/favicon.svg`,
    bootstrap_endpoint: `${origin}/bootstrap/challenge`,
    bootstrap_verify_endpoint: `${origin}/bootstrap/verify`,
    refresh_endpoint: `${origin}/refresh/challenge`,
    refresh_verify_endpoint: `${origin}/refresh/verify`,
    callback_endpoint: `${origin}/callback`,
    login_endpoint: `${origin}/login`,
    localhost_callback_allowed: true,
  })
})

app.get('/.well-known/aauth-resource.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    client_name: c.env.AGENT_NAME,
    authorization_endpoint: `${origin}/authorize`,
    scope_descriptions: SCOPE_DESCRIPTIONS,
  })
})

app.get('/.well-known/jwks.json', async (c) => {
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  return c.json({ keys: [publicJwk] })
})

// ── Bootstrap: step 1 (challenge) ──
//
// The agent has already completed a PS /bootstrap ceremony and holds a
// bootstrap_token whose cnf.jwk binds the agent's ephemeral key.
//
// We verify the token (signature via PS JWKS, aud, exp, jti replay, cnf
// matches ephemeral), look up or create the (ps_url, user_sub) binding,
// and return a WebAuthn challenge — register for new bindings, assert
// for existing ones. The transaction id ties the challenge to the already-
// validated bootstrap claims so /bootstrap/verify doesn't re-verify.
//
// SECURITY NOTE: attestation is required. This excludes platforms without
// WebAuthn platform authenticators — acknowledged gap, to be revisited.

app.post('/bootstrap/challenge', async (c) => {
  // The request is signed with sig=jwt;jwt=<bootstrap_token>. httpSigVerify
  // extracts bootstrap_token.cnf.jwk from Signature-Key and verifies the
  // RFC 9421 signature against it (the PS already bound this key to the
  // user at bootstrap consent), and we verify the bootstrap_token's own
  // JWT signature against the PS JWKS via psJwksVerifier.
  const verifyRes = await verifySigJwt(c, {
    verifyInner: psJwksVerifier(),
    // bootstrap_token has no iss constraint at this layer; we check aud
    // below explicitly. allowExpired is false so we reject expired tokens
    // via the exp check inside the helper.
  })
  if (verifyRes instanceof Response) return verifyRes

  const bootstrapToken = verifyRes.innerJwt
  const payload = verifyRes.innerPayload as unknown as BootstrapTokenPayload

  let body: { bootstrap_token: string; ephemeral_jwk: JsonWebKey; agent_local?: string }
  try {
    body = JSON.parse(verifyRes.rawBody)
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }
  if (!body.bootstrap_token || !body.ephemeral_jwk) {
    return c.json({ error: 'missing bootstrap_token or ephemeral_jwk' }, 400)
  }
  // Signature-Key JWT must equal body.bootstrap_token — they're the same
  // token, but belt-and-suspenders check: don't let a caller sign with one
  // token and submit a different one in the body.
  if (body.bootstrap_token !== bootstrapToken) {
    return c.json({ error: 'bootstrap_token mismatch between Signature-Key and body' }, 401)
  }

  // Claim checks.
  const origin = c.env.ORIGIN
  const now = Math.floor(Date.now() / 1000)
  if (payload.aud !== origin) return c.json({ error: `aud mismatch: expected ${origin}` }, 401)
  if (!payload.iat || payload.iat > now + 60) return c.json({ error: 'bootstrap_token not yet valid' }, 401)
  if (!payload.sub) return c.json({ error: 'bootstrap_token missing sub' }, 401)
  if (!payload.cnf?.jwk) return c.json({ error: 'bootstrap_token missing cnf.jwk' }, 401)
  if (!payload.jti) return c.json({ error: 'bootstrap_token missing jti' }, 401)

  // cnf.jwk must match the client-supplied ephemeral key.
  const cnfThumb = await computeJwkThumbprint(payload.cnf.jwk)
  const ephThumb = await computeJwkThumbprint(body.ephemeral_jwk)
  if (cnfThumb !== ephThumb) {
    return c.json({ error: 'ephemeral_jwk does not match bootstrap_token.cnf.jwk' }, 401)
  }

  // Replay guard (jti seen before).
  const jtiKey = `jti:${payload.jti}`
  const seen = await c.env.WEBAUTHN_KV.get(jtiKey)
  if (seen) return c.json({ error: 'bootstrap_token replayed' }, 401)
  const jtiTtl = Math.max(60, payload.exp - now)
  await c.env.WEBAUTHN_KV.put(jtiKey, '1', { expirationTtl: jtiTtl })

  // Derive binding key and look up existing binding.
  const bindingKey = await deriveBindingKey(payload.iss, payload.sub)
  const existing = await getBinding(c.env, bindingKey)

  const host = new URL(origin).hostname
  // First bootstrap for this (PS, user) picks up the client-supplied
  // agent_local (the generated three-word handle). Subsequent bootstraps
  // or refreshes reuse the stored aauth_sub so the identifier is stable
  // across devices and ephemeral-key rotations for the same binding.
  const agentLocal = sanitizeAgentLocal(body.agent_local)
  const aauthSub = existing?.aauth_sub ?? `aauth:${agentLocal}@${host}`

  const rpID = host
  const rpName = c.env.AGENT_NAME
  const displayName = `AAuth user (${new URL(payload.iss).host})`

  let type: 'register' | 'assert'
  let options: any
  if (!existing || existing.credentials.length === 0) {
    type = 'register'
    options = await createRegistrationOptionsForBinding(c.env, bindingKey, displayName, rpName, rpID)
  } else {
    type = 'assert'
    options = await createAuthenticationOptionsForBinding(c.env, existing, rpID)
  }

  // Stash the bootstrap transaction so /bootstrap/verify can mint tokens
  // without re-verifying the bootstrap_token.
  const tx: BootstrapTransaction = {
    binding_key: bindingKey,
    ps_url: payload.iss,
    user_sub: payload.sub,
    aauth_sub: aauthSub,
    ephemeral_jwk: body.ephemeral_jwk,
    challenge: options.challenge,
    type,
    created_at: Date.now(),
  }
  const txId = base64urlEncode(crypto.getRandomValues(new Uint8Array(24)))
  await c.env.WEBAUTHN_KV.put(`bootstrap_tx:${txId}`, JSON.stringify(tx), { expirationTtl: 300 })

  return c.json({
    bootstrap_tx_id: txId,
    webauthn_type: type,
    webauthn_options: options,
  })
})

// ── Bootstrap: step 2 (verify WebAuthn + mint tokens) ──

app.post('/bootstrap/verify', async (c) => {
  // Signed with sig=jwt;jwt=<bootstrap_token> — same scheme as /challenge.
  // Verify the HTTP signature, then cross-check that the signing token's
  // cnf.jwk matches the ephemeral stored in the transaction (ties this
  // call to the same key that just went through /challenge).
  const verifyRes = await verifySigJwt(c, {
    verifyInner: psJwksVerifier(),
  })
  if (verifyRes instanceof Response) return verifyRes

  let body: { bootstrap_tx_id: string; webauthn_response: any }
  try {
    body = JSON.parse(verifyRes.rawBody)
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }
  if (!body.bootstrap_tx_id || !body.webauthn_response) {
    return c.json({ error: 'missing bootstrap_tx_id or webauthn_response' }, 400)
  }

  const tx = (await c.env.WEBAUTHN_KV.get(`bootstrap_tx:${body.bootstrap_tx_id}`, 'json')) as BootstrapTransaction | null
  if (!tx) return c.json({ error: 'transaction not found or expired' }, 400)

  // The bootstrap_token's cnf.jwk must be the SAME ephemeral the tx was
  // keyed to at /challenge. Prevents someone with a different valid
  // bootstrap_token (for the same PS) from completing this /verify call.
  const tokenCnf = (verifyRes.innerPayload as any)?.cnf?.jwk
  if (!tokenCnf) return c.json({ error: 'bootstrap_token missing cnf.jwk' }, 401)
  const tokenThumb = await computeJwkThumbprint(tokenCnf)
  const txThumb = await computeJwkThumbprint(tx.ephemeral_jwk)
  if (tokenThumb !== txThumb) {
    return c.json({ error: 'bootstrap_token cnf does not match transaction' }, 401)
  }

  const origin = c.env.ORIGIN
  const rpID = new URL(origin).hostname

  try {
    if (tx.type === 'register') {
      const binding: Binding = (await getBinding(c.env, tx.binding_key)) ?? {
        ps_url: tx.ps_url,
        user_sub: tx.user_sub,
        aauth_sub: tx.aauth_sub,
        created_at: Date.now(),
        credentials: [],
      }
      await verifyAndStoreRegistration(c.env, origin, rpID, tx.challenge, body.webauthn_response, binding)
    } else {
      const binding = await getBinding(c.env, tx.binding_key)
      if (!binding) return c.json({ error: 'binding missing for assertion' }, 400)
      const { credential, newCounter } = await verifyAssertion(origin, rpID, tx.challenge, body.webauthn_response, binding)
      credential.counter = newCounter
      await putBinding(c.env, tx.binding_key, binding)
    }
  } catch (err) {
    return c.json({ error: `WebAuthn verification failed: ${(err as Error).message}` }, 401)
  }

  // Clean up single-use transaction + challenge.
  await c.env.WEBAUTHN_KV.delete(`bootstrap_tx:${body.bootstrap_tx_id}`)
  await c.env.WEBAUTHN_KV.delete(`challenge:${tx.challenge}`)

  return c.json(await mintAgentAndResource(c.env, {
    aauthSub: tx.aauth_sub,
    psUrl: tx.ps_url,
    ephemeralJwk: tx.ephemeral_jwk,
  }))
})

// ── Binding delete (playground Reset button) ──
//
// Lets the client drop its server-side binding so the next bootstrap for
// the same (PS, user) pair runs the full register path (fresh WebAuthn
// credential, new aauth_sub).
//
// Authenticated with sig=jwt;jwt=<agent_token>. The agent_token's sub
// must match the binding's aauth_sub — you can only forget your own.
app.post('/binding/forget', async (c) => {
  const ourJwk = await getPublicJWK(c.env.SIGNING_KEY)
  const origin = c.env.ORIGIN
  const verifyRes = await verifySigJwt(c, {
    verifyInner: ourJwksVerifier(ourJwk),
    expectedIss: origin,
    // Allow expired tokens — reset after your agent_token has lapsed is
    // the common case.
    allowExpired: true,
  })
  if (verifyRes instanceof Response) return verifyRes

  let body: { binding_key: string }
  try {
    body = JSON.parse(verifyRes.rawBody)
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }
  if (!body.binding_key) return c.json({ error: 'missing binding_key' }, 400)

  const binding = await getBinding(c.env, body.binding_key)
  // If already forgotten, no-op success (idempotent reset).
  if (!binding) return c.json({ ok: true })

  if (verifyRes.innerPayload?.sub !== binding.aauth_sub) {
    return c.json({ error: 'agent_token sub does not match binding' }, 401)
  }

  await c.env.WEBAUTHN_KV.delete(`binding:${body.binding_key}`)
  return c.json({ ok: true })
})

// ── Refresh: step 1 (WebAuthn assertion challenge) ──
//
// Client already holds a binding_key from an earlier bootstrap. It rotates
// its ephemeral key and calls /refresh/challenge → /refresh/verify to mint
// fresh agent + resource tokens. No PS involvement.

app.post('/refresh/challenge', async (c) => {
  // Signed with sig=jwt;jwt=<agent_token>. The agent_token may be expired
  // (that's the whole point of refresh), so allowExpired: true tells the
  // helper to skip its exp check. httpSigVerify still needs the signature
  // to verify against agent_token.cnf.jwk — proving PoP of the ephemeral.
  const ourJwk = await getPublicJWK(c.env.SIGNING_KEY)
  const origin = c.env.ORIGIN
  const verifyRes = await verifySigJwt(c, {
    verifyInner: ourJwksVerifier(ourJwk),
    expectedIss: origin,
    allowExpired: true,
  })
  if (verifyRes instanceof Response) return verifyRes

  let body: { binding_key: string; new_ephemeral_jwk: JsonWebKey }
  try {
    body = JSON.parse(verifyRes.rawBody)
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }
  if (!body.binding_key || !body.new_ephemeral_jwk) {
    return c.json({ error: 'missing binding_key or new_ephemeral_jwk' }, 400)
  }

  const binding = await getBinding(c.env, body.binding_key)
  if (!binding) return c.json({ error: 'binding not found' }, 404)

  // Agent_token's sub must match the binding's aauth_sub — you can only
  // refresh your own binding.
  if (verifyRes.innerPayload?.sub !== binding.aauth_sub) {
    return c.json({ error: 'agent_token sub does not match binding' }, 401)
  }

  const rpID = new URL(c.env.ORIGIN).hostname
  const options = await createAuthenticationOptionsForBinding(c.env, binding, rpID)

  const tx: RefreshTransaction = {
    binding_key: body.binding_key,
    new_ephemeral_jwk: body.new_ephemeral_jwk,
    challenge: options.challenge,
    created_at: Date.now(),
  }
  const txId = base64urlEncode(crypto.getRandomValues(new Uint8Array(24)))
  await c.env.WEBAUTHN_KV.put(`refresh_tx:${txId}`, JSON.stringify(tx), { expirationTtl: 300 })

  return c.json({
    refresh_tx_id: txId,
    webauthn_options: options,
  })
})

app.post('/refresh/verify', async (c) => {
  // Signed with sig=jwt;jwt=<agent_token>, same shape as /challenge.
  // allowExpired: true for the same reason.
  const ourJwk = await getPublicJWK(c.env.SIGNING_KEY)
  const origin = c.env.ORIGIN
  const verifyRes = await verifySigJwt(c, {
    verifyInner: ourJwksVerifier(ourJwk),
    expectedIss: origin,
    allowExpired: true,
  })
  if (verifyRes instanceof Response) return verifyRes

  let body: { refresh_tx_id: string; webauthn_response: any }
  try {
    body = JSON.parse(verifyRes.rawBody)
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }
  if (!body.refresh_tx_id || !body.webauthn_response) {
    return c.json({ error: 'missing refresh_tx_id or webauthn_response' }, 400)
  }

  const tx = (await c.env.WEBAUTHN_KV.get(`refresh_tx:${body.refresh_tx_id}`, 'json')) as RefreshTransaction | null
  if (!tx) return c.json({ error: 'transaction not found or expired' }, 400)

  const binding = await getBinding(c.env, tx.binding_key)
  if (!binding) return c.json({ error: 'binding not found' }, 404)

  // Agent_token's sub must match the binding we're refreshing.
  if (verifyRes.innerPayload?.sub !== binding.aauth_sub) {
    return c.json({ error: 'agent_token sub does not match binding' }, 401)
  }

  const rpID = new URL(origin).hostname

  try {
    const { credential, newCounter } = await verifyAssertion(origin, rpID, tx.challenge, body.webauthn_response, binding)
    credential.counter = newCounter
    await putBinding(c.env, tx.binding_key, binding)
  } catch (err) {
    return c.json({ error: `WebAuthn verification failed: ${(err as Error).message}` }, 401)
  }

  await c.env.WEBAUTHN_KV.delete(`refresh_tx:${body.refresh_tx_id}`)
  await c.env.WEBAUTHN_KV.delete(`challenge:${tx.challenge}`)

  return c.json(await mintAgentAndResource(c.env, {
    aauthSub: binding.aauth_sub,
    psUrl: binding.ps_url,
    ephemeralJwk: tx.new_ephemeral_jwk,
  }))
})

// Constrain the client-supplied agent_local to a conservative shape so
// it's safe to splice into the aauth identifier without escaping. Matches
// the three-word-handle format generated in public/app.js.
function sanitizeAgentLocal(input: string | undefined): string {
  const fallback = 'agent'
  if (!input) return fallback
  const cleaned = input.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 64)
  return cleaned.length > 0 ? cleaned : fallback
}

// ── Token minting helper ──

async function mintAgentAndResource(
  env: Env,
  args: { aauthSub: string; psUrl: string; ephemeralJwk: JsonWebKey }
): Promise<{ agent_token: string; agent_id: string; expires_in: number; resource_token: string; resource_token_decoded: Record<string, unknown>; ps: string }> {
  const origin = env.ORIGIN
  const privateKey = await importSigningKey(env.SIGNING_KEY)
  const publicJwk = await getPublicJWK(env.SIGNING_KEY)
  const now = Math.floor(Date.now() / 1000)

  const agentHeader = { alg: 'EdDSA', typ: 'aa-agent+jwt', kid: publicJwk.kid }
  const agentPayload = {
    iss: origin,
    dwk: 'aauth-agent.json',
    sub: args.aauthSub,
    ps: args.psUrl,
    jti: generateJTI(),
    cnf: { jwk: sanitizeCnfJwk(args.ephemeralJwk) },
    iat: now,
    exp: now + 3600,
  }
  const agentToken = await signJWT(agentHeader, agentPayload, privateKey)

  // No `scope` claim here. Per AAuth §12.2 scope is a property of the
  // agent↔resource authorization, not the agent↔PS binding. Bootstrap and
  // refresh mint an identity-only resource_token; the authorization scope
  // is chosen per-request at POST /authorize.
  const resourceHeader = { alg: 'EdDSA', typ: 'aa-resource+jwt', kid: publicJwk.kid }
  const resourcePayload = {
    iss: origin,
    dwk: 'aauth-resource.json',
    aud: args.psUrl,
    jti: generateJTI(),
    agent: args.aauthSub,
    agent_jkt: await computeJwkThumbprint(args.ephemeralJwk),
    iat: now,
    exp: now + 300,
  }
  const resourceToken = await signJWT(resourceHeader, resourcePayload, privateKey)

  return {
    agent_token: agentToken,
    agent_id: args.aauthSub,
    expires_in: 3600,
    resource_token: resourceToken,
    resource_token_decoded: resourcePayload,
    ps: args.psUrl,
  }
}

// ── Authorization (resource token issuance) ──

app.post('/authorize', async (c) => {
  // sig=jwt;jwt=<agent_token>. Verify the HTTP signature against
  // agent_token.cnf.jwk, then verify the agent_token itself against our
  // own JWKS — proves both that the token is ours and that the caller
  // holds the cnf-bound ephemeral.
  const ourJwk = await getPublicJWK(c.env.SIGNING_KEY)
  const origin = c.env.ORIGIN
  const verifyRes = await verifySigJwt(c, {
    verifyInner: ourJwksVerifier(ourJwk),
    expectedIss: origin,
  })
  if (verifyRes instanceof Response) return verifyRes

  const agentToken = verifyRes.innerJwt
  const agentPayload = verifyRes.innerPayload as Record<string, unknown>

  let body: { ps: string; scope: string }
  try {
    body = JSON.parse(verifyRes.rawBody) as { ps: string; scope: string }
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }

  if (!body.ps || !body.scope) {
    return c.json({ error: 'missing required fields: ps, scope' }, 400)
  }

  // Per §12.2, resource_token.scope MUST only contain values the resource
  // advertises in its scope_descriptions. Reject unknowns before we sign.
  const requestedScopes = body.scope.trim().split(/\s+/).filter(Boolean)
  const unknown = requestedScopes.filter((s) => !(s in SCOPE_DESCRIPTIONS))
  if (unknown.length > 0) {
    return c.json({ error: 'invalid_scope', unknown }, 400)
  }

  // Validate PS URL is HTTPS
  let psUrl: URL
  try {
    psUrl = new URL(body.ps)
    if (psUrl.protocol !== 'https:') {
      return c.json({ error: 'PS URL must be HTTPS' }, 400)
    }
  } catch {
    return c.json({ error: 'invalid PS URL' }, 400)
  }

  // Step 1: Fetch and validate PS metadata
  let psMetadata: Record<string, unknown>
  const psMetadataUrl = `${psUrl.origin}/.well-known/aauth-person.json`
  try {
    const psRes = await fetch(psMetadataUrl)
    if (!psRes.ok) {
      return c.json({
        error: `Failed to fetch PS metadata: ${psRes.status}`,
        ps_metadata_url: psMetadataUrl,
      }, 502)
    }
    psMetadata = await psRes.json() as Record<string, unknown>
  } catch (err) {
    return c.json({
      error: `Cannot reach PS: ${(err as Error).message}`,
      ps_metadata_url: psMetadataUrl,
    }, 502)
  }

  // Validate required PS metadata fields
  if (!psMetadata.issuer || !psMetadata.token_endpoint || !psMetadata.jwks_uri) {
    return c.json({
      error: 'PS metadata missing required fields (issuer, token_endpoint, jwks_uri)',
      ps_metadata: psMetadata,
    }, 502)
  }

  // Step 2: Create resource token.
  const agentJkt = await computeJwkThumbprint(
    (agentPayload.cnf as { jwk: JsonWebKey }).jwk
  )

  const privateKey = await importSigningKey(c.env.SIGNING_KEY)

  const now = Math.floor(Date.now() / 1000)
  const rtHeader = {
    alg: 'EdDSA',
    typ: 'aa-resource+jwt',
    kid: ourJwk.kid,
  }
  const rtPayload = {
    iss: origin,
    dwk: 'aauth-resource.json',
    aud: psMetadata.issuer as string,
    jti: generateJTI(),
    agent: agentPayload.sub as string,
    agent_jkt: agentJkt,
    scope: body.scope,
    iat: now,
    exp: now + 300, // 5 minutes
  }

  const resourceToken = await signJWT(rtHeader, rtPayload, privateKey)

  return c.json({
    ps_metadata: psMetadata,
    ps_metadata_url: psMetadataUrl,
    resource_token: resourceToken,
    resource_token_decoded: rtPayload,
  })
})

// ── Resource API: /api/demo ──
//
// The resource endpoint gated by `playground.demo`. An agent calls this with
// an auth_token issued by the PS; we verify the token, check the scope, and
// echo back a greeting using identity claims the PS placed on the token.
// Keeps the demo honest — the user sees a scope go end-to-end and actually
// gate something, rather than hanging unused in a consent screen.
app.get('/api/demo', async (c) => {
  // sig=jwt;jwt=<auth_token>. httpSigVerify extracts auth_token.cnf.jwk
  // from Signature-Key and verifies the RFC 9421 signature — proving
  // possession of the ephemeral. psJwksVerifier fetches the auth_token's
  // issuer JWKS (the PS) and verifies the token's own JWT signature.
  const origin = c.env.ORIGIN
  const verifyRes = await verifySigJwt(c, {
    verifyInner: psJwksVerifier(),
  })
  if (verifyRes instanceof Response) return verifyRes

  const payload = verifyRes.innerPayload as Record<string, unknown>
  if (payload.aud !== origin) return c.json({ error: 'auth_token aud mismatch' }, 401)

  const scopeStr = typeof payload.scope === 'string' ? payload.scope : ''
  const scopes = scopeStr.split(/\s+/).filter(Boolean)
  if (!scopes.includes('playground.demo')) {
    return c.json({ error: 'insufficient_scope', required: 'playground.demo', granted: scopes }, 403)
  }

  const name = (payload.name as string) || (payload.given_name as string) || 'friend'
  return c.json({
    hello: name,
    granted_scopes: scopes,
    identity_claims_present: {
      name: typeof payload.name === 'string',
      email: typeof payload.email === 'string',
      picture: typeof payload.picture === 'string',
    },
  })
})

export default app
