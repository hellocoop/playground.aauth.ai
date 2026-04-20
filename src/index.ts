import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { verify as httpSigVerify } from '@hellocoop/httpsig'
import type { Env, BootstrapTokenPayload, Binding, BootstrapTransaction, RefreshTransaction } from './types'
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
  webauthnRoutes,
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

// ── Scope metadata ──
//
// Per AAuth §12.2, scope is a property of the agent↔resource authorization
// (POST /authorize → resource_token.scope → auth_token.scope). This map is
// the single source of truth: the /.well-known/aauth-resource.json endpoint
// exposes it, the UI hydrates its checkboxes from it, and /authorize rejects
// any scope not listed here.
const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'Access your profile information',
  name: 'Access your full name',
  email: 'Access your email address',
  picture: 'Access your profile picture',
  nickname: 'Access your nickname',
  given_name: 'Access your given name',
  family_name: 'Access your family name',
  phone: 'Access your phone number',
  ethereum: 'Access your linked Ethereum wallet',
  discord: 'Access your linked Discord account',
  twitter: 'Access your linked Twitter account',
  github: 'Access your linked GitHub account',
  gitlab: 'Access your linked GitLab account',
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

// ── Session check (legacy /token path) ──

app.get('/session', async (c) => {
  const sessionId = c.req.header('X-Session-Id')
  if (!sessionId) return c.json({ valid: false }, 401)
  const sessionData = await c.env.WEBAUTHN_KV.get(`session:${sessionId}`, 'json') as any
  if (!sessionData) return c.json({ valid: false }, 401)
  return c.json({ valid: true, username: sessionData.username })
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
  const body = await c.req.json<{ bootstrap_token: string; ephemeral_jwk: JsonWebKey; agent_local?: string }>()
  if (!body.bootstrap_token || !body.ephemeral_jwk) {
    return c.json({ error: 'missing bootstrap_token or ephemeral_jwk' }, 400)
  }

  // Decode (unverified) to find the PS issuer before we trust the signature.
  const unverifiedPayload = decodeJWTPayload(body.bootstrap_token) as unknown as BootstrapTokenPayload
  if (!unverifiedPayload.iss || !unverifiedPayload.dwk) {
    return c.json({ error: 'bootstrap_token missing iss or dwk' }, 400)
  }

  // Fetch PS metadata to get its JWKS URI.
  let psJwks: { keys: JsonWebKey[] }
  let psMetadata: Record<string, unknown>
  try {
    const metaUrl = `${unverifiedPayload.iss}/.well-known/${unverifiedPayload.dwk}`
    const metaRes = await fetch(metaUrl)
    if (!metaRes.ok) return c.json({ error: `fetch PS metadata failed: ${metaRes.status}` }, 502)
    psMetadata = (await metaRes.json()) as Record<string, unknown>
    const jwksUri = psMetadata.jwks_uri as string | undefined
    if (!jwksUri) return c.json({ error: 'PS metadata missing jwks_uri' }, 502)
    const jwksRes = await fetch(jwksUri)
    if (!jwksRes.ok) return c.json({ error: `fetch PS JWKS failed: ${jwksRes.status}` }, 502)
    psJwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
  } catch (err) {
    return c.json({ error: `PS discovery error: ${(err as Error).message}` }, 502)
  }

  // Verify signature.
  let payload: BootstrapTokenPayload
  try {
    const res = await verifyJWT(body.bootstrap_token, psJwks)
    payload = res.payload as unknown as BootstrapTokenPayload
  } catch (err) {
    return c.json({ error: `bootstrap_token signature invalid: ${(err as Error).message}` }, 401)
  }

  // Claim checks.
  const origin = c.env.ORIGIN
  const now = Math.floor(Date.now() / 1000)
  if (payload.aud !== origin) return c.json({ error: `aud mismatch: expected ${origin}` }, 401)
  if (!payload.exp || payload.exp < now) return c.json({ error: 'bootstrap_token expired' }, 401)
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
  const body = await c.req.json<{ bootstrap_tx_id: string; webauthn_response: any }>()
  if (!body.bootstrap_tx_id || !body.webauthn_response) {
    return c.json({ error: 'missing bootstrap_tx_id or webauthn_response' }, 400)
  }

  const tx = (await c.env.WEBAUTHN_KV.get(`bootstrap_tx:${body.bootstrap_tx_id}`, 'json')) as BootstrapTransaction | null
  if (!tx) return c.json({ error: 'transaction not found or expired' }, 400)

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
// credential, new aauth_sub). Without this, a stale binding on the
// server forces the assert path forever and callers never see the
// register ceremony again.
//
// SECURITY NOTE: intentionally unauthenticated — the binding_key is a
// SHA-256 that only the owning client knows, and worst-case a leak just
// forces that user to re-bootstrap. Acceptable for a playground; would
// warrant an auth check in any real deployment.
app.post('/binding/forget', async (c) => {
  const body = await c.req.json<{ binding_key: string }>()
  if (!body.binding_key) return c.json({ error: 'missing binding_key' }, 400)
  await c.env.WEBAUTHN_KV.delete(`binding:${body.binding_key}`)
  return c.json({ ok: true })
})

// ── Refresh: step 1 (WebAuthn assertion challenge) ──
//
// Client already holds a binding_key from an earlier bootstrap. It rotates
// its ephemeral key and calls /refresh/challenge → /refresh/verify to mint
// fresh agent + resource tokens. No PS involvement.

app.post('/refresh/challenge', async (c) => {
  const body = await c.req.json<{ binding_key: string; new_ephemeral_jwk: JsonWebKey }>()
  if (!body.binding_key || !body.new_ephemeral_jwk) {
    return c.json({ error: 'missing binding_key or new_ephemeral_jwk' }, 400)
  }

  const binding = await getBinding(c.env, body.binding_key)
  if (!binding) return c.json({ error: 'binding not found' }, 404)

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
  const body = await c.req.json<{ refresh_tx_id: string; webauthn_response: any }>()
  if (!body.refresh_tx_id || !body.webauthn_response) {
    return c.json({ error: 'missing refresh_tx_id or webauthn_response' }, 400)
  }

  const tx = (await c.env.WEBAUTHN_KV.get(`refresh_tx:${body.refresh_tx_id}`, 'json')) as RefreshTransaction | null
  if (!tx) return c.json({ error: 'transaction not found or expired' }, 400)

  const binding = await getBinding(c.env, tx.binding_key)
  if (!binding) return c.json({ error: 'binding not found' }, 404)

  const origin = c.env.ORIGIN
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

// ── @deprecated Agent token issuance via session (pre-bootstrap path) ──
//
// DEPRECATED: retained for the legacy WebAuthn-login flow. New clients
// should use POST /bootstrap/challenge + /bootstrap/verify which issue
// the agent_token based on a PS-vouched bootstrap_token.

app.post('/token', async (c) => {
  // Verify the user is authenticated via WebAuthn session
  const sessionId = c.req.header('X-Session-Id')
  if (!sessionId) {
    return c.json({ error: 'missing session' }, 401)
  }

  const sessionData = await c.env.WEBAUTHN_KV.get(`session:${sessionId}`, 'json')
  if (!sessionData) {
    return c.json({ error: 'invalid session' }, 401)
  }

  // Parse the request — client sends its ephemeral public key
  const body = await c.req.json<{ ephemeral_jwk: JsonWebKey; agent_local?: string }>()
  if (!body.ephemeral_jwk) {
    return c.json({ error: 'missing ephemeral_jwk' }, 400)
  }

  const origin = c.env.ORIGIN
  const agentLocal = body.agent_local || 'playground'
  const domain = new URL(origin).hostname
  const sub = `aauth:${agentLocal}@${domain}`

  const privateKey = await importSigningKey(c.env.SIGNING_KEY)
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)

  const now = Math.floor(Date.now() / 1000)
  const header = {
    alg: 'EdDSA',
    typ: 'aa-agent+jwt',
    kid: publicJwk.kid,
  }
  const payload = {
    iss: origin,
    dwk: 'aauth-agent.json',
    sub,
    jti: generateJTI(),
    cnf: { jwk: sanitizeCnfJwk(body.ephemeral_jwk) },
    iat: now,
    exp: now + 3600, // 1 hour
  }

  const jwt = await signJWT(header, payload, privateKey)

  return c.json({
    agent_token: jwt,
    agent_id: sub,
    expires_in: 3600,
  })
})

// ── Authorization (resource token issuance) ──

app.post('/authorize', async (c) => {
  // Read the body as text — c.req.json() would consume the stream before
  // httpsig.verify() sees it (needed for content-digest when present).
  const rawBody = await c.req.text()

  // httpsig.verify extracts agent_token.cnf.jwk from Signature-Key and uses
  // it to verify the RFC 9421 signature. It does NOT verify the token's own
  // JWT signature — we do that separately below against our JWKS.
  const url = new URL(c.req.url)
  const sigResult = await httpSigVerify({
    method: c.req.method,
    authority: url.host,
    path: url.pathname,
    query: url.search.replace(/^\?/, ''),
    headers: c.req.raw.headers,
    body: rawBody,
  })
  if (!sigResult.verified) {
    return c.json({ error: `signature verification failed: ${sigResult.error || 'unknown'}` }, 401)
  }
  if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
    return c.json({ error: 'Signature-Key must use sig=jwt' }, 401)
  }

  // Verify the agent_token's JWT signature against our own JWKS — proves we
  // issued it. Together with the httpsig check above, this proves both that
  // the token is ours and that the caller holds the cnf-bound ephemeral key.
  const agentToken = sigResult.jwt.raw
  const origin = c.env.ORIGIN
  const ourJwk = await getPublicJWK(c.env.SIGNING_KEY)
  let agentPayload: Record<string, unknown>
  try {
    const { payload } = await verifyJWT(agentToken, { keys: [ourJwk] })
    agentPayload = payload as Record<string, unknown>
  } catch (err) {
    return c.json({ error: `agent_token invalid: ${(err as Error).message}` }, 401)
  }
  if (agentPayload.iss !== origin) return c.json({ error: 'agent_token iss mismatch' }, 401)
  const now = Math.floor(Date.now() / 1000)
  if (!agentPayload.exp || (agentPayload.exp as number) < now) return c.json({ error: 'agent_token expired' }, 401)

  // Now parse the body we already read.
  let body: { ps: string; scope: string }
  try {
    body = JSON.parse(rawBody) as { ps: string; scope: string }
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

// ── WebAuthn routes (legacy, backing /token) ──

app.route('/', webauthnRoutes())

export default app
