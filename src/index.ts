import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Env } from './types'
import { importSigningKey, getPublicJWK, signJWT, generateJTI, computeJwkThumbprint, decodeJWTPayload } from './crypto'
import { webauthnRoutes } from './webauthn'

type HonoEnv = { Bindings: Env }

const app = new Hono<HonoEnv>()

app.use('*', cors())

// ── Well-known endpoints ──

app.get('/.well-known/aauth-agent.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    client_name: c.env.AGENT_NAME,
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
    scope_descriptions: {
      openid: 'Verify your identity',
      profile: 'Access your profile information',
      email: 'Access your email address',
      phone: 'Access your phone number',
    },
  })
})

app.get('/.well-known/jwks.json', async (c) => {
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  return c.json({ keys: [publicJwk] })
})

// ── Session check ──

app.get('/session', async (c) => {
  const sessionId = c.req.header('X-Session-Id')
  if (!sessionId) return c.json({ valid: false }, 401)
  const sessionData = await c.env.WEBAUTHN_KV.get(`session:${sessionId}`, 'json') as any
  if (!sessionData) return c.json({ valid: false }, 401)
  return c.json({ valid: true, username: sessionData.username })
})

// ── Agent token issuance ──

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
    cnf: { jwk: body.ephemeral_jwk },
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
  // Verify session
  const sessionId = c.req.header('X-Session-Id')
  if (!sessionId) return c.json({ error: 'missing session' }, 401)
  const sessionData = await c.env.WEBAUTHN_KV.get(`session:${sessionId}`, 'json')
  if (!sessionData) return c.json({ error: 'invalid session' }, 401)

  const body = await c.req.json<{
    ps: string
    scope: string
    agent_token: string
  }>()

  if (!body.ps || !body.scope || !body.agent_token) {
    return c.json({ error: 'missing required fields: ps, scope, agent_token' }, 400)
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

  // Step 2: Create resource token
  const agentPayload = decodeJWTPayload(body.agent_token)
  const agentJkt = await computeJwkThumbprint(
    (agentPayload.cnf as { jwk: JsonWebKey }).jwk
  )

  const origin = c.env.ORIGIN
  const privateKey = await importSigningKey(c.env.SIGNING_KEY)
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)

  const now = Math.floor(Date.now() / 1000)
  const rtHeader = {
    alg: 'EdDSA',
    typ: 'aa-resource+jwt',
    kid: publicJwk.kid,
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

// ── WebAuthn routes ──

app.route('/', webauthnRoutes())

export default app
