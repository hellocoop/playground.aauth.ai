import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Env } from './types'
import { importSigningKey, getPublicJWK, signJWT, generateJTI, computeJwkThumbprint } from './crypto'
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

app.get('/.well-known/jwks.json', async (c) => {
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  return c.json({ keys: [publicJwk] })
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

// ── WebAuthn routes ──

app.route('/', webauthnRoutes())

// ── Static UI ──

app.get('/', (c) => {
  return c.redirect('/index.html')
})

export default app
