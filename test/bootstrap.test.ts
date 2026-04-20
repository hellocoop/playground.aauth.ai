import { describe, it, expect, beforeAll, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { fetch as sigFetch } from '@hellocoop/httpsig'
import { computeJwkThumbprint, decodeJWTPayload } from '../src/crypto'

beforeAll(() => {
  if (!(globalThis as any).crypto) {
    ;(globalThis as any).crypto = webcrypto as unknown as Crypto
  }
})

// ── Test fixtures ──

async function makeSigningKeyJson(): Promise<string> {
  const kp = (await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair
  const jwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey)
  return JSON.stringify(jwk)
}

class InMemoryKV {
  private store = new Map<string, string>()
  async get(key: string, type?: 'json'): Promise<unknown> {
    const v = this.store.get(key)
    if (!v) return null
    return type === 'json' ? JSON.parse(v) : v
  }
  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value)
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key)
  }
}

async function makeEnv(): Promise<{ env: any; kv: InMemoryKV }> {
  const kv = new InMemoryKV()
  const env = {
    ORIGIN: 'https://playground.test',
    AGENT_NAME: 'test-agent',
    SIGNING_KEY: await makeSigningKeyJson(),
    WEBAUTHN_KV: kv,
  }
  return { env, kv }
}

async function loadApp() {
  // Reset module registry so each test gets a fresh signing key env
  vi.resetModules()
  const mod = await import('../src/index')
  return mod.default
}

// Generate a PS keypair + issue a bootstrap_token + publish PS metadata/JWKS
// via a stubbed fetch. Returns everything the caller might need to assert.
async function mintBootstrapToken(opts: {
  iss: string
  aud: string
  sub: string
  ephemeralJwk: JsonWebKey
  exp?: number
  iat?: number
  scope?: string
  jti?: string
}): Promise<{
  token: string
  psPrivateKey: CryptoKey
  psPublicJwk: JsonWebKey
  psJwksKid: string
}> {
  const kp = (await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair
  const publicJwk = await webcrypto.subtle.exportKey('jwk', kp.publicKey)
  const kid = await computeJwkThumbprint(publicJwk)

  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'EdDSA', typ: 'aa-bootstrap+jwt', kid }
  // Strip WebCrypto-inserted fields from the cnf.jwk so the library's
  // verify sees the canonical RFC 7638 form (matches what a real PS would
  // embed, and what @hellocoop/httpsig expects to import for verify).
  const cnfJwk = opts.ephemeralJwk.kty === 'OKP'
    ? { kty: 'OKP', crv: opts.ephemeralJwk.crv, x: opts.ephemeralJwk.x }
    : opts.ephemeralJwk
  const payload = {
    iss: opts.iss,
    dwk: 'aauth-person.json',
    aud: opts.aud,
    sub: opts.sub,
    cnf: { jwk: cnfJwk },
    scope: opts.scope ?? 'openid profile',
    jti: opts.jti ?? `jti-${Math.random().toString(36).slice(2)}`,
    iat: opts.iat ?? now,
    exp: opts.exp ?? now + 300,
  }

  const enc = new TextEncoder()
  const b64 = (bytes: Uint8Array) => {
    let s = ''
    for (const b of bytes) s += String.fromCharCode(b)
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  const headerB64 = b64(enc.encode(JSON.stringify(header)))
  const payloadB64 = b64(enc.encode(JSON.stringify(payload)))
  const signingInput = `${headerB64}.${payloadB64}`
  const sig = await webcrypto.subtle.sign('Ed25519', kp.privateKey, enc.encode(signingInput))
  const token = `${signingInput}.${b64(new Uint8Array(sig))}`
  return { token, psPrivateKey: kp.privateKey, psPublicJwk: publicJwk, psJwksKid: kid }
}

function stubPsDiscovery(psOrigin: string, jwks: { keys: JsonWebKey[] }) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url === `${psOrigin}/.well-known/aauth-person.json`) {
        return new Response(
          JSON.stringify({
            issuer: psOrigin,
            jwks_uri: `${psOrigin}/.well-known/jwks.json`,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      }
      if (url === `${psOrigin}/.well-known/jwks.json`) {
        return new Response(JSON.stringify(jwks), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response('not found', { status: 404 })
    })
  )
}

async function makeEphemeral(): Promise<{ publicJwk: JsonWebKey; privateJwk: JsonWebKey }> {
  const kp = (await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair
  return {
    publicJwk: await webcrypto.subtle.exportKey('jwk', kp.publicKey),
    privateJwk: await webcrypto.subtle.exportKey('jwk', kp.privateKey),
  }
}

// Compute the headers a real client would attach to a signed request
// against the agent server, using sig=jwt with the given token. We use
// sigFetch's dryRun to hand us the Signature-Input / Signature /
// Signature-Key headers without actually firing the request — the test
// then replays them on app.request(...).
async function signedHeaders(opts: {
  url: string
  method: string
  body?: string
  jwt: string
  signingPublicJwk: JsonWebKey
  signingPrivateJwk: JsonWebKey
}): Promise<Record<string, string>> {
  const hasBody = opts.body !== undefined
  const components = hasBody
    ? ['@method', '@authority', '@path', 'content-type', 'signature-key']
    : ['@method', '@authority', '@path', 'signature-key']
  const reqHeaders: Record<string, string> = hasBody ? { 'Content-Type': 'application/json' } : {}
  // Match the pattern used by /authorize tests: pass the private JWK as
  // signingKey and let the library import it as a CryptoKey internally.
  const dry = await sigFetch(opts.url, {
    method: opts.method,
    headers: reqHeaders,
    body: hasBody ? opts.body : undefined,
    signingKey: opts.signingPrivateJwk,
    signatureKey: { type: 'jwt', jwt: opts.jwt },
    components,
    dryRun: true,
  }) as { headers: Headers }
  // Start empty — the sigFetch-returned Headers already include every
  // input header (lowercased) plus the signature triple. Merging
  // reqHeaders back on top adds a duplicate capitalized "Content-Type"
  // which Hono concatenates into "application/json, application/json",
  // breaking the content-type component in the signature base.
  const out: Record<string, string> = {}
  dry.headers.forEach((v, k) => { out[k] = v })
  return out
}

// ── Tests ──

describe('POST /bootstrap/challenge', () => {
  const ORIGIN = 'https://playground.test'
  const PS = 'https://ps.test'
  const TEST_URL = 'http://localhost/bootstrap/challenge'

  // Build a fully-wired valid request: bootstrap_token, matching ephemeral,
  // and RFC 9421 signature headers. Callers can tweak the result to
  // exercise individual failure modes.
  async function validRequest(env: any, opts: {
    sub?: string
    jti?: string
    iat?: number
    exp?: number
    aud?: string
    agentLocal?: string
  } = {}) {
    const eph = await makeEphemeral()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS,
      aud: opts.aud ?? ORIGIN,
      sub: opts.sub ?? 'pairwise-abc',
      ephemeralJwk: eph.publicJwk,
      iat: opts.iat,
      exp: opts.exp,
      jti: opts.jti,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const body = JSON.stringify({
      bootstrap_token: token,
      ephemeral_jwk: eph.publicJwk,
      agent_local: opts.agentLocal,
    })
    const headers = await signedHeaders({
      url: TEST_URL,
      method: 'POST',
      body,
      jwt: token,
      signingPublicJwk: eph.publicJwk,
      signingPrivateJwk: eph.privateJwk,
    })
    return { eph, token, body, headers }
  }

  // ── Signature-verification matrix ──

  it('(sig) valid signature → 200 happy path', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { body, headers } = await validRequest(env)

    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(200)
    const out = await res.json() as any
    expect(out.bootstrap_tx_id).toBeDefined()
    vi.unstubAllGlobals()
  })

  it('(sig) missing Signature-Key → 401', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { body } = await validRequest(env)
    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/signature verification failed/i)
    vi.unstubAllGlobals()
  })

  it('(sig) garbled signature bytes → 401', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { body, headers } = await validRequest(env)
    // Replace the signature bytes with random garbage but keep the header shape.
    const garbled = { ...headers, 'Signature': 'sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:' }
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers: garbled, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/signature verification failed/i)
    vi.unstubAllGlobals()
  })

  it('(sig) signed by attacker key (not cnf-bound) → 401', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { token, body } = await validRequest(env)
    // Sign with a different keypair — HTTP signature won't verify against
    // bootstrap_token.cnf.jwk.
    const attacker = await makeEphemeral()
    const attackerHeaders = await signedHeaders({
      url: TEST_URL,
      method: 'POST',
      body,
      jwt: token,
      signingPublicJwk: attacker.publicJwk,
      signingPrivateJwk: attacker.privateJwk,
    })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers: attackerHeaders, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/signature verification failed/i)
    vi.unstubAllGlobals()
  })

  it('(sig) signed Content-Type tampered after signing → 401', async () => {
    // The signature base covers content-type but NOT the body itself
    // (would need content-digest for that — tracked as a TODO; see
    // comment on `components` in signedHeaders). This test exercises the
    // coverage we DO have: if a signed header changes, verification
    // fails. Catches the "did httpsig actually run?" regression.
    const { env } = await makeEnv()
    const app = await loadApp()
    const { body, headers } = await validRequest(env)
    const tamperedHeaders = { ...headers, 'content-type': 'text/plain' }
    const res = await app.request('/bootstrap/challenge', {
      method: 'POST', headers: tamperedHeaders, body,
    }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/signature verification failed/i)
    vi.unstubAllGlobals()
  })

  // ── Claim / token semantics ──

  it('rejects missing fields (body) even with valid signature', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const eph = await makeEphemeral()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: eph.publicJwk,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })
    const body = JSON.stringify({})
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: token,
      signingPublicJwk: eph.publicJwk, signingPrivateJwk: eph.privateJwk,
    })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(400)
    vi.unstubAllGlobals()
  })

  it('rejects tampered bootstrap_token signature', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const eph = await makeEphemeral()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: eph.publicJwk,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })
    const parts = token.split('.')
    const tamperedToken = `${parts[0]}.${parts[1]}.AAAAAAAA`
    const body = JSON.stringify({ bootstrap_token: tamperedToken, ephemeral_jwk: eph.publicJwk })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: tamperedToken,
      signingPublicJwk: eph.publicJwk, signingPrivateJwk: eph.privateJwk,
    })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    vi.unstubAllGlobals()
  })

  it('rejects expired bootstrap_token', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const past = Math.floor(Date.now() / 1000) - 600
    const { body, headers } = await validRequest(env, { iat: past - 300, exp: past })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/expired/)
    vi.unstubAllGlobals()
  })

  it('rejects wrong aud', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { body, headers } = await validRequest(env, { aud: 'https://other-agent-server.test' })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/aud mismatch/)
    vi.unstubAllGlobals()
  })

  it('rejects when ephemeral_jwk does not match cnf.jwk', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    // Mint bootstrap_token bound to cnfEph, but send otherEph in the body.
    // httpsig verifies with cnfEph (which is what we sign with), so the HTTP
    // sig succeeds — but the agent server catches the mismatch between
    // body.ephemeral_jwk and bootstrap_token.cnf.jwk.
    const cnfEph = await makeEphemeral()
    const otherEph = await makeEphemeral()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: cnfEph.publicJwk,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })
    const body = JSON.stringify({ bootstrap_token: token, ephemeral_jwk: otherEph.publicJwk })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: token,
      signingPublicJwk: cnfEph.publicJwk, signingPrivateJwk: cnfEph.privateJwk,
    })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/ephemeral_jwk does not match/)
    vi.unstubAllGlobals()
  })

  it('rejects replayed jti', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { body, headers } = await validRequest(env, { jti: 'replay-me' })

    const first = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(first.status).toBe(200)

    const second = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    expect(second.status).toBe(401)
    expect((await second.json() as any).error).toMatch(/replay/)
    vi.unstubAllGlobals()
  })

  it('stashes a bootstrap transaction keyed by tx_id', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { body, headers } = await validRequest(env, { sub: 'pairwise-xyz' })

    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers, body }, env)
    const out = await res.json() as any
    const stored = (await kv.get(`bootstrap_tx:${out.bootstrap_tx_id}`, 'json')) as any
    expect(stored).toBeTruthy()
    expect(stored.ps_url).toBe(PS)
    expect(stored.user_sub).toBe('pairwise-xyz')
    // Per §12.2 scope is not a property of the binding — it must not be
    // stashed on the bootstrap transaction.
    expect(stored.scope).toBeUndefined()
    expect(stored.type).toBe('register')
    vi.unstubAllGlobals()
  })
})

describe('well-known metadata', () => {
  it('/.well-known/aauth-agent.json exposes bootstrap + refresh endpoints, name, logo_uri', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/.well-known/aauth-agent.json', {}, env)
    const body = await res.json() as any
    expect(body.bootstrap_endpoint).toBe('https://playground.test/bootstrap/challenge')
    expect(body.bootstrap_verify_endpoint).toBe('https://playground.test/bootstrap/verify')
    expect(body.refresh_endpoint).toBe('https://playground.test/refresh/challenge')
    expect(body.refresh_verify_endpoint).toBe('https://playground.test/refresh/verify')
    expect(body.name).toBe('test-agent')
    expect(body.logo_uri).toBeDefined()
  })
})
