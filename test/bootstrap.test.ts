import { describe, it, expect, beforeAll, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
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
  const payload = {
    iss: opts.iss,
    dwk: 'aauth-person.json',
    aud: opts.aud,
    sub: opts.sub,
    cnf: { jwk: opts.ephemeralJwk },
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

async function makeEphemeralJwk(): Promise<JsonWebKey> {
  const kp = (await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair
  return await webcrypto.subtle.exportKey('jwk', kp.publicKey)
}

// ── Tests ──

describe('POST /bootstrap/challenge', () => {
  const ORIGIN = 'https://playground.test'
  const PS = 'https://ps.test'

  it('rejects missing fields', async () => {
    const app = await loadApp()
    const { env } = await makeEnv()
    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }, env)
    expect(res.status).toBe(400)
  })

  it('accepts a well-formed bootstrap_token and returns a WebAuthn challenge', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()

    const eph = await makeEphemeralJwk()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 'pairwise-abc', ephemeralJwk: eph,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: eph }),
    }, env)
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.bootstrap_tx_id).toBeDefined()
    expect(body.webauthn_type).toBe('register')
    expect(body.webauthn_options.challenge).toBeDefined()

    vi.unstubAllGlobals()
  })

  it('rejects tampered signature', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()

    const eph = await makeEphemeralJwk()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: eph,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    // Swap the signature with random bytes.
    const parts = token.split('.')
    const tampered = `${parts[0]}.${parts[1]}.AAAAAAAA`

    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: tampered, ephemeral_jwk: eph }),
    }, env)
    expect(res.status).toBe(401)
    vi.unstubAllGlobals()
  })

  it('rejects expired bootstrap_token', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()

    const eph = await makeEphemeralJwk()
    const past = Math.floor(Date.now() / 1000) - 600
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: eph, iat: past - 300, exp: past,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: eph }),
    }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/expired/)
    vi.unstubAllGlobals()
  })

  it('rejects wrong aud', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()

    const eph = await makeEphemeralJwk()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: 'https://other-agent-server.test', sub: 's', ephemeralJwk: eph,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: eph }),
    }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/aud mismatch/)
    vi.unstubAllGlobals()
  })

  it('rejects when ephemeral_jwk does not match cnf.jwk', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()

    const cnfEph = await makeEphemeralJwk()
    const otherEph = await makeEphemeralJwk()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: cnfEph,
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: otherEph }),
    }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/ephemeral_jwk does not match/)
    vi.unstubAllGlobals()
  })

  it('rejects replayed jti', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()

    const eph = await makeEphemeralJwk()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 's', ephemeralJwk: eph, jti: 'replay-me',
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const first = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: eph }),
    }, env)
    expect(first.status).toBe(200)

    const second = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: eph }),
    }, env)
    expect(second.status).toBe(401)
    expect((await second.json() as any).error).toMatch(/replay/)
    vi.unstubAllGlobals()
  })

  it('stashes a bootstrap transaction keyed by tx_id', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()

    const eph = await makeEphemeralJwk()
    const { token, psPublicJwk, psJwksKid } = await mintBootstrapToken({
      iss: PS, aud: ORIGIN, sub: 'pairwise-xyz', ephemeralJwk: eph, scope: 'openid email',
    })
    stubPsDiscovery(PS, { keys: [{ ...psPublicJwk, kid: psJwksKid }] })

    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: token, ephemeral_jwk: eph }),
    }, env)
    const body = await res.json() as any
    const stored = (await kv.get(`bootstrap_tx:${body.bootstrap_tx_id}`, 'json')) as any
    expect(stored).toBeTruthy()
    expect(stored.ps_url).toBe(PS)
    expect(stored.user_sub).toBe('pairwise-xyz')
    expect(stored.scope).toBe('openid email')
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
