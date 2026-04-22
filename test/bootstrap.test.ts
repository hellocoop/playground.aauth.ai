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

  // Build a fully-wired valid request: bootstrap_token in Signature-Key,
  // empty body, RFC 9421 signature headers. Callers can tweak the result
  // to exercise individual failure modes. The challenge endpoint takes
  // an empty body — bootstrap_token rides in Signature-Key, ephemeral
  // is bound by cnf, and agent_local is minted server-side.
  async function validRequest(_env: any, opts: {
    sub?: string
    jti?: string
    iat?: number
    exp?: number
    aud?: string
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

    const headers = await signedHeaders({
      url: TEST_URL,
      method: 'POST',
      jwt: token,
      signingPublicJwk: eph.publicJwk,
      signingPrivateJwk: eph.privateJwk,
    })
    return { eph, token, body: undefined as string | undefined, headers }
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
    await validRequest(env)
    const res = await app.request('/bootstrap/challenge', {
      method: 'POST',
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

  // ── Claim / token semantics ──

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
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', jwt: tamperedToken,
      signingPublicJwk: eph.publicJwk, signingPrivateJwk: eph.privateJwk,
    })
    const res = await app.request('/bootstrap/challenge', { method: 'POST', headers }, env)
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

// ── /refresh tests ──
//
// Setup helper: seed a binding in KV and mint an agent_token whose
// cnf.jwk is the ephemeral we'll sign with. Lets each test focus on the
// signature/authorization check without rebuilding the full bootstrap
// ceremony.

async function setupBinding(env: any, kv: any, opts: { aauthSub: string; psUrl: string } = { aauthSub: 'aauth:test@playground.test', psUrl: 'https://ps.test' }) {
  const { computeJwkThumbprint } = await import('../src/crypto')
  const kp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
  const publicJwk = await webcrypto.subtle.exportKey('jwk', kp.publicKey)
  const privateJwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey)

  // Sign an agent_token with the env's SIGNING_KEY.
  const serverJwk = JSON.parse(env.SIGNING_KEY)
  const serverKey = await webcrypto.subtle.importKey('jwk', serverJwk, { name: 'Ed25519' }, false, ['sign'])
  const { d: _d, ...serverPub } = serverJwk as any
  const serverKid = await computeJwkThumbprint(serverPub)
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'EdDSA', typ: 'aa-agent+jwt', kid: serverKid }
  const payload = {
    iss: env.ORIGIN,
    dwk: 'aauth-agent.json',
    sub: opts.aauthSub,
    ps: opts.psUrl,
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    cnf: { jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x } },
    iat: now,
    exp: now + 3600,
  }
  const enc = new TextEncoder()
  const b64 = (bytes: Uint8Array) => {
    let s = ''
    for (const b of bytes) s += String.fromCharCode(b)
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  const hB = b64(enc.encode(JSON.stringify(header)))
  const pB = b64(enc.encode(JSON.stringify(payload)))
  const sig = await webcrypto.subtle.sign('Ed25519', serverKey, enc.encode(`${hB}.${pB}`))
  const agentToken = `${hB}.${pB}.${b64(new Uint8Array(sig))}`

  // Seed the binding in KV.
  const userSub = 'pairwise-test'
  const encoder = new TextEncoder()
  const hash = await webcrypto.subtle.digest('SHA-256', encoder.encode(`${opts.psUrl}|${userSub}`))
  const bindingKey = b64(new Uint8Array(hash))
  await kv.put(`binding:${bindingKey}`, JSON.stringify({
    ps_url: opts.psUrl,
    user_sub: userSub,
    aauth_sub: opts.aauthSub,
    created_at: Date.now(),
    credentials: [], // empty — /refresh/challenge doesn't need one; /refresh/verify would
  }))

  return { agentToken, publicJwk, privateJwk, bindingKey, aauthSub: opts.aauthSub }
}

describe('POST /refresh/challenge', () => {
  const TEST_URL = 'http://localhost/refresh/challenge'

  it('(sig) valid signature → 200', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { agentToken, publicJwk, privateJwk, bindingKey } = await setupBinding(env, kv)
    const newEph = await makeEphemeral()
    const body = JSON.stringify({ binding_key: bindingKey, new_ephemeral_jwk: newEph.publicJwk })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: agentToken,
      signingPublicJwk: publicJwk, signingPrivateJwk: privateJwk,
    })
    const res = await app.request('/refresh/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(200)
    const out = await res.json() as any
    expect(out.refresh_tx_id).toBeDefined()
  })

  it('(sig) missing Signature-Key → 401', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { bindingKey } = await setupBinding(env, kv)
    const newEph = await makeEphemeral()
    const res = await app.request('/refresh/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ binding_key: bindingKey, new_ephemeral_jwk: newEph.publicJwk }),
    }, env)
    expect(res.status).toBe(401)
  })

  it('(sig) signed by attacker key → 401', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { agentToken, bindingKey } = await setupBinding(env, kv)
    const attacker = await makeEphemeral()
    const newEph = await makeEphemeral()
    const body = JSON.stringify({ binding_key: bindingKey, new_ephemeral_jwk: newEph.publicJwk })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: agentToken,
      signingPublicJwk: attacker.publicJwk, signingPrivateJwk: attacker.privateJwk,
    })
    const res = await app.request('/refresh/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
  })

  it('accepts expired agent_token (refresh is for post-expiry renewal)', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    // Build a binding and mint an expired agent_token bound to a key we hold.
    const { computeJwkThumbprint } = await import('../src/crypto')
    const kp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
    const publicJwk = await webcrypto.subtle.exportKey('jwk', kp.publicKey)
    const privateJwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey)
    const serverJwk = JSON.parse(env.SIGNING_KEY)
    const serverKey = await webcrypto.subtle.importKey('jwk', serverJwk, { name: 'Ed25519' }, false, ['sign'])
    const { d: _d, ...serverPub } = serverJwk as any
    const serverKid = await computeJwkThumbprint(serverPub)
    const past = Math.floor(Date.now() / 1000) - 600
    const header = { alg: 'EdDSA', typ: 'aa-agent+jwt', kid: serverKid }
    const aauthSub = 'aauth:expired@playground.test'
    const payload = {
      iss: env.ORIGIN,
      dwk: 'aauth-agent.json',
      sub: aauthSub,
      jti: 'j',
      cnf: { jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x } },
      iat: past - 3600,
      exp: past,
    }
    const enc = new TextEncoder()
    const b64 = (bytes: Uint8Array) => {
      let s = ''
      for (const b of bytes) s += String.fromCharCode(b)
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    }
    const hB = b64(enc.encode(JSON.stringify(header)))
    const pB = b64(enc.encode(JSON.stringify(payload)))
    const sig = await webcrypto.subtle.sign('Ed25519', serverKey, enc.encode(`${hB}.${pB}`))
    const expiredToken = `${hB}.${pB}.${b64(new Uint8Array(sig))}`

    // Seed binding with matching aauth_sub.
    const psUrl = 'https://ps.test'
    const userSub = 'pairwise-test'
    const hash = await webcrypto.subtle.digest('SHA-256', enc.encode(`${psUrl}|${userSub}`))
    const bindingKey = b64(new Uint8Array(hash))
    await kv.put(`binding:${bindingKey}`, JSON.stringify({
      ps_url: psUrl, user_sub: userSub, aauth_sub: aauthSub,
      created_at: Date.now(), credentials: [],
    }))

    const newEph = await makeEphemeral()
    const body = JSON.stringify({ binding_key: bindingKey, new_ephemeral_jwk: newEph.publicJwk })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: expiredToken,
      signingPublicJwk: publicJwk, signingPrivateJwk: privateJwk,
    })
    const res = await app.request('/refresh/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(200)
  })

  it('rejects when agent_token.sub does not match binding.aauth_sub', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    // Mint binding for aauth:legit, but sign with an agent_token whose
    // sub is aauth:other. /refresh must refuse to cross wires.
    const { agentToken, publicJwk, privateJwk } = await setupBinding(env, kv, {
      aauthSub: 'aauth:other@playground.test', psUrl: 'https://ps.test',
    })
    // Replace binding's aauth_sub with 'aauth:legit@...' to create the mismatch.
    const encoder = new TextEncoder()
    const hash = await webcrypto.subtle.digest('SHA-256', encoder.encode('https://ps.test|pairwise-test'))
    const b64 = (bytes: Uint8Array) => {
      let s = ''
      for (const b of bytes) s += String.fromCharCode(b)
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    }
    const bindingKey = b64(new Uint8Array(hash))
    await kv.put(`binding:${bindingKey}`, JSON.stringify({
      ps_url: 'https://ps.test', user_sub: 'pairwise-test',
      aauth_sub: 'aauth:legit@playground.test',
      created_at: Date.now(), credentials: [],
    }))

    const newEph = await makeEphemeral()
    const body = JSON.stringify({ binding_key: bindingKey, new_ephemeral_jwk: newEph.publicJwk })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: agentToken,
      signingPublicJwk: publicJwk, signingPrivateJwk: privateJwk,
    })
    const res = await app.request('/refresh/challenge', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/does not match binding/i)
  })
})

// ── /binding/forget tests ──

describe('POST /binding/forget', () => {
  const TEST_URL = 'http://localhost/binding/forget'

  it('(sig) valid signature → 200 and binding removed', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { agentToken, publicJwk, privateJwk, bindingKey } = await setupBinding(env, kv)

    const body = JSON.stringify({ binding_key: bindingKey })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: agentToken,
      signingPublicJwk: publicJwk, signingPrivateJwk: privateJwk,
    })
    const res = await app.request('/binding/forget', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(200)
    expect(await kv.get(`binding:${bindingKey}`)).toBeNull()
  })

  it('(sig) missing Signature-Key → 401', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { bindingKey } = await setupBinding(env, kv)
    const res = await app.request('/binding/forget', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ binding_key: bindingKey }),
    }, env)
    expect(res.status).toBe(401)
    // Binding still exists — unauthorized call didn't delete it.
    expect(await kv.get(`binding:${bindingKey}`)).toBeTruthy()
  })

  it('rejects when agent_token.sub does not match binding.aauth_sub', async () => {
    const { env, kv } = await makeEnv()
    const app = await loadApp()
    const { agentToken, publicJwk, privateJwk } = await setupBinding(env, kv, {
      aauthSub: 'aauth:other@playground.test', psUrl: 'https://ps.test',
    })
    // Overwrite binding with a different aauth_sub.
    const encoder = new TextEncoder()
    const hash = await webcrypto.subtle.digest('SHA-256', encoder.encode('https://ps.test|pairwise-test'))
    const b64 = (bytes: Uint8Array) => {
      let s = ''
      for (const b of bytes) s += String.fromCharCode(b)
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    }
    const bindingKey = b64(new Uint8Array(hash))
    await kv.put(`binding:${bindingKey}`, JSON.stringify({
      ps_url: 'https://ps.test', user_sub: 'pairwise-test',
      aauth_sub: 'aauth:victim@playground.test',
      created_at: Date.now(), credentials: [],
    }))

    const body = JSON.stringify({ binding_key: bindingKey })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'POST', body, jwt: agentToken,
      signingPublicJwk: publicJwk, signingPrivateJwk: privateJwk,
    })
    const res = await app.request('/binding/forget', { method: 'POST', headers, body }, env)
    expect(res.status).toBe(401)
    expect(await kv.get(`binding:${bindingKey}`)).toBeTruthy()
  })
})

// ── /api/demo tests ──
//
// Signed with sig=jwt;jwt=<auth_token>. The auth_token is issued by a
// PS (we fake one) and carries user identity claims + scope. Server
// verifies the HTTP signature against auth_token.cnf.jwk AND the inner
// token's JWT signature against the PS's JWKS.

describe('GET /api/demo', () => {
  const TEST_URL = 'http://localhost/api/demo'

  // Mint a PS-signed auth_token + matching ephemeral keypair, and stub
  // PS discovery so the agent server can fetch the JWKS.
  async function mintAuthToken(env: any, opts: { scope?: string; exp?: number } = {}) {
    const { computeJwkThumbprint } = await import('../src/crypto')
    const psKp = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair
    const psPub = await webcrypto.subtle.exportKey('jwk', psKp.publicKey)
    const psKid = await computeJwkThumbprint(psPub)

    const eph = await makeEphemeral()
    const now = Math.floor(Date.now() / 1000)
    const header = { alg: 'EdDSA', typ: 'aa-auth+jwt', kid: psKid }
    const payload = {
      iss: 'https://ps.test',
      dwk: 'aauth-person.json',
      aud: env.ORIGIN,
      sub: 'pairwise-abc',
      name: 'Ada',
      email: 'ada@example.com',
      scope: opts.scope ?? 'playground.demo',
      cnf: { jwk: { kty: eph.publicJwk.kty, crv: eph.publicJwk.crv, x: eph.publicJwk.x } },
      iat: now,
      exp: opts.exp ?? now + 3600,
    }
    const enc = new TextEncoder()
    const b64 = (bytes: Uint8Array) => {
      let s = ''
      for (const b of bytes) s += String.fromCharCode(b)
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    }
    const hB = b64(enc.encode(JSON.stringify(header)))
    const pB = b64(enc.encode(JSON.stringify(payload)))
    const sig = await webcrypto.subtle.sign('Ed25519', psKp.privateKey, enc.encode(`${hB}.${pB}`))
    const authToken = `${hB}.${pB}.${b64(new Uint8Array(sig))}`

    stubPsDiscovery('https://ps.test', { keys: [{ ...psPub, kid: psKid }] })
    return { authToken, eph }
  }

  it('(sig) valid signature + playground.demo scope → 200', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { authToken, eph } = await mintAuthToken(env)
    const headers = await signedHeaders({
      url: TEST_URL, method: 'GET', jwt: authToken,
      signingPublicJwk: eph.publicJwk, signingPrivateJwk: eph.privateJwk,
    })
    const res = await app.request('/api/demo', { method: 'GET', headers }, env)
    expect(res.status).toBe(200)
    const out = await res.json() as any
    expect(out.hello).toBe('Ada')
    vi.unstubAllGlobals()
  })

  it('(sig) missing Signature-Key → 401', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    await mintAuthToken(env)
    const res = await app.request('/api/demo', { method: 'GET' }, env)
    expect(res.status).toBe(401)
    vi.unstubAllGlobals()
  })

  it('(sig) signed by attacker key → 401', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { authToken } = await mintAuthToken(env)
    const attacker = await makeEphemeral()
    const headers = await signedHeaders({
      url: TEST_URL, method: 'GET', jwt: authToken,
      signingPublicJwk: attacker.publicJwk, signingPrivateJwk: attacker.privateJwk,
    })
    const res = await app.request('/api/demo', { method: 'GET', headers }, env)
    expect(res.status).toBe(401)
    vi.unstubAllGlobals()
  })

  it('rejects with 403 when scope lacks playground.demo', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const { authToken, eph } = await mintAuthToken(env, { scope: 'openid profile' })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'GET', jwt: authToken,
      signingPublicJwk: eph.publicJwk, signingPrivateJwk: eph.privateJwk,
    })
    const res = await app.request('/api/demo', { method: 'GET', headers }, env)
    expect(res.status).toBe(403)
    expect((await res.json() as any).error).toBe('insufficient_scope')
    vi.unstubAllGlobals()
  })

  it('rejects expired auth_token', async () => {
    const { env } = await makeEnv()
    const app = await loadApp()
    const past = Math.floor(Date.now() / 1000) - 60
    const { authToken, eph } = await mintAuthToken(env, { exp: past })
    const headers = await signedHeaders({
      url: TEST_URL, method: 'GET', jwt: authToken,
      signingPublicJwk: eph.publicJwk, signingPrivateJwk: eph.privateJwk,
    })
    const res = await app.request('/api/demo', { method: 'GET', headers }, env)
    expect(res.status).toBe(401)
    expect((await res.json() as any).error).toMatch(/expired/i)
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
