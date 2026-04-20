// Ed25519 JWT signing for agent tokens

const textEncoder = new TextEncoder()

function base64urlEncode(data: Uint8Array): string {
  let binary = ''
  for (const byte of data) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export async function importSigningKey(jwkJson: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkJson)
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    false,
    ['sign']
  )
}

export async function getPublicJWK(jwkJson: string): Promise<JsonWebKey & { kid: string }> {
  const jwk = JSON.parse(jwkJson)
  // Strip private key material AND any private-half operational hints
  // (key_ops: ["sign"], ext) that WebCrypto carries over when exporting
  // the private JWK. Published JWKS keys are for verification only.
  const { d: _d, key_ops: _ops, ext: _ext, ...rest } = jwk
  const publicJwk = { ...rest, key_ops: ['verify'] }
  // Compute kid as thumbprint of the required public members only
  const kid = await computeJwkThumbprint(publicJwk)
  return { ...publicJwk, kid }
}

// Keep only the RFC 7638 required public-key members for the given key type.
// Drops d (private), key_ops, ext, alg, and any other WebCrypto-inserted
// hints. Use for cnf.jwk in agent_token / resource_token so the confirmation
// key is reduced to the canonical form verifiers can directly thumbprint.
export function sanitizeCnfJwk(jwk: JsonWebKey): JsonWebKey {
  if (jwk.kty === 'OKP') return { kty: 'OKP', crv: jwk.crv, x: jwk.x }
  if (jwk.kty === 'EC') return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y }
  if (jwk.kty === 'RSA') return { kty: 'RSA', n: jwk.n, e: jwk.e }
  const { d: _d, key_ops: _ops, ext: _ext, alg: _alg, ...rest } = jwk as unknown as Record<string, unknown>
  return rest as unknown as JsonWebKey
}

export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  // Per RFC 7638: lexicographic order of required members for OKP: crv, kty, x
  const thumbprintInput = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  })
  const hash = await crypto.subtle.digest('SHA-256', textEncoder.encode(thumbprintInput))
  return base64urlEncode(new Uint8Array(hash))
}

export async function signJWT(
  header: Record<string, string>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey
): Promise<string> {
  const headerB64 = base64urlEncode(textEncoder.encode(JSON.stringify(header)))
  const payloadB64 = base64urlEncode(textEncoder.encode(JSON.stringify(payload)))
  const signingInput = `${headerB64}.${payloadB64}`
  const signature = await crypto.subtle.sign(
    'Ed25519',
    privateKey,
    textEncoder.encode(signingInput)
  )
  const signatureB64 = base64urlEncode(new Uint8Array(signature))
  return `${signingInput}.${signatureB64}`
}

export function generateJTI(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return base64urlEncode(bytes)
}

export function decodeJWTPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.')
  const json = new TextDecoder().decode(base64urlDecode(parts[1]))
  return JSON.parse(json)
}

export function decodeJWTHeader(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.')
  const json = new TextDecoder().decode(base64urlDecode(parts[0]))
  return JSON.parse(json)
}

// Verify an Ed25519-signed JWT against a JWKS. Finds the verification key by
// `kid` (falling back to first key if no kid), rejects non-EdDSA algs, and
// checks the signature. Callers are responsible for payload claim checks
// (iss/aud/exp/nbf/jti).
// Maps JWT alg → WebCrypto import/verify parameters. Extend here for new
// algorithms. Hellō's issuer JWKS uses RS256; our own JWKS uses EdDSA.
const JWT_ALG_PARAMS: Record<string, { importAlgo: any; verifyAlgo: any }> = {
  EdDSA: { importAlgo: { name: 'Ed25519' }, verifyAlgo: 'Ed25519' },
  RS256: {
    importAlgo: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    verifyAlgo: 'RSASSA-PKCS1-v1_5',
  },
  ES256: {
    importAlgo: { name: 'ECDSA', namedCurve: 'P-256' },
    verifyAlgo: { name: 'ECDSA', hash: 'SHA-256' },
  },
}

export async function verifyJWT(
  jwt: string,
  jwks: { keys: JsonWebKey[] }
): Promise<{ header: Record<string, unknown>; payload: Record<string, unknown> }> {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new Error('invalid JWT format')
  const [headerB64, payloadB64, signatureB64] = parts

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)))
  const algParams = JWT_ALG_PARAMS[header.alg]
  if (!algParams) {
    throw new Error(`unsupported alg: ${header.alg}`)
  }

  // Match by kid when present; otherwise accept a single-key JWKS.
  const candidates = jwks.keys.filter((k) =>
    header.kid ? (k as { kid?: string }).kid === header.kid : true
  )
  if (candidates.length === 0) throw new Error('no matching key in JWKS')

  const signingInput = textEncoder.encode(`${headerB64}.${payloadB64}`)
  const signature = base64urlDecode(signatureB64)

  for (const jwk of candidates) {
    try {
      const key = await crypto.subtle.importKey(
        'jwk',
        { ...jwk, key_ops: ['verify'] },
        algParams.importAlgo,
        false,
        ['verify']
      )
      const ok = await crypto.subtle.verify(
        algParams.verifyAlgo,
        key,
        signature as unknown as ArrayBuffer,
        signingInput as unknown as ArrayBuffer
      )
      if (ok) {
        const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)))
        return { header, payload }
      }
    } catch {
      // try next key
    }
  }
  throw new Error('signature verification failed')
}

export { base64urlEncode, base64urlDecode }
