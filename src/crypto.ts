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
  // Strip private key material — only return public components
  const { d: _, ...publicJwk } = jwk
  // Compute kid as thumbprint
  const kid = await computeJwkThumbprint(publicJwk)
  return { ...publicJwk, kid }
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

export { base64urlEncode, base64urlDecode }
