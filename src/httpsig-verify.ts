import { verify as httpSigVerify } from '@hellocoop/httpsig'
import type { Context } from 'hono'
import { verifyJWT } from './crypto'

// Shared RFC 9421 verification for endpoints that accept sig=jwt. Reads
// the body once, runs httpSigVerify, enforces the jwt scheme, and
// optionally runs a caller-supplied JWT verification on the inner token
// (e.g. against our own JWKS or a PS JWKS).
//
// Returns the parsed body as text (callers parse JSON themselves, since
// c.req.json() would re-consume the stream) and the inner JWT payload.
//
// On failure, returns a Hono Response — callers can return it directly.

export interface SigJwtVerifyOptions {
  // Optional inner-token verifier: takes the raw JWT string and returns
  // { payload } if it's valid. Use this to verify against our own JWKS
  // (agent_token from us) or a PS JWKS (auth_token from the PS).
  verifyInner?: (jwt: string) => Promise<{ payload: Record<string, unknown> }>
  // If true, skip exp check on the inner JWT payload (used for /refresh,
  // where an expired agent_token is precisely what's being renewed).
  allowExpired?: boolean
  // Require payload.iss === expectedIss when set.
  expectedIss?: string
}

export interface SigJwtVerifyResult {
  rawBody: string
  innerJwt: string
  innerPayload: Record<string, unknown> | null
}

export async function verifySigJwt(
  c: Context,
  options: SigJwtVerifyOptions = {}
): Promise<SigJwtVerifyResult | Response> {
  // Read body as text — httpSigVerify needs it to reconstruct the
  // signature base, and c.req.json() would consume the stream first.
  const rawBody = await c.req.text()

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

  const innerJwt = sigResult.jwt.raw
  let innerPayload: Record<string, unknown> | null = null

  if (options.verifyInner) {
    try {
      const { payload } = await options.verifyInner(innerJwt)
      innerPayload = payload
    } catch (err) {
      return c.json({ error: `inner JWT invalid: ${(err as Error).message}` }, 401)
    }
    if (options.expectedIss && innerPayload.iss !== options.expectedIss) {
      return c.json({ error: `inner JWT iss mismatch: expected ${options.expectedIss}` }, 401)
    }
    if (!options.allowExpired) {
      const now = Math.floor(Date.now() / 1000)
      if (!innerPayload.exp || (innerPayload.exp as number) < now) {
        return c.json({ error: 'inner JWT expired' }, 401)
      }
    }
  }

  return { rawBody, innerJwt, innerPayload }
}

// Convenience: build a verifyInner that uses our own JWKS. For tokens we
// issued (agent_token minted at bootstrap/refresh).
export function ourJwksVerifier(ourJwk: JsonWebKey) {
  return (jwt: string) => verifyJWT(jwt, { keys: [ourJwk] })
}

// Build a verifyInner that fetches the PS JWKS (via the JWT's iss+dwk)
// and verifies against it. Used for auth_tokens at /api/demo.
export function psJwksVerifier() {
  return async (jwt: string) => {
    const { decodeJWTPayload } = await import('./crypto')
    const unverified = decodeJWTPayload(jwt)
    const iss = unverified.iss as string | undefined
    const dwk = (unverified.dwk as string | undefined) ?? 'aauth-person.json'
    if (!iss) throw new Error('token missing iss')
    const metaRes = await fetch(`${iss}/.well-known/${dwk}`)
    if (!metaRes.ok) throw new Error(`fetch PS metadata failed: ${metaRes.status}`)
    const meta = (await metaRes.json()) as Record<string, unknown>
    const jwksUri = meta.jwks_uri as string | undefined
    if (!jwksUri) throw new Error('PS metadata missing jwks_uri')
    const jwksRes = await fetch(jwksUri)
    if (!jwksRes.ok) throw new Error(`fetch PS JWKS failed: ${jwksRes.status}`)
    const jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
    return verifyJWT(jwt, jwks)
  }
}
