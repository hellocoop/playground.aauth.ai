export interface Env {
  ORIGIN: string
  AGENT_NAME: string
  SIGNING_KEY: string // Ed25519 private key (JWK JSON), set as a secret
  WEBAUTHN_KV: KVNamespace
}

export interface AgentTokenPayload {
  iss: string
  dwk: string
  sub: string
  jti: string
  cnf: { jwk: JsonWebKey }
  iat: number
  exp: number
  ps?: string
}

export interface WebAuthnRegistration {
  credentialID: string
  credentialPublicKey: string // base64url encoded
  counter: number
  transports?: string[]
}
