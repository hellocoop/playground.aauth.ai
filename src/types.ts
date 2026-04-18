export interface Env {
  ORIGIN: string
  AGENT_NAME: string
  SIGNING_KEY: string // Ed25519 private key (JWK JSON), set as a secret
  WEBAUTHN_KV: KVNamespace
  AGENT_LOGO_URI?: string
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

export interface BootstrapTokenPayload {
  iss: string
  dwk: string
  aud: string
  sub: string
  cnf: { jwk: JsonWebKey }
  scope: string
  jti: string
  iat: number
  exp: number
}

export interface WebAuthnRegistration {
  credentialID: string
  credentialPublicKey: string // base64url encoded
  counter: number
  transports?: string[]
}

// A (PS, user) → aauth identity binding stored at the agent server.
// The binding_key is sha-256(ps_url + "|" + user_sub) and keys the KV record.
export interface Binding {
  ps_url: string
  user_sub: string
  aauth_sub: string // aauth:local@agent_server_host
  created_at: number
  credentials: WebAuthnRegistration[]
}

// Short-lived record written during /bootstrap/challenge and consumed by
// /bootstrap/verify — ties a WebAuthn challenge to the bootstrap_token
// claims we already validated, so we don't re-verify the token on the
// second round-trip.
export interface BootstrapTransaction {
  binding_key: string
  ps_url: string
  user_sub: string
  aauth_sub: string
  ephemeral_jwk: JsonWebKey
  scope: string
  challenge: string
  type: 'register' | 'assert'
  created_at: number
}

// Same pattern for /refresh — the client already holds the binding_key
// (stored at bootstrap time) and is proving possession of the WebAuthn
// credential to rotate the ephemeral key.
export interface RefreshTransaction {
  binding_key: string
  new_ephemeral_jwk: JsonWebKey
  challenge: string
  created_at: number
}
