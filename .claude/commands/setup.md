Set up this AAuth web agent for deployment on Cloudflare Workers. Walk through each step, verifying success before proceeding.

## Prerequisites

- Node.js installed
- Cloudflare account with `wrangler` authenticated (`npx wrangler login`)
- A domain configured in Cloudflare (for the custom domain)

## Steps

### 1. Install dependencies

```
npm install
```

### 2. Generate the Ed25519 signing key

Run `node scripts/generate-key.mjs` to generate an Ed25519 key pair. This key is used by the agent server to sign agent tokens (`aa-agent+jwt`). Save the output — you'll need it in the next step.

### 3. Set the signing key as a Cloudflare secret

```
npx wrangler secret put SIGNING_KEY
```

Paste the full JWK JSON from step 2 when prompted.

### 4. Create the KV namespace for WebAuthn

```
npx wrangler kv namespace create WEBAUTHN_KV
```

This returns an `id` value. Update `wrangler.toml` to replace the placeholder `id` under `[[kv_namespaces]]` with the real value.

### 5. Update wrangler.toml configuration

Set the `ORIGIN` variable to your deployment URL (e.g., `https://playground.aauth.ai` or your custom domain). Set `AGENT_NAME` to your preferred display name.

### 6. Deploy

```
npx wrangler deploy
```

### 7. Set up custom domain (optional)

In the Cloudflare dashboard, go to Workers & Pages > your worker > Settings > Domains & Routes, and add your custom domain (e.g., `playground.aauth.ai`). Make sure the domain's DNS is managed by Cloudflare.

### 8. Verify well-known endpoints

After deployment, verify these URLs return valid JSON:
- `{ORIGIN}/.well-known/aauth-agent.json` — agent server metadata
- `{ORIGIN}/.well-known/jwks.json` — public signing key

## What this deploys

This is an **AAuth agent server** implementing the browser-based agent pattern from the AAuth protocol spec:

1. **WebAuthn authentication** — binds user authentication to the device and origin, preventing scripts or headless browsers from impersonating the web page
2. **Ephemeral key binding** — the browser generates an Ed25519 key pair via Web Crypto API; the agent server issues an agent token (`aa-agent+jwt`) binding that ephemeral key to an agent identifier
3. **Well-known metadata** — publishes `/.well-known/aauth-agent.json` and `/.well-known/jwks.json` so any AAuth party can discover and verify this agent's identity
4. **Agent token issuance** — the `/token` endpoint issues signed JWTs with the agent's identity (`aauth:playground@{domain}`), the ephemeral public key in the `cnf` claim, and the agent server's signature

The agent token lifetime is tied to the browser session. The web server controls the entire agent identity lifecycle.

## Architecture

- **Runtime**: Cloudflare Workers (Hono framework)
- **Auth state**: Cloudflare KV (WebAuthn credentials and sessions)
- **Signing**: Ed25519 via Web Crypto API (both server-side JWT signing and client-side ephemeral keys)
- **Protocol**: AAuth Protocol — https://aauth.ai
