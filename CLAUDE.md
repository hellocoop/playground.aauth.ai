# playground.aauth.dev — Claude project notes

## Deployment

**Do not run `wrangler deploy` manually.** Cloudflare Workers is wired to
a Git trigger on this repo: pushing to `main` auto-deploys. Running
`wrangler deploy` in addition just creates a redundant deployment.

To ship a change:

1. Commit locally.
2. `git push origin main`.
3. Verify the live site picked it up:
   ```bash
   curl -s https://playground.aauth.dev/.well-known/aauth-agent.json | jq .
   ```
4. Check deployment history if needed: `npx wrangler deployments list`.

Auto-deploy can take a minute or two after the push lands.

## Local development

- `npm run dev` — runs esbuild watcher on `client/protocol.js` plus
  `wrangler dev` in parallel.
- `npm run build:client` — one-shot bundle of the client into
  `public/protocol.js` (bundled, committed).
- `npm test` — vitest run.
- `npx tsc --noEmit` — type check.

## Architecture quick ref

- Cloudflare Worker (`src/index.ts`, Hono) serves both static assets
  (from `public/`) and API routes.
- Client code is split: `public/app.js` (loaded directly, handles
  state/UI) and `client/protocol.js` (bundled by esbuild into
  `public/protocol.js`, handles the protocol flow).
- KV namespace `WEBAUTHN_KV` stores WebAuthn challenges, sessions,
  bindings, and short-lived transaction records.
- Signing key is an Ed25519 JWK stored as the `SIGNING_KEY` Worker
  secret (generated via `npm run generate-key`).
