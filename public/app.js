// ── State ──

let agentToken = null
let ephemeralKeyPair = null // CryptoKeyPair — private key never exported
// The (PS, user) binding_key derived at bootstrap; persisted in localStorage
// and used on /refresh to prove which (PS, user) pair we're holding
// credentials for without exposing the raw identifiers again.
let bindingKey = null
let bindingPs = null
let bindingSub = null

// ── IndexedDB helpers for CryptoKey persistence ──

const DB_NAME = 'aauth-playground'
const DB_VERSION = 1
const STORE_NAME = 'keys'

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function saveKeyPair(keyPair) {
  const db = await openDB()
  const tx = db.transaction(STORE_NAME, 'readwrite')
  tx.objectStore(STORE_NAME).put(keyPair, 'ephemeral')
  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve
    tx.onerror = () => reject(tx.error)
  })
}

async function loadKeyPair() {
  const db = await openDB()
  const tx = db.transaction(STORE_NAME, 'readonly')
  const req = tx.objectStore(STORE_NAME).get('ephemeral')
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result || null)
    req.onerror = () => reject(req.error)
  })
}

async function clearKeyPair() {
  const db = await openDB()
  const tx = db.transaction(STORE_NAME, 'readwrite')
  tx.objectStore(STORE_NAME).delete('ephemeral')
}

// Generate a fresh ephemeral Ed25519 key pair and persist it. The design
// rotates this key on every bootstrap/refresh so the cnf binding in any
// historical agent_token can't be reused against a rotated key.
async function rotateEphemeralKeyPair() {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  ephemeralKeyPair = keyPair
  await saveKeyPair(keyPair)
  return keyPair
}

// ── Agent name generation ──

const adjectives = [
  'able','aged','apt','arch','avid','bald','bare','big','blue','bold',
  'born','brave','brief','bright','broad','brisk','calm','civic','clean','clear',
  'close','cold','cool','crisp','curly','cute','damp','dark','dear','deep',
  'dense','dim','dire','dry','dual','dull','dusk','dusty','eager','early',
  'easy','edgy','elfin','elite','even','exact','extra','faded','fair','fast',
  'fawn','few','fiery','final','fine','firm','first','fit','flat','flush',
  'focal','fond','free','fresh','full','fuzzy','glad','glum','gold','gone',
  'good','grand','gray','great','green','grim','grown','hairy','half','happy',
  'hard','harsh','hazel','heavy','hex','high','hollow','hot','huge','human',
  'humid','husky','icy','ideal','idle','inner','ionic','iron','ivory','jade',
  'jolly','just','keen','kept','kind','known','lame','large','last','late',
  'lazy','lean','left','level','light','limp','live','local','lofty','lone',
  'long','lost','loud','loved','low','lucid','lunar','lusty','lyric','mad',
  'magic','main','major','male','maple','meek','mere','merry','micro','mild',
  'mini','mint','misty','modal','moist','mossy','moved','murky','mute','naive',
  'naval','near','neat','new','next','nice','noble','north','novel','numb',
  'oaken','oaky','oblong','odd','oily','old','olive','only','opal','open',
  'opted','oral','outer','owned','oxide','paid','pale','past','peach','peppy',
  'petty','pink','plain','plum','plump','polar','prime','proud','puce','pulpy',
  'pure','pushy','quick','quiet','radio','rapid','rare','raw','ready','real',
  'red','regal','rich','rigid','ripe','rocky','roomy','rosy','rough','round',
  'royal','ruby','rude','rum','rusty','safe','salty','same','sandy','satin',
  'scant','sharp','sheer','shiny','short','shy','silky','slim','slow','small',
  'smart','smoky','snowy','snug','soft','solar','sole','solid','sonic','south',
  'spare','spicy','steep','still','stock','stout','strong','sunny','super','sure',
  'sweet','swift','tall','tame','tan','tart',
]
const nouns = [
  'ace','acorn','agate','aide','aisle','amber','angel','anvil','ape','apple',
  'arch','aspen','atlas','badge','basin','bass','bay','beach','beam','bear',
  'bee','bell','belt','bench','birch','bird','blade','blaze','bloom','bluff',
  'board','bolt','bone','booth','bow','braid','brass','brick','brook','brush',
  'bud','bulb','cape','cargo','cedar','chain','charm','chess','chief','chime',
  'chip','chord','cider','clam','clay','cliff','cloud','clove','coast','cobra',
  'coil','coin','coral','cork','cove','crane','crest','crow','crown','crush',
  'cub','cup','curl','curve','dale','dawn','deer','delta','den','dew',
  'dock','dome','dove','drake','drift','drum','dune','dust','eagle','edge',
  'elm','ember','epoch','fable','fawn','feast','fern','fiber','fig','finch',
  'fjord','flame','flare','flask','flint','float','flora','flute','foam','forge',
  'fort','fox','frost','fruit','gale','gate','gem','ghost','glade','glen',
  'globe','glove','goat','gorge','grain','grape','grove','guide','gull','gust',
  'halo','hare','harp','haven','hawk','hazel','helm','herb','heron','hinge',
  'holly','honey','hood','horn','horse','hull','hydra','inlet','iris','ivory',
  'ivy','jade','jewel','joint','kelp','king','kite','knob','knoll','knot',
  'lace','lake','lance','lark','latch','leaf','ledge','lever','light','lily',
  'lime','linen','lodge','loom','lotus','lumen','lunar','lynx','lyric','mango',
  'manor','maple','marsh','mask','mast','maze','medal','melon','mesa','mica',
  'midge','mill','mint','mist','moat','moon','moose','morse','moss','mount',
  'mouse','mulch','mural','myrrh','nest','node','north','notch','novel','oak',
  'oasis','ocean','olive','onyx','orbit','orchid','otter','owl','oxide','palm',
  'panda','panel','park','path','peach','pearl','petal','phase','pilot','pine',
  'pixel','plaid','plane','plank','plaza','plum','plume','poise','polar','pond',
  'poppy','port','prism','probe','pulse','quail','quake','quartz','quest','quill',
  'raven','realm','reed','reef','ridge','river',
]
const verbs = [
  'act','add','aim','ask','bake','bank','base','beam','bend','bid',
  'bind','bite','blow','blur','boil','bolt','bond','bore','bow','brew',
  'burn','bury','buzz','call','camp','carve','cast','catch','chase','chime',
  'chip','chop','clap','clasp','claw','clean','climb','cling','clip','close',
  'coil','comb','cook','cope','copy','count','crack','craft','crawl','cross',
  'crush','curl','curve','cut','dab','dance','dare','dart','dash','deal',
  'delve','dent','dial','dig','dine','dip','dive','dock','dodge','dose',
  'dot','draft','drain','drape','draw','dream','dress','drift','drill','drink',
  'drive','drop','dry','duel','dump','dunk','dust','dwell','dye','earn',
  'eat','edge','emit','empty','end','enter','erase','evade','exit','eye',
  'face','fade','fall','fan','farm','fast','feast','feed','feel','fence',
  'fetch','file','fill','find','fire','fish','fit','fix','flame','flash',
  'flee','fling','flip','float','flock','flood','flow','fly','foam','focus',
  'fold','forge','form','frame','free','frost','fuel','fuse','gain','gaze',
  'get','give','glow','glue','gnaw','grab','grasp','grate','graze','grid',
  'grind','grip','groan','groom','group','grow','guard','guess','guide','gulp',
  'halt','hang','hatch','haul','heal','heap','hear','heat','hedge','help',
  'herd','hike','hint','hold','honor','hook','hop','hover','howl','hum',
  'hunt','hurl','inch','iron','jam','jog','join','joke','joust','judge',
  'jump','keep','kick','kneel','knit','knock','knot','lace','land','lap',
  'latch','launch','lay','lead','lean','leap','learn','lend','level','lift',
  'light','limb','link','list','live','load','lock','log','look','loop',
  'loom','lure','lurk','make','map','march','mark','mask','match','melt',
  'mend','merge','mill','mind','mine','miss','mix','mold','mount','move',
  'mow','muse','nail','name','nap','nest','nod','note','nudge','nurse',
  'obey','orbit','own','pace','pack','paint',
]

function generateAgentName() {
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)]
  const noun = nouns[Math.floor(Math.random() * nouns.length)]
  const verb = verbs[Math.floor(Math.random() * verbs.length)]
  return `${adj}-${noun}-${verb}`
}

// Return the stored agent name, or generate + persist a fresh one. Called
// from protocol.js at bootstrap time — not on page load — so a fresh
// install or post-Reset page shows no name until bootstrap actually runs.
function getOrGenerateAgentName() {
  let name = localStorage.getItem('aauth-agent-name')
  if (!name) {
    name = generateAgentName()
    localStorage.setItem('aauth-agent-name', name)
  }
  return name
}
window.aauthGetOrGenerateAgentName = getOrGenerateAgentName

// ── JWT helpers ──

function decodeJWTPayload(jwt) {
  const parts = jwt.split('.')
  return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
}

// ── jwt.io-style syntax highlighting ──

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// Render an encoded JWT as <header>.<payload>.<signature> with each segment colored.
function renderEncodedJWT(jwt) {
  const parts = String(jwt).split('.')
  if (parts.length < 2) return escapeHtml(jwt)
  const [h, p, s = ''] = parts
  return (
    `<span class="jwt-header">${escapeHtml(h)}</span>` +
    `<span class="jwt-dot">.</span>` +
    `<span class="jwt-payload">${escapeHtml(p)}</span>` +
    `<span class="jwt-dot">.</span>` +
    `<span class="jwt-signature">${escapeHtml(s)}</span>`
  )
}

// Pretty-print a JS value as JSON with syntax-highlighted spans.
function renderJSON(obj) {
  const json = JSON.stringify(obj, null, 2)
  if (json === undefined) return ''
  // Escape HTML first so user-controlled strings can't inject markup.
  const safe = escapeHtml(json)
  return safe.replace(
    /(&quot;(?:\\.|(?!&quot;).)*&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, bool, num) => {
      if (str) {
        const cls = colon ? 'json-key' : 'json-string'
        return `<span class="${cls}">${str}</span>${colon || ''}`
      }
      if (bool) return `<span class="json-bool">${bool}</span>`
      if (num) return `<span class="json-num">${num}</span>`
      return match
    }
  )
}

// ── WebAuthn helpers (used by bootstrap/refresh ceremonies) ──

function base64urlToBuffer(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function parseCreationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map(c => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  }
}

function parseRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(c => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  }
}

function serializeCredential(cred) {
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      attestationObject: bufferToBase64url(cred.response.attestationObject),
      transports: cred.response.getTransports?.() || [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment,
  }
}

function serializeAssertion(cred) {
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      authenticatorData: bufferToBase64url(cred.response.authenticatorData),
      signature: bufferToBase64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufferToBase64url(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment,
  }
}

// Exposed for protocol.js (bundled file) to run the WebAuthn prompt itself.
window.aauthWebAuthn = {
  parseCreationOptions,
  parseRequestOptions,
  serializeCredential,
  serializeAssertion,
}

// ── UI updates ──

// Post-bootstrap state: hide the pre-bootstrap controls (Person Server
// picker, Bootstrap agent button, intro copy) so a reloaded page doesn't
// show the user an option they're already past. The Bootstrap fieldset
// itself stays visible because it now hosts the inline Agent Identity
// block + protocol log from the completed ceremony. Reset lives on the
// Authorization Request fieldset.
//
// Scrolls to the Agent Identity card on first reveal so a post-OAuth
// redirect-back lands the viewport on the next actionable block instead
// of wherever the Bootstrap section happened to be.
function setAuthenticated(label) {
  document.getElementById('bootstrap-controls')?.classList.add('hidden')
  const authSection = document.getElementById('auth-section')
  const authzSection = document.getElementById('authz-section')
  authSection?.classList.remove('hidden')
  authzSection?.classList.remove('hidden')
  document.getElementById('auth-user').textContent = label
  // Defer one frame so layout settles (hidden → visible) before scroll.
  requestAnimationFrame(() => {
    authSection?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  })
}

// Pre-bootstrap state: show only the Bootstrap section's pre-ceremony
// controls; hide Agent Identity and Authorization Request.
function setUnauthenticated() {
  document.getElementById('bootstrap-section')?.classList.remove('hidden')
  document.getElementById('bootstrap-controls')?.classList.remove('hidden')
  document.getElementById('auth-section')?.classList.add('hidden')
  document.getElementById('authz-section')?.classList.add('hidden')
}

function displayAgentToken(data) {
  const payload = decodeJWTPayload(data.agent_token)
  document.getElementById('agent-id').textContent = data.agent_id
  const raw = document.getElementById('agent-token-raw')
  raw.classList.add('encoded')
  raw.innerHTML = renderEncodedJWT(data.agent_token)
  document.getElementById('token-payload').innerHTML = renderJSON(payload)
}

// ── Binding state ──
//
// localStorage keys:
//   aauth-binding-key — opaque SHA-256(ps_url + "|" + user_sub), used as
//                       the refresh key. Matches the server's key.
//   aauth-binding-ps  — display only (so user sees which PS they bound to)
//   aauth-binding-sub — pairwise user_sub from bootstrap_token (opaque)

function loadBinding() {
  bindingKey = localStorage.getItem('aauth-binding-key')
  bindingPs = localStorage.getItem('aauth-binding-ps')
  bindingSub = localStorage.getItem('aauth-binding-sub')
  return bindingKey ? { bindingKey, psUrl: bindingPs, userSub: bindingSub } : null
}

function saveBinding({ binding_key, ps_url, user_sub }) {
  bindingKey = binding_key
  bindingPs = ps_url
  bindingSub = user_sub
  localStorage.setItem('aauth-binding-key', binding_key)
  localStorage.setItem('aauth-binding-ps', ps_url)
  localStorage.setItem('aauth-binding-sub', user_sub)
}

function clearBinding() {
  bindingKey = null
  bindingPs = null
  bindingSub = null
  localStorage.removeItem('aauth-binding-key')
  localStorage.removeItem('aauth-binding-ps')
  localStorage.removeItem('aauth-binding-sub')
}

// Exposed for protocol.js
window.aauthBinding = { loadBinding, saveBinding, clearBinding, get: () => ({ bindingKey, bindingPs, bindingSub }) }

// Exposed so startBootstrap (in the bundled protocol.js) can reset the
// Agent Identity + Authorization Request UI when a user clicks
// "Bootstrap agent" again after already having bootstrapped — otherwise
// the old "Bound as …" line stays on screen while the new ceremony runs.
window.aauthUI = { setAuthenticated, setUnauthenticated }

// ── Agent token persistence ──

function saveAgentToken(token) {
  agentToken = token
  localStorage.setItem('aauth-agent-token', token)
}

function clearAgentToken() {
  agentToken = null
  localStorage.removeItem('aauth-agent-token')
}

async function restoreAgentTokenAndKey() {
  const savedToken = localStorage.getItem('aauth-agent-token')
  if (!savedToken) return false

  const payload = decodeJWTPayload(savedToken)
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp <= now) {
    clearAgentToken()
    return false
  }

  const keyPair = await loadKeyPair()
  if (!keyPair) {
    clearAgentToken()
    return false
  }

  agentToken = savedToken
  ephemeralKeyPair = keyPair
  displayAgentToken({ agent_token: savedToken, agent_id: payload.sub })
  return true
}

// Applied by protocol.js after a successful bootstrap or refresh call.
function applyBootstrapResult(result) {
  saveAgentToken(result.agent_token)
  displayAgentToken({ agent_token: result.agent_token, agent_id: result.agent_id })
  setAuthenticated(result.agent_id)
}
window.aauthApplyBootstrapResult = applyBootstrapResult

// Exposed for protocol.js to manage the ephemeral key.
//
// `rotate` is the simple case (bootstrap): generate + save + make current.
//
// `stage` / `commitStaged` splits that into two phases for /refresh: we
// need to sign /refresh/challenge and /refresh/verify with the OLD
// ephemeral (which matches agent_token.cnf), while also handing the
// NEW public key to the server so the refreshed tokens bind to it.
// Only after /refresh/verify succeeds do we promote the staged key.
let stagedKeyPair = null

window.aauthEphemeral = {
  rotate: async () => {
    const kp = await rotateEphemeralKeyPair()
    return {
      keyPair: kp,
      publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey),
    }
  },
  stage: async () => {
    const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
    stagedKeyPair = kp
    return {
      keyPair: kp,
      publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey),
    }
  },
  commitStaged: async () => {
    if (!stagedKeyPair) return null
    ephemeralKeyPair = stagedKeyPair
    await saveKeyPair(stagedKeyPair)
    stagedKeyPair = null
    return ephemeralKeyPair
  },
  discardStaged: () => { stagedKeyPair = null },
  get: () => ephemeralKeyPair,
  getPublicJwk: async () => ephemeralKeyPair ? crypto.subtle.exportKey('jwk', ephemeralKeyPair.publicKey) : null,
}

// ── Scope picker hydration ──
//
// Two separate scope pickers, corresponding to the two scope axes:
//
// Identity scopes — requested at bootstrap. Granted claims come back as
// named fields on the auth_token (name, email, ...). List hardcoded here
// for now since the wallet PS doesn't publish scope descriptions.
// TODO: when PS publishes scopes_supported with descriptions, hydrate
// from {ps_origin}/.well-known/aauth-person.json instead.
//
// Resource scopes — requested at /authorize. End up in auth_token.scope
// and gate what the agent can do at this resource. Hydrated from this
// resource's /.well-known/aauth-resource.json so the UI never offers
// something the server would reject.

const IDENTITY_SCOPES = [
  { name: 'openid',      description: 'Verify your identity',            required: true },
  { name: 'profile',     description: 'Access your profile information', checked: true },
  { name: 'name',        description: 'Access your full name' },
  { name: 'email',       description: 'Access your email address' },
  { name: 'picture',     description: 'Access your profile picture' },
  { name: 'nickname',    description: 'Access your nickname' },
  { name: 'given_name',  description: 'Access your given name' },
  { name: 'family_name', description: 'Access your family name' },
  { name: 'phone',       description: 'Access your phone number' },
  { name: 'ethereum',    description: 'Access your linked Ethereum wallet' },
  { name: 'discord',     description: 'Access your linked Discord account' },
  { name: 'twitter',     description: 'Access your linked Twitter account' },
  { name: 'github',      description: 'Access your linked GitHub account' },
  { name: 'gitlab',      description: 'Access your linked GitLab account' },
]

function renderScopeRow(scope, description, opts = {}) {
  const attrs = [`value="${scope}"`]
  if (opts.checked) attrs.push('checked')
  if (opts.disabled) attrs.push('disabled')
  const title = description ? ` title="${description.replace(/"/g, '&quot;')}"` : ''
  const required = opts.required ? ' <span class="scope-required">*</span>' : ''
  return `<label class="checkbox-label"${title}><input type="checkbox" ${attrs.join(' ')}> <span>${scope}${required}</span></label>`
}

function hydrateIdentityScopes() {
  const grid = document.getElementById('identity-scope-grid')
  if (!grid) return
  grid.innerHTML = IDENTITY_SCOPES.map((s) =>
    renderScopeRow(s.name, s.description, {
      checked: !!s.required || !!s.checked,
      disabled: !!s.required,
      required: !!s.required,
    }),
  ).join('')
}

async function hydrateResourceScopes() {
  const grid = document.getElementById('resource-scope-grid')
  if (!grid) return
  let descriptions = {}
  try {
    const res = await fetch('/.well-known/aauth-resource.json')
    const body = await res.json()
    descriptions = body?.scope_descriptions || {}
  } catch {
    // Fall through — resource-scope grid renders empty.
  }
  const scopes = Object.keys(descriptions).sort()
  // Pre-check everything the resource advertises. Saner default for a demo
  // with a single scope (one click to Continue) and for most real flows
  // (agent is asking for this set, the user will typically consent); user
  // can uncheck anything they don't want to grant.
  grid.innerHTML = scopes
    .map((s) => renderScopeRow(s, descriptions[s], { checked: true }))
    .join('')
}

// ── Settings persistence ──
// Mirrors the playground.hello.dev pattern: one localStorage key holds all
// user-customizable settings (PS selection, scopes, hints) as JSON.

const SETTINGS_KEY = 'aauth-playground-settings'
const HINT_FIELDS = ['login-hint', 'domain-hint', 'provider-hint', 'tenant']
const DEFAULT_PS = 'https://person.hello.coop'

function loadSettings() {
  let saved = {}
  try {
    saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') || {}
  } catch { /* ignore corrupt JSON */ }

  // Restore PS selection
  const psList = document.getElementById('ps-list')
  if (psList) {
    const psValue = saved.ps || DEFAULT_PS
    const psCustom = saved.ps_custom || ''
    document.getElementById('ps-custom').value = psCustom
    const radios = psList.querySelectorAll('input[name="ps"]')
    let matched = false
    for (const r of radios) {
      if (r.value === psValue) { r.checked = true; matched = true; break }
    }
    if (!matched) {
      // Saved PS isn't a preset → treat as custom
      const customRadio = document.getElementById('ps-custom-radio')
      if (customRadio) customRadio.checked = true
      if (psValue && psValue !== 'custom') {
        document.getElementById('ps-custom').value = psValue
      }
    }
    updatePSCurrent()
  }

  // Restore identity scope checkboxes.
  if (Array.isArray(saved.identity_scopes)) {
    const set = new Set(saved.identity_scopes)
    const boxes = document.querySelectorAll('#identity-scope-grid input[type="checkbox"]')
    for (const b of boxes) {
      if (b.disabled) continue // openid stays checked regardless
      b.checked = set.has(b.value)
    }
  }

  // Restore resource scope checkboxes.
  if (Array.isArray(saved.resource_scopes)) {
    const set = new Set(saved.resource_scopes)
    const boxes = document.querySelectorAll('#resource-scope-grid input[type="checkbox"]')
    for (const b of boxes) {
      if (b.disabled) continue
      b.checked = set.has(b.value)
    }
  }

  // Restore hint inputs + their enable checkboxes. saved.hints is
  // `{ [id]: string }` for values and saved.hints_enabled is `[id, ...]`
  // for the enabled set.
  if (saved.hints && typeof saved.hints === 'object') {
    for (const f of HINT_FIELDS) {
      const el = document.getElementById(f)
      if (el && typeof saved.hints[f] === 'string') el.value = saved.hints[f]
    }
  }
  if (Array.isArray(saved.hints_enabled)) {
    const set = new Set(saved.hints_enabled)
    for (const f of HINT_FIELDS) {
      const cb = document.querySelector(`.hint-enable[data-hint-for="${f}"]`)
      if (cb) cb.checked = set.has(f)
    }
  }
}

function saveSettings() {
  const psRadio = document.querySelector('#ps-list input[name="ps"]:checked')
  const psCustom = document.getElementById('ps-custom')?.value?.trim() || ''
  const ps = psRadio ? psRadio.value : DEFAULT_PS

  const identity_scopes = Array.from(
    document.querySelectorAll('#identity-scope-grid input[type="checkbox"]:checked')
  ).map(b => b.value)
  const resource_scopes = Array.from(
    document.querySelectorAll('#resource-scope-grid input[type="checkbox"]:checked')
  ).map(b => b.value)

  const hints = {}
  const hints_enabled = []
  for (const f of HINT_FIELDS) {
    const v = document.getElementById(f)?.value?.trim()
    if (v) hints[f] = v
    const cb = document.querySelector(`.hint-enable[data-hint-for="${f}"]`)
    if (cb?.checked) hints_enabled.push(f)
  }

  localStorage.setItem(SETTINGS_KEY, JSON.stringify({
    ps,
    ps_custom: psCustom,
    identity_scopes,
    resource_scopes,
    hints,
    hints_enabled,
  }))
}

// Returns the URL the user has currently chosen for the PS.
// Used by client/protocol.js (exposed via window for esbuild-bundled code).
function getCurrentPS() {
  const psRadio = document.querySelector('#ps-list input[name="ps"]:checked')
  if (!psRadio) return ''
  if (psRadio.value === 'custom') {
    return document.getElementById('ps-custom')?.value?.trim() || ''
  }
  return psRadio.value
}
window.getCurrentPS = getCurrentPS

// Show the active PS URL in the <summary> when collapsed.
function updatePSCurrent() {
  const el = document.getElementById('ps-current')
  if (el) el.textContent = getCurrentPS() || '(none selected)'
}

function wireSettingsAutosave() {
  // PS picker + hints live in the Bootstrap section; scope grids live in
  // the Authorization section. Watch both for any user edit.
  const roots = ['bootstrap-section', 'authz-section']
    .map((id) => document.getElementById(id))
    .filter(Boolean)
  for (const root of roots) {
    root.addEventListener('change', () => { saveSettings(); updatePSCurrent() })
    root.addEventListener('input', () => { saveSettings(); updatePSCurrent() })
  }
  // Typing in the custom URL field implicitly selects the custom radio.
  const customInput = document.getElementById('ps-custom')
  const customRadio = document.getElementById('ps-custom-radio')
  if (customInput && customRadio) {
    customInput.addEventListener('focus', () => { customRadio.checked = true; saveSettings(); updatePSCurrent() })
  }
}

// ── Initialization ──

// Hydrate both scope pickers BEFORE restoring saved selections —
// loadSettings queries checkboxes by value, so they have to exist first.
// Identity scopes are synchronous (hardcoded list); resource scopes are
// async (from this resource's well-known metadata).
;(async () => {
  hydrateIdentityScopes()
  await hydrateResourceScopes()
  loadSettings()
  wireSettingsAutosave()
})()

// Copy button SVG icons — inlined for crisp rendering at any scale.
const COPY_ICON_HTML = `
  <svg class="copy-icon-copy" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
  <svg class="copy-icon-check" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5"/></svg>
`
function renderCopyIcons(root = document) {
  for (const btn of root.querySelectorAll('.copy-btn:empty')) {
    btn.innerHTML = COPY_ICON_HTML
  }
}
renderCopyIcons()
new MutationObserver(() => renderCopyIcons()).observe(document.body, { childList: true, subtree: true })

// Copy buttons — delegated. `data-copy` copies a literal string; `data-copy-target`
// copies the textContent of the matched element. Toggles a 500ms "copied" state.
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.copy-btn')
  if (!btn) return
  const literal = btn.dataset.copy
  const target = btn.dataset.copyTarget
  const text = literal != null
    ? literal
    : (target ? (() => {
        const el = document.querySelector(target)
        if (!el) return ''
        return 'value' in el ? el.value : el.textContent
      })() : '')
  if (!text) return
  navigator.clipboard.writeText(text).then(() => {
    btn.classList.add('copied')
    setTimeout(() => btn.classList.remove('copied'), 500)
  })
})


// Reset button — clears all playground state (settings, binding, agent
// token, ephemeral key, session, agent-name) and reloads. Matches the
// pattern in playground.hello.dev; handy when testing a fresh bootstrap
// or switching between person servers.
document.getElementById('reset-btn')?.addEventListener('click', async () => {
  if (!confirm('Reset playground? This clears your PS selection, scopes, agent binding, tokens, and WebAuthn linkage — on the agent server too, so the next Continue runs a full bootstrap (registering a new passkey).')) return

  // Tell the server to drop the (PS, user) binding so the next bootstrap
  // runs the register path (new WebAuthn credential, new aauth_sub).
  // Without this, the server-side binding survives the client-side reset
  // and the next bootstrap silently asserts against the old credential.
  // /binding/forget must be signed with sig=jwt + agent_token so the
  // server can authorize the deletion (agent_token.sub must match the
  // binding's aauth_sub). If we don't have both a saved agent_token and
  // the ephemeral that signs for it, skip the server call — client
  // reset still happens, the server binding just stays until it's
  // orphaned by expiry. Not ideal for "fresh register" UX but safe.
  const savedBindingKey = localStorage.getItem('aauth-binding-key')
  const savedAgentToken = localStorage.getItem('aauth-agent-token')
  if (savedBindingKey && savedAgentToken && window.aauthSigFetch) {
    try {
      await window.aauthSigFetch('/binding/forget', {
        method: 'POST',
        body: JSON.stringify({ binding_key: savedBindingKey }),
        jwt: savedAgentToken,
      })
    } catch { /* best-effort — still proceed with client reset */ }
  }

  // Sweep every playground-owned localStorage key. Prefix-matched so
  // future additions are covered automatically.
  const toRemove = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (k && k.startsWith('aauth-')) toRemove.push(k)
  }
  for (const k of toRemove) localStorage.removeItem(k)

  // Clear ephemeral keypair stored in IndexedDB.
  try { await clearKeyPair() } catch { /* IndexedDB may be unavailable */ }

  location.reload()
})

;(async () => {
  loadBinding()
  const restored = await restoreAgentTokenAndKey()
  if (restored) {
    const payload = decodeJWTPayload(agentToken)
    setAuthenticated(payload.sub)
  } else if (bindingKey) {
    // Binding exists but agent_token expired/missing. We're still bootstrapped;
    // Continue will refresh. Show the post-bootstrap UI.
    setAuthenticated(bindingSub || bindingPs || 'agent')
  } else if (localStorage.getItem('aauth-pending-bootstrap')) {
    // First-bootstrap resume case: no agent_token exists yet, but the
    // ephemeral key was saved to IndexedDB before the PS redirect. Load
    // it so resumePendingInteraction can sign the /pending poll.
    const kp = await loadKeyPair()
    if (kp) ephemeralKeyPair = kp
  }
  // Resume whichever pending flow the user left mid-interaction when they
  // redirected to the PS. Bootstrap takes precedence (can't authorize
  // without an agent_token anyway). Both are no-ops if no pending state
  // is saved or it's gone stale.
  window.resumePendingInteraction?.()
  window.resumePendingAuthorize?.()
})()
