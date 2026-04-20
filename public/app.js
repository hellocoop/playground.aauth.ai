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

function getAgentName() {
  let name = localStorage.getItem('aauth-agent-name')
  if (!name) {
    name = generateAgentName()
    localStorage.setItem('aauth-agent-name', name)
  }
  return name
}

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

function setAuthenticated(label) {
  document.documentElement.classList.remove('show-auth')
  document.getElementById('auth-form').classList.add('hidden')
  document.getElementById('auth-info').classList.remove('hidden')
  document.getElementById('auth-user').textContent = label
  document.getElementById('token-section').classList.remove('hidden')
}

function setUnauthenticated() {
  document.getElementById('auth-form').classList.remove('hidden')
  document.getElementById('auth-info').classList.add('hidden')
  document.getElementById('token-section').classList.add('hidden')
  // Authz section stays enabled — Continue triggers bootstrap.
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
  enableAuthzSection()
  return true
}

// Applied by protocol.js after a successful bootstrap or refresh call.
function applyBootstrapResult(result) {
  saveAgentToken(result.agent_token)
  displayAgentToken({ agent_token: result.agent_token, agent_id: result.agent_id })
  enableAuthzSection()
  setAuthenticated(result.agent_id)
}
window.aauthApplyBootstrapResult = applyBootstrapResult

// Exposed for protocol.js to rotate the ephemeral key before bootstrap/refresh
// and retrieve it for signing.
window.aauthEphemeral = {
  rotate: async () => {
    const kp = await rotateEphemeralKeyPair()
    return {
      keyPair: kp,
      publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey),
    }
  },
  get: () => ephemeralKeyPair,
  getPublicJwk: async () => ephemeralKeyPair ? crypto.subtle.exportKey('jwk', ephemeralKeyPair.publicKey) : null,
}

function enableAuthzSection() {
  const section = document.getElementById('authz-section')
  if (section) {
    section.style.opacity = '1'
    section.style.pointerEvents = 'auto'
  }
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

  // Restore scope checkboxes (if persisted; otherwise leave HTML defaults)
  if (Array.isArray(saved.scopes)) {
    const set = new Set(saved.scopes)
    const boxes = document.querySelectorAll('#authz-section input[type="checkbox"]')
    for (const b of boxes) {
      if (b.disabled) continue // openid stays checked regardless
      b.checked = set.has(b.value)
    }
  }

  // Restore hint inputs
  if (saved.hints && typeof saved.hints === 'object') {
    for (const f of HINT_FIELDS) {
      const el = document.getElementById(f)
      if (el && typeof saved.hints[f] === 'string') el.value = saved.hints[f]
    }
  }
}

function saveSettings() {
  const psRadio = document.querySelector('#ps-list input[name="ps"]:checked')
  const psCustom = document.getElementById('ps-custom')?.value?.trim() || ''
  const ps = psRadio ? psRadio.value : DEFAULT_PS

  const scopes = Array.from(
    document.querySelectorAll('#authz-section input[type="checkbox"]:checked')
  ).map(b => b.value)

  const hints = {}
  for (const f of HINT_FIELDS) {
    const v = document.getElementById(f)?.value?.trim()
    if (v) hints[f] = v
  }

  localStorage.setItem(SETTINGS_KEY, JSON.stringify({ ps, ps_custom: psCustom, scopes, hints }))
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
  const authz = document.getElementById('authz-section')
  if (!authz) return
  // Any input/change inside the authz section saves and refreshes the summary.
  authz.addEventListener('change', () => { saveSettings(); updatePSCurrent() })
  authz.addEventListener('input', () => { saveSettings(); updatePSCurrent() })
  // Typing in the custom URL field implicitly selects the custom radio.
  const customInput = document.getElementById('ps-custom')
  const customRadio = document.getElementById('ps-custom-radio')
  if (customInput && customRadio) {
    customInput.addEventListener('focus', () => { customRadio.checked = true; saveSettings(); updatePSCurrent() })
  }
}

// ── Initialization ──

const agentName = getAgentName()
document.getElementById('agent-name').textContent = agentName

// Restore PS / scopes / hints from localStorage and start auto-saving on edit
loadSettings()
wireSettingsAutosave()

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

// The authz section is always enabled now — Continue kicks off the
// bootstrap ceremony if no agent_token has been minted yet.
enableAuthzSection()
document.documentElement.classList.remove('show-auth')

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
  const savedBindingKey = localStorage.getItem('aauth-binding-key')
  if (savedBindingKey) {
    try {
      await fetch('/binding/forget', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binding_key: savedBindingKey }),
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
