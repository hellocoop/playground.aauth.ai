// ── State ──

let sessionId = null
let agentToken = null
let ephemeralKeyPair = null // CryptoKeyPair — private key never exported

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

// ── WebAuthn helpers ──

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

// ── Authentication ──

async function loginWithPasskey() {
  const optionsRes = await fetch('/webauthn/login/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  })
  const options = await optionsRes.json()

  const credential = await navigator.credentials.get({
    publicKey: parseRequestOptions(options),
    mediation: 'optional',
  })

  const verifyRes = await fetch('/webauthn/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      response: serializeAssertion(credential),
      challenge: options.challenge,
    }),
  })
  const result = await verifyRes.json()

  if (result.verified) {
    sessionId = result.sessionId
    localStorage.setItem('aauth-session-id', sessionId)
    const recoveredName = result.username
    if (recoveredName) {
      localStorage.setItem('aauth-agent-name', recoveredName)
      document.getElementById('agent-name').textContent = recoveredName
    }
    setAuthenticated(recoveredName || agentName)
    await generateAndSaveAgentToken()
    return true
  }
  return false
}

async function registerPasskey() {
  const username = agentName
  const optionsRes = await fetch('/webauthn/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  })
  const options = await optionsRes.json()

  const credential = await navigator.credentials.create({ publicKey: parseCreationOptions(options) })

  const verifyRes = await fetch('/webauthn/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      response: serializeCredential(credential),
      challenge: options.challenge,
    }),
  })
  const result = await verifyRes.json()

  if (result.verified) {
    sessionId = result.sessionId
    localStorage.setItem('aauth-session-id', sessionId)
    localStorage.setItem('aauth-has-passkey', 'true')
    setAuthenticated(username)
    await generateAndSaveAgentToken()
    return true
  }
  return false
}

async function authenticate() {
  const hasPasskey = localStorage.getItem('aauth-has-passkey')

  if (hasPasskey) {
    try {
      if (await loginWithPasskey()) return
    } catch (err) {
      console.log('Login failed, trying registration:', err.message)
    }
  }

  try {
    await registerPasskey()
  } catch (err) {
    console.error('Registration failed:', err)
  }
}

// ── UI updates ──

function setAuthenticated(username) {
  document.documentElement.classList.remove('show-auth')
  document.getElementById('auth-info').classList.remove('hidden')
  document.getElementById('auth-user').textContent = username
  document.getElementById('token-section').classList.remove('disabled')
  document.getElementById('agent-id-row').classList.remove('hidden')
  document.getElementById('authz-btn').classList.remove('hidden')
}

function displayAgentToken(data) {
  const payload = decodeJWTPayload(data.agent_token)
  document.getElementById('agent-id').textContent = data.agent_id
  const raw = document.getElementById('agent-token-raw')
  raw.classList.add('encoded')
  raw.innerHTML = renderEncodedJWT(data.agent_token)
  document.getElementById('token-payload').innerHTML = renderJSON(payload)
}

// ── Agent token management ──

async function generateAndSaveAgentToken() {
  if (!sessionId) return

  // Generate ephemeral Ed25519 key pair — private key stays as CryptoKey
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  ephemeralKeyPair = keyPair

  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)

  const res = await fetch('/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionId,
    },
    body: JSON.stringify({ ephemeral_jwk: publicJwk, agent_local: agentName }),
  })
  const data = await res.json()

  agentToken = data.agent_token

  // Persist: token string in localStorage, CryptoKey pair in IndexedDB
  localStorage.setItem('aauth-agent-token', data.agent_token)
  await saveKeyPair(keyPair)

  displayAgentToken(data)
  enableAuthzSection()
}

async function restoreAgentToken() {
  const savedToken = localStorage.getItem('aauth-agent-token')
  if (!savedToken) return false

  // Check expiry
  const payload = decodeJWTPayload(savedToken)
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp <= now) {
    localStorage.removeItem('aauth-agent-token')
    return false
  }

  // Restore key pair from IndexedDB
  const keyPair = await loadKeyPair()
  if (!keyPair) {
    localStorage.removeItem('aauth-agent-token')
    return false
  }

  agentToken = savedToken
  ephemeralKeyPair = keyPair

  displayAgentToken({
    agent_token: savedToken,
    agent_id: payload.sub,
  })
  enableAuthzSection()
  return true
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
const DEFAULT_PS = 'https://issuer.hello-beta.net'

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

// Update auth button text
if (localStorage.getItem('aauth-has-passkey')) {
  document.getElementById('auth-btn').textContent = 'Sign in with Passkey'
} else {
  document.getElementById('auth-btn').textContent = 'Create Passkey'
}

// Wire up the auth button
document.getElementById('auth-btn').addEventListener('click', authenticate)

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

// Restore PS / scopes / hints from localStorage and start auto-saving on edit
loadSettings()
wireSettingsAutosave()

// Check for existing session on page load
const savedSession = localStorage.getItem('aauth-session-id')
if (!savedSession) {
  // No session stored → definitely unauthenticated, reveal the form now.
  document.documentElement.classList.add('show-auth')
}
if (savedSession) {
  fetch('/session', {
    headers: { 'X-Session-Id': savedSession },
  }).then(res => res.json()).then(async (data) => {
    if (!data.valid) {
      localStorage.removeItem('aauth-session-id')
      document.documentElement.classList.add('show-auth')
    } else {
      sessionId = savedSession
      localStorage.setItem('aauth-has-passkey', 'true')
      const name = data.username || agentName
      localStorage.setItem('aauth-agent-name', name)
      document.getElementById('agent-name').textContent = name
      setAuthenticated(name)

      // Try to restore saved token, generate new one if can't
      const restored = await restoreAgentToken()
      if (!restored) {
        await generateAndSaveAgentToken()
      }

      // If the user is returning from a PS interaction (same-tab redirect
      // back to '/'), resume polling where we left off.
      window.resumePendingInteraction?.()
    }
  })
}
