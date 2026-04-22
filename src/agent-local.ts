// Server-side generator for the local part of an aauth identifier.
// Per draft-hardt-aauth-bootstrap §Bootstrap Overview, the agent server
// mints `aauth:local@domain`. The local part is opaque and MUST NOT be
// derived from any user identifier — generating it here keeps it
// decoupled from the (PS, user_sub) pair on the binding.

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

function pick<T>(list: readonly T[]): T {
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  return list[buf[0] % list.length]
}

export function generateAgentLocal(): string {
  return `${pick(adjectives)}-${pick(nouns)}-${pick(verbs)}`
}
