/* ── Desktop app (Tauri): every operation goes through Rust commands ── */
/* ── Language: Italian (default) or English. The Italian text is the key of the dictionary
      (window.NTB_EN, files ui/i18n/en-*.js): __('testo italiano', {n: 3}) returns the English text
      when the language is English, otherwise the Italian one; {name} placeholders are replaced.
      Changing the language reloads the page, so every string is evaluated with a fixed language. ── */
const LANG = (() => { try { return localStorage.getItem('ntb-lang') === 'en' ? 'en' : 'it'; } catch(e){ return 'it'; } })();
const LOC = LANG === 'en' ? 'en-GB' : 'it-IT';
const NTB_EN = window.NTB_EN || {};
const __ = (it, vars) => {
  let s = LANG === 'en' && NTB_EN[it] !== undefined ? NTB_EN[it] : it;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => k in vars ? vars[k] : m);
  return s;
};
/* static HTML: texts and attributes are translated once at load, keeping the surrounding spaces */
function translateStatic(){
  if (LANG !== 'en') return;
  document.documentElement.lang = 'en';
  const tr1 = raw => {
    const core = raw.trim();
    return core && NTB_EN[core] !== undefined ? raw.replace(core, NTB_EN[core]) : raw;
  };
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode: n => /^(SCRIPT|STYLE)$/.test(n.parentNode.nodeName) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT });
  for (let n = w.nextNode(); n; n = w.nextNode()) n.nodeValue = tr1(n.nodeValue);
  document.querySelectorAll('[title],[aria-label],[alt]').forEach(el => ['title', 'aria-label', 'alt'].forEach(a => {
    if (el.hasAttribute(a)) el.setAttribute(a, tr1(el.getAttribute(a)));
  }));
  document.title = tr1(document.title);
}
translateStatic();

const TAURI = window.__TAURI__ && window.__TAURI__.core;
if (!TAURI){
  document.body.innerHTML = '<p style="padding:24px;font-family:sans-serif">' + __('Network Toolbox funziona solo come app desktop.') + '</p>';
  throw new Error('Tauri non disponibile');
}
// language of the backend messages (errors, checks, notes)
TAURI.invoke('set_lang', {lang: LANG}).catch(() => {});
const DESKTOP_TOOLS = new Set(['home', 'ping', 'trace', 'sweep', 'lan', 'wol', 'dns', 'portscan', 'whois', 'blacklist', 'myip', 'subnet',
  'headers', 'ssl', 'email', 'ntp', 'snmp', 'smtp', 'pwgen', 'numconv', 'uuid', 'wifi']);
const COMMANDS = {
  '/api/ping': 'ping', '/api/ping/stream': 'ping_stream',
  '/api/traceroute': 'traceroute', '/api/traceroute/stream': 'traceroute_stream',
  '/api/wol': 'wol',
  '/api/dns': 'dns', '/api/blacklist': 'blacklist',
  '/api/whois': 'whois', '/api/subnet': 'subnet', '/api/myip': 'myip',
  '/api/headers': 'headers', '/api/ssl': 'ssl', '/api/emailheader': 'emailheader', '/api/ntp': 'ntp',
  '/api/snmp': 'snmp', '/api/smtp': 'smtp_test',
  '/api/pwgen': 'pwgen_password', '/api/pwgen/estimate': 'pwgen_estimate',
 
  '/api/numconv': 'numconv', '/api/uuid': 'uuid_generate', '/api/uuid/inspect': 'uuid_inspect'
};
const tauriError = e => String(e && e.message || e).replace(/^invalid args `req` for command `\w+`: /, __('Dati non validi: '));
const $ = id => document.getElementById(id);
const val = id => $(id).value.trim();
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

/* ── theme (button in the top bar) ── */
const themeBtn = $('theme-btn');
const THEME_ICON = {
  dark: '<circle cx="10" cy="10" r="3.5"/><path d="M10 2v1.8M10 16.2V18M2 10h1.8M16.2 10H18M4.3 4.3l1.3 1.3M14.4 14.4l1.3 1.3M4.3 15.7l1.3-1.3M14.4 5.6l1.3-1.3"/>',
  light: '<path d="M16.5 12.3A7 7 0 017.7 3.5a7 7 0 108.8 8.8z"/>'
};
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  $('theme-txt').textContent = t === 'dark' ? __('Tema chiaro') : __('Tema scuro');
  $('theme-ico').innerHTML = THEME_ICON[t];
  document.querySelector('meta[name="theme-color"]').content = t === 'dark' ? '#141c27' : '#eef2f6';
}
// dark by default (the system preference is not used); only a choice made with the button is remembered
let theme = 'dark';
try { theme = localStorage.getItem('ntb-theme') === 'light' ? 'light' : 'dark'; } catch(e){}
applyTheme(theme);
themeBtn.onclick = () => { theme = theme === 'dark' ? 'light' : 'dark'; applyTheme(theme); try{ localStorage.setItem('ntb-theme', theme); }catch(e){} };

/* ── language (flag button next to the theme button) ── */
const FLAGS = {
  it: '<svg viewBox="0 0 3 2" class="flag" aria-hidden="true"><rect width="1" height="2" fill="#008c45"/><rect x="1" width="1" height="2" fill="#f4f5f0"/><rect x="2" width="1" height="2" fill="#cd212a"/></svg>',
  en: '<svg viewBox="0 0 60 30" class="flag" aria-hidden="true"><rect width="60" height="30" fill="#012169"/><path d="M0 0l60 30M60 0L0 30" stroke="#fff" stroke-width="6"/><path d="M0 0l60 30M60 0L0 30" stroke="#c8102e" stroke-width="2.4" clip-path="url(#ukc)"/><path d="M30 0v30M0 15h60" stroke="#fff" stroke-width="10"/><path d="M30 0v30M0 15h60" stroke="#c8102e" stroke-width="6"/><clipPath id="ukc"><path d="M30 15h30v15zM30 15v15H0zM30 15H0V0zM30 15V0h30z"/></clipPath></svg>'
};
$('lang-ico').innerHTML = FLAGS[LANG];
$('lang-btn').title = LANG === 'en' ? 'English — switch to Italian (Italiano)' : "Italiano — passa all'inglese (English)";
$('lang-btn').setAttribute('aria-label', $('lang-btn').title);
$('lang-btn').onclick = () => {
  try { localStorage.setItem('ntb-lang', LANG === 'en' ? 'it' : 'en'); } catch(e){}
  location.reload();
};

const allowed = v => !!v && !!$('view-' + v) && DESKTOP_TOOLS.has(v);
window.addEventListener('hashchange', () => { const v = location.hash.slice(1); if (allowed(v)) show(v); });

/* ── status: version and Internet connectivity ── */
let appVersion = '', pcName = '', pcIp = '';
const brandTip = () => { document.querySelector('.brand').title = [pcName, pcIp].filter(Boolean).join(' · '); };
async function online(){
  let s = null;
  try { s = await TAURI.invoke('internet_check'); } catch(e){}
  const ok = !!(s && s.online), at = new Date().toLocaleTimeString(LOC);
  if (s && s.local_ip) pcIp = s.local_ip;
  np.net = s;
  brandTip();
  npRender();
  const svc = $('svc');
  svc.classList.remove('checking'); svc.classList.toggle('down', !ok);
  $('svc-txt').textContent = ok ? __('Internet raggiungibile') : __('Nessuna connessione a Internet');
  svc.title = (ok ? __('Internet raggiungibile ({target}, {ms} ms)', {target: s.target, ms: s.rtt_ms}) : __('Nessuna risposta da Internet (ping a 1.1.1.1 e 8.8.8.8)'))
    + '\n' + __('Ultimo controllo: {t}', {t: at});
}
/* ── home screen: path PC → gateway → Internet ── */
const NP_PC = {
  cable: '<rect x="3" y="4" width="18" height="11.5" rx="1.8"/><path d="M8.5 20h7M12 15.5V20"/>',
  wifi: '<path d="M4.5 15.5V7a1.5 1.5 0 011.5-1.5h12A1.5 1.5 0 0119.5 7v8.5"/><path d="M2.5 18.5h19"/><path d="M9.3 11.4a3.8 3.8 0 015.4 0M11.95 13.6h.1"/>',
  vpn: '<path d="M12 3l7 3v5.2c0 4.4-3 7.9-7 9.3-4-1.4-7-4.9-7-9.3V6z"/><rect x="9.25" y="10.5" width="5.5" height="4.5" rx="1"/><path d="M10.5 10.5V9a1.5 1.5 0 013 0v1.5"/>',
  other: '<rect x="3" y="4" width="18" height="11.5" rx="1.8"/><path d="M8.5 20h7M12 15.5V20"/>'
};
const NP_KIND = {cable: __('via cavo'), wifi: __('via Wi-Fi'), vpn: __('via VPN'), other: ''};
const np = {path: null, net: null, pub: null, key: null, pubAt: 0};
const fmtMs = v => Number(v).toLocaleString(LOC, {maximumFractionDigits: v < 10 ? 1 : 0});
const npMs = v => v === null || v === undefined ? '—' : (v < 1 ? '<1' : fmtMs(v)) + ' ms';
function npRender(){
  const p = np.path || {}, n = np.net, pub = np.pub;
  const pc = $('np-pc'), gw = $('np-gw'), net = $('np-net');
  $('np-pc-ico').innerHTML = '<svg viewBox="0 0 24 24">' + (NP_PC[p.kind] || NP_PC.other) + '</svg>';
  $('np-pc-name').textContent = (pcName || __('questo PC')).split('.')[0];
  $('np-pc-ip').textContent = p.local_ip || pcIp || '—';
  pc.className = 'np-node ' + (!np.path ? '' : p.local_ip ? 'ok' : 'down');
  pc.title = [NP_KIND[p.kind] ? __('Connesso {kind}', {kind: NP_KIND[p.kind]}) : '', p.if_name, p.if_descr].filter(Boolean).join(' · ') + '\n' + __('Apri Rete locale');
  $('np-gw-name').textContent = p.gateway_name || (p.gateway ? 'gateway' : np.path ? __('nessun gateway') : 'gateway');
  $('np-gw-ip').textContent = p.gateway || '—';
  gw.className = 'np-node ' + (!np.path ? '' : !p.gateway ? 'down' : p.gateway_rtt_ms !== null && p.gateway_rtt_ms !== undefined ? 'ok' : '');
  gw.title = p.gateway ? (p.gateway_name ? p.gateway_name + '\n' : '') + __('Ping a {ip}', {ip: p.gateway}) : __('Nessuna route predefinita');
  $('np-l1-ms').textContent = npMs(p.gateway_rtt_ms);
  $('np-l1').classList.toggle('down', !!np.path && !p.gateway);
  const on = !!(n && n.online);
  const org = pub && pub.org ? pub.org.replace(/^AS\d+\s+/, '') : '';
  $('np-net-name').textContent = org || (n && !on ? __('nessuna connessione') : 'Internet');
  $('np-net-ip').textContent = pub && pub.ip ? pub.ip : '—';
  net.className = 'np-node ' + (!n ? '' : on ? 'ok' : 'down');
  net.title = (pub && pub.org ? pub.org + '\n' : '') + (pub && pub.hostname ? pub.hostname + '\n' : '')
    + (on ? __('Latenza verso {target}', {target: n.target}) : __('Nessuna risposta da 1.1.1.1 e 8.8.8.8')) + (pub && pub.ip ? '\n' + __('Whois e posizione di {ip}', {ip: pub.ip}) : '');
  $('np-l2-ms').textContent = on ? npMs(n.rtt_ms) : '—';
  $('np-l2').classList.toggle('down', !!n && !on);
}
async function npPublic(){
  np.pubAt = Date.now();
  const d = await call('/api/myip');
  np.pub = d && !d.error ? d : null;
  npRender();
}
async function npPath(){
  try { np.path = await TAURI.invoke('net_path'); } catch(e){ np.path = null; }
  const key = np.path ? (np.path.local_ip || '') + '|' + (np.path.gateway || '') : '';
  // public IP at startup and when the PC IP or the gateway change (e.g. VPN)
  if (key !== np.key){ np.key = key; npPublic(); }
  npRender();
}
$('np-pc').addEventListener('click', () => show('lan'));
$('np-gw').addEventListener('click', () => {
  const g = np.path && np.path.gateway; if (!g) return;
  show('ping'); $('ping-host').value = g; $('view-ping').querySelector('form').requestSubmit();
});
$('np-net').addEventListener('click', () => {
  const ip = np.pub && np.pub.ip; if (!ip) return;
  show('whois'); $('whois-host').value = ip; $('view-whois').querySelector('form').requestSubmit();
});

/* ── home screen clock: 24 h with seconds, full date below ── */
const CLOCK_T = new Intl.DateTimeFormat(LOC, {hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'});
const CLOCK_D = new Intl.DateTimeFormat(LOC, {weekday:'long', day:'numeric', month:'long', year:'numeric'});
function clock(){
  const d = new Date();
  $('clock-time').textContent = CLOCK_T.format(d);
  $('clock-time').dateTime = d.toISOString();
  $('clock-date').textContent = CLOCK_D.format(d);
  // next update at the start of the next second
  setTimeout(clock, 1000 - d.getMilliseconds() + 5);
}
clock();

// connectivity and network path every 30 s
const tick = () => { online(); npPath(); };
tick(); setInterval(tick, 30000);

/* ── logo and available tools ── */
$('brand-logo').addEventListener('error', e =>
  e.target.replaceWith(Object.assign(document.createElement('div'), {className:'brand-mark', textContent:'NT'})));
document.querySelectorAll('.nav-item').forEach(n => { if (!DESKTOP_TOOLS.has(n.dataset.view)) n.remove(); });
document.querySelectorAll('.nav-group').forEach(g => { if (!g.querySelector('.nav-item')) g.remove(); });
TAURI.invoke('app_info').then(i => {
  pcName = i.hostname; pcIp = pcIp || i.ip || ''; brandTip(); npRender();
  appVersion = i.version;
  $('home-version').textContent = i.version;
  document.title = 'Network Toolbox — ' + i.hostname.split('.')[0];
}).catch(() => {});

/* ── custom title bar: minimise, maximise, close ── */
const WIN = window.__TAURI__.window && window.__TAURI__.window.getCurrentWindow();
if (WIN){
  $('win-ctl').classList.remove('hidden');
  $('win-min').onclick = () => WIN.minimize();
  $('win-max').onclick = () => WIN.toggleMaximize();
  $('win-close').onclick = () => WIN.close();
  const MAX_ICO = {false:'<rect x=".5" y=".5" width="9" height="9"/>', true:'<rect x=".5" y="2.5" width="7" height="7"/><path d="M2.5 2.5V.5h7v7h-2"/>'};
  const syncMax = async () => {
    const m = await WIN.isMaximized().catch(() => false);
    $('win-max-ico').innerHTML = MAX_ICO[m];
    $('win-max').title = $('win-max').ariaLabel = m ? __('Ripristina') : __('Ingrandisci');
  };
  WIN.onResized(syncMax); syncMax();
}

/* ── navigation ── */
function show(view){
  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.dataset.view === view) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view));
  $('home-btn').setAttribute('aria-pressed', view === 'home');
  const first = $('view-' + view).querySelector('input[type=text]:not([data-nofocus]), textarea');
  if (first && matchMedia('(min-width: 901px)').matches) first.focus();
  history.replaceState(null, '', '#' + view);
  if (view === 'wifi') setTimeout(wifiShown);   // after the script has loaded
}
document.querySelectorAll('.nav-item').forEach(n => n.addEventListener('click', () => show(n.dataset.view)));
$('home-btn').addEventListener('click', () => {
  show('home');
  // Home also refreshes the path and, at most every 10 s, the public IP
  online(); npPath(); if (Date.now() - np.pubAt > 10000) npPublic();
});
// The home screen at startup; with Ctrl+R the open view stays
show(allowed(location.hash.slice(1)) ? location.hash.slice(1) : 'home');

/* ── tabs (SNMP, generators, DNS) ── */
const tabState = {snmp:'v2c', uuid:'v4', wifi:'nets', dns:'compare', lan:'scan', email:'domain'};
document.querySelectorAll('[data-tabs]').forEach(bar => {
  const group = bar.dataset.tabs;
  bar.querySelectorAll('button').forEach(btn => btn.addEventListener('click', () => {
    bar.querySelectorAll('button').forEach(b => b.setAttribute('aria-selected', b === btn));
    tabState[group] = btn.dataset.tab;
    document.querySelectorAll('#view-' + group + ' [data-pane]').forEach(p =>
      p.classList.toggle('hidden', !p.dataset.pane.split(' ').includes(group + '-' + btn.dataset.tab)));
    if (group === 'snmp') snmpSecLevel();
    if (group === 'uuid') uuidChanged();
  }));
});
function snmpSecLevel(){
  const v3 = tabState.snmp === 'v3', lv = $('snmp-seclevel').value;
  $('snmp-auth-row').classList.toggle('hidden', !v3 || lv === 'noAuthNoPriv');
  $('snmp-priv-proto').classList.toggle('hidden', lv !== 'authPriv');
  $('snmp-priv-pass').classList.toggle('hidden', lv !== 'authPriv');
}
$('snmp-seclevel').onchange = snmpSecLevel;

/* ── presets (the labels are translated here: the values are machine data) ── */
function presets(id, items, pick){
  const box = $(id);
  items.forEach(([label, value]) => {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'chip'; b.textContent = __(label);
    b.onclick = () => pick(value);
    box.appendChild(b);
  });
}
const PORTS = [
  ['Comuni','21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443'],
  ['Web','80,443,8000,8080,8443,8888,3000,5000,9000,9090'],
  ['Posta','25,110,143,465,587,993,995'],
  ['Database','1433,1521,3306,5432,6379,9200,27017'],
  ['Windows e AD','53,88,135,139,389,445,464,636,3268,3269,3389,5985,5986'],
  ['VoIP','5060,5061'],
  ['Gestione apparati','22,23,161,443,4443,8443,10443']
];
presets('scan-presets', PORTS, v => { $('scan-ports').value = v; });
presets('snmp-oids', [
  ['Descrizione','sysDescr.0|get'], ['Uptime','sysUpTime.0|get'], ['Nome','sysName.0|get'],
  ['Interfacce','ifTable|table'], ['Indirizzi IP','ipAddrTable|table'], ['Dischi e memoria','hrStorageTable|table'],
  ['Carico CPU','hrProcessorLoad|walk'], ['Materiali di consumo','prtMarkerSuppliesTable|table']
], v => { const [oid, mode] = v.split('|'); $('snmp-oid').value = oid; $('snmp-mode').value = mode; });
presets('ntp-presets', [['INRIM','ntp1.inrim.it'], ['pool.ntp.org','pool.ntp.org'], ['Cloudflare','time.cloudflare.com'], ['Google','time.google.com']],
  v => { $('ntp-host').value = v; });
presets('dns-presets', [['Google 8.8.8.8','8.8.8.8'], ['Cloudflare 1.1.1.1','1.1.1.1'], ['Quad9 9.9.9.9','9.9.9.9']], v => {
  const list = val('dns-servers').split(',').map(x => x.trim()).filter(Boolean);
  $('dns-servers').value = (list.includes(v) ? list.filter(x => x !== v) : list.concat(v)).join(', ');
});

/* ── options stored in the browser ── */
const store = {
  get(k, d){ try { const v = localStorage.getItem('ntb-' + k); return v === null ? d : JSON.parse(v); } catch(e){ return d; } },
  set(k, v){ try { localStorage.setItem('ntb-' + k, JSON.stringify(v)); } catch(e){} }
};
[['opt-resolve', true], ['opt-live', true], ['trace-resolve', true], ['trace-live', true], ['dns-system', true], ['sweep-tcp', false], ['lan-svc', false], ['smtp-relay', false], ['smtp-auth', false], ['smtp-send', false]].forEach(([id, d]) => {
  $(id).checked = store.get(id, d);
  $(id).addEventListener('change', () => store.set(id, $(id).checked));
});
$('dns-servers').value = store.get('dns-servers', '');
$('dns-servers').addEventListener('change', () => store.set('dns-servers', val('dns-servers')));

/* ── network ── */
async function call(ep, payload){
  const cmd = COMMANDS[ep];
  if (!cmd) return {error: __('Strumento non disponibile.')};
  try { return await TAURI.invoke(cmd, {req: payload || {}}); }
  catch(e){ return {error: tauriError(e)}; }
}

/* ── render helper ── */
function colorize(text){
  return esc(text)
    .replace(/\b(error|errore|failed|unreachable|timed out|timeout|refused|no response|interrotto|NXDOMAIN|SERVFAIL)\b/gi, '<span class="c-err">$1</span>')
    .replace(/(ttl=\d+|time=[\d.]+ ?ms|\b0% packet loss)/gi, '<span class="c-ok">$1</span>')
    .replace(/(\b(?:\d{1,3}\.){3}\d{1,3}\b)/g, '<span class="c-ip">$1</span>');
}
const pre = t => '<pre class="out">' + colorize(t || __('(nessuna risposta)')) + '</pre>';
/* New line at the end of a live output: only that line is coloured, not the whole text */
function addLine(preEl, line){
  preEl.insertAdjacentHTML('beforeend', colorize(line) + '\n');
  preEl.scrollTop = preEl.scrollHeight;
}
const kv = items => '<div class="kv">' + items.filter(i => i[1] !== undefined && i[1] !== null && i[1] !== '')
  .map(([k, v, c]) => '<div class="kv-item ' + (c || '') + '"><div class="kv-k">' + esc(k) + '</div><div class="kv-v">' + esc(v) + '</div></div>').join('') + '</div>';
const rows = list => '<table class="tbl">' + list.map(([k, v, c]) =>
  '<tr><td class="k">' + esc(k) + '</td><td class="v ' + (c || '') + '">' + esc(v) + '</td></tr>').join('') + '</table>';
const tags = list => '<div class="tags">' + list.map(t => '<span class="tag">' + esc(t) + '</span>').join('') + '</div>';
const fail = msg => ({status:'err', html:'<div class="msg-err">' + esc(msg) + '</div>'});
const STATE = {run: __('In corso'), ok: __('Completato'), warn: __('Da verificare'), err: __('Errore'), stop: __('Fermato')};
const ICON  = {run:'', ok:'✓', warn:'!', err:'✕', stop:'■'};

/* ── result strips ── */
const MAX_STRIPS = 6;
function ensureBar(box){
  if (box.querySelector('.results-bar')) return;
  box.insertAdjacentHTML('afterbegin',
    '<div class="results-bar"><h2>' + __('Risultati') + '</h2><button type="button" class="link-btn">' + __('Cancella risultati') + '</button></div><div class="stack"></div>');
  box.querySelector('.link-btn').onclick = () => { box.innerHTML = ''; };
}
function newStrip(view, tool, target){
  const box = $('res-' + view); ensureBar(box);
  const stack = box.querySelector('.stack');
  const el = document.createElement('article');
  el.className = 'strip run fresh';
  el.innerHTML = '<div class="strip-band"></div><div>'
    + '<div class="strip-head"><span class="strip-tool">' + esc(tool) + '</span>'
    + (target ? '<span class="strip-target">' + esc(target) + '</span>' : '')
    + '<span class="strip-state"></span>'
    + '<span class="strip-time">' + new Date().toLocaleTimeString(LOC) + '</span>'
    + '<button type="button" class="strip-copy">' + __('Copia') + '</button></div>'
    + '<div class="strip-body"><span class="spinner"></span>' + __('Operazione in corso…') + '</div></div>';
  setState(el, 'run');
  el.querySelector('.strip-copy').onclick = e => {
    navigator.clipboard?.writeText(el._text || el.querySelector('.strip-body').innerText).then(() => {
      e.target.textContent = __('Copiato'); setTimeout(() => e.target.textContent = __('Copia'), 1400);
    });
  };
  stack.prepend(el);
  [...stack.children].slice(MAX_STRIPS).forEach(s => s.remove());
  return el;
}
function setState(el, st){
  el.classList.remove('run', 'ok', 'warn', 'err', 'stop'); el.classList.add(st);
  el.querySelector('.strip-state').textContent = (ICON[st] ? ICON[st] + ' ' : '') + STATE[st];
}
/* Form buttons while a test runs; returns the function that restores them.
   With data-stop (ping, traceroute, subnet scan, local network, ports, TLS certificates) the submit button stays in place and becomes
   "Stop": the click calls the command that interrupts the test. The other forms are disabled. */
function busy(form){
  if (!form) return () => {};
  const sb = form.dataset.stop && form.querySelector('button[type=submit]');
  if (!sb){
    const btns = [...form.querySelectorAll('button')];
    btns.forEach(b => b.disabled = true);
    return () => btns.forEach(b => b.disabled = false);
  }
  const id = form._run = (form._run || 0) + 1;
  if (!sb.dataset.label){ sb.dataset.label = sb.textContent; sb.style.minWidth = sb.getBoundingClientRect().width + 'px'; }
  sb.textContent = __('Ferma'); sb.classList.add('secondary'); sb.disabled = false;
  form.dataset.running = '1';
  return () => {
    if (form._run !== id) return;   // another test has meanwhile started from the same form
    sb.textContent = sb.dataset.label; sb.classList.remove('secondary'); sb.disabled = false;
    delete form.dataset.running;
  };
}
async function run(view, tool, target, fn, form){
  const strip = newStrip(view, tool, target);
  const idle = busy(form);
  try {
    const r = await fn();
    setState(strip, r.status || 'ok');
    strip.querySelector('.strip-body').innerHTML = r.html;
    if (r.text) strip._text = r.text;
    if (r.data) strip._data = r.data;   // data for the result buttons (filter, CSV)
  } catch(e) {
    setState(strip, 'err');
    strip.querySelector('.strip-body').innerHTML = '<div class="msg-err">' + esc(e.message) + '</div>';
  } finally {
    idle();
  }
}

function setName(strip, meta, target){
  if (!meta) return;
  const parts = [];
  if (meta.name && meta.name !== target) parts.push(meta.name);
  if (meta.ip && meta.ip !== target) parts.push(meta.ip);
  if (meta.ptr && meta.ptr !== meta.name && meta.ptr !== target) parts.push(meta.ptr);
  if (!parts.length) return;
  const el = document.createElement('span');
  el.className = 'strip-name'; el.textContent = parts.join(' · ');
  strip.querySelector('.strip-target').after(el);
}

/* Execution with line-by-line output (Tauri Channel) */
async function runLive(view, tool, target, ep, payload, form, finish){
  const strip = newStrip(view, tool, target);
  const bodyEl = strip.querySelector('.strip-body');
  bodyEl.innerHTML = '<pre class="out live-cursor"></pre>';
  const preEl = bodyEl.querySelector('pre');
  const idle = busy(form);
  let text = '', meta = null;
  const onMsg = m => {
    if (m.meta){ meta = m.meta; setName(strip, meta, target); }
    else if (m.line !== undefined){ text += m.line + '\n'; addLine(preEl, m.line); }
  };
  try {
    // The lines arrive on a Channel; we also wait for the "done" message,
    // which may arrive after the command response.
    let doneResolve; const done = new Promise(r => doneResolve = r);
    const ch = new TAURI.Channel();
    ch.onmessage = m => { onMsg(m); if (m.done) doneResolve(); };
    let end;
    try { end = await TAURI.invoke(COMMANDS[ep], {req: payload, onEvent: ch}); }
    catch(e){ throw new Error(tauriError(e)); }
    await Promise.race([done, new Promise(r => setTimeout(r, 3000))]);
    preEl.classList.remove('live-cursor');
    // stopped with "Stop": the summary covers what has arrived so far
    const stopped = !!(end && end.stopped);
    const res = finish(text, meta, stopped);
    setState(strip, stopped ? 'stop' : res.status);
    if (res.prefix) bodyEl.insertAdjacentHTML('afterbegin', res.prefix);
  } catch(e) {
    preEl.classList.remove('live-cursor');
    setState(strip, 'err');
    bodyEl.insertAdjacentHTML('afterbegin', '<div class="msg-err">' + esc(e.message) + '</div>');
    if (!text) preEl.remove();
  } finally {
    idle();
  }
}

/* Ping / traceroute summaries */
function pingSummary(out, meta, stopped){
  // stopped before any packet had an outcome: no statistics to show
  if (stopped && !/packets transmitted/.test(out)) return {status: 'stop', prefix: ''};
  const loss = (out.match(/(\d+(?:\.\d+)?)% packet loss/) || [])[1];
  const sent = (out.match(/(\d+) packets transmitted/) || [])[1];
  const recv = (out.match(/(\d+) (?:packets )?received/) || [])[1];
  const rtt  = out.match(/= ([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+) ms/);
  const l = loss === undefined ? null : parseFloat(loss);
  const st = l === null ? 'err' : l === 0 ? 'ok' : l === 100 ? 'err' : 'warn';
  const name = meta ? meta.ptr || (meta.name && !/^\d+\.\d+\.\d+\.\d+$/.test(meta.name) ? meta.name : (meta.ptr || '')) : '';
  return {status: st, prefix: kv([
    [__('Nome host'), name || __('nessun record PTR'), 'txt' + (name ? '' : ' warn')],
    [__('Pacchetti ricevuti'), sent ? __('{recv} su {sent}', {recv, sent}) : '—', st + ' big'],
    [__('Perdita'), l === null ? '—' : l + '%', (l === 0 ? 'ok' : 'err') + ' big'],
    [__('RTT medio'), rtt ? rtt[2] + ' ms' : '—', 'big'],
    [__('Min / max'), rtt ? rtt[1] + ' / ' + rtt[3] + ' ms' : '—']
  ]) + '<div style="height:14px"></div>'};
}
/* Payload chosen in the Ping form: preset or free value (empty = default in the backend) */
function pingSize(){
  const v = $('ping-size').value;
  return v === 'custom' ? val('ping-size-custom') : v;
}
$('ping-size').addEventListener('change', () => {
  const custom = $('ping-size').value === 'custom';
  $('ping-size-custom-box').classList.toggle('hidden', !custom);
  if (custom) $('ping-size-custom').focus();
});
function mtuSummary(out, meta, stopped){
  const m = out.match(/^mtu=(\d+)/m);
  if (!m) return {status: stopped ? 'stop' : 'err', prefix: ''};
  const mtu = parseInt(m[1], 10);
  // the backend marks the doubtful result with a line starting "(!)"
  return {status: /^\(!\)/m.test(out) ? 'warn' : 'ok', prefix: kv([
    [__('MTU del percorso'), mtu + ' ' + __('byte'), 'big ok'],
    [__('Dati massimi per pacchetto'), (mtu - 28) + ' ' + __('byte'), 'big'],
    [__('Per un ping senza frammentazione'), __('dimensione dati ≤ {n}', {n: mtu - 28}), 'txt']
  ]) + '<div style="height:14px"></div>'};
}
function traceSummary(out, meta, stopped){
  const hops = out.split('\n').filter(l => /^\s*\d+\s/.test(l));
  if (stopped && !hops.length) return {status: 'stop', prefix: ''};
  const lost = hops.filter(l => /^\s*\d+\s+\*/.test(l)).length;
  return {status: !hops.length || lost === hops.length ? 'err' : lost ? 'warn' : 'ok',
    prefix:'<p class="summary">' + __('<strong>{n}</strong> salti', {n: hops.length}) + (lost ? __(', di cui <strong>{n}</strong> senza risposta', {n: lost}) : '') + '</p>'};
}

/* ═════════ tools ═════════ */
const tools = {

  ping: form => {
    const host = val('ping-host'), count = val('ping-count') || 4;
    if (!host) return $('ping-host').focus();
    const payload = {host, count, interval_ms: val('ping-interval'), timeout_ms: val('ping-timeout'), resolve: $('opt-resolve').checked,
      size: pingSize(), dont_fragment: $('opt-df').checked};
    if ($('opt-live').checked) return runLive('ping', 'Ping', host, '/api/ping/stream', payload, form, pingSummary);
    run('ping', 'Ping', host, async () => {
      const d = await call('/api/ping', payload);
      if (d.error) return fail(d.error);
      const r = pingSummary(d.output, d.meta, d.stopped);
      return {status: d.stopped ? 'stop' : r.status, html: r.prefix + pre(d.output)};
    }, form);
  },

  /* Path MTU: echo with "Do not fragment" and growing size, always live (the steps are the result) */
  pingmtu: form => {
    if (form.dataset.running) return;
    const host = val('ping-host');
    if (!host) return $('ping-host').focus();
    const payload = {host, timeout_ms: val('ping-timeout'), resolve: false, mtu: true};
    runLive('ping', __('Ping — MTU'), host, '/api/ping/stream', payload, form, mtuSummary);
  },

  traceroute: form => {
    const host = val('trace-host');
    if (!host) return $('trace-host').focus();
    const payload = {host, max_hops: val('trace-hops'), timeout_ms: val('trace-timeout'), resolve: $('trace-resolve').checked};
    if ($('trace-live').checked) return runLive('trace', 'Traceroute', host, '/api/traceroute/stream', payload, form, traceSummary);
    run('trace', 'Traceroute', host, async () => {
      const d = await call('/api/traceroute', payload);
      if (d.error) return fail(d.error);
      const r = traceSummary(d.output, d.meta, d.stopped);
      return {status: d.stopped ? 'stop' : r.status, html: r.prefix + pre(d.output)};
    }, form);
  },

  sweep: async form => {
    const cidr = val('sweep-cidr');
    if (!cidr) return $('sweep-cidr').focus();
    const tcp = $('sweep-tcp').checked;
    const strip = newStrip('sweep', __('Scansione'), cidr + (tcp ? ' + TCP' : ''));
    const body = strip.querySelector('.strip-body');
    body.innerHTML = '<p class="summary"><span class="spinner"></span>' + __('Avvio della scansione…') + '</p>'
      + '<div class="lan-progress"><i></i></div><div class="sw-hosts"></div>';
    const sum = body.querySelector('.summary'), bar = body.querySelector('.lan-progress'), box = body.querySelector('.sw-hosts');
    const idle = busy(form);
    let n = 0, done = 0, total = 0, tbody = null;
    const live = () => {
      sum.innerHTML = '<span class="spinner"></span>' + __('<strong>{n}</strong> host attivi · {done} su {total} controllati', {n, done, total});
      bar.firstChild.style.width = Math.round(done / Math.max(total, 1) * 100) + '%';
    };
    const table = () => {
      box.innerHTML = '<table class="tbl"><thead><tr><th>' + __('Indirizzo') + '</th><th>' + __('Nome') + '</th><th>' + __('Rilevato con') + '</th><th>RTT</th><th>MAC</th><th></th></tr></thead><tbody></tbody></table>';
      return box.querySelector('tbody');
    };
    // hosts appear at the bottom of the table, in the order they arrive; when
    // the name arrives the same host is sent again and its row is updated
    const ch = new TAURI.Channel();
    ch.onmessage = m => {
      if (m.start) total = m.start.total;
      else if (m.progress) done = m.progress.done;
      else if (m.host){
        const row = tbody && tbody.querySelector('tr[data-ip="' + m.host.ip + '"]');
        if (row) row.outerHTML = sweepRow(m.host);
        else { n++; (tbody || (tbody = table())).insertAdjacentHTML('beforeend', sweepRow(m.host)); }
      }
      live();
    };
    try {
      const d = await TAURI.invoke('sweep', {req: {cidr, tcp}, onEvent: ch});
      // when the scan is closed (finished or stopped) the table goes in address order
      n = d.alive.length;
      bar.remove();
      sum.innerHTML = __('<strong>{n}</strong> host attivi ', {n})
        + (d.stopped ? __('· scansione fermata dopo {checked} indirizzi su {total} ({s} secondi)', {checked: d.checked, total: d.total, s: d.elapsed_s})
                     : __('su {total} in {s} secondi', {total: d.total, s: d.elapsed_s}))
        + (d.tcp || d.local ? '' : __('. Gli host che bloccano il ping possono mancare: attiva la verifica TCP.'))
        + (d.local ? '' : __('. Rete non collegata direttamente a questo PC: MAC non disponibili.'));
      if (n) (tbody || table()).innerHTML = d.alive.map(sweepRow).join('');
      else box.innerHTML = '';
      setState(strip, d.stopped ? 'stop' : n ? 'ok' : 'warn');
    } catch(e) {
      setState(strip, 'err');
      body.innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>';
    } finally {
      idle();
    }
  },

  wifi: () => wifiScan(true),
  wifimon: form => wifiMonitor(form),

  lan: async form => {
    const cidr = val('lan-cidr'), services = $('lan-svc').checked;
    $('res-lan').innerHTML = '';
    lan.hosts = []; lan.open = new Set(); lan.start = null; lan.summary = null; lan.done = 0;
    const strip = newStrip('lan', __('Rete locale'), cidr || (lan.def ? lan.def.cidr : __('rete di questo PC')));
    strip.querySelector('.strip-copy').onclick = e => lanCopy(e.target);
    const body = strip.querySelector('.strip-body');
    body.innerHTML = '<div class="lan-head"><p class="summary" id="lan-sum"><span class="spinner"></span>' + __('Avvio della scansione…') + '</p>'
      + '<div class="lan-tools"><label>' + __('Filtra') + ' <input type="text" id="lan-filter" spellcheck="false" autocomplete="off"></label>'
      + '<select id="lan-sort" aria-label="' + __('Ordinamento') + '"><option value="ip">' + __('Ordina per IP') + '</option><option value="name">' + __('Ordina per nome') + '</option>'
      + '<option value="kind">' + __('Ordina per tipo') + '</option><option value="svc">' + __('Ordina per servizi') + '</option></select></div></div>'
      + '<div class="lan-progress" id="lan-prog"><i></i></div><div class="lan-list" id="lan-list"></div>';
    $('lan-sort').value = lan.sort;
    $('lan-filter').addEventListener('input', lanRender);
    $('lan-sort').addEventListener('change', () => { lan.sort = $('lan-sort').value; lanRender(); });
    const idle = busy(form);
    const ch = new TAURI.Channel();
    ch.onmessage = m => {
      if (m.start){ lan.start = m.start; lanSummary(); }
      else if (m.progress){ lan.done = m.progress.done; lanProgress(m.progress.done, m.progress.total); lanSummary(); }
      else if (m.host){
        // a host arrives as soon as it answers, and again, complete, when the details are in
        const i = lan.hosts.findIndex(h => h.ip === m.host.ip);
        if (i < 0) lan.hosts.push(m.host); else lan.hosts[i] = m.host;
        lanRender(); lanSummary();
      }
    };
    try {
      const sum = await TAURI.invoke('lan_scan', {req: {cidr, services}, onEvent: ch});
      lan.summary = sum;
      // scan closed (also with "Stop"): no more details are coming
      lan.hosts.forEach(h => { h.pending = false; });
      lanProgress(1, 1); $('lan-prog').classList.add('hidden');
      setState(strip, sum.stopped ? 'stop' : sum.found ? 'ok' : 'warn');
      lanSummary(); lanRender();
    } catch(e) {
      setState(strip, 'err');
      body.innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>';
    } finally {
      idle();
    }
  },

  dns: form => {
    // "Domain analysis": a single command, result in tabs
    if (tabState.dns === 'domain'){
      const domain = val('dnsd-domain'), axfr = $('dnsd-axfr').checked;
      if (!domain) return $('dnsd-domain').focus();
      return run('dns', __('Analisi DNS'), domain, async () => {
        try { return dnsDomainRender(await TAURI.invoke('dns_domain', {req: {domain, axfr}})); }
        catch(e) { return fail(tauriError(e)); }
      }, form);
    }
    let host = val('dns-host'), type = $('dns-type').value;
    if (!host) return $('dns-host').focus();
    if (type === 'DMARC'){ type = 'TXT'; host = '_dmarc.' + host.replace(/^_dmarc\./, ''); }
    const servers = val('dns-servers').split(',').map(x => x.trim()).filter(Boolean);
    if ($('dns-system').checked || !servers.length) servers.unshift('');
    store.set('dns-servers', val('dns-servers'));
    const label = servers.length > 1 ? servers.length + ' server' : (servers[0] || __('resolver di sistema'));
    run('dns', 'DNS ' + $('dns-type').value, host + '  @ ' + label, async () => {
      const d = await call('/api/dns', {host, type, servers});
      if (d.error) return fail(d.error);
      const res = d.results;
      const okRes = res.filter(r => r.status === 'NOERROR');
      const sig = r => r.data.join('|');
      const ref = okRes.length ? sig(okRes[0]) : null;
      const differ = res.length > 1 && new Set(res.map(r => r.status + '#' + sig(r))).size > 1;
      const anyErr = res.some(r => !['NOERROR', 'NXDOMAIN'].includes(r.status));
      const empty = res.every(r => !r.data.length);
      let html = '';
      if (d.name && d.name !== host) html += '<p class="summary">' + __('Nome interrogato: <strong>{name}</strong>', {name: esc(d.name)}) + '</p>';
      if (res.length > 1) html += '<p class="summary">' + (differ ? __('<strong class="c-warn">Le risposte non coincidono</strong> fra i server interrogati.') : __('<strong class="c-ok">Risposte identiche</strong> su tutti i {n} server.', {n: res.length})) + '</p>';
      html += '<table class="tbl"><thead><tr><th>Server</th><th>' + __('Esito') + '</th><th>' + __('Risposta') + '</th><th>' + __('Tempo') + '</th></tr></thead><tbody>'
        + res.map(r => {
            const cls = r.status === 'NOERROR' ? (r.data.length ? 'ok' : 'warn') : r.status === 'NXDOMAIN' ? 'warn' : 'err';
            const lbl = r.status === 'NOERROR' && !r.data.length ? __('Nessun record') : r.status;
            return '<tr class="' + (differ && ref !== null && sig(r) !== ref ? 'diff' : '') + '">'
              + '<td class="m">' + esc(r.server) + (r.server_ip && r.server_ip !== r.server ? '<br><span class="c-dim">' + esc(r.server_ip) + '</span>' : '') + '</td>'
              + '<td><span class="pill ' + cls + '">' + esc(lbl) + '</span>'
              + ((r.flags || []).length ? '<span class="dx-flags" title="' + __('AA = risposta autoritativa, RA = ricorsione disponibile, AD = validata con DNSSEC dal server') + '">' + esc(r.flags.join(' ')) + '</span>' : '') + '</td>'
              + '<td class="m">' + esc(r.data.join('\n') || '—') + '</td>'
              + '<td class="m">' + (r.time_ms !== null ? r.time_ms + ' ms' : '—') + '</td></tr>';
          }).join('') + '</tbody></table>';
      html += '<div class="sub">' + __('Risposta completa') + '</div>' + pre(res.map(r => ';; ' + r.server + '\n' + (r.answers.join('\n') || __('(nessuna risposta)'))).join('\n\n'));
      return {status: anyErr ? 'err' : (differ || empty) ? 'warn' : 'ok', html};
    }, form);
  },

  portscan: async form => {
    const host = val('scan-host'), ports = val('scan-ports') || PORTS[0][1];
    if (!host) return $('scan-host').focus();
    const strip = newStrip('portscan', __('Porte TCP'), host);
    const body = strip.querySelector('.strip-body');
    body.innerHTML = '<p class="summary"><span class="spinner"></span>' + __('Avvio della scansione…') + '</p>'
      + '<div class="lan-progress"><i></i></div><div class="sw-hosts"></div>';
    const sum = body.querySelector('.summary'), bar = body.querySelector('.lan-progress'), box = body.querySelector('.sw-hosts');
    const idle = busy(form);
    let n = 0, done = 0, total = 0, tbody = null;
    // open ports appear as soon as they are found, in the order they arrive
    const ch = new TAURI.Channel();
    ch.onmessage = m => {
      if (m.start){ total = m.start.total; setName(strip, {ip: m.start.ip}, host); }
      else if (m.progress) done = m.progress.done;
      else if (m.port){
        n++;
        if (!tbody){ box.innerHTML = portTable(''); tbody = box.querySelector('tbody'); }
        tbody.insertAdjacentHTML('beforeend', portRow(m.port));
      }
      sum.innerHTML = '<span class="spinner"></span>' + __('<strong>{n}</strong> porte aperte · {done} su {total} controllate', {n, done, total});
      bar.firstChild.style.width = Math.round(done / Math.max(total, 1) * 100) + '%';
    };
    try {
      const d = await TAURI.invoke('portscan', {req: {host, ports}, onEvent: ch});
      // when the scan is closed (finished or stopped) the full summary, with the ports in order
      const open = d.results.filter(r => r.status === 'OPEN');
      body.innerHTML = portsBody(d);
      setState(strip, d.stopped ? 'stop' : open.length ? 'ok' : 'warn');
    } catch(e) {
      setState(strip, 'err');
      body.innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>';
    } finally {
      idle();
    }
  },

  whois: form => {
    const host = val('whois-host');
    if (!host) return $('whois-host').focus();
    run('whois', 'Whois', host, async () => {
      const d = await call('/api/whois', {host});
      if (d.error) return fail(d.error);
      const g = d.geo || {};
      let html = '';
      if (g.status === 'success') html += kv([['IP', g.query, 'info'], [__('Paese'), g.country, 'txt'], [__('Regione'), g.regionName, 'txt'], [__('Città'), g.city, 'txt'], ['Provider', g.org, 'txt']]);
      else if (g.status === 'private') html += '<p class="summary">' + __('<strong>{ip}</strong> è un indirizzo privato: nessuna posizione geografica.', {ip: esc(g.query)}) + '</p>';
      return {html: html + pre(d.output)};
    }, form);
  },

  blacklist: form => {
    const host = val('bl-host');
    if (!host) return $('bl-host').focus();
    run('blacklist', 'Blacklist', host, async () => {
      const d = await call('/api/blacklist', {host});
      if (d.error) return fail(d.error);
      const listed = d.results.filter(r => r.state === 'listed');
      const errs = d.results.filter(r => r.state === 'error');
      const lbl = {listed:['err', __('✕ Presente')], clean:['ok', __('✓ Pulito')], error:['warn', __('! Non verificabile')]};
      let html = kv([
        [__('IP controllato'), d.ip, 'info big'],
        [__('Nome (PTR)'), d.ptr || __('nessun record PTR'), 'txt' + (d.ptr ? '' : ' warn')],
        [__('Presente in'), __('{n} liste su {total}', {n: listed.length, total: d.results.length}), (listed.length ? 'err' : 'ok') + ' big']]
        .concat(d.resolver ? [[__('DNS usato'), d.resolver]] : []));
      const order = {listed:0, error:1, clean:2};
      html += '<div style="height:14px"></div><table class="tbl"><thead><tr><th>' + __('Lista') + '</th><th>' + __('Esito') + '</th><th>' + __('Dettaglio') + '</th></tr></thead><tbody>'
        + d.results.slice().sort((a, b) => order[a.state] - order[b.state]).map(r =>
          '<tr><td>' + esc(r.list) + '<br><span class="c-dim mono" style="font-size:12.5px">' + esc(r.zone) + '</span></td>'
          + '<td><span class="pill ' + lbl[r.state][0] + '">' + lbl[r.state][1] + '</span></td>'
          + '<td class="m">' + esc(r.detail || '—') + '</td></tr>').join('') + '</tbody></table>';
      return {status: listed.length ? 'err' : errs.length ? 'warn' : 'ok', html};
    }, form);
  },

  wol: form => {
    const mac = val('wol-mac'), name = val('wol-name'), broadcast = val('wol-bcast') || '255.255.255.255', port = $('wol-port').value;
    if (!mac) return $('wol-mac').focus();
    run('wol', 'Wake-on-LAN', name ? name + ' · ' + mac : mac, async () => {
      const d = await call('/api/wol', {mac, broadcast, port});
      if (d.error) return fail(d.error);
      if (name) saveWol({name, mac: d.mac, broadcast: d.broadcast, port: String(d.port)});
      return {html:'<p class="summary">' + __('Inviati <strong>{sent}</strong> magic packet a <strong>{mac}</strong> tramite {bcast}:{port}', {sent: d.sent, mac: esc(d.mac), bcast: esc(d.broadcast), port: d.port})
        + __('. Una workstation impiega di solito 30–90 secondi ad avviarsi: poi verifica con un ping.') + '</p>'};
    }, form);
  },

  myip: form => run('myip', __('IP pubblico'), '', async () => {
    const d = await call('/api/myip');
    if (d.error) return fail(d.error);
    return {html: kv([[__('IP pubblico'), d.ip, 'info big'], ['Provider', d.org], ['Reverse DNS', d.hostname],
      [__('Città'), d.city], [__('Regione'), d.region], [__('Paese'), d.country], [__('Fuso orario'), d.timezone]])};
  }, form),

  subnet: form => {
    const cidr = val('subnet-cidr');
    if (!cidr) return $('subnet-cidr').focus();
    run('subnet', 'Subnet', cidr, async () => {
      const d = await call('/api/subnet', {cidr});
      if (d.error) return fail(d.error);
      let html = kv([
        [__('Rete'), d.cidr, 'info big'], [__('Host utilizzabili'), d.usable_hosts.toLocaleString(LOC), 'ok big'],
        [__('Primo host'), d.first_host], [__('Ultimo host'), d.last_host], ['Broadcast', d.broadcast],
        ['Netmask', d.netmask], ['Wildcard', d.wildcard], [__('Indirizzi totali'), d.total_hosts.toLocaleString(LOC)],
        [__('Tipo'), d.is_private ? __('Privata (RFC 1918)') : __('Pubblica'), d.is_private ? 'txt' : 'warn txt']]);
      if (d.subnets && d.subnets.length) html += '<div class="sub">' + __('Suddivisione in /{p}', {p: d.sub_prefix}) + '</div>' + tags(d.subnets);
      return {html};
    }, form);
  },

  headers: form => {
    const url = val('hdr-url');
    if (!url) return $('hdr-url').focus();
    run('headers', 'Header HTTP', url, async () => {
      const d = await call('/api/headers', {url});
      if (d.error) return fail(d.error);
      return headersRender(d);
    }, form);
  },


  ssl: async form => {
    const host = val('ssl-host'), port = val('ssl-port') || 443;
    if (!host) return $('ssl-host').focus();
    const req = {host, port, protocol: $('ssl-proto').value, sni: val('ssl-sni'), scan: $('ssl-scan').checked};
    const strip = newStrip('ssl', __('Certificato TLS'), host + ':' + port);
    const body = strip.querySelector('.strip-body');
    const idle = busy(form);
    // stays on the open tab even when the result is redrawn
    const show = (d, running) => {
      const cur = body.querySelector('.seg.rtabs [aria-selected="true"]');
      const r = sslRender(d, cur ? cur.dataset.rtab : 'chk', running);
      body.innerHTML = r.html; strip._text = r.text;
      return r;
    };
    // with the scan the certificate arrives first, then the suites as the server accepts them
    let live = null;
    const ch = new TAURI.Channel();
    ch.onmessage = m => {
      if (m.result) live = Object.assign({}, m.result, {scan: {versions: [], tried: 0}});
      else if (m.scan && live){
        const s = m.scan, vs = live.scan.versions;
        if (s.progress) live.scan.tried = s.progress.tried;
        else if (s.cipher){
          let v = vs.find(x => x.name === s.cipher.version);
          if (!v) vs.push(v = {name: s.cipher.version, accepted: true, status: 'run', ciphers: []});
          v.ciphers.push(s.cipher.cipher);
        } else if (s.version){
          const i = vs.findIndex(x => x.name === s.version.name);
          if (i < 0) vs.push(s.version); else vs[i] = s.version;
        }
      }
      if (live) show(live, true);
    };
    try {
      const d = await TAURI.invoke('ssl', {req, onEvent: ch});
      const r = show(d, false);
      setState(strip, d.scan && d.scan.stopped ? 'stop' : r.status);
    } catch(e) {
      setState(strip, 'err');
      body.innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>';
    } finally {
      idle();
    }
  },

  email: form => {
    const domain = val('email-domain'), selector = val('email-sel'), ip = val('email-ip');
    if (!domain) return $('email-domain').focus();
    run('email', __('Record email'), domain, async () => {
      const d = await call('/api/emailheader', {domain, selector, ip});
      if (d.error) return fail(d.error);
      return emailDomainRender(d.domain_report);
    }, form);
  },

  emailraw: form => {
    const raw = $('email-raw').value.trim();
    if (!raw) return $('email-raw').focus();
    const subj = (raw.match(/^Subject:\s*(.+)$/mi) || [])[1] || '';
    run('email', __('Header messaggio'), subj.slice(0, 60), async () => {
      const d = await call('/api/emailheader', {raw_header: raw});
      if (d.error) return fail(d.error);
      return emailMessageRender(d.message);
    }, form);
  },

  snmp: form => {
    const req = snmpReq();
    if (!req.host) return $('snmp-host').focus();
    if (sn.mode === 'dev') return snmpDevice(form, req);
    const oid = val('snmp-oid'), mode = $('snmp-mode').value;
    snSugHide();
    run('snmp', 'SNMP ' + ({get: 'GET', walk: 'WALK', table: __('Tabella')})[mode], req.host + '  ' + oid, async () => {
      const d = await call('/api/snmp', Object.assign({oid, mode}, req));
      if (d.error) return fail(d.error);
      return snmpOidRender(d);
    }, form);
  },

  pwgen: form => {
    const req = pwReq();
    $('res-pwgen').innerHTML = '';
    const target = __('{len} caratteri × {count}', {len: req.length, count: req.count}) + (req.pronounceable ? __(', pronunciabile') : '');
    run('pwgen', 'Password', target, async () => {
      const d = await call('/api/pwgen', req);
      if (d.error) return fail(d.error);
      pwLast = {req, data: d};
      pwRemember('Password', d.passwords);
      return {status: d.strength === 'debole' ? 'warn' : 'ok', html: pwBody(d)};
    }, form);
    // the strip's "Copy" would also copy numbers and captions: each row has its own
    $('res-pwgen').querySelectorAll('.strip-copy').forEach(b => b.remove());
  },

  uuid: form => {
    const v = tabState.uuid.slice(1), req = {version: v};
    if (v === '5'){
      req.namespace = $('uuid-ns').value === 'custom' ? val('uuid-ns-custom') : $('uuid-ns').value;
      req.names = $('uuid-names').value;
    } else req.count = $('uuid-count').value;
    const n = v === '5' ? $('uuid-names').value.split('\n').filter(l => l.trim()).length : +req.count;
    run('uuid', 'UUID v' + v, n + ' UUID', async () => {
      const d = await call('/api/uuid', req);
      if (d.error) return fail(d.error);
      return {status:'ok', html: uuidBody(d)};
    }, form);
    // strip "Copy" replaced by "Copy all" (without numbers and captions)
    $('res-uuid').querySelectorAll('.strip-copy').forEach(b => b.remove());
  },

  uuidinspect: form => {
    const text = val('uuid-in');
    if (!text) return $('uuid-in').focus();
    run('uuid', __('Analisi'), text, async () => {
      const d = await call('/api/uuid/inspect', {text});
      if (d.error) return fail(d.error);
      return {status: d.variant.startsWith('RFC') ? 'ok' : 'warn', html: uuidInspectBody(d)};
    }, form);
  },

  smtp: async form => {
    const host = val('smtp-host'), port = val('smtp-port') || '25';
    if (!host) return $('smtp-host').focus();
    smtpSave();
    const auth = $('smtp-auth').checked, send = $('smtp-send').checked;
    const req = {host, port, security: $('smtp-sec').value, ehlo: val('smtp-ehlo'), relay: $('smtp-relay').checked,
      auth, user: auth ? val('smtp-user') : '', password: auth ? $('smtp-pass').value : '',
      send, from: send ? val('smtp-from') : '', to: send ? val('smtp-to') : '', subject: send ? val('smtp-subject') : '', body: send ? $('smtp-body').value : ''};
    const strip = newStrip('smtp', __('Server SMTP'), host + ':' + port);
    const body = strip.querySelector('.strip-body');
    body.innerHTML = '<pre class="out live-cursor"></pre>';
    const preEl = body.querySelector('pre');
    const btns = [...form.querySelectorAll('button')];
    btns.forEach(b => b.disabled = true);
    let text = '';
    const ch = new TAURI.Channel();
    ch.onmessage = m => {
      if (m.line === undefined) return;
      text += m.line + '\n'; addLine(preEl, m.line);
    };
    try {
      const d = await TAURI.invoke('smtp_test', {req, onEvent: ch});
      const r = smtpRender(d);
      setName(strip, {ip: d.ip, name: d.ptr}, host);
      setState(strip, r.status);
      body.innerHTML = r.html;
    } catch(e) {
      setState(strip, 'err');
      body.innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>' + (text ? pre(text) : '');
    } finally {
      btns.forEach(b => b.disabled = false);
    }
  },

  ntp: form => {
    const host = val('ntp-host');
    if (!host) return $('ntp-host').focus();
    run('ntp', 'NTP', host, async () => {
      const d = await call('/api/ntp', {host});
      if (d.error) return fail(d.error);
      const off = Math.abs(d.offset_ms), oc = off < 10 ? 'ok' : off < 100 ? 'warn' : 'err';
      const sc = d.stratum <= 2 ? 'ok' : d.stratum <= 4 ? 'warn' : 'err';
      return {status: oc === 'err' || sc === 'err' ? 'err' : oc === 'warn' || sc === 'warn' ? 'warn' : 'ok',
        html: kv([[__('Scarto da questo PC'), d.offset_ms + ' ms', oc + ' big'], ['Stratum', d.stratum, sc + ' big'], [__('Ritardo di rete'), d.delay_ms + ' ms', 'big'],
          [__('Riferimento'), d.ref_id], [__('Ora del server'), d.ntp_time], [__('Ora di questo PC'), d.local_time],
          ['Root delay', d.root_delay_ms + ' ms'], ['Root dispersion', d.root_disp_ms + ' ms'], [__('Intervallo di poll'), d.poll_interval + ' s'], ['Leap', d.leap]])};
    }, form);
  }
};

/* ── TCP ports ── */
const portRow = r => '<tr><td class="m">' + r.port + '</td><td><span class="pill ok">' + __('Aperta') + '</span></td><td class="m">' + esc(r.banner || '—') + '</td></tr>';
const portTable = rows => '<table class="tbl"><thead><tr><th>' + __('Porta') + '</th><th>' + __('Stato') + '</th><th>' + __('Banner del servizio') + '</th></tr></thead><tbody>' + rows + '</tbody></table>';
/* Summary of a closed scan: open, closed and filtered ports kept apart */
function portsBody(d){
  const open = d.results.filter(r => r.status === 'OPEN');
  let html = '<p class="summary">' + __('<strong>{n}</strong> porte aperte ', {n: open.length})
    + (d.stopped ? __('· scansione fermata dopo {n} porte su {total}', {n: d.results.length, total: d.total}) : __('su {n} controllate', {n: d.results.length})) + '</p>';
  if (open.length) html += portTable(open.map(portRow).join(''));
  const refused = d.results.filter(r => r.status === 'CLOSED').map(r => r.port);
  const filtered = d.results.filter(r => r.status === 'FILTERED').map(r => r.port);
  const group = (title, ports) => !ports.length ? '' : '<div class="sub">' + title + '</div>'
    + (ports.length > 60 ? '<p class="summary">' + __('{n} porte', {n: ports.length}) + '</p>' : tags(ports.map(String)));
  html += group(__('Chiuse: l\'host risponde con un rifiuto'), refused);
  html += group(__('Filtrate: nessuna risposta, probabilmente un firewall'), filtered);
  const errs = d.results.filter(r => r.status === 'FILTERED' && r.banner);
  if (errs.length) html += '<div class="sub">' + __('Motivo') + '</div>' + rows(errs.map(r => [__('Porta {p}', {p: r.port}), r.banner]));
  if (!d.stopped && !open.length && !refused.length && filtered.length) html += '<p class="note">' + __('Nessuna porta ha risposto, nemmeno con un rifiuto: tra questo PC e l\'host c\'è un firewall che scarta il traffico, oppure l\'host è spento.') + '</p>';
  return html;
}

/* ── tabs inside a result (.seg.rtabs + [data-rpane]) ── */
const rtabs = (tabs, active) => '<div class="seg rtabs" role="tablist">' + tabs.map(([k, label, n]) =>
  '<button type="button" role="tab" data-rtab="' + k + '" aria-selected="' + (k === active) + '">' + esc(label)
  + (n === undefined ? '' : '<span class="n">' + n + '</span>') + '</button>').join('') + '</div>';
const rpane = (k, active, html) => '<div data-rpane="' + k + '"' + (k === active ? '' : ' class="hidden"') + '>' + html + '</div>';
document.addEventListener('click', e => {
  const btn = e.target.closest('.seg.rtabs button');
  if (!btn) return;
  const body = btn.closest('.strip-body');
  btn.parentNode.querySelectorAll('button').forEach(b => b.setAttribute('aria-selected', b === btn));
  body.querySelectorAll('[data-rpane]').forEach(p => p.classList.toggle('hidden', p.dataset.rpane !== btn.dataset.rtab));
});

/* ── HTTP headers: checks in order of severity, then path, cookies, CSP, headers ── */
const CHK_ICON = {ok:'✓', warn:'!', err:'✕', info:'i'};
const CHK_RANK = {err:0, warn:1, info:2, ok:3};
const chkPill = (st, txt) => '<span class="pill hx-pill ' + esc(st) + '">' + esc(txt === undefined ? (CHK_ICON[st] || '') : txt) + '</span>';
const HDR_TR = {https:'HTTPS', 'https-invalid': __('HTTPS, certificato non valido'), http: __('HTTP in chiaro')};
function headersRender(d){
  const checks = (d.checks || []).map((c, i) => [c, i]).sort((a, b) => (CHK_RANK[a[0].status] - CHK_RANK[b[0].status]) || (a[1] - b[1])).map(x => x[0]);
  const nErr = checks.filter(c => c.status === 'err').length, nWarn = checks.filter(c => c.status === 'warn').length;
  const hops = d.hops || [], last = hops.length - 1, cookies = d.cookies || [], csp = d.csp;
  const invalid = hops.some(h => h.transport === 'https-invalid'), plain = hops.some(h => h.transport === 'http');
  const sc = d.status_code, codeCls = sc < 300 ? 'ok' : sc < 400 ? 'warn' : 'err';
  const many = (n, one, more) => n + ' ' + (n === 1 ? one : more);
  const found = nErr || nWarn ? [nErr && many(nErr, __('errore'), __('errori')), nWarn && many(nWarn, __('avviso'), __('avvisi'))].filter(Boolean).join(' · ') : __('Tutti superati');
  const tls = invalid ? [__('Certificato'), __('Non valido'), 'err big txt']
    : plain ? [__('Trasporto'), hops[last].transport === 'http' ? __('HTTP in chiaro') : __('Redirect su HTTP'), 'warn big txt']
    : [__('Certificato'), __('Valido'), 'ok big txt'];
  let html = kv([[__('Risposta'), sc + ' ' + (d.status_text || ''), codeCls + ' big'],
    [__('Controlli'), found, (nErr ? 'err' : nWarn ? 'warn' : 'ok') + ' big txt'], tls,
    d.cdn ? ['CDN', d.cdn, 'info big txt'] : ['', '']]);
  if (invalid) html += '<p class="note">' + __('Il certificato non è stato accettato, quindi la risposta può essere stata scritta da chiunque si trovi sul percorso: gli header mostrati non provano nulla sulla sicurezza del sito.') + '</p>';

  const pChecks = '<table class="tbl smtp-checks hx-tbl"><thead><tr><th></th><th>' + __('Area') + '</th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
    + checks.map(c => '<tr><td>' + chkPill(c.status) + '</td><td class="k hx-area">' + esc(c.area) + '</td><td class="k">' + esc(c.name)
      + '</td><td class="m">' + esc(c.detail) + '</td></tr>').join('') + '</tbody></table>';

  const pHops = '<div class="hx-path">' + hops.map((h, i) => {
    const pills = [chkPill(i === last ? codeCls : 'neutral', h.status),
      chkPill(h.transport === 'https' ? 'ok' : h.transport === 'http' ? 'warn' : 'err', HDR_TR[h.transport] || h.transport)];
    if (h.hsts === true) pills.push(chkPill('ok', 'HSTS'));
    if (h.hsts === false) pills.push(chkPill('warn', __('senza HSTS')));
    if (h.cookies) pills.push(chkPill('neutral', __('imposta {n}', {n: many(h.cookies, 'cookie', 'cookie')})));
    return '<div class="hx-hop"><div class="hx-n">' + (i + 1) + '</div><div><div class="u">' + esc(h.url) + '</div><div class="meta">' + pills.join('') + '</div>'
      + (h.tls_error ? '<div class="hx-why">' + esc(h.tls_error) + '</div>' : '') + '</div><div class="t">' + esc(h.time_ms) + ' ms</div></div>';
  }).join('') + '</div>';

  const yn = b => chkPill(b ? 'ok' : 'err', b ? '✓' : '✕');
  const from = i => i === last ? __('destinazione') : __('passo {n}', {n: i + 1});
  const pCookies = !cookies.length ? '<p class="note hx-top">' + __('La risposta non imposta cookie.') + '</p>'
    : '<table class="tbl hx-tbl hx-ck"><thead><tr><th></th><th>' + __('Nome') + '</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>' + __('Dominio') + '</th><th>' + __('Durata') + '</th><th>' + __('Impostato da') + '</th></tr></thead><tbody>'
      + cookies.map(c => '<tr><td>' + chkPill(c.status) + '</td><td><span class="hx-name">' + esc(c.name) + '</span>'
        + (c.note ? '<span class="hx-why">' + esc(c.note) + '</span>' : '') + '</td><td>' + yn(c.secure) + '</td><td>' + yn(c.http_only) + '</td><td>'
        + chkPill(c.same_site === 'Strict' || c.same_site === 'Lax' ? 'ok' : 'warn', c.same_site || __('assente')) + '</td><td class="m">'
        + esc(c.domain || __('solo questo host')) + '</td><td class="m">' + esc(c.lifetime) + '</td><td class="m dim">' + from(c.hop) + '</td></tr>').join('')
      + '</tbody></table><p class="note">' + __('I valori dei cookie non vengono mostrati: possono essere token di sessione.') + '</p>';

  const pCsp = !csp ? '<p class="note hx-top">' + __('Il sito non invia una Content-Security-Policy.') + '</p>'
    : (csp.report_only ? '<p class="note hx-top">' + __('Solo <span class="mono">Content-Security-Policy-Report-Only</span>: le violazioni sono segnalate ma non bloccate.') + '</p>' : '')
      + '<table class="tbl smtp-checks hx-tbl"><tbody>'
      + csp.directives.map(x => '<tr><td>' + (x.status ? chkPill(x.status) : '') + '</td><td class="k"><span class="hx-name">' + esc(x.name) + '</span></td><td class="m">'
        + (x.sources.map(s => '<span class="hx-src ' + esc(s.level) + '">' + esc(s.value) + '</span>').join('') || '<span class="hx-dim">' + __('nessuna sorgente') + '</span>') + '</td></tr>').join('')
      + (csp.missing || []).map(m => '<tr><td>' + chkPill(m === 'script-src' ? 'err' : 'warn') + '</td><td class="k"><span class="hx-name hx-dim">' + esc(m)
        + '</span></td><td class="m hx-dim">' + __('assente') + '</td></tr>').join('')
      + '</tbody></table>';

  const all = Object.entries(d.headers || {});
  const tab = 'chk';
  html += rtabs([['chk', __('Controlli'), checks.length], ['hop', __('Percorso'), hops.length], ['ck', 'Cookie', cookies.length],
      ['csp', 'CSP', csp ? csp.directives.length : 0], ['hdr', 'Header', all.length]], tab)
    + rpane('chk', tab, pChecks) + rpane('hop', tab, pHops) + rpane('ck', tab, pCookies) + rpane('csp', tab, pCsp) + rpane('hdr', tab, rows(all));

  // "Copy" takes the whole result, not just the open tab
  const text = [__('Header HTTP') + ' · ' + d.final_url + ' · ' + sc + ' ' + (d.status_text || ''), '', __('CONTROLLI'),
    ...checks.map(c => '[' + (CHK_ICON[c.status] || '') + '] ' + c.area + ' · ' + c.name + ': ' + c.detail), '', __('PERCORSO'),
    ...hops.map((h, i) => (i + 1) + '. ' + h.url + '  ' + h.status + '  ' + (HDR_TR[h.transport] || h.transport) + '  ' + h.time_ms + ' ms'), '', 'COOKIE',
    ...(cookies.length ? cookies.map(c => __('{name}: Secure {secure}, HttpOnly {http}, SameSite {ss}, dominio {domain}, durata {life}, impostato da {from}',
      {name: c.name, secure: c.secure ? __('sì') : __('no'), http: c.http_only ? __('sì') : __('no'), ss: c.same_site || __('assente'),
       domain: c.domain || __('solo questo host'), life: c.lifetime, from: from(c.hop)}) + (c.note ? ' (' + c.note + ')' : '')) : [__('nessuno')]), '', 'CSP',
    ...(csp ? [...csp.directives.map(x => x.name + ' ' + x.sources.map(s => s.value).join(' ')), ...(csp.missing || []).map(m => m + ' (' + __('assente') + ')')] : [__('assente')]), '', 'HEADER',
    ...all.map(([k, v]) => k + ': ' + String(v).replace(/\n/g, '\n  '))].join('\n');
  return {status: codeCls === 'err' ? 'err' : (nErr || nWarn || invalid || plain) ? 'warn' : 'ok', html, text};
}

/* ── Email: domain analysis (SPF tree, DMARC and DKIM, MX and transport) and header analysis ── */
const emChecks = list => {
  const checks = (list || []).map((c, i) => [c, i]).sort((a, b) => (CHK_RANK[a[0].status] - CHK_RANK[b[0].status]) || (a[1] - b[1])).map(x => x[0]);
  const nErr = checks.filter(c => c.status === 'err').length, nWarn = checks.filter(c => c.status === 'warn').length;
  const many = (n, one, more) => n + ' ' + (n === 1 ? one : more);
  return {checks, nErr, nWarn,
    found: nErr || nWarn ? [nErr && many(nErr, __('errore'), __('errori')), nWarn && many(nWarn, __('avviso'), __('avvisi'))].filter(Boolean).join(' · ') : __('Tutti superati'),
    html: '<table class="tbl smtp-checks hx-tbl"><thead><tr><th></th><th>' + __('Area') + '</th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
      + checks.map(k => '<tr><td>' + chkPill(k.status) + '</td><td class="k hx-area">' + esc(k.area) + '</td><td class="k">' + esc(k.name)
        + '</td><td class="m">' + esc(k.detail) + '</td></tr>').join('') + '</tbody></table>',
    text: checks.map(k => '[' + (CHK_ICON[k.status] || '') + '] ' + k.area + ' · ' + k.name + ': ' + k.detail)};
};
const emRows = list => '<table class="tbl smtp-checks hx-tbl"><tbody>' + list.map(r => '<tr><td>' + (r.status ? chkPill(r.status) : '') + '</td><td class="k sp-tag"><span class="hx-name">'
  + esc(r.name) + '</span></td><td class="m">' + esc(r.value) + '</td><td class="m hx-dim">' + esc(r.detail) + '</td></tr>').join('') + '</tbody></table>';

function emailDomainRender(d){
  const c = emChecks(d.checks), spf = d.spf || {nodes: []}, dm = d.dmarc || {rows: []}, dkim = d.dkim || [], mx = d.mx || [], sts = d.mta_sts || {rows: []};
  const over = spf.lookups > 10;
  let html = kv([
    [__('Controlli'), c.found, (c.nErr ? 'err' : c.nWarn ? 'warn' : 'ok') + ' big txt'],
    ['SPF', !spf.found ? __('Assente') : over ? __('{n} lookup su 10', {n: spf.lookups}) : (spf.all || __('senza all')) + ' · ' + spf.lookups + ' lookup',
      (!spf.found || over || spf.all === '+all' ? 'err' : spf.all === '-all' || spf.all === '~all' ? 'ok' : 'warn') + ' big txt'],
    ['DMARC', dm.found ? 'p=' + (dm.policy || '?') : __('Assente'), (!dm.found ? 'err' : dm.policy === 'reject' || dm.policy === 'quarantine' ? 'ok' : 'warn') + ' big txt'],
    ['DKIM', dkim.length ? dkim.length + (dkim.length === 1 ? __(' selettore') : __(' selettori')) : __('Non trovato'), (dkim.length ? 'ok' : '') + ' big txt']]);

  // SPF: one mechanism per row, indented under the include that contains it
  const pSpf = !spf.found ? '<p class="note hx-top">' + __('Il dominio non ha un record SPF.') + '</p>'
    : '<div class="sp-tree">' + spf.nodes.map(n => '<div class="sp-node' + (n.level ? '' : ' root') + '" style="--l:' + n.level + '"><div><div class="sp-mech'
        + (n.status === 'off' ? ' hx-dim' : '') + '">' + esc(n.mechanism) + '</div>' + (n.result ? '<div class="sp-res">' + esc(n.result) + '</div>' : '')
        + (n.note ? '<div class="hx-why sp-err">' + esc(n.note) + '</div>' : '') + '</div><div class="sp-tags">'
        + (n.status === 'ok' ? chkPill('ok', __('decide')) : '') + (n.status === 'err' && !n.lookups ? chkPill('err', __('non valido')) : '')
        + (n.lookups ? chkPill(n.status === 'err' ? 'err' : 'neutral', n.lookups + ' lookup') : '') + '</div></div>').join('') + '</div>'
      + '<p class="note">' + __('{n} ricerche DNS su 10 ammesse, contate percorrendo tutto il record (ip4, ip6 e all non ne fanno).', {n: spf.lookups})
      + (spf.ip ? ' ' + __('Per {ip} l\'esito è <strong>{result}</strong>', {ip: esc(spf.ip), result: esc(spf.ip_result)}) + (spf.ip_match ? __(', deciso da <span class="mono">{m}</span>', {m: esc(spf.ip_match)}) : '') + '.' : '') + '</p>';

  const pDk = (dm.found ? '<p class="note hx-top"><span class="mono">' + esc(dm.name) + '</span> · <span class="mono">' + esc(dm.record) + '</span></p>' + emRows(dm.rows)
      : '<p class="note hx-top">' + __('Nessun record DMARC su <span class="mono">{name}</span>.', {name: esc(dm.name || '')}) + '</p>')
    + '<div class="sub">DKIM</div>'
    + (dkim.length ? emRows(dkim.map(k => ({status: k.status, name: k.selector, value: k.key, detail: k.note || (k.record.length > 70 ? k.record.slice(0, 70) + '…' : k.record)}))) : '<p class="note hx-top">' + __('Nessun selettore trovato.') + '</p>')
    + '<p class="note">' + __('Selettori provati: {list}. Il selettore vero può avere un altro nome: si scrive nel form oppure si legge dagli header di un messaggio.', {list: esc((d.selectors || []).join(', '))}) + '</p>';

  const act = h => '<div class="row-act"><button type="button" data-goto="smtp" data-host="' + esc(h.host) + '">' + __('Server SMTP') + '</button>'
    + '<button type="button" data-goto="ssl" data-host="' + esc(h.host) + '">' + __('Certificato') + '</button>'
    + (h.ipv4.length ? '<button type="button" data-goto="blacklist" data-host="' + esc(h.ipv4[0]) + '">Blacklist</button>' : '') + '</div>';
  const pMx = (!mx.length ? '<p class="note hx-top">' + __('Nessun record MX.') + '</p>'
    : '<table class="tbl hx-tbl hx-ck"><thead><tr><th></th><th>' + __('Priorità') + '</th><th>Server</th><th>' + __('Indirizzi') + '</th><th>' + __('Nome inverso') + '</th><th>' + __('Apri in') + '</th></tr></thead><tbody>'
      + mx.map(h => '<tr><td>' + chkPill(h.status) + '</td><td class="m">' + h.priority + '</td><td><span class="hx-name">' + esc(h.host || '.') + '</span>'
        + (h.note ? '<span class="hx-why">' + esc(h.note) + '</span>' : '') + '</td><td class="m sp-wrap">' + esc(h.ipv4.concat(h.ipv6).join('\n') || '—') + '</td><td class="m hx-dim">' + esc(h.ptr || '—')
        + '</td><td>' + (h.host && h.host !== '.' ? act(h) : '') + '</td></tr>').join('') + '</tbody></table>')
    + '<div class="sub">MTA-STS e TLS-RPT</div>'
    + (sts.found || d.tls_rpt ? emRows(sts.rows.concat(d.tls_rpt ? [d.tls_rpt] : [])) : '<p class="note hx-top">' + __('Né MTA-STS né TLS-RPT: il TLS verso il dominio resta facoltativo e senza rapporti.') + '</p>')
    + (sts.found && sts.url ? '<p class="note">' + __('Policy letta da <span class="mono">{url}</span>.', {url: esc(sts.url)}) + '</p>' : '')
    + (d.bimi ? '<div class="sub">BIMI</div><p class="note hx-top"><span class="mono">' + esc(d.bimi) + '</span></p>' : '');

  const tab = 'chk';
  html += rtabs([['chk', __('Controlli'), c.checks.length], ['spf', 'SPF', spf.found ? spf.lookups : 0], ['dk', __('DMARC e DKIM')], ['mx', __('MX e trasporto'), mx.length]], tab)
    + rpane('chk', tab, c.html) + rpane('spf', tab, pSpf) + rpane('dk', tab, pDk) + rpane('mx', tab, pMx);

  const text = ['Email · ' + d.domain, '', __('CONTROLLI'), ...c.text, '', 'SPF',
    ...(spf.found ? spf.nodes.map(n => '  '.repeat(n.level) + n.mechanism + (n.lookups ? ' [' + n.lookups + ' lookup]' : '') + (n.result ? ' → ' + n.result : '') + (n.note ? ' (' + n.note + ')' : '')) : [__('assente')]),
    '', 'DMARC', dm.found ? dm.record : __('assente'), ...dm.rows.map(r => r.name + ' = ' + r.value + ' (' + r.detail + ')'), '', 'DKIM',
    ...(dkim.length ? dkim.map(k => k.selector + ': ' + k.key + (k.note ? ' (' + k.note + ')' : '')) : [__('nessun selettore trovato')]), '', 'MX',
    ...(mx.length ? mx.map(h => h.priority + ' ' + (h.host || '.') + ' ' + h.ipv4.concat(h.ipv6).join(' ') + (h.ptr ? ' (' + h.ptr + ')' : '')) : [__('nessuno')]), '', __('MTA-STS E TLS-RPT'),
    ...sts.rows.concat(d.tls_rpt ? [d.tls_rpt] : []).map(r => r.name + ': ' + r.value + ' (' + r.detail + ')')].join('\n');
  return {status: (c.nErr || c.nWarn) ? 'warn' : 'ok', html, text};
}

function emailMessageRender(m){
  const c = emChecks(m.checks), hops = m.hops || [], a = m.auth || {}, scores = m.scores || [], sigs = m.signatures || [], all = m.headers || [];
  const secs = s => s < 120 ? s + ' s' : s < 7200 ? Math.round(s / 60) + ' min' : Math.round(s / 3600) + ' h';
  const cls = v => !v ? '' : v === 'pass' ? 'ok' : /^(none|neutral|softfail)$/.test(v) ? 'warn' : 'err';
  const methods = [['SPF', a.spf], ['DKIM', a.dkim], ['DMARC', a.dmarc]].filter(x => x[1]);
  const allPass = methods.length === 3 && methods.every(x => x[1] === 'pass');
  const worst = methods.some(x => cls(x[1]) === 'err') ? 'err' : methods.some(x => cls(x[1]) === 'warn') ? 'warn' : methods.length ? 'ok' : '';
  const slow = hops.some(h => h.status === 'warn');
  let html = kv([
    [__('Controlli'), c.found, (c.nErr ? 'err' : c.nWarn ? 'warn' : 'ok') + ' big txt'],
    [__('Autenticazione'), !methods.length ? '—' : allPass ? 'SPF · DKIM · DMARC' : methods.map(x => x[0] + ' ' + x[1]).join(' · '), worst + ' big txt'],
    [__('Consegna'), m.total_s !== null && m.total_s !== undefined ? __('{t} in {n} passi', {t: secs(m.total_s), n: hops.length}) : hops.length + (hops.length === 1 ? __(' passo') : __(' passi')), (slow ? 'warn' : '') + ' big txt'],
    [__('Mittente'), m.from || '—', '']]);

  const pChk = c.html + (sigs.length ? '<div class="sub">' + __('Firme DKIM del messaggio') + '</div><table class="tbl hx-tbl"><tbody>' + sigs.map(s => '<tr><td class="k sp-tag">' + __('Dominio') + '</td><td class="m">' + esc(s.domain)
    + '</td><td class="k sp-tag">' + __('Selettore') + '</td><td class="m">' + esc(s.selector) + '</td><td><div class="row-act"><button type="button" data-goto="email" data-domain="' + esc(s.domain)
    + '" data-selector="' + esc(s.selector) + '">' + __('Verifica la chiave') + '</button></div></td></tr>').join('') + '</tbody></table>' : '');

  const pHop = !hops.length ? '<p class="note hx-top">' + __('Nessun header Received.') + '</p>'
    : '<div class="hx-path">' + hops.map((h, i) => {
        const from = [h.from, h.from_ip ? '[' + h.from_ip + ']' : ''].filter(Boolean).join(' ') || __('origine');
        const delay = h.delay_s === null || h.delay_s === undefined ? (i ? __('ora non confrontabile') : __('partenza')) : '+' + secs(h.delay_s);
        const pills = (h.with ? [chkPill('neutral', h.with)] : []).concat([h.tls ? chkPill('ok', h.tls) : chkPill('neutral', __('senza TLS')), chkPill(h.status === 'warn' ? 'warn' : 'neutral', delay)]);
        return '<div class="hx-hop"><div class="hx-n">' + (i + 1) + '</div><div><div class="u">' + esc(from) + ' <span class="hx-dim">→</span> ' + esc(h.by || '?') + '</div><div class="meta">'
          + pills.join('') + '</div></div><div class="t">' + (h.time ? new Date(h.time * 1000).toLocaleTimeString(LOC) : '—') + '</div></div>';
      }).join('') + '</div><p class="note">' + (m.total_s !== null && m.total_s !== undefined ? __('Dal primo all\'ultimo server: {t}. ', {t: secs(m.total_s)}) : '')
      + __('Orari scritti dai server (i loro orologi possono non essere allineati), riportati al fuso di questo PC.') + '</p>';

  const pSpam = scores.length ? emRows(scores) : '<p class="note hx-top">' + __('Nessun header antispam nel messaggio.') + '</p>';

  const tab = 'chk';
  html += rtabs([['chk', __('Controlli'), c.checks.length], ['hop', __('Percorso'), hops.length], ['spam', 'Antispam', scores.length], ['hdr', 'Header', all.length]], tab)
    + rpane('chk', tab, pChk) + rpane('hop', tab, pHop) + rpane('spam', tab, pSpam) + rpane('hdr', tab, rows(all));

  const text = [__('Header email') + ' · ' + (m.subject || ''), '', __('CONTROLLI'), ...c.text, '', __('PERCORSO'),
    ...hops.map((h, i) => (i + 1) + '. ' + (h.from || h.from_ip || __('origine')) + ' → ' + h.by + '  ' + h.with + (h.tls ? ' ' + h.tls : '') + (h.delay_s !== null && h.delay_s !== undefined ? '  +' + secs(h.delay_s) : '')), '', 'ANTISPAM',
    ...(scores.length ? scores.map(r => r.name + ': ' + r.value + (r.detail ? ' (' + r.detail + ')' : '')) : [__('nessuno')]), '', 'HEADER', ...all.map(([k, v]) => k + ': ' + v)].join('\n');
  return {status: c.nErr ? 'err' : c.nWarn ? 'warn' : 'ok', html, text};
}

/* ── DNS, domain analysis: checks, records, delegation, DNSSEC ── */
const dnsTtl = s => s < 60 ? s + ' s' : s < 3600 ? Math.round(s / 60) + ' min' : s < 86400 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + __(' g');
function dnsDomainRender(d){
  const checks = (d.checks || []).map((c, i) => [c, i]).sort((a, b) => (CHK_RANK[a[0].status] - CHK_RANK[b[0].status]) || (a[1] - b[1])).map(x => x[0]);
  const nErr = checks.filter(c => c.status === 'err').length, nWarn = checks.filter(c => c.status === 'warn').length;
  const many = (n, one, more) => n + ' ' + (n === 1 ? one : more);
  const found = nErr || nWarn ? [nErr && many(nErr, __('errore'), __('errori')), nWarn && many(nWarn, __('avviso'), __('avvisi'))].filter(Boolean).join(' · ') : __('Tutti superati');
  const ns = d.nameservers || [], recs = d.records || [], sec = d.dnssec || {rows: [], validation: []};
  const asked = ns.filter(n => n.ipv4.length).length, up = ns.filter(n => n.responds).length;
  const blocked = !up && !d.parent_ok;
  const parent = d.parent || '.';

  let html = kv([
    [__('Controlli'), found, (nErr ? 'err' : nWarn ? 'warn' : 'ok') + ' big txt'],
    ['Name server', blocked ? __('Non raggiungibili dal PC') : up + __(' su ') + asked + (up === 1 ? __(' risponde') : __(' rispondono')), (blocked ? '' : up < asked ? 'warn' : 'ok') + ' big txt'],
    ['DNSSEC', sec.label || '—', (sec.level || '') + ' big txt'],
    [__('Indirizzi'), (d.addresses || []).join(' · ') || '—', '']]);
  if (d.zone_note) html += '<p class="summary hx-run">' + esc(d.zone_note) + '</p>';

  const pChecks = '<table class="tbl smtp-checks hx-tbl"><thead><tr><th></th><th>' + __('Area') + '</th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
    + checks.map(k => '<tr><td>' + chkPill(k.status) + '</td><td class="k hx-area">' + esc(k.area) + '</td><td class="k">' + esc(k.name)
      + '</td><td class="m">' + esc(k.detail) + '</td></tr>').join('') + '</tbody></table>';

  let last = null;
  const pRec = (!recs.length ? '<p class="note hx-top">' + __('Nessun record trovato.') + '</p>'
    : '<table class="tbl hx-tbl"><thead><tr><th>' + __('Tipo') + '</th><th>' + __('Valore') + '</th><th class="dx-ttl">TTL</th></tr></thead><tbody>' + recs.map(r => {
        const t = r.type === last ? '' : r.type; last = r.type;
        return '<tr><td class="k hx-ver"><span class="dx-type">' + esc(t) + '</span></td><td>' + (r.name ? '<span class="hx-why dx-own">' + esc(r.name) + '</span>' : '')
          + '<span class="dx-val">' + esc(r.value) + '</span></td><td class="dx-ttl">' + dnsTtl(r.ttl) + '</td></tr>';
      }).join('') + '</tbody></table>')
    + '<p class="note">' + __('Risposte del DNS di questo PC.') + ((d.empty_types || []).length ? ' ' + __('Tipi senza risposta: {list}.', {list: esc(d.empty_types.join(', '))}) : '') + '</p>';

  const top = Math.max(0, ...ns.map(n => n.serial || 0));
  const pDel = (!ns.length ? '<p class="note hx-top">' + __('Nessun name server trovato.') + '</p>'
    : '<div class="hx-path">' + ns.map((n, i) => {
        const pills = n.ipv4.concat(n.ipv6).map(a => chkPill('neutral', a));
        if (n.parent !== null && n.parent !== undefined) pills.push(chkPill(n.parent ? 'ok' : 'warn', n.parent ? __('nel registro') : __('non nel registro')));
        pills.push(chkPill(n.zone ? 'ok' : 'warn', n.zone ? __('nella zona') : __('non nella zona')));
        if (n.responds){
          pills.push(chkPill(n.authoritative ? 'ok' : 'err', n.authoritative ? __('autoritativo') : __('non autoritativo')));
          if (n.serial !== null && n.serial !== undefined) pills.push(chkPill(n.serial === top ? 'neutral' : 'err', __('seriale {n}', {n: n.serial})));
          if (n.axfr === true) pills.push(chkPill('err', __('AXFR consentito')));
          if (n.axfr === false) pills.push(chkPill('ok', __('AXFR rifiutato')));
        } else if (n.ipv4.length) pills.push(chkPill(n.status === 'err' ? 'err' : 'neutral', n.status === 'err' ? __('non risponde') : __('non raggiungibile')));
        return '<div class="hx-hop"><div class="hx-n">' + (i + 1) + '</div><div><div class="u">' + esc(n.name) + '</div><div class="meta">' + pills.join('') + '</div>'
          + (n.note ? '<div class="hx-why">' + esc(n.note) + '</div>' : '') + '</div><div class="t">' + (n.time_ms !== null && n.time_ms !== undefined ? n.time_ms + ' ms' : '—') + '</div></div>';
      }).join('') + '</div>')
    + '<p class="note">' + (d.parent_ok ? __('Delega letta dai name server di <span class="mono">{parent}</span>; ogni name server interrogato direttamente (SOA e NS).', {parent: esc(parent)})
      : __('I name server di <span class="mono">{parent}</span> non rispondono da questo PC: elenco letto dal DNS del PC, senza confronto con il registro.', {parent: esc(parent)})) + '</p>';

  const rowsT = (list, cls) => '<table class="tbl smtp-checks hx-tbl"><tbody>' + list.map(r => '<tr><td>' + chkPill(r.status) + '</td><td class="k ' + cls + '">' + esc(r.name) + '</td>'
    + (r.what !== undefined || cls === '' ? '<td class="m">' + esc(r.what || '') + '</td>' : '') + '<td class="m">' + esc(r.detail) + '</td></tr>').join('') + '</tbody></table>';
  const pSec = (sec.rows.length ? rowsT(sec.rows, '') : '<p class="note hx-top">' + __('La zona non è firmata con DNSSEC.') + '</p>')
    + (sec.validation.length ? '<div class="sub">' + __('Validazione') + '</div>' + rowsT(sec.validation.map(r => ({status: r.status, name: r.name, detail: r.detail})), 'dx-who') : '')
    + '<p class="note">' + __('L\'app controlla la struttura (DS, chiavi, scadenze) e confronta le risposte di un resolver che valida; non verifica le firme da sé.') + '</p>';

  const tab = 'chk';
  html += rtabs([['chk', __('Controlli'), checks.length], ['rec', 'Record', recs.length], ['del', __('Delega'), ns.length], ['sec', 'DNSSEC']], tab)
    + rpane('chk', tab, pChecks) + rpane('rec', tab, pRec) + rpane('del', tab, pDel) + rpane('sec', tab, pSec);

  // "Copy" takes the whole result, not just the open tab
  const text = [__('Analisi DNS') + ' · ' + d.domain + ' · DNSSEC: ' + (sec.label || '—'), '', __('CONTROLLI'),
    ...checks.map(k => '[' + (CHK_ICON[k.status] || '') + '] ' + k.area + ' · ' + k.name + ': ' + k.detail), '', 'RECORD',
    ...recs.map(r => (r.name || d.domain) + '. ' + r.ttl + ' IN ' + r.type + ' ' + r.value), '', __('DELEGA'),
    ...ns.map(n => n.name + ' ' + n.ipv4.concat(n.ipv6).join(' ') + ' · ' + (n.parent === true ? __('nel registro') : n.parent === false ? __('non nel registro') : __('registro non letto'))
      + ' · ' + (n.zone ? __('nella zona') : __('non nella zona')) + ' · ' + (n.responds ? (n.authoritative ? __('autoritativo') : __('non autoritativo')) + __(', seriale ') + (n.serial ?? '—') + ', ' + n.time_ms + ' ms' : __('nessuna risposta'))
      + (n.axfr === true ? ' · ' + __('AXFR consentito') : n.axfr === false ? ' · ' + __('AXFR rifiutato') : '') + (n.note ? ' (' + n.note + ')' : '')), '', 'DNSSEC',
    ...sec.rows.map(r => '[' + (CHK_ICON[r.status] || '') + '] ' + r.name + ': ' + [r.what, r.detail].filter(Boolean).join(' · ')),
    ...sec.validation.map(r => '[' + (CHK_ICON[r.status] || '') + '] ' + r.name + ': ' + r.detail)].join('\n');
  return {status: (nErr || nWarn) ? 'warn' : 'ok', html, text};
}

/* ── TLS certificates: checks, certificate, chain and (on request) versions and ciphers ── */
const TLS_SENT = {sent:['ok', __('inviato')], missing:['err', __('non inviata')], store:['neutral', __('archivio del PC')], extra:['warn', __('fuori dalla catena')]};
function sslRender(d, tab, running){
  const checks = (d.checks || []).map((c, i) => [c, i]).sort((a, b) => (CHK_RANK[a[0].status] - CHK_RANK[b[0].status]) || (a[1] - b[1])).map(x => x[0]);
  const nErr = checks.filter(c => c.status === 'err').length, nWarn = checks.filter(c => c.status === 'warn').length;
  const many = (n, one, more) => n + ' ' + (n === 1 ? one : more);
  const found = nErr || nWarn ? [nErr && many(nErr, __('errore'), __('errori')), nWarn && many(nWarn, __('avviso'), __('avvisi'))].filter(Boolean).join(' · ') : __('Tutti superati');
  const c = d.cert || {}, chain = d.chain_info || [], scan = d.scan, days = d.days_remaining;
  const dc = d.expired ? 'err' : d.expiring_soon ? 'warn' : 'ok';
  const ver = (d.tls_version || '').replace('TLSv', 'TLS '), cipher = (d.cipher || '').replace(/^TLS13_/, 'TLS_');
  const oldProto = /^(SSLv3|TLSv1\.[01])$/.test(d.tls_version || '');
  const when = t => (t || '').replace('T', ' ');
  const gg = n => many(Math.abs(n), __('giorno'), __('giorni'));

  let html = kv([
    [__('Scade tra'), days === null || days === undefined ? '—' : (d.expired ? __('scaduto da {n}', {n: gg(days)}) : gg(days)), dc + ' big'],
    [__('Attendibilità'), d.verified ? (d.partial ? __('Catena verificata (handshake non completato)') : __('Catena verificata')) : __('Non attendibile'), (d.verified ? 'ok' : 'err') + ' big txt'],
    [__('Controlli'), found, (nErr ? 'err' : nWarn ? 'warn' : 'ok') + ' big txt'],
    [__('Protocollo'), ver, oldProto || d.compat ? 'warn' : '']]);
  if (running) html += '<p class="summary hx-run"><span class="spinner"></span>' + __('Prova di versioni e cipher: <strong>{n}</strong> connessioni…', {n: (scan && scan.tried) || 0}) + '</p>';

  const pChecks = '<table class="tbl smtp-checks hx-tbl"><thead><tr><th></th><th>' + __('Area') + '</th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
    + checks.map(k => '<tr><td>' + chkPill(k.status) + '</td><td class="k hx-area">' + esc(k.area) + '</td><td class="k">' + esc(k.name)
      + '</td><td class="m">' + esc(k.detail) + '</td></tr>').join('') + '</tbody></table>';

  // certificate: [label, value, class, long value to wrap]
  const list = a => (a || []).join('\n');
  const info = [
    [__('Soggetto'), c.subject || (d.subject && d.subject.commonName)], [__('Emesso da'), c.issuer || (d.issuer && (d.issuer.organizationName || d.issuer.commonName))],
    [__('Valido dal'), when(d.not_before)], [__('Valido fino al'), when(d.not_after), dc],
    [__('Durata'), c.lifetime_days ? gg(c.lifetime_days) : ''], [__('Chiave'), c.key], [__('Firma'), c.signature],
    [__('Uso'), c.usage && c.usage.length ? c.usage.join(', ') : (d.cert ? __('nessuna restrizione') : '')],
    [__('Seriale'), d.serial, '', 1], [__('Impronta SHA-256'), c.sha256, '', 1], [__('Impronta SHA-1'), c.sha1, '', 1],
    ['OCSP', list(c.ocsp), '', 1], ['CRL', list(c.crl), '', 1], [__('Emittente (AIA)'), list(c.ca_issuers), '', 1],
    [__('Trasparenza'), c.sct ? many(c.sct, __('SCT incorporato'), __('SCT incorporati')) : ''],
    [__('Collegamento'), d.protocol], [__('Nome SNI'), d.sni],
    [d.partial ? __('Cipher scelta dal server') : __('Cipher negoziata'), cipher],
    ['OCSP stapling', d.ocsp_stapled === true ? __('risposta inviata dal server') : d.ocsp_stapled === false ? __('non inviato') : '']
  ].filter(r => r[1]);
  const sans = (d.sans || []).map(s => s.replace(/^(DNS|IP): /, ''));
  const pCert = '<table class="tbl">' + info.map(([k, v, cls, long]) => '<tr><td class="k">' + esc(k) + '</td><td class="v ' + (cls || '') + (long ? ' hx-long' : '') + '">'
      + esc(v).replace(/\n/g, '<br>') + '</td></tr>').join('') + '</table>'
    + (sans.length ? '<div class="sub">' + __('Nomi coperti ({n})', {n: sans.length}) + '</div>' + tags(sans) : '');

  const pChain = !chain.length ? '<p class="note hx-top">' + __('Catena non disponibile.') + '</p>'
    : '<div class="hx-path">' + chain.map((e, i) => {
      const exp = e.expired ? __('scaduto il {date}', {date: (e.not_after || '').slice(0, 10)}) : __('scade il {date}', {date: (e.not_after || '').slice(0, 10)}) + (e.days_remaining <= 30 ? ' (' + gg(e.days_remaining) + ')' : '');
      const s = TLS_SENT[e.sent] || ['neutral', e.sent];
      const pills = [chkPill('neutral', e.role), chkPill('neutral', e.key), chkPill('neutral', e.signature),
        chkPill(e.expired ? 'err' : e.days_remaining <= 30 ? 'warn' : 'neutral', exp), chkPill(s[0], s[1])];
      return '<div class="hx-hop"><div class="hx-n">' + (i + 1) + '</div><div><div class="u">' + esc(e.name) + '</div><div class="meta">' + pills.join('') + '</div>'
        + (e.note ? '<div class="hx-why">' + esc(e.note) + '</div>' : '') + '</div><div class="t">' + (e.self_signed ? __('autofirmato') : __('emesso da {name}', {name: esc(e.issuer_name)})) + '</div></div>';
    }).join('') + '</div>';

  const vers = (scan && scan.versions) || [], names = new Set();
  vers.forEach(v => v.ciphers.forEach(x => names.add(x.name)));
  const pScan = !scan ? '' : (!vers.length ? '<p class="note hx-top">' + __('Nessuna versione provata finora.') + '</p>'
    : '<table class="tbl smtp-checks hx-tbl"><tbody>' + vers.map(v => '<tr><td>'
      + (v.status === 'run' ? '<span class="spinner"></span>' : v.accepted ? chkPill(v.status) : chkPill('neutral', '–'))
      + '</td><td class="k hx-ver"><span class="hx-name' + (v.accepted ? '' : ' hx-dim') + '">' + esc(v.name) + '</span></td><td class="m">'
      + (v.ciphers.map(x => '<span class="hx-src ' + esc(x.level) + '" title="' + esc(x.kx + ' · ' + x.enc) + '">' + esc(x.name) + '</span>').join('') || '<span class="hx-dim">' + __('non accettato') + '</span>')
      + '</td></tr>').join('') + '</tbody></table>')
    + (running ? '' : '<p class="note">' + (scan.stopped ? __('Scansione fermata: risultato parziale. ') : '') + (scan.note ? esc(scan.note) + ' ' : '')
      + __('{n} in {s} s. Le suite sono nell\'ordine in cui il server le sceglie; in giallo quelle deboli (CBC o senza forward secrecy), in rosso quelle da togliere.',
        {n: many(scan.tried, __('connessione'), __('connessioni')), s: (scan.time_ms / 1000).toFixed(1).replace('.', LANG === 'en' ? '.' : ',')}) + '</p>');

  const tabs = [['chk', __('Controlli'), checks.length], ['crt', __('Certificato')], ['chn', __('Catena'), chain.length]];
  if (scan) tabs.push(['pro', __('Protocolli e cipher'), names.size]);
  if (!tabs.some(t => t[0] === tab)) tab = 'chk';
  html += rtabs(tabs, tab) + rpane('chk', tab, pChecks) + rpane('crt', tab, pCert) + rpane('chn', tab, pChain) + (scan ? rpane('pro', tab, pScan) : '');

  // "Copy" takes the whole result, not just the open tab
  const text = [__('Certificato TLS') + ' · ' + d.host + ':' + d.port + (d.sni ? ' (SNI ' + d.sni + ')' : '') + ' · ' + ver, '', __('CONTROLLI'),
    ...checks.map(k => '[' + (CHK_ICON[k.status] || '') + '] ' + k.area + ' · ' + k.name + ': ' + k.detail), '', __('CERTIFICATO'),
    ...info.map(([k, v]) => k + ': ' + String(v).replace(/\n/g, ', ')), __('Nomi coperti: ') + (sans.join(', ') || __('nessuno')), '', __('CATENA'),
    ...chain.map((e, i) => (i + 1) + '. ' + e.role + ': ' + e.name + ' · ' + e.key + ' · ' + e.signature + ' · ' + __('scade il {date}', {date: (e.not_after || '').slice(0, 10)})
      + ' · ' + (TLS_SENT[e.sent] || ['', e.sent])[1] + (e.note ? ' (' + e.note + ')' : '')),
    ...(scan ? ['', __('PROTOCOLLI E CIPHER'), ...vers.flatMap(v => [v.name + ': ' + (v.accepted ? __('accettato') : __('non accettato')),
      ...v.ciphers.map(x => '  ' + x.name + ' · ' + x.kx + ' · ' + x.enc + (x.level === 'bad' ? ' · ' + __('da togliere') : x.level === 'weak' ? ' · ' + __('debole') : ''))])] : [])].join('\n');
  return {status: d.expired ? 'err' : (nErr || nWarn) ? 'warn' : 'ok', html, text};
}

const SMTP_ICON = {ok:'✓', warn:'!', err:'✕', info:'i'};
const SMTP_TLS = {starttls:'STARTTLS', implicit: __('TLS implicito'), none: __('Nessuna')};
function smtpRender(d){
  const c = d.checks || [];
  const n = s => c.filter(x => x.status === s).length;
  const status = n('err') ? 'err' : n('warn') ? 'warn' : 'ok';
  const tlsCls = d.tls ? (d.tls.verified ? 'ok' : 'warn') : (d.tls_mode === 'none' ? 'warn' : '');
  const cnt = [[n('ok'), 'ok'], [n('warn'), __('da verificare')], [n('err'), __('non superati')]].filter(x => x[0]).map(x => x[0] + ' ' + x[1]).join(' · ');
  let html = kv([
    [__('Controlli'), cnt || '—', status + ' txt'],
    [__('Connessione'), d.connect_ms + ' ms', 'big'],
    [__('Transazione'), (d.total_ms / 1000).toFixed(3) + ' s', 'big'],
    [__('Cifratura'), SMTP_TLS[d.tls_mode] || d.tls_mode, (tlsCls ? tlsCls + ' ' : '') + 'big txt']]);
  html += '<table class="tbl smtp-checks"><thead><tr><th></th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
    + c.map(x => '<tr><td><span class="pill ' + esc(x.status) + '">' + (SMTP_ICON[x.status] || '') + '</span></td>'
      + '<td class="k">' + esc(x.name) + '</td><td class="m">' + esc(x.detail) + '</td></tr>').join('')
    + '</tbody></table>';
  const t = d.tls;
  if (t){
    html += '<div class="sub">' + __('Certificato') + '</div>' + rows([
      ['Common name', (t.subject && t.subject.commonName) || '—'],
      [__('Emesso da'), (t.issuer && (t.issuer.organizationName || t.issuer.commonName)) || '—'],
      [__('Valido fino al'), (t.not_after || '').replace('T', ' '), t.expired ? 'err' : t.expiring_soon ? 'warn' : ''],
      [__('Protocollo'), t.tls_version + ' · ' + t.cipher]]
      .concat(t.verified ? [] : [[__('Motivo'), t.verify_error || '—', 'warn']]));
    if (t.sans && t.sans.length) html += '<div class="sub">' + __('Nomi coperti ({n})', {n: t.sans.length}) + '</div>' + tags(t.sans.map(s => s.replace(/^DNS: /, '')));
  }
  html += '<div class="sub">' + __('Trascrizione della sessione') + '</div>' + pre((d.transcript || []).join('\n'));
  return {status, html};
}
const SMTP_FIELDS = ['smtp-host', 'smtp-port', 'smtp-sec', 'smtp-ehlo', 'smtp-user', 'smtp-from', 'smtp-to', 'smtp-subject'];
function smtpSave(){ store.set('smtp', Object.fromEntries(SMTP_FIELDS.map(id => [id, $(id).value]))); }
function smtpToggle(){
  $('smtp-auth-row').classList.toggle('hidden', !$('smtp-auth').checked);
  $('smtp-send-box').classList.toggle('hidden', !$('smtp-send').checked);
}
(() => {
  const saved = store.get('smtp', {});
  SMTP_FIELDS.forEach(id => { if (typeof saved[id] === 'string') $(id).value = saved[id]; });
  if (!$('smtp-sec').value) $('smtp-sec').value = 'auto';
  ['smtp-auth', 'smtp-send'].forEach(id => $(id).addEventListener('change', smtpToggle));
  smtpToggle();
  presets('smtp-presets', [['25 SMTP', '25'], ['587 Submission', '587'], ['465 SMTPS', '465']], v => {
    $('smtp-port').value = v; $('smtp-sec').value = 'auto'; smtpSave();
  });
  $('smtp-clear').onclick = () => {
    SMTP_FIELDS.forEach(id => { $(id).value = ''; });
    $('smtp-port').value = '25'; $('smtp-sec').value = 'auto'; $('smtp-subject').value = __('Test SMTP');
    $('smtp-pass').value = ''; $('smtp-body').value = '';
    ['smtp-relay', 'smtp-auth', 'smtp-send'].forEach(id => { $(id).checked = false; store.set(id, false); });
    smtpToggle(); smtpSave(); $('smtp-host').focus();
  };
})();

/* ── Wake-on-LAN: workstations saved in the browser ── */
function renderWol(){
  const list = store.get('wol', []), box = $('wol-saved');
  box.querySelectorAll('.saved').forEach(x => x.remove());
  box.classList.toggle('hidden', !list.length);
  list.forEach((w, i) => {
    const wrap = document.createElement('span'); wrap.className = 'saved';
    const b = document.createElement('button'); b.type = 'button'; b.className = 'chip'; b.textContent = w.name;
    b.title = __('{mac} via {bcast}', {mac: w.mac, bcast: w.broadcast});
    b.onclick = () => { $('wol-mac').value = w.mac; $('wol-name').value = w.name; $('wol-bcast').value = w.broadcast; $('wol-port').value = w.port || '9'; };
    const x = document.createElement('button'); x.type = 'button'; x.className = 'chip-x'; x.textContent = '×';
    x.setAttribute('aria-label', __('Rimuovi {name}', {name: w.name}));
    x.onclick = () => { const l = store.get('wol', []); l.splice(i, 1); store.set('wol', l); renderWol(); };
    wrap.append(b, x); box.appendChild(wrap);
  });
}
function saveWol(w){
  const l = store.get('wol', []).filter(x => x.mac !== w.mac);
  l.push(w); l.sort((a, b) => a.name.localeCompare(b.name)); store.set('wol', l); renderWol();
}
renderWol();

/* ── Password generator ── */
const PW_STRENGTH = {debole:['err', __('Debole')], media:['warn', __('Media')], forte:['ok', __('Forte')], estrema:['info', __('Estrema')]};
const PW_CHECKS = ['pw-lower', 'pw-upper', 'pw-digits', 'pw-symbols', 'pw-noamb', 'pw-pron'];
const PW_VALUES = ['pw-min-lower', 'pw-min-upper', 'pw-min-digits', 'pw-min-symbols', 'pw-symset', 'pw-len', 'pw-count'];
const PW_HIST_MAX = 20;
const pwHist = [];
let pwLast = null, pwTimer = null, pwSeq = 0;

const fmtBits = (b, dec) => Number(b).toLocaleString(LOC, {maximumFractionDigits: dec});
const strengthPill = s => '<span class="pill ' + PW_STRENGTH[s][0] + '">' + PW_STRENGTH[s][1] + '</span>';
const meter = (bits, s) => '<span class="meter ' + PW_STRENGTH[s][0] + '" aria-hidden="true"><i style="width:'
  + Math.min(100, Math.round(bits / 128 * 100)) + '%"></i></span>';
// letters in the text colour, digits and symbols highlighted
const pwColor = s => [...s].map(c => /[A-Za-z]/.test(c) ? esc(c)
  : /\d/.test(c) ? '<span class="ch-d">' + c + '</span>' : '<span class="ch-s">' + esc(c) + '</span>').join('');
const two = i => String(i + 1).padStart(2, '0');
function pwReq(){
  return {lower:$('pw-lower').checked, upper:$('pw-upper').checked, digits:$('pw-digits').checked, symbols:$('pw-symbols').checked,
    min_lower:val('pw-min-lower'), min_upper:val('pw-min-upper'), min_digits:val('pw-min-digits'), min_symbols:val('pw-min-symbols'),
    symbol_set:$('pw-symset').value, length:$('pw-len').value, count:$('pw-count').value,
    exclude_ambiguous:$('pw-noamb').checked, pronounceable:$('pw-pron').checked};
}
/* remembered options (never the passwords) */
function pwSave(){
  const o = {};
  PW_CHECKS.forEach(id => o[id] = $(id).checked);
  PW_VALUES.forEach(id => o[id] = $(id).value);
  store.set('pwgen', o);
}
function pwLoad(){
  const o = store.get('pwgen', null);
  if (!o) return;
  PW_CHECKS.forEach(id => { if (typeof o[id] === 'boolean') $(id).checked = o[id]; });
  PW_VALUES.forEach(id => { if (typeof o[id] === 'string') $(id).value = o[id]; });
}

function pwSync(){
  $('pw-len-val').textContent = $('pw-len').value;
  $('pw-count-val').textContent = $('pw-count').value;
  $('pw-sym-show').textContent = $('pw-symset').value.replace(/\s/g, '') || '!@#$%^&*()-_=+[]{}|;:,.<>?';
  ['lower', 'upper', 'digits', 'symbols'].forEach(k => { $('pw-min-' + k).disabled = !$('pw-' + k).checked; });
  $('pw-symset').disabled = !$('pw-symbols').checked;
  $('pw-pron-note').classList.toggle('hidden', !$('pw-pron').checked);
}

/* entropy preview while the options are changed */
function pwPreview(){
  clearTimeout(pwTimer);
  pwTimer = setTimeout(async () => {
    const seq = ++pwSeq;
    const d = await call('/api/pwgen/estimate', pwReq());
    if (seq !== pwSeq) return;
    const el = $('pw-preview');
    if (d.error){ el.innerHTML = '<span class="c-err">✕ ' + esc(d.error) + '</span>'; return; }
    const extra = d.pool ? __('{n} caratteri possibili', {n: d.pool}) : __('sillabe consonante-vocale');
    el.innerHTML = __('Entropia ≈ <strong>{bits} bit</strong> ', {bits: Math.round(d.entropy_bits)}) + meter(d.entropy_bits, d.strength)
      + strengthPill(d.strength) + ' · ' + extra;
  }, 60);
}
function pwChanged(){ pwSync(); pwSave(); pwPreview(); }

function pwBody(d){
  return '<p class="summary">' + __('Entropia <strong>{bits} bit</strong> per password ', {bits: fmtBits(d.entropy_bits, 1)})
    + meter(d.entropy_bits, d.strength) + strengthPill(d.strength)
    + ' · ' + __('{n} caratteri', {n: d.length}) + ' · ' + (d.pool ? __('{n} caratteri possibili', {n: d.pool}) : __('pronunciabile')) + '</p>'
    + '<div class="pw-list">' + d.passwords.map((p, i) => '<div class="pw-row"><span class="pw-n">' + two(i) + '</span>'
      + '<span class="pw-val">' + pwColor(p) + '</span><div class="row-act">'
      + '<button type="button" data-act="regen" data-i="' + i + '">' + __('Rigenera') + '</button>'
      + '<button type="button" data-act="copy" data-i="' + i + '">' + __('Copia') + '</button></div></div>').join('') + '</div>';
}
/* protected copy: outside the Win+V history, cleared after 30 s (Rust) */
async function secureCopy(text, btn){
  let ok = false, err = '';
  try { await TAURI.invoke('clipboard_secret', {req: {text}}); ok = true; } catch(e){ err = tauriError(e); }
  if (!btn) return ok;
  const label = btn.dataset.label || (btn.dataset.label = btn.textContent);
  btn.textContent = ok ? __('Copiata') : __('Errore');
  btn.title = ok ? __('Negli appunti per 30 secondi') : err;
  setTimeout(() => { btn.textContent = label; }, 1600);
  return ok;
}

/* session history: in memory only */
function pwRemember(kind, values){
  const at = new Date().toLocaleTimeString(LOC);
  values.forEach(v => pwHist.unshift({at, kind, v}));
  pwHist.splice(PW_HIST_MAX);
  renderHist();
}
function renderHist(){
  $('pw-hist-n').textContent = pwHist.length;
  $('pw-hist-body').innerHTML = !pwHist.length ? '<div class="empty">' + __('Nessuna password generata in questa sessione.') + '</div>'
    : '<table class="tbl"><thead><tr><th>' + __('Ora') + '</th><th>' + __('Tipo') + '</th><th>' + __('Valore') + '</th><th></th></tr></thead><tbody>'
      + pwHist.map((h, i) => '<tr><td class="m nw">' + esc(h.at) + '</td><td class="nw">' + esc(h.kind) + '</td>'
        + '<td class="v">' + pwColor(h.v) + '</td><td><div class="row-act"><button type="button" data-hcopy="' + i + '">' + __('Copia') + '</button></div></td></tr>').join('')
      + '</tbody></table>';
}
$('pw-hist-btn').onclick = () => {
  const open = !$('pw-hist').classList.toggle('hidden');
  $('pw-hist-btn').setAttribute('aria-expanded', open);
};
$('pw-hist-clear').onclick = () => { pwHist.length = 0; renderHist(); };
$('pw-hist-body').addEventListener('click', e => {
  const b = e.target.closest('[data-hcopy]');
  if (b && pwHist[+b.dataset.hcopy]) secureCopy(pwHist[+b.dataset.hcopy].v, b);
});

/* actions on the generated passwords: copy and regenerate */
$('res-pwgen').addEventListener('click', async e => {
  const b = e.target.closest('[data-act]');
  if (!b || !pwLast) return;
  const i = +b.dataset.i;
  if (b.dataset.act === 'copy') return secureCopy(pwLast.data.passwords[i], b);
  b.disabled = true;
  const n = await call('/api/pwgen', Object.assign({}, pwLast.req, {count: '1'}));
  b.disabled = false;
  if (n.error){ b.textContent = __('Errore'); b.title = n.error; return; }
  pwLast.data.passwords[i] = n.passwords[0];
  pwRemember('Password', n.passwords);
  b.closest('.pw-row').querySelector('.pw-val').innerHTML = pwColor(n.passwords[0]);
});

document.querySelectorAll('#view-pwgen form input').forEach(i =>
  i.addEventListener(i.type === 'checkbox' ? 'change' : 'input', pwChanged));
pwLoad(); pwSync(); renderHist(); pwPreview();

/* ── Numeric converter ── */
const NC_IDS = {dec:'nc-dec', hex:'nc-hex', bin:'nc-bin', ip:'nc-ip'};
const nc = {width:'32', src:null, last:null, seq:0};
const ncCompact = (base, v) => base === 'dec' || base === 'ip' ? v : v.replace(/\s/g, '');
function ncOptsSync(){
  document.querySelectorAll('#nc-width button').forEach(b => b.setAttribute('aria-checked', b.dataset.w === nc.width));
  $('nc-signed').disabled = nc.width === 'free';
  $('nc-signed').closest('.check').title = nc.width === 'free' ? __('Con larghezza libera solo senza segno') : '';
  document.querySelectorAll('#view-numconv .nc-ip').forEach(e => e.classList.toggle('hidden', !(nc.width === '32' || nc.width === 'free')));
  store.set('numconv', {width: nc.width, signed: $('nc-signed').checked});
}
function ncMsg(text, cls){ const m = $('nc-msg'); m.className = 'nc-msg' + (cls ? ' ' + cls : ''); m.textContent = text || ''; }
function ncClear(except){
  Object.entries(NC_IDS).forEach(([b, id]) => { if (b !== except) $(id).value = ''; $(id).removeAttribute('aria-invalid'); });
  nc.src = nc.last = null; ncMsg('');
  $('nc-bits-panel').classList.add('hidden'); $('nc-info-panel').classList.add('hidden');
}
/* converts from the `base` field; the other fields are updated, the one being edited is not */
async function ncConvert(base, value, all){
  const seq = ++nc.seq;
  if (!value.trim()) return ncClear(base);
  const d = await call('/api/numconv', {value, base, width: nc.width, signed: $('nc-signed').checked && nc.width !== 'free'});
  if (seq !== nc.seq) return;
  Object.values(NC_IDS).forEach(id => $(id).removeAttribute('aria-invalid'));
  if (d.error){ $(NC_IDS[base]).setAttribute('aria-invalid', 'true'); ncMsg('✕ ' + d.error, 'err'); return; }
  nc.src = {base, value}; nc.last = d;
  const out = {dec: d.dec, hex: d.hex, bin: d.bin, ip: d.ipv4 || ''};
  Object.entries(NC_IDS).forEach(([b, id]) => { if (all || b !== base) $(id).value = out[b]; });
  ncMsg(d.warning ? '! ' + d.warning : '', d.warning ? 'warn' : '');
  ncRender(d);
}
function ncRender(d){
  // bit grid (up to 128): bytes from the most significant, indexes below
  const show = d.bits <= 128, bytes = d.raw.match(/.{8}/g) || [];
  $('nc-bits-panel').classList.remove('hidden');
  $('nc-bits-note').classList.toggle('hidden', show);
  $('nc-bits').style.setProperty('--cols', Math.min(bytes.length, 4));
  $('nc-bits').innerHTML = !show ? '' : bytes.map((byte, k) => {
    const hi = d.bits - 1 - k * 8;
    return '<div class="nc-byte"><div class="nc-byte-bits">' + [...byte].map((c, j) => {
      const i = hi - j;
      return '<button type="button" class="nc-bit' + (c === '1' ? ' on' : '') + '" data-bit="' + i + '" title="' + __('Bit {i}', {i})
        + (i < 63 ? __(' · valore {v}', {v: (2 ** i).toLocaleString(LOC)}) : '') + '">' + c + '</button>';
    }).join('') + '</div><div class="nc-idx"><span>' + hi + '</span><span>' + (hi - 7) + '</span></div></div>';
  }).join('');
  $('nc-bits-sum').innerHTML = __('<strong>{bits}</strong> bit · <strong>{ones}</strong> a 1', {bits: d.bits, ones: d.ones})
    + (d.msb !== null && d.msb !== undefined ? __(' · bit più alto a 1: <strong>{msb}</strong>', {msb: d.msb}) : '');
  // interpretations
  const hx = d.hex.replace(/\s/g, ''), bn = d.raw.replace(/^0+(?=.)/, '');
  $('nc-info-panel').classList.remove('hidden');
  $('nc-info').innerHTML = rows([
    [__('Senza segno'), d.unsigned],
    d.signed !== null && d.signed !== undefined ? [__('Con segno (complemento a due)'), d.signed] : null,
    [__('Esadecimale con prefisso'), '0x' + hx],
    [__('Binario con prefisso'), '0b' + bn],
    [__('Byte (big endian, ordine di rete)'), d.hex],
    d.swapped ? [__('Byte (little endian, ordine di Intel)'), d.bytes_le] : null,
    d.swapped ? [__('Valore con i byte invertiti'), d.swapped] : null,
    d.ipv4 ? ['IPv4', d.ipv4] : null,
    d.ascii ? ['ASCII', d.ascii] : null
  ].filter(Boolean));
}
Object.entries(NC_IDS).forEach(([base, id]) => {
  $(id).addEventListener('input', () => ncConvert(base, $(id).value));
  // on leaving the field, the one being edited also takes the normalised form
  $(id).addEventListener('blur', () => {
    if (nc.last && nc.src && nc.src.base === base && !$(id).hasAttribute('aria-invalid'))
      $(id).value = {dec: nc.last.dec, hex: nc.last.hex, bin: nc.last.bin, ip: nc.last.ipv4 || $(id).value}[base];
  });
});
function ncRefresh(){ ncOptsSync(); if (nc.src) ncConvert(nc.src.base, nc.src.value, true); }
document.querySelectorAll('#nc-width button').forEach(b => b.addEventListener('click', () => { nc.width = b.dataset.w; ncRefresh(); }));
$('nc-signed').addEventListener('change', ncRefresh);
$('nc-bits').addEventListener('click', e => {
  const b = e.target.closest('[data-bit]'); if (!b || !nc.last) return;
  const raw = [...nc.last.raw], k = nc.last.bits - 1 - +b.dataset.bit;
  raw[k] = raw[k] === '1' ? '0' : '1';
  ncConvert('bin', raw.join(''), true);
});
$('nc-panel').addEventListener('click', e => {
  const b = e.target.closest('[data-nc-copy]'); if (!b) return;
  const base = b.dataset.ncCopy, v = ncCompact(base, $(NC_IDS[base]).value.trim());
  if (!v) return;
  navigator.clipboard?.writeText(v).then(() => { b.textContent = __('Copiato'); setTimeout(() => b.textContent = __('Copia'), 1400); });
});
(() => {
  const o = store.get('numconv', null);
  if (o && ['8', '16', '32', '64', 'free'].includes(o.width)) nc.width = o.width;
  if (o) $('nc-signed').checked = !!o.signed;
  ncOptsSync();
})();

/* ── UUID generator ── */
const uuidOpt = {wrap:'none'};
function uuidFmt(u){
  let s = $('uuid-hyph').checked ? u : u.replace(/-/g, '');
  if ($('uuid-upper').checked) s = s.toUpperCase();
  return uuidOpt.wrap === 'braces' ? '{' + s + '}' : uuidOpt.wrap === 'urn' ? 'urn:uuid:' + s : s;
}
function uuidSync(){
  $('uuid-count-val').textContent = $('uuid-count').value;
  $('uuid-ns-custom-f').classList.toggle('hidden', $('uuid-ns').value !== 'custom');
  $('uuid-note-v4').classList.toggle('hidden', tabState.uuid !== 'v4');
  $('uuid-note-v7').classList.toggle('hidden', tabState.uuid !== 'v7');
  document.querySelectorAll('#uuid-wrap button').forEach(b => b.setAttribute('aria-checked', b.dataset.wrap === uuidOpt.wrap));
  $('uuid-sample').textContent = __('Esempio: {s}', {s: uuidFmt('550e8400-e29b-41d4-a716-446655440000')});
}
function uuidChanged(){
  uuidSync();
  store.set('uuid', {tab: tabState.uuid, count: $('uuid-count').value, ns: $('uuid-ns').value, nsCustom: $('uuid-ns-custom').value,
    upper: $('uuid-upper').checked, hyph: $('uuid-hyph').checked, wrap: uuidOpt.wrap});
  // the format also applies to the UUIDs already generated
  document.querySelectorAll('#res-uuid .uuid-list').forEach(l => {
    const raw = JSON.parse(l.dataset.raw);
    l.querySelectorAll('.uuid-val').forEach((e, i) => { e.textContent = uuidFmt(raw[i]); });
  });
}
function uuidBody(d){
  const names = d.names || [];
  return '<div class="uuid-top"><p class="summary">' + __('{n} UUID versione {v}', {n: d.uuids.length, v: d.version})
    + (d.namespace ? __(' · namespace <span class="mono">{ns}</span>', {ns: esc(d.namespace)}) : '') + '</p>'
    + '<div class="row-act"><button type="button" data-uact="all">' + __('Copia tutti') + '</button></div></div>'
    + '<div class="uuid-list" data-raw="' + esc(JSON.stringify(d.uuids)) + '">' + d.uuids.map((u, i) =>
      '<div class="pw-row"><span class="pw-n">' + String(i + 1).padStart(d.uuids.length > 99 ? 3 : 2, '0') + '</span>'
      + '<span><span class="uuid-val">' + esc(uuidFmt(u)) + '</span>' + (names[i] ? '<span class="uuid-name">' + esc(names[i]) + '</span>' : '') + '</span>'
      + '<div class="row-act"><button type="button" data-uact="inspect" data-i="' + i + '">' + __('Analizza') + '</button>'
      + '<button type="button" data-uact="copy" data-i="' + i + '">' + __('Copia') + '</button></div></div>').join('') + '</div>';
}
function uuidInspectBody(d){
  const special = d.version_name.startsWith('UUID'), rfc = d.variant.startsWith('RFC');
  let t = '';
  if (d.time_ms !== null && d.time_ms !== undefined){
    const dt = new Date(d.time_ms);
    t = isNaN(dt) ? '' : dt.toLocaleString(LOC, {dateStyle:'full', timeStyle:'medium'})
      + ',' + String(((d.time_ms % 1000) + 1000) % 1000).padStart(3, '0');
  }
  return '<p class="summary"><strong>' + esc(d.version_name) + '</strong> '
    + (special ? '' : '<span class="pill ' + (rfc ? 'ok' : 'warn') + '">' + __('Variante {v}', {v: esc(d.variant)}) + '</span>') + '</p>'
    + rows([
      t ? [__('Creato (ora locale)'), t] : null,
      t ? [__('Creato (UTC)'), d.time_utc] : null,
      d.node ? [d.node_random ? __('Nodo (casuale, non è un MAC)') : __('MAC della scheda'), d.node] : null,
      d.node ? [__('Sequenza di clock'), d.clock_seq] : null,
      [__('Canonica'), d.canonical], [__('Maiuscola tra graffe (registro, GPO)'), '{' + d.canonical.toUpperCase() + '}'],
      ['URN', 'urn:uuid:' + d.canonical], [__('Senza trattini'), d.canonical.replace(/-/g, '')],
      [__('Byte in ordine Windows (objectGUID)'), d.guid_bytes], [__('Filtro LDAP su objectGUID'), d.ldap_filter]
    ].filter(Boolean));
}
$('res-uuid').addEventListener('click', e => {
  const b = e.target.closest('[data-uact]'); if (!b) return;
  const list = b.closest('.strip-body').querySelector('.uuid-list'), raw = JSON.parse(list.dataset.raw);
  if (b.dataset.uact === 'inspect'){
    $('uuid-in').value = raw[+b.dataset.i];
    $('view-uuid').querySelector('form[data-submit="uuidinspect"]').requestSubmit();
    return;
  }
  const text = b.dataset.uact === 'all' ? raw.map(uuidFmt).join('\n') : uuidFmt(raw[+b.dataset.i]);
  navigator.clipboard?.writeText(text).then(() => {
    const l = b.textContent; b.textContent = __('Copiato'); setTimeout(() => b.textContent = l, 1400);
  });
});
['uuid-count', 'uuid-ns-custom'].forEach(id => $(id).addEventListener('input', uuidChanged));
['uuid-ns', 'uuid-upper', 'uuid-hyph'].forEach(id => $(id).addEventListener('change', uuidChanged));
document.querySelectorAll('#uuid-wrap button').forEach(b => b.addEventListener('click', () => { uuidOpt.wrap = b.dataset.wrap; uuidChanged(); }));
(() => {
  const o = store.get('uuid', null);
  if (o){
    if (typeof o.count === 'string') $('uuid-count').value = o.count;
    if (['dns', 'url', 'oid', 'x500', 'custom'].includes(o.ns)) $('uuid-ns').value = o.ns;
    if (typeof o.nsCustom === 'string') $('uuid-ns-custom').value = o.nsCustom;
    $('uuid-upper').checked = !!o.upper; $('uuid-hyph').checked = o.hyph !== false;
    if (['none', 'braces', 'urn'].includes(o.wrap)) uuidOpt.wrap = o.wrap;
    if (['v7', 'v5'].includes(o.tab)) document.querySelector('[data-tabs="uuid"] [data-tab="' + o.tab + '"]').click();
  }
  uuidSync();
})();

/* ── Local network ── */
/* Row of the subnet scan table */
function sweepRow(h){
  return '<tr data-ip="' + esc(h.ip) + '"><td class="m nw">' + esc(h.ip) + '</td>'
    + '<td class="m' + (h.name ? '' : ' dim') + '">' + esc(h.name || '—') + '</td>'
    + '<td><span class="pill ' + (h.via === 'ICMP' ? 'ok' : 'neutral') + '">' + esc(h.via) + '</span></td>'
    + '<td class="m nw">' + (h.rtt_ms !== null ? esc(h.rtt_ms) + ' ms' : '—') + '</td>'
    + '<td class="m nw' + (h.mac ? '' : ' dim') + '">' + esc(h.mac || '—') + '</td>'
    + '<td><div class="row-act">'
    + '<button type="button" data-goto="ping" data-ip="' + esc(h.ip) + '">Ping</button>'
    + '<button type="button" data-goto="portscan" data-ip="' + esc(h.ip) + '">' + __('Porte') + '</button>'
    + (h.mac ? '<button type="button" data-goto="wol" data-mac="' + esc(h.mac) + '" data-name="' + esc((h.name || '').split('.')[0]) + '">Wake-on-LAN</button>' : '')
    + '</div></td></tr>';
}
const lan = {hosts: [], open: new Set(), start: null, summary: null, done: 0, sort: 'ip', def: null, raf: 0};
const LAN_KIND = {printer:__('Stampante'), network:__('Apparato di rete'), phone:__('Telefono VoIP'), camera:__('Telecamera'),
  pc:__('PC o server Windows'), server:__('Server o dispositivo Linux'), other:__('Dispositivo')};
const LAN_ORDER = ['pc', 'server', 'printer', 'network', 'phone', 'camera', 'other'];
const LAN_ICON = {
  pc: '<rect x="2.5" y="3.5" width="15" height="10" rx="1.5"/><path d="M7 17h6M10 13.5V17"/>',
  printer: '<path d="M6 7V2.5h8V7"/><rect x="2.5" y="7" width="15" height="7" rx="1.5"/><path d="M6 11.5h8v6H6z"/>',
  network: '<rect x="2" y="7" width="16" height="6" rx="1.5"/><path d="M5 10h.01M8 10h.01M11 10h.01M14 10h2"/>',
  phone: '<path d="M3 7c0-2.2 3-3.5 7-3.5S17 4.8 17 7v1.5h-4V7H7v1.5H3z"/><rect x="4" y="10" width="12" height="7.5" rx="1.5"/><path d="M8 13h4M8 15.5h4"/>',
  camera: '<rect x="2.5" y="6" width="11" height="8" rx="1.5"/><path d="M13.5 9l4-2.5v7l-4-2.5"/>',
  server: '<rect x="3" y="3" width="14" height="6" rx="1.5"/><rect x="3" y="11" width="14" height="6" rx="1.5"/><path d="M6 6h.01M6 14h.01"/>',
  other: '<circle cx="10" cy="10" r="7"/><circle cx="10" cy="10" r="1.5"/>'
};
const ipNum = ip => ip.split('.').reduce((a, b) => a * 256 + +b, 0);
const isIp = s => /^\d+\.\d+\.\d+\.\d+$/.test(s);
const shortName = n => !n ? '' : isIp(n) ? n : n.split('.')[0];
const lanModel = h => h.snmp && h.snmp.device && h.kind === 'printer' ? h.snmp.device : '';
function lanTitle(h){
  const m = lanModel(h);
  return shortName(h.name) || (m ? (h.vendor ? h.vendor + ' ' : '') + m : '') || h.vendor || h.ip;
}
function lanSub(h){
  const t = lanTitle(h), m = lanModel(h);
  return [t === h.ip ? '' : h.ip, h.vendor && !t.includes(h.vendor) ? h.vendor : '', m && !t.includes(m) ? m : '',
    h.random_mac ? __('MAC casuale') : '', t === h.ip && !h.vendor ? LAN_KIND[h.kind] : ''].filter(Boolean).join(' · ');
}
const lanSvcCount = h => h.services.length + (h.snmp ? 1 : 0);

function lanSummary(){
  const st = lan.start, n = lan.hosts.length, sm = lan.summary, el = $('lan-sum');
  if (!st || !el) return;
  const extra = [];
  if (!st.local) extra.push(__('rete non collegata direttamente: niente MAC né produttore'));
  else if (!st.oui) extra.push(__('elenco produttori (oui.txt) non trovato'));
  el.innerHTML = (sm ? '<span class="svc-dot"></span>' : '<span class="spinner"></span>')
    + __('<strong>{n}</strong> online · ', {n}) + esc(st.cidr)
    + (sm ? __(' · {total} indirizzi in {s} s', {total: st.total.toLocaleString(LOC), s: fmtBits(sm.elapsed_s, 1)}) + (sm.stopped ? ' · <span class="c-warn">' + __('interrotta') + '</span>' : '')
        : __(' · {done} su {total} controllati', {done: lan.done.toLocaleString(LOC), total: st.total.toLocaleString(LOC)}))
    + (extra.length ? ' · <span class="c-dim">' + extra.join(' · ') + '</span>' : '');
}
function lanProgress(done, total){
  const i = document.querySelector('#lan-prog i');
  if (i) i.style.width = Math.round(done / Math.max(total, 1) * 100) + '%';
}
function lanSorted(){
  const by = {
    ip: (a, b) => ipNum(a.ip) - ipNum(b.ip),
    name: (a, b) => (shortName(a.name) ? 0 : 1) - (shortName(b.name) ? 0 : 1) || lanTitle(a).localeCompare(lanTitle(b), 'it', {numeric: true}),
    kind: (a, b) => LAN_ORDER.indexOf(a.kind) - LAN_ORDER.indexOf(b.kind) || ipNum(a.ip) - ipNum(b.ip),
    svc: (a, b) => lanSvcCount(b) - lanSvcCount(a) || ipNum(a.ip) - ipNum(b.ip)
  }[lan.sort];
  const q = (($('lan-filter') || {}).value || '').trim().toLowerCase();
  return lan.hosts.filter(h => !q || [lanTitle(h), h.ip, h.vendor, h.mac, h.name, h.netbios, LAN_KIND[h.kind],
      h.snmp && h.snmp.sys_descr, h.snmp && h.snmp.device, h.services.map(s => s.port + ' ' + s.name).join(' ')]
    .some(x => x && String(x).toLowerCase().includes(q))).sort(by);
}
function lanDetail(h){
  let html = kv([[__('Indirizzo IP'), h.ip, 'info'], ['MAC', h.mac || (lan.start && lan.start.local ? __('non rilevato') : __('rete remota'))],
    [__('Produttore'), h.vendor || (h.random_mac ? __('MAC casuale') : '—'), 'txt'], [__('Tipo'), LAN_KIND[h.kind] + (h.vm ? __(' (virtuale)') : ''), 'txt'],
    [__('Nome DNS (PTR)'), h.ptr || '—'], ['NetBIOS', h.netbios || '—'], [__('Rilevato con'), h.via],
    ['RTT', h.rtt_ms !== null && h.rtt_ms !== undefined ? h.rtt_ms + ' ms' : '—']]);
  if (h.snmp) html += '<div class="sub">' + __('SNMP (community public)') + '</div>' + rows([['sysName', h.snmp.sys_name || '—'],
    ['sysDescr', h.snmp.sys_descr || '—'], [__('Dispositivo (hrDeviceDescr)'), h.snmp.device || '—'], ['sysObjectID', h.snmp.object_id || '—']]);
  if (h.services.length) html += '<div class="sub">' + __('Servizi in ascolto ({n})', {n: h.services.length}) + '</div>'
    + '<table class="tbl"><thead><tr><th>' + __('Porta') + '</th><th>' + __('Servizio') + '</th><th>Banner</th></tr></thead><tbody>'
    + h.services.map(s => '<tr><td class="m nw">' + s.port + '</td><td class="nw">' + esc(s.name) + '</td><td class="m">' + esc(s.banner || '—') + '</td></tr>').join('')
    + '</tbody></table>';
  else if (h.pending) html += '<p class="note"><span class="spinner"></span>' + __('Nomi, SNMP e servizi in arrivo…') + '</p>';
  else if (lan.start && lan.start.services) html += '<p class="note">' + __('Nessuna delle 21 porte controllate è aperta.') + '</p>';
  html += '<div class="row-act">'
    + '<button type="button" data-goto="ping" data-ip="' + esc(h.ip) + '">Ping</button>'
    + '<button type="button" data-goto="portscan" data-ip="' + esc(h.ip) + '">' + __('Porte') + '</button>'
    + '<button type="button" data-goto="snmp" data-ip="' + esc(h.ip) + '">SNMP</button>'
    + (h.mac && !h.random_mac ? '<button type="button" data-goto="wol" data-mac="' + esc(h.mac) + '" data-name="' + esc(shortName(h.name)) + '">Wake-on-LAN</button>' : '')
    + '</div>';
  return html;
}
function lanRender(){
  if (lan.raf) return;
  lan.raf = requestAnimationFrame(() => {
    lan.raf = 0;
    const list = $('lan-list');
    if (!list) return;
    const svc = lan.start && lan.start.services;
    list.innerHTML = lanSorted().map(h => {
      const open = lan.open.has(h.ip), n = lanSvcCount(h);
      return '<div class="lan-row" data-ip="' + esc(h.ip) + '"><button type="button" class="lan-main" aria-expanded="' + open + '">'
        + '<span class="lan-ico" title="' + esc(LAN_KIND[h.kind]) + '"><svg viewBox="0 0 20 20" aria-hidden="true">' + LAN_ICON[h.kind] + '</svg><span class="lan-dot"></span></span>'
        + '<span class="lan-txt"><span class="lan-title">' + esc(lanTitle(h)) + (h.vm ? '<span class="tag">VM</span>' : '') + '</span>'
        + '<span class="lan-sub">' + esc(lanSub(h)) + '</span></span>'
        + '<span class="lan-svc">' + (h.pending ? '<span class="spinner" title="' + __('Dettagli in arrivo') + '"></span>' : svc ? n + ' svc' : h.snmp ? 'SNMP' : '') + '</span><span class="lan-chev" aria-hidden="true">›</span></button>'
        + (open ? '<div class="lan-detail">' + lanDetail(h) + '</div>' : '') + '</div>';
    }).join('');
  });
}
function lanCopy(btn){
  const lines = lanSorted().map(h => [h.ip, lanTitle(h), LAN_KIND[h.kind], h.mac, h.vendor,
    h.services.map(s => s.port).join(' ')].join('\t'));
  navigator.clipboard?.writeText([__('IP\tNome\tTipo\tMAC\tProduttore\tPorte')].concat(lines).join('\n')).then(() => {
    btn.textContent = __('Copiato'); setTimeout(() => btn.textContent = __('Copia'), 1400);
  });
}
$('res-lan').addEventListener('click', e => {
  const m = e.target.closest('.lan-main');
  if (!m) return;
  const ip = m.closest('.lan-row').dataset.ip;
  if (lan.open.has(ip)) lan.open.delete(ip); else lan.open.add(ip);
  lanRender();
});
TAURI.invoke('lan_default').then(d => {
  if (!d) return;
  lan.def = d;
  $('lan-net').innerHTML = __('Rete di questo PC: <strong>{cidr}</strong> (indirizzo {ip})', {cidr: esc(d.cidr), ip: esc(d.ip)})
    + (d.reduced ? __('. La scheda è su {iface}, più grande di una /21: proposta la /24 del PC.', {iface: esc(d.iface)}) : '');
}).catch(() => {});

/* ── Local network, Neighbours tab: ARP and NDP tables of this PC, merged by MAC ── */
const NB_STATE = {reachable:['ok', __('raggiungibile')], cache:['neutral', __('in cache')], permanent:['neutral', __('statico')], incomplete:['warn', __('non risolto')]};
const NB_SHOWN = 4;
const nbStatePill = s => chkPill(NB_STATE[s][0], NB_STATE[s][1]);
const nbDur = s => s === null || s === undefined ? __('senza scadenza') : s >= 86400 ? Math.round(s / 86400) + ' ' + __('g') : s >= 3600 ? Math.round(s / 3600) + ' h' : s >= 60 ? Math.round(s / 60) + ' min' : s + ' s';
const nbTitle = d => !d.mac ? __('Indirizzi non risolti') : d.vendor || (d.random_mac ? __('MAC casuale') : d.mac);
const nbKey = d => d.mac || '-';
const nbFlat = s => String(s).toLowerCase().replace(/[:.\-\s]/g, '');
function nbMatches(d, q){
  if (!q) return true;
  const t = q.trim().toLowerCase(), f = nbFlat(t);
  return [d.mac, d.vendor, d.ifaces.join(' '), ...d.v4.map(a => a.ip), ...d.v6.map(a => a.ip)].some(x => x && String(x).toLowerCase().includes(t))
    || (f.length >= 2 && nbFlat(d.mac).includes(f));
}
function nbChips(d){
  const all = [...d.v4.map(a => [a, '']), ...d.v6.map(a => [a, ' v6'])];
  const shown = d.mac ? all : all.slice(0, NB_SHOWN);
  return '<span class="nb-chips">' + shown.map(([a, c]) => '<span class="hx-src' + c + '" title="' + esc(a.scope || 'IPv4') + '">' + esc(a.ip) + '</span>').join('')
    + (all.length > shown.length ? '<span class="nb-dim">+' + (all.length - shown.length) + '</span>' : '') + '</span>';
}
function nbDetail(d){
  const line = a => a.ip + (a.scope ? '  (' + a.scope + ')' : '') + (a.state === 'reachable' ? '' : '  · ' + NB_STATE[a.state][1]) + (a.router ? '  · router' : '');
  let html = '<table class="tbl"><tbody>';
  if (d.mac) html += '<tr><td class="k">MAC</td><td class="v">' + esc(d.mac) + '</td></tr>'
    + '<tr><td class="k">' + __('Produttore') + '</td><td class="v txt">' + esc(d.vendor || (d.random_mac ? __('MAC casuale (nessun produttore)') : '—')) + (d.vm ? __(' · scheda virtuale') : '') + '</td></tr>';
  html += '<tr><td class="k">' + __('Scheda') + '</td><td class="v txt">' + esc(d.ifaces.join(', ') || '—') + '</td></tr>';
  if (d.v4.length) html += '<tr><td class="k">IPv4 (' + d.v4.length + ')</td><td class="v">' + esc(d.v4.map(line).join('\n')) + '</td></tr>';
  if (d.v6.length) html += '<tr><td class="k">IPv6 (' + d.v6.length + ')</td><td class="v">' + esc(d.v6.map(line).join('\n')) + '</td></tr>';
  html += '</tbody></table>';
  const ip = d.v4.length ? d.v4[0].ip : '';
  if (ip && d.mac) html += '<div class="row-act">'
    + '<button type="button" data-goto="ping" data-ip="' + esc(ip) + '">Ping</button>'
    + '<button type="button" data-goto="portscan" data-ip="' + esc(ip) + '">' + __('Porte') + '</button>'
    + '<button type="button" data-goto="snmp" data-ip="' + esc(ip) + '">SNMP</button>'
    + (d.random_mac ? '' : '<button type="button" data-goto="wol" data-mac="' + esc(d.mac) + '" data-name="">Wake-on-LAN</button>') + '</div>';
  return html;
}
function nbRows(data, q, open){
  const list = data.devices.filter(d => nbMatches(d, q));
  if (!list.length) return '<p class="note">' + __('Nessun dispositivo corrisponde a «{q}».', {q: esc(q)}) + '</p>';
  return list.map(d => {
    const o = open.has(nbKey(d));
    const tags = (d.gateway ? '<span class="tag">Gateway</span>' : '') + (d.router6 ? '<span class="tag">' + __('Router IPv6') + '</span>' : '') + (d.vm ? '<span class="tag">VM</span>' : '');
    return '<div class="lan-row nb-row" data-nb="' + esc(nbKey(d)) + '"><button type="button" class="lan-main" aria-expanded="' + o + '">'
      + '<span class="lan-ico"><svg viewBox="0 0 20 20" aria-hidden="true"><rect x="3" y="4" width="14" height="9" rx="1.5"/><path d="M7 16h6M10 13v3"/></svg></span>'
      + '<span class="lan-txt"><span class="lan-title">' + esc(nbTitle(d)) + tags + '</span>'
      + '<span class="lan-sub mono">' + esc((d.mac || __('{n} indirizzi senza risposta', {n: d.v4.length + d.v6.length})) + (d.mac && d.ifaces.length ? ' · ' + d.ifaces.join(', ') : '')) + '</span>'
      + nbChips(d) + '</span><span class="lan-svc">' + nbStatePill(d.state) + '</span><span class="lan-chev" aria-hidden="true">›</span></button>'
      + (o ? '<div class="lan-detail nb-detail">' + nbDetail(d) + '</div>' : '') + '</div>';
  }).join('');
}
function nbText(d){
  const out = [__('Vicini di questo PC, letti alle {t} ({n} dispositivi)', {t: new Date(d.at * 1000).toLocaleTimeString(LOC), n: d.n_devices}), '', __('Controlli')];
  d.checks.slice().sort((a, b) => CHK_RANK[a.status] - CHK_RANK[b.status]).forEach(c => out.push('  [' + c.status + '] ' + c.name + ': ' + c.detail));
  out.push('', __('Router IPv6'));
  d.routers.forEach(r => out.push('  ' + r.addr + '\t' + r.mac + '\t' + r.vendor + '\t' + r.iface + '\t' + nbDur(r.lifetime_s)));
  out.push('', __('Prefissi IPv6'));
  d.prefixes.forEach(p => out.push('  ' + p.prefix + '\t' + p.iface + '\t' + (p.on_link ? __('sul collegamento') : __('tramite router')) + '\t' + nbDur(p.valid_s)));
  out.push('', __('Dispositivi (CSV)'), d.csv);
  return out.join('\n');
}
function neighRender(d){
  const checks = d.checks.map((c, i) => [c, i]).sort((a, b) => (CHK_RANK[a[0].status] - CHK_RANK[b[0].status]) || (a[1] - b[1])).map(x => x[0]);
  const nErr = checks.filter(c => c.status === 'err').length, nWarn = checks.filter(c => c.status === 'warn').length;
  const at = t => new Date(t * 1000).toLocaleTimeString(LOC);
  const summary = '<p class="summary"><span class="svc-dot"></span>' + __('<strong>{n}</strong> dispositivi', {n: d.n_devices}) + ' · ' + d.n_v4 + ' IPv4 · ' + d.n_v6 + ' IPv6 · '
    + d.routers.length + ' ' + __('router IPv6') + ' · ' + (d.prefixes.length === 1 ? __('{n} prefisso', {n: d.prefixes.length}) : __('{n} prefissi', {n: d.prefixes.length}))
    + __(' · letta alle {t}', {t: at(d.at)}) + (d.previous_at ? __(' · confronto con le {t}', {t: at(d.previous_at)}) : __(' · primo aggiornamento, nessun confronto'))
    + (d.source === 'ripiego-ipv4' ? ' · <span class="c-warn">' + __('solo IPv4') + '</span>' : '') + '</p>';
  const pChecks = '<table class="tbl smtp-checks hx-tbl"><thead><tr><th></th><th>' + __('Area') + '</th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
    + checks.map(c => '<tr><td>' + chkPill(c.status) + '</td><td class="k hx-area">' + esc(c.area) + '</td><td class="k">' + esc(c.name) + '</td><td class="m">' + esc(c.detail) + '</td></tr>').join('') + '</tbody></table>';
  const pDev = '<div class="lan-tools" style="margin:12px 0"><label>' + __('Cerca') + ' <input type="text" data-nbq spellcheck="false" autocomplete="off"></label>'
    + '<button type="button" class="chip" data-nbcsv>' + __('Copia CSV') + '</button></div><div class="lan-list" data-nblist>' + nbRows(d, '', new Set()) + '</div>';
  const pRt = (d.routers.length ? '<table class="tbl hx-tbl"><thead><tr><th>' + __('Router IPv6') + '</th><th>MAC</th><th>' + __('Produttore') + '</th><th>' + __('Scheda') + '</th><th>' + __('Validità') + '</th><th></th></tr></thead><tbody>'
      + d.routers.map(r => '<tr><td class="m">' + esc(r.addr) + '</td><td class="m">' + esc(r.mac || '—') + '</td><td>' + esc(r.vendor || '—') + '</td><td>' + esc(r.iface) + '</td><td class="m">'
        + esc(nbDur(r.lifetime_s)) + '</td><td>' + (r.same_as_gateway ? chkPill('ok', __('come il gateway IPv4')) : '') + '</td></tr>').join('') + '</tbody></table>'
    : '<p class="note hx-top">' + __('Nessun router IPv6 annunciato: questo PC non ha ricevuto Router Advertisement.') + '</p>')
    + (d.prefixes.length ? '<table class="tbl hx-tbl" style="margin-top:14px"><thead><tr><th>' + __('Prefisso annunciato') + '</th><th>' + __('Scheda') + '</th><th>' + __('Tipo') + '</th><th>' + __('Validità') + '</th><th>Router</th></tr></thead><tbody>'
      + d.prefixes.map(p => '<tr><td class="m">' + esc(p.prefix) + '</td><td>' + esc(p.iface) + '</td><td>' + (p.on_link ? __('sul collegamento') : __('tramite router')) + '</td><td class="m">'
        + esc(nbDur(p.valid_s)) + '</td><td class="m">' + esc(p.via.join('\n') || '—') + '</td></tr>').join('') + '</tbody></table>' : '');
  const tab = 'chk';
  return {status: nErr ? 'err' : nWarn ? 'warn' : 'ok', data: d, text: nbText(d),
    html: summary + rtabs([['chk', __('Controlli'), checks.length], ['dev', __('Dispositivi'), d.n_devices], ['rt', __('Router e prefissi'), d.routers.length + d.prefixes.length]], tab)
      + rpane('chk', tab, pChecks) + rpane('dev', tab, pDev) + rpane('rt', tab, pRt)};
}
tools.neigh = form => {
  const probe = $('neigh-probe').checked;
  run('neigh', __('Vicini'), __('questo PC'), async () => {
    try { return neighRender(await TAURI.invoke('neigh_scan', {req: {probe}})); }
    catch(e){ throw new Error(tauriError(e)); }
  }, form);
};
$('res-neigh').addEventListener('click', e => {
  const strip = e.target.closest('.strip');
  if (!strip || !strip._data) return;
  const main = e.target.closest('.lan-main');
  if (main){
    const key = main.closest('.nb-row').dataset.nb, open = strip._open || (strip._open = new Set());
    if (open.has(key)) open.delete(key); else open.add(key);
    strip.querySelector('[data-nblist]').innerHTML = nbRows(strip._data, strip.querySelector('[data-nbq]').value, open);
  } else if (e.target.closest('[data-nbcsv]')){
    const b = e.target.closest('[data-nbcsv]');
    navigator.clipboard?.writeText(strip._data.csv).then(() => { b.textContent = __('Copiato'); setTimeout(() => b.textContent = __('Copia CSV'), 1400); });
  }
});
// the search redraws only the rows: the field being typed in stays as it is
$('res-neigh').addEventListener('input', e => {
  if (!e.target.matches('[data-nbq]')) return;
  const strip = e.target.closest('.strip');
  strip.querySelector('[data-nblist]').innerHTML = nbRows(strip._data, e.target.value, strip._open || new Set());
});
$('res-neigh').addEventListener('click', gotoTool);

/* ── Wi-Fi: nearby networks, current connection, channels, signal monitor ── */
const wf = {data: null, busy: false, shown: false, filter: 'all', at: null, timer: 0,
  mon: {samples: [], events: [], start: 0, run: false, raf: 0, roams: 0}};
const WF_PAL = ['var(--wf-c1)', 'var(--wf-c2)', 'var(--wf-c3)', 'var(--wf-c4)', 'var(--wf-c5)', 'var(--wf-c6)'];
const WF_SEC = {open:'err', weak:'warn', wpa2:'neutral', wpa3:'ok', ent:'info', owe:'ok'};
const WF_BAND = {'2.4':__('2,4 GHz'), '5':'5 GHz', '6':'6 GHz'};
const WF_BLOCKING = ['no_adapter', 'no_wlan', 'service', 'unsupported', 'error'];
const wfLevel = d => d >= -67 ? 'ok' : d >= -75 ? 'warn' : 'err';
const wfBars = d => {
  const n = d >= -55 ? 4 : d >= -67 ? 3 : d >= -75 ? 2 : 1;
  return '<span class="wf-bars ' + wfLevel(d) + '">' + [1, 2, 3, 4].map(i => '<i class="' + (i <= n ? 'on' : '') + '"></i>').join('') + '</span>';
};
const wfName = n => n.ssid || n.profile || '';
const wfStd = (gen, std) => gen ? gen + ' · 802.11' + std : std ? '802.11' + std : '—';
const wfIcon = '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M6 19a25.5 25.5 0 0136 0M12 25.5a17 17 0 0124 0M18 32a8.6 8.6 0 0112 0"/><circle cx="24" cy="38.5" r="1.6"/><path class="x" d="M8 8l32 32"/></svg>';

function wifiShown(){
  if (wf.shown) return;
  wf.shown = true;
  // first the list Windows already has in memory (immediate), then a fresh scan
  wifiScan(false).then(() => { if (wf.data && wf.data.adapters.length && !wf.data.problem) wifiScan(true); });
}

async function wifiScan(fresh){
  if (wf.busy) return;
  wf.busy = true;
  const form = $('wf-form'), btn = $('wifi-btn');
  const idle = busy(form);
  btn.innerHTML = '<span class="spinner"></span>' + __('Scansione…');
  if (!wf.data) $('wf-msg').innerHTML = '<p class="summary wf-box"><span class="spinner"></span>' + __('Lettura delle schede Wi-Fi…') + '</p>';
  try {
    const d = await TAURI.invoke('wifi_scan', {req: {adapter: $('wifi-if').value || '', scan: fresh}});
    wf.data = d; wf.at = new Date();
    wifiRender();
  } catch(e) {
    $('wf-msg').innerHTML = '<div class="panel wf-box"><div class="msg-err">' + esc(tauriError(e)) + '</div></div>';
  } finally {
    btn.textContent = __('Scansiona');
    idle();
    wf.busy = false;
  }
}

function wifiRender(){
  const d = wf.data;
  const sel = $('wifi-if');
  sel.innerHTML = d.adapters.map(a => '<option value="' + esc(a.id) + '">' + esc(a.name)
    + (a.radio !== 'on' ? __(' · spenta') : '') + '</option>').join('');
  if (d.adapter) sel.value = d.adapter;
  $('wf-form').classList.toggle('hidden', !d.adapters.length);
  const p = d.problem, blocking = p && (WF_BLOCKING.includes(p.code) || p.code === 'radio_off');
  if (blocking){
    $('wf-msg').innerHTML = '<div class="panel wf-empty wf-box">' + wfIcon
      + '<div class="wf-empty-t">' + esc(p.title) + '</div><p class="lede">' + esc(p.detail) + '</p>'
      + '<button class="btn secondary" type="button" id="wf-retry">' + __('Controlla di nuovo') + '</button></div>';
    $('wf-retry').onclick = () => wifiScan(false);
  } else if (p || d.warning){
    $('wf-msg').innerHTML = '<div class="wf-note">' + (p ? '<div><strong>' + esc(p.title) + '</strong><span class="c-dim">' + esc(p.detail) + '</span></div>'
      : '<div>' + esc(d.warning) + '</div>') + '</div>';
  } else {
    $('wf-msg').innerHTML = '';
  }
  $('wf-conn').classList.toggle('hidden', blocking);
  $('wf-tabs').classList.toggle('hidden', blocking);
  if (blocking) return;
  wifiConn(); wifiNets(); wifiChannels();
}

function wifiGauge(dbm){
  const p = Math.max(0, Math.min(100, (dbm + 90) / 60 * 100));
  const lvl = dbm >= -55 ? ['ok', __('Ottimo')] : dbm >= -67 ? ['ok', __('Buono')] : dbm >= -75 ? ['warn', __('Discreto')] : ['err', __('Debole')];
  const r = 44, c = Math.PI * r * 1.5;
  const arc = (len, col) => '<circle cx="52" cy="52" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="8" stroke-dasharray="'
    + len.toFixed(1) + ' 999" transform="rotate(135 52 52)" stroke-linecap="round"/>';
  return '<div class="wf-gauge"><svg viewBox="0 0 104 104" aria-hidden="true">' + arc(c, 'var(--raised)') + arc(c * p / 100, 'var(--' + lvl[0] + ')')
    + '</svg><b>' + dbm + '<small>dBm</small></b><em class="c-' + lvl[0] + '">' + lvl[1] + '</em></div>';
}

function wifiConn(){
  const c = wf.data.connection, box = $('wf-conn');
  if (!c){
    box.innerHTML = '<div></div><div><div class="panel-title" style="margin:0;font-size:15px">' + __('Connessione attuale') + '</div>'
      + '<p class="summary" style="margin:6px 0 0">' + __('La scheda non è connessa a nessuna rete Wi-Fi.') + '</p></div>';
    return;
  }
  const dbm = c.rssi ?? Math.round(c.quality / 2 - 100);
  const kvr = c.k === null ? '—' : ['k', 'v', 'r'].filter(x => c[x]).join(', ') || __('nessuno');
  const chan = c.channel ? c.channel + (c.band ? ' · ' + WF_BAND[c.band] : '') + (c.width_mhz ? ' · ' + c.width_mhz + ' MHz' : '') : '—';
  const item = (k, v, cls) => '<div class="kv-item' + (cls ? ' ' + cls : '') + '"><div class="kv-k">' + k + '</div><div class="kv-v" title="' + esc(v) + '">' + esc(v) + '</div></div>';
  const fmt = v => Number(v).toLocaleString(LOC, {maximumFractionDigits: 1});
  box.innerHTML = wifiGauge(dbm) + '<div><div class="wf-tools" style="margin-bottom:8px"><div class="panel-title" style="margin:0;font-size:15px">' + __('Connessione attuale') + '</div>'
    + '<span>' + (c.mlo ? '<span class="pill info">' + __('MLO annunciato dall\'AP') + '</span> ' : '') + '<span class="pill ok">' + __('Connesso') + '</span></span></div><div class="kv">'
    + item(__('Rete'), c.ssid, 'txt')
    + item('Access point' + (c.vendor ? ' (' + esc(c.vendor.split(/[ ,]/)[0]) + ')' : ''), c.bssid)
    + item(__('Canale'), chan)
    + item('Standard', wfStd(c.gen, c.std))
    + item(__('Velocità RX / TX'), fmt(c.rx_mbps) + ' / ' + fmt(c.tx_mbps) + ' Mbit/s')
    + item(__('Sicurezza') + (c.cipher ? ' (' + esc(c.cipher) + ')' : ''), c.security)
    + item(__('Indirizzo IP'), c.ip || '—')
    + item('Roaming 802.11k/v/r', kvr, kvr !== '—' && kvr !== __('nessuno') ? 'ok' : '')
    + '</div></div>';
}

/* filtered list and, if requested, grouped by network */
function wifiList(){
  const n = wf.data.networks, f = wf.filter;
  return n.filter(x => f === 'all' || (f === 'hidden' ? x.hidden : x.band === f));
}
function wifiRow(a){
  let name;
  if (a.ssid) name = '<span class="wf-ssid">' + esc(a.ssid) + '</span>';
  else if (a.profile) name = '<span class="wf-ssid">' + esc(a.profile) + '</span> <span class="pill neutral sm">' + __('nascosta, da profilo') + '</span>';
  else name = '<span class="wf-ssid hid">(' + __('rete nascosta') + (a.ssid_len ? __(', {n} caratteri', {n: a.ssid_len}) : '') + ')</span>';
  if (a.connected) name += ' <span class="pill info sm">' + __('collegato') + '</span>';
  name += '<span class="wf-sub">' + esc(a.bssid) + '</span>';
  if (a.same_ap) name += '<span class="wf-hint">' + __('stesso AP di {n} (probabile)', {n: esc(a.same_ap)}) + '</span>';
  const kvr = '<span class="wf-k">' + ['k', 'v', 'r'].map(x => '<span class="tag' + (a[x] ? '' : ' off') + '">' + x + '</span>').join('') + '</span>';
  return '<tr class="' + (a.connected ? 'me' : '') + '">'
    + '<td class="nw"><span class="wf-bar">' + wfBars(a.rssi) + '<span class="wf-dbm">' + a.rssi + '</span></span></td>'
    + '<td>' + name + '</td>'
    + '<td>' + esc(a.vendor || '—') + '</td>'
    + '<td class="nw"><span class="mono">' + a.channel + '</span><span class="wf-sub">' + WF_BAND[a.band] + ' · ' + a.width_mhz + ' MHz</span></td>'
    + '<td class="nw">' + (a.gen || '802.11' + a.std) + (a.mlo ? ' <span class="tag sm" title="Multi-Link Operation">MLO</span>' : '')
    + (a.gen ? '<span class="wf-sub">802.11' + a.std + '</span>' : '') + '</td>'
    + '<td class="nw"><span class="pill ' + WF_SEC[a.sec_class] + '"' + (a.cipher ? ' title="' + esc(a.cipher) + '"' : '') + '>' + esc(a.security) + '</span></td>'
    + '<td>' + kvr + '</td>'
    + '<td class="mono' + (a.clients === null ? ' c-dim' : '') + '">' + (a.clients ?? '—')
    + (a.load_pct !== null ? '<span class="wf-sub">' + __('carico {n}%', {n: a.load_pct}) + '</span>' : '') + '</td></tr>';
}
function wifiNets(){
  const d = wf.data, all = d.networks;
  $('wf-count').textContent = all.length || '';
  const nets = new Set(all.filter(n => wfName(n)).map(wfName)).size;
  const hid = all.filter(n => n.hidden).length;
  const cnt = b => all.filter(n => n.band === b).length;
  const chip = (f, label, n) => '<button class="chip' + (wf.filter === f ? ' on' : '') + '" type="button" data-wf="' + f + '">' + label
    + (n === undefined ? '' : ' <span class="c-dim">' + n + '</span>') + '</button>';
  let html = '<div class="wf-tools"><p class="summary">' + __('<strong>{n}</strong> access point, ', {n: all.length})
    + (nets === 1 ? __('<strong>{n}</strong> rete', {n: nets}) : __('<strong>{n}</strong> reti', {n: nets}))
    + (hid ? ', ' + (hid === 1 ? __('<strong>{n}</strong> nascosta', {n: hid}) : __('<strong>{n}</strong> nascoste', {n: hid})) : '')
    + (wf.at ? __(' · ultima scansione {t}', {t: wf.at.toLocaleTimeString(LOC)}) : '') + '</p><div class="wf-chips">'
    + chip('all', __('Tutte')) + chip('2.4', __('2,4 GHz'), cnt('2.4')) + chip('5', '5 GHz', cnt('5')) + chip('6', '6 GHz', cnt('6')) + chip('hidden', __('Nascoste'), hid)
    + '<button class="chip" type="button" id="wf-csv">' + __('Copia CSV') + '</button></div></div>';
  let list = wifiList();
  if (!all.length){
    html += '<div class="empty">' + (d.problem && d.problem.code === 'location' ? __('Elenco delle reti non disponibile senza accesso alla posizione.') : __('Nessuna rete trovata.')) + '</div>';
  } else if (!list.length){
    html += '<div class="empty">' + __('Nessuna rete con questo filtro.') + '</div>';
  } else {
    let body;
    if ($('wifi-group').checked){
      const key = n => n.hidden && !n.profile ? '\u0000' : wfName(n);
      const groups = new Map();
      list.forEach(n => { const k = key(n); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n); });
      body = [...groups.entries()].sort((a, b) => b[1][0].rssi - a[1][0].rssi).map(([k, g]) =>
        '<tr class="wf-grp"><td colspan="8">' + esc(k === '\u0000' ? __('Reti nascoste') : k) + ' · ' + g.length + ' access point</td></tr>' + g.map(wifiRow).join('')).join('');
    } else body = list.map(wifiRow).join('');
    html += '<div class="panel wf-tblwrap"><table class="tbl wf"><thead><tr><th>' + __('Segnale') + '</th><th>' + __('Rete') + '</th><th>' + __('Produttore AP') + '</th><th>' + __('Canale') + '</th><th>Standard</th>'
      + '<th>' + __('Sicurezza') + '</th><th title="' + __('Roaming assistito: 802.11k, 802.11v, 802.11r') + '">k / v / r</th><th>Client</th></tr></thead><tbody>' + body + '</tbody></table></div>';
  }
  html += '<p class="note">' + __('Il numero di client e il carico compaiono solo se l\'access point li annuncia (BSS Load). k/v/r: roaming assistito annunciato dall\'AP. '
    + 'MLO: AP Wi-Fi 7 che trasmette su più bande insieme. Il nome di una rete nascosta compare solo se questo PC ne ha il profilo salvato.') + '</p>';
  $('wf-nets').innerHTML = html;
}
$('wf-nets').addEventListener('click', e => {
  const c = e.target.closest('[data-wf]');
  if (c){ wf.filter = c.dataset.wf; wifiNets(); return; }
  if (e.target.closest('#wf-csv')){
    const head = __('segnale_dbm;ssid;nascosta;bssid;produttore;banda_ghz;canale;larghezza_mhz;standard;sicurezza;cifratura;k;v;r;mlo;client;carico_pct');
    const q = v => /[;"\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v ?? '');
    const lines = wifiList().map(n => [n.rssi, wfName(n), n.hidden ? __('si') : __('no'), n.bssid, n.vendor, n.band, n.channel, n.width_mhz,
      '802.11' + n.std, n.security, n.cipher, +n.k, +n.v, +n.r, +n.mlo, n.clients, n.load_pct].map(q).join(';'));
    const b = e.target.closest('#wf-csv');
    navigator.clipboard?.writeText([head, ...lines].join('\n')).then(() => { b.textContent = __('Copiato'); setTimeout(() => b.textContent = __('Copia CSV'), 1400); });
  }
});

/* chart of a band: one trapezoid per access point (height = signal, width = occupied band) */
function wifiChart(aps, f0, f1, ticks, freqOf, extra){
  const W = 900, H = 240, L = 40, R = 10, T = 34, B = 30;
  const x = f => L + (f - f0) / (f1 - f0) * (W - L - R), y = d => T + (-30 - Math.max(-95, Math.min(-30, d))) / 65 * (H - T - B), floor = y(-95);
  const me = wf.data.connection ? wf.data.connection.ssid : null;
  const colors = new Map(); let ci = 0;
  const colorOf = a => {
    const k = wfName(a) || a.bssid;
    if (me && k === me) return 'var(--info)';
    if (!colors.has(k)) colors.set(k, WF_PAL[ci++ % WF_PAL.length]);
    return colors.get(k);
  };
  let s = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img">';
  if (extra) s += extra(x, T, floor);
  for (let d = -40; d >= -90; d -= 10)
    s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + y(d) + '" y2="' + y(d) + '" stroke="var(--line)" stroke-dasharray="2 4"/>'
      + '<text x="' + (L - 6) + '" y="' + (y(d) + 4) + '" text-anchor="end" font-size="10.5" fill="var(--faint)">' + d + '</text>';
  s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + floor + '" y2="' + floor + '" stroke="var(--line-strong)"/>';
  ticks.forEach(c => { const X = x(freqOf(c));
    s += '<line x1="' + X + '" x2="' + X + '" y1="' + floor + '" y2="' + (floor + 4) + '" stroke="var(--line-strong)"/>'
      + '<text x="' + X + '" y="' + (floor + 17) + '" text-anchor="middle" font-size="10.5" fill="var(--muted)">' + c + '</text>'; });
  const labels = [];
  [...aps].sort((a, b) => (a.connected - b.connected) || a.rssi - b.rssi).forEach(a => {
    const xl = Math.max(L, x(a.center_mhz - a.width_mhz / 2)), xr = Math.min(W - R, x(a.center_mhz + a.width_mhz / 2));
    const rp = (xr - xl) * .18, top = y(a.rssi), c = colorOf(a), own = me && wfName(a) === me;
    s += '<path d="M' + xl + ' ' + floor + ' C' + (xl + rp * .6) + ' ' + floor + ' ' + (xl + rp * .4) + ' ' + top + ' ' + (xl + rp) + ' ' + top
      + ' L' + (xr - rp) + ' ' + top + ' C' + (xr - rp * .4) + ' ' + top + ' ' + (xr - rp * .6) + ' ' + floor + ' ' + xr + ' ' + floor
      + '" fill="' + c + '" fill-opacity="' + (a.connected ? .28 : own ? .14 : .10) + '" stroke="' + c + '" stroke-width="' + (a.connected ? 2.6 : 1.4) + '"/>';
    labels.push({fc: a.center_mhz, x: x(a.center_mhz), top, c, me: a.connected, dbm: a.rssi, name: (wfName(a) || __('(nascosta)')) + (a.connected ? ' ●' : '')});
  });
  // same frequency and similar signal: a single label; then no overlaps
  const grp = [];
  labels.sort((a, b) => b.dbm - a.dbm).forEach(l => {
    const g = grp.find(g => g.fc === l.fc && g.dbm - l.dbm <= 6);
    if (g){ if (!g.items.some(i => i.name === l.name)) g.items.push(l); } else grp.push({fc: l.fc, dbm: l.dbm, x: l.x, top: l.top, items: [l]});
  });
  const boxes = [];
  grp.forEach(g => {
    const w = g.items.map(i => i.name).join(' · ').length * 6.2;
    g.x = Math.max(L + w / 2, Math.min(W - R - w / 2, g.x));
    let yy = g.top - 6;
    const hit = () => boxes.some(b => Math.abs(b.x - g.x) < (b.w + w) / 2 + 6 && Math.abs(b.y - yy) < 13);
    while (hit() && yy > 12) yy -= 14;
    boxes.push({x: g.x, y: yy, w});
    s += '<text x="' + g.x + '" y="' + yy + '" text-anchor="middle" font-size="11" font-family="Instrument Sans">'
      + g.items.map((i, k) => (k ? '<tspan fill="var(--faint)"> · </tspan>' : '') + '<tspan fill="' + i.c + '" font-weight="' + (i.me ? 700 : 500) + '">' + esc(i.name) + '</tspan>').join('') + '</text>';
  });
  return s + '<text x="' + L + '" y="12" font-size="10.5" fill="var(--faint)">dBm</text></svg>';
}
function wifiChannels(){
  const d = wf.data, nets = d.networks, by = b => nets.filter(n => n.band === b);
  const head = (b, n, txt) => '<div class="wf-chart-h"><b>' + WF_BAND[b] + '</b><span>' + n + ' access point' + (txt ? ' · ' + txt : '') + '</span></div>';
  const t24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  const t5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
  const t6 = []; for (let c = 1; c <= 93; c += 4) t6.push(c);
  const dfs = (x, T, fl) => [[5250, 5330, 'DFS'], [5490, 5730, 'DFS (radar)']].map(([a, b, t]) =>
    '<rect x="' + x(a) + '" y="' + (T - 14) + '" width="' + (x(b) - x(a)) + '" height="' + (fl - T + 14) + '" fill="var(--warn)" fill-opacity=".05"/>'
    + '<text x="' + x((a + b) / 2) + '" y="' + (T - 2) + '" text-anchor="middle" font-size="10.5" fill="var(--warn)" font-family="Instrument Sans">' + t + '</text>').join('');
  const eu6 = (x, T) => '<text x="' + x(6185) + '" y="' + (T - 2) + '" text-anchor="middle" font-size="10.5" fill="var(--faint)" font-family="Instrument Sans">' + __('In Europa: 5945–6425 MHz, canali 1–93') + '</text>';
  if (!nets.length){ $('wf-chan').innerHTML = '<div class="empty">' + __('Nessuna rete da mostrare.') + '</div>'; return; }
  let html = '<div class="wf-chart">' + head('2.4', by('2.4').length, d.best24 ? __('canale più libero tra 1, 6 e 11: <strong class="c-ok">{c}</strong>', {c: d.best24}) : '')
    + wifiChart(by('2.4'), 2397, 2487, t24, c => 2407 + 5 * c) + '</div>';
  html += '<div class="wf-chart">' + head('5', by('5').length, d.best5 ? __('gruppo da 80 MHz più libero: <strong class="c-ok">{l}</strong>', {l: d.best5.label}) + (d.best5.dfs ? ' (DFS)' : '') : '')
    + wifiChart(by('5'), 5165, 5840, t5, c => 5000 + 5 * c, dfs) + '</div>';
  if (d.six_seen) html += '<div class="wf-chart">' + head('6', by('6').length) + wifiChart(by('6'), 5940, 6430, t6, c => 5950 + 5 * c, eu6) + '</div>';
  const me = d.connection ? d.connection.ssid : '';
  html += '<div class="wf-legend">' + (me ? '<span><i style="background:var(--info)"></i>' + esc(me) + ' ' + __('(rete di questo PC, ● = AP collegato)') + '</span>' : '')
    + '<span><i style="background:var(--wf-c1)"></i>' + __('altre reti, un colore per rete') + '</span><span>' + __('Altezza = segnale ricevuto · larghezza = banda occupata (20–320 MHz)') + '</span></div>'
    + '<p class="note">' + (d.six_seen ? '' : __('6 GHz: nessuna rete rilevata. Le reti a 6 GHz si vedono solo con una scheda Wi-Fi 6E o 7. '))
    + __('I consigli considerano i canali 1, 6 e 11 e i gruppi da 80 MHz ammessi in Europa all\'interno (36–64 e 100–128); i canali DFS richiedono un AP che li supporti. Le reti nascoste sono incluse: occupano il canale come le altre.') + '</p>';
  $('wf-chan').innerHTML = html;
}

/* ── signal monitor ── */
const WFM_WINDOW = 180000; // last 3 minutes in the chart
async function wifiMonitor(form){
  const m = wf.mon;
  m.samples = []; m.events = []; m.roams = 0; m.start = Date.now(); m.run = true;
  const live = $('wfm-live');
  live.className = 'wf-live'; live.textContent = __('In corso');
  $('wfm-body').innerHTML = '<p class="summary"><span class="spinner"></span>' + __('Avvio del monitor…') + '</p>';
  const idle = busy(form);
  const ch = new TAURI.Channel();
  ch.onmessage = msg => {
    if (msg.sample) m.samples.push(msg.sample);
    if (msg.event){ m.events.push(msg.event); if (msg.event.kind === 'roam') m.roams++; }
    if (!m.raf) m.raf = requestAnimationFrame(() => { m.raf = 0; wifiMonRender(); });
  };
  try {
    const end = await TAURI.invoke('wifi_monitor', {req: {adapter: $('wifi-if').value || '', interval_ms: $('wfm-int').value}, onEvent: ch});
    live.className = 'wf-live done';
    live.textContent = (end.stopped ? __('Fermato') : __('Concluso')) + ' · ' + wifiDur(Date.now() - m.start);
    wifiMonRender();
  } catch(e) {
    live.className = 'wf-live hidden';
    $('wfm-body').innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>';
  } finally {
    m.run = false;
    idle();
  }
}
const wifiDur = ms => { const s = Math.round(ms / 1000); return (s >= 60 ? Math.floor(s / 60) + ' min ' : '') + String(s % 60).padStart(s >= 60 ? 2 : 1, '0') + ' s'; };
const wifiClock = t => new Date(wf.mon.start + t).toLocaleTimeString(LOC);
setInterval(() => { if (wf.mon.run) $('wfm-live').textContent = __('In corso') + ' · ' + wifiDur(Date.now() - wf.mon.start); }, 1000);

function wifiMonRender(){
  const m = wf.mon, S = m.samples, ok = S.filter(s => s.rssi !== null);
  if (!S.length) return;
  const v = ok.map(s => s.rssi), last = S[S.length - 1];
  const avg = v.length ? Math.round(v.reduce((a, b) => a + b, 0) / v.length) : null;
  const kvi = (k, val, cls) => '<div class="kv-item' + (cls ? ' ' + cls : '') + '"><div class="kv-k">' + k + '</div><div class="kv-v">' + val + '</div></div>';
  const db = d => d === null || d === undefined ? '—' : d + ' dBm';
  let html = '<div class="kv">'
    + kvi(__('Attuale'), db(last.rssi), 'big ' + (last.rssi === null ? 'err' : wfLevel(last.rssi)))
    + kvi(__('Minimo'), db(v.length ? Math.min(...v) : null), v.length ? wfLevel(Math.min(...v)) : '')
    + kvi(__('Massimo'), db(v.length ? Math.max(...v) : null))
    + kvi(LANG === 'en' ? 'Average' : 'Media', db(avg)) // not __(): the key "Media" means "Medium" elsewhere
    + kvi('AP' + (last.channel ? __(' · canale {c}', {c: last.channel}) : ''), esc(last.bssid ? '…' + last.bssid.slice(-5) : '—'))
    + kvi('Roaming', m.roams) + '</div>';
  // chart: last 3 minutes
  const W = 900, H = 250, L = 40, R = 12, T = 14, B = 30;
  const tEnd = Math.max(last.t, 1), t0 = Math.max(0, tEnd - WFM_WINDOW), span = Math.max(tEnd - t0, 10000);
  const x = t => L + (t - (tEnd - span)) / span * (W - L - R), y = d => T + (-35 - Math.max(-95, Math.min(-35, d))) / 60 * (H - T - B);
  let s = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img">'
    + '<rect x="' + L + '" y="' + y(-35) + '" width="' + (W - L - R) + '" height="' + (y(-67) - y(-35)) + '" fill="var(--ok)" fill-opacity=".06"/>'
    + '<rect x="' + L + '" y="' + y(-67) + '" width="' + (W - L - R) + '" height="' + (y(-75) - y(-67)) + '" fill="var(--warn)" fill-opacity=".08"/>'
    + '<rect x="' + L + '" y="' + y(-75) + '" width="' + (W - L - R) + '" height="' + (y(-95) - y(-75)) + '" fill="var(--err)" fill-opacity=".07"/>';
  for (let d = -40; d >= -90; d -= 10)
    s += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + y(d) + '" y2="' + y(d) + '" stroke="var(--line)" stroke-dasharray="2 4"/>'
      + '<text x="' + (L - 6) + '" y="' + (y(d) + 4) + '" text-anchor="end" font-size="10.5" fill="var(--faint)">' + d + '</text>';
  s += '<text x="' + (W - R - 4) + '" y="' + (y(-67) - 5) + '" text-anchor="end" font-size="10.5" fill="var(--ok)">' + __('−67 dBm: buono per voce e video') + '</text>'
    + '<text x="' + (W - R - 4) + '" y="' + (y(-75) - 5) + '" text-anchor="end" font-size="10.5" fill="var(--warn)">' + __('−75 dBm: limite per i dati') + '</text>';
  for (let k = 0; k <= 6; k++){
    const t = tEnd - span + span * k / 6, rel = Math.round((t - tEnd) / 1000);
    const lbl = k === 6 ? __('adesso') : '−' + Math.floor(-rel / 60) + ':' + String(-rel % 60).padStart(2, '0');
    s += '<text x="' + (L + k / 6 * (W - L - R)) + '" y="' + (H - 10) + '" text-anchor="' + (k === 0 ? 'start' : k === 6 ? 'end' : 'middle') + '" font-size="10.5" fill="var(--muted)">' + lbl + '</text>';
  }
  m.events.filter(e => e.kind === 'roam' || e.kind === 'disconnect').filter(e => e.t >= tEnd - span).forEach(e => {
    const X = x(e.t), col = e.kind === 'roam' ? 'var(--brand)' : 'var(--err)';
    s += '<line x1="' + X + '" x2="' + X + '" y1="' + T + '" y2="' + (H - B) + '" stroke="' + col + '" stroke-dasharray="4 3" stroke-width="1.4"/>';
    if (e.kind === 'roam'){
      // the event text comes from the backend (Italian or English)
      const ch = (e.text.match(/(?:canale|channel) (\d+), -?\d+ dBm$/) || [])[1];
      const to = (e.text.match(/ (?:a|to) ([0-9a-f:]{17})/) || [])[1];
      const lbl = 'Roaming → …' + (to ? to.slice(-5) : '') + (ch ? __(' · canale {c}', {c: ch}) : '');
      const right = X > W - 220;
      s += '<text x="' + (right ? X - 6 : X + 6) + '" y="' + (T + 12) + '" text-anchor="' + (right ? 'end' : 'start') + '" font-size="11" font-weight="600" fill="var(--brand)" font-family="Instrument Sans">' + esc(lbl) + '</text>';
    }
  });
  // broken line where the connection is missing
  let path = '', pen = false;
  S.filter(p => p.t >= tEnd - span).forEach(p => {
    if (p.rssi === null){ pen = false; return; }
    path += (pen ? ' L' : ' M') + x(p.t).toFixed(1) + ' ' + y(p.rssi).toFixed(1); pen = true;
  });
  s += '<path d="' + path + '" fill="none" stroke="var(--info)" stroke-width="2" stroke-linejoin="round"/>';
  if (last.rssi !== null) s += '<circle cx="' + x(last.t) + '" cy="' + y(last.rssi) + '" r="4" fill="var(--info)" stroke="var(--sunken)" stroke-width="2"/>';
  s += '</svg>';
  html += '<div class="wf-chart">' + s + '</div>';
  const ev = [...m.events].reverse().slice(0, 50);
  const cls = {weak:'c-err', fair:'c-warn', disconnect:'c-err', good:'c-ok', connect:'c-ok'};
  if (ev.length) html += '<div class="panel wf-events"><table class="tbl"><thead><tr><th>' + __('Ora') + '</th><th>' + __('Evento') + '</th></tr></thead><tbody>'
    + ev.map(e => '<tr><td class="mono nw">' + wifiClock(e.t) + '</td><td><span class="' + (cls[e.kind] || '') + '">' + esc(e.text) + '</span>'
      + (e.gap_ms !== null && e.gap_ms !== undefined ? __(' · interruzione {n} ms', {n: e.gap_ms}) : '') + '</td></tr>').join('') + '</tbody></table></div>';
  html += '<p class="note">' + __('Cammina con il portatile nelle zone da verificare: il grafico mostra dove il segnale scende e quando la scheda cambia access point. '
    + 'L\'interruzione del roaming è quella segnalata da Windows.') + '</p>';
  $('wfm-body').innerHTML = html;
}
$('wfm-csv').addEventListener('click', e => {
  const head = __('ora;rssi_dbm;qualita_pct;bssid;canale;rx_mbps;tx_mbps');
  const lines = wf.mon.samples.map(s => [wifiClock(s.t), s.rssi, s.quality, s.bssid, s.channel, s.rx_mbps, s.tx_mbps].map(v => v ?? '').join(';'));
  navigator.clipboard?.writeText([head, ...lines].join('\n')).then(() => { e.target.textContent = __('Copiato'); setTimeout(() => e.target.textContent = __('Copia CSV'), 1400); });
});

[['wifi-auto', false], ['wifi-group', false]].forEach(([id, d]) => {
  $(id).checked = store.get(id, d);
  $(id).addEventListener('change', () => { store.set(id, $(id).checked); if (id === 'wifi-group' && wf.data) wifiNets(); });
});
$('wifi-if').addEventListener('change', () => wifiScan(true));
// "Repeat every 10 s": only with the Wi-Fi view open and the window visible
setInterval(() => {
  if ($('wifi-auto').checked && $('view-wifi').classList.contains('active') && document.visibilityState === 'visible' && wf.data && !wf.busy) wifiScan(true);
}, 10000);

/* ── SNMP: device with tabs, tables, built-in names, profiles, live counters ── */
const sn = {mode: store.get('snmp-what', 'dev'), names: null, sug: [], sel: -1};
const SN_MAX_ROWS = 300;
const SN_KIND = {group:__('gruppo'), scalar:__('valore'), table:__('tabella'), column:__('colonna')};
const SN_STATE = {up:['ok', __('attiva')], down:['neutral', __('scollegata')], off:['neutral', __('disattivata')]};
const SN_FDB = {dinamico:__('dinamico'), statico:__('statico'), apparato:__('apparato'), altro:__('altro'), arp:__('solo ARP')};
const snNum = (v, d) => Number(v).toLocaleString(LOC, {maximumFractionDigits: d});
const snSpeed = b => !b ? '—' : b >= 1e9 ? snNum(b / 1e9, 1) + ' Gb/s' : b >= 1e6 ? snNum(b / 1e6, 0) + ' Mb/s' : snNum(b / 1e3, 0) + ' kb/s';
const snRate = b => b === null || b === undefined ? '—' : b >= 1e9 ? snNum(b / 1e9, 2) + ' Gb/s' : b >= 1e6 ? snNum(b / 1e6, 1) + ' Mb/s' : b >= 1e3 ? snNum(b / 1e3, 1) + ' kb/s' : snNum(b, 0) + ' b/s';
const snAgo = s => {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  const many = (n, one, more) => n + ' ' + (n === 1 ? __(one) : __(more));
  return d ? many(d, 'giorno', 'giorni') + (h ? ', ' + many(h, 'ora', 'ore') : '') : h ? many(h, 'ora', 'ore') + (m ? ', ' + many(m, 'minuto', 'minuti') : '') : many(Math.max(m, 1), 'minuto', 'minuti');
};
const snHms = s => Math.floor(s / 3600) + ':' + String(Math.floor(s % 3600 / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
const snClock = ms => { const s = Math.round(ms / 1000); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
const snCsv = rows => rows.map(r => r.map(c => { const s = String(c ?? ''); return /[;"\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(';')).join('\r\n');
const snChip = (attr, key, label, on) => '<button type="button" class="chip' + (on ? ' on' : '') + '" ' + attr + '="' + key + '">' + label + '</button>';

/* common request: host, port and credentials of the open tab */
function snmpReq(){
  const b = {host: val('snmp-host'), port: val('snmp-port')};
  if (tabState.snmp === 'v3') Object.assign(b, {version:'3', user:val('snmp-user'), sec_level:$('snmp-seclevel').value,
    auth_proto:$('snmp-authproto').value, auth_pass:$('snmp-authpass').value, priv_proto:$('snmp-privproto').value, priv_pass:$('snmp-privpass').value});
  else Object.assign(b, {version:$('snmp-ver').value, community:$('snmp-comm').value});
  return b;
}

/* "Device / OID and tables" switch: a single submit button, which changes its name */
function snmpWhat(mode){
  sn.mode = mode; store.set('snmp-what', mode);
  document.querySelectorAll('#snmp-what button').forEach(b => b.setAttribute('aria-selected', b.dataset.snmode === mode));
  document.querySelectorAll('#view-snmp [data-snpane]').forEach(p => p.classList.toggle('hidden', p.dataset.snpane !== mode));
  const go = $('snmp-go'), label = mode === 'dev' ? __('Analizza') : __('Interroga');
  if (go.dataset.label) go.dataset.label = label;
  if (!go.closest('form').dataset.running) go.textContent = label;
  if (mode === 'dev'){ snSugHide(); $('snmp-tree').classList.add('hidden'); }
}
document.querySelectorAll('#snmp-what button').forEach(b => b.addEventListener('click', () => snmpWhat(b.dataset.snmode)));
snmpWhat(sn.mode === 'oid' ? 'oid' : 'dev');
['snmp-s-sys', 'snmp-s-if', 'snmp-s-nb', 'snmp-s-fdb', 'snmp-s-res', 'snmp-s-prn'].forEach(id => {
  $(id).checked = store.get(id, true);
  $(id).addEventListener('change', () => store.set(id, $(id).checked));
});

/* ── profiles: host, port, version, user and protocols. Never community or password ── */
const SN_PROF_MAX = 12;
function snProfiles(){
  const box = $('snmp-profiles'), list = store.get('snmp-profiles', []);
  box.querySelectorAll('.saved').forEach(x => x.remove());
  list.forEach((p, i) => {
    const s = document.createElement('span'); s.className = 'saved';
    s.innerHTML = '<button type="button" class="chip" data-snprof="' + i + '">' + esc(p.label) + '</button><button type="button" class="chip-x" data-snprofx="' + i + '" aria-label="' + __('Elimina il profilo') + '">×</button>';
    box.insertBefore(s, $('snmp-prof-save'));
  });
}
function snProfileSave(){
  const host = val('snmp-host');
  if (!host) return $('snmp-host').focus();
  const v3 = tabState.snmp === 'v3';
  const p = {host, port: val('snmp-port'), v3, ver: $('snmp-ver').value, user: val('snmp-user'), sec_level: $('snmp-seclevel').value,
    auth_proto: $('snmp-authproto').value, priv_proto: $('snmp-privproto').value};
  p.label = host + ' · ' + (v3 ? 'v3' + (p.user ? ' ' + p.user : '') : 'v' + p.ver);
  const list = store.get('snmp-profiles', []).filter(x => x.label !== p.label);
  list.push(p);
  store.set('snmp-profiles', list.slice(-SN_PROF_MAX));
  snProfiles();
}
function snProfileLoad(p){
  document.querySelector('[data-tabs="snmp"] [data-tab="' + (p.v3 ? 'v3' : 'v2c') + '"]').click();
  $('snmp-host').value = p.host; $('snmp-port').value = p.port || '';
  $('snmp-ver').value = p.ver || '2c'; $('snmp-user').value = p.user || '';
  $('snmp-seclevel').value = p.sec_level || 'authPriv'; $('snmp-authproto').value = p.auth_proto || 'SHA'; $('snmp-privproto').value = p.priv_proto || 'AES';
  // secrets are not in the profile: fields cleared, the first one to fill in gets the focus
  ['snmp-comm', 'snmp-authpass', 'snmp-privpass'].forEach(id => { $(id).value = ''; });
  snmpSecLevel();
  const first = !p.v3 ? 'snmp-comm' : p.sec_level === 'noAuthNoPriv' ? 'snmp-host' : 'snmp-authpass';
  $(first).focus();
}
$('snmp-profiles').addEventListener('click', e => {
  const list = store.get('snmp-profiles', []);
  const x = e.target.closest('[data-snprofx]'), p = e.target.closest('[data-snprof]');
  if (x){ list.splice(+x.dataset.snprofx, 1); store.set('snmp-profiles', list); snProfiles(); }
  else if (p && list[+p.dataset.snprof]) snProfileLoad(list[+p.dataset.snprof]);
  else if (e.target.closest('#snmp-prof-save')) snProfileSave();
});
snProfiles();

/* ── built-in names: suggestions while typing and the tree behind "Browse names" ── */
async function snNames(){
  if (!sn.names){
    try {
      const list = await TAURI.invoke('snmp_names');
      sn.names = list.map(o => Object.assign({arcs: o.oid.split('.').map(Number)}, o));
      // parent = the object with the longest OID that is a prefix
      sn.names.forEach(o => {
        o.parent = null;
        sn.names.forEach(p => { if (p !== o && p.arcs.length < o.arcs.length && p.arcs.every((a, i) => a === o.arcs[i]) && (!o.parent || p.arcs.length > o.parent.arcs.length)) o.parent = p; });
        o.depth = 0;
      });
      sn.names.forEach(o => { for (let p = o.parent; p; p = p.parent) o.depth++; });
      sn.open = new Set(sn.names.filter(o => !o.parent).map(o => o.oid));
    } catch(e){ sn.names = []; }
  }
  return sn.names;
}
function snPick(o){
  $('snmp-oid').value = o.kind === 'scalar' ? o.name + '.0' : o.name;
  $('snmp-mode').value = o.kind === 'scalar' ? 'get' : o.kind === 'table' ? 'table' : 'walk';
  snSugHide(); $('snmp-oid').focus();
}
const snNode = (o, cls, name, depth, tw) => '<button type="button" class="sn-node ' + cls + '" style="--l:' + depth + '" data-snoid="' + esc(o.oid) + '"><span class="nm">'
  + (tw === undefined ? '' : '<i>' + tw + '</i>') + name + '<span class="ds">' + esc(o.descr) + '</span></span><span class="sn-mib">' + esc(o.mib) + '</span><span class="oid">' + esc(o.oid)
  + (o.kind === 'group' ? '' : ' ' + chkPill(o.kind === 'table' ? 'info' : 'neutral', SN_KIND[o.kind])) + '</span></button>';
function snSugHide(){ sn.sug = []; sn.sel = -1; $('snmp-sug').classList.add('hidden'); }
async function snSuggest(){
  const q = val('snmp-oid').replace(/^.*::/, '').split('.')[0].toLowerCase();
  // a numeric OID or an already complete name needs no suggestions
  if (q.length < 2 || /^\d/.test(q)) return snSugHide();
  const names = await snNames();
  const hit = names.filter(o => o.name.toLowerCase().includes(q) && o.name.toLowerCase() !== q);
  hit.sort((a, b) => (a.name.toLowerCase().indexOf(q) - b.name.toLowerCase().indexOf(q)) || (a.kind === 'table' ? -1 : 0) - (b.kind === 'table' ? -1 : 0) || a.name.length - b.name.length);
  sn.sug = hit.slice(0, 8); sn.sel = -1;
  if (!sn.sug.length) return snSugHide();
  const mark = n => { const i = n.toLowerCase().indexOf(q); return esc(n.slice(0, i)) + '<mark>' + esc(n.slice(i, i + q.length)) + '</mark>' + esc(n.slice(i + q.length)); };
  $('snmp-sug').innerHTML = sn.sug.map(o => snNode(o, '', mark(o.name), 0)).join('')
    + (hit.length > sn.sug.length ? '<div class="sn-more">' + __('altri {n} nomi contengono "{q}": continua a scrivere o apri "Sfoglia nomi"', {n: hit.length - sn.sug.length, q: esc(q)}) + '</div>' : '');
  $('snmp-sug').classList.remove('hidden');
}
$('snmp-oid').addEventListener('input', snSuggest);
$('snmp-oid').addEventListener('keydown', e => {
  if (!sn.sug.length) return;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp'){
    e.preventDefault();
    sn.sel = (sn.sel + (e.key === 'ArrowDown' ? 1 : -1) + sn.sug.length + (sn.sel < 0 && e.key === 'ArrowUp' ? 1 : 0)) % sn.sug.length;
    $('snmp-sug').querySelectorAll('.sn-node').forEach((n, i) => n.classList.toggle('sel', i === sn.sel));
  } else if (e.key === 'Enter' && sn.sel >= 0){ e.preventDefault(); snPick(sn.sug[sn.sel]); }
  else if (e.key === 'Escape') snSugHide();
});
$('snmp-sug').addEventListener('click', e => {
  const n = e.target.closest('[data-snoid]'); if (!n) return;
  snPick(sn.names.find(o => o.oid === n.dataset.snoid));
});
function snTree(){
  const q = val('snmp-tree-q').toLowerCase(), names = sn.names || [];
  let shown;
  if (q){
    // with the filter: the names found and the branches containing them, all open
    const keep = new Set();
    names.filter(o => o.name.toLowerCase().includes(q) || o.descr.toLowerCase().includes(q)).forEach(o => { for (let p = o; p; p = p.parent) keep.add(p); });
    shown = names.filter(o => keep.has(o));
  } else shown = names.filter(o => { for (let p = o.parent; p; p = p.parent) if (!sn.open.has(p.oid)) return false; return true; });
  const kids = new Set(names.map(o => o.parent).filter(Boolean));
  $('snmp-tree-list').innerHTML = shown.map(o => snNode(o, o.kind === 'group' ? 'grp' : '', esc(o.name), o.depth, !kids.has(o) ? '' : q || sn.open.has(o.oid) ? '▾' : '▸')).join('')
    || '<div class="sn-more">' + __('Nessun nome contiene "{q}".', {q: esc(q)}) + '</div>';
  $('snmp-tree-n').textContent = __('{n} nomi di {m} MIB standard', {n: names.length, m: new Set(names.map(o => o.mib)).size});
}
$('snmp-browse').addEventListener('click', async () => {
  const t = $('snmp-tree');
  if (!t.classList.toggle('hidden')){ snSugHide(); await snNames(); snTree(); }
});
$('snmp-tree-q').addEventListener('input', snTree);
$('snmp-tree-list').addEventListener('click', e => {
  const n = e.target.closest('[data-snoid]'); if (!n) return;
  const o = sn.names.find(x => x.oid === n.dataset.snoid);
  // branches open and close; values, tables and columns go into the OID field
  if (o.kind === 'group' || (o.kind === 'table' && e.target.closest('i'))){
    if (sn.open.has(o.oid)) sn.open.delete(o.oid); else sn.open.add(o.oid);
    return snTree();
  }
  snPick(o);
});

/* ── result of GET, WALK and table ── */
function snSecLine(checks){
  const bad = (checks || []).filter(c => c.status === 'err' || c.status === 'warn');
  return bad.length ? '<p class="sn-sec">' + bad.map(c => '<span title="' + esc(c.detail) + '">' + chkPill(c.status) + esc(c.name) + '</span>').join('') + '</p>' : '';
}
const snSecText = checks => (checks || []).filter(c => c.status === 'err' || c.status === 'warn').map(c => '[' + CHK_ICON[c.status] + '] ' + c.area + ' · ' + c.name + ': ' + c.detail);
function snTableRows(t, q){
  const num = t.columns.map((c, i) => t.rows.every(r => /^-?\d*$/.test(r.cells[i])) && t.rows.some(r => r.cells[i] !== ''));
  q = (q || '').toLowerCase();
  const rows = q ? t.rows.filter(r => (r.index + ' ' + r.cells.join(' ')).toLowerCase().includes(q)) : t.rows;
  return rows.slice(0, SN_MAX_ROWS).map(r => '<tr><td class="num l">' + esc(r.index) + '</td>' + r.cells.map((c, i) => '<td class="' + (num[i] ? 'num' : '') + '">' + esc(c) + '</td>').join('') + '</tr>').join('')
    + (rows.length > SN_MAX_ROWS ? '<tr><td colspan="' + (t.columns.length + 1) + '" class="dim sn-rest">' + __('… altre {n} righe: usa il filtro, oppure "Copia CSV" per averle tutte', {n: rows.length - SN_MAX_ROWS}) + '</td></tr>' : '')
    || '<tr><td colspan="' + (t.columns.length + 1) + '" class="dim sn-rest">' + __('Nessuna riga contiene "{q}".', {q: esc(q)}) + '</td></tr>';
}
function snmpOidRender(d){
  const sec = snSecLine(d.checks), secText = snSecText(d.checks);
  const cut = d.truncated ? '<p class="note">' + __('Lettura fermata al limite di {n} valori: la tabella non è completa.', {n: d.count}) + '</p>' : d.stopped ? '<p class="note">' + __('Lettura fermata dopo {n} valori.', {n: d.count}) + '</p>' : '';
  if (d.mode === 'table' && d.table){
    const t = d.table;
    const num = t.columns.map((c, i) => t.rows.every(r => /^-?\d*$/.test(r.cells[i])) && t.rows.some(r => r.cells[i] !== ''));
    const html = '<div class="sn-tools"><p class="summary"><strong>' + t.rows.length + '</strong> ' + (t.rows.length === 1 ? __('riga') : __('righe')) + ' · ' + __('{n} colonne', {n: t.columns.length}) + ' · <span class="mono">' + esc(t.name) + '</span></p>'
      + '<div class="r"><label>' + __('Filtra') + ' <input type="text" class="sn-find" data-sntf spellcheck="false" autocomplete="off"></label><button type="button" class="chip" data-sncsv="table">' + __('Copia CSV') + '</button></div></div>'
      + '<div class="sn-wrap"><table class="tbl sn"><thead><tr><th>' + __('Indice') + '</th>' + t.columns.map((c, i) => '<th class="' + (num[i] ? 'num' : '') + '" title="' + esc(c.oid) + '">' + esc(c.name) + '</th>').join('') + '</tr></thead><tbody>'
      + snTableRows(t, '') + '</tbody></table></div>' + cut
      + '<p class="note">' + __('Una riga per indice, una colonna per ogni oggetto della tabella; le colonne senza un nome integrato hanno l\'OID numerico. "Copia" e "Copia CSV" prendono tutte le righe.') + '</p>' + sec;
    const text = [t.name + ' · ' + d.host, '', [__('Indice'), ...t.columns.map(c => c.name)].join('\t'), ...t.rows.map(r => [r.index, ...r.cells].join('\t')), ...(secText.length ? ['', ...secText] : [])].join('\n');
    return {status: d.stopped ? 'stop' : 'ok', html, text, data: {table: t, csv: d.csv}};
  }
  if (d.mode === 'table'){
    return {status: d.stopped ? 'stop' : 'warn', html: '<p class="summary">' + (d.count ? __('<strong>{n}</strong> valori letti, ma non hanno la forma di una tabella (colonna e indice).', {n: d.count}) : __('Nessun valore sotto questo OID: l\'apparato non ha questa tabella, oppure la vista dell\'utente non la comprende.')) + '</p>'
      + (d.count ? pre(d.output) : '') + sec};
  }
  const bad = /Timeout|No Such|No Response|Unknown user|Authentication failure|ERROR/i.test(d.output);
  return {status: d.stopped ? 'stop' : bad ? 'err' : 'ok',
    html: (d.mode === 'walk' && !bad ? '<p class="summary">' + __('<strong>{n}</strong> valori letti', {n: d.count}) + '</p>' : '') + pre(d.output) + sec,
    text: [d.output, ...(secText.length ? ['', ...secText] : [])].join('\n')};
}

/* ── whole device ── */
async function snmpDevice(form, req){
  const body = Object.assign({system: $('snmp-s-sys').checked, interfaces: $('snmp-s-if').checked, neighbors: $('snmp-s-nb').checked, fdb: $('snmp-s-fdb').checked, resources: $('snmp-s-res').checked, printer: $('snmp-s-prn').checked}, req);
  const strip = newStrip('snmp', __('SNMP · Dispositivo'), req.host);
  const el = strip.querySelector('.strip-body');
  const idle = busy(form);
  const ch = new TAURI.Channel();
  ch.onmessage = m => { if (m.step) el.innerHTML = '<span class="spinner"></span>' + __('Lettura: {name} ({done} di {total})…', {name: esc(m.step.name), done: m.step.done + 1, total: m.step.total}); };
  try {
    const d = await TAURI.invoke('snmp_device', {req: body, onEvent: ch});
    // the request stays in memory with the result: the live counters need it
    strip._data = {d, req, ifFilter: 'all', fdbFilter: 'all', fdbQ: '', mon: null};
    snDraw(strip);
  } catch(e) {
    setState(strip, 'err');
    el.innerHTML = '<div class="msg-err">' + esc(tauriError(e)) + '</div>';
  } finally {
    idle();
  }
}
const snErr = (now, total) => !total && !now ? '0' : (now ? '<span class="c-warn">+' + snNum(now, 0) + '</span> ' : '') + '<span class="' + (now ? 'c-dim' : 'c-warn') + '">' + (now ? '(' + snNum(total, 0) + ')' : snNum(total, 0)) + '</span>';
/* The tab has three parts: the bar (filters and buttons, which stay put), the monitor state and the table.
   On each sample only the last two are redrawn, so a click on the bar is never lost. */
const snIfState = (st, i) => { const mon = st.mon, s = mon && mon.samples.get(i.index); return (s || i).state; };
function snIfLive(st){
  const mon = st.mon;
  return mon && mon.running ? '<span class="sn-live"><i></i>' + __('Dal vivo · ogni {n} s', {n: mon.interval}) + (mon.n ? ' · ' + snClock(mon.t) : __(' · prima lettura…')) + '</span>'
    : mon && mon.n ? '<span class="sn-live off">' + __('Fermato dopo {t}', {t: snClock(mon.t)}) + '</span>' : '';
}
function snIfSummary(st){
  const list = st.d.interfaces.list, withErr = list.filter(i => i.in_errors + i.out_errors > 0).length;
  return __('<strong>{n}</strong> attive su {m}', {n: list.filter(i => snIfState(st, i) === 'up').length, m: list.length}) + (withErr ? __(' · {n} con errori', {n: withErr}) : '');
}
function snIfBody(st){
  const list = st.d.interfaces.list, mon = st.mon, live = mon && mon.samples.size;
  const errs = i => i.in_errors + i.out_errors;
  const shown = list.filter(i => st.ifFilter === 'up' ? snIfState(st, i) === 'up' : st.ifFilter === 'err' ? errs(i) + i.in_discards + i.out_discards > 0 : true);
  const bar = (v, i) => v === null || v === undefined || !i.speed_bps ? '' : '<span class="sn-bar"><i class="' + (v / i.speed_bps > .7 ? 'hot' : '') + '" style="width:' + Math.min(100, Math.max(1, Math.round(v / i.speed_bps * 100))) + '%"></i></span>';
  const rowsHtml = shown.map(i => {
    const s = live ? mon.samples.get(i.index) : null, state = snIfState(st, i), stt = SN_STATE[state];
    const e = s ? snErr(s.in_errors + s.out_errors, errs(i) + s.in_errors + s.out_errors) : snErr(0, errs(i));
    const dsc = s ? snErr(s.in_discards + s.out_discards, i.in_discards + i.out_discards + s.in_discards + s.out_discards) : snErr(0, i.in_discards + i.out_discards);
    return '<tr class="' + (state === 'up' ? '' : 'off') + '" data-if="' + i.index + '"><td><span class="sn-port">' + esc(i.name) + '</span>' + (i.alias ? '<span class="sn-sub">' + esc(i.alias) + '</span>' : '') + '</td><td>' + chkPill(stt[0], stt[1])
      + '</td><td class="num">' + snSpeed(i.speed_bps) + '</td><td class="num"><span class="sn-rate">' + (s ? snRate(s.in_bps) + bar(s.in_bps, i) : '—') + '</span></td><td class="num"><span class="sn-rate">' + (s ? snRate(s.out_bps) + bar(s.out_bps, i) : '—')
      + '</span></td><td class="num">' + e + '</td><td class="num">' + dsc + '</td></tr>';
  }).join('');
  return (mon && mon.error ? '<p class="note sn-monerr">' + __('Monitor interrotto: {e}', {e: esc(mon.error)}) + '</p>' : '')
    + (list.length ? '<div class="sn-wrap"><table class="tbl sn"><thead><tr><th>' + __('Porta') + '</th><th>' + __('Stato') + '</th><th class="num">' + __('Velocità') + '</th><th class="num">' + __('Ingresso') + '</th><th class="num">' + __('Uscita') + '</th><th class="num">' + __('Errori') + '</th><th class="num">' + __('Scarti') + '</th></tr></thead><tbody>'
      + (rowsHtml || '<tr><td colspan="7" class="dim sn-rest">' + __('Nessuna interfaccia con questo filtro.') + '</td></tr>') + '</tbody></table></div>' : '<p class="note hx-top">' + __('L\'agente non espone la tabella delle interfacce.') + '</p>')
    + '<p class="note">' + __('Ingresso e uscita compaiono con "Contatori dal vivo": velocità dalla differenza fra due letture dei contatori ') + (mon && mon.hc === false ? __('a 32 bit (ifInOctets, ifOutOctets)') : __('a 64 bit (ifHCInOctets, ifHCOutOctets)'))
    + __('. Con il monitor acceso errori e scarti sono quelli nuovi, fra parentesi il totale dall\'avvio dell\'apparato.') + '</p>';
}
function snIfPane(st){
  const on = st.mon && st.mon.running;
  return '<div class="sn-tools"><p class="summary" data-snifsum>' + snIfSummary(st) + '</p><div class="r"><span data-sniflive>' + snIfLive(st) + '</span>'
    + '<span class="wf-chips">' + snChip('data-snif', 'all', __('Tutte'), st.ifFilter === 'all') + snChip('data-snif', 'up', __('Attive'), st.ifFilter === 'up') + snChip('data-snif', 'err', __('Con errori'), st.ifFilter === 'err') + '</span>'
    + '<button type="button" class="sn-btn' + (on ? '' : ' go') + '" data-snmon>' + (on ? __('Ferma') : __('Contatori dal vivo')) + '</button>'
    + '<button type="button" class="chip" data-sncsv="if">' + __('Copia CSV') + '</button></div></div><div data-snifbody>' + snIfBody(st) + '</div>';
}
/* new sample: table, monitor state and summary; the bar is left alone */
function snIfTick(strip){
  const st = strip._data, pane = strip.querySelector('[data-rpane="if"]');
  if (!pane) return;
  pane.querySelector('[data-snifbody]').innerHTML = snIfBody(st);
  pane.querySelector('[data-sniflive]').innerHTML = snIfLive(st);
  pane.querySelector('[data-snifsum]').innerHTML = snIfSummary(st);
}
function snNbPane(d){
  const nb = d.neighbors;
  if (!nb.list.length) return '<p class="note hx-top">' + (nb.supported ? __('LLDP è attivo, ma nessun vicino si annuncia sulle porte.') : __('L\'apparato non espone la LLDP-MIB: LLDP è spento, oppure usa solo un protocollo di scoperta proprietario.')) + '</p>';
  return '<div class="sn-tools"><p class="summary"><strong>' + nb.list.length + '</strong> ' + (nb.list.length === 1 ? __('vicino annunciato') : __('vicini annunciati')) + ' ' + __('con LLDP') + '</p><div class="r"><button type="button" class="chip" data-sncsv="nb">' + __('Copia CSV') + '</button></div></div>'
    + '<div class="hx-path">' + nb.list.map(n => {
        const pills = n.caps.map(c => chkPill('info', c));
        pills.push(n.addr ? chkPill('neutral', n.addr) : chkPill('warn', __('senza IP di gestione')));
        if (n.chassis && n.chassis !== n.name) pills.push(chkPill('neutral', n.chassis));
        return '<div class="hx-hop sn-nb"><div class="hx-n">' + esc(n.local_port) + '</div><div><div class="u"><b>' + esc(n.name || '—') + '</b>' + (n.port ? '<span class="arrow">' + __('porta') + '</span>' + esc(n.port) : '')
          + (n.port_descr && n.port_descr !== n.port ? ' <span class="c-dim">· ' + esc(n.port_descr) + '</span>' : '') + '</div><div class="meta">' + pills.join('') + '</div>' + (n.descr ? '<div class="hx-why">' + esc(n.descr) + '</div>' : '')
          + '</div><div class="t">' + (n.addr && isIp(n.addr) ? '<button type="button" class="sn-btn" data-goto="snmp" data-ip="' + esc(n.addr) + '">SNMP</button> <button type="button" class="sn-btn" data-goto="ping" data-ip="' + esc(n.addr) + '">Ping</button>' : '') + '</div></div>';
      }).join('') + '</div><p class="note">' + __('A sinistra la porta di questo apparato, poi il vicino e la sua porta. Dati della LLDP-MIB (IEEE 802.1AB): un vicino che non parla LLDP non compare.') + '</p>';
}
function snFdbShown(st){
  const f = st.d.fdb, q = st.fdbQ.toLowerCase().replace(/[-.]/g, m => m === '-' ? ':' : m);
  const perPort = {};
  f.list.forEach(r => { if (r.port) perPort[r.port] = (perPort[r.port] || 0) + 1; });
  return f.list.filter(r => (st.fdbFilter === 'noip' ? !r.ip.length : st.fdbFilter === 'multi' ? perPort[r.port] > 1 : true)
    && (!q || [r.mac, r.vendor, r.ip.join(' '), r.port, r.vlan ?? '', SN_FDB[r.kind]].join(' ').toLowerCase().includes(q)));
}
function snFdbRows(st){
  const rows = snFdbShown(st);
  return rows.slice(0, SN_MAX_ROWS).map(r => '<tr><td class="num l">' + esc(r.mac) + '</td><td>' + (r.vendor ? esc(r.vendor) : '<span class="c-dim">' + (r.local ? __('amministrato in locale') : '—') + '</span>')
      + '</td><td class="num l">' + (esc(r.ip.join('\n')) || '—') + '</td><td><span class="sn-port">' + (esc(r.port) || '—') + '</span></td><td class="num l">' + (r.vlan ?? '—') + '</td><td>' + chkPill('neutral', SN_FDB[r.kind] || r.kind)
      + '</td><td class="num">' + (r.ip.length ? '<button type="button" class="sn-btn" data-goto="ping" data-ip="' + esc(r.ip[0]) + '">Ping</button>' : '') + '</td></tr>').join('')
    + (rows.length > SN_MAX_ROWS ? '<tr><td colspan="7" class="dim sn-rest">' + __('… altre {n} righe: usa la ricerca, oppure "Copia CSV" per averle tutte', {n: rows.length - SN_MAX_ROWS}) + '</td></tr>' : '')
    || '<tr><td colspan="7" class="dim sn-rest">' + __('Nessun indirizzo con questo filtro.') + '</td></tr>';
}
function snFdbPane(st){
  const f = st.d.fdb;
  if (!f.list.length) return '<p class="note hx-top">' + __('L\'apparato non espone né una tabella MAC (BRIDGE-MIB, Q-BRIDGE-MIB) né una tabella ARP, oppure la vista dell\'utente non le comprende.') + '</p>';
  return '<div class="sn-tools"><p class="summary"><strong>' + f.macs + '</strong> ' + __('indirizzi MAC') + (f.ports ? ' ' + (f.ports === 1 ? __('su {n} porta', {n: f.ports}) : __('su {n} porte', {n: f.ports})) : '') + ' · ' + __('{n} con indirizzo IP', {n: f.with_ip}) + '</p><div class="r">'
    + '<label>' + __('Cerca') + ' <input type="text" class="sn-find" data-snq spellcheck="false" autocomplete="off" value="' + esc(st.fdbQ) + '"></label>'
    + '<span class="wf-chips">' + snChip('data-snfdb', 'all', __('Tutti'), st.fdbFilter === 'all') + snChip('data-snfdb', 'noip', __('Senza IP'), st.fdbFilter === 'noip') + snChip('data-snfdb', 'multi', __('Porte con più MAC'), st.fdbFilter === 'multi') + '</span>'
    + '<button type="button" class="chip" data-sncsv="fdb">' + __('Copia CSV') + '</button></div></div>'
    + '<div class="sn-wrap"><table class="tbl sn"><thead><tr><th>MAC</th><th>' + __('Produttore') + '</th><th>' + __('Indirizzo IP') + '</th><th>' + (f.source ? __('Porta') : __('Interfaccia')) + '</th><th>VLAN</th><th>' + __('Tipo') + '</th><th></th></tr></thead><tbody>' + snFdbRows(st) + '</tbody></table></div>'
    + '<p class="note">' + (f.source ? __('MAC e porta dalla tabella di inoltro dello switch ({m}), indirizzi IP dalla tabella ARP dell\'apparato: un IP compare solo se l\'apparato fa anche da gateway per quella rete.', {m: f.source === 'qbridge' ? __('Q-BRIDGE-MIB, una per VLAN') : __('BRIDGE-MIB, senza VLAN')})
      : __('L\'apparato non è uno switch: si vedono gli indirizzi della sua tabella ARP, con l\'interfaccia su cui sono stati visti.')) + '</p>';
}
function snSysPane(d){
  const s = d.system, boot = s.uptime_s === null ? '' : new Date(Date.now() - s.uptime_s * 1000).toLocaleString(LOC, {day:'numeric', month:'long', year:'numeric', hour:'2-digit', minute:'2-digit'});
  const u = s.units.length === 1 ? s.units[0] : null;
  return rows([[__('Nome'), s.name || '—'], [__('Descrizione'), s.descr || '—'], ...(u ? [[__('Modello'), u.model || '—'], [__('Numero di serie'), u.serial || '—'], ['Firmware', u.firmware || '—']] : []),
      [__('Attivo da (sysUpTime)'), s.uptime_s === null ? '—' : snAgo(s.uptime_s) + __(' · avvio dell\'agente il {d}', {d: boot})], [__('Contatto'), s.contact || '—'], [__('Posizione'), s.location || '—'],
      [__('Servizi (sysServices)'), s.services.join(' · ') || '—'], [__('Identificativo (sysObjectID)'), s.object_id || '—'], [__('Indirizzo interrogato'), d.ip], ...(d.engine_id ? [['Engine ID (v3)', d.engine_id.replace(/(..)(?=.)/g, '$1 ').toUpperCase()]] : [])])
    + (s.units.length > 1 ? '<div class="sub">' + __('Unità dello stack') + '</div><table class="tbl sn"><thead><tr><th>' + __('Unità') + '</th><th>' + __('Modello') + '</th><th>' + __('Numero di serie') + '</th><th>Firmware</th></tr></thead><tbody>'
      + s.units.map(x => '<tr><td>' + esc(x.name || '—') + '</td><td class="num l">' + esc(x.model || '—') + '</td><td class="num l">' + esc(x.serial || '—') + '</td><td class="num l">' + esc(x.firmware || '—') + '</td></tr>').join('') + '</tbody></table>' : '')
    + (s.addresses.length ? '<div class="sub">' + __('Indirizzi IP dell\'apparato') + '</div><table class="tbl sn"><thead><tr><th>' + __('Indirizzo') + '</th><th>' + __('Maschera') + '</th><th>' + __('Interfaccia') + '</th></tr></thead><tbody>'
      + s.addresses.map(a => '<tr><td class="num l">' + esc(a.ip) + '</td><td class="num l">' + esc(a.mask || '—') + (a.prefix !== null ? ' (/' + a.prefix + ')' : '') + '</td><td>' + esc(a.if_name || '—') + '</td></tr>').join('') + '</tbody></table>' : '');
}
/* ── Resources (HOST-RESOURCES-MIB) and Printer (Printer-MIB) ── */
const SN_PC = {black:'pc-black', cyan:'pc-cyan', magenta:'pc-magenta', yellow:'pc-yellow', other:'pc-other'};
const SN_DISK = {disk:__('disco fisso'), removable:__('rimovibile'), ramdisk:__('disco RAM'), flash:'flash', network:__('disco di rete')};
const SN_ALERT = {critical:['err', __('critico')], warning:['warn', __('avviso')], other:['info', __('informazione')]};
const SN_GROUP = {other:__('altro'), hostResourcesMIBStorageTable:__('memoria'), hostResourcesMIBDeviceTable:__('dispositivo'), generalPrinter:__('stampante'), cover:__('sportello'), localization:__('lingua'),
  input:__('vassoio di ingresso'), output:__('uscita'), marker:__('unità di stampa'), markerSupplies:__('materiali'), markerColorant:__('coloranti'), mediaPath:__('percorso della carta'), channel:__('canale'), interpreter:__('interprete'),
  consoleDisplayBuffer:__('pannello'), consoleLights:__('spie')};
const snSize = b => { const u = ['B', 'KB', 'MB', 'GB', 'TB']; let v = b, i = 0; while (v >= 1024 && i < 4){ v /= 1024; i++; } return i ? snNum(v, 1) + ' ' + u[i] : b + ' B'; };
const snBar = (p, cls) => '<div class="rs-bar"><i class="' + (cls || '') + '" style="width:' + Math.max(0, Math.min(100, p)) + '%"></i></div>';
const snUsedCls = p => p >= 95 ? 'err' : p >= 85 ? 'warn' : '';
const snLeftCls = p => p <= 5 ? 'err' : p <= 15 ? 'warn' : '';
const snPcTxt = (cls, p) => cls ? '<span class="c-' + cls + '">' + p + ' %</span>' : p + ' %';
const snRow = (name, sub, bar, val) => '<div class="rs-row"><div class="nm">' + name + (sub ? '<small>' + esc(sub) + '</small>' : '') + '</div>' + bar + '<div class="v">' + val + '</div></div>';
const snCard = (t, big, small, p, cls) => '<div class="rs-card"><div class="t">' + esc(t) + '</div><div class="big">' + big + (small ? '<small>' + esc(small) + '</small>' : '') + '</div>' + snBar(p, cls) + '</div>';
const snLowCount = p => p.supplies.filter(s => s.state === 'warn' || s.state === 'err').length;

function snResPane(d){
  const r = d.resources, n = r.cpu.length, cards = [];
  if (r.cpu_avg !== null) cards.push(snCard(n === 1 ? __('CPU · media di {n} processore', {n}) : __('CPU · media di {n} processori', {n}), r.cpu_avg + ' %', '', r.cpu_avg, r.cpu_avg >= 90 ? 'warn' : ''));
  r.memory.forEach(m => cards.push(snCard(m.kind === 'ram' ? __('Memoria fisica') : __('Memoria virtuale'), m.pct + ' %', __('{a} di {b}', {a: snSize(m.used), b: snSize(m.size)}), m.pct, snUsedCls(m.pct))));
  const facts = [r.processes !== null && __('<strong>{n}</strong> processi', {n: snNum(r.processes, 0)}), r.users !== null && '<strong>' + r.users + '</strong> ' + (r.users === 1 ? __('utente collegato') : __('utenti collegati')),
    r.uptime_s !== null && __('sistema attivo da <strong>{t}</strong>', {t: snAgo(r.uptime_s)})].filter(Boolean);
  return '<div class="sn-tools"><p class="summary">' + (facts.join(' · ') || __('Risorse dell\'apparato')) + '</p><div class="r"><button type="button" class="chip" data-sncsv="res">' + __('Copia CSV') + '</button></div></div>'
    + (cards.length ? '<div class="rs-cards">' + cards.join('') + '</div>' : '')
    + (n > 1 ? '<div class="sub">' + __('Processori') + '</div>' + r.cpu.slice(0, 32).map(c => snRow(esc(c.name), '', snBar(c.load, c.load >= 90 ? 'warn' : ''), c.load + ' %')).join('')
      + (n > 32 ? '<p class="note">' + __('… altri {n} processori: "Copia CSV" li ha tutti.', {n: n - 32}) + '</p>' : '') : '')
    + (r.disks.length ? '<div class="sub">' + __('Dischi e volumi') + '</div>' + r.disks.map(x => snRow(esc(x.name), (SN_DISK[x.kind] || x.kind) + ' · ' + __('{s} totali', {s: snSize(x.size)}), snBar(x.pct, snUsedCls(x.pct)),
        snPcTxt(snUsedCls(x.pct), x.pct) + ' · ' + __('liberi {s}', {s: snSize(x.size - x.used)}))).join('') : '')
    + (r.top.length ? '<div class="sub">' + __('Processi che usano più memoria') + '</div><table class="tbl sn"><thead><tr><th>' + __('Processo') + '</th><th class="num">' + __('Memoria') + '</th><th class="num">' + __('CPU (tempo)') + '</th></tr></thead><tbody>'
      + r.top.map(p => '<tr><td>' + esc(p.name || '—') + '</td><td class="num">' + snSize(p.mem_kb * 1024) + '</td><td class="num">' + snHms(p.cpu_s) + '</td></tr>').join('')
      + '</tbody></table><p class="note">' + __('Primi {n} su {m} letti, per memoria. Il tempo di CPU è ore:minuti:secondi dall\'avvio del processo.', {n: r.top.length, m: snNum(r.process_total, 0)}) + '</p>' : '')
    + '<p class="note">' + __('Dati di HOST-RESOURCES-MIB. Alcuni agenti contano la cache come memoria usata; il carico dei processori è la media dell\'ultimo minuto.') + '</p>';
}

function snPrnPane(d){
  const p = d.printer, low = snLowCount(p);
  const supplyBar = s => s.level === null ? '<div class="rs-bar"></div>'
    : snBar(s.level, s.class === 'filled' ? snUsedCls(s.level) : s.color ? SN_PC[s.color] : snLeftCls(s.level));
  const supplyVal = s => s.level === null ? '<span class="c-dim">' + (s.some ? __('almeno un\'unità') : __('sconosciuto')) + '</span>'
    : s.class === 'filled' ? snPcTxt(snUsedCls(s.level), s.level) + ' ' + __('pieno') : snPcTxt(snLeftCls(s.level), s.level);
  const trayVal = t => t.state === 'empty' ? '<span class="c-err">' + __('vuoto') + '</span>' + (t.max ? ' / ' + snNum(t.max, 0) : '') : t.some ? '<span class="c-dim">' + __('almeno un foglio') + '</span>' : t.current === null ? '—' : snNum(t.current, 0) + (t.max ? ' / ' + snNum(t.max, 0) : '');
  const info = [p.name && esc(p.name), p.serial && __('matricola <span class="num">{s}</span>', {s: esc(p.serial)})].filter(Boolean).join(' · ');
  return '<div class="sn-tools"><p class="summary"><strong>' + p.supplies.length + '</strong> ' + (p.supplies.length === 1 ? __('materiale di consumo') : __('materiali di consumo'))
      + (p.pages !== null ? __(' · contatore <strong>{n}</strong> pagine', {n: snNum(p.pages, 0)}) : '') + (low ? ' · <span class="c-warn">' + __('{n} da sostituire o svuotare', {n: low}) + '</span>' : '') + '</p>'
    + '<div class="r"><button type="button" class="chip" data-sncsv="prn">' + __('Copia CSV') + '</button></div></div>'
    + (info || p.errors.length ? '<div class="sn-sec">' + (info ? '<span>' + info + '</span>' : '') + p.errors.map(e => '<span>' + chkPill(e.severe ? 'err' : 'warn') + esc(e.label) + '</span>').join('') + '</div>' : '')
    + p.supplies.map(s => snRow((s.color ? '<span class="sw ' + SN_PC[s.color] + '"></span>' : '') + esc(s.name), s.kind + (s.class === 'filled' ? __(' · si riempie') : ''), supplyBar(s), supplyVal(s))).join('')
    + (p.trays.length ? '<div class="sub">' + __('Vassoi della carta') + '</div><table class="tbl sn"><thead><tr><th>' + __('Vassoio') + '</th><th>' + __('Carta') + '</th><th>' + __('Livello') + '</th><th class="num">' + __('Fogli') + '</th></tr></thead><tbody>'
      + p.trays.map(t => '<tr><td><b>' + esc(t.name) + '</b></td><td>' + (esc(t.media) || '<span class="c-dim">—</span>') + '</td><td style="width:34%">' + (t.level === null ? '' : snBar(t.level, t.state === 'empty' ? 'err' : '')) + '</td><td class="num">' + trayVal(t) + '</td></tr>').join('')
      + '</tbody></table>' : '')
    + (p.alerts.length ? '<div class="sub">' + __('Allarmi attivi') + '</div><table class="tbl sn"><thead><tr><th></th><th>' + __('Gravità') + '</th><th>' + __('Messaggio') + '</th><th>' + __('Parte') + '</th></tr></thead><tbody>'
      + p.alerts.map(a => '<tr><td>' + chkPill(SN_ALERT[a.severity][0]) + '</td><td>' + SN_ALERT[a.severity][1] + '</td><td>' + esc(a.text) + '</td><td>' + esc(SN_GROUP[a.group] || a.group || '—') + '</td></tr>').join('') + '</tbody></table>' : '')
    + '<p class="note">' + __('Dati di Printer-MIB (RFC 3805). Sotto il 15 % rimasto un materiale è un avviso; i contenitori (toner di scarto) lo diventano oltre l\'85 % di riempimento.') + '</p>';
}

function snmpDeviceRender(st, tab){
  const d = st.d, sec = d.sections;
  const checks = (d.checks || []).map((c, i) => [c, i]).sort((a, b) => (CHK_RANK[a[0].status] - CHK_RANK[b[0].status]) || (a[1] - b[1])).map(x => x[0]);
  const nErr = checks.filter(c => c.status === 'err').length, nWarn = checks.filter(c => c.status === 'warn').length;
  const many = (n, one, more) => n + ' ' + (n === 1 ? one : more);
  const found = nErr || nWarn ? [nErr && many(nErr, __('errore'), __('errori')), nWarn && many(nWarn, __('avviso'), __('avvisi'))].filter(Boolean).join(' · ') : __('Tutti superati');
  const ifs = d.interfaces, nb = d.neighbors, f = d.fdb, up = d.system.uptime_s, prn = d.printer, res = d.resources;
  // the two boxes on the right depend on what the device is: printer, server or network
  const ram = res && res.memory.find(m => m.kind === 'ram'), full = res && res.disks.length ? res.disks.reduce((a, b) => b.pct > a.pct ? b : a) : null;
  const lowN = prn ? snLowCount(prn) : 0;
  const side = prn ? [[__('Stato'), prn.status || '—', (prn.errors.length ? 'warn' : 'ok') + ' big txt'], [__('Materiali'), !prn.supplies.length ? '—' : lowN ? __('{n} da sostituire', {n: lowN}) : __('Tutti sopra il 15 %'), (lowN ? 'warn' : prn.supplies.length ? 'ok' : '') + ' big txt']]
    : res ? [res.cpu_avg !== null ? ['CPU', res.cpu_avg + ' %', (res.cpu_avg >= 90 ? 'warn' : 'ok') + ' big txt'] : ['', ''], ram ? [__('Memoria'), ram.pct + ' %', (ram.pct >= 95 ? 'warn' : 'ok') + ' big txt'] : full ? [__('Disco più pieno'), full.pct + ' %', (snUsedCls(full.pct) || 'ok') + ' big txt'] : ['', '']]
    : [ifs ? [__('Interfacce'), ifs.total ? __('{n} attive su {m}', {n: ifs.up, m: ifs.total}) : __('Nessuna'), (ifs.total ? 'ok' : '') + ' big txt'] : ['', ''], [__('Attivo da'), up === null ? '—' : snAgo(up).split(',')[0], 'big txt']];
  let html = kv([[__('Apparato'), d.name.split('.')[0] === d.name || isIp(d.name) ? d.name : d.name.split('.')[0], 'big txt'], [__('Controlli'), found, (nErr ? 'err' : nWarn ? 'warn' : 'ok') + ' big txt'], ...side]);
  if (d.stopped) html += '<p class="summary hx-run">' + __('Lettura fermata: le schede mostrano solo ciò che era già stato letto.') + '</p>';
  const pChecks = '<table class="tbl smtp-checks hx-tbl"><thead><tr><th></th><th>' + __('Area') + '</th><th>' + __('Controllo') + '</th><th>' + __('Risultato') + '</th></tr></thead><tbody>'
    + checks.map(k => '<tr><td>' + chkPill(k.status) + '</td><td class="k hx-area">' + esc(k.area) + '</td><td class="k">' + esc(k.name) + '</td><td class="m">' + esc(k.detail) + '</td></tr>').join('') + '</tbody></table>';
  const tabs = [['chk', __('Controlli'), checks.length]];
  if (sec.system) tabs.push(['sys', __('Sistema')]);
  if (prn) tabs.push(['prn', __('Stampante'), prn.supplies.length]);
  if (res) tabs.push(['res', __('Risorse'), res.disks.length + res.memory.length]);
  if (ifs) tabs.push(['if', __('Interfacce'), ifs.total]);
  if (nb) tabs.push(['nb', __('Vicini'), nb.list.length]);
  if (f) tabs.push(['fdb', __('MAC e ARP'), f.macs]);
  if (!tabs.some(t => t[0] === tab)) tab = 'chk';
  html += rtabs(tabs, tab) + rpane('chk', tab, pChecks) + (sec.system ? rpane('sys', tab, snSysPane(d)) : '') + (prn ? rpane('prn', tab, snPrnPane(d)) : '') + (res ? rpane('res', tab, snResPane(d)) : '') + (ifs ? rpane('if', tab, snIfPane(st)) : '')
    + (nb ? rpane('nb', tab, snNbPane(d)) : '') + (f ? rpane('fdb', tab, snFdbPane(st)) : '');

  // "Copy" takes the whole result, not just the open tab
  const s = d.system;
  const text = ['SNMP · ' + d.name + ' (' + d.ip + ')', '', __('CONTROLLI'), ...checks.map(k => '[' + (CHK_ICON[k.status] || '') + '] ' + k.area + ' · ' + k.name + ': ' + k.detail),
    ...(sec.system ? ['', __('SISTEMA'), __('Nome: {v}', {v: s.name}), __('Descrizione: {v}', {v: s.descr}), ...s.units.map(x => __('Unità: {v}', {v: [x.name, x.model, x.serial, x.firmware].filter(Boolean).join(' · ')})), __('Attivo da: {v}', {v: up === null ? '—' : snAgo(up)}),
      __('Contatto: {v}', {v: s.contact || '—'}), __('Posizione: {v}', {v: s.location || '—'}), 'sysObjectID: ' + s.object_id, ...s.addresses.map(a => __('Indirizzo: {v}', {v: a.ip + (a.prefix !== null ? '/' + a.prefix : '') + ' ' + a.if_name}))] : []),
    ...(prn ? ['', __('STAMPANTE'), [prn.name, prn.status, prn.serial && __('matricola {s}', {s: prn.serial}), prn.pages !== null && __('{n} pagine', {n: snNum(prn.pages, 0)})].filter(Boolean).join(' · '), ...prn.errors.map(e => __('Segnalazione: {v}', {v: e.label})),
      ...prn.supplies.map(x => x.name + ': ' + (x.level === null ? (x.some ? __('almeno un\'unità') : __('sconosciuto')) : x.level + ' %' + (x.class === 'filled' ? ' ' + __('pieno') : ''))),
      ...prn.trays.map(t => __('Vassoio {n}', {n: t.name}) + (t.media ? ' (' + t.media + ')' : '') + ': ' + (t.state === 'empty' ? __('vuoto') : t.some ? __('almeno un foglio') : t.current === null ? '—' : t.current + (t.max ? ' / ' + t.max : ''))),
      ...prn.alerts.map(a => __('Allarme ({g}): {t}', {g: SN_ALERT[a.severity][1], t: a.text}))] : []),
    ...(res ? ['', __('RISORSE'), ...(res.cpu_avg !== null ? [__('CPU: {p} % (media di {n})', {p: res.cpu_avg, n: res.cpu.length})] : []), ...res.memory.map(m => m.name + ': ' + m.pct + ' % (' + __('{a} di {b}', {a: snSize(m.used), b: snSize(m.size)}) + ')'),
      ...res.disks.map(x => x.name + ': ' + x.pct + ' % (' + __('liberi {a} su {b}', {a: snSize(x.size - x.used), b: snSize(x.size)}) + ')'), ...res.top.map(p => __('Processo {n}: {m}', {n: p.name, m: snSize(p.mem_kb * 1024)}))] : []),
    ...(ifs ? ['', __('INTERFACCE'), ...ifs.list.map(i => [i.name, i.alias, SN_STATE[i.state][1], snSpeed(i.speed_bps), i.mac, __('errori {n}', {n: i.in_errors + i.out_errors}), __('scarti {n}', {n: i.in_discards + i.out_discards})].filter(Boolean).join(' · '))] : []),
    ...(nb ? ['', __('VICINI LLDP'), ...(nb.list.length ? nb.list.map(n => n.local_port + ' → ' + [n.name, n.port && __('porta {n}', {n: n.port}), n.caps.join(', '), n.addr, n.descr].filter(Boolean).join(' · ')) : [__('nessuno')])] : []),
    ...(f ? ['', __('MAC E ARP'), ...(f.list.length ? f.list.map(r => [r.mac, r.vendor, r.ip.join(' '), r.port, r.vlan !== null ? 'VLAN ' + r.vlan : '', SN_FDB[r.kind]].filter(Boolean).join(' · ')) : [__('nessuno')])] : [])].join('\n');
  return {status: d.stopped ? 'stop' : (nErr || nWarn) ? 'warn' : 'ok', html, text};
}
function snDraw(strip){
  const st = strip._data, body = strip.querySelector('.strip-body');
  const cur = body.querySelector('.seg.rtabs [aria-selected="true"]');
  const r = snmpDeviceRender(st, cur ? cur.dataset.rtab : 'chk');
  body.innerHTML = r.html; strip._text = r.text;
  setState(strip, r.status);
}
const snPane = (strip, key, html) => { const p = strip.querySelector('[data-rpane="' + key + '"]'); if (p) p.innerHTML = html; };

/* live counters: one sample per reading until "Stop" is pressed */
async function snMonitor(strip){
  const st = strip._data;
  if (st.mon && st.mon.running) return TAURI.invoke('snmp_monitor_stop').catch(() => {});
  const mon = st.mon = {running: true, samples: new Map(), t: 0, n: 0, hc: null, interval: 5, error: null};
  snPane(strip, 'if', snIfPane(st));
  const ch = new TAURI.Channel();
  ch.onmessage = m => {
    // result removed while the monitor is on: it stops by itself
    if (!strip.isConnected) return TAURI.invoke('snmp_monitor_stop').catch(() => {});
    if (m.start){ mon.hc = m.start.hc; mon.interval = m.start.interval_s; }
    else if (m.sample){ mon.t = m.sample.t_ms; mon.n++; m.sample.ports.forEach(p => mon.samples.set(p.index, p)); }
    snIfTick(strip);
  };
  try {
    const end = await TAURI.invoke('snmp_monitor', {req: st.req, onEvent: ch});
    mon.error = end.error || null;
  } catch(e) { mon.error = tauriError(e); }
  mon.running = false;
  if (strip.isConnected) snPane(strip, 'if', snIfPane(st));
}
function snCopyCsv(strip, what, btn){
  const st = strip._data; if (!st) return;
  let csv = '';
  if (what === 'table') csv = st.csv;
  else if (what === 'if'){
    const mon = st.mon, live = mon && mon.samples.size;
    csv = snCsv([[__('Porta'), __('Descrizione'), __('Stato'), __('Velocità (bit/s)'), 'MAC', 'MTU', __('Tipo'), __('Errori in'), __('Errori out'), __('Scarti in'), __('Scarti out'), ...(live ? [__('Ingresso (bit/s)'), __('Uscita (bit/s)')] : [])],
      ...st.d.interfaces.list.map(i => { const s = live ? mon.samples.get(i.index) : null;
        return [i.name, i.alias, SN_STATE[(s || i).state][1], i.speed_bps ?? '', i.mac, i.mtu ?? '', i.kind, i.in_errors, i.out_errors, i.in_discards, i.out_discards,
          ...(live ? [s && s.in_bps !== null ? Math.round(s.in_bps) : '', s && s.out_bps !== null ? Math.round(s.out_bps) : ''] : [])]; })]);
  } else if (what === 'res'){
    const r = st.d.resources;
    csv = snCsv([[__('Tipo'), __('Nome'), __('Totale (byte)'), __('Usato (byte)'), __('Usato (%)')], ...r.cpu.map(c => [__('processore'), c.name, '', '', c.load]),
      ...r.memory.concat(r.disks).map(x => [x.kind, x.name, x.size, x.used, x.pct]), ...r.top.map(p => [__('processo'), p.name, '', p.mem_kb * 1024, ''])]);
  } else if (what === 'prn') csv = snCsv([[__('Materiale'), __('Tipo'), __('Classe'), __('Colore'), __('Livello (%)'), __('Stato')],
      ...st.d.printer.supplies.map(x => [x.name, x.kind, x.class === 'filled' ? __('si riempie') : __('si consuma'), x.color, x.level ?? (x.some ? __('almeno uno') : ''), x.state])]);
  else if (what === 'nb') csv = snCsv([[__('Porta locale'), __('Vicino'), __('Porta del vicino'), __('Descrizione della porta'), __('Funzioni'), __('Indirizzo di gestione'), 'Chassis', __('Descrizione')],
      ...st.d.neighbors.list.map(n => [n.local_port, n.name, n.port, n.port_descr, n.caps.join(', '), n.addr, n.chassis, n.descr])]);
  else if (what === 'fdb') csv = snCsv([['MAC', __('Produttore'), __('Indirizzo IP'), __('Porta'), 'VLAN', __('Tipo')], ...st.d.fdb.list.map(r => [r.mac, r.vendor, r.ip.join(' '), r.port, r.vlan ?? '', SN_FDB[r.kind] || r.kind])]);
  navigator.clipboard?.writeText(csv).then(() => { btn.textContent = __('Copiato'); setTimeout(() => btn.textContent = __('Copia CSV'), 1400); });
}
$('res-snmp').addEventListener('click', e => {
  const strip = e.target.closest('.strip'), st = strip && strip._data;
  if (!st) return;
  const csv = e.target.closest('[data-sncsv]'), f = e.target.closest('[data-snif]'), m = e.target.closest('[data-snfdb]');
  if (csv) snCopyCsv(strip, csv.dataset.sncsv, csv);
  else if (e.target.closest('[data-snmon]')) snMonitor(strip);
  else if (f){
    st.ifFilter = f.dataset.snif;
    f.parentNode.querySelectorAll('.chip').forEach(c => c.classList.toggle('on', c === f));
    snIfTick(strip);
  }
  else if (m){ st.fdbFilter = m.dataset.snfdb; snPane(strip, 'fdb', snFdbPane(st)); }
});
$('res-snmp').addEventListener('input', e => {
  const strip = e.target.closest('.strip'), st = strip && strip._data;
  if (!st) return;
  // only the rows are redrawn: the field being typed in stays as it is
  if (e.target.matches('[data-snq]')){ st.fdbQ = e.target.value; strip.querySelector('[data-rpane="fdb"] tbody').innerHTML = snFdbRows(st); }
  else if (e.target.matches('[data-sntf]')) strip.querySelector('tbody').innerHTML = snTableRows(st.table, e.target.value);
});
$('res-snmp').addEventListener('click', gotoTool);

/* ── actions from the rows of the scan and of the local network ── */
function gotoTool(e){
  const b = e.target.closest('[data-goto]'); if (!b) return;
  const to = b.dataset.goto;
  show(to);
  if (to === 'ping'){ $('ping-host').value = b.dataset.ip; $('view-ping').querySelector('form').requestSubmit(); }
  if (to === 'portscan'){ $('scan-host').value = b.dataset.ip; $('scan-host').focus(); }
  if (to === 'snmp'){ $('snmp-host').value = b.dataset.ip; $('snmp-host').focus(); $('view-snmp').scrollIntoView(); }
  if (to === 'wol'){ $('wol-mac').value = b.dataset.mac; $('wol-name').value = b.dataset.name.toUpperCase(); $('wol-name').focus(); }
  // from the MX rows: the field is filled in, the user starts the test
  if (to === 'smtp'){ $('smtp-host').value = b.dataset.host; $('smtp-host').focus(); }
  if (to === 'ssl'){ $('ssl-host').value = b.dataset.host; $('ssl-port').value = 25; $('ssl-proto').value = 'smtp'; $('ssl-host').focus(); }
  if (to === 'blacklist'){ $('bl-host').value = b.dataset.host; $('bl-host').focus(); }
  // from the DKIM signature of a message: domain and selector in the domain form
  if (to === 'email'){ document.querySelector('[data-tabs="email"] [data-tab="domain"]').click(); $('email-domain').value = b.dataset.domain; $('email-sel').value = b.dataset.selector; $('email-domain').focus(); $('view-email').scrollIntoView(); }
}
$('res-sweep').addEventListener('click', gotoTool);
$('res-lan').addEventListener('click', gotoTool);
$('res-email').addEventListener('click', gotoTool);

/* ── form submit (native Enter) and secondary buttons ── */
document.querySelectorAll('form[data-submit]').forEach(f => f.addEventListener('submit', e => {
  e.preventDefault(); tools[f.dataset.submit](f);
}));
/* Ping, traceroute, subnet scan, local network and ports: while the test runs the submit button is "Stop". The click (also
   Enter in a field, which the browser turns into a click on the button) does not start another
   test: it stops the running one. The button goes back to "Run…" when the test has ended. */
document.querySelectorAll('form[data-stop]').forEach(f => f.querySelector('button[type=submit]').addEventListener('click', e => {
  if (!f.dataset.running) return;
  e.preventDefault();
  e.currentTarget.disabled = true;
  TAURI.invoke(f.dataset.stop).catch(() => {});
}));
document.querySelectorAll('[data-run]').forEach(b => b.addEventListener('click', () => tools[b.dataset.run](b.closest('form'))));
