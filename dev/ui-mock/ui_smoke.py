"""UI test with simulated Tauri IPC (headless Chromium).
Usage: python -E -P dev/ui-mock/ui_smoke.py [ui folder] [screenshot folder]
(not -I: it excludes packages installed with --user, where Playwright lives)
The expected version (2.1.0) must be updated at every release."""
import sys, pathlib, threading, functools, http.server
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[2]
UI = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / 'ui'
OUT = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / 'target' / 'ui-shots'; OUT.mkdir(parents=True, exist_ok=True)

MOCK = r"""
window.__calls = [];
window.__probe = {};
window.__online = true;
// normal clipboard (navigator.clipboard): the copied text ends up in window.__copied
try { Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText: async t => { window.__copied = t; }}}); } catch(e){}
class Channel { constructor(){ this.onmessage = null; } }
window.__win = [];
window.__TAURI__ = { window: { getCurrentWindow: () => ({
  minimize: async () => window.__win.push('min'), toggleMaximize: async () => window.__win.push('max'),
  close: async () => window.__win.push('close'), isMaximized: async () => false, onResized: () => {} }) },
  core: { Channel, invoke: async (cmd, args) => {
  window.__calls.push([cmd, JSON.parse(JSON.stringify(args && args.req || {}))]);
  if (cmd === 'set_lang') { window.__lang = args.lang; return null; }
  if (cmd === 'app_info') return {hostname:'SRV01.corp.example', ip:'172.16.7.42', version:'2.1.0', os:'windows'};
  if (cmd === 'internet_check') return window.__online ? {online:true, target:'1.1.1.1', rtt_ms:12.3, local_ip:'172.16.7.42'} : {online:false, target:null, rtt_ms:null};
  // "Ferma" (Stop): interrupts the running test of the same tool
  if (cmd === 'ping_stop' || cmd === 'traceroute_stop') { const f = window.__probe[cmd.replace('_stop', '')]; if (f) f(); return null; }
  if (['ping', 'ping_stream', 'traceroute', 'traceroute_stream'].includes(cmd)) {
    // like the backend: one test at a time per tool (the new one stops the previous);
    // host "lento" = one line every 150 ms, host "muto" = no reply until stopped
    const kind = cmd.replace('_stream', ''), live = cmd.endsWith('_stream'), ping = kind === 'ping';
    if (window.__probe[kind]) window.__probe[kind]();
    let stopped = false, wake = null;
    const me = window.__probe[kind] = () => { stopped = true; if (wake) wake(); };
    const wait = ms => stopped ? Promise.resolve() : new Promise(r => { wake = r; setTimeout(r, ms); });
    const ch = live ? args.onEvent : null, r = args.req, h = r.host, out = [];
    const emit = l => { out.push(l); if (ch) ch.onmessage({line:l}); };
    let meta = null;
    const stats = n => ['', '--- '+h+' ping statistics ---', n+' packets transmitted, '+n+' received, 0% packet loss', 'rtt min/avg/max/mdev = 0.412/0.412/0.412/0.000 ms'].forEach(emit);
    if (h === 'muto') {
      await wait(60000);
      emit(ping ? 'Fermato prima della risposta al primo pacchetto.' : 'fermato prima della fine');
    } else {
      meta = {ip:'198.51.100.1', name:h}; if (ch) ch.onmessage({meta});
      if (h !== 'lento') {
        (ping ? ['PING '+h+' (198.51.100.1) 32 bytes of data.', '40 bytes from 198.51.100.1: icmp_seq=1 ttl=255 time=0.412 ms', '', '--- '+h+' ping statistics ---', '1 packets transmitted, 1 received, 0% packet loss', 'rtt min/avg/max/mdev = 0.412/0.412/0.412/0.000 ms']
              : ['traceroute to '+h+' (198.51.100.1), 30 hops max, 32 byte packets', ' 1  172.16.7.1  0.512 ms', ' 2  198.51.100.1  1.20 ms']).forEach(emit);
      } else if (ping) {
        const count = +(r.count || 4); let n = 0;
        emit('PING '+h+' (198.51.100.1) 32 bytes of data.');
        while (n < count) {
          emit('40 bytes from 198.51.100.1: icmp_seq='+(++n)+' ttl=255 time=0.412 ms');
          if (n < count) await wait(150);
          if (stopped) { emit(n === 1 ? 'Fermato dopo 1 pacchetto su '+count+'.' : 'Fermato dopo '+n+' pacchetti su '+count+'.'); break; }
        }
        stats(n);
      } else {
        const hops = +(r.max_hops || 30);
        emit('traceroute to '+h+' (198.51.100.1), '+hops+' hops max, 32 byte packets');
        for (let t = 1; t <= hops; t++) {
          emit(String(t).padStart(2)+'  172.16.'+t+'.1  1.00 ms');
          await wait(150);
          if (stopped) { emit('    fermato prima della fine'); break; }
        }
      }
    }
    if (window.__probe[kind] === me) delete window.__probe[kind];
    if (ch) ch.onmessage({done:true});
    return live ? {stopped} : {output: out.join('\n') + '\n', meta, stopped};
  }
  if (cmd === 'pwgen_estimate') {
    const r = args.req;
    if (!r.lower && !r.upper && !r.digits && !r.symbols) throw 'Seleziona almeno un tipo di carattere';
    return {entropy_bits:128.6, strength:'estrema', pool:r.pronounceable ? null : 88, length:+r.length, pronounceable:r.pronounceable};
  }
  if (cmd === 'pwgen_password') {
    const r = args.req, L = +r.length, cs = 'abcdeXYZ0123456789!@#<&>"';
    const pw = () => Array.from({length:L}, () => cs[Math.floor(Math.random() * cs.length)]).join('');
    return {entropy_bits:128.6, strength:'estrema', pool:88, length:L, pronounceable:false, passwords:Array.from({length:+r.count}, pw)};
  }
  if (cmd === 'clipboard_secret') { window.__clip = args.req.text; return 30; }
  if (cmd === 'net_path') return {local_ip:'172.16.1.248', if_name:'Ethernet', if_descr:'Intel(R) Ethernet Connection I219-LM', kind:'cable',
    gateway:'172.16.1.1', gateway_name:'gw01.corp.example', gateway_rtt_ms:0.6};
  if (cmd === 'myip') return {ip:'203.0.113.130', org:'AS64500 Provider Example S.p.A.', hostname:'host130.isp.example', city:'Roma'};
  if (cmd === 'lan_default') return {cidr:'172.16.0.0/21', ip:'172.16.1.248', iface:'172.16.0.0/21', reduced:false};
  if (cmd === 'lan_stop') { window.__lanStop = true; return null; }
  if (cmd === 'lan_scan') {
    const ch = args.onEvent, svc = args.req.services;
    const H = (o) => Object.assign({via:'ICMP', rtt_ms:0.4, mac:'', vendor:'', random_mac:false, vm:false, ptr:'', netbios:'', name:'', snmp:null, services:[], kind:'other'}, o);
    ch.onmessage({start:{cidr:'172.16.0.0/21', total:2046, local:true, services:svc, oui:true}});
    ch.onmessage({host:H({ip:'172.16.1.47', mac:'00:17:c8:11:22:33', vendor:'KYOCERA', kind:'printer',
      snmp:{sys_name:'KM-UFFICIO', sys_descr:'KYOCERA Document Solutions Printing System', object_id:'1.3.6.1.4.1.1347.41', device:'ECOSYS MA4500ix'},
      services: svc ? [{port:80, name:'HTTP', banner:'HTTP/1.1 200 OK'}, {port:9100, name:'Stampa RAW', banner:''}] : []})});
    ch.onmessage({progress:{done:1024, total:2046}});
    ch.onmessage({host:H({ip:'172.16.0.31', mac:'00:50:56:aa:bb:cc', vendor:'VMware', vm:true, ptr:'vm11.corp.example', netbios:'VM11', name:'vm11.corp.example', kind:'pc',
      services: svc ? [{port:445, name:'SMB', banner:''}, {port:3389, name:'Desktop remoto', banner:''}] : []})});
    ch.onmessage({host:H({ip:'172.16.1.84', via:'ARP', rtt_ms:null, mac:'8c:1f:64:10:3a:bc', vendor:'ESEMPIO', name:'imx6dl-dev0011', ptr:'imx6dl-dev0011', kind:'server',
      services: svc ? [{port:22, name:'SSH', banner:'SSH-2.0-dropbear'}] : []})});
    ch.onmessage({host:H({ip:'172.16.1.200', mac:'da:a1:19:00:00:01', random_mac:true})});
    ch.onmessage({progress:{done:2046, total:2046}});
    return {cidr:'172.16.0.0/21', total:2046, found:4, elapsed_s:31.4, stopped:false};
  }
  // Local network, Neighbours tab: first read and, from the second, an IP moved to another MAC
  if (cmd === 'neigh_scan') {
    const n = window.__neighN = (window.__neighN || 0) + 1, probe = !!args.req.probe;
    const A = (ip, scope, state, router) => ({ip, scope: scope || '', state: state || 'reachable', iface:'Ethernet', router: !!router});
    const D = o => Object.assign({mac:'', vendor:'', random_mac:false, vm:false, v4:[], v6:[], ifaces:['Ethernet'], state:'reachable', gateway:false, router6:false}, o);
    const devices = [
      D({mac:'00:50:56:aa:00:01', vendor:'Esempio Networks', gateway:true, router6:true, v4:[A('172.16.1.1')], v6:[A('fe80::250:56ff:feaa:1', 'link-local', 'reachable', true), A('2001:db8:1::1', 'globale')]}),
      D({mac: n > 1 ? '00:11:22:33:44:55' : '8c:1f:64:10:3a:bc', vendor: n > 1 ? '' : 'Esempio Devices', state:'cache', v4:[A('172.16.1.84', '', 'cache')],
        v6: n > 1 ? [] : [A('fe80::8e1f:64ff:fe10:3abc', 'link-local', 'cache'), A('2001:db8:1::84', 'globale', 'cache')]}),
      D({mac:'00:17:c8:11:22:33', vendor:'KYOCERA', v4:[A('172.16.1.47')], v6:[A('fe80::217:c8ff:fe11:2233', 'link-local')]}),
      D({mac:'da:a1:19:00:00:01', random_mac:true, ifaces:['Wi-Fi'], state:'cache', v4:[A('172.16.1.200', '', 'cache')], v6:[A('2001:db8:1::a1b2', 'globale', 'cache'), A('2001:db8:1::c3d4', 'globale', 'cache')]}),
      D({mac:'52:54:00:12:34:56', vendor:'QEMU', vm:true, v4:[10, 11, 12, 13, 14].map(i => A('172.16.1.' + i))}),
      D({mac:'', state:'incomplete', v4:[99, 100, 101, 102, 103, 104].map(i => A('172.16.1.' + i, '', 'incomplete'))})
    ];
    const C = (area, status, name, detail) => ({area, status, name, detail});
    const checks = [C('Rete', 'ok', 'Gateway nella tabella', '172.16.1.1 (00:50:56:aa:00:01)'),
      C('Rete', 'warn', 'MAC con molti indirizzi IPv4', '52:54:00:12:34:56 risponde per 5 indirizzi: ARP proxy, host con più indirizzi o un duplicato'),
      C('Rete', 'info', 'Indirizzi non risolti', '6 indirizzi: nessuna risposta ARP o NDP finora'),
      C('IPv6', 'ok', 'Un solo router IPv6', 'fe80::250:56ff:feaa:1 (stesso MAC del gateway IPv4)')];
    let pr = null;
    if (n > 1) checks.push(C('Cambiamenti', 'warn', 'Indirizzo passato a un altro MAC', '172.16.1.84: prima 8c:1f:64:10:3a:bc, ora 00:11:22:33:44:55 (DHCP, IP duplicato o ARP spoofing)'), C('Cambiamenti', 'info', 'Dispositivi nuovi', '1 MAC dall\'aggiornamento precedente'));
    else checks.push(C('Cambiamenti', 'info', 'Nessun confronto', 'primo aggiornamento'));
    if (probe) { pr = {ifaces:2, replies:['fe80::217:c8ff:fe11:2233'], new_entries:3, note:'percorso: Icmp6SendEcho2'};
      checks.push(C('IPv6', 'info', 'Echo a ff02::1', '2 pacchetti su 2 schede; 1 risposta/e dirette (fe80::217:c8ff:fe11:2233); voci nuove nella tabella: 3')); }
    const v4 = devices.filter(d => d.mac).reduce((a, d) => a + d.v4.length, 0), v6 = devices.reduce((a, d) => a + d.v6.length, 0);
    return {at: 1763373000 + n * 60, previous_at: n > 1 ? 1763373000 + (n - 1) * 60 : null, source:'ip-helper', gateway:'172.16.1.1', devices,
      routers:[{addr:'fe80::250:56ff:feaa:1', mac:'00:50:56:aa:00:01', vendor:'Esempio Networks', iface:'Ethernet', lifetime_s:1800, same_as_gateway:true}],
      prefixes:[{prefix:'2001:db8:1::/64', iface:'Ethernet', on_link:true, valid_s:86400, via:[]}],
      n_devices:5, n_v4:v4, n_v6:v6, unresolved:6, checks, probe: pr,
      csv:'MAC;Produttore;Famiglia;Indirizzo;Ambito;Stato;Scheda;Ruolo\r\n00:50:56:aa:00:01;Esempio Networks;IPv4;172.16.1.1;;reachable;Ethernet;gateway'};
  }
  // Subnet scan and TCP ports in streaming: like the backend,
  // hosts and open ports arrive on the Channel in the order they are found, the final response
  // reorders them; a new test stops the running one. Network 198.51.100.0/24 and host "lento" go on until
  // stopped; 203.0.113.0/29 = network not attached to the PC, empty; host "firewall" = all filtered.
  if (cmd === 'sweep_stop' || cmd === 'portscan_stop') { const f = window.__probe[cmd.replace('_stop', '')]; if (f) f(); return null; }
  if (cmd === 'sweep' || cmd === 'portscan') {
    if (window.__probe[cmd]) window.__probe[cmd]();
    let stopped = false, wake = null;
    const me = window.__probe[cmd] = () => { stopped = true; if (wake) wake(); };
    const wait = ms => stopped ? Promise.resolve() : new Promise(r => { wake = r; setTimeout(r, ms); });
    const end = v => { if (window.__probe[cmd] === me) delete window.__probe[cmd]; return v; };
    const ch = args.onEvent, r = args.req;
    let done = 0;
    if (cmd === 'sweep') {
      if (!r.cidr.includes('/')) { end(); throw 'Indica la rete con il prefisso, per esempio 172.16.24.0/24'; }
      const net = r.cidr.split('/')[0].split('.').slice(0, 3).join('.') + '.';
      const slow = r.cidr === '198.51.100.0/24', local = r.cidr !== '203.0.113.0/29', total = slow ? 254 : 6;
      const num = ip => ip.split('.').reduce((a, x) => a * 256 + +x, 0);
      const alive = new Map(), H = o => Object.assign({via:'ICMP', rtt_ms:0.4, mac:'', name:''}, o);
      const host = h => { h = H(h); alive.set(h.ip, h); ch.onmessage({host:h}); };
      const prog = n => { done = n; ch.onmessage({progress:{done, total}}); };
      ch.onmessage({start:{cidr:r.cidr, total, local, tcp:r.tcp}});
      if (slow) {
        // .10 arrives before .5; the name of .10 arrives later, with the same host sent again
        host({ip:net + '10', mac:'00:50:56:aa:bb:10', rtt_ms:0.6});
        await wait(120); if (!stopped) host({ip:net + '5', mac:'00:50:56:aa:bb:05'});
        await wait(120); if (!stopped) host({ip:net + '10', mac:'00:50:56:aa:bb:10', rtt_ms:0.6, name:'vm10.corp.example'});
        for (let i = 20; done < total; i += 7) {
          await wait(150); if (stopped) break;
          prog(Math.min(total, done + 16));
          if (i < 255) host(i % 2 ? {ip:net + i, rtt_ms:1.1} : {ip:net + i, via:'TCP 445', rtt_ms:null});
        }
      } else if (local) {
        host({ip:net + '2', rtt_ms:0.3, mac:'00:17:c8:11:22:33'});
        prog(3);
        host({ip:net + '1', rtt_ms:0.5, mac:'00:09:0f:00:00:01'});
        host({ip:net + '2', rtt_ms:0.3, mac:'00:17:c8:11:22:33', name:'srv01.corp.example'});
        prog(total);
      } else prog(total);
      return end({cidr:r.cidr, total, alive:[...alive.values()].sort((a, b) => num(a.ip) - num(b.ip)), tcp:r.tcp, local,
        elapsed_s: slow ? 0.6 : 1.4, stopped, checked: stopped ? done : total});
    }
    const slow = r.host === 'lento', list = slow ? Array.from({length:100}, (_, i) => 8000 + i) : [22, 80, 443, 445, 3389];
    const total = list.length, res = new Map();
    const set = (port, status, banner = '') => res.set(port, {port, status, banner});
    const open = (port, banner) => { set(port, 'OPEN', banner); ch.onmessage({port:res.get(port)}); };
    const prog = n => { done = n; ch.onmessage({progress:{done, total}}); };
    ch.onmessage({start:{host:r.host, ip:'198.51.100.1', total}});
    if (slow) {
      // 8080 arrives before 8022; then five filtered ports every 150 ms (~3 s in all: time to press "Ferma")
      await wait(100); if (!stopped) { open(8080, 'HTTP/1.1 200 OK'); for (let p = 8000; p < 8010; p++) set(p, 'CLOSED'); set(8010, 'CLOSED'); prog(11); }
      await wait(100); if (!stopped) { open(8022, 'SSH-2.0-OpenSSH_9.6'); prog(12); }
      for (const p of list) {
        if (res.has(p)) continue;
        if (done % 5 === 0) { await wait(150); if (stopped) break; }
        set(p, 'FILTERED'); prog(done + 1);
      }
    } else if (r.host === 'firewall') {
      list.forEach(p => set(p, 'FILTERED')); prog(total);
    } else {
      open(443, ''); set(80, 'CLOSED'); prog(2);
      open(22, 'SSH-2.0-OpenSSH_9.6');
      set(445, 'FILTERED', 'Bloccata sul PC (errore 10013): firewall o antivirus locale'); set(3389, 'FILTERED'); prog(total);
    }
    return end({host:r.host, ip:'198.51.100.1', results:[...res.values()].sort((a, b) => a.port - b.port), total, stopped});
  }
  if (cmd === 'numconv') {
    // simplified conversion (BigInt) to exercise the UI; the real logic is in numconv.rs
    const r = args.req; let v;
    try {
      const t = r.value.replace(/[\s_:]/g, '');
      if (r.base === 'dec') v = BigInt(t.replace(/\./g, ''));
      else if (r.base === 'hex') v = BigInt('0x' + t.replace(/^0x/i, ''));
      else if (r.base === 'bin') v = BigInt('0b' + t.replace(/^0b/i, ''));
      else { const o = t.split('.').map(Number); if (o.length !== 4 || o.some(x => !(x >= 0 && x <= 255))) throw 0;
        v = BigInt(o[0]) * 16777216n + BigInt(o[1] * 65536 + o[2] * 256 + o[3]); }
    } catch(e) { throw 'Carattere non valido nell\'esadecimale'; }
    const bits = r.width === 'free' ? Math.max(8, Math.ceil(v.toString(2).length / 8) * 8) : +r.width;
    v = v & ((1n << BigInt(bits)) - 1n);
    const raw = v.toString(2).padStart(bits, '0');
    const hex = v.toString(16).toUpperCase().padStart(bits / 4, '0').match(/../g).join(' ');
    const sv = r.width !== 'free' && raw[0] === '1' ? v - (1n << BigInt(bits)) : v;
    return {bits, dec:(r.signed ? sv : v).toString(), hex, bin:raw.match(/.{4}/g).join(' '), raw,
      unsigned:v.toLocaleString('it-IT'), signed:r.width === 'free' ? null : sv.toLocaleString('it-IT'),
      bytes_le:hex.split(' ').reverse().join(' '), swapped:bits > 8 ? '1' : null,
      ipv4:bits === 32 ? [24, 16, 8, 0].map(s => Number((v >> BigInt(s)) & 255n)).join('.') : null,
      ascii:bits === 8 && v >= 32n && v < 127n ? '"' + String.fromCharCode(Number(v)) + '"' : null,
      ones:[...raw].filter(c => c === '1').length, msb:v ? v.toString(2).length - 1 : null, warning:null};
  }
  if (cmd === 'uuid_generate') {
    const r = args.req;
    if (r.version === '5') {
      const names = r.names.split('\n').map(x => x.trim()).filter(Boolean);
      if (!names.length) throw 'Scrivi almeno un nome (uno per riga)';
      return {version:5, uuids:names.map((n, i) => '886313e1-3b8a-5372-9b90-0c9aee199e5' + i.toString(16)), names, namespace:'6ba7b810-9dad-11d1-80b4-00c04fd430c8'};
    }
    return {version:+r.version, uuids:Array.from({length:+r.count}, (_, i) => (r.version === '7' ? '019a4e2b-1c3d-7' : 'f47ac10b-58cc-4') + '372-a567-0e02b2c3d4' + String(i).padStart(2, '0'))};
  }
  if (cmd === 'uuid_inspect') return {canonical:args.req.text.toLowerCase(), version:7, version_name:'v7 — ordinato nel tempo (ms Unix)', variant:'RFC 9562 (standard)',
    time_ms:1762243200123, time_utc:'2025-11-04 08:00:00.123 UTC', node:null, node_random:false, clock_seq:null,
    guid_bytes:'0B C1 7A F4 CC 58 72 43 A5 67 0E 02 B2 C3 D4 00', ldap_filter:'(objectGUID=\\0B\\C1\\7A\\F4\\CC\\58\\72\\43\\A5\\67\\0E\\02\\B2\\C3\\D4\\00)'};
  if (cmd === 'smtp_test') {
    const r = args.req, ch = args.onEvent;
    if (r.host === 'chiuso') throw 'Porta 25 chiusa su chiuso (connessione rifiutata)';
    const T = ['Connessione a 192.0.2.10:' + r.port + ' (' + r.host + ')', '220 mail01.corp.example Microsoft ESMTP MAIL Service ready [12 ms]',
      'EHLO srv01.corp.example', '250-mail01.corp.example Hello', '250-SIZE 37748736', '250-STARTTLS', '250 CHUNKING [3 ms]',
      'STARTTLS', '220 2.0.0 SMTP server ready [2 ms]', '--- TLS: TLSv1.2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, certificato verificato [21 ms]',
      'EHLO srv01.corp.example', '250-mail01.corp.example Hello', '250-AUTH NTLM LOGIN', '250 CHUNKING [2 ms]'];
    if (r.auth) T.push('AUTH LOGIN', '334 VXNlcm5hbWU6 [1 ms]', 'dXRlbnRl', '334 UGFzc3dvcmQ6 [1 ms]', '********', '235 2.7.0 Authentication successful [40 ms]');
    T.push('QUIT', '221 2.0.0 Service closing transmission channel [1 ms]');
    T.forEach(l => ch.onmessage({line:l}));
    ch.onmessage({done:true});
    const C = (name, status, detail) => ({name, status, detail});
    const checks = [C('Connessione', 'ok', '4 ms'), C('Banner', 'ok', T[1].replace(/ \[.*/, '')),
      C('Reverse DNS', 'ok', '192.0.2.10 → mail01.corp.example → 192.0.2.10 (diretto e inverso coincidono)'),
      C('Hostname valido', 'ok', 'mail01.corp.example è un FQDN'), C('Banner e reverse DNS', 'ok', 'Il nome nel banner coincide con il PTR (mail01.corp.example)'),
      C('TLS', 'ok', 'TLSv1.2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (STARTTLS)'), C('Certificato', 'ok', 'mail01.corp.example, emesso da CORP-CA, scade tra 412 giorni'),
      C('EHLO', 'ok', 'SIZE, AUTH, CHUNKING'), C('Autenticazione offerta', 'info', 'NTLM LOGIN'), C('Dimensione massima', 'info', '36.0 MB (37748736 byte)')];
    if (r.relay) checks.push(C('Open relay', 'warn', 'Non determinabile: il mittente di prova è stato rifiutato (530 5.7.1 Client was not authenticated)'));
    if (r.auth) checks.push(C('Login', 'ok', 'Autenticato come ' + r.user + ' (LOGIN): 235 2.7.0 Authentication successful'));
    checks.push(C('Tempo di transazione', 'ok', '0.112 s'));
    return {host:r.host, ip:'192.0.2.10', port:+r.port, ptr:'mail01.corp.example', ehlo_name:r.ehlo || 'srv01.corp.example', tls_mode:'starttls',
      banner:checks[1].detail, extensions:['SIZE', 'AUTH', 'CHUNKING'], auth_mechs:['NTLM', 'LOGIN'], connect_ms:4, total_ms:112, sent:false, checks, transcript:T,
      tls:{host:r.host, port:+r.port, verified:true, subject:{commonName:'mail01.corp.example'}, issuer:{commonName:'CORP-CA'}, not_before:'2025-12-18T10:00:00',
        not_after:'2027-12-18T10:00:00', days_remaining:412, serial:'1A2B', sans:['DNS: mail01.corp.example', 'DNS: mail.example.it'], cipher:'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        tls_version:'TLSv1.2', expired:false, expiring_soon:false, chain:['mail01.corp.example', 'CORP-CA']}};
  }
  // TLS certificates (checks, certificate, chain, version and cipher scan in streaming).
  // "www.example.com" = misconfigured server (intermediate not sent, expires soon; with the scan TLS 1.0/1.1 and 3DES),
  // "legacy.corp.example" = compatibility probe, "tls12.corp.example" = fallback, any other host = all fine.
  // With scan: the result arrives at once on the Channel, then one suite every 60 ms; "Ferma" (ssl_stop) gives a partial result.
  if (cmd === 'ssl_stop') { const f = window.__probe.ssl; if (f) f(); return null; }
  if (cmd === 'ssl') {
    if (window.__probe.ssl) window.__probe.ssl();
    let stopped = false, wake = null;
    const me = window.__probe.ssl = () => { stopped = true; if (wake) wake(); };
    const wait = ms => stopped ? Promise.resolve() : new Promise(r => { wake = r; setTimeout(r, ms); });
    const end = v => { if (window.__probe.ssl === me) delete window.__probe.ssl; return v; };
    const r = args.req, h = r.host, ch = args.onEvent, legacy = h === 'legacy.corp.example', t12 = h === 'tls12.corp.example', bad = h === 'www.example.com';
    const ck = (area, status, name, detail) => ({area, status, name, detail});
    const name = r.sni || h;
    const protocol = {tls:'TLS diretto', smtp:'SMTP con STARTTLS', imap:'IMAP con STARTTLS', pop3:'POP3 con STLS', rdp:'RDP'}[r.protocol] || (+r.port === 25 ? 'SMTP con STARTTLS' : 'TLS diretto');
    const cipher = legacy ? 'TLS_RSA_WITH_AES_128_CBC_SHA' : t12 ? 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' : 'TLS13_AES_256_GCM_SHA384';
    const tls_version = legacy ? 'TLSv1.0' : t12 ? 'TLSv1.2' : 'TLSv1.3';
    const compat = legacy ? "Il server rifiuta l'handshake di questa app sia con TLS 1.3 sia con TLS 1.2 (primo errore: Handshake TLS fallito: Connessione in corso interrotta forzatamente dall'host remoto. (os error 10054)). Con l'offerta di compatibilità sceglie TLSv1.0 con TLS_RSA_WITH_AES_128_CBC_SHA, che l'app non supporta: certificato letto dal ServerHello, senza completare l'handshake."
      : t12 ? 'Il server rifiuta il ClientHello con TLS 1.3 (Handshake TLS fallito: connessione chiusa): handshake riuscito offrendo solo TLS 1.2.' : '';
    const days = bad ? 23 : 59, not_after = bad ? '2026-12-09T08:14:01' : '2027-01-10T00:00:00', not_before = bad ? '2026-09-10T08:14:02' : '2026-01-10T00:00:00';
    const sans = bad ? ['DNS: www.example.com', 'DNS: example.com', 'DNS: *.cdn.example.com', 'IP: 2001:db8::10'] : ['DNS: ' + name];
    const cert = {name, issuer_name:'Example Issuing CA R3', subject:'CN=' + name, issuer:'C=IT, O=Example Trust Services, CN=Example Issuing CA R3',
      not_before, not_after, days_remaining:days, lifetime_days: bad ? 90 : 365, expired:false, not_yet_valid:false, key:'RSA 2048 bit', signature:'SHA-256 con RSA',
      usage:['Autenticazione server', 'Autenticazione client'], serial:'048E1B5C22A97F3061CC02D49A13B7E8550F',
      sha256:'9F:2C:41:7A:E0:5B:D3:18:66:AC:90:1E:F4:27:8D:B5:3C:71:0A:E9:54:C8:2F:6B:D0:13:A7:4E:98:1C:65:F2', sha1:'3B:A1:7E:04:C9:52:D8:6F:10:EB:95:2C:47:A3:0D:F6:81:5E:B2:79',
      sans, ocsp:['http://ocsp.ca.example.net'], crl: bad ? ['http://crl.ca.example.net/r3.crl'] : [], ca_issuers:['http://crt.ca.example.net/r3.cer'], sct: bad ? 3 : 0, self_signed:false, is_ca:false};
    const E = (role, nm, issuer_name, key, na, d, sent, status, note) => Object.assign({role, name:nm, issuer_name, key, signature:'SHA-256 con RSA', not_after:na,
      days_remaining:d, expired:false, self_signed:role === 'Radice', sent, status}, note ? {note} : {});
    const chain_info = [E('Server', name, 'Example Issuing CA R3', 'RSA 2048 bit', not_after, days, 'sent', bad ? 'warn' : 'ok'),
      E('Intermedia', 'Example Issuing CA R3', 'Example Root CA X1', 'RSA 2048 bit', '2029-03-15T00:00:00', 850, bad ? 'missing' : 'sent', bad ? 'err' : 'ok',
        bad ? "Non inviata dal server: questo PC l'ha recuperata da sola." : ''),
      E('Radice', 'Example Root CA X1', 'Example Root CA X1', 'RSA 4096 bit', '2037-06-04T00:00:00', 3850, 'store', 'ok')];
    // in the order the backend sends them (by area): the UI does the severity ordering
    const checks = [ck('Certificato', 'ok', 'Attendibilità', "catena verificata con l'archivio dei certificati di questo PC"),
      ck('Certificato', bad ? 'warn' : 'ok', 'Scadenza', 'tra ' + days + ' giorni (' + not_after.slice(0, 10) + ')'),
      ck('Certificato', 'ok', 'Nome', name + ' coperto dai nomi alternativi'), ck('Certificato', 'ok', 'Chiave', 'RSA 2048 bit'),
      ck('Certificato', 'ok', 'Firma', 'SHA-256 con RSA'), ck('Certificato', 'ok', 'Durata', (bad ? 90 : 365) + ' giorni'),
      ck('Certificato', 'info', 'Trasparenza', bad ? '3 SCT incorporati nel certificato' : 'nessun SCT nel certificato (normale per le CA interne)'),
      bad ? ck('Catena', 'err', 'Certificato intermedio', 'non inviato dal server (Example Issuing CA R3): questo PC lo ha recuperato da solo, altri client rifiutano la connessione')
          : ck('Catena', 'ok', 'Catena', '2 certificati inviati, nell\'ordine corretto'),
      legacy ? ck('Revoca', 'info', 'Revoca', 'il certificato indica un server OCSP') : ck('Revoca', 'info', 'OCSP stapling', 'non inviato; il certificato indica un server OCSP')];
    if (compat) checks.push(ck('Protocolli', 'warn', 'Compatibilità', compat));
    checks.push(legacy ? ck('Protocolli', 'warn', 'Scelta del server', 'TLS 1.0 con ' + cipher + ': versione obsoleta')
      : ck('Protocolli', 'ok', 'Negoziato', tls_version.replace('TLSv', 'TLS ') + ' con ' + cipher.replace('TLS13_', 'TLS_')));
    if (bad) checks.push(ck('Certificato', 'info', 'SNI', 'senza SNI il server presenta un altro certificato (<b>default</b>.example.net)'));
    const d = Object.assign({host:h, port:+r.port, verified:true, subject:{commonName:name}, issuer:{commonName:'Example Issuing CA R3', organizationName:'Example Trust Services'},
      not_before, not_after, days_remaining:days, serial:cert.serial, sans, cipher, tls_version, expired:false, expiring_soon:bad, chain:[name, 'Example Issuing CA R3'],
      cert, chain_info, checks, protocol}, legacy ? {partial:true} : {ocsp_stapled:false}, compat ? {compat} : {}, r.sni ? {sni:r.sni} : {});
    if (!r.scan) return end(d);
    ch.onmessage({result:d});
    const S = (nm, level, kx, enc) => ({name:nm, level, kx, enc});
    const old = [S('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'weak', 'ECDHE', 'AES-256 CBC'), S('TLS_RSA_WITH_AES_128_CBC_SHA', 'weak', 'RSA', 'AES-128 CBC'), S('TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'bad', 'RSA', '3DES CBC')];
    const V = [['TLS 1.3', 'ok', [S('TLS_AES_256_GCM_SHA384', '', 'ECDHE', 'AES-256 GCM'), S('TLS_AES_128_GCM_SHA256', '', 'ECDHE', 'AES-128 GCM'), S('TLS_CHACHA20_POLY1305_SHA256', '', 'ECDHE', 'ChaCha20-Poly1305')]],
      ['TLS 1.2', 'ok', [S('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', '', 'ECDHE', 'AES-256 GCM'), S('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', '', 'ECDHE', 'AES-128 GCM')]
        .concat(bad ? [S('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'weak', 'ECDHE', 'AES-256 CBC'), S('TLS_RSA_WITH_AES_256_GCM_SHA384', 'weak', 'RSA', 'AES-256 GCM'), old[1], old[2]] : [])],
      ['TLS 1.1', 'warn', bad ? old : []], ['TLS 1.0', 'err', bad ? old : []]];
    const versions = []; let tried = 0;
    for (const [vn, st, cs] of V) {
      const got = [];
      for (const c of cs) {
        await wait(60); if (stopped) break;
        ch.onmessage({scan:{progress:{tried: ++tried}}}); got.push(c); ch.onmessage({scan:{cipher:{version:vn, cipher:c}}});
      }
      if (stopped) { if (got.length) versions.push({name:vn, accepted:true, status:st, ciphers:got}); break; }
      ch.onmessage({scan:{progress:{tried: ++tried}}});
      const v = {name:vn, accepted:cs.length > 0, status: cs.length ? st : 'off', ciphers:got};
      versions.push(v); ch.onmessage({scan:{version:v}});
    }
    const more = stopped ? [ck('Protocolli', 'info', 'Scansione', 'fermata: risultato parziale')]
      : bad ? [ck('Protocolli', 'err', 'TLS 1.0', 'accettato: obsoleto, da disattivare'), ck('Protocolli', 'warn', 'TLS 1.1', 'accettato: obsoleto, da disattivare'),
          ck('Protocolli', 'ok', 'TLS 1.3 e TLS 1.2', 'accettati'), ck('Cipher', 'err', '3DES', 'accettata con TLS 1.0, TLS 1.1, TLS 1.2: TLS_RSA_WITH_3DES_EDE_CBC_SHA'),
          ck('Cipher', 'warn', 'Forward secrecy', '3 suite con scambio RSA: senza forward secrecy'), ck('Cipher', 'info', 'CBC', '3 suite CBC: meglio GCM o ChaCha20-Poly1305')]
      : [ck('Protocolli', 'ok', 'TLS 1.3 e TLS 1.2', 'accettati'), ck('Protocolli', 'ok', 'Versioni obsolete', 'TLS 1.0 e TLS 1.1 rifiutati'),
          ck('Cipher', 'ok', 'Cipher', '5 suite, tutte con forward secrecy e cifratura autenticata')];
    return end(Object.assign({}, d, {checks:checks.concat(more), scan:{versions, tried, time_ms:9400, stopped}}));
  }
  // DNS: comparison between servers with the response flags, and domain analysis.
  // "example.com" = domain with defects (one name server down, different serials, registry and zone differ, signature about to expire),
  // "corp.example" = network that does not let DNS out (only the PC DNS, unsigned zone), "nessuno.example" = NXDOMAIN.
  if (cmd === 'dns') {
    const r = args.req, two = r.servers.length > 1;
    const data = r.type === 'DNSKEY' ? ['256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWz', '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d'] : r.type === 'MX' ? ['10 mail.example.com.'] : ['203.0.113.10'];
    const one = (server, ip, flags, d) => ({server, server_ip:ip, status:'NOERROR', time_ms:12, data:d, flags,
      answers:d.map(x => r.host + '. 300 IN ' + r.type + ' ' + x)});
    return {name:r.host, type:r.type, results: two
      ? [one('resolver di sistema', '172.16.7.1', ['RA'], data), one(r.servers[1], r.servers[1], ['RA', 'AD'], r.type === 'A' ? ['203.0.113.99'] : data)]
      : [one(r.servers[0] || 'resolver di sistema', r.servers[0] || '172.16.7.1', ['RA'], data)]};
  }
  if (cmd === 'dns_domain') {
    const r = args.req, ck = (area, status, name, detail) => ({area, status, name, detail});
    if (r.domain === 'nessuno.example') throw 'Il dominio nessuno.example non esiste (NXDOMAIN)';
    const R = (type, value, ttl, name) => Object.assign({type, value, ttl}, name ? {name} : {});
    if (r.domain.endsWith('corp.example')) {
      const N = name => ({name, ipv4:['198.51.100.' + name[2]], ipv6:[], parent:null, zone:true, responds:false, authoritative:false, serial:null, time_ms:null, status:'info', note:'Non raggiungibile da questo PC.'});
      return {domain:'corp.example', zone_note: r.domain === 'corp.example' ? undefined : r.domain + " fa parte della zona corp.example: l'analisi riguarda la zona.",
        parent:'example', parent_ok:false, addresses:['172.16.7.10'], time_ms:4100, empty_types:['AAAA', 'MX', 'TXT', 'CAA', 'HTTPS', 'DNSKEY', 'DS', 'TLSA'],
        records:[R('A', '172.16.7.10', 3600), R('NS', 'ns1.corp.example.', 3600), R('NS', 'ns2.corp.example.', 3600), R('SOA', 'ns1.corp.example. hostmaster.corp.example. 4012 900 600 86400 3600', 3600)],
        nameservers:[N('ns1.corp.example'), N('ns2.corp.example')],
        dnssec:{label:'Non firmato', level:'', rows:[], validation:[{status:'info', name:'Resolver che valida', detail:'non raggiungibile da questo PC: validazione non controllata'},
          {status:'info', name:'DNS di questo PC', detail:'risponde senza flag AD: non valida (o non lo dichiara)'}]},
        checks:[ck('Delega', 'info', 'Name server', "nessun name server raggiungibile da questo PC (porta 53 verso l'esterno chiusa?): delega letta solo dal DNS del PC, seriali e risposte autoritative non controllati"),
          ck('Delega', 'warn', 'Reti', 'tutti i name server stanno sulla stessa rete (198.51.100.0/24)'), ck('Trasferimento', 'info', 'AXFR', 'non provato (casella spenta)'),
          ck('SOA', 'warn', 'Valori', 'expire di 86400 s: meno di 7 giorni'), ck('DNSSEC', 'info', 'DNSSEC', 'zona non firmata: nessun DS e nessuna chiave'),
          ck('Record', 'info', 'CAA', 'assente: qualsiasi autorità può emettere certificati per il dominio'), ck('Record', 'info', 'IPv6', 'nessun record AAAA')]};
    }
    const N = (name, ipv4, ipv6, parent, zone, serial, ms, status, note, axfr) => Object.assign({name, ipv4:[ipv4], ipv6: ipv6 ? [ipv6] : [], parent, zone,
      responds:serial !== null, authoritative:serial !== null, serial, time_ms:ms, status}, note ? {note} : {}, r.axfr && serial !== null ? {axfr} : {});
    const checks = [ck('Delega', 'err', 'Name server', 'ns3.example.net (198.51.100.53) non risponde da questo PC, né su UDP né su TCP'),
      ck('Delega', 'err', 'Seriale SOA', 'ns2.example.net ha 2026111501, gli altri 2026111603: zona non allineata'),
      ck('Delega', 'warn', 'NS del registro e della zona', 'il registro delega a ns1.example.net, ns2.example.net, ns3.example.net; la zona dichiara ns1.example.net, ns2.example.net, ns4.example.net'),
      ck('Delega', 'ok', 'Reti', 'i name server stanno su 2 reti diverse'),
      r.axfr ? ck('Trasferimento', 'err', 'AXFR', 'trasferimento di zona consentito a chiunque da ns4.example.net') : ck('Trasferimento', 'info', 'AXFR', 'non provato (casella spenta)'),
      ck('SOA', 'ok', 'Valori', 'refresh 7200, retry 3600, expire 1209600, minimo 3600'),
      ck('DNSSEC', 'ok', 'Validazione', 'il resolver che valida risponde con il flag AD'),
      ck('DNSSEC', 'ok', 'DS e DNSKEY', 'il DS pubblicato nel registro corrisponde alla chiave 2371'),
      ck('DNSSEC', 'info', 'Algoritmo', '13 (ECDSA P-256 con SHA-256)'),
      ck('DNSSEC', 'warn', 'Firme', 'la firma del record SOA: scade il 17 novembre 2026 (tra 3 ore)'),
      ck('Record', 'info', 'TTL', 'indirizzi con TTL di 30 secondi: molto basso'),
      ck('Record', 'info', 'Jolly', '*.example.com risponde: ogni nome inesistente viene risolto'),
      ck('Record', 'ok', 'CAA', 'presente: 0 issue "<b>ca</b>.example.net"'), ck('Record', 'ok', 'IPv6', 'record AAAA presente')];
    return {domain:'example.com', parent:'com', parent_ok:true, addresses:['203.0.113.10', '2001:db8::10'], time_ms:2300, checks, empty_types:['HTTPS'],
      records:[R('A', '203.0.113.10', 30), R('AAAA', '2001:db8::10', 3600), R('NS', 'ns1.example.net.', 86400), R('NS', 'ns2.example.net.', 86400), R('NS', 'ns4.example.net.', 86400),
        R('SOA', 'ns1.example.net. hostmaster.example.com. 2026111603 7200 3600 1209600 3600', 3600), R('MX', '10 mail.example.com.', 3600),
        R('TXT', '"v=spf1 mx ip4:203.0.113.0/28 -all"', 3600), R('CAA', '0 issue "ca.example.net"', 3600),
        R('DNSKEY', '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==', 3600),
        R('DNSKEY', '256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==', 3600),
        R('DS', '2371 13 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766', 86400),
        R('TLSA', '3 1 1 9f2c417ae05bd31866ac901ef4278db53c710ae954c82f6bd013a74e981c65f2', 300, '_443._tcp.example.com')],
      nameservers:[N('ns1.example.net', '198.51.100.51', '2001:db8:53::1', true, true, 2026111603, 12, 'ok', '', false),
        N('ns2.example.net', '198.51.100.52', '', true, true, 2026111501, 14, 'err', 'Seriale più vecchio degli altri: la zona non è allineata.', false),
        N('ns3.example.net', '198.51.100.53', '', true, false, null, null, 'err', 'Non risponde da questo PC (UDP e TCP 53). Delegato dal registro ma non dichiarato dalla zona.'),
        N('ns4.example.net', '203.0.113.53', '2001:db8:53::4', false, true, 2026111603, 31, 'warn', 'Dichiarato dalla zona ma non delegato dal registro.', true)],
      dnssec:{label:'Firmato e valido', level:'ok', rows:[
          {status:'ok', name:'DS nel registro', what:'id 2371 · algoritmo 13 · digest SHA-256', detail:'corrisponde alla chiave 2371'},
          {status:'ok', name:'DNSKEY 2371', what:'KSK (257) · ECDSA P-256 con SHA-256', detail:'firma le chiavi della zona'},
          {status:'ok', name:'DNSKEY 40111', what:'ZSK (256) · ECDSA P-256 con SHA-256', detail:'firma i record'},
          {status:'warn', name:'Firma di SOA', what:'chiave 40111 · valida dal 5 novembre 2026', detail:'scade il 17 novembre 2026 (tra 3 ore)'},
          {status:'ok', name:'Firma di DNSKEY', what:'chiave 2371 · valida dal 1 novembre 2026', detail:'scade il 1 dicembre 2026 (14 giorni)'},
          {status:'ok', name:'Negazione', what:'NSEC3 · 0 iterazioni · senza sale', detail:'nomi inesistenti provati senza elencare la zona'}],
        validation:[{status:'ok', name:'Resolver che valida (1.1.1.1), query normale', detail:'NOERROR con flag AD: la catena è valida'},
          {status:'ok', name:'Resolver che valida (1.1.1.1), con CD', detail:'NOERROR: stessa risposta senza validazione'},
          {status:'info', name:'DNS di questo PC', detail:'risponde senza flag AD: non valida (o non lo dichiara)'}]}};
  }
  if (cmd === 'headers') {
    // checks, cookies (without value), CSP, CDN; the steps have time, HSTS and cookies
    const ck = (area, status, name, detail) => ({area, status, name, detail});
    if (args.req.url === 'www.example.com') return {status_code:200, status_text:'OK', final_url:'https://www.example.com/it/', authenticated:true, cdn:'Cloudflare · MXP',
      redirects:['https://example.com/', 'https://www.example.com/', 'https://www.example.com/it/'],
      hops:[{url:'https://example.com/', status:301, transport:'https', time_ms:112, hsts:false, cookies:1},
            {url:'https://www.example.com/', status:302, transport:'https', time_ms:96, hsts:true, cookies:0},
            {url:'https://www.example.com/it/', status:200, transport:'https', time_ms:141, hsts:true, cookies:3}],
      headers:{'Cache-Control':'no-store', 'Cf-Cache-Status':'HIT', 'Cf-Ray':'8a1b2c3d4e5f6789-MXP',
        'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'self'",
        'Content-Type':'text/html; charset=utf-8', 'Server':'nginx/1.18.0',
        'Set-Cookie':'__Host-sid=(nascosto); Path=/; Secure; HttpOnly; SameSite=Strict\nsessionid=(nascosto); Domain=.example.com; Path=/; HttpOnly; SameSite=Lax\nlang=(nascosto); Path=/; Max-Age=31536000; Secure',
        'Strict-Transport-Security':'max-age=86400', 'X-Content-Type-Options':'nosniff', 'X-Powered-By':'PHP/7.4.3', 'X-Xss-Protection':'1; mode=block'},
      cookies:[{name:'_track', secure:false, http_only:false, same_site:'None', domain:'.example.com', path:'/', lifetime:'2 anni', hop:0, status:'err', note:'SameSite=None senza Secure: il browser lo scarta'},
        {name:'__Host-sid', secure:true, http_only:true, same_site:'Strict', domain:'', path:'/', lifetime:'sessione', hop:2, status:'ok', note:''},
        {name:'sessionid', secure:false, http_only:true, same_site:'Lax', domain:'.example.com', path:'/', lifetime:'sessione', hop:2, status:'err', note:'senza Secure: viaggia anche su HTTP'},
        {name:'lang', secure:true, http_only:false, same_site:'', domain:'', path:'/', lifetime:'365 giorni', hop:2, status:'info', note:'senza SameSite (il browser applica Lax)'}],
      csp:{report_only:false, policies:1, missing:['base-uri'], directives:[
        {name:'default-src', status:'', sources:[{value:"'self'", level:''}]},
        {name:'script-src', status:'err', sources:[{value:"'self'", level:''}, {value:"'unsafe-inline'", level:'bad'}, {value:"'unsafe-eval'", level:'bad'}, {value:'https://cdn.example.com', level:''}]},
        {name:'style-src', status:'warn', sources:[{value:"'self'", level:''}, {value:"'unsafe-inline'", level:'weak'}]},
        {name:'img-src', status:'', sources:[{value:"'self'", level:''}, {value:'data:', level:''}, {value:'https:', level:''}]},
        {name:'frame-ancestors', status:'ok', sources:[{value:"'self'", level:''}]}]},
      checks:[ck('Trasporto', 'ok', 'HTTP porta a HTTPS', 'http://www.example.com/ → 301 → https://www.example.com/ (38 ms)'),
        ck('Trasporto', 'ok', 'Certificato', 'valido su tutti i passi HTTPS'),
        ck('Trasporto', 'warn', 'HSTS', 'max-age=86400 (1 giorno): consigliato almeno 6 mesi; senza includeSubDomains'),
        ck('Trasporto', 'warn', 'HSTS sui redirect', 'assente su https://example.com/ (passo 1)'),
        ck('Header', 'ok', 'X-Content-Type-Options', 'nosniff'),
        ck('Header', 'ok', 'Protezione dai frame', "CSP frame-ancestors 'self' (X-Frame-Options non serve)"),
        ck('Header', 'warn', 'Referrer-Policy', 'assente (i browser applicano strict-origin-when-cross-origin)'),
        ck('Header', 'warn', 'Permissions-Policy', 'assente'),
        ck('Header', 'info', 'Isolamento cross-origin', 'COOP, COEP e CORP assenti'),
        ck('Header', 'info', 'X-Xss-Protection', 'obsoleto: i browser lo ignorano'),
        ck('CSP', 'err', 'script-src', "'unsafe-inline' e 'unsafe-eval' permettono script non previsti"),
        ck('CSP', 'warn', 'style-src', "'unsafe-inline' indebolisce la protezione"),
        ck('CSP', 'warn', 'base-uri', 'assente: non è coperta da default-src'),
        ck('Cookie', 'err', '_track', 'SameSite=None senza Secure: il browser lo scarta'),
        ck('Cookie', 'err', 'sessionid', 'senza Secure: viaggia anche su HTTP'),
        ck('Cookie', 'info', 'lang', 'senza SameSite (il browser applica Lax)'),
        ck('Server', 'warn', 'Server', 'rivela la versione: nginx/1.18.0'),
        ck('Server', 'warn', 'X-Powered-By', 'rivela il software: PHP/7.4.3'),
        ck('Server', 'info', 'CDN', 'Cloudflare, datacenter MXP, cache HIT')]};
    // invalid certificate, no CSP, no cookie
    return {status_code:200, status_text:'OK', final_url:'https://web01.corp.example/', authenticated:false, cdn:'',
      headers:{'Strict-Transport-Security':'max-age=0', 'X-Content-Type-Options':'nosniff', 'Server':'nginx'},
      redirects:['http://web01.corp.example/', 'https://web01.corp.example/'], cookies:[], csp:null,
      hops:[{url:'http://web01.corp.example/', status:301, transport:'http', time_ms:4, hsts:null, cookies:0},
            {url:'https://web01.corp.example/', status:200, transport:'https-invalid', time_ms:9, hsts:false, cookies:0,
             tls_error:'La catena di certificati è stata emessa da un\'autorità non attendibile. <b>x</b>'}],
      checks:[ck('Trasporto', 'err', 'Certificato', 'non valido (destinazione): la risposta non è autenticata. <b>x</b>'),
        ck('Trasporto', 'ok', 'HTTP porta a HTTPS', 'http://web01.corp.example/ → 301 → https://web01.corp.example/'),
        ck('Trasporto', 'err', 'HSTS', 'max-age=0 disattiva HSTS'),
        ck('Header', 'ok', 'X-Content-Type-Options', 'nosniff'),
        ck('Header', 'err', 'Protezione dai frame', 'né X-Frame-Options né CSP frame-ancestors'),
        ck('CSP', 'err', 'Content-Security-Policy', 'assente')]};
  }
  // Email: {domain_report} or {message}. "example.com" = SPF over the limit, DMARC p=none, one selector
  // with a short key, MTA-STS in testing; any other domain = no records. Headers with "Ordine" in the subject = message
  // authenticated with a slow hop; the others = SPF and DMARC failed, marked as spam.
  if (cmd === 'emailheader') {
    const r = args.req, ck = (area, status, name, detail) => ({area, status, name, detail});
    const row = (status, name, value, detail) => ({status, name, value, detail});
    if (r.raw_header) {
      const good = /Ordine/.test(r.raw_header);
      const H = (from, from_ip, by, w, tls, time, delay_s, status) => Object.assign({from, by, with:w, tls, time, delay_s, status}, from_ip ? {from_ip} : {});
      if (good) return {message:{subject:'Ordine n. 4012', from:'ordini@example.org', from_domain:'example.org', return_path:'bounce@invio.example.org', total_s:44,
        auth:{server:'spam01.corp.example', spf:'pass', dkim:'pass', dmarc:'pass', count:2},
        hops:[H('', '192.0.2.44', 'mail-out.example.org', 'ESMTPSA', 'TLS 1.3', 1793351642, null, ''), H('mail-out.example.org', '198.51.100.25', 'mx1.example.com', 'ESMTPS', 'TLS 1.3', 1793351644, 2, ''),
          H('mx1.example.com', '203.0.113.10', 'spam01.corp.example', 'ESMTPS', 'TLS 1.2', 1793351685, 41, 'warn'), H('spam01.corp.example', '172.16.7.20', 'mail01.corp.example', 'ESMTP', '', 1793351686, 1, '')],
        scores:[row('ok', 'X-Spam-Status', 'No, score=2.1 required=5.0', 'non segnato come posta indesiderata'), row('ok', 'X-MS-Exchange-Organization-SCL', '1', 'sotto la soglia della posta indesiderata')],
        signatures:[{domain:'example.org', selector:'s1'}],
        headers:[['Received', 'from spam01.corp.example ([172.16.7.20]) by mail01.corp.example with ESMTP; Fri, 30 Oct 2026 10:14:46 +0100'], ['From', '"Ufficio <b>Ordini</b>" <ordini@example.org>'],
          ['Reply-To', 'assistenza@example.net'], ['Subject', 'Ordine n. 4012']],
        checks:[ck('Autenticazione', 'ok', 'SPF', 'pass per invio.example.org, allineato al mittente'), ck('Autenticazione', 'ok', 'DKIM', 'pass, firma di example.org, allineato al mittente'),
          ck('Autenticazione', 'ok', 'DMARC', 'pass per example.org'),
          ck('Autenticazione', 'info', 'Chi lo dice', 'esiti dal primo Authentication-Results (spam01.corp.example): controlla che sia il tuo server di posta; gli altri 1 più in basso possono venire dal mittente e non sono considerati'),
          ck('Mittente', 'ok', 'From e Return-Path', 'stesso dominio: example.org'), ck('Mittente', 'warn', 'Reply-To', 'risposte verso un altro dominio: assistenza@example.net'),
          ck('Percorso', 'warn', 'Ritardo', '41 s prima di spam01.corp.example (passo 3)'), ck('Percorso', 'info', 'Cifratura', 'TLS dichiarato su 3 passi su 4'),
          ck('Antispam', 'info', 'Punteggi', 'X-Spam-Status No, score=2.1 required=5.0 · X-MS-Exchange-Organization-SCL 1')]}};
      return {message:{subject:'Prova', from:'tizio@altro.example.net', from_domain:'altro.example.net', return_path:'x@altro.example.net', total_s:null,
        auth:{server:'', spf:'fail', dkim:'none', dmarc:'fail', count:2}, hops:[H('a', '', 'b', '', '', null, null, '')],
        scores:[row('warn', 'X-Spam-Flag', 'YES', 'segnato come posta indesiderata')], signatures:[], headers:[['Subject', 'Prova'], ['Authentication-Results', 'spf=fail']],
        checks:[ck('Autenticazione', 'err', 'SPF', 'fail per altro.example.net, allineato al mittente'), ck('Autenticazione', 'warn', 'DKIM', 'none'), ck('Autenticazione', 'err', 'DMARC', 'fail per example.org'),
          ck('Autenticazione', 'info', 'Chi lo dice', 'esiti dal primo Authentication-Results: controlla che sia il tuo server di posta; gli altri 1 più in basso possono venire dal mittente e non sono considerati'),
          ck('Mittente', 'warn', 'Nome visualizzato', "mostra direzione@example.org, ma l'indirizzo vero è tizio@altro.example.net"),
          ck('Percorso', 'info', 'Cifratura', 'TLS dichiarato su 0 passi su 1'), ck('Antispam', 'warn', 'Giudizio', 'segnato come posta indesiderata da X-Spam-Flag')]}};
    }
    if (r.ip && !/^[0-9a-f.:]+$/i.test(r.ip)) throw 'IP da verificare non valido: ' + r.ip;
    if (r.domain !== 'example.com') return {domain_report:{domain:r.domain, selectors:r.selector ? [r.selector] : ['default', 'google', 'selector1'], bimi:'', mx:[], dkim:[],
      spf:{found:false, record:'', count:0, nodes:[], lookups:0, void_lookups:0, all:''}, dmarc:{found:false, record:'', name:'_dmarc.' + r.domain, policy:'', rows:[]}, mta_sts:{found:false, mode:'', rows:[]},
      checks:[ck('SPF', 'err', 'Record', 'assente: chiunque può inviare posta a nome del dominio senza che SPF lo segnali'),
        ck('DMARC', 'err', 'Record', 'assente: nessuna indicazione ai destinatari su che cosa fare dei messaggi falsi'),
        r.selector ? ck('DKIM', 'err', r.selector, 'nessun record per questo selettore') : ck('DKIM', 'info', 'Selettori', 'nessuno dei nomi più comuni: il selettore vero può avere un altro nome (si legge dagli header di un messaggio)'),
        ck('MX', 'warn', 'Server', "nessun record MX: la posta viene consegnata all'indirizzo del dominio, se esiste"),
        ck('MTA-STS', 'info', 'Record', 'assente: il TLS verso il dominio resta facoltativo'), ck('TLS-RPT', 'info', 'Rapporti', 'assente: nessun rapporto sui problemi di TLS'), ck('BIMI', 'info', 'Record', 'assente')]}};
    const N = (level, mechanism, lookups, result, status, note) => Object.assign({level, mechanism, lookups, result, status: status || ''}, note ? {note} : {});
    const hit = r.ip === '203.0.113.25';
    const nodes = [N(0, 'v=spf1 mx include:_spf.mail.example.net include:spf.crm.example.org ip4:203.0.113.0/28 -all', 0, 'example.com'),
      N(1, 'mx', 1, 'mail1.example.com 203.0.113.10 · mail2.example.com 203.0.113.11 2001:db8:25::11'),
      N(1, 'include:_spf.mail.example.net', 1, 'v=spf1 include:_a.mail.example.net include:_b.mail.example.net ~all'),
      N(2, 'include:_a.mail.example.net', 1, 'v=spf1 ip4:198.51.100.0/24 ~all'), N(3, 'ip4:198.51.100.0/24', 0, ''), N(3, '~all', 0, 'tutto il resto: softfail'),
      N(2, 'include:_b.mail.example.net', 1, 'v=spf1 a:out1.mail.example.net a:out2.mail.example.net a:out3.mail.example.net ~all'),
      N(3, 'a:out1.mail.example.net', 1, '192.0.2.201'), N(3, 'a:out2.mail.example.net', 1, '192.0.2.202'), N(3, 'a:out3.mail.example.net', 1, '192.0.2.203'), N(3, '~all', 0, 'tutto il resto: softfail'),
      N(2, '~all', 0, 'tutto il resto: softfail'),
      N(1, 'include:spf.crm.example.org', 1, 'v=spf1 a:r1.crm.example.org a:r2.crm.example.org a:r3.crm.example.org exists:%{i}.spf.crm.example.org ~all'),
      N(2, 'a:r1.crm.example.org', 1, '192.0.2.211'), N(2, 'a:r2.crm.example.org', 1, '192.0.2.212'),
      N(2, 'a:r3.crm.example.org', 1, '192.0.2.213', 'err', 'Ricerca numero 11: oltre il limite di 10, da qui in poi il record non viene più valutato.'),
      N(2, 'exists:%{i}.spf.crm.example.org', 1, 'non valutato (oltre il limite)', 'off'), N(2, '~all', 0, 'tutto il resto: softfail'),
      N(1, 'ip4:203.0.113.0/28', 0, hit ? 'corrisponde a 203.0.113.25' : '', hit ? 'ok' : ''), N(1, '-all', 0, 'tutto il resto: fail', r.ip && !hit ? 'ok' : '')];
    const sel = r.selector ? r.selector.split(',').map(x => x.trim()) : ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'smtp', 'dkim', 'email', 's1', 's2'];
    const checks = [ck('SPF', 'err', 'Limite di lookup', '11 ricerche DNS, il massimo è 10: i destinatari trattano il record come non valido (permerror)'),
      ck('SPF', 'ok', 'Chiusura', '-all: tutto il resto viene rifiutato')]
      .concat(r.ip ? [ck('SPF', 'info', 'IP ' + r.ip, 'permerror: decide ' + (hit ? 'ip4:203.0.113.0/28' : '-all'))] : [])
      .concat([ck('DMARC', 'warn', 'Policy', 'p=none: i messaggi che falliscono vengono consegnati lo stesso (solo monitoraggio)'), ck('DMARC', 'ok', 'Rapporti', 'aggregati inviati a mailto:dmarc@example.com'),
        ck('DKIM', 'ok', 'selector1', 'chiave RSA 2048 bit'), ck('DKIM', 'warn', 'selector2', 'RSA 1024 bit: chiave corta: usare 2048 bit'),
        ck('MX', 'ok', 'Server', '2 server, tutti con indirizzo'), ck('MX', 'info', 'Nome inverso', 'assente per mail2.example.com'),
        ck('MTA-STS', 'warn', 'Policy', 'mode=testing: i server senza TLS valido non vengono rifiutati'), ck('MTA-STS', 'ok', 'Server', 'la policy copre tutti gli MX del dominio'),
        ck('TLS-RPT', 'info', 'Rapporti', 'inviati a mailto:tlsrpt@example.com'), ck('BIMI', 'info', 'Record', 'assente')]);
    return {domain_report:{domain:'example.com', checks, selectors:sel, bimi:'',
      spf:Object.assign({found:true, record:nodes[0].mechanism, count:1, nodes, lookups:11, void_lookups:0, all:'-all'}, r.ip ? {ip:r.ip, ip_result:'permerror', ip_match: hit ? 'ip4:203.0.113.0/28' : '-all'} : {}),
      dmarc:{found:true, name:'_dmarc.example.com', record:'v=DMARC1; p=none; rua=mailto:dmarc@example.com', policy:'none', rows:[row('warn', 'p', 'none', 'nessuna azione sui messaggi che falliscono'),
        row('', 'sp', '(non indicata)', 'i sottodomini ereditano p=none'), row('', 'pct', '100', 'applicata a tutti i messaggi'), row('ok', 'rua', 'mailto:dmarc@example.com', 'rapporti aggregati'),
        row('', 'ruf', '(non indicato)', 'rapporti sui singoli messaggi'), row('', 'adkim / aspf', 'r / r', 'allineamento rilassato: vale anche un sottodominio')]},
      dkim:[{selector:'selector1', key:'RSA 2048 bit', record:'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvX3Zk1pQ8m2yQe7R', status:'ok'},
        {selector:'selector2', key:'RSA 1024 bit', record:'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC', status:'warn', note:'chiave corta: usare 2048 bit'}],
      mx:[{priority:10, host:'mail1.example.com', ipv4:['203.0.113.10'], ipv6:[], ptr:'mail1.example.com', status:'ok'},
        {priority:20, host:'mail2.example.com', ipv4:['203.0.113.11'], ipv6:['2001:db8:25::11'], ptr:'', status:'ok', note:'Senza nome inverso.'}],
      mta_sts:{found:true, mode:'testing', url:'https://mta-sts.example.com/.well-known/mta-sts.txt', rows:[row('ok', 'Record', '_mta-sts.example.com', 'v=STSv1; id=20261102T101500'),
        row('warn', 'mode', 'testing', 'solo rapporti: nessun rifiuto'), row('ok', 'mx', 'mail1.example.com, mail2.example.com', 'copre tutti gli MX del dominio'), row('', 'max_age', '604800', '7 giorni')]},
      tls_rpt:row('ok', 'TLS-RPT', '_smtp._tls.example.com', 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com')}};
  }
  // Wi-Fi: window.__wifi = 'ok' | 'none' | 'location' | 'radio'
  if (cmd === 'wifi_scan') {
    const mode = window.__wifi || 'ok';
    const A = {id:'{11111111-2222-3333-4444-555555555555}', name:'Intel(R) Wi-Fi 6E AX211 160MHz', connected:true, radio: mode === 'radio' ? 'off' : 'on'};
    const base = {adapters:[A], adapter:A.id, problem:null, warning:null, connection:null, networks:[], best24:null, best5:null, six_seen:false};
    if (mode === 'none') return Object.assign(base, {adapters:[], adapter:null, problem:{code:'no_adapter', title:'Nessuna scheda Wi-Fi su questo PC', detail:'Windows non segnala schede di rete wireless attive. Get-NetAdapter -Physical'}});
    if (mode === 'radio') return Object.assign(base, {problem:{code:'radio_off', title:'Wi-Fi spento', detail:'Il Wi-Fi è spento in Windows (modalità aereo o pulsante Wi-Fi).'}});
    const N = (o) => Object.assign({ssid:'', hidden:false, ssid_len:0, profile:null, same_ap:null, vendor:'Ubiquiti Inc', quality:80, band:'5', channel:36, freq_mhz:5180,
      width_mhz:80, center_mhz:5210, std:'ax', gen:'Wi-Fi 6', security:'WPA2-Enterprise', sec_class:'ent', cipher:'AES', k:true, v:true, r:true, mlo:false, clients:null, load_pct:null, connected:false}, o);
    const nets = [
      N({ssid:'CORP', bssid:'74:ac:b9:3e:41:c2', rssi:-48, clients:9, load_pct:12, connected:true}),
      N({ssid:'CORP-GUEST', bssid:'76:ac:b9:3e:41:c2', rssi:-49, security:'WPA2-Personal', sec_class:'wpa2', r:false, clients:2}),
      N({hidden:true, profile:'CORP-MGMT', bssid:'7e:ac:b9:3e:41:c2', rssi:-49, clients:1}),
      N({ssid:'CORP', bssid:'74:ac:b9:3e:41:c1', rssi:-51, band:'2.4', channel:6, freq_mhz:2437, width_mhz:20, center_mhz:2437, clients:3}),
      N({ssid:'CORP-IOT', bssid:'7a:ac:b9:3e:41:c1', rssi:-53, band:'2.4', channel:6, freq_mhz:2437, width_mhz:20, center_mhz:2437, security:'WPA2-Personal', sec_class:'wpa2', k:false, v:false, r:false, clients:6}),
      N({ssid:'CORP', bssid:'74:ac:b9:12:8f:a2', rssi:-67, channel:100, freq_mhz:5500, center_mhz:5530, clients:14}),
      N({hidden:true, same_ap:'CORP', bssid:'7e:ac:b9:12:8f:a2', rssi:-68, channel:100, freq_mhz:5500, center_mhz:5530, security:'WPA3-Personal', sec_class:'wpa3', r:false}),
      N({ssid:'Esempio-WiFi7', bssid:'a8:42:a1:5d:07:3c', vendor:'TP-Link', rssi:-72, band:'6', channel:37, freq_mhz:6135, width_mhz:320, center_mhz:6105, std:'be', gen:'Wi-Fi 7', security:'WPA3-Personal', sec_class:'wpa3', mlo:true, clients:4, load_pct:20}),
      N({ssid:'Esempio-WiFi7', bssid:'a8:42:a1:5d:07:3b', vendor:'TP-Link', rssi:-77, channel:100, freq_mhz:5500, width_mhz:160, center_mhz:5570, std:'be', gen:'Wi-Fi 7', security:'WPA3-Personal', sec_class:'wpa3', mlo:true}),
      N({ssid:'Stampante <b>DIRECT</b>', bssid:'fa:da:0c:4f:21:9e', vendor:null, rssi:-71, band:'2.4', channel:6, freq_mhz:2437, width_mhz:20, center_mhz:2437, std:'n', gen:'Wi-Fi 4', security:'WPA2-Personal', sec_class:'wpa2', k:false, v:false, r:false}),
      N({hidden:true, ssid_len:9, bssid:'c0:56:e3:9a:11:04', vendor:'Hikvision', rssi:-82, band:'2.4', channel:11, freq_mhz:2462, width_mhz:20, center_mhz:2462, std:'n', gen:'Wi-Fi 4', security:'WPA2-Personal', sec_class:'wpa2', k:false, v:false, r:false}),
      N({ssid:'Bar', bssid:'50:c7:bf:22:0e:41', vendor:'TP-Link', rssi:-84, band:'2.4', channel:11, freq_mhz:2462, width_mhz:20, center_mhz:2462, std:'g', gen:'', security:'Aperta', sec_class:'open', cipher:'', k:false, v:false, r:false}),
    ].sort((a, b) => b.rssi - a.rssi);
    const conn = {ssid:'CORP', bssid:'74:ac:b9:3e:41:c2', vendor:'Ubiquiti Inc', profile:'CORP', band:'5', channel:36, width_mhz:80, std:'ax', gen:'Wi-Fi 6',
      rssi:-48, quality:100, rx_mbps:1201, tx_mbps:960.7, security:'WPA2-Enterprise', cipher:'AES', ip:'172.16.7.42', k:true, v:true, r:true, mlo:false};
    if (mode === 'location') return Object.assign(base, {problem:{code:'location', title:'Windows nega l\'accesso alla posizione', detail:'Impostazioni › Privacy e sicurezza › Posizione'},
      connection:Object.assign({}, conn, {band:null, width_mhz:null, k:null, v:null, r:null})});
    return Object.assign(base, {connection:conn, networks:nets, best24:1, best5:{label:'52–64', dfs:true}, six_seen:true,
      warning: args.req.scan ? null : null});
  }
  if (cmd === 'wifi_monitor_stop') { if (window.__wfmStop) window.__wfmStop(); return null; }
  if (cmd === 'wifi_monitor') {
    if (window.__wifiMonErr) throw 'La scheda Wi-Fi non è connessa a nessuna rete: il monitor misura il segnale della connessione attuale.';
    const ch = args.onEvent; let stopped = false, wake = null, t = 0, n = 0;
    window.__wfmStop = () => { stopped = true; if (wake) wake(); };
    ch.onmessage({event:{t:0, kind:'start', text:'Monitor avviato su CORP · 74:ac:b9:3e:41:c2, canale 36', gap_ms:null}});
    const S = (rssi, b, c) => ({t, rssi, quality:rssi === null ? null : 2 * (rssi + 100), bssid:b, channel:c, rx_mbps:rssi === null ? null : 866.7, tx_mbps:rssi === null ? null : 780});
    while (!stopped && n < 400) {
      n++; t += 1000;
      if (n < 8) ch.onmessage({sample:S(-50 - n * 3, '74:ac:b9:3e:41:c2', 36)});
      else if (n === 8) { ch.onmessage({event:{t, kind:'weak', text:'Segnale sotto -75 dBm (-77 dBm)', gap_ms:null}}); ch.onmessage({sample:S(-77, '74:ac:b9:3e:41:c2', 36)}); }
      else if (n === 9) { ch.onmessage({event:{t, kind:'roam', text:'Roaming da 74:ac:b9:3e:41:c2, canale 36, -77 dBm a 74:ac:b9:12:8f:a2, canale 100, -58 dBm', gap_ms:38}}); ch.onmessage({sample:S(-58, '74:ac:b9:12:8f:a2', 100)}); }
      else if (n === 10) ch.onmessage({sample:S(null, null, null)});
      else ch.onmessage({sample:S(-60 + (n % 3), '74:ac:b9:12:8f:a2', 100)});
      await new Promise(r => { wake = r; setTimeout(r, 25); });
    }
    return {stopped, samples:n, roams:1};
  }
  // SNMP. Whole device (snmp_device, with the sections on the Channel): "sw-core01…" = switch with
  // 10 interfaces, 4 LLDP neighbours, 61 MACs; "fw01" = router without LLDP or MAC table (ARP only, 32-bit counters);
  // "lento" = one section every 300 ms until stopped; "muto" = no reply. The security checks
  // depend on the request. snmp: get, walk and table ("ifTable" = 310 rows, "lldpRemTable" = empty).
  // snmp_monitor: one sample every 25 ms (simulated time: 5 s per sample) until stopped.
  if (cmd === 'snmp_names') return [
    {oid:'1.3.6.1.2.1', name:'mib-2', mib:'SNMPv2-SMI', kind:'group', descr:'oggetti standard'},
    {oid:'1.3.6.1.2.1.1', name:'system', mib:'SNMPv2-MIB', kind:'group', descr:"identità dell'apparato"},
    {oid:'1.3.6.1.2.1.1.1', name:'sysDescr', mib:'SNMPv2-MIB', kind:'scalar', descr:'descrizione: modello e firmware'},
    {oid:'1.3.6.1.2.1.1.5', name:'sysName', mib:'SNMPv2-MIB', kind:'scalar', descr:"nome dell'apparato"},
    {oid:'1.3.6.1.2.1.2', name:'interfaces', mib:'IF-MIB', kind:'group', descr:'interfacce di rete'},
    {oid:'1.3.6.1.2.1.2.1', name:'ifNumber', mib:'IF-MIB', kind:'scalar', descr:'numero di interfacce'},
    {oid:'1.3.6.1.2.1.2.2', name:'ifTable', mib:'IF-MIB', kind:'table', descr:'una riga per interfaccia'},
    {oid:'1.3.6.1.2.1.2.2.1.2', name:'ifDescr', mib:'IF-MIB', kind:'column', descr:'descrizione'},
    {oid:'1.3.6.1.2.1.2.2.1.5', name:'ifSpeed', mib:'IF-MIB', kind:'column', descr:'velocità in bit/s (fino a 4 Gb/s)'},
    {oid:'1.3.6.1.2.1.2.2.1.6', name:'ifPhysAddress', mib:'IF-MIB', kind:'column', descr:'indirizzo MAC'},
    {oid:'1.3.6.1.2.1.2.2.1.7', name:'ifAdminStatus', mib:'IF-MIB', kind:'column', descr:"stato voluto dall'amministratore"},
    {oid:'1.3.6.1.2.1.2.2.1.8', name:'ifOperStatus', mib:'IF-MIB', kind:'column', descr:'stato del collegamento'},
    {oid:'1.3.6.1.2.1.2.2.1.14', name:'ifInErrors', mib:'IF-MIB', kind:'column', descr:'pacchetti ricevuti con errori'},
    {oid:'1.3.6.1.2.1.2.2.1.20', name:'ifOutErrors', mib:'IF-MIB', kind:'column', descr:'pacchetti non inviati per errori'},
    {oid:'1.3.6.1.2.1.25', name:'host', mib:'HOST-RESOURCES-MIB', kind:'group', descr:'memoria, dischi, CPU'},
    {oid:'1.3.6.1.2.1.25.2.3', name:'hrStorageTable', mib:'HOST-RESOURCES-MIB', kind:'table', descr:'dischi e memoria'},
    {oid:'1.3.6.1.2.1.25.2.3.1.3', name:'hrStorageDescr', mib:'HOST-RESOURCES-MIB', kind:'column', descr:'descrizione o punto di montaggio'},
    {oid:'1.3.6.1.2.1.31', name:'ifMIB', mib:'IF-MIB', kind:'group', descr:'nomi, alias e contatori a 64 bit'},
    {oid:'1.3.6.1.2.1.31.1.1', name:'ifXTable', mib:'IF-MIB', kind:'table', descr:'estensione della tabella delle interfacce'},
    {oid:'1.3.6.1.2.1.31.1.1.1.1', name:'ifName', mib:'IF-MIB', kind:'column', descr:"nome breve dell'interfaccia"},
    {oid:'1.3.6.1.2.1.31.1.1.1.6', name:'ifHCInOctets', mib:'IF-MIB', kind:'column', descr:'byte ricevuti, contatore a 64 bit'},
    {oid:'1.3.6.1.2.1.31.1.1.1.18', name:'ifAlias', mib:'IF-MIB', kind:'column', descr:"descrizione scritta dall'amministratore"},
    {oid:'1.0.8802.1.1.2', name:'lldpMIB', mib:'LLDP-MIB', kind:'group', descr:'vicini LLDP'},
    {oid:'1.0.8802.1.1.2.1.4.1', name:'lldpRemTable', mib:'LLDP-MIB', kind:'table', descr:'un vicino per riga'},
  ];
  if (cmd === 'snmp_stop') { const f = window.__probe.snmp; if (f) f(); return null; }
  if (cmd === 'snmp_monitor_stop') { if (window.__snMonStop) window.__snMonStop(); return null; }
  if (cmd === 'snmp_monitor') {
    const r = args.req;
    if (r.host === 'muto') throw 'Nessuna risposta da muto: community errata, versione SNMP non abilitata, IP del PC non nelle ACL dell\'agente oppure UDP 161 bloccata';
    if (window.__snMonStop) window.__snMonStop();
    let stopped = false, wake = null, n = 0;
    window.__snMonStop = () => { stopped = true; if (wake) wake(); };
    const wait = ms => stopped ? Promise.resolve() : new Promise(res => { wake = res; setTimeout(res, ms); });
    const hc = r.host !== 'fw01';
    args.onEvent.onmessage({start: {hc, interval_s: 5, ports: 10}});
    while (!stopped) {
      await wait(25);
      if (stopped) break;
      n++;
      if (window.__snMonErr && n > 2) return {samples: n - 1, elapsed_s: n * 5, stopped: false, error: 'Nessuna risposta da ' + r.host + ': controlla UDP 161'};
      const P = (index, inb, outb, err, state) => ({index, in_bps: inb, out_bps: outb, in_errors: err, out_errors: 0, in_discards: err ? n : 0, out_discards: 0, state: state || 'up'});
      args.onEvent.onmessage({sample: {t_ms: n * 5000, ports: [P(1, 2.4e6, 3e5, 0), P(2, 1e5, 0, 0), P(3, null, null, 0, 'down'), P(14, 6.8e6, 2e5, n * 4), P(15, null, null, 0, 'off'),
        P(23, 1.84e8, 6.12e8 + n * 1e6, 0), P(25, 8.2e9, 3.86e8, 0), P(26, 9.6e7, 4.1e7, 0), P(27, 1.336e9, 4.27e8, 0), P(110, 3.1e6, 5.6e6, 0)]}});
    }
    return {samples: n, elapsed_s: n * 5, stopped: true};
  }
  if (cmd === 'snmp' || cmd === 'snmp_device') {
    const r = args.req, C = (area, status, name, detail) => ({area, status, name, detail});
    if (r.port && !(+r.port >= 1 && +r.port <= 65535)) throw 'Porta: da 1 a 65535';
    if (r.host === 'muto') throw 'Nessuna risposta da muto: community errata, versione SNMP non abilitata, IP del PC non nelle ACL dell\'agente oppure UDP 161 bloccata';
    const sec = [];
    if (r.version === '3') {
      if (r.sec_level === 'noAuthNoPriv') sec.push(C('Sicurezza', 'err', 'v3 senza autenticazione', 'Livello noAuthNoPriv: basta conoscere il nome dell\'utente.'));
      else if (r.sec_level === 'authNoPriv') sec.push(C('Sicurezza', 'warn', 'v3 senza cifratura', 'Livello authNoPriv: le risposte dell\'apparato passano in chiaro sulla rete.'));
      else sec.push(C('Sicurezza', 'ok', 'SNMP v3 con autenticazione e cifratura', 'Utente autenticato e risposte cifrate.'));
    } else {
      if (r.community === 'public') sec.push(C('Sicurezza', 'err', 'Community predefinita', '"public" è fra le prime community che chiunque prova. Cambiala e limita gli indirizzi IP ammessi.'));
      sec.push(C('Sicurezza', 'warn', 'Protocollo in chiaro', 'SNMP v' + r.version + ' non cifra e non autentica: community e risposte si leggono sulla rete.'));
    }
    // one test at a time, like the backend: the new one stops the previous
    if (window.__probe.snmp) window.__probe.snmp();
    let stopped = false, wake = null;
    window.__probe.snmp = () => { stopped = true; if (wake) wake(); };
    const wait = ms => stopped ? Promise.resolve() : new Promise(res => { wake = res; setTimeout(res, ms); });

    if (cmd === 'snmp') {
      const base = {host: r.host, oid: r.oid, mode: r.mode, truncated: false, stopped: false, checks: sec};
      if (r.host === 'lento') { await wait(60000); return Object.assign(base, {output: 'IF-MIB::ifDescr.1 = STRING: "1/1"\n… fermato dopo 1 valori', count: 1, stopped: true}); }
      if (r.mode === 'get') return Object.assign(base, {count: 1, output: /sysName/.test(r.oid) ? 'SNMPv2-MIB::sysName.0 = STRING: "sw-core01.corp.example"' : 'SNMPv2-MIB::sysDescr.0 = STRING: "Switch L3 a 24 porte + 2 uplink 10G, firmware 4.2.1"'});
      if (r.mode === 'walk') return Object.assign(base, {count: 3, output: 'IF-MIB::ifDescr.1 = STRING: "1/1"\nIF-MIB::ifDescr.2 = STRING: "1/2"\nIF-MIB::ifDescr.3 = STRING: "1/3"'});
      if (/lldpRemTable/.test(r.oid)) return Object.assign(base, {count: 0, output: ''});
      const table = /ifTable/i.test(r.oid)
        ? {name: 'IF-MIB::ifTable', columns: [{oid: '1.3.6.1.2.1.2.2.1.2', name: 'ifDescr'}, {oid: '1.3.6.1.2.1.2.2.1.8', name: 'ifOperStatus'}, {oid: '1.3.6.1.2.1.2.2.1.14', name: 'ifInErrors'}],
           rows: Array.from({length: 310}, (_, i) => ({index: String(i + 1), cells: ['porta ' + (i + 1), i % 3 ? 'up' : 'down', String(i === 13 ? 1204 : 0)]}))}
        : {name: 'HOST-RESOURCES-MIB::hrStorageTable', columns: [{oid: '1.3.6.1.2.1.25.2.3.1.2', name: 'hrStorageType'}, {oid: '1.3.6.1.2.1.25.2.3.1.3', name: 'hrStorageDescr'},
             {oid: '1.3.6.1.2.1.25.2.3.1.4', name: 'hrStorageAllocationUnits'}, {oid: '1.3.6.1.2.1.25.2.3.1.5', name: 'hrStorageSize'}, {oid: '1.3.6.1.2.1.25.2.3.1.6', name: 'hrStorageUsed'}],
           rows: [['1', 'hrStorageRam', 'Physical memory', '1024', '16303412', '9114208'], ['3', 'hrStorageVirtualMemory', 'Virtual memory', '1024', '20497712', '9870336'],
                  ['31', 'hrStorageFixedDisk', '/', '4096', '12850176', '4211908'], ['36', 'hrStorageFixedDisk', '/var', '4096', '51400704', '38870112'],
                  ['40', 'hrStorageFixedDisk', '/srv/dati;archivio', '4096', '257003520', '101224960']].map(x => ({index: x[0], cells: x.slice(1)}))};
      const q = s => /[;"\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      const csv = [['Indice', ...table.columns.map(c => c.name)], ...table.rows.map(x => [x.index, ...x.cells])].map(l => l.map(q).join(';')).join('\r\n');
      return Object.assign(base, {oid: table.columns[0].oid.split('.').slice(0, -2).join('.'), count: table.rows.length * table.columns.length, table, csv, output: ''});
    }

    const on = k => r[k] !== false;
    const names = ['Sistema', on('interfaces') && 'Interfacce', on('neighbors') && 'Vicini', on('fdb') && 'MAC e ARP', on('resources') && 'Risorse', on('printer') && 'Stampante'].filter(Boolean);
    for (let i = 0; i < names.length; i++) {
      args.onEvent.onmessage({step: {name: names[i], done: i, total: names.length}});
      if (r.host === 'lento') await wait(300);
      if (stopped) break;
    }
    const I = (index, name, alias, state, speed, ie, idc, kind) => ({index, name, alias, kind: kind || 'ethernetCsmacd', mtu: 1500, speed_bps: speed, mac: speed ? '02:00:5e:00:00:' + String(index % 100).padStart(2, '0') : '', state, changed_s: 3542400,
      in_errors: ie || 0, out_errors: 0, in_discards: idc || 0, out_discards: 0});
    // prn01 = printer (black toner at 12 %, waste container, one empty tray, one alarm); srv01 = server (CPU, memory,
    // three disks, two of them nearly full, processes). Both have few interfaces like fw01; the other hosts have neither view.
    const prn = r.host === 'prn01.corp.example', srv = r.host === 'srv01.corp.example';
    const fw = r.host === 'fw01' || prn || srv;
    const list = fw ? [I(1, 'wan', 'uscita Internet', 'up', 1e9), I(2, 'lan', '', 'up', 1e9), I(3, 'dmz', '', 'down', null)]
      : [I(1, '1/1', 'pc-ufficio-01', 'up', 1e9), I(2, '1/2', 'stampante piano 1', 'up', 1e8), I(3, '1/3', '', 'down', null), I(14, '1/14', 'telecamera ingresso', 'up', 1e8, 1204, 37), I(15, '1/15', 'porta libera', 'off', null),
         I(23, '1/23', 'srv01', 'up', 1e9), I(25, '1/25', 'uplink sw-dist01', 'up', 1e10), I(26, '1/26', 'uplink sw-dist02', 'up', 1e10), I(27, 'lag1', 'uplink (1/25 + 1/26)', 'up', 2e10, 0, 0, 'ieee8023adLag'), I(110, 'vlan10', 'utenti', 'up', null, 0, 0, 'l3ipvlan')];
    const F = (mac, vendor, ip, port, vlan, kind) => ({mac, vendor, local: mac.startsWith('02'), ip, port, vlan, kind});
    const fdbList = fw ? [F('00:50:56:09:09:09', 'Produttore di prova', ['203.0.113.1'], 'wan', null, 'arp'), F('02:00:5e:60:00:21', '', ['172.16.10.101'], 'lan', null, 'arp')]
      : [F('02:00:5e:10:00:01', '', ['172.16.0.2'], '1/25', 1, 'dinamico'), F('00:50:56:01:02:03', 'Produttore di prova', ['172.16.20.11', '172.16.20.12'], '1/23', 20, 'dinamico'),
         F('00:50:56:01:02:04', 'Produttore di prova', [], '1/23', 20, 'statico'), F('02:00:5e:40:00:14', '', ['172.16.10.60'], '1/14', 10, 'dinamico'), F('02:00:5e:30:01:17', '', [], '1/11', 30, 'dinamico'),
         F('02:00:5e:00:00:fe', '', [], '', 1, 'apparato'), F('02:00:5e:77:00:09', '', ['172.16.99.9'], 'vlan10', null, 'arp'),
         ...Array.from({length: 54}, (_, i) => F('02:00:5e:60:00:' + String(i).padStart(2, '0'), '', i % 2 ? ['172.16.10.' + (100 + i)] : [], 'lag1', 10, 'dinamico'))];
    const checks = sec.concat(stopped ? [] : [
      C('Sistema', 'info', 'Contatto e posizione', 'sysContact non è compilato: in un inventario l\'apparato resta senza riferimenti.'),
      ...(on('interfaces') ? (fw ? [C('Interfacce', 'ok', 'Nessun errore', 'Contatori degli errori a zero su 3 interfacce.'), C('Interfacce', 'info', 'Solo contatori a 32 bit', 'Senza ifHCInOctets il contatore dei byte ricomincia da zero ogni 34 secondi a 1 Gb/s.')]
        : [C('Interfacce', 'warn', 'Errori sulle porte', '1/14 (telecamera ingresso): 1204 errori dall\'avvio. Cavo, connettore o duplex da controllare.'),
           C('Interfacce', 'info', 'Porte senza collegamento', '1 porta attiva ma senza collegamento.'), C('Interfacce', 'ok', 'Contatori a 64 bit', 'L\'agente espone ifHCInOctets.')]) : []),
      ...(on('neighbors') ? (fw ? [C('Vicini', 'info', 'LLDP non disponibile', 'L\'agente non espone la LLDP-MIB.')]
        : [C('Vicini', 'ok', 'Vicini LLDP', '4 vicini annunciati.'), C('Vicini', 'info', 'Vicini senza indirizzo di gestione', '1 su 4 non annuncia un indirizzo IP con LLDP.')]) : []),
      ...(on('fdb') && fw ? [C('MAC e ARP', 'info', 'Solo tabella ARP', 'L\'apparato non espone una tabella MAC (non è uno switch).')] : []),
      ...(on('printer') && prn ? [C('Stampante', 'info', 'Stato', 'Inattiva.'), C('Stampante', 'warn', 'Carta in esaurimento', 'La stampante segnala: carta in esaurimento (hrPrinterDetectedErrorState).'),
        C('Stampante', 'warn', 'Materiale in esaurimento', 'Toner nero: rimasto il 12 %.'), C('Stampante', 'warn', 'Vassoio vuoto', 'Cassetto 2: carta esaurita.'),
        C('Stampante', 'warn', 'Avviso della stampante', 'Cassetto 2 vuoto (vassoio di ingresso).')] : []),
      ...(on('resources') && srv ? [C('Risorse', 'ok', 'Processore', 'Carico medio 24 % su 2 processori nell\'ultimo minuto.'), C('Risorse', 'ok', 'Memoria fisica', 'Physical Memory: 56 % usato (9,0 GB su 16,0 GB).'),
        C('Risorse', 'warn', 'Disco da tenere d\'occhio', 'D:\\ Dati: 93 % usato, 32,7 GB liberi su 465,7 GB.'), C('Risorse', 'err', 'Disco quasi pieno', 'E:\\ Archivio: 99 % usato, 40,0 KB liberi su 3,9 MB.')] : []),
    ]).concat([C('Agente', 'ok', 'Risposta', stopped ? '12 valori letti in 0,3 s, lettura fermata.' : '412 valori letti in 1,8 s.')]);
    return {host: r.host, ip: '172.16.0.1', name: prn || srv ? r.host : fw ? 'fw01' : r.host === 'lento' ? 'lento' : 'sw-core01.corp.example', elapsed_ms: 1800, values: stopped ? 12 : 412, stopped,
      sections: {system: on('system'), interfaces: on('interfaces'), neighbors: on('neighbors'), fdb: on('fdb'), resources: on('resources'), printer: on('printer')}, checks,
      system: {name: prn || srv ? r.host : fw ? 'fw01' : 'sw-core01.corp.example', descr: 'Switch L3 a 24 porte + 2 uplink 10G, firmware 4.2.1', object_id: '1.3.6.1.4.1.99999.1.3.24', uptime_s: 3553200, contact: '', location: 'Sala server',
        services: ['livello 2 (switch)', 'livello 3 (router)'], units: on('system') ? [{name: 'Unità 1', model: 'SW-2426X', serial: 'EX4K2026A0117', firmware: '4.2.1'}] : [],
        addresses: on('system') ? [{ip: '172.16.0.1', mask: '255.255.255.0', prefix: 24, if_name: 'vlan1'}, {ip: '172.16.10.1', mask: '255.255.254.0', prefix: 23, if_name: 'vlan10'}] : []},
      interfaces: on('interfaces') ? {list: stopped ? [] : list, up: stopped ? 0 : list.filter(i => i.state === 'up').length, total: stopped ? 0 : list.length, hc: !fw} : null,
      neighbors: on('neighbors') ? {supported: !fw, list: fw || stopped ? [] : [
        {local_port: '1/25', name: 'sw-dist01.corp.example', port: '2/1', port_descr: 'uplink core', descr: 'Switch L3 48 porte, firmware 4.2.1', caps: ['switch', 'router'], addr: '172.16.0.2', chassis: '02:00:5e:10:00:01'},
        {local_port: '1/26', name: 'sw-dist02.corp.example', port: '2/1', port_descr: 'uplink core', descr: 'Switch L3 48 porte, firmware 4.1.9', caps: ['switch', 'router'], addr: '172.16.0.3', chassis: '02:00:5e:10:00:02'},
        {local_port: '1/9', name: 'ap-piano1', port: 'eth0', port_descr: '', descr: 'Access point <b>Wi-Fi 6</b>', caps: ['access point'], addr: '172.16.0.41', chassis: '02:00:5e:20:00:09'},
        {local_port: '1/11', name: '02:00:5e:30:01:17', port: '02:00:5e:30:01:17', port_descr: '', descr: '', caps: ['telefono'], addr: '', chassis: '02:00:5e:30:01:17'}]} : null,
      fdb: on('fdb') ? {list: stopped ? [] : fdbList, macs: stopped ? 0 : fdbList.length, ports: fw ? 0 : 5, with_ip: fdbList.filter(x => x.ip.length).length, source: fw ? '' : 'qbridge', arp: 31} : null,
      resources: on('resources') && srv && !stopped ? {uptime_s: 432000, users: 2, processes: 143, memory_kb: 16777216,
        cpu: [{name: 'Processore 0', load: 12}, {name: 'Processore 1', load: 36}], cpu_avg: 24,
        memory: [{name: 'Physical Memory', kind: 'ram', size: 17179869184, used: 9663676416, pct: 56}, {name: 'Virtual Memory', kind: 'virtual', size: 25769803776, used: 12884901888, pct: 50}],
        disks: [{name: 'C:\\ Label:Sistema', kind: 'disk', size: 122880000000, used: 86016000000, pct: 70}, {name: 'D:\\ Label:Dati', kind: 'disk', size: 409600000000, used: 380928000000, pct: 93},
          {name: 'E:\\ Label:Archivio', kind: 'disk', size: 4096000, used: 4055040, pct: 99}],
        top: [{name: 'sqlservr.exe', mem_kb: 4000000, cpu_s: 12000}, {name: 'w3wp.exe', mem_kb: 800000, cpu_s: 50}, {name: 'System', mem_kb: 300, cpu_s: 900}], process_total: 143} : null,
      printer: on('printer') && prn && !stopped ? {name: 'Stampante laser a colori', status: 'Inattiva', serial: 'PRN0123456', pages: 48213,
        errors: [{label: 'carta in esaurimento', severe: false}, {label: 'toner in esaurimento', severe: false}],
        supplies: [{name: 'Toner nero', kind: 'toner', class: 'consumed', color: 'black', level: 12, some: false, state: 'warn'}, {name: 'Toner ciano', kind: 'toner', class: 'consumed', color: 'cyan', level: 64, some: false, state: 'ok'},
          {name: 'Toner magenta', kind: 'toner', class: 'consumed', color: 'magenta', level: 48, some: false, state: 'ok'}, {name: 'Toner giallo', kind: 'toner', class: 'consumed', color: 'yellow', level: null, some: true, state: 'ok'},
          {name: 'Contenitore toner di scarto', kind: 'wasteToner', class: 'filled', color: '', level: 35, some: false, state: 'ok'}, {name: 'Unità fusore', kind: 'fuser', class: 'consumed', color: '', level: null, some: false, state: 'unknown'}],
        trays: [{name: 'Cassetto 1', media: 'A4', level: 46, current: 230, max: 500, some: false, state: 'ok'}, {name: 'Cassetto 2', media: 'A4', level: 0, current: 0, max: 500, some: false, state: 'empty'},
          {name: 'Bypass', media: '', level: null, current: null, max: null, some: true, state: 'ok'}],
        alerts: [{severity: 'warning', text: 'Cassetto 2 vuoto', group: 'input'}]} : null,
      engine_id: r.version === '3' ? '80001f88805a3c110d427e01' : undefined};
  }
  return {error:'non simulato: '+cmd};
}}};
"""


def home_layout(pg, theme):
    """Home checks at the current window size."""
    lay = pg.evaluate("""(() => { const r = s => document.querySelector(s).getBoundingClientRect().toJSON();
      const sb = document.querySelector('.sidebar');
      return {m: r('main'), np: r('#np'), map: r('.home-map'), ck: r('.clock-card'), t: r('#clock-time'),
        sb: r('.sidebar'), cr: r('.side-credits'), crShown: getComputedStyle(document.querySelector('.side-credits')).display !== 'none',
        sbScroll: [sb.scrollHeight, sb.clientHeight], viewScroll: [document.querySelector('main').scrollHeight, document.querySelector('main').clientHeight],
        bg: getComputedStyle(document.querySelector('.home-map')).backgroundImage + ' ' + getComputedStyle(document.querySelector('.home-foot'), '::before').backgroundImage,
        filt: getComputedStyle(document.querySelector('.home-map')).filter}; })()""")
    m = lay['m']
    assert lay['np']['top'] - m['top'] < 30, ('percorso non in alto', lay)
    assert lay['np']['width'] > m['width'] - 60, ('percorso non su tutta la larghezza', lay)
    assert lay['np']['bottom'] <= lay['map']['top'] and lay['map']['bottom'] <= lay['ck']['top'], ('mappa coperta', lay)
    assert lay['map']['height'] >= 120, ('mappa troppo bassa', lay)
    assert m['bottom'] - lay['ck']['bottom'] < 30, ('orologio non in fondo', lay)
    assert abs((lay['ck']['left'] + lay['ck']['right']) / 2 - (m['left'] + m['right']) / 2) < 2, ('orologio non centrato', lay)
    assert lay['ck']['width'] <= 330 and lay['t']['height'] < 60, lay
    assert lay['viewScroll'][0] <= lay['viewScroll'][1], ('Home con scorrimento', lay)
    if pg.viewport_size['height'] >= 860:
        assert lay['sbScroll'][0] <= lay['sbScroll'][1], ('menu con scorrimento', lay)
        assert lay['crShown'], 'crediti nascosti a 860 px'
    if lay['crShown']:
        assert lay['sb']['bottom'] - lay['cr']['bottom'] < 2, ('crediti non in fondo al menu', lay)
    assert 'home-map.webp' in lay['bg'] and 'home-ground.webp' in lay['bg'], lay['bg']
    assert (lay['filt'] == 'none') == (theme == 'dark'), lay['filt']
    return lay

errors = []
# UI served over HTTP on 127.0.0.1: with file:// headless Chromium sometimes loses localStorage on reload
class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
SRV = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(_Quiet, directory=str(UI)))
threading.Thread(target=SRV.serve_forever, daemon=True).start()
URL = f'http://127.0.0.1:{SRV.server_address[1]}/index.html'

with sync_playwright() as p:
    b = p.chromium.launch()
    for theme in ('dark', 'light'):
        pg = b.new_page(viewport={'width': 1269, 'height': 860})
        pg.on('pageerror', lambda e: errors.append(str(e)))
        pg.on('console', lambda m: m.type == 'error' and errors.append(m.text))
        pg.add_init_script(MOCK + f"localStorage.setItem('ntb-theme', '{theme}');")
        pg.goto(URL)
        pg.wait_for_timeout(400)
        # startup: home screen, no menu item selected
        assert pg.locator('#view-home').is_visible(), 'home non visibile'
        assert pg.locator('.nav-item[aria-current]').count() == 0
        assert pg.inner_text('#home-version') == '2.1.0'
        assert pg.get_attribute('.topbar .brand', 'title') == 'SRV01.corp.example · 172.16.7.42'
        assert pg.locator('#brand-host').count() == 0 and 'App desktop' not in pg.inner_text('.topbar')
        assert pg.evaluate("document.querySelector('.topbar').getBoundingClientRect().height") == 40
        assert pg.evaluate("(() => { const a = document.getElementById('home-btn').getBoundingClientRect(), b = document.getElementById('svc').getBoundingClientRect(); return a.height === b.height && a.top === b.top; })()")
        # single bar: status on the right, before Theme and Home, then the window buttons
        xs = pg.evaluate("['theme-btn','home-btn','svc','win-min','win-max','win-close'].map(i => document.getElementById(i).getBoundingClientRect().x)")
        assert xs == sorted(xs) and xs[0] > 600, xs
        assert pg.locator('#win-ctl').is_visible()
        pg.click('#win-min'); pg.click('#win-max'); pg.click('#win-close')
        assert pg.evaluate('window.__win') == ['min', 'max', 'close']
        assert 'down' not in pg.get_attribute('#svc', 'class')
        assert 'Internet raggiungibile' in pg.get_attribute('#svc', 'title')
        # images loaded
        assert pg.evaluate("[...document.images].every(i => i.complete && i.naturalWidth > 0)")
        # menu without scrolling
        sb = pg.evaluate("(() => { const s = document.querySelector('.sidebar'); return [s.scrollHeight, s.clientHeight]; })()")
        assert sb[0] <= sb[1], f'menu con scorrimento: {sb}'
        # network path above the logo: PC → gateway → Internet
        pg.wait_for_function("document.getElementById('np-net-ip').textContent === '203.0.113.130'")
        assert pg.inner_text('#np-pc-name') == 'SRV01' and pg.inner_text('#np-pc-ip') == '172.16.1.248'
        assert pg.inner_text('#np-gw-name') == 'gw01.corp.example' and pg.inner_text('#np-gw-ip') == '172.16.1.1'
        assert pg.inner_text('#np-net-name') == 'Provider Example S.p.A.'
        assert pg.inner_text('#np-l1-ms') == '<1 ms' and pg.inner_text('#np-l2-ms') == '12 ms', (pg.inner_text('#np-l1-ms'), pg.inner_text('#np-l2-ms'))
        assert all('ok' in pg.get_attribute(i, 'class') for i in ('#np-pc', '#np-gw', '#np-net'))
        assert 'via cavo' in pg.get_attribute('#np-pc', 'title')
        # layout: path at the top over the full width, map in the free space,
        # clock at the bottom centre, version and credits at the bottom of the side menu
        assert pg.locator('.home-brand').count() == 0 and pg.locator('.home-logo').count() == 0
        # only clock and date in the box, no heading
        assert pg.locator('.clock-head').count() == 0 and 'Ora e data' not in pg.inner_text('.clock-card')
        home_layout(pg, theme)
        # the lines between nodes at half the icon height
        al = pg.evaluate("""(() => { const c = e => { const r = e.getBoundingClientRect(); return (r.top + r.bottom) / 2; };
          return [c(document.querySelector('#np-pc .np-ico')), c(document.querySelector('#np-l1 i'))]; })()""")
        assert abs(al[0] - al[1]) <= 3, al
        # full names, without "…"
        assert pg.evaluate("[...document.querySelectorAll('.np-name')].every(e => e.scrollWidth <= e.clientWidth)")
        assert pg.evaluate(r"/^\d{2}:\d{2}:\d{2}$/.test(document.getElementById('clock-time').textContent)")
        assert len([c for c in pg.evaluate('window.__calls') if c[0] == 'myip']) == 1
        pg.screenshot(path=str(OUT / f'home-{theme}.png'))
        assert pg.evaluate("""Promise.all(['home-map.webp', 'home-ground.webp'].map(u => new Promise(ok => {
          const i = new Image(); i.onload = () => ok(i.naturalWidth > 1000); i.onerror = () => ok(false); i.src = u; }))).then(r => r.every(Boolean))""")
        cr = pg.inner_text('.side-credits')
        assert 'Versione 2.1.0' in cr and '© 2026 Giorgio Casciola' in cr and 'Apache 2.0' in cr, cr
        for w, h in ((1000, 640), (1920, 1080), (1269, 700)):
            pg.set_viewport_size({'width': w, 'height': h}); pg.wait_for_timeout(100)
            home_layout(pg, theme)
            pg.screenshot(path=str(OUT / f'home-{theme}-{w}x{h}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.click('#np-gw')
        assert pg.locator('#view-ping').is_visible() and pg.input_value('#ping-host') == '172.16.1.1'
        pg.wait_for_selector('#res-ping .strip.ok'); pg.click('#res-ping .link-btn')
        pg.click('#home-btn'); pg.click('#np-net')
        assert pg.locator('#view-whois').is_visible() and pg.input_value('#whois-host') == '203.0.113.130'
        pg.click('#home-btn')
        # no placeholder; Active Directory removed
        assert pg.locator('[placeholder]').count() == 0
        assert pg.locator('.nav-item[data-view="ldap"]').count() == 0 and pg.locator('#view-ldap').count() == 0
        # ping limits and defaults: packets 1-100 (4), interval 100-2000 (1000), timeout 100-5000 (2000)
        lim = lambda i: [pg.get_attribute(i, a) for a in ('value', 'min', 'max')]
        assert lim('#ping-count') == ['4', '1', '100'], lim('#ping-count')
        assert lim('#ping-interval') == ['1000', '100', '2000'], lim('#ping-interval')
        assert lim('#ping-timeout') == ['2000', '100', '5000'], lim('#ping-timeout')
        assert lim('#trace-hops') == ['30', '1', '64'], lim('#trace-hops')
        assert lim('#trace-timeout') == ['2000', '100', '5000'], lim('#trace-timeout')
        # ping
        pg.click('.nav-item[data-view="ping"]')
        PB, TB = '#view-ping button[type=submit]', '#view-trace button[type=submit]'
        box = lambda sel: pg.evaluate("s => { const r = document.querySelector(s).getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }", sel)
        calls = lambda cmd: [c for c in pg.evaluate('window.__calls') if c[0] == cmd]
        idle_box = box(PB)
        assert pg.inner_text(PB) == 'Esegui ping'
        pg.fill('#ping-host', 'fw01'); pg.fill('#ping-count', '100')
        pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.ok')
        req = calls('ping_stream')[-1][1]
        assert req['count'] == '100' and req['interval_ms'] == '1000' and req['timeout_ms'] == '2000', req
        assert pg.inner_text(PB) == 'Esegui ping' and not pg.is_disabled(PB) and box(PB) == idle_box
        pg.screenshot(path=str(OUT / f'ping-{theme}.png'))
        # "Ferma": during the test the same button, in the same place, becomes "Ferma"
        def stop_flow(view, btn, label, stream, stop_cmd, how):
            n_stream, n_stop = len(calls(stream)), len(calls(stop_cmd))
            before = box(btn)
            pg.fill(f'#{view}-host', 'lento')
            pg.click(btn)
            pg.wait_for_selector(f'#res-{view} .strip.run')
            assert pg.inner_text(btn) == 'Ferma' and not pg.is_disabled(btn), pg.inner_text(btn)
            assert 'secondary' in pg.get_attribute(btn, 'class')
            assert box(btn) == before, (box(btn), before)   # same place, same size
            pg.wait_for_function(f"document.querySelector('#res-{view} .strip pre').textContent.split('\\n').length > 3")
            if how == 'clic':
                pg.screenshot(path=str(OUT / f'{view}-running-{theme}.png'))
                pg.click(btn)
            else:                      # Enter in a field = click on the button = Stop
                pg.press(f'#{view}-host', 'Enter')
            pg.wait_for_selector(f'#res-{view} .strip.stop')
            assert len(calls(stream)) == n_stream + 1, 'Ferma ha avviato un altro test'
            assert len(calls(stop_cmd)) == n_stop + 1
            pg.wait_for_function(f"document.querySelector('{btn}').textContent === '{label}'")
            assert not pg.is_disabled(btn) and 'secondary' not in pg.get_attribute(btn, 'class') and box(btn) == before
            assert pg.locator(f'#res-{view} .strip.stop .strip-state').first.inner_text() == '■ Fermato'
            assert pg.locator(f'#res-{view} .strip.run').count() == 0
            return pg.locator(f'#res-{view} .strip.stop').first.inner_text()
        t = stop_flow('ping', PB, 'Esegui ping', 'ping_stream', 'ping_stop', 'clic')
        assert 'Fermato dopo' in t and 'pacchetti su 100' in t and 'Pacchetti ricevuti' in t and 'Perdita\n0%' in t, t
        pg.screenshot(path=str(OUT / f'ping-stopped-{theme}.png'))
        t = stop_flow('ping', PB, 'Esegui ping', 'ping_stream', 'ping_stop', 'invio')
        assert 'Fermato dopo' in t, t
        # stopped before a packet has an outcome: no statistics
        pg.fill('#ping-host', 'muto'); pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.run'); pg.wait_for_timeout(150); pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.stop:first-child')
        first = pg.locator('#res-ping .strip').first
        assert 'Fermato prima della risposta al primo pacchetto.' in first.inner_text()
        assert first.locator('.kv').count() == 0 and first.locator('.msg-err').count() == 0
        pg.wait_for_function(f"document.querySelector('{PB}').textContent === 'Esegui ping'")
        # without "Mostra le righe man mano" (show lines as they arrive): same button, single response with the partial result
        pg.uncheck('#opt-live')
        pg.fill('#ping-host', 'lento'); pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.run')
        assert pg.inner_text(PB) == 'Ferma'
        pg.wait_for_timeout(400); pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.stop:first-child')
        t = pg.locator('#res-ping .strip').first.inner_text()
        assert 'Fermato dopo' in t and 'Pacchetti ricevuti' in t and calls('ping')[-1][1]['host'] == 'lento', t
        pg.wait_for_function(f"document.querySelector('{PB}').textContent === 'Esegui ping'")
        pg.check('#opt-live')
        # a test started from another view while the ping runs: the first stops, the button follows the second
        pg.fill('#ping-host', 'lento'); pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.run')
        pg.evaluate("document.getElementById('ping-host').value = 'fw02'; document.querySelector('#view-ping form').requestSubmit()")
        pg.wait_for_function("document.querySelectorAll('#res-ping .strip.run').length === 0")
        st = pg.evaluate("[...document.querySelectorAll('#res-ping .strip')].slice(0, 2).map(s => [s.querySelector('.strip-target').textContent, s.classList.contains('ok'), s.classList.contains('stop')])")
        assert st == [['fw02', True, False], ['lento', False, True]], st
        assert pg.inner_text(PB) == 'Esegui ping' and not pg.is_disabled(PB) and box(PB) == idle_box
        assert len(calls('ping_stop')) == 4
        pg.click('#res-ping .link-btn')
        pg.fill('#ping-host', 'fw01'); pg.fill('#ping-count', '4'); pg.click(PB)
        pg.wait_for_selector('#res-ping .strip.ok')
        # separate traceroute
        pg.click('.nav-item[data-view="trace"]')
        assert pg.locator('#view-trace').is_visible() and not pg.locator('#view-ping').is_visible()
        assert pg.inner_text(TB) == 'Esegui traceroute' and pg.input_value('#trace-hops') == '30'
        # "Ferma" in the traceroute too (default max hops: 30)
        t = stop_flow('trace', TB, 'Esegui traceroute', 'traceroute_stream', 'traceroute_stop', 'clic')
        assert 'fermato prima della fine' in t and 'salti' in t, t
        assert calls('traceroute_stream')[-1][1]['max_hops'] == '30'
        pg.screenshot(path=str(OUT / f'trace-stopped-{theme}.png'))
        assert pg.inner_text(PB) == 'Esegui ping'            # the ping is not affected by the traceroute Stop
        pg.click('#res-trace .link-btn')
        pg.fill('#trace-host', 'fw01'); pg.fill('#trace-hops', '15'); pg.fill('#trace-timeout', '5000')
        pg.click(TB)
        pg.wait_for_selector('#res-trace .strip.ok')
        assert pg.locator('#res-ping .strip').count() == 1
        req = calls('traceroute_stream')[-1][1]
        assert req['max_hops'] == '15' and req['timeout_ms'] == '5000' and 'interval_ms' not in req, req
        assert pg.inner_text(TB) == 'Esegui traceroute' and not pg.is_disabled(TB)
        pg.screenshot(path=str(OUT / f'trace-{theme}.png'))
        # HTTP headers (tabs Controlli, Percorso, Cookie, CSP, Header)
        # invalid certificate: unauthenticated headers, no CSP, no cookie
        pg.click('.nav-item[data-view="headers"]')
        HS = '#res-headers .strip:first-child '
        htab = lambda k: pg.click(HS + f'.seg.rtabs [data-rtab="{k}"]')
        pg.fill('#hdr-url', 'web01.corp.example'); pg.click('#view-headers button[type=submit]')
        pg.wait_for_selector('#res-headers .strip.warn')
        t = pg.inner_text('#res-headers')
        assert 'Non valido' in t and '4 errori' in t and 'non provano nulla' in t and 'max-age=0 disattiva HSTS' in t, t
        assert 'CDN' not in t, t
        htab('hop'); t = pg.inner_text(HS)
        assert 'HTTPS, certificato non valido' in t and 'autorità non attendibile' in t and '9 ms' in t, t
        assert pg.locator(HS + '.hx-hop').count() == 2
        htab('ck'); assert 'non imposta cookie' in pg.inner_text(HS)
        htab('csp'); assert 'non invia una Content-Security-Policy' in pg.inner_text(HS)
        assert pg.locator('#res-headers b').count() == 0  # server text escaped
        pg.screenshot(path=str(OUT / f'headers-invalido-{theme}.png'), full_page=True)
        # site with redirects, cookies, weak CSP and CDN
        pg.fill('#hdr-url', 'www.example.com'); pg.click('#view-headers button[type=submit]')
        pg.wait_for_selector(HS + '.seg.rtabs')
        assert pg.locator('#res-headers .strip').count() == 2
        t = pg.inner_text(HS)
        assert '3 errori · 8 avvisi' in t and 'Cloudflare · MXP' in t and 'Valido' in t, t
        tabs = pg.eval_on_selector_all(HS + '.seg.rtabs button', 'b => b.map(x => x.innerText.replace(/\\s+/g, " ").trim())')
        assert tabs == ['Controlli19', 'Percorso3', 'Cookie4', 'CSP5', 'Header11'], tabs
        # checks are in severity order (the mock sends them by area): errors, warnings, info, passed
        order = pg.eval_on_selector_all(HS + '[data-rpane="chk"] tbody tr td:first-child .pill', 'p => p.map(x => ["err", "warn", "info", "ok"].find(c => x.classList.contains(c)))')
        assert order == ['err'] * 3 + ['warn'] * 8 + ['info'] * 4 + ['ok'] * 4, order
        first = pg.inner_text(HS + '[data-rpane="chk"] tbody tr:first-child')
        assert 'CSP' in first and 'script-src' in first, first
        assert pg.locator(HS + '[data-rpane="ck"]').is_hidden() and pg.locator(HS + '[data-rpane="chk"]').is_visible()
        pg.wait_for_timeout(450)
        pg.set_viewport_size({'width': 1269, 'height': 1700})
        pg.evaluate("document.querySelector('main').scrollTop = 0")
        pg.screenshot(path=str(OUT / f'headers-controlli-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        htab('hop')
        assert pg.locator(HS + '[data-rpane="chk"]').is_hidden()
        assert pg.locator(HS + '.hx-hop').count() == 3
        t = pg.inner_text(HS + '[data-rpane="hop"]')
        assert 'senza HSTS' in t and 'imposta 1 cookie' in t and 'imposta 3 cookie' in t and '112 ms' in t, t
        pg.screenshot(path=str(OUT / f'headers-percorso-{theme}.png'))
        htab('ck')
        assert pg.locator(HS + '[data-rpane="ck"] tbody tr').count() == 4
        t = pg.inner_text(HS + '[data-rpane="ck"]')
        assert 'passo 1' in t and 'destinazione' in t and 'solo questo host' in t and 'assente' in t and 'non vengono mostrati' in t, t
        pg.screenshot(path=str(OUT / f'headers-cookie-{theme}.png'))
        htab('csp')
        assert pg.locator(HS + '.hx-src.bad').count() == 2 and pg.locator(HS + '.hx-src.weak').count() == 1
        t = pg.inner_text(HS + '[data-rpane="csp"]')
        assert 'base-uri' in t and 'assente' in t and "'unsafe-eval'" in t, t
        pg.screenshot(path=str(OUT / f'headers-csp-{theme}.png'))
        htab('hdr')
        t = pg.inner_text(HS + '[data-rpane="hdr"]')
        assert '__Host-sid=(nascosto)' in t and 'nginx/1.18.0' in t, t
        # "Copia" (Copy) takes all the tabs, not only the open one
        pg.click(HS + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('CONTROLLI', 'PERCORSO', 'COOKIE', 'CSP', 'HEADER', 'sessionid: Secure no', "script-src 'self'", 'Cf-Ray: 8a1b')), c
        # the tabs of one result do not affect those of the other
        assert pg.locator('#res-headers .strip:nth-child(2) [data-rpane="csp"]').is_visible()
        assert pg.locator('#res-headers .strip:nth-child(2) [data-rpane="hdr"]').is_hidden()
        # TLS certificates (tabs Controlli, Certificato, Catena, Protocolli e cipher; "Ferma")
        pg.click('.nav-item[data-view="ssl"]')
        XS = '#res-ssl .strip:first-child '
        XB = '#view-ssl button[type=submit]'
        xtab = lambda k: pg.click(XS + f'.seg.rtabs [data-rtab="{k}"]')
        xtabs = lambda: pg.eval_on_selector_all(XS + '.seg.rtabs button', 'b => b.map(x => x.innerText.replace(/\\s+/g, " ").trim())')
        # healthy server, no scan: three tabs, everything passed
        pg.fill('#ssl-host', 'srv01.corp.example'); pg.click(XB)
        pg.wait_for_selector('#res-ssl .strip.ok >> text=srv01.corp.example')
        req = calls('ssl')[-1][1]
        assert req == {'host': 'srv01.corp.example', 'port': '443', 'protocol': 'auto', 'sni': '', 'scan': False}, req
        t = pg.inner_text(XS)
        assert 'Tutti superati' in t and '59 giorni' in t and 'Catena verificata' in t and 'TLS 1.3' in t, t
        assert xtabs() == ['Controlli10', 'Certificato', 'Catena3'], xtabs()
        assert pg.inner_text(XB) == 'Controlla' and not pg.is_disabled(XB)
        # fallback to TLS 1.2 and compatibility probe: warnings, with the explanation among the checks
        for host in ('tls12.corp.example', 'legacy.corp.example'):
            pg.fill('#ssl-host', host); pg.click(XB)
            pg.wait_for_selector(f'#res-ssl .strip.warn >> text={host}')
        t = pg.inner_text('#res-ssl')
        assert 'Catena verificata (handshake non completato)' in t and 'senza completare' in t and 'offrendo solo TLS 1.2' in t, t
        assert t.count('Compatibilità') == 2 and 'versione obsoleta' in t, t
        xtab('crt'); t = pg.inner_text(XS + '[data-rpane="crt"]')
        assert 'Cipher scelta dal server' in t and 'TLS_RSA_WITH_AES_128_CBC_SHA' in t and 'OCSP stapling' not in t, t
        pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'ssl-legacy-{theme}.png'), full_page=True)
        # misconfigured server on SMTP with STARTTLS, different SNI and version and cipher scan
        pg.fill('#ssl-host', 'www.example.com'); pg.fill('#ssl-port', '25'); pg.select_option('#ssl-proto', 'smtp')
        pg.fill('#ssl-sni', 'mail.example.com'); pg.check('#ssl-scan'); pg.click(XB)
        pg.wait_for_selector(XS + '.hx-run')
        assert pg.inner_text(XB) == 'Ferma' and not pg.is_disabled(XB)
        req = calls('ssl')[-1][1]
        assert req == {'host': 'www.example.com', 'port': '25', 'protocol': 'smtp', 'sni': 'mail.example.com', 'scan': True}, req
        # during the scan the certificate is already there and the chosen tab stays open while it fills up
        assert 'Certificato intermedio' in pg.inner_text(XS + '[data-rpane="chk"]')
        xtab('pro')
        pg.wait_for_selector(XS + '[data-rpane="pro"] .hx-src')
        assert pg.locator(XS + '[data-rpane="pro"]').is_visible() and pg.locator(XS + '[data-rpane="chk"]').is_hidden()
        pg.screenshot(path=str(OUT / f'ssl-running-{theme}.png'))
        pg.wait_for_selector('#res-ssl .strip:first-child.warn', timeout=8000)
        assert pg.locator(XS + '[data-rpane="pro"]').is_visible(), 'la scheda aperta deve restare quella scelta'
        assert pg.locator(XS + '.hx-run').count() == 0 and pg.inner_text(XB) == 'Controlla'
        assert pg.locator('#res-ssl .strip').count() == 4
        t = pg.inner_text(XS)
        assert '3 errori · 3 avvisi' in t and '23 giorni' in t, t
        pg.set_viewport_size({'width': 1269, 'height': 1600}); pg.evaluate("document.querySelector('main').scrollTop = 0")
        assert xtabs() == ['Controlli17', 'Certificato', 'Catena3', 'Protocolli e cipher10'], xtabs()
        rows_ = pg.locator(XS + '[data-rpane="pro"] tbody tr')
        assert rows_.count() == 4
        assert pg.locator(XS + '[data-rpane="pro"] .hx-src').count() == 15
        assert pg.locator(XS + '[data-rpane="pro"] .hx-src.bad').count() == 3 and pg.locator(XS + '[data-rpane="pro"] .hx-src.weak').count() == 7
        t = pg.inner_text(XS + '[data-rpane="pro"]')
        assert '9,4 s' in t and 'TLS 1.0' in t and 'non accettato' not in t and 'fermata' not in t, t
        pg.wait_for_timeout(120); pg.screenshot(path=str(OUT / f'ssl-cipher-{theme}.png'))
        xtab('chk')
        order = pg.eval_on_selector_all(XS + '[data-rpane="chk"] tbody tr td:first-child .pill', 'p => p.map(x => ["err", "warn", "info", "ok"].find(c => x.classList.contains(c)))')
        assert order == ['err'] * 3 + ['warn'] * 3 + ['info'] * 4 + ['ok'] * 7, order
        assert 'Certificato intermedio' in pg.inner_text(XS + '[data-rpane="chk"] tbody tr:first-child')
        assert pg.locator('#res-ssl b').count() == 0  # server text escaped
        pg.wait_for_timeout(120); pg.screenshot(path=str(OUT / f'ssl-controlli-{theme}.png'))
        xtab('crt'); t = pg.inner_text(XS + '[data-rpane="crt"]')
        assert all(x in t for x in ('Impronta SHA-256', '9F:2C:41', 'RSA 2048 bit', 'SMTP con STARTTLS', 'mail.example.com', '2001:db8::10', '*.cdn.example.com',
                                    'http://ocsp.ca.example.net', '3 SCT incorporati', 'Autenticazione server', 'non inviato')), t
        assert 'DNS: ' not in t, t
        pg.wait_for_timeout(120); pg.screenshot(path=str(OUT / f'ssl-certificato-{theme}.png'))
        xtab('chn')
        assert pg.locator(XS + '[data-rpane="chn"] .hx-hop').count() == 3
        t = pg.inner_text(XS + '[data-rpane="chn"]')
        assert all(x in t for x in ('non inviata', 'archivio del PC', 'inviato', 'autofirmato', 'emesso da Example Root CA X1', 'recuperata da sola', '(23 giorni)')), t
        pg.wait_for_timeout(120); pg.screenshot(path=str(OUT / f'ssl-catena-{theme}.png'))
        # "Copia" (Copy) takes all the tabs
        pg.click(XS + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('CONTROLLI', 'CERTIFICATO', 'CATENA', 'PROTOCOLLI E CIPHER', 'SNI mail.example.com', 'Impronta SHA-1: 3B:A1',
                                    '2. Intermedia: Example Issuing CA R3', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA · RSA · 3DES CBC · da togliere', 'TLS 1.1: accettato')), c
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # "Ferma" during the scan: same button, a single ssl_stop, partial result
        n_stop = len(calls('ssl_stop')); n_run = len(calls('ssl'))
        pg.click(XB)
        pg.wait_for_selector(XS + '[data-rpane="pro"] .hx-src', state='attached')
        assert pg.inner_text(XB) == 'Ferma'
        pg.click(XB)
        pg.wait_for_selector('#res-ssl .strip:first-child.stop')
        assert len(calls('ssl_stop')) == n_stop + 1 and len(calls('ssl')) == n_run + 1
        assert pg.inner_text(XB) == 'Controlla' and not pg.is_disabled(XB)
        xtab('pro'); t = pg.inner_text(XS)
        assert 'Scansione fermata: risultato parziale' in t and 'Fermato' in t and 'Certificato intermedio' not in pg.inner_text(XS + '[data-rpane="pro"]'), t
        n = pg.locator(XS + '[data-rpane="pro"] .hx-src').count()
        assert 1 <= n < 15, n
        pg.screenshot(path=str(OUT / f'ssl-stopped-{theme}.png'))
        pg.uncheck('#ssl-scan'); pg.fill('#ssl-sni', ''); pg.fill('#ssl-port', '443'); pg.select_option('#ssl-proto', 'auto')
        # DNS: comparison with the flags and the new types, then "Analisi del dominio" (domain analysis) in tabs
        pg.click('.nav-item[data-view="dns"]')
        DS = '#res-dns .strip:first-child '
        DB = '#view-dns [data-pane="dns-compare"] button[type=submit]'
        dtab = lambda k: pg.click(DS + f'.seg.rtabs [data-rtab="{k}"]')
        assert pg.locator('#view-dns [data-pane="dns-compare"]').is_visible() and pg.locator('#view-dns [data-pane="dns-domain"]').is_hidden()
        opts = pg.eval_on_selector_all('#dns-type option', 'o => o.map(x => x.value || x.textContent)')
        assert all(x in opts for x in ('A', 'CAA', 'HTTPS', 'SVCB', 'TLSA', 'DNSKEY', 'DS', 'NAPTR', 'SSHFP', 'DMARC')), opts
        pg.fill('#dns-host', 'example.com'); pg.fill('#dns-servers', '1.1.1.1'); pg.click(DB)
        pg.wait_for_selector('#res-dns .strip.warn')
        req = calls('dns')[-1][1]
        assert req == {'host': 'example.com', 'type': 'A', 'servers': ['', '1.1.1.1']}, req
        t = pg.inner_text(DS)
        assert 'Le risposte non coincidono' in t and '203.0.113.99' in t and 'RA AD' in t, t
        assert pg.locator(DS + '.dx-flags').count() == 2
        pg.select_option('#dns-type', 'DNSKEY'); pg.fill('#dns-servers', ''); pg.click(DB)
        pg.wait_for_selector('#res-dns .strip.ok >> text=DNS DNSKEY')
        assert '257 3 13 mdssw' in pg.inner_text(DS)
        pg.select_option('#dns-type', 'A')
        pg.screenshot(path=str(OUT / f'dns-confronto-{theme}.png'))
        # domain analysis: switch, request, summary
        pg.click('#view-dns [data-tabs="dns"] [data-tab="domain"]')
        assert pg.locator('#view-dns [data-pane="dns-compare"]').is_hidden() and pg.locator('#view-dns [data-pane="dns-domain"]').is_visible()
        n_dns = len(calls('dns'))
        pg.fill('#dnsd-domain', 'nessuno.example'); pg.press('#dnsd-domain', 'Enter')
        pg.wait_for_selector('#res-dns .strip.err >> text=non esiste (NXDOMAIN)')
        pg.fill('#dnsd-domain', 'example.com'); pg.press('#dnsd-domain', 'Enter')
        pg.wait_for_selector(DS + '.seg.rtabs')
        assert calls('dns_domain')[-1][1] == {'domain': 'example.com', 'axfr': False} and len(calls('dns')) == n_dns
        assert 'warn' in pg.get_attribute('#res-dns .strip:first-child', 'class')
        t = pg.inner_text(DS)
        assert all(x in t for x in ('Analisi DNS', '2 errori · 2 avvisi', '3 su 4 rispondono', 'Firmato e valido', '203.0.113.10 · 2001:db8::10')), t
        tabs = pg.eval_on_selector_all(DS + '.seg.rtabs button', 'b => b.map(x => x.innerText.replace(/\\s+/g, " ").trim())')
        assert tabs == ['Controlli14', 'Record13', 'Delega4', 'DNSSEC'], tabs
        order = pg.eval_on_selector_all(DS + '[data-rpane="chk"] tbody tr td:first-child .pill', 'p => p.map(x => ["err", "warn", "info", "ok"].find(c => x.classList.contains(c)))')
        assert order == ['err'] * 2 + ['warn'] * 2 + ['info'] * 4 + ['ok'] * 6, order
        assert pg.locator('#res-dns b').count() == 0  # server text escaped
        pg.set_viewport_size({'width': 1269, 'height': 1500}); pg.evaluate("document.querySelector('main').scrollTop = 0")
        pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'dns-controlli-{theme}.png'))
        dtab('rec')
        assert pg.locator(DS + '[data-rpane="rec"] tbody tr').count() == 13
        types = pg.eval_on_selector_all(DS + '[data-rpane="rec"] .dx-type', 't => t.map(x => x.textContent)')
        assert types == ['A', 'AAAA', 'NS', '', '', 'SOA', 'MX', 'TXT', 'CAA', 'DNSKEY', '', 'DS', 'TLSA'], types
        t = pg.inner_text(DS + '[data-rpane="rec"]')
        assert all(x in t for x in ('30 s', '1 h', '1 g', '5 min', '_443._tcp.example.com', 'Tipi senza risposta: HTTPS.')), t
        pg.screenshot(path=str(OUT / f'dns-record-{theme}.png'))
        dtab('del')
        assert pg.locator(DS + '[data-rpane="del"] .hx-hop').count() == 4
        t = pg.inner_text(DS + '[data-rpane="del"]')
        assert all(x in t for x in ('nel registro', 'non nel registro', 'non nella zona', 'autoritativo', 'seriale 2026111501', 'non risponde', '31 ms',
                                    '2001:db8:53::4', 'Delega letta dai name server di com')), t
        assert 'AXFR' not in t, t
        pills = pg.eval_on_selector_all(DS + '[data-rpane="del"] .hx-hop:nth-child(2) .pill.err', 'p => p.map(x => x.textContent)')
        assert pills == ['seriale 2026111501'], pills
        pg.screenshot(path=str(OUT / f'dns-delega-{theme}.png'))
        dtab('sec')
        t = pg.inner_text(DS + '[data-rpane="sec"]')
        assert all(x in t for x in ('DS nel registro', 'KSK (257)', 'Firma di SOA', 'tra 3 ore', 'NSEC3 · 0 iterazioni', 'Validazione', 'Resolver che valida (1.1.1.1), con CD',
                                    'non verifica le firme')), t
        pg.screenshot(path=str(OUT / f'dns-dnssec-{theme}.png'))
        pg.click(DS + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('CONTROLLI', 'RECORD', 'DELEGA', 'DNSSEC', 'example.com. 30 IN A 203.0.113.10', '_443._tcp.example.com. 300 IN TLSA',
                                    'ns3.example.net 198.51.100.53 · nel registro · non nella zona · nessuna risposta', '[!] Firma di SOA')), c
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # with AXFR: request, extra error, labels in the delegation
        pg.check('#dnsd-axfr'); pg.press('#dnsd-domain', 'Enter')
        pg.wait_for_selector(DS + '.kv >> text=3 errori')
        assert calls('dns_domain')[-1][1] == {'domain': 'example.com', 'axfr': True}
        dtab('del'); t = pg.inner_text(DS + '[data-rpane="del"]')
        assert 'AXFR consentito' in t and t.count('AXFR rifiutato') == 2, t
        pg.uncheck('#dnsd-axfr')
        # network that does not let DNS out: information, not errors; subdomain reported back to the zone
        pg.fill('#dnsd-domain', 'srv01.corp.example'); pg.press('#dnsd-domain', 'Enter')
        pg.wait_for_selector(DS + '.kv >> text=Non raggiungibili dal PC')
        t = pg.inner_text(DS)
        assert all(x in t for x in ('2 avvisi', 'Non firmato', "fa parte della zona corp.example", 'porta 53')), t
        assert 'errore' not in pg.inner_text(DS + '.kv'), t
        dtab('del'); t = pg.inner_text(DS + '[data-rpane="del"]')
        assert t.count('non raggiungibile') == 2 and 'non risponde' not in t and 'registro' in t and 'senza confronto con il registro' in t, t
        assert pg.locator(DS + '[data-rpane="del"] .pill.err').count() == 0
        dtab('sec'); t = pg.inner_text(DS + '[data-rpane="sec"]')
        assert 'La zona non è firmata con DNSSEC' in t and 'validazione non controllata' in t, t
        pg.screenshot(path=str(OUT / f'dns-rete-chiusa-{theme}.png'))
        # back to the comparison: the same form as before, with its values
        pg.click('#view-dns [data-tabs="dns"] [data-tab="compare"]')
        assert pg.locator('#view-dns [data-pane="dns-compare"]').is_visible() and pg.input_value('#dns-host') == 'example.com'
        pg.press('#dns-host', 'Enter'); pg.wait_for_selector('#res-dns .strip:first-child >> text=DNS A')
        assert len(calls('dns')) == n_dns + 1
        # SNMP: device in tabs (checks, system, interfaces with live counters, neighbours,
        # MAC and ARP), tables with CSV, built-in names (suggestions and tree), profiles without secrets, "Ferma"
        pg.click('.nav-item[data-view="snmp"]')
        NS = '#res-snmp .strip:first-child '
        NB = '#snmp-go'
        ntab = lambda k: pg.click(NS + f'.seg.rtabs [data-rtab="{k}"]')
        ntabs = lambda: pg.eval_on_selector_all(NS + '.seg.rtabs button', 'b => b.map(x => x.innerText.replace(/\\s+/g, " ").trim())')
        norder = lambda: pg.eval_on_selector_all(NS + '[data-rpane="chk"] tbody tr td:first-child .pill', 'p => p.map(x => ["err", "warn", "info", "ok"].find(c => x.classList.contains(c)))')
        vis = lambda sel: pg.locator(sel).is_visible()
        # form: "Dispositivo" (Device) on opening, a single submit button that changes name with the switch
        assert pg.locator('#view-snmp button[type=submit]').count() == 1 and pg.inner_text(NB) == 'Analizza'
        assert vis('#snmp-s-fdb') and not vis('#snmp-oid') and not vis('#snmp-browse') and not vis('#snmp-oids')
        assert pg.input_value('#snmp-port') == '' and pg.inner_text('label[for="snmp-port"]') == 'Porta (161)'
        pg.click('#snmp-what [data-snmode="oid"]')
        assert pg.inner_text(NB) == 'Interroga' and vis('#snmp-oid') and vis('#snmp-browse') and vis('#snmp-oids') and not vis('#snmp-s-fdb')
        assert pg.eval_on_selector_all('#snmp-mode option', 'o => o.map(x => x.value)') == ['get', 'walk', 'table']
        assert pg.eval_on_selector_all('#snmp-oids .chip', 'c => c.map(x => x.textContent)') == ['Descrizione', 'Uptime', 'Nome', 'Interfacce', 'Indirizzi IP', 'Dischi e memoria', 'Carico CPU', 'Materiali di consumo']
        pg.click('#snmp-what [data-snmode="dev"]')
        assert pg.inner_text(NB) == 'Analizza' and pg.evaluate("localStorage.getItem('ntb-snmp-what')") == '"dev"'

        # profiles: host, port, version, user and protocols; never community or password
        assert pg.locator('#snmp-profiles .saved').count() == 0
        pg.click('[data-tabs="snmp"] [data-tab="v3"]')
        pg.fill('#snmp-host', 'sw-core01.corp.example'); pg.fill('#snmp-port', '1161'); pg.fill('#snmp-user', 'lettura')
        pg.select_option('#snmp-authproto', 'SHA-256'); pg.fill('#snmp-authpass', 'Segreta-auth-1'); pg.fill('#snmp-privpass', 'Segreta-priv-1')
        pg.click('#snmp-prof-save')
        assert pg.eval_on_selector_all('#snmp-profiles .saved [data-snprof]', 'c => c.map(x => x.textContent)') == ['sw-core01.corp.example · v3 lettura']
        saved = pg.evaluate("localStorage.getItem('ntb-snmp-profiles')")
        assert 'SHA-256' in saved and '1161' in saved and 'lettura' in saved, saved
        assert all(x not in saved for x in ('Segreta', 'public', 'pass', 'community')), saved
        pg.click('#snmp-prof-save')   # same profile: replaced, not duplicated
        assert pg.locator('#snmp-profiles .saved').count() == 1
        pg.click('[data-tabs="snmp"] [data-tab="v2c"]'); pg.fill('#snmp-host', 'fw01'); pg.fill('#snmp-port', ''); pg.select_option('#snmp-ver', '1')
        pg.click('#snmp-prof-save')
        assert pg.eval_on_selector_all('#snmp-profiles .saved [data-snprof]', 'c => c.map(x => x.textContent)') == ['sw-core01.corp.example · v3 lettura', 'fw01 · v1']
        pg.click('#snmp-profiles [data-snprof="0"]')
        assert pg.get_attribute('[data-tabs="snmp"] [data-tab="v3"]', 'aria-selected') == 'true' and vis('#snmp-authpass') and not vis('#snmp-comm')
        assert (pg.input_value('#snmp-host'), pg.input_value('#snmp-port'), pg.input_value('#snmp-user'), pg.input_value('#snmp-authproto')) == ('sw-core01.corp.example', '1161', 'lettura', 'SHA-256')
        assert pg.input_value('#snmp-authpass') == '' and pg.input_value('#snmp-privpass') == ''
        assert pg.evaluate('document.activeElement.id') == 'snmp-authpass'
        pg.click('#snmp-profiles [data-snprof="1"]')
        assert pg.get_attribute('[data-tabs="snmp"] [data-tab="v2c"]', 'aria-selected') == 'true' and pg.input_value('#snmp-ver') == '1'
        assert pg.input_value('#snmp-comm') == '' and pg.input_value('#snmp-port') == '' and pg.evaluate('document.activeElement.id') == 'snmp-comm'
        pg.click('#snmp-profiles [data-snprofx="1"]')
        assert pg.locator('#snmp-profiles .saved').count() == 1
        if theme == 'light': pg.click('#snmp-profiles [data-snprofx="0"]')

        # whole device with v2c and default community
        pg.select_option('#snmp-ver', '2c'); pg.fill('#snmp-host', 'sw-core01.corp.example'); pg.fill('#snmp-comm', 'public')
        n_dev = len(calls('snmp_device'))
        pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.warn >> text=Dispositivo')
        assert len(calls('snmp_device')) == n_dev + 1 and not calls('snmp')
        assert calls('snmp_device')[-1][1] == {'system': True, 'interfaces': True, 'neighbors': True, 'fdb': True, 'resources': True, 'printer': True, 'host': 'sw-core01.corp.example', 'port': '', 'version': '2c', 'community': 'public'}
        t = pg.inner_text(NS)
        assert all(x in t for x in ('sw-core01', '1 errore · 2 avvisi', '8 attive su 10', '41 giorni', 'Community predefinita', 'Protocollo in chiaro', 'Errori sulle porte')), t
        assert ntabs() == ['Controlli9', 'Sistema', 'Interfacce10', 'Vicini4', 'MAC e ARP61'], ntabs()
        assert norder() == ['err'] + ['warn'] * 2 + ['info'] * 3 + ['ok'] * 3, norder()
        assert pg.inner_text(NB) == 'Analizza' and pg.get_attribute('#view-snmp form', 'data-running') is None
        pg.set_viewport_size({'width': 1269, 'height': 1650}); pg.evaluate("document.querySelector('#view-snmp').scrollIntoView()")
        pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'snmp-controlli-{theme}.png'))
        ntab('sys'); t = pg.inner_text(NS + '[data-rpane="sys"]')
        assert all(x in t for x in ('SW-2426X', 'EX4K2026A0117', '41 giorni, 3 ore', "avvio dell'agente il", 'livello 2 (switch) · livello 3 (router)', '1.3.6.1.4.1.99999.1.3.24',
                                    'Indirizzi IP', '255.255.254.0 (/23)', 'vlan10', 'Indirizzo interrogato')), t
        assert 'Engine ID' not in t and 'Unità dello stack' not in t
        pg.screenshot(path=str(OUT / f'snmp-sistema-{theme}.png'))

        # interfaces: column table, speed only with live counters
        ntab('if')
        IFP = NS + '[data-rpane="if"] '
        assert pg.eval_on_selector_all(IFP + 'thead th', 't => t.map(x => x.textContent)') == ['Porta', 'Stato', 'Velocità', 'Ingresso', 'Uscita', 'Errori', 'Scarti']
        assert pg.locator(IFP + 'tbody tr').count() == 10 and pg.locator(IFP + 'tbody tr.off').count() == 2
        row = lambda i: pg.eval_on_selector_all(IFP + f'tbody tr[data-if="{i}"] td', 't => t.map(x => x.innerText.replace(/\\s+/g, " ").trim())')
        assert row(14) == ['1/14 telecamera ingresso', 'attiva', '100 Mb/s', '—', '—', '1204', '37'], row(14)
        assert row(25)[2] == '10 Gb/s' and row(27)[:3] == ['lag1 uplink (1/25 + 1/26)', 'attiva', '20 Gb/s'] and row(3)[1] == 'scollegata' and row(15)[1] == 'disattivata'
        assert '8 attive su 10 · 1 con errori' in pg.inner_text(IFP + '.summary') and pg.locator(IFP + '.sn-bar').count() == 0
        pg.click(IFP + '[data-snif="err"]'); assert pg.locator(IFP + 'tbody tr').count() == 1
        pg.click(IFP + '[data-snif="up"]'); assert pg.locator(IFP + 'tbody tr').count() == 8
        pg.click(IFP + '[data-snif="all"]')
        # live counters: same request as the analysis, samples on the Channel, "Ferma" on the same button
        n_mon, n_ms = len(calls('snmp_monitor')), len(calls('snmp_monitor_stop'))
        assert pg.inner_text(IFP + '[data-snmon]') == 'Contatori dal vivo'
        pg.click(IFP + '[data-snmon]')
        pg.wait_for_selector(IFP + '.sn-live >> text=00:1')
        assert calls('snmp_monitor')[-1][1] == {'host': 'sw-core01.corp.example', 'port': '', 'version': '2c', 'community': 'public'}
        assert pg.inner_text(IFP + '[data-snmon]') == 'Ferma' and 'Dal vivo · ogni 5 s' in pg.inner_text(IFP + '.sn-live')
        r = row(14)
        assert r[3] == '6,8 Mb/s' and r[4] == '200 kb/s' and r[5].startswith('+') and r[5].endswith(')') and r[6].startswith('+'), r
        assert row(25)[3] == '8,2 Gb/s' and row(3)[3] == '—' and row(1)[5] == '0', (row(25), row(3), row(1))
        # utilisation bar: above 70% of the port speed it changes colour
        assert pg.locator(IFP + 'tbody tr[data-if="25"] .sn-bar i.hot').count() == 1 and pg.locator(IFP + 'tbody tr[data-if="1"] .sn-bar i.hot').count() == 0
        assert pg.locator(IFP + 'tbody tr[data-if="110"] .sn-bar').count() == 0   # without nominal speed no bar
        pg.wait_for_timeout(120); pg.screenshot(path=str(OUT / f'snmp-interfacce-running-{theme}.png'))
        # the filter stays while the samples arrive
        pg.click(IFP + '[data-snif="err"]'); pg.wait_for_timeout(80)
        assert pg.locator(IFP + 'tbody tr').count() == 1 and pg.get_attribute(IFP + '[data-snif="err"]', 'class') == 'chip on'
        pg.click(IFP + '[data-snif="all"]')
        pg.click(IFP + '[data-snmon]')
        pg.wait_for_selector(IFP + '.sn-live.off')
        assert len(calls('snmp_monitor_stop')) == n_ms + 1 and len(calls('snmp_monitor')) == n_mon + 1
        assert 'Fermato dopo' in pg.inner_text(IFP + '.sn-live') and pg.inner_text(IFP + '[data-snmon]') == 'Contatori dal vivo'
        assert row(14)[3] == '6,8 Mb/s'   # the last values remain
        pg.click(IFP + '[data-sncsv="if"]'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied').split('\r\n')
        assert c[0] == 'Porta;Descrizione;Stato;Velocità (bit/s);MAC;MTU;Tipo;Errori in;Errori out;Scarti in;Scarti out;Ingresso (bit/s);Uscita (bit/s)', c[0]
        assert len(c) == 11 and c[4].startswith('1/14;telecamera ingresso;attiva;100000000;02:00:5e:00:00:14;1500;ethernetCsmacd;1204;0;37;0;6800000;200000'), c[4]
        # monitor that closes by itself: the reason stays written
        pg.evaluate('window.__snMonErr = true'); pg.click(IFP + '[data-snmon]')
        pg.wait_for_selector(IFP + '.sn-monerr >> text=Monitor interrotto: Nessuna risposta da sw-core01.corp.example')
        pg.evaluate('window.__snMonErr = false')

        # LLDP neighbours: list with the labels, row actions
        ntab('nb')
        NBP = NS + '[data-rpane="nb"] '
        assert pg.locator(NBP + '.hx-hop').count() == 4
        t = pg.inner_text(NBP)
        assert all(x in t for x in ('4 vicini annunciati con LLDP', '1/25', 'sw-dist01.corp.example', 'porta', '2/1', 'uplink core', 'switch', 'router', '172.16.0.2', 'access point', 'telefono', 'senza IP di gestione')), t
        assert pg.locator(NBP + 'b >> text=Wi-Fi 6').count() == 0   # text announced by the neighbour: escaped
        assert pg.locator(NBP + '[data-goto]').count() == 6
        pg.screenshot(path=str(OUT / f'snmp-vicini-{theme}.png'))
        pg.click(NBP + '.hx-hop:nth-child(2) [data-goto="snmp"]')
        assert pg.input_value('#snmp-host') == '172.16.0.3' and len(calls('snmp_device')) == n_dev + 1
        pg.fill('#snmp-host', 'sw-core01.corp.example')
        pg.click(NBP + '[data-sncsv="nb"]'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied').split('\r\n')
        assert len(c) == 5 and c[1] == '1/25;sw-dist01.corp.example;2/1;uplink core;switch, router;172.16.0.2;02:00:5e:10:00:01;Switch L3 48 porte, firmware 4.2.1', c[1]

        # MAC and ARP: table with search, filters and CSV
        ntab('fdb')
        FP = NS + '[data-rpane="fdb"] '
        assert pg.eval_on_selector_all(FP + 'thead th', 't => t.map(x => x.textContent)') == ['MAC', 'Produttore', 'Indirizzo IP', 'Porta', 'VLAN', 'Tipo', '']
        assert pg.locator(FP + 'tbody tr').count() == 61
        t = pg.inner_text(FP)
        assert all(x in t for x in ('61 indirizzi MAC su 5 porte · 31 con indirizzo IP', 'Produttore di prova', 'amministrato in locale', '172.16.20.11', '172.16.20.12', 'statico', 'apparato', 'solo ARP', 'Q-BRIDGE-MIB')), t
        pg.screenshot(path=str(OUT / f'snmp-mac-arp-{theme}.png'))
        pg.click(FP + '[data-snq]'); pg.keyboard.type('00-50-56')   # hyphens instead of colons
        assert pg.locator(FP + 'tbody tr').count() == 2 and pg.evaluate('document.activeElement.matches("[data-snq]")')
        assert pg.input_value(FP + '[data-snq]') == '00-50-56'
        pg.fill(FP + '[data-snq]', '1/14'); assert pg.locator(FP + 'tbody tr').count() == 1
        pg.fill(FP + '[data-snq]', 'zzz'); assert 'Nessun indirizzo con questo filtro' in pg.inner_text(FP + 'tbody')
        pg.fill(FP + '[data-snq]', '')
        pg.click(FP + '[data-snfdb="noip"]'); assert pg.locator(FP + 'tbody tr').count() == 30
        pg.click(FP + '[data-snfdb="multi"]'); assert pg.locator(FP + 'tbody tr').count() == 56   # lag1 (54) e 1/23 (2)
        pg.click(FP + '[data-snfdb="all"]')
        pg.click(FP + '[data-sncsv="fdb"]'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied').split('\r\n')
        assert len(c) == 62 and c[0] == 'MAC;Produttore;Indirizzo IP;Porta;VLAN;Tipo' and c[2] == '00:50:56:01:02:03;Produttore di prova;172.16.20.11 172.16.20.12;1/23;20;dinamico', c[:3]
        n_ping = len(calls('ping')) + len(calls('ping_stream'))
        pg.click(FP + 'tbody tr:nth-child(1) [data-goto="ping"]')
        assert pg.locator('#view-ping').is_visible() and pg.input_value('#ping-host') == '172.16.0.2' and len(calls('ping')) + len(calls('ping_stream')) == n_ping + 1
        pg.click('.nav-item[data-view="snmp"]')
        # "Copia" (Copy) takes all the tabs
        pg.click(NS + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('SNMP · sw-core01.corp.example (172.16.0.1)', 'CONTROLLI', '[✕] Sicurezza · Community predefinita', 'SISTEMA', 'Unità: Unità 1 · SW-2426X · EX4K2026A0117 · 4.2.1', 'INTERFACCE',
                                    '1/14 · telecamera ingresso · attiva · 100 Mb/s', 'VICINI LLDP', '1/25 → sw-dist01.corp.example · porta 2/1', 'MAC E ARP', '00:50:56:01:02:03 · Produttore di prova')), c
        pg.set_viewport_size({'width': 1269, 'height': 860})

        # chosen sections: request and tabs; v3 with encryption: no security warning, Engine ID
        pg.uncheck('#snmp-s-nb'); pg.uncheck('#snmp-s-fdb')
        pg.click('[data-tabs="snmp"] [data-tab="v3"]'); pg.fill('#snmp-user', 'lettura'); pg.fill('#snmp-authpass', 'Segreta-auth-1'); pg.fill('#snmp-privpass', 'Segreta-priv-1')
        pg.click(NB); pg.wait_for_selector(NS + '.kv >> text=1 avviso')
        q = calls('snmp_device')[-1][1]
        assert (q['neighbors'], q['fdb'], q['version'], q['sec_level'], q['auth_pass']) == (False, False, '3', 'authPriv', 'Segreta-auth-1') and 'community' not in q, q
        assert ntabs() == ['Controlli6', 'Sistema', 'Interfacce10'], ntabs()
        assert pg.evaluate("localStorage.getItem('ntb-snmp-s-fdb')") == 'false'
        ntab('sys'); assert '80 00 1F 88 80 5A 3C 11 0D 42 7E 01' in pg.inner_text(NS + '[data-rpane="sys"]')
        assert 'Segreta' not in pg.evaluate("JSON.stringify(localStorage)") and 'Segreta' not in pg.inner_text('#res-snmp')
        pg.check('#snmp-s-nb'); pg.check('#snmp-s-fdb'); pg.click('[data-tabs="snmp"] [data-tab="v2c"]')

        # router: no LLDP, ARP table only, 32-bit counters
        pg.fill('#snmp-host', 'fw01'); pg.fill('#snmp-comm', 'una-community-lunga'); pg.click(NB)
        pg.wait_for_selector(NS + '.strip-target >> text=fw01')
        pg.wait_for_selector(NS + '.kv >> text=2 attive su 3')
        assert ntabs() == ['Controlli7', 'Sistema', 'Interfacce3', 'Vicini0', 'MAC e ARP2'], ntabs()
        ntab('nb'); assert 'non espone la LLDP-MIB' in pg.inner_text(NS + '[data-rpane="nb"]')
        ntab('fdb'); t = pg.inner_text(NS + '[data-rpane="fdb"]')
        assert 'Interfaccia' in t and 'non è uno switch' in t and '2 indirizzi MAC · 2 con indirizzo IP' in t, t
        ntab('if'); pg.click(NS + '[data-snmon]'); pg.wait_for_selector(NS + '.sn-live >> text=00:0')
        assert 'a 32 bit (ifInOctets, ifOutOctets)' in pg.inner_text(NS + '[data-rpane="if"]')
        # result cleared with the monitor on: the monitor stops by itself
        n_ms = len(calls('snmp_monitor_stop'))
        pg.click('#res-snmp .link-btn'); pg.wait_for_timeout(120)
        assert len(calls('snmp_monitor_stop')) >= n_ms + 1 and pg.locator('#res-snmp .strip').count() == 0

        # printer and server : the Stampante and Risorse tabs exist only if the device has the data
        sev = lambda: [x for x in norder()]
        pg.fill('#snmp-host', 'prn01.corp.example'); pg.click(NB)
        pg.wait_for_selector(NS + '.strip-target >> text=prn01')
        q = calls('snmp_device')[-1][1]
        assert q['resources'] is True and q['printer'] is True, q
        assert ntabs() == ['Controlli12', 'Sistema', 'Stampante6', 'Interfacce3', 'Vicini0', 'MAC e ARP2'], ntabs()
        kv = pg.inner_text(NS + '.kv')
        assert 'Stato' in kv and 'Inattiva' in kv and '1 da sostituire' in kv, kv
        o = sev(); assert o == sorted(o, key=['err', 'warn', 'info', 'ok'].index), o
        assert 'Materiale in esaurimento' in pg.inner_text(NS + '[data-rpane="chk"]') and 'Vassoio vuoto' in pg.inner_text(NS + '[data-rpane="chk"]')
        ntab('prn'); P = NS + '[data-rpane="prn"] '
        t = pg.inner_text(NS + '[data-rpane="prn"]')
        assert all(x in t for x in ('6 materiali di consumo', '48.213', 'PRN0123456', 'Toner nero', '12 %', 'Toner ciano', '35 % pieno', "almeno un'unità", 'sconosciuto',
                                    'Cassetto 2', 'vuoto', 'almeno un foglio', 'Cassetto 2 vuoto', 'vassoio di ingresso', 'carta in esaurimento', '1 da sostituire')), t
        assert pg.locator(P + '.rs-row').count() == 6 and pg.locator(P + '.sw').count() == 4
        assert pg.locator(P + '.rs-bar i.pc-cyan').count() == 1 and pg.locator(P + '.rs-bar i.pc-black').count() == 1
        assert pg.eval_on_selector(P + '.rs-bar i.pc-black', 'e => e.style.width') == '12%'
        assert pg.locator(P + '.rs-row .v .c-warn').count() == 1          # only the black toner is below 15 %
        assert pg.locator(P + '.rs-bar i.err').count() == 1               # the empty tray
        pg.click(P + '[data-sncsv="prn"]'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert c.startswith('Materiale;Tipo;Classe;Colore;Livello (%);Stato') and 'Toner nero;toner;si consuma;black;12;warn' in c and 'Unità fusore;fuser;si consuma;;;unknown' in c, c
        pg.click(NS + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('STAMPANTE', 'Stampante laser a colori · Inattiva · matricola PRN0123456 · 48.213 pagine', 'Toner nero: 12 %', 'Contenitore toner di scarto: 35 % pieno',
                                    'Vassoio Cassetto 2 (A4): vuoto', 'Allarme (avviso): Cassetto 2 vuoto', '[!] Stampante · Materiale in esaurimento')), c
        pg.set_viewport_size({'width': 1269, 'height': 1500}); pg.evaluate("document.querySelector('#view-snmp').scrollIntoView()"); pg.wait_for_timeout(300)
        pg.screenshot(path=str(OUT / f'snmp-stampante-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # the section can be removed from the form: the request says so and the tab disappears
        pg.uncheck('#snmp-s-prn'); pg.click(NB); pg.wait_for_selector(NS + '.strip-target >> text=prn01')
        assert calls('snmp_device')[-1][1]['printer'] is False and 'Stampante6' not in ntabs() and 'Stampante' not in ' '.join(ntabs()), ntabs()
        assert pg.evaluate("localStorage.getItem('ntb-snmp-s-prn')") == 'false'
        pg.check('#snmp-s-prn')

        pg.fill('#snmp-host', 'srv01.corp.example'); pg.click(NB)
        pg.wait_for_selector(NS + '.strip-target >> text=srv01')
        assert ntabs() == ['Controlli11', 'Sistema', 'Risorse5', 'Interfacce3', 'Vicini0', 'MAC e ARP2'], ntabs()
        kv = pg.inner_text(NS + '.kv')
        assert 'CPU' in kv and '24 %' in kv and 'Memoria' in kv and '56 %' in kv, kv
        assert 'Disco quasi pieno' in pg.inner_text(NS + '[data-rpane="chk"]')
        ntab('res'); R = NS + '[data-rpane="res"] '
        t = pg.inner_text(NS + '[data-rpane="res"]')
        assert all(x in t for x in ('143 processi', '2 utenti collegati', 'CPU · MEDIA DI 2 PROCESSORI', 'MEMORIA FISICA', '9 GB di 16 GB', 'Processore 1', 'C:\\ Label:Sistema', '93 %', 'liberi',
                                    'Processi che usano più memoria', 'sqlservr.exe', 'Primi 3 su 143', '3:20:00')), t
        assert pg.locator(R + '.rs-card').count() == 3 and pg.locator(R + '.rs-bar i.warn').count() == 1 and pg.locator(R + '.rs-bar i.err').count() == 1
        pg.click(R + '[data-sncsv="res"]'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert c.startswith('Tipo;Nome;Totale (byte);Usato (byte);Usato (%)') and 'disk;D:\\ Label:Dati;409600000000;380928000000;93' in c and 'processore;Processore 0;;;12' in c, c
        pg.click(NS + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('RISORSE', 'CPU: 24 % (media di 2)', 'E:\\ Label:Archivio: 99 %', 'Processo sqlservr.exe')), c
        pg.set_viewport_size({'width': 1269, 'height': 1500}); pg.evaluate("document.querySelector('#view-snmp').scrollIntoView()"); pg.wait_for_timeout(300)
        pg.screenshot(path=str(OUT / f'snmp-risorse-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.fill('#snmp-host', 'fw01')

        # "Ferma" while reading the device: same button, a single snmp_stop, partial result
        pg.fill('#snmp-host', 'lento'); n_st = len(calls('snmp_stop')); n_dev = len(calls('snmp_device'))
        pg.click(NB)
        pg.wait_for_selector(NS + '.strip-body >> text=Lettura: Sistema (1 di 6)')
        assert pg.inner_text(NB) == 'Ferma' and pg.get_attribute('#view-snmp form', 'data-running') == '1'
        pg.wait_for_selector(NS + '.strip-body >> text=Lettura: Interfacce (2 di 6)')
        pg.screenshot(path=str(OUT / f'snmp-running-{theme}.png'))
        pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.stop >> text=Lettura fermata')
        assert len(calls('snmp_stop')) == n_st + 1 and len(calls('snmp_device')) == n_dev + 1
        assert pg.inner_text(NB) == 'Analizza' and pg.is_enabled(NB) and '■ Fermato' in pg.inner_text(NS + '.strip-state')
        # silent agent and port out of range: backend errors
        pg.fill('#snmp-host', 'muto'); pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.err >> text=Nessuna risposta da muto')
        pg.fill('#snmp-host', 'fw01'); pg.fill('#snmp-port', '70000'); pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.err >> text=Porta: da 1 a 65535')
        pg.fill('#snmp-port', '')

        # OIDs and tables: suggestions while typing
        pg.click('#snmp-what [data-snmode="oid"]')
        pg.fill('#snmp-oid', ''); pg.click('#snmp-oid'); pg.keyboard.type('if')
        pg.wait_for_selector('#snmp-sug .sn-node')
        assert len(calls('snmp_names')) == 1
        sug = pg.eval_on_selector_all('#snmp-sug .sn-node .nm', 'n => n.map(x => x.firstChild.textContent + x.childNodes[1].textContent)')
        assert len(sug) == 8 and sug[0] == 'ifTable' and all(s.startswith('if') for s in sug), sug
        assert 'altri' in pg.inner_text('#snmp-sug .sn-more') and pg.locator('#snmp-sug mark').count() == 8
        pg.keyboard.press('ArrowDown'); pg.keyboard.press('ArrowDown'); pg.keyboard.press('ArrowUp')
        assert pg.locator('#snmp-sug .sn-node.sel').count() == 1 and len(calls('snmp')) == 0
        pg.wait_for_timeout(60); pg.screenshot(path=str(OUT / f'snmp-suggerimenti-{theme}.png'))
        pg.keyboard.press('Enter')   # picks the suggestion, does not start the read
        assert pg.input_value('#snmp-oid') == 'ifTable' and pg.input_value('#snmp-mode') == 'table' and not vis('#snmp-sug') and len(calls('snmp')) == 0
        pg.fill('#snmp-oid', ''); pg.keyboard.type('sysn'); pg.wait_for_selector('#snmp-sug .sn-node'); pg.click('#snmp-sug .sn-node')
        assert pg.input_value('#snmp-oid') == 'sysName.0' and pg.input_value('#snmp-mode') == 'get'
        pg.fill('#snmp-oid', '1.3.6'); pg.wait_for_timeout(40); assert not vis('#snmp-sug')   # a numeric OID does not need it
        pg.fill('#snmp-oid', 'ifd'); pg.wait_for_selector('#snmp-sug .sn-node'); pg.keyboard.press('Escape'); assert not vis('#snmp-sug')
        # name tree behind "Sfoglia nomi" (Browse names)
        pg.click('#snmp-browse'); pg.wait_for_selector('#snmp-tree-list .sn-node')
        assert len(calls('snmp_names')) == 1 and '24 nomi di 5 MIB standard' in pg.inner_text('#snmp-tree-n')
        tree = lambda: pg.eval_on_selector_all('#snmp-tree-list .sn-node', 'n => n.map(x => [x.querySelector(".nm").childNodes[1].textContent, +x.style.getPropertyValue("--l")])')
        assert tree() == [['mib-2', 0], ['system', 1], ['interfaces', 1], ['host', 1], ['ifMIB', 1], ['lldpMIB', 0], ['lldpRemTable', 1]], tree()
        pg.click('#snmp-tree-list .sn-node >> text=interfaces')
        assert tree()[2:5] == [['interfaces', 1], ['ifNumber', 2], ['ifTable', 2]], tree()
        pg.click('#snmp-tree-list [data-snoid="1.3.6.1.2.1.2.2"] i')   # the triangle opens the table
        assert [x for x in tree() if x[1] == 3][0] == ['ifDescr', 3] and pg.input_value('#snmp-oid') == 'ifd'
        pad = pg.eval_on_selector_all('#snmp-tree-list .sn-node', 'n => n.map(x => parseFloat(getComputedStyle(x).paddingLeft))')
        assert pad[1] - pad[0] == 22, pad
        pg.set_viewport_size({'width': 1269, 'height': 1500}); pg.evaluate("document.querySelector('#view-snmp').scrollIntoView()"); pg.wait_for_timeout(300)
        pg.screenshot(path=str(OUT / f'snmp-albero-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.click('#snmp-tree-list [data-snoid="1.3.6.1.2.1.2.2.1.8"]')   # a column: branch
        assert pg.input_value('#snmp-oid') == 'ifOperStatus' and pg.input_value('#snmp-mode') == 'walk'
        pg.fill('#snmp-tree-q', 'montaggio')   # the filter also searches the descriptions and opens the branches
        assert tree() == [['mib-2', 0], ['host', 1], ['hrStorageTable', 2], ['hrStorageDescr', 3]], tree()
        pg.fill('#snmp-tree-q', 'zzz'); assert 'Nessun nome contiene' in pg.inner_text('#snmp-tree-list')
        pg.fill('#snmp-tree-q', 'hrstoraget'); pg.click('#snmp-tree-list [data-snoid="1.3.6.1.2.1.25.2.3"] .nm')
        assert pg.input_value('#snmp-oid') == 'hrStorageTable' and pg.input_value('#snmp-mode') == 'table'
        pg.fill('#snmp-tree-q', ''); pg.click('#snmp-browse'); assert not vis('#snmp-tree')

        # any table of rows and columns, with filter and CSV
        pg.fill('#snmp-host', 'sw-core01.corp.example'); pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.ok >> text=SNMP Tabella')
        assert calls('snmp')[-1][1] == {'oid': 'hrStorageTable', 'mode': 'table', 'host': 'sw-core01.corp.example', 'port': '', 'version': '2c', 'community': 'una-community-lunga'}
        assert pg.eval_on_selector_all(NS + 'thead th', 't => t.map(x => x.textContent)') == ['Indice', 'hrStorageType', 'hrStorageDescr', 'hrStorageAllocationUnits', 'hrStorageSize', 'hrStorageUsed']
        assert pg.get_attribute(NS + 'thead th:nth-child(2)', 'title') == '1.3.6.1.2.1.25.2.3.1.2'
        assert pg.eval_on_selector_all(NS + 'thead th', 't => t.map(x => x.classList.contains("num"))') == [False, False, False, True, True, True]
        t = pg.inner_text(NS)
        assert all(x in t for x in ('5 righe · 5 colonne · HOST-RESOURCES-MIB::hrStorageTable', '/srv/dati;archivio', '257003520', 'Protocollo in chiaro')) and 'Community predefinita' not in t, t
        pg.set_viewport_size({'width': 1269, 'height': 1250}); pg.evaluate("document.querySelector('#view-snmp').scrollIntoView()"); pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'snmp-tabella-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.fill(NS + '[data-sntf]', 'fixeddisk'); assert pg.locator(NS + 'tbody tr').count() == 3
        pg.fill(NS + '[data-sntf]', '')
        pg.click(NS + '[data-sncsv="table"]'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied').split('\r\n')
        assert c[0] == 'Indice;hrStorageType;hrStorageDescr;hrStorageAllocationUnits;hrStorageSize;hrStorageUsed' and c[5] == '40;hrStorageFixedDisk;"/srv/dati;archivio";4096;257003520;101224960', c
        pg.click(NS + '.strip-copy'); pg.wait_for_timeout(50)
        assert '36\thrStorageFixedDisk\t/var\t4096' in pg.evaluate('window.__copied')
        # large table: 300 rows shown, the rest with the filter or in the CSV
        pg.click('#snmp-oids .chip >> text=Interfacce'); assert pg.input_value('#snmp-oid') == 'ifTable' and pg.input_value('#snmp-mode') == 'table'
        pg.click(NB); pg.wait_for_selector(NS + '.summary >> text=310')
        assert pg.locator(NS + 'tbody tr').count() == 301 and 'altre 10 righe' in pg.inner_text(NS + 'tbody tr:last-child')
        pg.fill(NS + '[data-sntf]', 'porta 305'); assert pg.locator(NS + 'tbody tr').count() == 1
        pg.click(NS + '[data-sncsv="table"]'); pg.wait_for_timeout(50)
        assert len(pg.evaluate('window.__copied').split('\r\n')) == 311
        # branch that is not a table, single value, stopped walk
        pg.fill('#snmp-oid', 'lldpRemTable'); pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.warn >> text=Nessun valore sotto questo OID')
        pg.click('#snmp-oids .chip >> text=Nome'); pg.fill('#snmp-comm', 'public'); pg.click(NB)
        pg.wait_for_selector('#res-snmp .strip.ok >> text=SNMP GET')
        t = pg.inner_text(NS)
        assert 'sysName.0 = STRING: "sw-core01.corp.example"' in t and 'Community predefinita' in t and 'Protocollo in chiaro' in t, t
        assert 'è fra le prime community' in pg.get_attribute(NS + '.sn-sec span', 'title')
        pg.fill('#snmp-host', 'lento'); pg.select_option('#snmp-mode', 'walk'); n_st = len(calls('snmp_stop'))
        pg.click(NB); pg.wait_for_selector('#view-snmp form[data-running]')
        assert pg.inner_text(NB) == 'Ferma'
        # changing mode during the read does not touch the "Ferma" button; at the end it gets the right name
        pg.click('#snmp-what [data-snmode="dev"]'); assert pg.inner_text(NB) == 'Ferma'
        pg.click(NB); pg.wait_for_selector('#res-snmp .strip.stop >> text=fermato dopo 1 valori')
        assert len(calls('snmp_stop')) == n_st + 1 and pg.inner_text(NB) == 'Analizza'
        pg.fill('#snmp-host', ''); pg.fill('#snmp-comm', 'public'); pg.click('#res-snmp .link-btn')

        # Email: domain in tabs (SPF tree, DMARC and DKIM, MX with actions), headers in tabs
        pg.click('.nav-item[data-view="email"]')
        ES = '#res-email .strip:first-child '
        EB = '#view-email form[data-submit="email"] button[type=submit]'
        etab = lambda k: pg.click(ES + f'.seg.rtabs [data-rtab="{k}"]')
        etabs = lambda: pg.eval_on_selector_all(ES + '.seg.rtabs button', 'b => b.map(x => x.innerText.replace(/\\s+/g, " ").trim())')
        eorder = lambda: pg.eval_on_selector_all(ES + '[data-rpane="chk"] > table:first-child tbody tr td:first-child .pill', 'p => p.map(x => ["err", "warn", "info", "ok"].find(c => x.classList.contains(c)))')
        # domain without records
        pg.fill('#email-domain', 'vuoto.example.org'); pg.click(EB)
        pg.wait_for_selector('#res-email .strip.warn >> text=vuoto.example.org')
        assert calls('emailheader')[-1][1] == {'domain': 'vuoto.example.org', 'selector': '', 'ip': ''}
        t = pg.inner_text(ES)
        assert all(x in t for x in ('2 errori · 1 avviso', 'Assente', 'Non trovato')), t
        etab('spf'); assert 'non ha un record SPF' in pg.inner_text(ES + '[data-rpane="spf"]')
        etab('mx'); t = pg.inner_text(ES + '[data-rpane="mx"]')
        assert 'Nessun record MX' in t and 'Né MTA-STS né TLS-RPT' in t, t
        # invalid IP: backend error
        pg.fill('#email-ip', 'pippo'); pg.click(EB)
        pg.wait_for_selector('#res-email .strip.err >> text=IP da verificare non valido')
        # domain with defects, IP to check
        pg.fill('#email-domain', 'example.com'); pg.fill('#email-ip', '203.0.113.25'); pg.click(EB)
        pg.wait_for_selector(ES + '.kv >> text=11 lookup su 10')
        assert calls('emailheader')[-1][1] == {'domain': 'example.com', 'selector': '', 'ip': '203.0.113.25'}
        t = pg.inner_text(ES)
        assert all(x in t for x in ('1 errore · 3 avvisi', 'p=none', '2 selettori')), t
        assert etabs() == ['Controlli13', 'SPF11', 'DMARC e DKIM', 'MX e trasporto2'], etabs()
        assert eorder() == ['err'] + ['warn'] * 3 + ['info'] * 4 + ['ok'] * 5, eorder()
        pg.set_viewport_size({'width': 1269, 'height': 2100}); pg.evaluate("document.querySelector('#res-email').scrollIntoView()")
        pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'email-controlli-{theme}.png'))
        etab('spf')
        assert pg.locator(ES + '.sp-node').count() == 20
        levels = pg.eval_on_selector_all(ES + '.sp-node', 'n => n.map(x => +x.style.getPropertyValue("--l"))')
        assert levels == [0, 1, 1, 2, 3, 3, 2, 3, 3, 3, 3, 2, 1, 2, 2, 2, 2, 2, 1, 1], levels
        # the indentation follows the level: each level 26 px further right
        pad = pg.eval_on_selector_all(ES + '.sp-node', 'n => n.map(x => parseFloat(getComputedStyle(x).paddingLeft))')
        assert pad[1] - pad[0] == 26 and pad[4] - pad[1] == 52, pad
        t = pg.inner_text(ES + '[data-rpane="spf"]')
        assert all(x in t for x in ('Ricerca numero 11', 'non valutato (oltre il limite)', 'corrisponde a 203.0.113.25', 'decide', '11 ricerche DNS su 10',
                                    "l'esito è permerror", 'deciso da ip4:203.0.113.0/28')), t
        assert pg.locator(ES + '.sp-node .pill.err').count() == 1 and pg.locator(ES + '.sp-node .pill.ok').count() == 1
        assert pg.locator(ES + '.sp-mech.hx-dim').count() == 1
        pg.screenshot(path=str(OUT / f'email-spf-{theme}.png'))
        etab('dk'); t = pg.inner_text(ES + '[data-rpane="dk"]')
        assert all(x in t for x in ('_dmarc.example.com', 'i sottodomini ereditano p=none', 'adkim / aspf', 'selector2', 'RSA 1024 bit', 'chiave corta', 'Selettori provati: default, google')), t
        pg.screenshot(path=str(OUT / f'email-dmarc-dkim-{theme}.png'))
        etab('mx'); t = pg.inner_text(ES + '[data-rpane="mx"]')
        assert all(x in t for x in ('mail2.example.com', '2001:db8:25::11', 'Senza nome inverso', 'testing', 'copre tutti gli MX', '_smtp._tls.example.com', 'Policy letta da https://mta-sts.example.com')), t
        assert pg.locator(ES + '[data-rpane="mx"] .row-act button').count() == 6
        pg.screenshot(path=str(OUT / f'email-mx-{theme}.png'))
        pg.click(ES + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('CONTROLLI', 'SPF', 'DMARC', 'DKIM', 'MX', 'MTA-STS E TLS-RPT', '      a:out1.mail.example.net [1 lookup] → 192.0.2.201',
                                    'selector2: RSA 1024 bit', '20 mail2.example.com 203.0.113.11 2001:db8:25::11')), c
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # row actions: they fill the other tool's form without launching anything
        n_smtp, n_ssl, n_bl = len(calls('smtp_test')), len(calls('ssl')), len(calls('blacklist'))
        pg.click(ES + '[data-rpane="mx"] tbody tr:nth-child(2) [data-goto="ssl"]')
        assert pg.locator('#view-ssl').is_visible() and pg.input_value('#ssl-host') == 'mail2.example.com' and pg.input_value('#ssl-port') == '25' and pg.input_value('#ssl-proto') == 'smtp'
        pg.fill('#ssl-port', '443'); pg.select_option('#ssl-proto', 'auto')
        pg.click('.nav-item[data-view="email"]'); pg.click(ES + '[data-rpane="mx"] tbody tr:nth-child(1) [data-goto="smtp"]')
        assert pg.locator('#view-smtp').is_visible() and pg.input_value('#smtp-host') == 'mail1.example.com'
        pg.click('.nav-item[data-view="email"]'); pg.click(ES + '[data-rpane="mx"] tbody tr:nth-child(1) [data-goto="blacklist"]')
        assert pg.locator('#view-blacklist').is_visible() and pg.input_value('#bl-host') == '203.0.113.10'
        assert (len(calls('smtp_test')), len(calls('ssl')), len(calls('blacklist'))) == (n_smtp, n_ssl, n_bl)
        pg.click('.nav-item[data-view="email"]')
        # headers of a fake message: error, only the first Authentication-Results
        HB = '#view-email form[data-submit="emailraw"] button[type=submit]'
        pg.fill('#email-raw', 'Subject: Prova\nAuthentication-Results: spf=fail\n'); pg.click(HB)
        pg.wait_for_selector('#res-email .strip.err >> text=Header messaggio')
        t = pg.inner_text(ES)
        assert all(x in t for x in ('2 errori · 3 avvisi', 'SPF fail · DKIM none · DMARC fail', 'gli altri 1 più in basso', 'Nome visualizzato', '1 passo')), t
        etab('spam'); assert 'X-Spam-Flag' in pg.inner_text(ES + '[data-rpane="spam"]')
        # good message with a slow hop
        pg.fill('#email-raw', 'Subject: Ordine n. 4012\nFrom: ordini@example.org\n'); pg.click(HB)
        pg.wait_for_selector('#res-email .strip.warn >> text=Ordine n. 4012')
        t = pg.inner_text(ES)
        assert all(x in t for x in ('2 avvisi', 'SPF · DKIM · DMARC', '44 s in 4 passi', 'ordini@example.org')), t
        assert etabs() == ['Controlli9', 'Percorso4', 'Antispam2', 'Header4'], etabs()
        assert eorder() == ['warn'] * 2 + ['info'] * 3 + ['ok'] * 4, eorder()
        assert 'Firme DKIM del messaggio' in pg.inner_text(ES + '[data-rpane="chk"]')
        assert pg.locator('#res-email b').count() == 0  # message text escaped
        pg.set_viewport_size({'width': 1269, 'height': 1700}); pg.evaluate("document.querySelector('#res-email').scrollIntoView()")
        pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'email-header-{theme}.png'))
        etab('hop')
        assert pg.locator(ES + '[data-rpane="hop"] .hx-hop').count() == 4
        t = pg.inner_text(ES + '[data-rpane="hop"]')
        assert all(x in t for x in ('[192.0.2.44] → mail-out.example.org', 'mx1.example.com [203.0.113.10] → spam01.corp.example', 'partenza', '+2 s', '+41 s', 'senza TLS', 'TLS 1.2',
                                    "Dal primo all'ultimo server: 44 s")), t
        assert pg.eval_on_selector_all(ES + '[data-rpane="hop"] .pill.warn', 'p => p.map(x => x.textContent)') == ['+41 s']
        pg.screenshot(path=str(OUT / f'email-percorso-{theme}.png'))
        etab('hdr'); assert 'assistenza@example.net' in pg.inner_text(ES + '[data-rpane="hdr"]')
        pg.click(ES + '.strip-copy'); pg.wait_for_timeout(50)
        c = pg.evaluate('window.__copied')
        assert all(x in c for x in ('CONTROLLI', 'PERCORSO', 'ANTISPAM', 'HEADER', '3. mx1.example.com → spam01.corp.example  ESMTPS TLS 1.2  +41 s', 'Reply-To: assistenza@example.net')), c
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # from the DKIM signature to the domain form, with the selector
        etab('chk'); n_em = len(calls('emailheader'))
        pg.click(ES + '[data-goto="email"]')
        assert pg.input_value('#email-domain') == 'example.org' and pg.input_value('#email-sel') == 's1' and len(calls('emailheader')) == n_em
        pg.fill('#email-ip', ''); pg.click(EB)
        pg.wait_for_selector('#res-email .strip:first-child >> text=example.org')
        assert calls('emailheader')[-1][1] == {'domain': 'example.org', 'selector': 's1', 'ip': ''}
        assert 'nessun record per questo selettore' in pg.inner_text(ES)
        pg.fill('#email-sel', '')
        # subnet scan in streaming
        # rows of the first table of the most recent result strip (hosts or open ports)
        first_rows = lambda view: pg.evaluate("v => { const t = document.querySelector('#res-' + v + ' .strip').querySelector('table');"
                                              " return t ? [...t.querySelectorAll('tbody tr')].map(r => [r.dataset.ip || r.cells[0].textContent, r.cells[1].textContent]) : []; }", view)
        first_text = lambda view: pg.locator(f'#res-{view} .strip').first.inner_text()
        pg.click('.nav-item[data-view="sweep"]')
        SB = '#view-sweep button[type=submit]'
        sweep_label, sweep_box = pg.inner_text(SB), box(SB)
        assert not pg.is_checked('#sweep-tcp')
        pg.fill('#sweep-cidr', '192.0.2.0/29'); pg.check('#sweep-tcp'); pg.click(SB)
        pg.wait_for_selector('#res-sweep .strip.ok:first-child')
        assert calls('sweep')[-1][1] == {'cidr': '192.0.2.0/29', 'tcp': True}, calls('sweep')[-1]
        # once the scan is over: in address order, name arrived with the second sending of the same host
        assert first_rows('sweep') == [['192.0.2.1', '—'], ['192.0.2.2', 'srv01.corp.example']], first_rows('sweep')
        t = first_text('sweep')
        assert '2 host attivi su 6 in 1.4 secondi' in t and 'verifica TCP' not in t and 'MAC non disponibili' not in t, t
        assert '192.0.2.0/29 + TCP' in t, t
        assert pg.locator('#res-sweep .strip >> nth=0 >> [data-goto="wol"]').count() == 2
        assert pg.locator('#res-sweep .strip >> nth=0 >> .lan-progress').count() == 0
        assert pg.inner_text(SB) == sweep_label and box(SB) == sweep_box and not pg.is_disabled(SB)
        pg.wait_for_timeout(600)   # end of the strip appearing
        pg.screenshot(path=str(OUT / f'sweep-{theme}.png'))
        # network not attached to the PC and without hosts: warning, no table
        pg.fill('#sweep-cidr', '203.0.113.0/29'); pg.uncheck('#sweep-tcp'); pg.click(SB)
        pg.wait_for_selector('#res-sweep .strip.warn:first-child')
        t = first_text('sweep')
        assert '0 host attivi' in t and 'attiva la verifica TCP' in t and 'MAC non disponibili' in t, t
        assert first_rows('sweep') == []
        # "Ferma": hosts in arrival order during the scan, row updated with the name, then in address order
        n_sweep, n_stop = len(calls('sweep')), len(calls('sweep_stop'))
        pg.fill('#sweep-cidr', '198.51.100.0/24'); pg.click(SB)
        pg.wait_for_selector('#res-sweep .strip.run:first-child')
        assert pg.inner_text(SB) == 'Ferma' and 'secondary' in pg.get_attribute(SB, 'class') and box(SB) == sweep_box
        pg.wait_for_function("(() => { const r = document.querySelector('#res-sweep .strip tr[data-ip=\"198.51.100.10\"]');"
                             " return r && r.cells[1].textContent === 'vm10.corp.example'; })()")
        rows = first_rows('sweep')
        assert [r[0] for r in rows[:2]] == ['198.51.100.10', '198.51.100.5'], rows
        assert [r[0] for r in rows].count('198.51.100.10') == 1, rows
        t = first_text('sweep')
        assert 'host attivi ·' in t and 'controllati' in t, t
        pg.wait_for_function("document.querySelectorAll('#res-sweep .strip.run tbody tr').length >= 4")
        pg.screenshot(path=str(OUT / f'sweep-running-{theme}.png'))
        pg.click(SB)
        pg.wait_for_selector('#res-sweep .strip.stop:first-child')
        assert len(calls('sweep')) == n_sweep + 1 and len(calls('sweep_stop')) == n_stop + 1, 'Ferma ha avviato un altro test'
        ips = [r[0] for r in first_rows('sweep')]
        assert ips[:2] == ['198.51.100.5', '198.51.100.10'] and ips == sorted(ips, key=lambda ip: int(ip.rsplit('.', 1)[1])), ips
        t = first_text('sweep')
        assert 'scansione fermata dopo' in t and 'indirizzi su 254' in t and '■ Fermato' in t, t
        pg.wait_for_function(f"document.querySelector('{SB}').textContent === {sweep_label!r}")
        assert box(SB) == sweep_box and 'secondary' not in pg.get_attribute(SB, 'class')
        pg.screenshot(path=str(OUT / f'sweep-stopped-{theme}.png'))
        # from a host row to the port scan
        pg.click('#res-sweep .strip >> nth=0 >> tr[data-ip="198.51.100.5"] >> [data-goto="portscan"]')
        assert pg.locator('#view-portscan').is_visible() and pg.input_value('#scan-host') == '198.51.100.5'
        # TCP ports in streaming
        PSB = '#view-portscan button[type=submit]'
        ps_label, ps_box = pg.inner_text(PSB), box(PSB)
        pg.fill('#scan-host', 'fw01'); pg.fill('#scan-ports', ''); pg.click(PSB)
        pg.wait_for_selector('#res-portscan .strip.ok:first-child')
        req = calls('portscan')[-1][1]
        assert req['host'] == 'fw01' and req['ports'], req   # empty field = common ports
        # summary: open in port order, closed and filtered separate, reason for the block
        assert first_rows('portscan') == [['22', 'Aperta'], ['443', 'Aperta']], first_rows('portscan')
        t = first_text('portscan')
        assert '2 porte aperte su 5 controllate' in t and 'SSH-2.0-OpenSSH_9.6' in t, t
        assert 'Chiuse' in t and 'Filtrate' in t and 'Motivo' in t and '10013' in t and '3389' in t, t
        assert pg.locator('#res-portscan .strip >> nth=0 >> .strip-name').inner_text() == '198.51.100.1'
        assert pg.inner_text(PSB) == ps_label and box(PSB) == ps_box and not pg.is_disabled(PSB)
        pg.wait_for_timeout(600)
        pg.screenshot(path=str(OUT / f'portscan-{theme}.png'))
        pg.fill('#scan-host', 'firewall'); pg.click(PSB)
        pg.wait_for_selector('#res-portscan .strip.warn:first-child')
        t = first_text('portscan')
        assert '0 porte aperte' in t and 'Nessuna porta ha risposto' in t, t
        # "Ferma": open ports in arrival order, then partial summary in port order
        n_ps, n_stop = len(calls('portscan')), len(calls('portscan_stop'))
        pg.fill('#scan-host', 'lento'); pg.click(PSB)
        pg.wait_for_selector('#res-portscan .strip.run:first-child')
        assert pg.inner_text(PSB) == 'Ferma' and box(PSB) == ps_box
        pg.wait_for_function("document.querySelectorAll('#res-portscan .strip.run tbody tr').length === 2")
        assert [r[0] for r in first_rows('portscan')] == ['8080', '8022'], first_rows('portscan')
        t = first_text('portscan')
        assert '2 porte aperte ·' in t and 'su 100 controllate' in t, t
        pg.screenshot(path=str(OUT / f'portscan-running-{theme}.png'))
        pg.click(PSB)
        pg.wait_for_selector('#res-portscan .strip.stop:first-child')
        assert len(calls('portscan')) == n_ps + 1 and len(calls('portscan_stop')) == n_stop + 1, 'Ferma ha avviato un altro test'
        assert [r[0] for r in first_rows('portscan')] == ['8022', '8080'], first_rows('portscan')
        t = first_text('portscan')
        assert 'scansione fermata dopo' in t and 'porte su 100' in t and '■ Fermato' in t, t
        pg.wait_for_function(f"document.querySelector('{PSB}').textContent === {ps_label!r}")
        pg.screenshot(path=str(OUT / f'portscan-stopped-{theme}.png'))
        # local network
        pg.click('.nav-item[data-view="lan"]')
        assert pg.locator('#view-lan').is_visible()
        assert '172.16.0.0/21' in pg.inner_text('#lan-net')
        assert not pg.is_checked('#lan-svc')
        pg.check('#lan-svc')
        pg.click('#lan-btn')
        pg.wait_for_selector('#res-lan .strip.ok')
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'lan_scan'][-1][1]
        assert req == {'cidr': '', 'services': True}, req
        pg.wait_for_function("document.querySelectorAll('#lan-list .lan-row').length === 4")
        ips = pg.eval_on_selector_all('#lan-list .lan-row', 'r => r.map(x => x.dataset.ip)')
        assert ips == ['172.16.0.31', '172.16.1.47', '172.16.1.84', '172.16.1.200'], ips
        assert pg.inner_text('#lan-list .lan-row >> nth=0 >> .lan-title').startswith('vm11')
        assert pg.inner_text('#lan-list .lan-row >> nth=1 >> .lan-title') == 'KYOCERA ECOSYS MA4500ix'
        assert pg.inner_text('#lan-list .lan-row >> nth=1 >> .lan-svc') == '3 svc'
        assert 'MAC casuale' in pg.inner_text('#lan-list .lan-row >> nth=3 >> .lan-sub')
        assert '4 online' in pg.inner_text('#lan-sum') and '31,4 s' in pg.inner_text('#lan-sum')
        assert pg.locator('#lan-stop').is_hidden() and not pg.is_disabled('#lan-btn')
        pg.click('#lan-list .lan-row >> nth=1 >> .lan-main')
        pg.wait_for_selector('#lan-list .lan-detail')
        det = pg.inner_text('#lan-list .lan-detail')
        assert 'ECOSYS MA4500ix' in det and '9100' in det and 'KM-UFFICIO' in det, det
        pg.set_viewport_size({'width': 1269, 'height': 1250})
        pg.evaluate("document.querySelector('main').scrollTop = 0")
        pg.screenshot(path=str(OUT / f'lan-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.fill('#lan-filter', 'ssh'); pg.wait_for_timeout(100)
        assert pg.eval_on_selector_all('#lan-list .lan-row', 'r => r.map(x => x.dataset.ip)') == ['172.16.1.84']
        pg.fill('#lan-filter', ''); pg.select_option('#lan-sort', 'kind'); pg.wait_for_timeout(100)
        assert pg.eval_on_selector_all('#lan-list .lan-row', 'r => r.map(x => x.dataset.ip)')[0] == '172.16.0.31'
        pg.click('#lan-list .lan-detail [data-goto="snmp"]')
        assert pg.locator('#view-snmp').is_visible() and pg.input_value('#snmp-host') == '172.16.1.47'
        # Local network, Neighbours tab 
        pg.click('.nav-item[data-view="lan"]')
        assert pg.locator('.nav-item').count() == 21
        assert pg.locator('#view-lan [data-pane="lan-scan"]').is_visible() and pg.locator('#view-lan [data-pane="lan-neigh"]').is_hidden()
        pg.click('#view-lan [data-tab="neigh"]')
        assert pg.locator('#view-lan [data-pane="lan-neigh"]').is_visible() and pg.locator('#view-lan [data-pane="lan-scan"]').is_hidden()
        assert pg.locator('#view-lan [placeholder]').count() == 0
        assert not pg.is_checked('#neigh-probe')
        pg.click('#neigh-btn')
        pg.wait_for_selector('#res-neigh .strip.warn')
        assert [c for c in pg.evaluate('window.__calls') if c[0] == 'neigh_scan'][-1][1] == {'probe': False}
        sm = pg.inner_text('#res-neigh .strip .summary')
        assert '5 dispositivi' in sm and '9 IPv4' in sm and '1 router IPv6' in sm and 'primo aggiornamento' in sm, sm
        tabs = pg.eval_on_selector_all('#res-neigh .rtabs button', 'b => b.map(x => x.textContent)')
        assert tabs == ['Controlli5', 'Dispositivi5', 'Router e prefissi2'], tabs
        pills = pg.eval_on_selector_all('#res-neigh [data-rpane="chk"] tbody tr', 'r => r.map(x => x.children[0].textContent + "|" + x.children[2].textContent)')
        assert pills[0].endswith('MAC con molti indirizzi IPv4') and pills[0].startswith('!'), pills
        assert pills[-1].startswith('✓'), pills        # in severity order: ok last
        pg.wait_for_timeout(500)
        pg.screenshot(path=str(OUT / f'neigh-controlli-{theme}.png'))
        pg.click('#res-neigh .rtabs [data-rtab="dev"]')
        rows = pg.eval_on_selector_all('#res-neigh .nb-row', 'r => r.map(x => x.dataset.nb)')
        assert rows[0] == '00:50:56:aa:00:01' and rows[-1] == '-' and len(rows) == 6, rows
        first = pg.inner_text('#res-neigh .nb-row >> nth=0')
        assert 'Gateway' in first and 'Router IPv6' in first and '172.16.1.1' in first and '2001:db8:1::1' in first, first
        last = pg.inner_text('#res-neigh .nb-row >> nth=5')
        assert 'Indirizzi non risolti' in last and '+2' in last and '172.16.1.103' not in last, last
        pg.click('#res-neigh .nb-row >> nth=2 >> .lan-main')
        det = pg.inner_text('#res-neigh .nb-detail')
        assert '00:17:c8:11:22:33' in det and 'KYOCERA' in det and 'link-local' in det, det
        pg.fill('#res-neigh [data-nbq]', '0017C8')           # MAC without separators and in upper case
        assert pg.eval_on_selector_all('#res-neigh .nb-row', 'r => r.map(x => x.dataset.nb)') == ['00:17:c8:11:22:33']
        assert pg.evaluate("document.activeElement === document.querySelector('#res-neigh [data-nbq]')")
        pg.fill('#res-neigh [data-nbq]', '2001:db8:1::84')
        assert pg.eval_on_selector_all('#res-neigh .nb-row', 'r => r.map(x => x.dataset.nb)') == ['8c:1f:64:10:3a:bc']
        pg.fill('#res-neigh [data-nbq]', 'zzzz')
        assert 'Nessun dispositivo' in pg.inner_text('#res-neigh [data-nblist]')
        pg.fill('#res-neigh [data-nbq]', '')
        assert pg.locator('#res-neigh .nb-row').count() == 6 and pg.locator('#res-neigh .nb-detail').count() == 1
        pg.click('#res-neigh [data-nbcsv]')
        pg.wait_for_function('window.__copied !== undefined && window.__copied.startsWith("MAC;Produttore;")')
        pg.evaluate("document.querySelector('main').scrollTop = 0")
        pg.set_viewport_size({'width': 1269, 'height': 1300})
        pg.screenshot(path=str(OUT / f'neigh-dispositivi-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.click('#res-neigh .rtabs [data-rtab="rt"]')
        rt = pg.inner_text('#res-neigh [data-rpane="rt"]')
        assert 'fe80::250:56ff:feaa:1' in rt and 'come il gateway IPv4' in rt and '30 min' in rt and '2001:db8:1::/64' in rt and '1 g' in rt, rt
        pg.screenshot(path=str(OUT / f'neigh-router-{theme}.png'))
        pg.click('#res-neigh .strip-copy')
        pg.wait_for_function('window.__copied !== undefined && window.__copied.startsWith("Vicini di questo PC")')
        cp = pg.evaluate('window.__copied')
        assert 'Router IPv6' in cp and 'Prefissi IPv6' in cp and 'MAC;Produttore;' in cp and '[warn] MAC con molti' in cp, cp
        # second refresh, with the echo to ff02::1: the comparison reports the MAC change
        pg.check('#neigh-probe')
        pg.click('#neigh-btn')
        pg.wait_for_function("document.querySelectorAll('#res-neigh .strip').length === 2")
        assert [c for c in pg.evaluate('window.__calls') if c[0] == 'neigh_scan'][-1][1] == {'probe': True}
        top = pg.inner_text('#res-neigh .strip >> nth=0 >> .summary')
        assert 'confronto con le' in top, top
        t0 = pg.inner_text('#res-neigh .strip >> nth=0 >> [data-rpane="chk"]')
        assert 'Indirizzo passato a un altro MAC' in t0 and 'Echo a ff02::1' in t0 and '172.16.1.84: prima 8c:1f:64:10:3a:bc' in t0, t0
        assert 'Indirizzo passato' not in pg.inner_text('#res-neigh .strip >> nth=1 >> [data-rpane="chk"]')
        # from the row to the ping
        pg.click('#res-neigh .strip >> nth=0 >> .rtabs [data-rtab="dev"]')
        pg.click('#res-neigh .strip >> nth=0 >> .nb-row >> nth=0 >> .lan-main')
        pg.click('#res-neigh .strip >> nth=0 >> [data-goto="ping"]')
        assert pg.locator('#view-ping').is_visible() and pg.input_value('#ping-host') == '172.16.1.1'
        # password generator
        pg.click('.nav-item[data-view="pwgen"]')
        assert pg.locator('#view-pwgen').is_visible()
        pg.wait_for_function("document.getElementById('pw-preview').textContent.includes('129 bit')")
        assert '88 caratteri possibili' in pg.inner_text('#pw-preview')
        assert pg.input_value('#pw-symset') == '!@#$%^&*()-_=+[]{}|;:,.<>?'
        pg.fill('#pw-len', '24')
        assert pg.inner_text('#pw-len-val') == '24'
        pg.click('#pw-btn')
        pg.wait_for_selector('#res-pwgen .strip.ok')
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'pwgen_password'][-1][1]
        assert req['length'] == '24' and req['count'] == '3' and req['symbol_set'] and req['min_symbols'] == '1', req
        assert pg.locator('#res-pwgen .pw-row').count() == 3
        assert pg.locator('#res-pwgen .strip-copy').count() == 0
        first = pg.inner_text('#res-pwgen .pw-row >> nth=0 >> .pw-val')
        assert len(first) == 24, first          # characters < & > " shown as text
        pg.click('#res-pwgen .pw-row >> nth=0 >> [data-act="copy"]')
        pg.wait_for_function('window.__clip !== undefined')
        assert pg.evaluate('window.__clip') == first
        assert pg.inner_text('#res-pwgen .pw-row >> nth=0 >> [data-act="copy"]') == 'Copiata'
        pg.click('#res-pwgen .pw-row >> nth=1 >> [data-act="regen"]'); pg.wait_for_timeout(100)
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'pwgen_password'][-1][1]
        assert req['count'] == '1', req
        assert pg.inner_text('#pw-hist-n') == '4'
        pg.click('#pw-hist-btn')
        assert pg.locator('#pw-hist').is_visible() and pg.locator('#pw-hist tbody tr').count() == 4
        pg.set_viewport_size({'width': 1269, 'height': 1500})
        pg.evaluate("document.querySelector('main').scrollTop = 0")
        pg.screenshot(path=str(OUT / f'pwgen-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        pg.click('#pw-hist-clear')
        assert pg.inner_text('#pw-hist-n') == '0'
        # no type chosen: error in the preview
        for k in ('lower', 'upper', 'digits', 'symbols'): pg.uncheck('#pw-' + k)
        pg.wait_for_selector('#pw-preview .c-err')
        assert 'almeno un tipo' in pg.inner_text('#pw-preview')
        assert pg.is_disabled('#pw-min-lower') and pg.is_disabled('#pw-symset')
        for k in ('lower', 'upper', 'digits', 'symbols'): pg.check('#pw-' + k)
        pg.check('#pw-pron'); assert pg.locator('#pw-pron-note').is_visible()
        pg.wait_for_function("document.getElementById('pw-preview').textContent.includes('sillabe')")
        pg.uncheck('#pw-pron')
        # number converter
        pg.click('.nav-item[data-view="numconv"]')
        assert pg.locator('#view-numconv').is_visible()
        assert pg.evaluate("document.activeElement.id") == 'nc-dec'
        assert pg.get_attribute('#nc-width [data-w="32"]', 'aria-checked') == 'true'
        assert pg.locator('#nc-ip').is_visible() and pg.locator('#nc-bits-panel').is_hidden()
        pg.fill('#nc-ip', '192.0.2.10')
        pg.wait_for_function("document.getElementById('nc-hex').value === 'C0 00 02 0A'")
        assert pg.input_value('#nc-dec') == '3221225994' and pg.input_value('#nc-bin').startswith('1100 0000 0000 0000')
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'numconv'][-1][1]
        assert req == {'value': '192.0.2.10', 'base': 'ip', 'width': '32', 'signed': False}, req
        assert pg.locator('#nc-bits .nc-bit').count() == 32 and pg.locator('#nc-bits .nc-bit.on').count() == 5
        assert pg.evaluate("getComputedStyle(document.getElementById('nc-bits')).gridTemplateColumns.split(' ').length") == 4
        info = pg.inner_text('#nc-info')
        assert '0xC000020A' in info and '0A 02 00 C0' in info and '3.221.225.994' in info, info
        # click on bit 0: 192.0.2.11, in the IPv4 field too
        pg.click('#nc-bits [data-bit="0"]')
        pg.wait_for_function("document.getElementById('nc-ip').value === '192.0.2.11'")
        assert pg.locator('#nc-bits [data-bit="0"].on').count() == 1
        pg.click('[data-nc-copy="hex"]'); pg.wait_for_timeout(50)
        assert pg.evaluate('window.__copied') == 'C000020B'
        pg.set_viewport_size({'width': 1269, 'height': 1250})
        pg.evaluate("document.querySelector('main').scrollTop = 0")
        pg.screenshot(path=str(OUT / f'numconv-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # readable error and field flagged, the others stay
        pg.fill('#nc-hex', 'ZZ')
        pg.wait_for_selector('#nc-hex[aria-invalid="true"]')
        assert 'non valido' in pg.inner_text('#nc-msg') and pg.input_value('#nc-dec') == '3221225995'
        # 8 bit: no IPv4; free: no sign
        pg.click('#nc-width [data-w="8"]')
        assert pg.locator('#nc-ip').is_hidden()
        pg.fill('#nc-dec', '65')
        pg.wait_for_function("document.getElementById('nc-hex').value === '41'")
        assert pg.locator('#nc-bits .nc-bit').count() == 8 and '"A"' in pg.inner_text('#nc-info')
        pg.check('#nc-signed'); pg.fill('#nc-hex', 'FF')
        pg.wait_for_function("document.getElementById('nc-dec').value === '-1'")
        pg.click('#nc-width [data-w="free"]')
        assert pg.is_disabled('#nc-signed') and pg.locator('#nc-ip').is_visible()
        pg.wait_for_function("document.getElementById('nc-dec').value === '255'")
        # on leaving the field the value takes the normalised form
        pg.fill('#nc-hex', 'c0a8'); pg.wait_for_function("document.getElementById('nc-dec').value === '49320'")
        pg.focus('#nc-dec'); assert pg.input_value('#nc-hex') == 'C0 A8'
        # UUID generator
        pg.click('.nav-item[data-view="uuid"]')
        assert pg.get_attribute('#view-uuid [data-tab="v4"]', 'aria-selected') == 'true'
        assert pg.locator('#uuid-names').is_hidden()
        pg.fill('#uuid-count', '3'); assert pg.inner_text('#uuid-count-val') == '3'
        pg.click('#uuid-btn')
        pg.wait_for_selector('#res-uuid .strip.ok')
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'uuid_generate'][-1][1]
        assert req == {'version': '4', 'count': '3'}, req
        assert pg.locator('#res-uuid .uuid-val').count() == 3 and pg.locator('#res-uuid .strip-copy').count() == 0
        assert pg.inner_text('#res-uuid .uuid-val >> nth=0') == 'f47ac10b-58cc-4372-a567-0e02b2c3d400'
        # the format also applies to the UUIDs already generated
        pg.check('#uuid-upper'); pg.click('#uuid-wrap [data-wrap="braces"]')
        assert pg.inner_text('#res-uuid .uuid-val >> nth=0') == '{F47AC10B-58CC-4372-A567-0E02B2C3D400}'
        assert '{550E8400-E29B-' in pg.inner_text('#uuid-sample')
        pg.click('#res-uuid [data-uact="all"]'); pg.wait_for_timeout(50)
        cp = pg.evaluate('window.__copied').split('\n')
        assert len(cp) == 3 and all(x.startswith('{F47AC10B') for x in cp), cp
        pg.click('#res-uuid [data-uact="inspect"] >> nth=1')
        pg.wait_for_function("document.querySelectorAll('#res-uuid .strip.ok').length === 2")
        assert pg.input_value('#uuid-in') == 'f47ac10b-58cc-4372-a567-0e02b2c3d401'
        ins = pg.inner_text('#res-uuid .strip >> nth=0')
        assert 'objectGUID' in ins and 'ordinato nel tempo' in ins and '2025' in ins, ins
        pg.set_viewport_size({'width': 1269, 'height': 1600})
        pg.evaluate("document.querySelector('main').scrollTop = 0"); pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'uuid-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # v5: namespace and names
        pg.click('#view-uuid [data-tab="v5"]')
        assert pg.locator('#uuid-count').is_hidden() and pg.locator('#uuid-names').is_visible()
        pg.select_option('#uuid-ns', 'custom'); assert pg.locator('#uuid-ns-custom').is_visible()
        pg.select_option('#uuid-ns', 'dns'); assert pg.locator('#uuid-ns-custom').is_hidden()
        pg.fill('#uuid-names', 'python.org\nexample.it')
        pg.click('#uuid-btn')
        pg.wait_for_function("document.querySelectorAll('#res-uuid .strip.ok').length === 3")
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'uuid_generate'][-1][1]
        assert req == {'version': '5', 'namespace': 'dns', 'names': 'python.org\nexample.it'}, req
        assert pg.locator('#res-uuid .strip >> nth=0 >> .uuid-name').count() == 2
        pg.fill('#uuid-names', ''); pg.click('#uuid-btn')
        pg.wait_for_selector('#res-uuid .strip.err')
        assert 'almeno un nome' in pg.inner_text('#res-uuid .strip.err')
        # SMTP server: item in Protocolli, options, transcript and checks
        pg.click('.nav-item[data-view="smtp"]')
        assert pg.locator('#view-smtp').is_visible()
        assert pg.locator('#smtp-auth-row').is_hidden() and pg.locator('#smtp-send-box').is_hidden()
        assert pg.input_value('#smtp-port') == '25' and pg.input_value('#smtp-sec') == 'auto'
        pg.click('#smtp-presets .chip >> nth=1'); assert pg.input_value('#smtp-port') == '587'
        pg.click('#smtp-presets .chip >> nth=0'); assert pg.input_value('#smtp-port') == '25'
        pg.check('#smtp-auth'); assert pg.locator('#smtp-auth-row').is_visible()
        pg.check('#smtp-send'); assert pg.locator('#smtp-send-box').is_visible()
        assert pg.input_value('#smtp-subject') == 'Test SMTP'
        pg.uncheck('#smtp-send')
        pg.fill('#smtp-host', 'mail01.corp.example'); pg.fill('#smtp-user', 'utente'); pg.fill('#smtp-pass', 'Segreta!1')
        pg.check('#smtp-relay')
        pg.click('#smtp-btn')
        pg.wait_for_selector('#res-smtp .strip.warn')
        req = [c for c in pg.evaluate('window.__calls') if c[0] == 'smtp_test'][-1][1]
        assert req['host'] == 'mail01.corp.example' and req['port'] == '25' and req['relay'] and req['auth'] and not req['send'], req
        assert req['password'] == 'Segreta!1' and req['from'] == '' and req['security'] == 'auto', req
        txt = pg.inner_text('#res-smtp .strip >> nth=0')
        assert 'Segreta' not in txt and '********' in txt and 'Trascrizione della sessione' in txt, txt
        assert pg.locator('#res-smtp .smtp-checks tbody tr').count() == 13
        assert pg.locator('#res-smtp .smtp-checks .pill.warn').count() == 1
        assert 'mail.example.it' in txt and '235 2.7.0' in txt
        pg.set_viewport_size({'width': 1269, 'height': 1900})
        pg.evaluate("document.querySelector('main').scrollTop = 0"); pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'smtp-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # the password does not end up in localStorage, the other fields do
        ls = pg.evaluate("JSON.stringify(Object.assign({}, localStorage))")
        assert 'Segreta' not in ls and 'mail01.corp.example' in ls, ls
        # connection error
        pg.fill('#smtp-host', 'chiuso'); pg.click('#smtp-btn')
        pg.wait_for_selector('#res-smtp .strip.err')
        assert 'chiusa' in pg.inner_text('#res-smtp .strip.err')
        # Clear (Pulisci)
        pg.click('#smtp-clear')
        assert pg.input_value('#smtp-host') == '' and pg.input_value('#smtp-pass') == '' and not pg.is_checked('#smtp-auth')
        assert pg.locator('#smtp-auth-row').is_hidden()
        # Wi-Fi: item in Diagnostica after Rete locale, full menu
        views = pg.evaluate("[...document.querySelectorAll('.nav-group')][0].innerText.split('\\n').map(s => s.trim()).filter(Boolean)")
        assert views[:7] == ['Diagnostica', 'Ping', 'Traceroute', 'Scansione subnet', 'Rete locale', 'Wi-Fi', 'DNS'], views
        pg.click('.nav-item[data-view="wifi"]')
        pg.wait_for_selector('#wf-nets tbody tr')
        pg.wait_for_function("window.__calls.filter(c => c[0] === 'wifi_scan').length >= 2")
        sc = [c[1] for c in pg.evaluate('window.__calls') if c[0] == 'wifi_scan']
        assert sc[0] == {'adapter': '', 'scan': False} and sc[1]['scan'] is True, sc
        pg.wait_for_function("document.getElementById('wifi-btn').textContent === 'Scansiona'")
        conn = pg.inner_text('#wf-conn')
        for t in ('CORP', '74:ac:b9:3e:41:c2', '36 · 5 GHz · 80 MHz', 'Wi-Fi 6 · 802.11ax', '1201 / 960,7 Mbit/s', 'WPA2-Enterprise', '172.16.7.42', 'k, v, r', 'Ottimo', 'Access point (Ubiquiti)'):
            assert t in conn, (t, conn)
        assert pg.inner_text('#wf-count') == '12'
        rows = pg.locator('#wf-nets tbody tr')
        assert rows.count() == 12 and pg.locator('#wf-nets tr.me').count() == 1
        nets = pg.inner_text('#wf-nets')
        for t in ('12 access point, 7 reti, 3 nascoste', 'CORP-MGMT', 'nascosta, da profilo', 'stesso AP di CORP (probabile)', '(rete nascosta, 9 caratteri)',
                  '6 GHz · 320 MHz', 'Wi-Fi 7', 'carico 20%', 'Stampante <b>DIRECT</b>'):
            assert t in nets, (t, nets)
        assert pg.locator('#wf-nets .tag:text-is("MLO")').count() == 2
        assert pg.locator('#wf-nets .pill.err').count() == 1   # open network
        # filters, grouping, CSV
        pg.click('#wf-nets [data-wf="6"]'); assert rows.count() == 1
        pg.click('#wf-nets [data-wf="hidden"]'); assert rows.count() == 3
        pg.click('#wf-nets [data-wf="2.4"]'); assert rows.count() == 5
        pg.click('#wf-nets #wf-csv'); pg.wait_for_function('window.__copied && window.__copied.startsWith("segnale_dbm;")')
        csv = pg.evaluate('window.__copied').split('\n')
        assert len(csv) == 6 and csv[1].startswith('-51;CORP;no;74:ac:b9:3e:41:c1;Ubiquiti Inc;2.4;6;20;802.11ax'), csv[:2]
        pg.click('#wf-nets [data-wf="all"]'); assert rows.count() == 12
        pg.check('#wifi-group'); assert pg.locator('#wf-nets tr.wf-grp').count() == 8
        grp = pg.locator('#wf-nets tr.wf-grp').all_inner_texts()
        assert grp[0] == 'CORP · 3 access point' and 'Reti nascoste · 2 access point' in grp, grp
        pg.uncheck('#wifi-group'); assert pg.locator('#wf-nets tr.wf-grp').count() == 0
        pg.set_viewport_size({'width': 1269, 'height': 1720})
        pg.evaluate("document.querySelector('main').scrollTop = 0"); pg.wait_for_timeout(450)
        pg.screenshot(path=str(OUT / f'wifi-reti-{theme}.png'))
        # channels: three bands, advice
        pg.click('#view-wifi [data-tab="chan"]')
        assert pg.locator('#wf-chan svg').count() == 3
        ch = pg.inner_text('#wf-chan')
        assert 'canale più libero tra 1, 6 e 11: 1' in ch and '52–64 (DFS)' in ch and 'In Europa' in ch, ch
        assert 'CORP ●' in ch and 'CORP-MGMT' in ch, ch
        pg.screenshot(path=str(OUT / f'wifi-canali-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # monitor: Avvia (Start) becomes Ferma (Stop), samples, roaming, stop
        pg.click('#view-wifi [data-tab="mon"]')
        pg.click('#wfm-btn')
        pg.wait_for_function("document.getElementById('wfm-btn').textContent === 'Ferma'")
        pg.wait_for_function("wf.mon.samples.length >= 14")
        assert 'In corso' in pg.inner_text('#wfm-live')
        mon = pg.inner_text('#wfm-body')
        assert 'Roaming da 74:ac:b9:3e:41:c2' in mon and 'interruzione 38 ms' in mon and 'Segnale sotto -75 dBm' in mon, mon
        assert pg.locator('#wfm-body svg path').count() == 1
        pg.evaluate("document.querySelector('[data-pane=\"wifi-mon\"]').scrollIntoView()"); pg.wait_for_timeout(200)
        pg.screenshot(path=str(OUT / f'wifi-monitor-running-{theme}.png'))
        pg.click('#wfm-btn')
        pg.wait_for_function("document.getElementById('wfm-btn').textContent === 'Avvia'")
        assert pg.inner_text('#wfm-live').startswith('Fermato'), pg.inner_text('#wfm-live')
        mreq = [c[1] for c in pg.evaluate('window.__calls') if c[0] == 'wifi_monitor'][-1]
        assert mreq == {'adapter': '{11111111-2222-3333-4444-555555555555}', 'interval_ms': '1000'}, mreq
        assert pg.inner_text('#wfm-body .kv-item:last-child .kv-v') == '1'
        pg.click('#wfm-csv'); pg.wait_for_function('window.__copied && window.__copied.startsWith("ora;rssi_dbm")')
        assert ';;;;;;' in pg.evaluate('window.__copied')   # sample without connection
        pg.evaluate('window.__wifiMonErr = true'); pg.click('#wfm-btn')
        pg.wait_for_selector('#wfm-body .msg-err'); assert 'non è connessa' in pg.inner_text('#wfm-body')
        pg.evaluate('window.__wifiMonErr = false')
        # location denied: warning, connection visible, no networks
        pg.evaluate("window.__wifi = 'location'"); pg.click('#wifi-btn')
        pg.wait_for_selector('#wf-msg .wf-note'); assert 'posizione' in pg.inner_text('#wf-msg')
        pg.click('#view-wifi [data-tab="nets"]')
        assert 'senza accesso alla posizione' in pg.inner_text('#wf-nets') and pg.locator('#wf-conn').is_visible()
        assert '36' in pg.inner_text('#wf-conn') and '—' in pg.inner_text('#wf-conn')
        # Wi-Fi off: no adapters or connection, the adapter choice stays
        pg.evaluate("window.__wifi = 'radio'"); pg.click('#wifi-btn')
        pg.wait_for_selector('#wf-msg .wf-empty'); assert 'Wi-Fi spento' in pg.inner_text('#wf-msg')
        assert pg.locator('#wf-tabs').is_hidden() and pg.locator('#wf-form').is_visible()
        assert 'spenta' in pg.inner_text('#wifi-if')
        # PC without a Wi-Fi adapter
        pg.evaluate("window.__wifi = 'none'"); pg.click('#wifi-btn')
        pg.wait_for_selector('#wf-msg .wf-empty'); assert 'Nessuna scheda Wi-Fi' in pg.inner_text('#wf-msg')
        assert pg.locator('#wf-form').is_hidden() and pg.locator('#wf-conn').is_hidden() and pg.locator('#wf-tabs').is_hidden()
        pg.screenshot(path=str(OUT / f'wifi-senza-scheda-{theme}.png'))
        n0 = len([c for c in pg.evaluate('window.__calls') if c[0] == 'wifi_scan'])
        pg.click('#wf-retry'); pg.wait_for_function(f"window.__calls.filter(c => c[0] === 'wifi_scan').length > {n0}")
        pg.evaluate("window.__wifi = 'ok'"); pg.click('#wf-retry')
        pg.wait_for_selector('#wf-nets tbody tr'); assert pg.locator('#wf-form').is_visible()
        # full menu even with a short window (laptop 1366×768 zoomed): 728 and 790 px
        for h in (790, 728):
            pg.set_viewport_size({'width': 1269, 'height': h}); pg.wait_for_timeout(100)
            sb = pg.evaluate("(() => { const s = document.querySelector('.sidebar'); return [s.scrollHeight, s.clientHeight]; })()")
            assert sb[0] <= sb[1], (h, sb)
            assert not pg.locator('.side-credits').is_visible()
        pg.screenshot(path=str(OUT / f'wifi-728-{theme}.png'))
        pg.set_viewport_size({'width': 1269, 'height': 860})
        # the password generator history does not survive a restart
        pg.click('.nav-item[data-view="pwgen"]')
        pg.reload(); pg.wait_for_timeout(400)
        assert pg.inner_text('#pw-hist-n') == '0'
        assert pg.locator('#view-pwgen [data-tab]').count() == 0 and 'iceware' not in pg.inner_text('#view-pwgen')
        # nor do those of the converter and the UUIDs
        assert pg.get_attribute('#nc-width [data-w="free"]', 'aria-checked') == 'true' and pg.is_disabled('#nc-signed')
        assert pg.get_attribute('#view-uuid [data-tab="v5"]', 'aria-selected') == 'true'
        assert pg.is_checked('#uuid-upper') and pg.get_attribute('#uuid-wrap [data-wrap="braces"]', 'aria-checked') == 'true'
        # theme and Home from the top bar
        pg.click('#theme-btn')
        other = 'light' if theme == 'dark' else 'dark'
        assert pg.get_attribute('html', 'data-theme') == other
        pg.click('#home-btn')
        assert pg.locator('#view-home').is_visible()
        assert pg.locator('.nav-item[aria-current]').count() == 0
        # language: flag next to the theme button, Italian by default; the click switches to English
        # (the page reloads), tells the backend with set_lang and translates the static texts
        xs = pg.evaluate("['lang-btn','theme-btn','home-btn'].map(i => document.getElementById(i).getBoundingClientRect().x)")
        assert xs == sorted(xs), xs
        assert pg.locator('#lang-btn svg.flag').count() == 1 and pg.evaluate('window.__lang') == 'it'
        assert pg.get_attribute('html', 'lang') == 'it' and 'Tema' in pg.inner_text('#theme-btn')
        it_flag = pg.inner_html('#lang-ico')
        pg.click('#lang-btn'); pg.wait_for_load_state(); pg.wait_for_function("window.__lang === 'en'")
        assert pg.evaluate("localStorage.getItem('ntb-lang')") == 'en' and pg.get_attribute('html', 'lang') == 'en'
        assert pg.inner_html('#lang-ico') != it_flag
        assert 'theme' in pg.inner_text('#theme-btn') and 'Tema' not in pg.inner_text('.topbar')
        assert 'Diagnostics' in pg.inner_text('.sidebar') and 'Diagnostica' not in pg.inner_text('.sidebar')
        assert pg.inner_text('.nav-item[data-view="sweep"]').strip() == 'Subnet scan'
        pg.screenshot(path=str(OUT / f'lang-en-{other}.png'))
        pg.click('#lang-btn'); pg.wait_for_load_state(); pg.wait_for_function("window.__lang === 'it'")
        assert pg.evaluate("localStorage.getItem('ntb-lang')") == 'it' and 'Diagnostics' not in pg.inner_text('.sidebar')
        # red dot without Internet
        pg.evaluate('window.__online = false'); pg.evaluate('online()'); pg.wait_for_timeout(100)
        assert 'down' in pg.get_attribute('#svc', 'class')
        assert 'down' in pg.get_attribute('#np-net', 'class') and pg.inner_text('#np-l2-ms') == '—'
        pg.screenshot(path=str(OUT / f'offline-{other}.png'), clip={'x': 0, 'y': 0, 'width': 1269, 'height': 60})
        # content scroll bar (long page)
        pg.click('.nav-item[data-view="wol"]')
        pg.set_viewport_size({'width': 1269, 'height': 560})
        pg.screenshot(path=str(OUT / f'scroll-{other}.png'))
        pg.close()
    # the theme is dark by default even if the system prefers light, and the language is Italian
    pg = b.new_page(viewport={'width': 1269, 'height': 860}, color_scheme='light')
    pg.on('pageerror', lambda e: errors.append(str(e)))
    pg.add_init_script(MOCK)
    pg.goto(URL); pg.wait_for_timeout(300)
    assert pg.get_attribute('html', 'data-theme') == 'dark' and pg.get_attribute('html', 'lang') == 'it'
    assert pg.evaluate('window.__lang') == 'it'
    pg.close()
    # clock with simulated time: 24 h, ticking seconds, date changing at midnight
    pg = b.new_page(viewport={'width': 1269, 'height': 860})
    pg.on('pageerror', lambda e: errors.append(str(e)))
    pg.add_init_script(MOCK)
    pg.clock.install(time='2026-11-03T21:05:07')
    pg.clock.pause_at('2026-11-03T21:05:07')
    pg.goto(URL)
    pg.clock.run_for(10)
    assert pg.inner_text('#clock-time') == '21:05:07', pg.inner_text('#clock-time')
    assert pg.inner_text('#clock-date') == 'martedì 3 novembre 2026', pg.inner_text('#clock-date')
    pg.clock.run_for(1000)
    assert pg.inner_text('#clock-time') == '21:05:08', pg.inner_text('#clock-time')
    pg.clock.set_fixed_time('2026-11-03T08:04:03'); pg.evaluate('clock()')
    assert pg.inner_text('#clock-time') == '08:04:03'
    pg.close()
    pg = b.new_page(viewport={'width': 1269, 'height': 860})
    pg.on('pageerror', lambda e: errors.append(str(e)))
    pg.add_init_script(MOCK)
    pg.clock.install(time='2026-11-03T23:59:59')
    pg.clock.pause_at('2026-11-03T23:59:59')
    pg.goto(URL)
    pg.clock.run_for(10)
    assert pg.inner_text('#clock-time') == '23:59:59'
    pg.clock.run_for(1000)
    assert pg.inner_text('#clock-time') == '00:00:00', pg.inner_text('#clock-time')
    assert pg.inner_text('#clock-date') == 'mercoledì 4 novembre 2026', pg.inner_text('#clock-date')
    # fixed-width digits: the time does not "dance" when the seconds change
    w = pg.evaluate("""(() => { const e = document.getElementById('clock-time'), o = e.textContent, r = [];
      for (const s of ['11:11:11', '00:00:00', '08:48:58']) { e.textContent = s; r.push(e.getBoundingClientRect().width); }
      e.textContent = o; return r; })()""")
    assert max(w) - min(w) < 1, w
    pg.close()
    b.close()

print('JS errors:', errors or 'none')
assert not errors
print('OK')
