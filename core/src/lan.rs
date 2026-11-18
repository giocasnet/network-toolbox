//! Local network: inventory of the hosts of a network up to /21.
//!
//! In two phases. First who is there, on every address: ping (two attempts) and,
//! on directly connected networks, the system ARP table (it also contains
//! hosts that block ping); the host is emitted at once with MAC and vendor (IEEE registry).
//! Then, only for the hosts found: DNS name (PTR) and NetBIOS, SNMP v2c with community
//! `public` (name, description, model) and, if requested, the listening TCP services
//! with the banner. The device type is derived from the collected data and the host is
//! emitted a second time, complete.

use crate::icmp::{self, ArpTable};
use crate::ping::Stop;
use crate::snmp::client::{Security, Session, Value, GET};
use crate::{net, netbios, ports, sweep, t, tf};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Largest network allowed: /21 (2046 hosts).
pub const MIN_PREFIX: u8 = 21;
/// Name of the vendors file, installed next to the executable.
pub const OUI_FILE: &str = "oui.txt";
/// Hosts whose details (names, SNMP, services) are collected at the same time.
const DETAILS: usize = 64;

/// TCP services checked with the "services" option.
pub const SERVICES: [(u16, &str); 21] = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (135, "RPC"),
    (139, "NetBIOS"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (515, "LPD"),
    (631, "IPP"),
    (1433, "SQL Server"),
    (3306, "MySQL"),
    (3389, "Desktop remoto"),
    (5900, "VNC"),
    (5985, "WinRM"),
    (8080, "HTTP alternativo"),
    (8443, "HTTPS alternativo"),
    (9100, "Stampa RAW"),
];

/// Display name of a service (the table keeps the Italian names).
fn service_name(n: &'static str) -> &'static str {
    match n {
        "Desktop remoto" => t!("Desktop remoto", "Remote Desktop"),
        "HTTP alternativo" => t!("HTTP alternativo", "Alternative HTTP"),
        "HTTPS alternativo" => t!("HTTPS alternativo", "Alternative HTTPS"),
        "Stampa RAW" => t!("Stampa RAW", "RAW printing"),
        other => other,
    }
}

// ───────────────────────── vendors (OUI) ─────────────────────────

/// MAC prefixes → vendor: MA-L (24 bit), MA-M (28 bit), MA-S (36 bit).
pub struct OuiDb {
    l: HashMap<u64, String>,
    m: HashMap<u64, String>,
    s: HashMap<u64, String>,
}

impl std::fmt::Debug for OuiDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OuiDb({} prefixes)", self.len())
    }
}

impl OuiDb {
    /// Format: "prefix<TAB>vendor" (6, 7 or 9 hex digits); # = comment.
    pub fn parse(text: &str) -> crate::Result<Self> {
        let mut db = OuiDb {
            l: HashMap::new(),
            m: HashMap::new(),
            s: HashMap::new(),
        };
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let bad = || {
                tf!(
                    "Elenco produttori non valido (riga {}): «{t}»",
                    "Invalid vendor list (line {}): «{t}»",
                    i + 1
                )
            };
            let (p, name) = t.split_once('\t').ok_or_else(bad)?;
            let v = u64::from_str_radix(p, 16).map_err(|_| bad())?;
            let map = match p.len() {
                6 => &mut db.l,
                7 => &mut db.m,
                9 => &mut db.s,
                _ => return Err(bad()),
            };
            map.insert(v, name.trim().to_string());
        }
        if db.is_empty() {
            return Err(t!("Elenco produttori vuoto", "Vendor list is empty").into());
        }
        Ok(db)
    }

    pub fn load(path: &Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                tf!(
                    "Elenco produttori non trovato ({})",
                    "Vendor list not found ({})",
                    path.display()
                )
            } else {
                tf!(
                    "Impossibile leggere {}: {e}",
                    "Cannot read {}: {e}",
                    path.display()
                )
            }
        })?;
        Self::parse(&text)
    }

    pub fn len(&self) -> usize {
        self.l.len() + self.m.len() + self.s.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Vendor of a MAC "aa:bb:cc:dd:ee:ff", from the longest prefix.
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let v = mac_value(mac)?;
        [
            self.s.get(&(v >> 12)),
            self.m.get(&(v >> 20)),
            self.l.get(&(v >> 24)),
        ]
        .into_iter()
        .flatten()
        .map(String::as_str)
        // the IEEE's own MA-L blocks contain the MA-M and MA-S sub-blocks
        .find(|n| *n != "IEEE Registration Authority")
    }
}

pub(crate) fn mac_value(mac: &str) -> Option<u64> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

/// Prefixes of the most common virtual adapters.
const VM_PREFIXES: [u64; 8] = [
    0x005056, 0x000C29, 0x000569, 0x001C14, // VMware
    0x00155D, // Hyper-V
    0x525400, // QEMU / KVM
    0x080027, // VirtualBox
    0x00163E, // Xen
];

pub(crate) fn is_vm_mac(mac: &str) -> bool {
    mac_value(mac).is_some_and(|v| VM_PREFIXES.contains(&(v >> 24)))
}

/// Locally administered MAC (bit 0x02 of the first byte): usually random
/// (phones and PCs with a "private address"), hence without a vendor.
pub(crate) fn is_random_mac(mac: &str) -> bool {
    mac_value(mac).is_some_and(|v| (v >> 40) & 0x02 != 0) && !is_vm_mac(mac)
}

// ───────────────────────── requests and responses ─────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct LanReq {
    /// Empty = this PC's network.
    #[serde(default)]
    pub cidr: String,
    /// Checks the TCP services and uses TCP to look for hosts that do not answer ping.
    #[serde(default)]
    pub services: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanDefault {
    /// Network proposed for the scan.
    pub cidr: String,
    /// This PC's IPv4.
    pub ip: String,
    /// Adapter network (can be larger than the proposed one).
    pub iface: String,
    /// `true` if the adapter network exceeds /21 and the PC's /24 was proposed.
    pub reduced: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SnmpInfo {
    pub sys_name: String,
    pub sys_descr: String,
    pub object_id: String,
    /// hrDeviceDescr.1: on printers it is the model.
    pub device: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenService {
    pub port: u16,
    pub name: String,
    pub banner: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanHost {
    pub ip: String,
    /// ICMP, ARP or "TCP <port>".
    pub via: String,
    pub rtt_ms: Option<f64>,
    pub mac: String,
    pub vendor: String,
    pub random_mac: bool,
    pub vm: bool,
    pub ptr: String,
    pub netbios: String,
    /// Name to show: PTR, NetBIOS or sysName.
    pub name: String,
    pub snmp: Option<SnmpInfo>,
    pub services: Vec<OpenService>,
    /// printer, network, phone, camera, pc, server, other
    pub kind: &'static str,
    /// Found, but names, SNMP and services have not been collected yet: the host
    /// will be emitted again, complete.
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanStart {
    pub cidr: String,
    pub total: usize,
    pub local: bool,
    pub services: bool,
    /// Vendor list available.
    pub oui: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanProgress {
    pub done: usize,
    pub total: usize,
}

/// Scan events: `{"start":{..}}`, `{"progress":{..}}`, `{"host":{..}}`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LanEvent {
    Start(LanStart),
    Progress(LanProgress),
    Host(Box<LanHost>),
}

#[derive(Debug, Clone, Serialize)]
pub struct LanSummary {
    pub cidr: String,
    pub total: usize,
    pub found: usize,
    pub elapsed_s: f64,
    /// Interrupted with "Stop".
    pub stopped: bool,
}

// ───────────────────────── this PC's network ─────────────────────────

pub fn default_network() -> Option<LanDefault> {
    let ip = crate::online::local_ip()?;
    let mask = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) if a.ip == ip => Some(a.netmask),
            _ => None,
        })?;
    let iface = Ipv4Net::with_netmask(ip, mask).ok()?.trunc();
    let (net, reduced) = if (MIN_PREFIX..=30).contains(&iface.prefix_len()) {
        (iface, false)
    } else {
        (Ipv4Net::new(ip, 24).ok()?.trunc(), true)
    };
    Some(LanDefault {
        cidr: net.to_string(),
        ip: ip.to_string(),
        iface: iface.to_string(),
        reduced,
    })
}

// ───────────────────────── SNMP ─────────────────────────

const SYS_DESCR: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 2, 0];
const SYS_NAME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 5, 0];
const HR_DEVICE_DESCR_1: [u32; 12] = [1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 3, 1];

fn text(v: &Value) -> String {
    match v {
        Value::Str(b) => String::from_utf8_lossy(b)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        Value::Oid(o) => crate::snmp::mib::dotted(o),
        _ => String::new(),
    }
}

/// sysName, sysDescr, sysObjectID and hrDeviceDescr.1 with SNMP v2c and community `public`.
async fn snmp_info(addr: SocketAddr) -> Option<SnmpInfo> {
    let mut s = Session::new(
        addr,
        Security::Community {
            v2c: true,
            community: "public".into(),
        },
    )
    .await
    .ok()?;
    s.timeout = Duration::from_millis(800);
    s.retries = 1;
    let mut oids = vec![
        SYS_DESCR.to_vec(),
        SYS_OBJECT_ID.to_vec(),
        SYS_NAME.to_vec(),
        HR_DEVICE_DESCR_1.to_vec(),
    ];
    let mut pdu = s.request(GET, 0, 0, &oids).await.ok()?;
    if pdu.error_status != 0 {
        // agent that rejects the whole request for a missing OID: retry without it
        oids.pop();
        pdu = s.request(GET, 0, 0, &oids).await.ok()?;
        if pdu.error_status != 0 {
            return None;
        }
    }
    let mut info = SnmpInfo::default();
    for vb in &pdu.varbinds {
        let t = text(&vb.value);
        if vb.oid == SYS_DESCR {
            info.sys_descr = t;
        } else if vb.oid == SYS_OBJECT_ID {
            info.object_id = t;
        } else if vb.oid == SYS_NAME {
            info.sys_name = t;
        } else if vb.oid == HR_DEVICE_DESCR_1 {
            info.device = t;
        }
    }
    Some(info)
}

// ───────────────────────── services ─────────────────────────

/// Open ports among those given, with the service banner.
async fn scan_services(ip: Ipv4Addr, list: &[(u16, &'static str)]) -> Vec<OpenService> {
    let mut set = JoinSet::new();
    for &(port, name) in list {
        set.spawn(async move { (name, ports::probe(IpAddr::V4(ip), port).await) });
    }
    let mut out = Vec::new();
    while let Some(Ok((name, r))) = set.join_next().await {
        if r.status == "OPEN" {
            out.push(OpenService {
                port: r.port,
                name: service_name(name).to_string(),
                banner: r.banner,
            });
        }
    }
    out.sort_by_key(|s| s.port);
    out
}

// ───────────────────────── device type ─────────────────────────

const PRINTER_WORDS: &[&str] = &[
    "printer",
    "printing",
    "ecosys",
    "taskalfa",
    "laserjet",
    "officejet",
    "deskjet",
    "designjet",
    "imagerunner",
    "imageclass",
    "bizhub",
    "workcentre",
    "versalink",
    "altalink",
    "aficio",
    "kyocera",
    "brother",
    "lexmark",
    "xerox",
    "ricoh",
    "konica",
    "epson",
    "zebra",
    "oki data",
];
const NETWORK_WORDS: &[&str] = &[
    "cisco",
    "fortigate",
    "fortinet",
    "fortios",
    "fortiswitch",
    "fortiap",
    "ruckus",
    "brocade",
    "procurve",
    "aruba",
    "mikrotik",
    "routeros",
    "ubiquiti",
    "unifi",
    "juniper",
    "netgear",
    "d-link",
    "tp-link",
    "zyxel",
    "switch",
    "router",
    "firewall",
    "access point",
];
const PHONE_WORDS: &[&str] = &[
    "yealink",
    "snom",
    "grandstream",
    "fanvil",
    "polycom",
    "gigaset",
    "avaya",
    "mitel",
    "htek",
];
const CAMERA_WORDS: &[&str] = &[
    "hikvision",
    "dahua",
    "axis communications",
    "hanwha",
    "vivotek",
    "uniview",
    "reolink",
    "milesight",
];
const SERVER_WORDS: &[&str] = &["linux", "synology", "qnap", "netapp", "esxi", "vmkernel"];

/// Device type from vendor, SNMP, NetBIOS and open ports.
pub fn classify(
    vendor: &str,
    snmp: Option<&SnmpInfo>,
    netbios: bool,
    open: &[u16],
) -> &'static str {
    let mut hay = vendor.to_lowercase();
    if let Some(s) = snmp {
        hay.push(' ');
        hay.push_str(&format!("{} {} {}", s.sys_descr, s.device, s.sys_name).to_lowercase());
    }
    let any = |words: &[&str]| words.iter().any(|w| hay.contains(w));
    let port = |p: &[u16]| p.iter().any(|x| open.contains(x));
    if any(PRINTER_WORDS) || port(&[9100, 515, 631]) {
        "printer"
    } else if any(NETWORK_WORDS) {
        "network"
    } else if any(PHONE_WORDS) {
        "phone"
    } else if any(CAMERA_WORDS) {
        "camera"
    } else if hay.contains("windows") || netbios || port(&[445, 135, 3389, 5985]) {
        "pc"
    } else if any(SERVER_WORDS) || port(&[22]) {
        "server"
    } else {
        "other"
    }
}

// ───────────────────────── scan ─────────────────────────

/// Host just found: address, MAC and vendor. The rest (names, SNMP,
/// services) is added by `enrich`; until then `pending` is true.
fn found_host(ip: Ipv4Addr, p: sweep::Presence, oui: Option<&OuiDb>) -> LanHost {
    let mac = p.mac;
    let random_mac = is_random_mac(&mac);
    let vendor = if random_mac {
        String::new()
    } else {
        oui.and_then(|db| db.lookup(&mac)).unwrap_or("").to_string()
    };
    LanHost {
        ip: ip.to_string(),
        via: p.via,
        rtt_ms: p.rtt_ms,
        vm: is_vm_mac(&mac),
        random_mac,
        kind: classify(&vendor, None, false, &[]),
        mac,
        vendor,
        ptr: String::new(),
        netbios: String::new(),
        name: String::new(),
        snmp: None,
        services: Vec::new(),
        pending: true,
    }
}

/// Completes a found host: DNS and NetBIOS name, SNMP, services (if requested) and
/// device type derived from everything collected.
async fn enrich(mut h: LanHost, ip: Ipv4Addr, services: bool) -> LanHost {
    let (ptr, nb, snmp, open) = tokio::join!(
        net::rdns(IpAddr::V4(ip), Duration::from_millis(1500)),
        netbios::name(ip, Duration::from_secs(1)),
        snmp_info(SocketAddr::new(IpAddr::V4(ip), 161)),
        async {
            if services {
                scan_services(ip, &SERVICES).await
            } else {
                Vec::new()
            }
        }
    );
    let nb = nb.unwrap_or_default();
    let ports: Vec<u16> = open.iter().map(|s| s.port).collect();
    h.kind = classify(&h.vendor, snmp.as_ref(), !nb.is_empty(), &ports);
    let sys_name = snmp
        .as_ref()
        .map(|s| s.sys_name.clone())
        .unwrap_or_default();
    h.name = [&ptr, &nb, &sys_name]
        .into_iter()
        .find(|n| !n.is_empty())
        .cloned()
        .unwrap_or_default();
    h.ptr = ptr;
    h.netbios = nb;
    h.snmp = snmp;
    h.services = open;
    h.pending = false;
    h
}

/// Network to scan: the one given (up to /21) or this PC's network.
pub fn target_network(cidr: &str) -> crate::Result<Ipv4Net> {
    if cidr.trim().is_empty() {
        let d = default_network().ok_or(t!(
            "Impossibile rilevare la rete di questo PC: indica la rete da scansionare",
            "Cannot detect this PC's network: specify the network to scan"
        ))?;
        return sweep::parse_net_limit(&d.cidr, MIN_PREFIX);
    }
    sweep::parse_net_limit(cidr, MIN_PREFIX)
}

/// Two-phase scan. First presence, on every address: the host is emitted
/// with `emit` as soon as it answers, with address, MAC and vendor (`pending`). Then the
/// details, only for the hosts found: the same host is emitted a second time,
/// complete (whoever receives the events updates the entry with the same address).
/// With `stop` ("Stop") it ends at once: the hosts found stay, those still
/// waiting for details keep only the data of the first emission.
pub async fn run<F>(
    req: LanReq,
    oui: Option<Arc<OuiDb>>,
    stop: &Stop,
    emit: F,
) -> crate::Result<LanSummary>
where
    F: Fn(LanEvent) + Send + Sync + 'static,
{
    let t0 = Instant::now();
    let net = target_network(&req.cidr)?;
    let all = sweep::targets(&net);
    let total = all.len();
    let local = sweep::is_local(&net);
    let emit = Arc::new(emit);
    emit(LanEvent::Start(LanStart {
        cidr: net.to_string(),
        total,
        local,
        services: req.services,
        oui: oui.is_some(),
    }));

    let sem = Arc::new(Semaphore::new(icmp::scan_parallelism()));
    let details = Arc::new(Semaphore::new(DETAILS));
    let arp = Arc::new(ArpTable::new());
    let nets = sweep::local_nets();
    let done = Arc::new(AtomicUsize::new(0));
    let mut set = JoinSet::new();
    for (i, ip) in all.into_iter().enumerate() {
        // after a stop no more addresses start
        if i > 0
            && i % sweep::BATCH == 0
            && stop
                .race(tokio::time::sleep(sweep::BATCH_EVERY))
                .await
                .is_none()
        {
            break;
        }
        let Some(permit) = stop.race(sem.clone().acquire_owned()).await else {
            break;
        };
        let permit = permit.expect("semaforo chiuso");
        let (emit, done, oui, stop) = (emit.clone(), done.clone(), oui.clone(), stop.clone());
        let (arp, details) = (arp.clone(), details.clone());
        let services = req.services;
        let on_link = nets.iter().any(|n| n.contains(&ip));
        set.spawn(async move {
            let found = sweep::presence(ip, on_link, services, &arp, &stop).await;
            drop(permit);
            let host = found.map(|p| found_host(ip, p, oui.as_deref()));
            if let Some(h) = &host {
                emit(LanEvent::Host(Box::new(h.clone())));
            }
            // stopped midway: the address does not count among those checked
            if host.is_some() || !stop.is_stopped() {
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 32 == 0 || n == total {
                    emit(LanEvent::Progress(LanProgress { done: n, total }));
                }
            }
            let Some(h) = host else {
                return false;
            };
            let full = stop
                .race(async {
                    let _slot = details.acquire().await;
                    enrich(h, ip, services).await
                })
                .await;
            if let Some(full) = full {
                emit(LanEvent::Host(Box::new(full)));
            }
            true
        });
    }
    let mut found = 0;
    while let Some(r) = set.join_next().await {
        if matches!(r, Ok(true)) {
            found += 1;
        }
    }
    Ok(LanSummary {
        cidr: net.to_string(),
        total,
        found,
        elapsed_s: (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        stopped: stop.is_stopped(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snmp::ber;

    const OUI: &str = include_str!("../../src-tauri/resources/oui.txt");

    #[test]
    fn produttori() {
        let db = OuiDb::parse(OUI).unwrap();
        assert!(db.len() > 50_000, "{}", db.len());
        assert_eq!(db.lookup("00:50:56:aa:bb:cc"), Some("VMware"));
        assert_eq!(db.lookup("00-15-5D-01-02-03"), Some("Microsoft"));
        // MA-S inside an IEEE block: the longest prefix wins
        assert_eq!(db.lookup("8c:1f:64:10:3a:bc"), Some("KRONOTECH"));
        assert_eq!(db.lookup("70:b3:d5:62:6f:01"), Some("KRONOTECH"));
        assert_eq!(db.lookup("4c:74:a7:e0:00:01"), Some("KYOCERA"));
        assert_ne!(
            db.lookup("8c:1f:64:00:00:00"),
            Some("IEEE Registration Authority")
        );
        assert_eq!(db.lookup("pippo"), None);
        assert!(OuiDb::parse("# solo commenti\n").is_err());
        assert!(OuiDb::parse("12345\tX\n").unwrap_err().contains("riga 1"));
        assert!(OuiDb::load(Path::new("/non/esiste/oui.txt"))
            .unwrap_err()
            .contains("non trovato"));
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let e = OuiDb::parse("12345\tX\n").unwrap_err();
        assert!(e.contains("line 1") && !e.contains("riga"), "{e}");
        assert!(OuiDb::load(Path::new("/non/esiste/oui.txt"))
            .unwrap_err()
            .contains("not found"));
        assert_eq!(service_name("Desktop remoto"), "Remote Desktop");
    }

    #[test]
    fn mac_particolari() {
        assert!(is_vm_mac("00:0c:29:12:34:56"));
        assert!(is_vm_mac("52:54:00:12:34:56"));
        assert!(!is_random_mac("52:54:00:12:34:56"));
        assert!(is_random_mac("da:a1:19:00:00:01"));
        assert!(!is_random_mac("00:50:56:00:00:01"));
        assert!(!is_random_mac(""));
    }

    #[test]
    fn reti() {
        assert_eq!(
            target_network("172.16.3.7/21").unwrap().to_string(),
            "172.16.0.0/21"
        );
        assert_eq!(
            sweep::targets(&target_network("172.16.0.0/21").unwrap()).len(),
            2046
        );
        assert_eq!(
            target_network("10.0.0.0/20").unwrap_err(),
            "Rete troppo grande: massimo una /21 (2046 host)"
        );
        // the subnet scan stays at /24
        assert!(sweep::parse_net("172.16.0.0/23")
            .unwrap_err()
            .contains("massimo una /24 (254 host)"));
    }

    #[test]
    fn tipi() {
        let snmp = |d: &str, dev: &str| SnmpInfo {
            sys_descr: d.into(),
            device: dev.into(),
            ..Default::default()
        };
        let k = snmp(
            "KYOCERA Document Solutions Printing System",
            "ECOSYS MA4500ix",
        );
        assert_eq!(classify("KYOCERA", Some(&k), false, &[]), "printer");
        assert_eq!(classify("", None, false, &[9100, 80]), "printer");
        // HP also makes PCs: without printing hints it stays a PC
        assert_eq!(classify("Hewlett Packard", None, true, &[]), "pc");
        let f = snmp("FortiGate-100F v7.2.8", "");
        assert_eq!(classify("Fortinet", Some(&f), false, &[443]), "network");
        assert_eq!(classify("Yealink", None, false, &[80]), "phone");
        assert_eq!(classify("Hikvision", None, false, &[80]), "camera");
        assert_eq!(classify("VMware", None, false, &[445, 3389]), "pc");
        assert_eq!(classify("KRONOTECH", None, false, &[22]), "server");
        let l = snmp("Linux imx6dl 4.9.88", "");
        assert_eq!(classify("KRONOTECH", Some(&l), false, &[]), "server");
        assert_eq!(classify("", None, false, &[]), "other");
    }

    /// Fake SNMP agent: answers a v2c GET with fixed values.
    async fn fake_agent(skip_hr: bool) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let mut r = ber::Reader::new(&buf[..n]);
                let mut msg = r.enter(ber::SEQUENCE).unwrap();
                let _ver = msg.int().unwrap();
                let _comm = msg.octets().unwrap();
                let (_, body, _) = msg.tlv().unwrap();
                let mut pdu = ber::Reader::new(body);
                let id = pdu.int().unwrap();
                let (_, _) = (pdu.int().unwrap(), pdu.int().unwrap());
                let mut vbl = pdu.enter(ber::SEQUENCE).unwrap();
                let mut vbs = Vec::new();
                while !vbl.at_end() {
                    let mut vb = vbl.enter(ber::SEQUENCE).unwrap();
                    let (oid, _) = vb.expect(ber::OID).unwrap();
                    let oid = ber::decode_oid(oid);
                    let val = if oid == SYS_DESCR {
                        ber::octets(b"KYOCERA Document Solutions Printing System")
                    } else if oid == SYS_NAME {
                        ber::octets(b"KM-UFFICIO\r\n")
                    } else if oid == SYS_OBJECT_ID {
                        ber::oid(&[1, 3, 6, 1, 4, 1, 1347, 41])
                    } else if oid == HR_DEVICE_DESCR_1 && !skip_hr {
                        ber::octets(b"ECOSYS MA4500ix")
                    } else {
                        ber::tlv(0x81, &[]) // noSuchInstance
                    };
                    vbs.push(ber::seq(&[ber::oid(&oid), val]));
                }
                let pdu = ber::tlv(
                    0xA2,
                    &[ber::int(id), ber::int(0), ber::int(0), ber::seq(&vbs)].concat(),
                );
                let reply = ber::seq(&[ber::int(1), ber::octets(b"public"), pdu]);
                let _ = sock.send_to(&reply, from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn snmp_public() {
        let i = snmp_info(fake_agent(false).await).await.unwrap();
        assert_eq!(i.sys_name, "KM-UFFICIO");
        assert_eq!(i.device, "ECOSYS MA4500ix");
        assert_eq!(i.object_id, "1.3.6.1.4.1.1347.41");
        assert!(i.sys_descr.starts_with("KYOCERA"));
        let i = snmp_info(fake_agent(true).await).await.unwrap();
        assert_eq!(i.device, "");
        // no agent: no information, no errors
        let mute = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(snmp_info(mute.local_addr().unwrap()).await.is_none());
    }

    #[tokio::test]
    async fn servizi() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
            }
        });
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cport = closed.local_addr().unwrap().port();
        drop(closed);
        let r = scan_services(Ipv4Addr::LOCALHOST, &[(port, "SSH"), (cport, "chiusa")]).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].port, port);
        assert_eq!(r[0].banner, "SSH-2.0-OpenSSH_9.6");
    }

    #[test]
    fn eventi_json() {
        let e = LanEvent::Progress(LanProgress {
            done: 32,
            total: 2046,
        });
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"progress":{"done":32,"total":2046}}"#
        );
    }

    fn collector() -> (
        Arc<std::sync::Mutex<Vec<LanEvent>>>,
        impl Fn(LanEvent) + Send + Sync + 'static,
    ) {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let e2 = ev.clone();
        (ev, move |e| e2.lock().unwrap().push(e))
    }

    /// First emission of a host (presence, MAC and vendor only) and completion.
    #[tokio::test]
    async fn host_trovato_e_completato() {
        let db = OuiDb::parse("005056\tVMware, Inc.\n3C5282\tHewlett Packard\n").unwrap();
        let ip = Ipv4Addr::LOCALHOST;
        let h = found_host(
            ip,
            sweep::Presence {
                via: "ICMP".into(),
                rtt_ms: Some(0.4),
                mac: "00:50:56:aa:bb:01".into(),
            },
            Some(&db),
        );
        assert!(h.pending && h.vm && !h.random_mac);
        assert_eq!((h.vendor.as_str(), h.kind), ("VMware, Inc.", "other"));
        assert!(h.name.is_empty() && h.snmp.is_none() && h.services.is_empty());
        let j = serde_json::to_string(&LanEvent::Host(Box::new(h.clone()))).unwrap();
        assert!(
            j.starts_with(r#"{"host":{"ip":"127.0.0.1","via":"ICMP""#),
            "{j}"
        );
        assert!(j.ends_with(r#""kind":"other","pending":true}}"#), "{j}");

        let full = enrich(h, ip, false).await;
        assert!(!full.pending);
        // the data of the first emission stays
        assert_eq!(
            (full.mac.as_str(), full.vendor.as_str(), full.rtt_ms),
            ("00:50:56:aa:bb:01", "VMware, Inc.", Some(0.4))
        );

        // without MAC (remote network) and without the vendor list
        let h = found_host(
            ip,
            sweep::Presence {
                via: "TCP 445".into(),
                rtt_ms: None,
                mac: String::new(),
            },
            None,
        );
        assert!(h.vendor.is_empty() && !h.vm && !h.random_mac);
    }

    /// Full scan of a network without hosts (TEST-NET-3).
    #[tokio::test]
    async fn scansione_senza_host() {
        let (ev, emit) = collector();
        let req = LanReq {
            cidr: "203.0.113.9/29".into(),
            services: false,
        };
        let r = run(req, None, &Stop::new(), emit).await.unwrap();
        assert_eq!(
            (r.cidr.as_str(), r.total, r.found),
            ("203.0.113.8/29", 6, 0)
        );
        assert!(!r.stopped);
        let ev = ev.lock().unwrap();
        assert!(matches!(&ev[0], LanEvent::Start(s) if s.total == 6 && !s.oui && !s.services));
        assert!(ev
            .iter()
            .any(|e| matches!(e, LanEvent::Progress(p) if p.done == 6 && p.total == 6)));
    }

    /// Stop already received: no address starts.
    #[tokio::test]
    async fn fermata_prima_di_partire() {
        let (ev, emit) = collector();
        let stop = Stop::new();
        stop.stop();
        let req = LanReq {
            cidr: "203.0.113.0/24".into(),
            services: true,
        };
        let t0 = Instant::now();
        let r = run(req, None, &stop, emit).await.unwrap();
        assert!(r.stopped);
        assert_eq!((r.total, r.found), (254, 0));
        assert!(t0.elapsed() < Duration::from_millis(500));
        assert_eq!(ev.lock().unwrap().len(), 1); // only the start
    }

    /// Stop during the scan of a /21: it ends at once, waiting neither for
    /// the pause between address groups nor for the probes in progress.
    #[tokio::test]
    async fn fermata_in_corso() {
        let (_ev, emit) = collector();
        let stop = Stop::new();
        let s2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            s2.stop();
        });
        let req = LanReq {
            cidr: "203.0.112.0/21".into(),
            services: true,
        };
        let t0 = Instant::now();
        let r = run(req, None, &stop, emit).await.unwrap();
        assert!(r.stopped);
        assert_eq!(r.total, 2046);
        assert!(
            t0.elapsed() < Duration::from_millis(1200),
            "{:?}",
            t0.elapsed()
        );
    }
}
