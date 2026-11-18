//! Neighbours: ARP (IPv4) and NDP (IPv6) table of this PC, merged by MAC.
//!
//! **Passive** reading: the system neighbour table is read without sending
//! anything (the only exception, on request, is an echo to `ff02::1`, see `probe`).
//! Every reading becomes a `NeighResult`; the comparison with the previous reading
//! (same IP with a different MAC, gateway changed, new IPv6 router) gives the anomalies.
//!
//! - `windows_impl`: `GetIpNetTable2(AF_UNSPEC)`, IPv6 routes announced by routers
//!   (`GetIpForwardTable2`), adapter names (`GetIfEntry2`) and ICMPv6 echo.
//!   If the unified table cannot be read it falls back to the IPv4-only table
//!   already tested (`icmp::neighbors_v4`).
//! - Linux: only `/proc/net/arp` (development and tests).
//!
//! Everything else (merge by MAC, roles, prefixes, checks, CSV) is pure
//! functions, tested with fake readings.

use crate::http::analyze::{check, Check};
use crate::lan::{is_random_mac, is_vm_mac, OuiDb};
use crate::{t, tf};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl;

#[cfg(not(windows))]
mod unix_impl;

#[cfg(not(windows))]
use unix_impl as backend;
#[cfg(windows)]
use windows_impl as backend;

/// From this number of IPv4 addresses on the same MAC a warning is raised.
const MANY_V4: usize = 4;

// ───────────────────────── raw reading ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NState {
    Unreachable,
    Incomplete,
    Probe,
    Delay,
    Stale,
    Reachable,
    Permanent,
}

#[derive(Debug, Clone)]
pub struct RawNeighbor {
    pub ip: IpAddr,
    pub mac: Option<[u8; 6]>,
    pub state: NState,
    pub iface: u32,
    pub is_router: bool,
}

/// IPv6 route from the routing table.
#[derive(Debug, Clone)]
pub struct RawRoute6 {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub next_hop: Ipv6Addr,
    pub iface: u32,
    /// Seconds of validity; `None` = no expiry.
    pub valid_s: Option<u32>,
    /// The route comes from a Router Advertisement.
    pub from_ra: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Raw {
    pub neighbors: Vec<RawNeighbor>,
    pub routes6: Vec<RawRoute6>,
    /// Adapter index → name.
    pub ifaces: HashMap<u32, String>,
    /// Reading path used: "ip-helper", "ripiego-ipv4", "linux-arp".
    pub source: &'static str,
    /// Things that could not be read (shown as information).
    pub notes: Vec<String>,
}

/// Reading of the neighbour table from the system.
pub fn read() -> Option<Raw> {
    backend::read()
}

// ───────────────────────── response ─────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NeighReq {
    /// A single echo to `ff02::1` on every adapter with IPv6, before reading.
    #[serde(default)]
    pub probe: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Addr {
    pub ip: String,
    /// "" (IPv4), "link-local", "unique local", "global", "other"
    pub scope: &'static str,
    /// "reachable", "cache", "permanent", "incomplete"
    pub state: &'static str,
    pub iface: String,
    pub router: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Device {
    /// Empty = unresolved addresses (all together).
    pub mac: String,
    pub vendor: String,
    pub random_mac: bool,
    pub vm: bool,
    pub v4: Vec<Addr>,
    pub v6: Vec<Addr>,
    pub ifaces: Vec<String>,
    pub state: &'static str,
    pub gateway: bool,
    pub router6: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Router6 {
    pub addr: String,
    pub mac: String,
    pub vendor: String,
    pub iface: String,
    /// Validity of the default route, in seconds (absent = no expiry).
    pub lifetime_s: Option<u32>,
    /// The same MAC as the IPv4 gateway.
    pub same_as_gateway: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Prefix6 {
    pub prefix: String,
    pub iface: String,
    pub on_link: bool,
    pub valid_s: Option<u32>,
    /// Addresses of the routers announcing the prefix.
    pub via: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct ProbeInfo {
    pub ifaces: usize,
    pub replies: Vec<String>,
    pub new_entries: usize,
    /// Path used ("icmp6" or "non disponibile") and explanation.
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NeighResult {
    /// Seconds since the Unix epoch.
    pub at: u64,
    pub previous_at: Option<u64>,
    pub source: &'static str,
    pub gateway: Option<String>,
    pub devices: Vec<Device>,
    pub routers: Vec<Router6>,
    pub prefixes: Vec<Prefix6>,
    pub n_devices: usize,
    pub n_v4: usize,
    pub n_v6: usize,
    pub unresolved: usize,
    pub checks: Vec<Check>,
    pub probe: Option<ProbeInfo>,
    pub csv: String,
}

// ───────────────────────── construction ─────────────────────────

fn fmt_mac(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Scope of an IPv6 address.
pub fn scope6(a: &Ipv6Addr) -> &'static str {
    let s = a.segments()[0];
    if s & 0xffc0 == 0xfe80 {
        "link-local"
    } else if s & 0xfe00 == 0xfc00 {
        t!("locale unica", "unique local")
    } else if s & 0xe000 == 0x2000 {
        t!("globale", "global")
    } else {
        t!("altro", "other")
    }
}

fn state_name(s: NState) -> &'static str {
    match s {
        NState::Reachable => "reachable",
        NState::Stale | NState::Delay | NState::Probe => "cache",
        NState::Permanent => "permanent",
        NState::Incomplete | NState::Unreachable => "incomplete",
    }
}

fn state_rank(s: &str) -> u8 {
    match s {
        "reachable" => 0,
        "cache" => 1,
        "permanent" => 2,
        _ => 3,
    }
}

/// Addresses that are not hosts: multicast, broadcast, loopback, unspecified.
fn is_noise(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_multicast() || a.is_broadcast() || a.is_loopback() || a.is_unspecified()
        }
        IpAddr::V6(a) => a.is_multicast() || a.is_loopback() || a.is_unspecified(),
    }
}

fn iface_name(raw: &Raw, index: u32) -> String {
    raw.ifaces
        .get(&index)
        .cloned()
        .unwrap_or_else(|| tf!("scheda {index}", "adapter {index}"))
}

fn ipv4_num(a: &str) -> u32 {
    a.parse::<Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX)
}

/// Merges the raw reading by MAC. `gateway` = IPv4 gateway of this PC.
pub fn build(raw: &Raw, gateway: Option<Ipv4Addr>, oui: Option<&OuiDb>, at: u64) -> NeighResult {
    let mut by_mac: BTreeMap<String, Device> = BTreeMap::new();
    // address → MAC, for the routers
    let mut mac_of: HashMap<IpAddr, String> = HashMap::new();
    let mut router_ips: HashSet<IpAddr> = HashSet::new();
    let mut unresolved_ips: HashSet<IpAddr> = HashSet::new();

    for n in &raw.neighbors {
        if is_noise(&n.ip) {
            continue;
        }
        let mac = match n.mac {
            Some(m) if m != [0u8; 6] && m[0] & 1 == 0 => Some(fmt_mac(m)),
            Some(m) if m[0] & 1 == 1 => continue, // multicast / broadcast
            _ => None,
        };
        let state = if mac.is_none() {
            "incomplete"
        } else {
            state_name(n.state)
        };
        let key = mac.clone().unwrap_or_default();
        if mac.is_none() {
            unresolved_ips.insert(n.ip);
        } else {
            mac_of.insert(n.ip, key.clone());
        }
        if n.is_router && n.ip.is_ipv6() {
            router_ips.insert(n.ip);
        }
        let dev = by_mac.entry(key.clone()).or_insert_with(|| Device {
            mac: key.clone(),
            vendor: if is_random_mac(&key) || key.is_empty() {
                String::new()
            } else {
                oui.and_then(|db| db.lookup(&key)).unwrap_or("").to_string()
            },
            random_mac: is_random_mac(&key),
            vm: is_vm_mac(&key),
            v4: vec![],
            v6: vec![],
            ifaces: vec![],
            state: "incomplete",
            gateway: false,
            router6: false,
        });
        let iface = iface_name(raw, n.iface);
        if !dev.ifaces.contains(&iface) {
            dev.ifaces.push(iface.clone());
        }
        if state_rank(state) < state_rank(dev.state) || dev.v4.is_empty() && dev.v6.is_empty() {
            dev.state = state;
        }
        let addr = Addr {
            ip: n.ip.to_string(),
            scope: match &n.ip {
                IpAddr::V6(a) => scope6(a),
                IpAddr::V4(a) if a.is_link_local() => "link-local",
                IpAddr::V4(_) => "",
            },
            state,
            iface,
            router: n.is_router && n.ip.is_ipv6(),
        };
        match n.ip {
            IpAddr::V4(_) => dev.v4.push(addr),
            IpAddr::V6(_) => dev.v6.push(addr),
        }
    }

    // IPv6 routers: neighbours with the "router" bit and the next hops of the announced default routes
    let mut routers: Vec<Router6> = vec![];
    let gw_mac = gateway.and_then(|g| mac_of.get(&IpAddr::V4(g)).cloned());
    let mut add_router = |ip: Ipv6Addr, iface: u32, lifetime: Option<u32>| {
        let addr = ip.to_string();
        if routers.iter().any(|r| r.addr == addr) {
            return;
        }
        let mac = mac_of.get(&IpAddr::V6(ip)).cloned().unwrap_or_default();
        let vendor = if mac.is_empty() || is_random_mac(&mac) {
            String::new()
        } else {
            oui.and_then(|db| db.lookup(&mac)).unwrap_or("").to_string()
        };
        routers.push(Router6 {
            same_as_gateway: !mac.is_empty() && gw_mac.as_deref() == Some(mac.as_str()),
            addr,
            mac,
            vendor,
            iface: iface_name(raw, iface),
            lifetime_s: lifetime,
        });
    };
    for r in raw.routes6.iter().filter(|r| r.from_ra && r.len == 0) {
        router_ips.insert(IpAddr::V6(r.next_hop));
        add_router(r.next_hop, r.iface, r.valid_s);
    }
    for n in raw.neighbors.iter().filter(|n| n.is_router) {
        if let IpAddr::V6(a) = n.ip {
            add_router(a, n.iface, None);
        }
    }
    routers.sort_by(|a, b| a.addr.cmp(&b.addr));

    // announced prefixes
    let mut prefixes: Vec<Prefix6> = vec![];
    for r in raw
        .routes6
        .iter()
        .filter(|r| r.from_ra && r.len > 0 && r.len < 128)
    {
        let p = format!(
            "{}/{}",
            Ipv6Addr::from(u128::from(r.prefix) & mask6(r.len)),
            r.len
        );
        let iface = iface_name(raw, r.iface);
        let on_link = r.next_hop.is_unspecified();
        let via = (!on_link).then(|| r.next_hop.to_string());
        if let Some(x) = prefixes
            .iter_mut()
            .find(|x| x.prefix == p && x.iface == iface)
        {
            x.on_link |= on_link;
            if let Some(v) = via {
                if !x.via.contains(&v) {
                    x.via.push(v);
                }
            }
        } else {
            prefixes.push(Prefix6 {
                prefix: p,
                iface,
                on_link,
                valid_s: r.valid_s,
                via: via.into_iter().collect(),
            });
        }
    }
    prefixes.sort_by(|a, b| a.prefix.cmp(&b.prefix));

    let mut devices: Vec<Device> = by_mac.into_values().collect();
    for d in &mut devices {
        d.v4.sort_by_key(|a| ipv4_num(&a.ip));
        d.v6.sort_by(|a, b| a.ip.cmp(&b.ip));
        d.gateway = gateway.is_some_and(|g| d.v4.iter().any(|a| a.ip == g.to_string()));
        d.router6 = d.v6.iter().any(|a| a.router);
    }
    devices.sort_by(|a, b| {
        a.mac
            .is_empty()
            .cmp(&b.mac.is_empty())
            .then(b.gateway.cmp(&a.gateway))
            .then(b.router6.cmp(&a.router6))
            .then_with(|| {
                let k = |d: &Device| {
                    (
                        d.v4.first().map(|x| ipv4_num(&x.ip)).unwrap_or(u32::MAX),
                        d.mac.clone(),
                    )
                };
                k(a).cmp(&k(b))
            })
    });

    let n_v4 = raw
        .neighbors
        .iter()
        .filter(|n| !is_noise(&n.ip) && n.ip.is_ipv4() && !unresolved_ips.contains(&n.ip))
        .count();
    let n_v6 = raw
        .neighbors
        .iter()
        .filter(|n| !is_noise(&n.ip) && n.ip.is_ipv6() && !unresolved_ips.contains(&n.ip))
        .count();
    let mut res = NeighResult {
        at,
        previous_at: None,
        source: raw.source,
        gateway: gateway.map(|g| g.to_string()),
        n_devices: devices.iter().filter(|d| !d.mac.is_empty()).count(),
        unresolved: unresolved_ips.len(),
        devices,
        routers,
        prefixes,
        n_v4,
        n_v6,
        checks: vec![],
        probe: None,
        csv: String::new(),
    };
    res.checks = static_checks(&res, &raw.notes);
    res.csv = csv(&res);
    res
}

fn mask6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len.min(128) as u32)
    }
}

// ───────────────────────── checks ─────────────────────────

fn plural(n: usize, one: &str, more: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { more })
}

/// Checks that depend on a single reading.
fn static_checks(r: &NeighResult, notes: &[String]) -> Vec<Check> {
    let mut v = vec![];
    for n in notes {
        v.push(check(
            t!("Lettura", "Reading"),
            "info",
            t!("Lettura incompleta", "Incomplete reading"),
            n.clone(),
        ));
    }
    match &r.gateway {
        Some(g) => match r.devices.iter().find(|d| d.gateway) {
            Some(d) => v.push(check(
                t!("Rete", "Network"),
                "ok",
                t!("Gateway nella tabella", "Gateway in the table"),
                format!("{g} ({})", d.mac),
            )),
            None => v.push(check(
                t!("Rete", "Network"),
                "info",
                t!(
                    "Gateway non ancora nella tabella",
                    "Gateway not yet in the table"
                ),
                tf!(
                    "{g}: Windows non l'ha ancora risolto, fai un ping o aggiorna dopo qualche istante",
                    "{g}: Windows has not resolved it yet, run a ping or refresh in a few moments"
                ),
            )),
        },
        None => v.push(check(
            t!("Rete", "Network"),
            "info",
            t!("Nessun gateway IPv4", "No IPv4 gateway"),
            t!(
                "il PC non ha una route predefinita IPv4",
                "the PC has no default IPv4 route"
            ),
        )),
    }
    for d in r
        .devices
        .iter()
        .filter(|d| !d.mac.is_empty() && d.v4.len() >= MANY_V4)
    {
        v.push(check(
            t!("Rete", "Network"),
            "warn",
            t!(
                "MAC con molti indirizzi IPv4",
                "MAC with many IPv4 addresses"
            ),
            tf!(
                "{} risponde per {}: ARP proxy, host con più indirizzi o un duplicato",
                "{} answers for {}: proxy ARP, a host with several addresses or a duplicate",
                d.mac,
                plural(
                    d.v4.len(),
                    t!("indirizzo", "address"),
                    t!("indirizzi", "addresses")
                )
            ),
        ));
    }
    if r.unresolved > 0 {
        v.push(check(
            t!("Rete", "Network"),
            "info",
            t!("Indirizzi non risolti", "Unresolved addresses"),
            tf!(
                "{}: nessuna risposta ARP o NDP finora",
                "{}: no ARP or NDP reply so far",
                plural(
                    r.unresolved,
                    t!("indirizzo", "address"),
                    t!("indirizzi", "addresses")
                )
            ),
        ));
    }
    // IPv6
    if r.n_v6 == 0 && r.routers.is_empty() {
        v.push(check(
            "IPv6",
            "info",
            t!("Nessun vicino IPv6", "No IPv6 neighbours"),
            t!(
                "la tabella NDP è vuota: IPv6 non in uso su questa rete oppure nessuno ha ancora parlato con il PC",
                "the NDP table is empty: IPv6 is not in use on this network or nobody has talked to the PC yet"
            ),
        ));
    } else if r.routers.is_empty() {
        v.push(check(
            "IPv6",
            "info",
            t!("Nessun router IPv6", "No IPv6 router"),
            t!(
                "nessun Router Advertisement ricevuto: la rete non assegna indirizzi IPv6 globali",
                "no Router Advertisement received: the network does not assign global IPv6 addresses"
            ),
        ));
    } else {
        let macs: HashSet<&str> = r
            .routers
            .iter()
            .filter(|x| !x.mac.is_empty())
            .map(|x| x.mac.as_str())
            .collect();
        if macs.len() > 1 {
            v.push(check(
                "IPv6",
                "warn",
                t!("Più router IPv6", "Several IPv6 routers"),
                tf!(
                    "{} con MAC diversi annunciano la rete: verifica che siano voluti (un Router Advertisement non autorizzato devia il traffico)",
                    "{} with different MACs announce the network: check that they are intended (a rogue Router Advertisement diverts traffic)",
                    r.routers.len()
                ),
            ));
        } else {
            let x = &r.routers[0];
            v.push(check(
                "IPv6",
                "ok",
                t!("Un solo router IPv6", "A single IPv6 router"),
                format!(
                    "{}{}",
                    x.addr,
                    if x.same_as_gateway {
                        t!(
                            " (stesso MAC del gateway IPv4)",
                            " (same MAC as the IPv4 gateway)"
                        )
                    } else {
                        ""
                    }
                ),
            ));
        }
        for x in r
            .routers
            .iter()
            .filter(|x| !x.mac.is_empty() && !x.same_as_gateway)
        {
            if r.gateway.is_some() && r.devices.iter().any(|d| d.gateway) {
                v.push(check(
                    "IPv6",
                    "info",
                    t!(
                        "Router IPv6 diverso dal gateway IPv4",
                        "IPv6 router different from the IPv4 gateway"
                    ),
                    tf!(
                        "{} ({}) non ha il MAC del gateway {}",
                        "{} ({}) does not have the MAC of the gateway {}",
                        x.addr,
                        x.mac,
                        r.gateway.clone().unwrap_or_default()
                    ),
                ));
            }
        }
    }
    let globals: HashSet<&str> = r.prefixes.iter().map(|p| p.prefix.as_str()).collect();
    if globals.len() > 1 {
        v.push(check(
            "IPv6",
            "info",
            t!("Più prefissi IPv6", "Several IPv6 prefixes"),
            tf!(
                "{} annunciati: {}",
                "{} announced: {}",
                globals.len(),
                globals.iter().copied().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    v
}

/// Comparison with the previous reading.
fn diff_checks(prev: &NeighResult, cur: &NeighResult) -> Vec<Check> {
    let mut v = vec![];
    // IP → MAC
    let map = |r: &NeighResult| -> HashMap<String, String> {
        r.devices
            .iter()
            .filter(|d| !d.mac.is_empty())
            .flat_map(|d| {
                d.v4.iter()
                    .chain(d.v6.iter())
                    .map(|a| (a.ip.clone(), d.mac.clone()))
            })
            .collect()
    };
    let (p, c) = (map(prev), map(cur));
    let mut changed: Vec<(&String, &String, &String)> = c
        .iter()
        .filter_map(|(ip, mac)| {
            p.get(ip)
                .filter(|old| *old != mac)
                .map(|old| (ip, old, mac))
        })
        .collect();
    changed.sort();
    for (ip, old, new) in changed {
        let gw = cur.gateway.as_deref() == Some(ip.as_str());
        v.push(check(
            t!("Cambiamenti", "Changes"),
            if gw { "err" } else { "warn" },
            if gw {
                t!("Il gateway ha cambiato MAC", "The gateway changed MAC")
            } else {
                t!(
                    "Indirizzo passato a un altro MAC",
                    "Address moved to another MAC"
                )
            },
            tf!(
                "{ip}: prima {old}, ora {new}{}",
                "{ip}: was {old}, now {new}{}",
                if gw {
                    t!(
                        ": possibile ARP spoofing o sostituzione dell'apparato",
                        ": possible ARP spoofing or device replacement"
                    )
                } else {
                    t!(
                        " (DHCP, IP duplicato o ARP spoofing)",
                        " (DHCP, duplicate IP or ARP spoofing)"
                    )
                }
            ),
        ));
    }
    if prev.gateway != cur.gateway {
        v.push(check(
            t!("Cambiamenti", "Changes"),
            "warn",
            t!("Gateway cambiato", "Gateway changed"),
            tf!(
                "prima {}, ora {}",
                "was {}, now {}",
                prev.gateway.as_deref().unwrap_or(t!("nessuno", "none")),
                cur.gateway.as_deref().unwrap_or(t!("nessuno", "none"))
            ),
        ));
    }
    let routers =
        |r: &NeighResult| -> HashSet<String> { r.routers.iter().map(|x| x.addr.clone()).collect() };
    let (pr, cr) = (routers(prev), routers(cur));
    let mut new: Vec<_> = cr.difference(&pr).cloned().collect();
    new.sort();
    for a in new {
        let mac = cur
            .routers
            .iter()
            .find(|x| x.addr == a)
            .map(|x| x.mac.clone())
            .unwrap_or_default();
        v.push(check(
            t!("Cambiamenti", "Changes"),
            "warn",
            t!("Nuovo router IPv6", "New IPv6 router"),
            tf!(
                "{a}{}: un Router Advertisement nuovo, verifica che sia voluto",
                "{a}{}: a new Router Advertisement, check that it is intended",
                if mac.is_empty() {
                    String::new()
                } else {
                    format!(" ({mac})")
                }
            ),
        ));
    }
    let mut gone: Vec<_> = pr.difference(&cr).cloned().collect();
    gone.sort();
    for a in gone {
        v.push(check(
            t!("Cambiamenti", "Changes"),
            "info",
            t!("Router IPv6 scomparso", "IPv6 router disappeared"),
            tf!("{a} non è più annunciato", "{a} is no longer announced"),
        ));
    }
    let macs = |r: &NeighResult| -> HashSet<String> {
        r.devices
            .iter()
            .filter(|d| !d.mac.is_empty())
            .map(|d| d.mac.clone())
            .collect()
    };
    let (pm, cm) = (macs(prev), macs(cur));
    let (n_new, n_gone) = (cm.difference(&pm).count(), pm.difference(&cm).count());
    if n_new > 0 {
        v.push(check(
            t!("Cambiamenti", "Changes"),
            "info",
            t!("Dispositivi nuovi", "New devices"),
            tf!(
                "{} dall'aggiornamento precedente",
                "{} since the previous refresh",
                plural(n_new, "MAC", "MAC")
            ),
        ));
    }
    if n_gone > 0 {
        v.push(check(
            t!("Cambiamenti", "Changes"),
            "info",
            t!("Dispositivi non più in tabella", "Devices no longer in the table"),
            tf!(
                "{}: la tabella dimentica i vicini dopo qualche minuto, non vuol dire che siano spenti",
                "{}: the table forgets neighbours after a few minutes, it does not mean they are switched off",
                plural(n_gone, "MAC", "MAC")
            ),
        ));
    }
    if v.is_empty() {
        v.push(check(
            t!("Cambiamenti", "Changes"),
            "ok",
            t!("Nessun cambiamento", "No changes"),
            t!(
                "stesse associazioni IP-MAC e stessi router dell'aggiornamento precedente",
                "same IP-MAC associations and same routers as the previous refresh"
            ),
        ));
    }
    v
}

/// Puts into `cur` the checks of the comparison with `prev`.
pub fn compare(cur: &mut NeighResult, prev: Option<&NeighResult>) {
    if let Some(p) = prev {
        cur.previous_at = Some(p.at);
        let extra = diff_checks(p, cur);
        cur.checks.extend(extra);
    }
}

// ───────────────────────── CSV ─────────────────────────

pub fn csv(r: &NeighResult) -> String {
    let field = |s: &str| {
        if s.contains([';', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    };
    let mut out = vec![t!(
        "MAC;Produttore;Famiglia;Indirizzo;Ambito;Stato;Scheda;Ruolo",
        "MAC;Vendor;Family;Address;Scope;State;Adapter;Role"
    )
    .to_string()];
    for d in &r.devices {
        for (fam, list) in [("IPv4", &d.v4), ("IPv6", &d.v6)] {
            for a in list {
                let ruolo = if d.gateway && fam == "IPv4" {
                    "gateway"
                } else if a.router {
                    t!("router IPv6", "IPv6 router")
                } else {
                    ""
                };
                out.push(
                    [
                        d.mac.as_str(),
                        d.vendor.as_str(),
                        fam,
                        a.ip.as_str(),
                        a.scope,
                        a.state,
                        a.iface.as_str(),
                        ruolo,
                    ]
                    .iter()
                    .map(|s| field(s))
                    .collect::<Vec<_>>()
                    .join(";"),
                );
            }
        }
    }
    out.join("\r\n")
}

// ───────────────────────── reading ─────────────────────────

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads the table (and possibly sends the echo to `ff02::1`) and compares it with
/// the previous reading.
pub async fn run(
    req: NeighReq,
    oui: Option<Arc<OuiDb>>,
    prev: Option<NeighResult>,
) -> crate::Result<NeighResult> {
    let gateway = crate::netpath::default_route().and_then(|r| r.gateway);
    let count6 = |r: &Option<Raw>| {
        r.as_ref()
            .map_or(0, |r| r.neighbors.iter().filter(|x| x.ip.is_ipv6()).count())
    };
    let (before, probe, raw) = tokio::task::spawn_blocking(move || {
        let before = req.probe.then(read);
        let probe = req.probe.then(|| {
            let info = backend::probe();
            // replies arrive within a few ms; Windows creates the NDP entries right after
            std::thread::sleep(std::time::Duration::from_millis(1200));
            info
        });
        (before, probe, read())
    })
    .await
    .map_err(|e| {
        tf!(
            "Lettura dei vicini interrotta: {e}",
            "Neighbour reading interrupted: {e}"
        )
    })?;
    let raw = raw.ok_or_else(|| {
        t!(
            "La tabella dei vicini non è leggibile su questo sistema",
            "The neighbour table cannot be read on this system"
        )
        .to_string()
    })?;
    let mut res = build(&raw, gateway, oui.as_deref(), now());
    if let (Some(before), Some(mut info)) = (before, probe) {
        info.new_entries = count6(&Some(raw.clone())).saturating_sub(count6(&before));
        res.checks.push(probe_check(&info));
        res.probe = Some(info);
    }
    compare(&mut res, prev.as_ref());
    Ok(res)
}

/// The check that reports the outcome of the echo to `ff02::1`.
pub fn probe_check(p: &ProbeInfo) -> Check {
    if p.ifaces == 0 {
        return check(
            "IPv6",
            "info",
            t!("Echo a ff02::1 non inviato", "Echo to ff02::1 not sent"),
            p.note.clone(),
        );
    }
    check(
        "IPv6",
        "info",
        t!("Echo a ff02::1", "Echo to ff02::1"),
        tf!(
            "{} su {}; {} risposta/e dirette ({}); voci nuove nella tabella: {}",
            "{} on {}; {} direct reply/replies ({}); new entries in the table: {}",
            plural(
                p.ifaces,
                t!("pacchetto", "packet"),
                t!("pacchetti", "packets")
            ),
            plural(p.ifaces, t!("scheda", "adapter"), t!("schede", "adapters")),
            p.replies.len(),
            if p.replies.is_empty() {
                t!("nessuna", "none").to_string()
            } else {
                p.replies.join(", ")
            },
            p.new_entries
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUI: &str = "005056\tVMware, Inc.\n3C5282\tEsempio Networks\n";

    fn v4(a: [u8; 4], mac: Option<[u8; 6]>, state: NState) -> RawNeighbor {
        RawNeighbor {
            ip: IpAddr::V4(Ipv4Addr::from(a)),
            mac,
            state,
            iface: 4,
            is_router: false,
        }
    }
    fn v6(a: &str, mac: Option<[u8; 6]>, state: NState, router: bool) -> RawNeighbor {
        RawNeighbor {
            ip: IpAddr::V6(a.parse().unwrap()),
            mac,
            state,
            iface: 4,
            is_router: router,
        }
    }
    const GW: [u8; 6] = [0x3c, 0x52, 0x82, 0, 0, 1];
    const PC: [u8; 6] = [0x3c, 0x52, 0x82, 0, 0, 2];

    fn raw() -> Raw {
        Raw {
            neighbors: vec![
                v4([172, 16, 1, 1], Some(GW), NState::Reachable),
                v4([172, 16, 1, 84], Some(PC), NState::Stale),
                v6("fe80::3e52:82ff:fe00:1", Some(GW), NState::Reachable, true),
                v6("2001:db8:1::84", Some(PC), NState::Stale, false),
                v6("fe80::3e52:82ff:fe00:2", Some(PC), NState::Stale, false),
                v4([172, 16, 1, 99], None, NState::Incomplete),
                v4(
                    [224, 0, 0, 22],
                    Some([1, 0, 0x5e, 0, 0, 0x16]),
                    NState::Permanent,
                ),
                v4([255, 255, 255, 255], Some([0xff; 6]), NState::Permanent),
            ],
            routes6: vec![
                RawRoute6 {
                    prefix: "::".parse().unwrap(),
                    len: 0,
                    next_hop: "fe80::3e52:82ff:fe00:1".parse().unwrap(),
                    iface: 4,
                    valid_s: Some(1800),
                    from_ra: true,
                },
                RawRoute6 {
                    prefix: "2001:db8:1::".parse().unwrap(),
                    len: 64,
                    next_hop: Ipv6Addr::UNSPECIFIED,
                    iface: 4,
                    valid_s: Some(86400),
                    from_ra: true,
                },
                RawRoute6 {
                    prefix: "2001:db8:ffff::".parse().unwrap(),
                    len: 48,
                    next_hop: Ipv6Addr::UNSPECIFIED,
                    iface: 4,
                    valid_s: None,
                    from_ra: false,
                },
            ],
            ifaces: HashMap::from([(4, "Ethernet".to_string())]),
            source: "ip-helper",
            notes: vec![],
        }
    }

    fn built() -> NeighResult {
        let db = OuiDb::parse(OUI).unwrap();
        build(&raw(), Some(Ipv4Addr::new(172, 16, 1, 1)), Some(&db), 1000)
    }

    #[test]
    fn unione_per_mac() {
        let r = built();
        // gateway, PC, unresolved; multicast and broadcast excluded
        assert_eq!(r.devices.len(), 3);
        let gw = &r.devices[0];
        assert!(gw.gateway && gw.router6 && gw.mac == "3c:52:82:00:00:01");
        assert_eq!(gw.vendor, "Esempio Networks");
        assert_eq!((gw.v4.len(), gw.v6.len()), (1, 1));
        assert_eq!(gw.state, "reachable");
        let pc = &r.devices[1];
        assert_eq!((pc.v4.len(), pc.v6.len(), pc.state), (1, 2, "cache"));
        assert_eq!(pc.v6[0].scope, "globale");
        assert_eq!(pc.v6[1].scope, "link-local");
        let un = &r.devices[2];
        assert!(un.mac.is_empty() && un.v4[0].ip == "172.16.1.99" && un.state == "incomplete");
        assert_eq!((r.n_devices, r.n_v4, r.n_v6, r.unresolved), (2, 2, 3, 1));
    }

    #[test]
    fn router_e_prefissi() {
        let r = built();
        assert_eq!(r.routers.len(), 1);
        let x = &r.routers[0];
        assert!(x.same_as_gateway && x.mac == "3c:52:82:00:00:01" && x.lifetime_s == Some(1800));
        // only the announced prefixes, in canonical form
        assert_eq!(r.prefixes.len(), 1);
        assert_eq!(r.prefixes[0].prefix, "2001:db8:1::/64");
        assert!(r.prefixes[0].on_link);
    }

    #[test]
    fn controlli_di_una_lettura() {
        let r = built();
        let nome = |n: &str| r.checks.iter().find(|c| c.name == n).map(|c| c.status);
        assert_eq!(nome("Gateway nella tabella"), Some("ok"));
        assert_eq!(nome("Un solo router IPv6"), Some("ok"));
        assert_eq!(nome("Indirizzi non risolti"), Some("info"));
        assert_eq!(nome("MAC con molti indirizzi IPv4"), None);
    }

    #[test]
    fn molti_ipv4_per_un_mac() {
        let mut raw = raw();
        for i in 10..15 {
            raw.neighbors.push(v4(
                [172, 16, 1, i],
                Some([0x52, 0x54, 0, 1, 2, 3]),
                NState::Reachable,
            ));
        }
        let r = build(&raw, None, None, 0);
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "MAC con molti indirizzi IPv4")
            .unwrap();
        assert_eq!(c.status, "warn");
        assert!(c.detail.contains("5 indirizzi"));
        assert!(r.checks.iter().any(|c| c.name == "Nessun gateway IPv4"));
    }

    #[test]
    fn i_non_risolti_non_sono_un_mac() {
        let mut raw = raw();
        for i in 10..20 {
            raw.neighbors
                .push(v4([172, 16, 1, i], None, NState::Unreachable));
        }
        let r = build(&raw, None, None, 0);
        assert_eq!(r.unresolved, 11);
        assert!(!r
            .checks
            .iter()
            .any(|c| c.name == "MAC con molti indirizzi IPv4"));
    }

    #[test]
    fn piu_router_con_mac_diversi() {
        let mut raw = raw();
        raw.neighbors
            .push(v6("fe80::1", Some(PC), NState::Reachable, true));
        let r = build(&raw, Some(Ipv4Addr::new(172, 16, 1, 1)), None, 0);
        assert_eq!(r.routers.len(), 2);
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "Più router IPv6" && c.status == "warn"));
    }

    #[test]
    fn senza_ipv6() {
        let mut raw = raw();
        raw.neighbors.retain(|n| n.ip.is_ipv4());
        raw.routes6.clear();
        let r = build(&raw, Some(Ipv4Addr::new(172, 16, 1, 1)), None, 0);
        assert!(r.routers.is_empty());
        assert!(r.checks.iter().any(|c| c.name == "Nessun vicino IPv6"));
    }

    #[test]
    fn confronto_stesso_ip_altro_mac() {
        let prev = built();
        let mut raw2 = raw();
        raw2.neighbors[1] = v4(
            [172, 16, 1, 84],
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            NState::Reachable,
        );
        let mut cur = build(&raw2, Some(Ipv4Addr::new(172, 16, 1, 1)), None, 2000);
        compare(&mut cur, Some(&prev));
        assert_eq!(cur.previous_at, Some(1000));
        let c = cur
            .checks
            .iter()
            .find(|c| c.name == "Indirizzo passato a un altro MAC")
            .unwrap();
        assert_eq!(c.status, "warn");
        assert!(c
            .detail
            .starts_with("172.16.1.84: prima 3c:52:82:00:00:02, ora 00:11:22:33:44:55"));
        assert!(cur.checks.iter().any(|c| c.name == "Dispositivi nuovi"));
        assert!(!cur.checks.iter().any(|c| c.name == "Nessun cambiamento"));
    }

    #[test]
    fn confronto_gateway() {
        let prev = built();
        // the gateway changes MAC
        let mut raw2 = raw();
        raw2.neighbors[0] = v4(
            [172, 16, 1, 1],
            Some([0xaa, 0xbb, 0xcc, 0, 0, 9]),
            NState::Reachable,
        );
        let mut cur = build(&raw2, Some(Ipv4Addr::new(172, 16, 1, 1)), None, 2000);
        compare(&mut cur, Some(&prev));
        assert!(cur
            .checks
            .iter()
            .any(|c| c.name == "Il gateway ha cambiato MAC" && c.status == "err"));
        // the gateway changes address
        let mut cur = build(&raw(), Some(Ipv4Addr::new(172, 16, 1, 254)), None, 2000);
        compare(&mut cur, Some(&prev));
        let c = cur
            .checks
            .iter()
            .find(|c| c.name == "Gateway cambiato")
            .unwrap();
        assert!(c.detail.contains("prima 172.16.1.1, ora 172.16.1.254"));
    }

    #[test]
    fn confronto_router_nuovo_e_nessun_cambiamento() {
        let prev = built();
        let mut same = built();
        compare(&mut same, Some(&prev));
        assert!(same
            .checks
            .iter()
            .any(|c| c.name == "Nessun cambiamento" && c.status == "ok"));
        let mut raw2 = raw();
        raw2.neighbors.push(v6(
            "fe80::dead",
            Some([0x02, 0, 0, 0, 0, 7]),
            NState::Reachable,
            true,
        ));
        let mut cur = build(&raw2, Some(Ipv4Addr::new(172, 16, 1, 1)), None, 2000);
        compare(&mut cur, Some(&prev));
        assert!(cur
            .checks
            .iter()
            .any(|c| c.name == "Nuovo router IPv6" && c.status == "warn"));
        // without a previous reading there is no comparison
        let mut first = built();
        let n = first.checks.len();
        compare(&mut first, None);
        assert_eq!((first.checks.len(), first.previous_at), (n, None));
    }

    #[test]
    fn csv_una_riga_per_indirizzo() {
        let r = built();
        let rows: Vec<&str> = r.csv.split("\r\n").collect();
        assert_eq!(
            rows[0],
            "MAC;Produttore;Famiglia;Indirizzo;Ambito;Stato;Scheda;Ruolo"
        );
        assert_eq!(rows.len(), 1 + 6);
        assert!(rows.contains(
            &"3c:52:82:00:00:01;Esempio Networks;IPv4;172.16.1.1;;reachable;Ethernet;gateway"
        ));
        assert!(rows
            .iter()
            .any(|x| x.contains("IPv6;fe80::3e52:82ff:fe00:1;link-local")
                && x.ends_with("router IPv6")));
    }

    #[test]
    fn ambiti_ipv6() {
        for (a, s) in [
            ("fe80::1", "link-local"),
            ("fd12::1", "locale unica"),
            ("2001:db8::1", "globale"),
            ("ff02::1", "altro"),
        ] {
            assert_eq!(scope6(&a.parse().unwrap()), s, "{a}");
        }
        assert_eq!(mask6(64), 0xffff_ffff_ffff_ffff_0000_0000_0000_0000);
        assert_eq!(mask6(0), 0);
    }

    #[test]
    fn esito_dell_echo() {
        let c = probe_check(&ProbeInfo {
            ifaces: 0,
            replies: vec![],
            new_entries: 0,
            note: "nessuna scheda con IPv6".into(),
        });
        assert_eq!(c.name, "Echo a ff02::1 non inviato");
        let c = probe_check(&ProbeInfo {
            ifaces: 2,
            replies: vec!["fe80::1".into()],
            new_entries: 3,
            note: String::new(),
        });
        assert!(
            c.detail.contains("2 pacchetti su 2 schede")
                && c.detail.contains("voci nuove nella tabella: 3"),
            "{}",
            c.detail
        );
    }

    #[test]
    fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let r = built();
        assert!(r.checks.iter().any(|c| c.name == "Gateway in the table"));
        assert!(r.checks.iter().any(|c| c.name == "A single IPv6 router"));
        assert!(!r.checks.iter().any(|c| c.name == "Gateway nella tabella"));
        assert!(r
            .devices
            .iter()
            .any(|d| d.v6.iter().any(|a| a.scope == "global")));
        assert!(csv(&r).starts_with("MAC;Vendor;Family;Address;"));
        assert_eq!(scope6(&"fd12::1".parse().unwrap()), "unique local");
        let mut cur = built();
        let mut old = built();
        old.gateway = Some("172.16.1.254".into());
        compare(&mut cur, Some(&old));
        let c = cur
            .checks
            .iter()
            .find(|c| c.name == "Gateway changed")
            .unwrap();
        assert!(c.detail.starts_with("was 172.16.1.254, now "));
        assert!(!c.detail.contains("prima"));
    }

    /// Real system reading: only the shape, without assuming what it contains.
    #[test]
    fn lettura_del_sistema() {
        if let Some(raw) = read() {
            let r = build(&raw, None, None, 0);
            assert!(r
                .devices
                .iter()
                .all(|d| d.mac.is_empty() || d.mac.len() == 17));
        }
    }
}
