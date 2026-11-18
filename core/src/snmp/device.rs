//! Reading of a whole device: system, interfaces, LLDP neighbours, MAC and ARP table.
//!
//! `collect` reads the needed columns from the agent (one at a time, with "Stop") and puts
//! them in `Raw`; everything else is pure functions that build the views and the checks
//! from `Raw`, tested with hand-written values.

use super::client::{Session, Value, VarBind};
use super::printer::{self, Printer};
use super::resources::{self, Resources};
use super::{connect, mib, walk, SnmpReq};
use crate::http::analyze::{check, Check, INFO, OK, WARN};
use crate::lan::OuiDb;
use crate::ping::Stop;
use crate::{t, tf, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

#[derive(Debug, Default, Deserialize)]
pub struct DeviceReq {
    #[serde(flatten)]
    pub snmp: SnmpReq,
    /// Sections to read: all of them if not specified.
    #[serde(default)]
    pub system: Option<bool>,
    #[serde(default)]
    pub interfaces: Option<bool>,
    #[serde(default)]
    pub neighbors: Option<bool>,
    #[serde(default)]
    pub fdb: Option<bool>,
    #[serde(default)]
    pub resources: Option<bool>,
    #[serde(default)]
    pub printer: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Sections {
    pub system: bool,
    pub interfaces: bool,
    pub neighbors: bool,
    pub fdb: bool,
    pub resources: bool,
    pub printer: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceEvent {
    /// The reading of a section starts.
    Step {
        name: &'static str,
        done: usize,
        total: usize,
    },
}

// Areas of the checks and names of the sections (shown to the user).
fn a_sys() -> &'static str {
    t!("Sistema", "System")
}
fn a_if() -> &'static str {
    t!("Interfacce", "Interfaces")
}
fn a_nb() -> &'static str {
    t!("Vicini", "Neighbours")
}
fn a_fdb() -> &'static str {
    t!("MAC e ARP", "MAC and ARP")
}
fn a_agent() -> &'static str {
    t!("Agente", "Agent")
}
fn a_res() -> &'static str {
    resources::area()
}
fn a_prn() -> &'static str {
    printer::area()
}

// ───────────────────────── values read ─────────────────────────

/// Columns and branches read from the agent, by built-in name (`ifDescr`, `lldpRemTable`...).
#[derive(Debug, Default)]
pub struct Raw {
    cols: HashMap<&'static str, Vec<VarBind>>,
    /// Sections read only in part: (area, reason).
    pub notes: Vec<(&'static str, String)>,
    /// Columns truncated by the walk limits.
    pub truncated: Vec<&'static str>,
    pub values: usize,
}

impl Raw {
    pub fn put(&mut self, name: &'static str, vbs: Vec<VarBind>) {
        self.values += vbs.len();
        self.cols.insert(name, vbs);
    }

    pub(super) fn has(&self, name: &str) -> bool {
        self.cols.get(name).is_some_and(|v| !v.is_empty())
    }

    /// Values of a column with their index (the part of the OID after the name).
    pub(super) fn col<'a>(
        &'a self,
        name: &str,
    ) -> impl Iterator<Item = (&'a [u32], &'a Value)> + 'a {
        let len = mib::oid_of(name).len();
        self.cols
            .get(name)
            .into_iter()
            .flatten()
            .filter(move |v| v.oid.len() > len)
            .map(move |v| (&v.oid[len..], &v.value))
    }

    /// Column with a single-number index (interfaces, ports).
    pub(super) fn by_num<'a>(&'a self, name: &str) -> BTreeMap<u32, &'a Value> {
        self.col(name)
            .filter(|(i, _)| i.len() == 1)
            .map(|(i, v)| (i[0], v))
            .collect()
    }
}

pub(super) fn text(v: &Value) -> String {
    match v {
        Value::Str(b) => match mib::printable(b) {
            Some(s) => s.split_whitespace().collect::<Vec<_>>().join(" "),
            None => mib::hex(b),
        },
        Value::Oid(o) => mib::dotted(o),
        Value::Ip(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        _ => String::new(),
    }
}

pub(super) fn num(v: &Value) -> Option<u64> {
    match v {
        Value::Int(i) => u64::try_from(*i).ok(),
        Value::Counter32(n) | Value::Gauge32(n) | Value::TimeTicks(n) | Value::Counter64(n) => {
            Some(*n)
        }
        _ => None,
    }
}

fn bytes(v: &Value) -> &[u8] {
    match v {
        Value::Str(b) => b,
        _ => &[],
    }
}

fn mac_of(v: &Value) -> Option<String> {
    let b = bytes(v);
    (b.len() == 6 && b.iter().any(|x| *x != 0)).then(|| mib::mac(b))
}

fn mac_from_index(i: &[u32]) -> Option<String> {
    (i.len() == 6 && i.iter().all(|x| *x <= 255)).then(|| {
        i.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

fn ipv4_from_index(i: &[u32]) -> Option<String> {
    (i.len() == 4 && i.iter().all(|x| *x <= 255))
        .then(|| format!("{}.{}.{}.{}", i[0], i[1], i[2], i[3]))
}

// ───────────────────────── system ─────────────────────────

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Unit {
    pub name: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
}

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Addr {
    pub ip: String,
    pub mask: String,
    pub prefix: Option<u32>,
    pub if_name: String,
}

#[derive(Debug, Default, Serialize)]
pub struct System {
    pub name: String,
    pub descr: String,
    pub object_id: String,
    /// Seconds since the agent started (sysUpTime).
    pub uptime_s: Option<u64>,
    pub contact: String,
    pub location: String,
    pub services: Vec<&'static str>,
    /// Chassis from the ENTITY-MIB: more than one in a stack.
    pub units: Vec<Unit>,
    pub addresses: Vec<Addr>,
}

fn sys_scalar(raw: &Raw, n: u32) -> Option<&Value> {
    raw.col("system")
        .find(|(i, _)| *i == [n, 0])
        .map(|(_, v)| v)
}

/// sysUpTime in hundredths of a second.
fn uptime_ticks(raw: &Raw) -> Option<u64> {
    sys_scalar(raw, 3).and_then(num)
}

fn services(v: u64) -> Vec<&'static str> {
    [
        (1, t!("livello 1 (fisico)", "layer 1 (physical)")),
        (2, t!("livello 2 (switch)", "layer 2 (switch)")),
        (4, t!("livello 3 (router)", "layer 3 (router)")),
        (8, t!("livello 4 (host)", "layer 4 (host)")),
        (64, t!("livello 7 (applicazioni)", "layer 7 (applications)")),
    ]
    .into_iter()
    .filter(|(bit, _)| v & bit != 0)
    .map(|x| x.1)
    .collect()
}

/// Prefix length of a mask, if the one bits are contiguous.
fn prefix_len(mask: [u8; 4]) -> Option<u32> {
    let m = u32::from_be_bytes(mask);
    (m.leading_ones() + m.trailing_zeros() == 32).then(|| m.leading_ones())
}

/// Name of each interface: ifName, otherwise ifDescr.
pub fn if_names(raw: &Raw) -> BTreeMap<u32, String> {
    let mut out: BTreeMap<u32, String> = raw
        .by_num("ifDescr")
        .into_iter()
        .map(|(i, v)| (i, text(v)))
        .collect();
    for (i, v) in raw.by_num("ifName") {
        let n = text(v);
        if !n.is_empty() {
            out.insert(i, n);
        }
    }
    out
}

pub fn system(raw: &Raw, names: &BTreeMap<u32, String>) -> System {
    let s = |n| sys_scalar(raw, n).map(text).unwrap_or_default();
    let mut sys = System {
        descr: s(1),
        object_id: s(2),
        uptime_s: uptime_ticks(raw).map(|t| t / 100),
        contact: s(4),
        name: s(5),
        location: s(6),
        services: sys_scalar(raw, 7)
            .and_then(num)
            .map(services)
            .unwrap_or_default(),
        ..Default::default()
    };

    // chassis of the ENTITY-MIB (one per stack unit); without a chassis, the first
    // component that has a serial number
    let col = |n: &str| -> BTreeMap<u32, String> {
        raw.by_num(n)
            .into_iter()
            .map(|(i, v)| (i, text(v)))
            .collect()
    };
    let (model, serial, soft, pname) = (
        col("entPhysicalModelName"),
        col("entPhysicalSerialNum"),
        col("entPhysicalSoftwareRev"),
        col("entPhysicalName"),
    );
    let unit = |i: u32| Unit {
        name: pname.get(&i).cloned().unwrap_or_default(),
        model: model.get(&i).cloned().unwrap_or_default(),
        serial: serial.get(&i).cloned().unwrap_or_default(),
        firmware: soft.get(&i).cloned().unwrap_or_default(),
    };
    let described = |u: &Unit| !(u.model.is_empty() && u.serial.is_empty());
    sys.units = raw
        .by_num("entPhysicalClass")
        .into_iter()
        .filter(|(_, v)| num(v) == Some(3))
        .map(|(i, _)| unit(i))
        .filter(described)
        .take(8)
        .collect();
    if sys.units.is_empty() {
        sys.units = serial
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(i, _)| unit(*i))
            .take(1)
            .collect();
    }

    let masks: HashMap<&[u32], &Value> = raw.col("ipAdEntNetMask").collect();
    for (i, v) in raw.col("ipAdEntIfIndex") {
        let Some(ip) = ipv4_from_index(i) else {
            continue;
        };
        if i[0] == 127 {
            continue;
        }
        let mask = match masks.get(i) {
            Some(Value::Ip(m)) => Some(*m),
            _ => None,
        };
        let ifx = num(v).and_then(|n| u32::try_from(n).ok());
        sys.addresses.push(Addr {
            ip,
            mask: mask
                .map(|m| format!("{}.{}.{}.{}", m[0], m[1], m[2], m[3]))
                .unwrap_or_default(),
            prefix: mask.and_then(prefix_len),
            if_name: ifx.and_then(|n| names.get(&n).cloned()).unwrap_or_default(),
        });
    }
    sys
}

// ───────────────────────── interfaces ─────────────────────────

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Iface {
    pub index: u32,
    pub name: String,
    /// Description written by the administrator (ifAlias) or, if missing and different
    /// from the name, ifDescr.
    pub alias: String,
    pub kind: String,
    pub mtu: Option<u64>,
    pub speed_bps: Option<u64>,
    pub mac: String,
    /// "up" (linked), "down" (enabled but without link), "off" (disabled).
    pub state: &'static str,
    /// Seconds since the last state change.
    pub changed_s: Option<u64>,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Interfaces {
    pub list: Vec<Iface>,
    pub up: usize,
    pub total: usize,
    /// The agent exposes 64-bit counters (ifHCInOctets).
    pub hc: bool,
}

pub fn state(admin: Option<u64>, oper: Option<u64>) -> &'static str {
    match (admin, oper) {
        (Some(a), _) if a != 1 => "off",
        (_, Some(1)) => "up",
        _ => "down",
    }
}

pub fn interfaces(raw: &Raw, names: &BTreeMap<u32, String>) -> Interfaces {
    let c = |n: &str| raw.by_num(n);
    let (descr, alias, kind, mtu, speed, high) = (
        c("ifDescr"),
        c("ifAlias"),
        c("ifType"),
        c("ifMtu"),
        c("ifSpeed"),
        c("ifHighSpeed"),
    );
    let (phys, admin, oper, changed) = (
        c("ifPhysAddress"),
        c("ifAdminStatus"),
        c("ifOperStatus"),
        c("ifLastChange"),
    );
    let (ie, oe, id, od) = (
        c("ifInErrors"),
        c("ifOutErrors"),
        c("ifInDiscards"),
        c("ifOutDiscards"),
    );
    let up_ticks = uptime_ticks(raw);
    let n = |m: &BTreeMap<u32, &Value>, i: u32| m.get(&i).and_then(|v| num(v));
    let indexes: BTreeSet<u32> = names.keys().chain(oper.keys()).copied().collect();
    let list: Vec<Iface> = indexes
        .into_iter()
        .map(|i| {
            let name = names.get(&i).cloned().unwrap_or_else(|| format!("if {i}"));
            let d = descr.get(&i).map(|v| text(v)).unwrap_or_default();
            let a = alias.get(&i).map(|v| text(v)).unwrap_or_default();
            Iface {
                index: i,
                alias: if !a.is_empty() {
                    a
                } else if d != name {
                    d
                } else {
                    String::new()
                },
                name,
                kind: kind
                    .get(&i)
                    .map(|v| match v {
                        Value::Int(t) => mib::if_type(*t)
                            .map(str::to_string)
                            .unwrap_or_else(|| t.to_string()),
                        _ => String::new(),
                    })
                    .unwrap_or_default(),
                mtu: n(&mtu, i).filter(|m| *m > 0),
                // ifHighSpeed is in Mb/s and does not stop at 4 Gb/s like ifSpeed
                speed_bps: n(&high, i)
                    .filter(|s| *s > 0)
                    .map(|s| s * 1_000_000)
                    .or_else(|| n(&speed, i).filter(|s| *s > 0 && *s != u32::MAX as u64)),
                mac: phys.get(&i).and_then(|v| mac_of(v)).unwrap_or_default(),
                state: state(n(&admin, i), n(&oper, i)),
                changed_s: match (up_ticks, n(&changed, i)) {
                    (Some(up), Some(ch)) if ch <= up => Some((up - ch) / 100),
                    _ => None,
                },
                in_errors: n(&ie, i).unwrap_or(0),
                out_errors: n(&oe, i).unwrap_or(0),
                in_discards: n(&id, i).unwrap_or(0),
                out_discards: n(&od, i).unwrap_or(0),
            }
        })
        .collect();
    Interfaces {
        up: list.iter().filter(|i| i.state == "up").count(),
        total: list.len(),
        hc: raw.has("ifHCInOctets"),
        list,
    }
}

// ───────────────────────── LLDP neighbours ─────────────────────────

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Neighbor {
    /// Port of this device.
    pub local_port: String,
    pub name: String,
    /// Port of the neighbour and its description.
    pub port: String,
    pub port_descr: String,
    pub descr: String,
    pub caps: Vec<&'static str>,
    /// Advertised management address (IPv4 if present, otherwise IPv6).
    pub addr: String,
    pub chassis: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Neighbors {
    pub list: Vec<Neighbor>,
    /// The agent exposes the LLDP-MIB.
    pub supported: bool,
}

/// Advertised capabilities (LldpSystemCapabilitiesMap): bit 0 is the most significant.
fn capabilities(b: &[u8]) -> Vec<&'static str> {
    let Some(first) = b.first() else {
        return Vec::new();
    };
    [
        (0x20, "switch"),
        (0x08, "router"),
        (0x10, "access point"),
        (0x04, t!("telefono", "phone")),
        (0x40, t!("ripetitore", "repeater")),
        (0x02, t!("modem via cavo", "cable modem")),
        (0x01, "host"),
        (0x80, t!("altro", "other")),
    ]
    .into_iter()
    .filter(|(bit, _)| first & bit != 0)
    .map(|x| x.1)
    .collect()
}

/// LLDP identifier (chassis or port) according to its subtype.
fn lldp_id(mac_subtype: u64, addr_subtype: u64, subtype: Option<u64>, v: &Value) -> String {
    let b = bytes(v);
    match subtype {
        Some(s) if s == mac_subtype && b.len() == 6 => mib::mac(b),
        // network address: first byte = family (1 = IPv4)
        Some(s) if s == addr_subtype && b.len() == 5 && b[0] == 1 => {
            format!("{}.{}.{}.{}", b[1], b[2], b[3], b[4])
        }
        _ => text(v),
    }
}

/// Address from the lldpRemManAddrTable index: subtype (1 = IPv4, 2 = IPv6) and
/// octets, with or without the length in front.
fn man_addr(i: &[u32]) -> Option<(bool, String)> {
    let (&subtype, rest) = i.split_first()?;
    let octets = |n: usize| -> Option<Vec<u8>> {
        let r = if rest.len() == n + 1 && rest[0] as usize == n {
            &rest[1..]
        } else {
            rest
        };
        (r.len() == n)
            .then(|| r.iter().map(|x| u8::try_from(*x).ok()).collect())
            .flatten()
    };
    match subtype {
        1 => octets(4).map(|o| (true, format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))),
        2 => octets(16).map(|o| {
            let a: [u8; 16] = o.try_into().unwrap_or([0; 16]);
            (false, std::net::Ipv6Addr::from(a).to_string())
        }),
        _ => None,
    }
}

pub fn neighbors(raw: &Raw, names: &BTreeMap<u32, String>) -> Neighbors {
    // local ports: index [1, column, port]
    let mut loc: BTreeMap<u32, BTreeMap<u32, &Value>> = BTreeMap::new();
    for (i, v) in raw.col("lldpLocPortTable") {
        if let [1, c, port] = i {
            loc.entry(*port).or_default().insert(*c, v);
        }
    }
    let local_port = |port: u32| -> String {
        let l = loc.get(&port);
        let get = |c: u32| {
            l.and_then(|m| m.get(&c))
                .map(|v| text(v))
                .unwrap_or_default()
        };
        let subtype = l.and_then(|m| m.get(&2)).and_then(|v| num(v));
        let id = get(3);
        // subtype 5 = interface name: it is already what is read on the device
        if subtype == Some(5) && !id.is_empty() {
            return id;
        }
        if let Some(n) = names.get(&port).filter(|n| !n.is_empty()) {
            return n.clone();
        }
        [get(4), id]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_else(|| tf!("porta {port}", "port {port}"))
    };

    // neighbours: index [1, column, timeMark, local port, neighbour number]
    let mut rem: BTreeMap<(u32, u32), BTreeMap<u32, &Value>> = BTreeMap::new();
    for (i, v) in raw.col("lldpRemTable") {
        if let [1, c, _, port, idx] = i {
            rem.entry((*port, *idx)).or_default().insert(*c, v);
        }
    }
    // management addresses: index [1, column, timeMark, port, neighbour, subtype, address...]
    let mut addrs: BTreeMap<(u32, u32), (bool, String)> = BTreeMap::new();
    for (i, _) in raw.col("lldpRemManAddrTable") {
        if i.len() < 6 || i[0] != 1 {
            continue;
        }
        if let Some((v4, a)) = man_addr(&i[5..]) {
            let slot = addrs.entry((i[3], i[4])).or_insert((v4, a.clone()));
            if v4 && !slot.0 {
                *slot = (v4, a);
            }
        }
    }

    let list = rem
        .iter()
        .map(|(key, cols)| {
            let get = |c: u32| cols.get(&c).map(|v| text(v)).unwrap_or_default();
            let sub = |c: u32| cols.get(&c).and_then(|v| num(v));
            let chassis = cols
                .get(&5)
                .map(|v| lldp_id(4, 5, sub(4), v))
                .unwrap_or_default();
            let name = get(9);
            Neighbor {
                local_port: local_port(key.0),
                name: if name.is_empty() {
                    chassis.clone()
                } else {
                    name
                },
                port: cols
                    .get(&7)
                    .map(|v| lldp_id(3, 4, sub(6), v))
                    .unwrap_or_default(),
                port_descr: get(8),
                descr: get(10),
                caps: cols
                    .get(&12)
                    .map(|v| capabilities(bytes(v)))
                    .unwrap_or_default(),
                addr: addrs.get(key).map(|a| a.1.clone()).unwrap_or_default(),
                chassis,
            }
        })
        .collect();
    Neighbors {
        list,
        supported: raw.has("lldpLocPortTable") || raw.has("lldpRemTable"),
    }
}

// ───────────────────────── MAC and ARP table ─────────────────────────

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct FdbRow {
    pub mac: String,
    pub vendor: String,
    /// Locally administered MAC (random or virtual): it has no vendor.
    pub local: bool,
    /// IP addresses from the ARP table of the device.
    pub ip: Vec<String>,
    pub port: String,
    pub vlan: Option<u32>,
    /// "dinamico", "statico", "apparato", "altro" (machine codes, the UI labels them),
    /// or "arp" for the entries that are only in the ARP table.
    pub kind: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct Fdb {
    pub list: Vec<FdbRow>,
    pub macs: usize,
    pub ports: usize,
    pub with_ip: usize,
    /// Where the MAC table comes from: "qbridge", "bridge", or "" if there is only ARP.
    pub source: &'static str,
    pub arp: usize,
}

fn fdb_kind(status: Option<u64>) -> Option<&'static str> {
    Some(match status {
        Some(2) => return None, // entry no longer valid
        Some(3) | None => "dinamico",
        Some(4) => "apparato",
        Some(5) => "statico",
        _ => "altro",
    })
}

pub fn fdb(raw: &Raw, names: &BTreeMap<u32, String>, oui: Option<&OuiDb>) -> Fdb {
    // ARP table: index [interface, a, b, c, d]; in the new one [interface, 1, 4, a, b, c, d]
    let mut arp: Vec<(String, String, u32)> = Vec::new();
    for (i, v) in raw.col("ipNetToMediaPhysAddress") {
        if let (Some(mac), Some(ip)) = (mac_of(v), i.get(1..).and_then(ipv4_from_index)) {
            arp.push((mac, ip, i[0]));
        }
    }
    for (i, v) in raw.col("ipNetToPhysicalPhysAddress") {
        if i.len() == 7 && i[1] == 1 && i[2] == 4 {
            if let (Some(mac), Some(ip)) = (mac_of(v), ipv4_from_index(&i[3..])) {
                if !arp.iter().any(|a| a.0 == mac && a.1 == ip) {
                    arp.push((mac, ip, i[0]));
                }
            }
        }
    }
    let mut ips: HashMap<&str, Vec<String>> = HashMap::new();
    for (mac, ip, _) in &arp {
        ips.entry(mac.as_str()).or_default().push(ip.clone());
    }

    // switch port -> interface -> name
    let base = raw.by_num("dot1dBasePortIfIndex");
    let port_name = |port: u64| -> String {
        if port == 0 {
            return String::new(); // learned, but not on a port (the device itself)
        }
        let p = u32::try_from(port).unwrap_or(0);
        base.get(&p)
            .and_then(|v| num(v))
            .and_then(|i| names.get(&u32::try_from(i).ok()?))
            .cloned()
            .unwrap_or_else(|| tf!("porta {port}", "port {port}"))
    };
    let row = |mac: String, port: String, vlan: Option<u32>, kind: &'static str| FdbRow {
        vendor: oui
            .and_then(|db| db.lookup(&mac))
            .unwrap_or_default()
            .to_string(),
        local: u8::from_str_radix(&mac[..2], 16).is_ok_and(|b| b & 0x02 != 0),
        ip: ips.get(mac.as_str()).cloned().unwrap_or_default(),
        mac,
        port,
        vlan,
        kind,
    };

    let mut list = Vec::new();
    let source = if raw.has("dot1qTpFdbPort") {
        // index [forwarding table (normally the VLAN), six MAC octets]
        let status: HashMap<&[u32], &Value> = raw.col("dot1qTpFdbStatus").collect();
        for (i, v) in raw.col("dot1qTpFdbPort") {
            let (Some(mac), Some(port)) = (i.get(1..).and_then(mac_from_index), num(v)) else {
                continue;
            };
            if let Some(kind) = fdb_kind(status.get(i).and_then(|v| num(v))) {
                list.push(row(mac, port_name(port), Some(i[0]), kind));
            }
        }
        "qbridge"
    } else if raw.has("dot1dTpFdbPort") {
        let status: HashMap<&[u32], &Value> = raw.col("dot1dTpFdbStatus").collect();
        for (i, v) in raw.col("dot1dTpFdbPort") {
            let (Some(mac), Some(port)) = (mac_from_index(i), num(v)) else {
                continue;
            };
            if let Some(kind) = fdb_kind(status.get(i).and_then(|v| num(v))) {
                list.push(row(mac, port_name(port), None, kind));
            }
        }
        "bridge"
    } else {
        ""
    };
    let ports: BTreeSet<&str> = list
        .iter()
        .map(|r| r.port.as_str())
        .filter(|p| !p.is_empty())
        .collect();
    let ports = ports.len();

    // ARP entries of addresses that the MAC table does not know (or all of them, on a router)
    let known: BTreeSet<String> = list.iter().map(|r| r.mac.clone()).collect();
    let mut seen = BTreeSet::new();
    for (mac, _, ifx) in &arp {
        if known.contains(mac) || !seen.insert(mac.clone()) {
            continue;
        }
        let port = names
            .get(ifx)
            .cloned()
            .unwrap_or_else(|| format!("if {ifx}"));
        list.push(row(mac.clone(), port, None, "arp"));
    }
    let macs: BTreeSet<&str> = list.iter().map(|r| r.mac.as_str()).collect();
    Fdb {
        macs: macs.len(),
        ports,
        with_ip: list.iter().filter(|r| !r.ip.is_empty()).count(),
        source,
        arp: arp.len(),
        list,
    }
}

// ───────────────────────── checks ─────────────────────────

fn many(n: usize, one: &str, more: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { more })
}

/// Duration in words: "41 giorni", "3 ore", "12 minuti" (or "41 days", "3 hours", ...).
pub fn ago(secs: u64) -> String {
    match secs {
        s if s >= 172_800 => tf!("{} giorni", "{} days", s / 86_400),
        s if s >= 86_400 => t!("1 giorno", "1 day").into(),
        s if s >= 7200 => tf!("{} ore", "{} hours", s / 3600),
        s if s >= 3600 => t!("1 ora", "1 hour").into(),
        s if s >= 120 => tf!("{} minuti", "{} minutes", s / 60),
        _ => t!("meno di 2 minuti", "less than 2 minutes").into(),
    }
}

/// Checks on the data read. Those on the security of the reading come from
/// `security_checks` and come first.
pub fn checks(
    raw: &Raw,
    sections: Sections,
    sys: &System,
    ifs: Option<&Interfaces>,
    nb: Option<&Neighbors>,
    fdb: Option<&Fdb>,
) -> Vec<Check> {
    let mut out = Vec::new();
    for (area, why) in &raw.notes {
        out.push(check(
            area,
            WARN,
            t!("Lettura incompleta", "Incomplete reading"),
            tf!(
                "{why}. I dati di questa sezione possono mancare in parte.",
                "{why}. The data of this section may be partly missing."
            ),
        ));
    }
    if !raw.truncated.is_empty() {
        out.push(check(
            a_agent(),
            WARN,
            t!("Tabelle troncate", "Truncated tables"),
            tf!(
                "Lettura fermata a {} valori per: {}.",
                "Reading stopped at {} values for: {}.",
                super::WALK_MAX,
                raw.truncated.join(", ")
            ),
        ));
    }

    if let Some(up) = sys.uptime_s {
        if up < 86_400 {
            out.push(check(
                a_sys(),
                INFO,
                t!("Avvio recente", "Recent start"),
                tf!(
                    "L'agente è partito da {}: riavvio o aggiornamento recente.",
                    "The agent started {} ago: recent restart or update.",
                    ago(up)
                ),
            ));
        }
    }
    if sections.system {
        let missing: Vec<&str> = [("sysContact", &sys.contact), ("sysLocation", &sys.location)]
            .into_iter()
            .filter(|(_, v)| v.is_empty())
            .map(|x| x.0)
            .collect();
        if !missing.is_empty() {
            let verb = if missing.len() == 1 {
                t!("è compilato", "is not filled in")
            } else {
                t!("sono compilati", "are not filled in")
            };
            out.push(check(
                a_sys(),
                INFO,
                t!("Contatto e posizione", "Contact and location"),
                tf!(
                    "{} non {}: in un inventario l'apparato resta senza riferimenti.",
                    "{} {}: in an inventory the device is left without references.",
                    missing.join(t!(" e ", " and ")),
                    verb
                ),
            ));
        }
    }

    if let Some(ifs) = ifs {
        if ifs.list.is_empty() {
            out.push(check(
                a_if(),
                INFO,
                t!("Nessuna interfaccia", "No interfaces"),
                t!(
                    "L'agente non espone la tabella delle interfacce (IF-MIB).",
                    "The agent does not expose the interface table (IF-MIB)."
                ),
            ));
        } else {
            let mut bad: Vec<&Iface> = ifs
                .list
                .iter()
                .filter(|i| i.in_errors + i.out_errors > 0)
                .collect();
            bad.sort_by_key(|i| std::cmp::Reverse(i.in_errors + i.out_errors));
            if bad.is_empty() {
                out.push(check(
                    a_if(),
                    OK,
                    t!("Nessun errore", "No errors"),
                    tf!(
                        "Contatori degli errori a zero su {}.",
                        "Error counters at zero on {}.",
                        many(
                            ifs.total,
                            t!("interfaccia", "interface"),
                            t!("interfacce", "interfaces")
                        )
                    ),
                ));
            } else {
                let worst: Vec<String> = bad
                    .iter()
                    .take(4)
                    .map(|i| {
                        tf!(
                            "{}{}: {} errori",
                            "{}{}: {} errors",
                            i.name,
                            if i.alias.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", i.alias)
                            },
                            i.in_errors + i.out_errors
                        )
                    })
                    .collect();
                out.push(check(
                    a_if(),
                    WARN,
                    t!("Errori sulle porte", "Port errors"),
                    tf!(
                        "{} dall'avvio{}. Cavo, connettore o duplex da controllare; \
                         i contatori dal vivo dicono se stanno ancora crescendo.",
                        "{} since start-up{}. Cable, connector or duplex to check; \
                         the live counters tell whether they are still growing.",
                        worst.join(", "),
                        if bad.len() > 4 {
                            tf!(" e altre {}", " and {} more", bad.len() - 4)
                        } else {
                            String::new()
                        }
                    ),
                ));
            }
            let idle = ifs.list.iter().filter(|i| i.state == "down").count();
            if idle > 0 {
                out.push(check(
                    a_if(),
                    INFO,
                    t!("Porte senza collegamento", "Ports without link"),
                    tf!(
                        "{} ma senza collegamento.",
                        "{} but without link.",
                        many(
                            idle,
                            t!("porta attiva", "enabled port"),
                            t!("porte attive", "enabled ports")
                        )
                    ),
                ));
            }
            out.push(if ifs.hc {
                check(
                    a_if(),
                    OK,
                    t!("Contatori a 64 bit", "64-bit counters"),
                    t!(
                        "L'agente espone ifHCInOctets: le velocità dal vivo sono affidabili anche \
                         sulle porte da 10 Gb/s.",
                        "The agent exposes ifHCInOctets: live speeds are reliable even \
                         on 10 Gb/s ports."
                    ),
                )
            } else {
                check(
                    a_if(),
                    INFO,
                    t!("Solo contatori a 32 bit", "Only 32-bit counters"),
                    t!(
                        "Senza ifHCInOctets il contatore dei byte ricomincia da zero ogni 34 secondi \
                         a 1 Gb/s: sopra qualche centinaio di Mb/s le velocità dal vivo possono \
                         risultare più basse del vero.",
                        "Without ifHCInOctets the byte counter wraps to zero every 34 seconds \
                         at 1 Gb/s: above a few hundred Mb/s the live speeds may \
                         come out lower than the real ones."
                    ),
                )
            });
        }
    }

    if let Some(nb) = nb {
        if !nb.supported {
            out.push(check(
                a_nb(),
                INFO,
                t!("LLDP non disponibile", "LLDP not available"),
                t!(
                    "L'agente non espone la LLDP-MIB: LLDP è spento oppure l'apparato usa solo un \
                     protocollo di scoperta proprietario.",
                    "The agent does not expose the LLDP-MIB: LLDP is off or the device only uses \
                     a proprietary discovery protocol."
                ),
            ));
        } else if nb.list.is_empty() {
            out.push(check(
                a_nb(),
                INFO,
                t!("Nessun vicino", "No neighbours"),
                t!(
                    "LLDP è attivo ma nessun vicino si annuncia sulle porte.",
                    "LLDP is active but no neighbour advertises itself on the ports."
                ),
            ));
        } else {
            out.push(check(
                a_nb(),
                OK,
                t!("Vicini LLDP", "LLDP neighbours"),
                format!(
                    "{}.",
                    many(
                        nb.list.len(),
                        t!("vicino annunciato", "neighbour advertised"),
                        t!("vicini annunciati", "neighbours advertised")
                    )
                ),
            ));
            let silent = nb.list.iter().filter(|n| n.addr.is_empty()).count();
            if silent > 0 {
                let verb = if silent == 1 {
                    t!("annuncia", "does not advertise")
                } else {
                    t!("annunciano", "do not advertise")
                };
                out.push(check(
                    a_nb(),
                    INFO,
                    t!(
                        "Vicini senza indirizzo di gestione",
                        "Neighbours without management address"
                    ),
                    tf!(
                        "{} su {} non {} un indirizzo IP con LLDP.",
                        "{} of {} {} an IP address through LLDP.",
                        silent,
                        nb.list.len(),
                        verb
                    ),
                ));
            }
        }
    }

    if let Some(f) = fdb {
        if f.list.is_empty() {
            out.push(check(
                a_fdb(),
                INFO,
                t!("Nessuna tabella", "No table"),
                t!(
                    "L'agente non espone né la tabella MAC (BRIDGE-MIB, Q-BRIDGE-MIB) né la tabella \
                     ARP, oppure la vista dell'utente non le comprende.",
                    "The agent exposes neither the MAC table (BRIDGE-MIB, Q-BRIDGE-MIB) nor the \
                     ARP table, or the user's view does not include them."
                ),
            ));
        } else if f.source.is_empty() {
            out.push(check(
                a_fdb(),
                INFO,
                t!("Solo tabella ARP", "ARP table only"),
                t!(
                    "L'apparato non espone una tabella MAC (non è uno switch): si vedono gli \
                     indirizzi della sua tabella ARP, con l'interfaccia al posto della porta.",
                    "The device does not expose a MAC table (it is not a switch): the addresses \
                     of its ARP table are shown, with the interface in place of the port."
                ),
            ));
        }
    }
    out
}

// ───────────────────────── reading ─────────────────────────

#[derive(Debug, Serialize)]
pub struct DeviceResult {
    pub host: String,
    pub ip: String,
    /// sysName, or the requested host.
    pub name: String,
    pub elapsed_ms: u64,
    pub values: usize,
    pub stopped: bool,
    pub sections: Sections,
    pub checks: Vec<Check>,
    pub system: System,
    pub interfaces: Option<Interfaces>,
    pub neighbors: Option<Neighbors>,
    pub fdb: Option<Fdb>,
    pub resources: Option<Resources>,
    pub printer: Option<Printer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
}

/// The views built from the values read, with their checks.
pub struct Views {
    pub system: System,
    pub interfaces: Option<Interfaces>,
    pub neighbors: Option<Neighbors>,
    pub fdb: Option<Fdb>,
    pub resources: Option<Resources>,
    pub printer: Option<Printer>,
    pub checks: Vec<Check>,
}

pub fn build(raw: &Raw, sections: Sections, oui: Option<&OuiDb>) -> Views {
    let names = if_names(raw);
    let system = system(raw, &names);
    let interfaces = sections.interfaces.then(|| interfaces(raw, &names));
    let neighbors = sections.neighbors.then(|| neighbors(raw, &names));
    let fdb = sections.fdb.then(|| fdb(raw, &names, oui));
    // the two newer views exist only if the device has the data
    let resources =
        (sections.resources && resources::present(raw)).then(|| resources::resources(raw));
    let printer = (sections.printer && printer::present(raw)).then(|| printer::printer(raw));
    let mut checks = checks(
        raw,
        sections,
        &system,
        interfaces.as_ref(),
        neighbors.as_ref(),
        fdb.as_ref(),
    );
    checks.extend(resources.iter().flat_map(resources::checks));
    checks.extend(printer.iter().flat_map(printer::checks));
    Views {
        system,
        interfaces,
        neighbors,
        fdb,
        resources,
        printer,
        checks,
    }
}

/// Columns to read for each section, in order.
fn plan(sections: Sections) -> Vec<(&'static str, Vec<&'static str>)> {
    let mut p = Vec::new();
    let mut sys = vec!["system"];
    if sections.interfaces || sections.neighbors || sections.fdb || sections.system {
        sys.extend(["ifName", "ifDescr"]);
    }
    if sections.system {
        sys.extend([
            "ipAdEntIfIndex",
            "ipAdEntNetMask",
            "entPhysicalClass",
            "entPhysicalName",
            "entPhysicalModelName",
            "entPhysicalSerialNum",
            "entPhysicalSoftwareRev",
        ]);
    }
    p.push((a_sys(), sys));
    if sections.interfaces {
        p.push((
            a_if(),
            vec![
                "ifAlias",
                "ifType",
                "ifMtu",
                "ifSpeed",
                "ifHighSpeed",
                "ifPhysAddress",
                "ifAdminStatus",
                "ifOperStatus",
                "ifLastChange",
                "ifInErrors",
                "ifOutErrors",
                "ifInDiscards",
                "ifOutDiscards",
                "ifHCInOctets",
            ],
        ));
    }
    if sections.neighbors {
        p.push((
            a_nb(),
            vec!["lldpLocPortTable", "lldpRemTable", "lldpRemManAddrTable"],
        ));
    }
    if sections.fdb {
        p.push((
            a_fdb(),
            vec![
                "dot1dBasePortIfIndex",
                "dot1qTpFdbPort",
                "dot1qTpFdbStatus",
                "dot1dTpFdbPort",
                "dot1dTpFdbStatus",
                "ipNetToMediaPhysAddress",
                "ipNetToPhysicalPhysAddress",
            ],
        ));
    }
    if sections.resources {
        p.push((
            a_res(),
            vec![
                "hrSystem",
                "hrMemorySize",
                "hrStorageSize",
                "hrStorageType",
                "hrStorageDescr",
                "hrStorageAllocationUnits",
                "hrStorageUsed",
                "hrProcessorLoad",
                "hrDeviceDescr",
                "hrSWRunName",
                "hrSWRunPerfMem",
                "hrSWRunPerfCPU",
            ],
        ));
    }
    if sections.printer {
        p.push((
            a_prn(),
            vec![
                "hrPrinterStatus",
                "hrPrinterDetectedErrorState",
                "hrDeviceDescr",
                "prtGeneralSerialNumber",
                "prtMarkerLifeCount",
                "prtMarkerCounterUnit",
                "prtMarkerSuppliesDescription",
                "prtMarkerSuppliesClass",
                "prtMarkerSuppliesType",
                "prtMarkerSuppliesSupplyUnit",
                "prtMarkerSuppliesMaxCapacity",
                "prtMarkerSuppliesLevel",
                "prtMarkerSuppliesColorantIndex",
                "prtMarkerColorantValue",
                "prtInputMaxCapacity",
                "prtInputCurrentLevel",
                "prtInputCapacityUnit",
                "prtInputName",
                "prtInputMediaName",
                "prtAlertDescription",
                "prtAlertSeverityLevel",
                "prtAlertGroup",
                "prtAlertCode",
            ],
        ));
    }
    p
}

/// Columns that are skipped when another one has already given the data.
fn skip(raw: &Raw, name: &str) -> bool {
    match name {
        // the MAC table without VLAN is only needed if the per-VLAN one is missing
        "dot1dTpFdbPort" | "dot1dTpFdbStatus" => raw.has("dot1qTpFdbPort"),
        "dot1qTpFdbStatus" => !raw.has("dot1qTpFdbPort"),
        // the new neighbour table is only needed if the classic ARP one is empty
        "ipNetToPhysicalPhysAddress" => raw.has("ipNetToMediaPhysAddress"),
        // without chassis or components there is nothing else to ask the ENTITY-MIB
        "entPhysicalName"
        | "entPhysicalModelName"
        | "entPhysicalSerialNum"
        | "entPhysicalSoftwareRev" => !raw.has("entPhysicalClass"),
        // volumes: the other columns are only needed if there is a size
        "hrStorageType" | "hrStorageDescr" | "hrStorageAllocationUnits" | "hrStorageUsed" => {
            !raw.has("hrStorageSize")
        }
        // device names are needed by processors and the printer, read only once
        "hrDeviceDescr" => {
            raw.has("hrDeviceDescr") || !(raw.has("hrProcessorLoad") || raw.has("hrPrinterStatus"))
        }
        "hrSWRunPerfMem" | "hrSWRunPerfCPU" => !raw.has("hrSWRunName"),
        // printer: the columns of a table are only asked for if the table has rows
        "prtMarkerCounterUnit" => !raw.has("prtMarkerLifeCount"),
        "prtMarkerSuppliesClass"
        | "prtMarkerSuppliesType"
        | "prtMarkerSuppliesSupplyUnit"
        | "prtMarkerSuppliesMaxCapacity"
        | "prtMarkerSuppliesLevel"
        | "prtMarkerSuppliesColorantIndex" => !raw.has("prtMarkerSuppliesDescription"),
        "prtMarkerColorantValue" => !raw.has("prtMarkerSuppliesColorantIndex"),
        "prtInputCurrentLevel" | "prtInputCapacityUnit" | "prtInputName" | "prtInputMediaName" => {
            !raw.has("prtInputMaxCapacity")
        }
        "prtAlertSeverityLevel" | "prtAlertGroup" | "prtAlertCode" => {
            !raw.has("prtAlertDescription")
        }
        _ => false,
    }
}

/// Reads the columns of the plan from the agent. The first branch (system) must answer:
/// if it does not, the error is the session's; afterwards, a section that fails
/// becomes a note and the reading goes on (but stops at the first timeout).
pub(crate) async fn collect<F: FnMut(DeviceEvent)>(
    s: &mut Session,
    sections: Sections,
    stop: &Stop,
    mut emit: F,
) -> Result<(Raw, bool)> {
    let mut raw = Raw::default();
    let plan = plan(sections);
    let total = plan.len();
    let mut dead = false;
    for (done, (area, cols)) in plan.into_iter().enumerate() {
        emit(DeviceEvent::Step {
            name: area,
            done,
            total,
        });
        for name in cols {
            if dead || skip(&raw, name) {
                continue;
            }
            match walk(s, &mib::oid_of(name), stop).await {
                Ok(w) => {
                    if w.truncated {
                        raw.truncated.push(name);
                    }
                    raw.put(name, w.vbs);
                    if w.stopped {
                        return Ok((raw, true));
                    }
                }
                Err(e) if name == "system" => return Err(e),
                Err(e) => {
                    dead = e == "TIMEOUT";
                    if !raw.notes.iter().any(|n| n.0 == area) {
                        raw.notes.push((
                            area,
                            if dead {
                                t!(
                                    "L'agente ha smesso di rispondere",
                                    "The agent stopped answering"
                                )
                                .to_string()
                            } else {
                                e
                            },
                        ));
                    }
                }
            }
        }
    }
    Ok((raw, false))
}

pub async fn run<F: FnMut(DeviceEvent)>(
    req: DeviceReq,
    oui: Option<std::sync::Arc<OuiDb>>,
    stop: &Stop,
    emit: F,
) -> Result<DeviceResult> {
    let sections = Sections {
        system: req.system.unwrap_or(true),
        interfaces: req.interfaces.unwrap_or(true),
        neighbors: req.neighbors.unwrap_or(true),
        fdb: req.fdb.unwrap_or(true),
        resources: req.resources.unwrap_or(true),
        printer: req.printer.unwrap_or(true),
    };
    let started = Instant::now();
    let mut c = connect(&req.snmp).await?;
    let (raw, stopped) = match collect(&mut c.s, sections, stop, emit).await {
        Ok(r) => r,
        Err(e) => return Err(c.explain(e)),
    };
    let Views {
        system,
        interfaces,
        neighbors,
        fdb,
        resources,
        printer,
        checks: found,
    } = build(&raw, sections, oui.as_deref());
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let secs = format!("{:.1}", elapsed_ms as f64 / 1000.0);
    let secs = if crate::i18n::is_en() {
        secs
    } else {
        secs.replace('.', ",")
    };
    let mut checks = std::mem::take(&mut c.checks);
    checks.extend(found);
    checks.push(check(
        a_agent(),
        OK,
        t!("Risposta", "Response"),
        tf!(
            "{} in {secs} s{}.",
            "{} in {secs} s{}.",
            many(
                raw.values,
                t!("valore letto", "value read"),
                t!("valori letti", "values read")
            ),
            if stopped {
                t!(", lettura fermata", ", reading stopped")
            } else {
                ""
            }
        ),
    ));
    Ok(DeviceResult {
        name: if system.name.is_empty() {
            c.host.clone()
        } else {
            system.name.clone()
        },
        host: c.host.clone(),
        ip: c.ip.to_string(),
        elapsed_ms,
        values: raw.values,
        stopped,
        sections,
        checks,
        system,
        interfaces,
        neighbors,
        fdb,
        resources,
        printer,
        engine_id: c.s.engine_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::ber;
    use super::super::fake::{self, at, counter32, counter64, gauge, ip, text as t, ticks};
    use super::*;

    const ALL: Sections = Sections {
        system: true,
        interfaces: true,
        neighbors: true,
        fdb: true,
        resources: true,
        printer: true,
    };

    /// Fake switch: 4 ports + a VLAN, two LLDP neighbours, per-VLAN MAC table and ARP.
    fn switch() -> fake::Mib {
        let mut m = fake::Mib::new();
        let mut put = |name: &str, index: &[u32], v: Vec<u8>| {
            m.insert(at(name, index), v);
        };
        put("sysDescr", &[0], t("Switch L3 di prova, firmware 4.2.1"));
        put(
            "sysObjectID",
            &[0],
            ber::oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 3]),
        );
        put("sysUpTime", &[0], ticks(41 * 8_640_000 + 360_000));
        put("sysContact", &[0], t(""));
        put("sysName", &[0], t("sw-core01.corp.example"));
        put("sysLocation", &[0], t("Sala server"));
        put("sysServices", &[0], ber::int(6));
        // interfaces: 1 and 2 linked, 3 without link, 4 disabled, 10 = VLAN
        for (i, name, alias, admin, oper, mbit) in [
            (1u32, "1/1", "uplink sw-dist01", 1, 1, 10_000u64),
            (2, "1/2", "", 1, 1, 1000),
            (3, "1/3", "", 1, 2, 0),
            (4, "1/4", "porta libera", 2, 2, 0),
            (10, "vlan10", "utenti", 1, 1, 0),
        ] {
            put("ifDescr", &[i], t(&format!("Interfaccia {name}")));
            put("ifName", &[i], t(name));
            put("ifAlias", &[i], t(alias));
            put("ifType", &[i], ber::int(if i == 10 { 136 } else { 6 }));
            put("ifMtu", &[i], ber::int(1500));
            put(
                "ifSpeed",
                &[i],
                gauge((mbit * 1_000_000).min(u32::MAX as u64)),
            );
            put("ifHighSpeed", &[i], gauge(mbit));
            put(
                "ifPhysAddress",
                &[i],
                ber::octets(&[2, 0, 0x5e, 0, 0, i as u8]),
            );
            put("ifAdminStatus", &[i], ber::int(admin));
            put("ifOperStatus", &[i], ber::int(oper));
            put("ifLastChange", &[i], ticks(360_000));
            put("ifInErrors", &[i], counter32(if i == 2 { 1204 } else { 0 }));
            put("ifOutErrors", &[i], counter32(0));
            put("ifInDiscards", &[i], counter32(if i == 2 { 37 } else { 0 }));
            put("ifOutDiscards", &[i], counter32(0));
            put("ifHCInOctets", &[i], counter64(1_000_000 * i as u64));
            put("ifHCOutOctets", &[i], counter64(2_000_000 * i as u64));
        }
        put("ipAdEntIfIndex", &[172, 16, 10, 1], ber::int(10));
        put("ipAdEntNetMask", &[172, 16, 10, 1], ip([255, 255, 254, 0]));
        put("ipAdEntIfIndex", &[127, 0, 0, 1], ber::int(99));
        put("ipAdEntNetMask", &[127, 0, 0, 1], ip([255, 0, 0, 0]));
        // ENTITY-MIB: one chassis (1) and one module (2)
        put("entPhysicalClass", &[1], ber::int(3));
        put("entPhysicalClass", &[2], ber::int(9));
        put("entPhysicalName", &[1], t("Unità 1"));
        put("entPhysicalModelName", &[1], t("SW-2426X"));
        put("entPhysicalSerialNum", &[1], t("EX4K2026A0117"));
        put("entPhysicalSerialNum", &[2], t("MOD0001"));
        put("entPhysicalSoftwareRev", &[1], t("4.2.1"));
        // LLDP: local port 1 (interface name) and 2 (local identifier)
        put("lldpLocPortTable", &[1, 2, 1], ber::int(5));
        put("lldpLocPortTable", &[1, 3, 1], t("1/1"));
        put("lldpLocPortTable", &[1, 2, 2], ber::int(7));
        put("lldpLocPortTable", &[1, 3, 2], t("2"));
        let mut rem =
            |port: u32, col: u32, v: Vec<u8>| put("lldpRemTable", &[1, col, 0, port, 1], v);
        rem(1, 4, ber::int(4));
        rem(1, 5, ber::octets(&[2, 0, 0x5e, 0x10, 0, 1]));
        rem(1, 6, ber::int(5));
        rem(1, 7, t("2/1"));
        rem(1, 8, t("uplink core"));
        rem(1, 9, t("sw-dist01.corp.example"));
        rem(1, 10, t("Switch L3 48 porte"));
        rem(1, 12, ber::octets(&[0x28, 0]));
        rem(2, 4, ber::int(4));
        rem(2, 5, ber::octets(&[2, 0, 0x5e, 0x30, 1, 0x17]));
        rem(2, 6, ber::int(3));
        rem(2, 7, ber::octets(&[2, 0, 0x5e, 0x30, 1, 0x17]));
        rem(2, 12, ber::octets(&[0x04, 0]));
        // management address of the first neighbour: IPv4 with the length in front
        put(
            "lldpRemManAddrTable",
            &[1, 3, 0, 1, 1, 1, 4, 172, 16, 0, 2],
            ber::int(2),
        );
        // switch ports 1 and 2 = interfaces 1 and 2
        put("dot1dBasePortIfIndex", &[1], ber::int(1));
        put("dot1dBasePortIfIndex", &[2], ber::int(2));
        let mut mac = |vlan: u32, last: u32, port: i64, status: i64| {
            put(
                "dot1qTpFdbPort",
                &[vlan, 0, 0x50, 0x56, 1, 2, last],
                ber::int(port),
            );
            put(
                "dot1qTpFdbStatus",
                &[vlan, 0, 0x50, 0x56, 1, 2, last],
                ber::int(status),
            );
        };
        mac(10, 3, 2, 3);
        mac(10, 4, 2, 5);
        mac(20, 5, 1, 3);
        mac(20, 6, 0, 4);
        mac(20, 7, 2, 2); // invalid entry: it does not appear
                          // ARP: .3 and .5 known to the MAC table, 02:... seen only by ARP on VLAN 10
        put(
            "ipNetToMediaPhysAddress",
            &[10, 172, 16, 10, 60],
            ber::octets(&[0, 0x50, 0x56, 1, 2, 3]),
        );
        put(
            "ipNetToMediaPhysAddress",
            &[10, 172, 16, 10, 61],
            ber::octets(&[0, 0x50, 0x56, 1, 2, 3]),
        );
        put(
            "ipNetToMediaPhysAddress",
            &[10, 172, 16, 10, 99],
            ber::octets(&[2, 0, 0x5e, 0x40, 0, 0x14]),
        );
        m
    }

    fn req(a: &fake::Agent, ver: &str) -> DeviceReq {
        DeviceReq {
            snmp: SnmpReq {
                host: "127.0.0.1".into(),
                version: Some(ver.into()),
                community: Some("prova-lettura".into()),
                port: Some(a.addr.port() as u32),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn names(c: &[Check]) -> Vec<(&'static str, &str)> {
        c.iter().map(|c| (c.status, c.name.as_str())).collect()
    }

    /// Full reading against the fake agent, with v2c (GETBULK) and v1 (GETNEXT).
    #[tokio::test]
    async fn apparato_intero() {
        let a = fake::agent(switch(), "prova-lettura").await;
        let oui = OuiDb::parse("005056\tProduttore di prova\n").unwrap();
        for ver in ["2c", "1"] {
            let mut steps = Vec::new();
            let d = run(
                req(&a, ver),
                Some(std::sync::Arc::new(
                    OuiDb::parse("005056\tProduttore di prova\n").unwrap(),
                )),
                &Stop::new(),
                |e| {
                    let DeviceEvent::Step { name, done, total } = e;
                    steps.push((name, done, total));
                },
            )
            .await
            .unwrap();
            assert_eq!(
                steps,
                vec![
                    ("Sistema", 0, 6),
                    ("Interfacce", 1, 6),
                    ("Vicini", 2, 6),
                    ("MAC e ARP", 3, 6),
                    ("Risorse", 4, 6),
                    ("Stampante", 5, 6)
                ]
            );
            // a switch without HOST-RESOURCES-MIB or Printer-MIB: the two views do not exist
            assert!(d.resources.is_none() && d.printer.is_none());
            assert!(d
                .checks
                .iter()
                .all(|c| c.area != "Risorse" && c.area != "Stampante"));
            assert_eq!(d.name, "sw-core01.corp.example");
            assert_eq!(d.ip, "127.0.0.1");
            assert!(!d.stopped && d.values > 100, "{}", d.values);

            // system
            let s = &d.system;
            assert_eq!(s.descr, "Switch L3 di prova, firmware 4.2.1");
            assert_eq!(s.object_id, "1.3.6.1.4.1.99999.1.3");
            assert_eq!(s.uptime_s, Some(41 * 86_400 + 3600));
            assert_eq!(s.location, "Sala server");
            assert_eq!(s.services, ["livello 2 (switch)", "livello 3 (router)"]);
            assert_eq!(
                s.units,
                vec![Unit {
                    name: "Unità 1".into(),
                    model: "SW-2426X".into(),
                    serial: "EX4K2026A0117".into(),
                    firmware: "4.2.1".into()
                }]
            );
            assert_eq!(
                s.addresses,
                vec![Addr {
                    ip: "172.16.10.1".into(),
                    mask: "255.255.254.0".into(),
                    prefix: Some(23),
                    if_name: "vlan10".into()
                }]
            );

            // interfaces
            let i = d.interfaces.as_ref().unwrap();
            assert_eq!((i.up, i.total, i.hc), (3, 5, ver == "2c"), "v{ver}");
            let l = &i.list;
            assert_eq!(
                l.iter()
                    .map(|x| (x.name.as_str(), x.state))
                    .collect::<Vec<_>>(),
                [
                    ("1/1", "up"),
                    ("1/2", "up"),
                    ("1/3", "down"),
                    ("1/4", "off"),
                    ("vlan10", "up")
                ]
            );
            assert_eq!(l[0].alias, "uplink sw-dist01");
            assert_eq!(l[1].alias, "Interfaccia 1/2"); // without alias: the description
            assert_eq!(l[0].speed_bps, Some(10_000_000_000)); // from ifHighSpeed
            assert_eq!(l[1].speed_bps, Some(1_000_000_000));
            assert_eq!(l[2].speed_bps, None);
            assert_eq!(l[0].mac, "02:00:5e:00:00:01");
            assert_eq!(l[4].kind, "l3ipvlan");
            assert_eq!(l[0].mtu, Some(1500));
            assert_eq!(l[0].changed_s, Some(41 * 86_400));
            assert_eq!((l[1].in_errors, l[1].in_discards), (1204, 37));

            // neighbours
            let n = &d.neighbors.as_ref().unwrap().list;
            assert_eq!(n.len(), 2);
            assert_eq!(
                n[0],
                Neighbor {
                    local_port: "1/1".into(),
                    name: "sw-dist01.corp.example".into(),
                    port: "2/1".into(),
                    port_descr: "uplink core".into(),
                    descr: "Switch L3 48 porte".into(),
                    caps: vec!["switch", "router"],
                    addr: "172.16.0.2".into(),
                    chassis: "02:00:5e:10:00:01".into(),
                }
            );
            // without name: the chassis is used; local port from the interface name
            assert_eq!(n[1].name, "02:00:5e:30:01:17");
            assert_eq!(n[1].local_port, "1/2");
            assert_eq!(n[1].port, "02:00:5e:30:01:17");
            assert_eq!(n[1].caps, ["telefono"]);
            assert_eq!(n[1].addr, "");

            // MAC and ARP table
            let f = d.fdb.as_ref().unwrap();
            assert_eq!(f.source, "qbridge");
            assert_eq!((f.macs, f.ports, f.with_ip, f.arp), (5, 2, 2, 3));
            let row = |mac: &str| f.list.iter().find(|r| r.mac == mac).unwrap();
            let r = row("00:50:56:01:02:03");
            assert_eq!(r.vendor, "Produttore di prova");
            assert_eq!(r.ip, ["172.16.10.60", "172.16.10.61"]);
            assert_eq!(
                (r.port.as_str(), r.vlan, r.kind, r.local),
                ("1/2", Some(10), "dinamico", false)
            );
            assert_eq!(row("00:50:56:01:02:04").kind, "statico");
            assert_eq!(row("00:50:56:01:02:05").port, "1/1");
            let own = row("00:50:56:01:02:06");
            assert_eq!((own.port.as_str(), own.kind), ("", "apparato"));
            assert!(f.list.iter().all(|r| r.mac != "00:50:56:01:02:07"));
            let arp = row("02:00:5e:40:00:14");
            assert_eq!(
                (arp.port.as_str(), arp.kind, arp.local),
                ("vlan10", "arp", true)
            );
            assert_eq!(arp.vendor, "");
            assert_eq!(oui.lookup(&arp.mac), None);

            // checks: security first, then the data, the agent's response last
            let c = names(&d.checks);
            assert_eq!(c[0], (WARN, "Protocollo in chiaro"));
            assert!(c.contains(&(INFO, "Contatto e posizione")));
            assert!(c.contains(&(WARN, "Errori sulle porte")));
            assert!(c.contains(&(INFO, "Porte senza collegamento")));
            assert!(c.contains(&(OK, "Vicini LLDP")));
            assert!(c.contains(&(INFO, "Vicini senza indirizzo di gestione")));
            assert_eq!(c.last(), Some(&(OK, "Risposta")));
            assert_eq!(
                c.contains(&(OK, "Contatori a 64 bit")),
                ver == "2c",
                "v1 non trasporta Counter64"
            );
            let e = d
                .checks
                .iter()
                .find(|c| c.name == "Errori sulle porte")
                .unwrap();
            assert!(
                e.detail.starts_with("1/2 (Interfaccia 1/2): 1204 errori"),
                "{}",
                e.detail
            );
        }
    }

    /// Only some sections: the others are not read and do not appear.
    #[tokio::test]
    async fn sezioni_scelte() {
        let a = fake::agent(switch(), "prova-lettura").await;
        let mut r = req(&a, "2c");
        r.system = Some(false);
        r.neighbors = Some(false);
        r.fdb = Some(false);
        let d = run(r, None, &Stop::new(), |_| {}).await.unwrap();
        assert!(d.neighbors.is_none() && d.fdb.is_none());
        assert_eq!(d.interfaces.unwrap().total, 5);
        // the name and uptime are read anyway, the rest of the system is not
        assert_eq!(d.name, "sw-core01.corp.example");
        assert!(d.system.units.is_empty() && d.system.addresses.is_empty());
        assert!(!names(&d.checks).contains(&(INFO, "Contatto e posizione")));
        let json = serde_json::to_value(d.sections).unwrap();
        assert_eq!(json["fdb"], false);
    }

    /// A device that is not a switch: no LLDP, no MAC table, only ARP (in the new form,
    /// ipNetToPhysicalTable).
    #[tokio::test]
    async fn router_senza_bridge() {
        let mut m = fake::Mib::new();
        m.insert(at("sysName", &[0]), t("fw01"));
        m.insert(at("sysUpTime", &[0]), ticks(360_000));
        m.insert(at("ifDescr", &[1]), t("wan"));
        m.insert(at("ifOperStatus", &[1]), ber::int(1));
        m.insert(
            at("ipNetToPhysicalPhysAddress", &[1, 1, 4, 203, 0, 113, 1]),
            ber::octets(&[0, 0x50, 0x56, 9, 9, 9]),
        );
        // IPv6 entry (type 2): ignored
        let mut v6 = vec![1, 2, 16];
        v6.extend([0u32; 16]);
        m.insert(
            at("ipNetToPhysicalPhysAddress", &v6),
            ber::octets(&[0, 0x50, 0x56, 9, 9, 8]),
        );
        let a = fake::agent(m, "prova-lettura").await;
        let d = run(req(&a, "2c"), None, &Stop::new(), |_| {})
            .await
            .unwrap();
        let f = d.fdb.unwrap();
        assert_eq!(f.source, "");
        assert_eq!(f.list.len(), 1);
        assert_eq!(
            f.list[0],
            FdbRow {
                mac: "00:50:56:09:09:09".into(),
                vendor: String::new(),
                local: false,
                ip: vec!["203.0.113.1".into()],
                port: "wan".into(),
                vlan: None,
                kind: "arp",
            }
        );
        let c = names(&d.checks);
        assert!(c.contains(&(INFO, "Solo tabella ARP")));
        assert!(c.contains(&(INFO, "LLDP non disponibile")));
        assert!(c.contains(&(INFO, "Avvio recente")));
        assert!(c.contains(&(INFO, "Solo contatori a 32 bit")));
        assert!(c.contains(&(OK, "Nessun errore")));
        assert!(!d.neighbors.unwrap().supported);
    }

    /// Silent agent and "Stop".
    #[tokio::test]
    async fn timeout_e_stop() {
        let a = fake::agent(switch(), "un'altra").await;
        // wrong community: the error explains the reasons (the timeout here is the real one, 3 s x 2)
        let mut c = connect(&req(&a, "2c").snmp).await.unwrap();
        c.s.timeout = std::time::Duration::from_millis(150);
        c.s.retries = 0;
        let e = collect(&mut c.s, ALL, &Stop::new(), |_| {})
            .await
            .unwrap_err();
        assert!(c.explain(e).starts_with("Nessuna risposta da 127.0.0.1"));

        // stop already received: no request, empty result marked as stopped
        let a = fake::agent(switch(), "prova-lettura").await;
        let stop = Stop::new();
        stop.stop();
        let d = run(req(&a, "2c"), None, &stop, |_| {}).await.unwrap();
        assert!(d.stopped && d.values == 0);
        assert_eq!(a.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(d
            .checks
            .last()
            .unwrap()
            .detail
            .ends_with("lettura fermata."));
    }

    fn oid_value(arcs: &[u32]) -> Vec<u8> {
        ber::oid(arcs)
    }

    /// Fake server: 2 processors, RAM, virtual memory, three disks (one almost full), processes.
    fn server() -> fake::Mib {
        let mut m = fake::Mib::new();
        let mut put = |name: &str, index: &[u32], v: Vec<u8>| {
            m.insert(at(name, index), v);
        };
        put("sysDescr", &[0], t("Server di prova"));
        put("sysName", &[0], t("srv01.corp.example"));
        put("hrSystem", &[1, 0], ticks(5 * 8_640_000));
        put("hrSystem", &[5, 0], gauge(2));
        put("hrSystem", &[6, 0], gauge(3));
        put("hrMemorySize", &[0], ber::int(16 * 1024 * 1024));
        let ram = [1, 3, 6, 1, 2, 1, 25, 2, 1, 2];
        let virt = [1, 3, 6, 1, 2, 1, 25, 2, 1, 3];
        let disk = [1, 3, 6, 1, 2, 1, 25, 2, 1, 4];
        let other = [1, 3, 6, 1, 2, 1, 25, 2, 1, 1];
        let rows = [
            (
                1,
                &ram,
                "Physical Memory",
                1024,
                16 * 1024 * 1024,
                9 * 1024 * 1024,
            ),
            (
                2,
                &virt,
                "Virtual Memory",
                1024,
                24 * 1024 * 1024,
                12 * 1024 * 1024,
            ),
            (
                3,
                &disk,
                "C:\\ Label:Sistema  Serial Number 1a2b3c4d",
                4096,
                30_000_000,
                21_000_000,
            ),
            (
                4,
                &disk,
                "D:\\ Label:Dati  Serial Number 5e6f7a8b",
                4096,
                100_000_000,
                93_000_000,
            ),
            (
                5,
                &disk,
                "E:\\ Label:Pieno  Serial Number 9c0d1e2f",
                4096,
                1000,
                990,
            ),
            (6, &other, "Cached memory", 1024, 1000, 1000),
        ];
        for (i, ty, descr, unit, size, used) in rows {
            put("hrStorageType", &[i], oid_value(ty));
            put("hrStorageDescr", &[i], t(descr));
            put("hrStorageAllocationUnits", &[i], ber::int(unit));
            put("hrStorageSize", &[i], ber::int(size));
            put("hrStorageUsed", &[i], ber::int(used));
        }
        put("hrProcessorLoad", &[196608], ber::int(12));
        put("hrProcessorLoad", &[196609], ber::int(36));
        put("hrDeviceDescr", &[196608], t("Processore 0"));
        put("hrDeviceDescr", &[196609], t("Processore 1"));
        for (i, name, mem, cpu) in [
            (4u32, "System", 300i64, 90_000i64),
            (812, "db", 4_000_000, 1_200_000),
            (900, "web", 800_000, 5000),
        ] {
            put("hrSWRunName", &[i], t(name));
            put("hrSWRunPerfMem", &[i], ber::int(mem));
            put("hrSWRunPerfCPU", &[i], ber::int(cpu));
        }
        m
    }

    /// Fake printer: 4 toners (black at 10 %), waste container, one empty tray, one alert.
    fn stampante() -> fake::Mib {
        let mut m = fake::Mib::new();
        let mut put = |name: &str, index: &[u32], v: Vec<u8>| {
            m.insert(at(name, index), v);
        };
        put("sysDescr", &[0], t("Stampante di prova"));
        put("sysName", &[0], t("prn01.corp.example"));
        put("hrDeviceDescr", &[1], t("Stampante laser a colori"));
        put("hrPrinterStatus", &[1], ber::int(3));
        // paper low (0x80) and toner low (0x20)
        put(
            "hrPrinterDetectedErrorState",
            &[1],
            ber::octets(&[0xa0, 0x00]),
        );
        put("prtGeneralSerialNumber", &[1, 1], t("PRN0123456"));
        put("prtMarkerLifeCount", &[1, 1], counter32(48_213));
        put("prtMarkerCounterUnit", &[1, 1], ber::int(7));
        // toner: black (colorant 1), cyan (2), magenta, yellow; waste without colour
        let sup: [(u32, &str, i64, i64, i64, i64, i64); 6] = [
            (1, "Toner nero", 3, 3, 100, 10, 1),
            (2, "Toner ciano", 3, 3, 100, 64, 2),
            (3, "Toner magenta", 3, 3, 100, 48, 3),
            (4, "Toner giallo", 3, 3, 100, -3, 4),
            (5, "Contenitore toner di scarto", 4, 4, 100, 35, 0),
            (6, "Unità fusore", 3, 15, 100, -2, 0),
        ];
        for (i, d, class, ty, max, level, colorant) in sup {
            put("prtMarkerSuppliesDescription", &[1, i], t(d));
            put("prtMarkerSuppliesClass", &[1, i], ber::int(class));
            put("prtMarkerSuppliesType", &[1, i], ber::int(ty));
            put("prtMarkerSuppliesSupplyUnit", &[1, i], ber::int(19));
            put("prtMarkerSuppliesMaxCapacity", &[1, i], ber::int(max));
            put("prtMarkerSuppliesLevel", &[1, i], ber::int(level));
            put(
                "prtMarkerSuppliesColorantIndex",
                &[1, i],
                ber::int(colorant),
            );
        }
        for (i, name) in [(1u32, "black"), (2, "cyan"), (3, "magenta"), (4, "yellow")] {
            put("prtMarkerColorantValue", &[1, i], t(name));
        }
        // trays: 1 with 230 sheets out of 500, 2 empty, 3 "at least one left"
        for (i, name, max, cur) in [
            (1u32, "Cassetto 1", 500i64, 230i64),
            (2, "Cassetto 2", 500, 0),
            (3, "Bypass", -2, -3),
        ] {
            put("prtInputName", &[1, i], t(name));
            put("prtInputMediaName", &[1, i], t("A4"));
            put("prtInputMaxCapacity", &[1, i], ber::int(max));
            put("prtInputCurrentLevel", &[1, i], ber::int(cur));
            put("prtInputCapacityUnit", &[1, i], ber::int(8));
        }
        put("prtAlertSeverityLevel", &[1, 1], ber::int(4));
        put("prtAlertGroup", &[1, 1], ber::int(8));
        put("prtAlertCode", &[1, 1], ber::int(808));
        put("prtAlertDescription", &[1, 1], t("Cassetto 2 vuoto"));
        m
    }

    #[tokio::test]
    async fn server_con_risorse() {
        let a = fake::agent(server(), "prova-lettura").await;
        for ver in ["2c", "1"] {
            let d = run(req(&a, ver), None, &Stop::new(), |_| {}).await.unwrap();
            assert!(d.printer.is_none(), "a server is not a printer");
            let r = d.resources.as_ref().expect("risorse");
            assert_eq!(r.uptime_s, Some(5 * 86_400));
            assert_eq!((r.users, r.processes), (Some(2), Some(3)));
            assert_eq!(r.memory_kb, Some(16 * 1024 * 1024));
            assert_eq!(
                r.cpu,
                vec![
                    resources::Cpu {
                        name: "Processore 0".into(),
                        load: 12
                    },
                    resources::Cpu {
                        name: "Processore 1".into(),
                        load: 36
                    }
                ]
            );
            assert_eq!(r.cpu_avg, Some(24));
            // memory: only RAM and virtual; "Cached memory" (type other) is not there
            assert_eq!(r.memory.len(), 2);
            assert_eq!((r.memory[0].kind, r.memory[0].pct), ("ram", 56));
            assert_eq!(r.memory[0].size, 16 * 1024 * 1024 * 1024);
            assert_eq!((r.memory[1].kind, r.memory[1].pct), ("virtual", 50));
            // disks: the Windows serial number is removed from the name
            let dn: Vec<_> = r.disks.iter().map(|x| (x.name.as_str(), x.pct)).collect();
            assert_eq!(
                dn,
                [
                    ("C:\\ Label:Sistema", 70),
                    ("D:\\ Label:Dati", 93),
                    ("E:\\ Label:Pieno", 99)
                ]
            );
            assert_eq!(r.disks[0].size, 30_000_000 * 4096);
            // processes: by decreasing memory, CPU in seconds
            let top: Vec<_> = r
                .top
                .iter()
                .map(|p| (p.name.as_str(), p.mem_kb, p.cpu_s))
                .collect();
            assert_eq!(
                top,
                [
                    ("db", 4_000_000, 12_000),
                    ("web", 800_000, 50),
                    ("System", 300, 900)
                ]
            );
            assert_eq!(r.process_total, 3);

            let c = names(&d.checks);
            for want in [
                ("ok", "Processore"),
                ("ok", "Memoria fisica"),
                ("warn", "Disco da tenere d'occhio"),
                ("err", "Disco quasi pieno"),
            ] {
                assert!(c.contains(&want), "v{ver}: manca {want:?} in {c:?}");
            }
            assert!(!c.iter().any(|(_, n)| *n == "Spazio sui dischi"));
        }
    }

    #[tokio::test]
    async fn stampante_con_materiali() {
        let a = fake::agent(stampante(), "prova-lettura").await;
        for ver in ["2c", "1"] {
            let d = run(req(&a, ver), None, &Stop::new(), |_| {}).await.unwrap();
            assert!(d.resources.is_none());
            let p = d.printer.as_ref().expect("stampante");
            assert_eq!(p.name, "Stampante laser a colori");
            assert_eq!(
                (p.status, p.serial.as_str(), p.pages),
                ("Inattiva", "PRN0123456", Some(48_213))
            );
            assert_eq!(
                p.errors.iter().map(|e| e.label).collect::<Vec<_>>(),
                ["carta in esaurimento", "toner in esaurimento"]
            );
            let s: Vec<_> = p
                .supplies
                .iter()
                .map(|s| (s.color, s.kind, s.class, s.level, s.some, s.state))
                .collect();
            assert_eq!(
                s,
                [
                    ("black", "toner", "consumed", Some(10), false, "warn"),
                    ("cyan", "toner", "consumed", Some(64), false, "ok"),
                    ("magenta", "toner", "consumed", Some(48), false, "ok"),
                    ("yellow", "toner", "consumed", None, true, "ok"),
                    ("", "wasteToner", "filled", Some(35), false, "ok"),
                    ("", "fuser", "consumed", None, false, "unknown"),
                ],
                "v{ver}"
            );
            let t: Vec<_> = p
                .trays
                .iter()
                .map(|t| (t.name.as_str(), t.level, t.state, t.some))
                .collect();
            assert_eq!(
                t,
                [
                    ("Cassetto 1", Some(46), "ok", false),
                    ("Cassetto 2", Some(0), "empty", false),
                    ("Bypass", None, "ok", true)
                ]
            );
            assert_eq!(p.trays[0].media, "A4");
            assert_eq!(
                p.alerts,
                vec![printer::Alert {
                    severity: "warning",
                    text: "Cassetto 2 vuoto".into(),
                    group: "input".into()
                }]
            );
            let c = names(&d.checks);
            for want in [
                ("warn", "Materiale in esaurimento"),
                ("warn", "Vassoio vuoto"),
                ("warn", "Avviso della stampante"),
                ("warn", "Carta in esaurimento"),
                ("info", "Stato"),
            ] {
                assert!(c.contains(&want), "v{ver}: manca {want:?} in {c:?}");
            }
        }
    }

    /// The newer sections can be removed, and without data the view does not exist.
    #[tokio::test]
    async fn sezioni_nuove_scelte() {
        let a = fake::agent(stampante(), "prova-lettura").await;
        let mut r = req(&a, "2c");
        r.printer = Some(false);
        let d = run(r, None, &Stop::new(), |_| {}).await.unwrap();
        assert!(d.printer.is_none() && d.resources.is_none());
        assert!(!d.sections.printer && d.sections.resources);
    }

    #[test]
    fn soglie_dei_materiali() {
        use printer::{checks, error_state, Printer, Supply};
        let s = |class, level, state| Supply {
            name: "x".into(),
            kind: "toner",
            class,
            color: "",
            level,
            some: false,
            state,
        };
        let p = Printer {
            supplies: vec![
                s("consumed", Some(0), "err"),
                s("filled", Some(97), "err"),
                s("filled", Some(88), "warn"),
            ],
            ..Default::default()
        };
        let found = checks(&p);
        let c = names(&found);
        assert_eq!(
            c,
            [
                ("err", "Materiale esaurito"),
                ("err", "Contenitore pieno"),
                ("warn", "Contenitore quasi pieno")
            ]
        );
        // detected errors: the bits of the second byte
        let e = error_state(&[0x04, 0x08]);
        assert_eq!(
            e.iter().map(|x| (x.label, x.severe)).collect::<Vec<_>>(),
            [("carta inceppata", true), ("uscita piena", true)]
        );
        assert!(error_state(&[]).is_empty());
    }

    #[test]
    fn etichette_stampante() {
        use super::super::mib::{cell, enum_label, oid_of};
        assert_eq!(enum_label("prtMarkerSuppliesType", 3), Some("toner"));
        assert_eq!(
            enum_label("prtMarkerSuppliesType", 21),
            Some("tonerCartridge")
        );
        assert_eq!(
            enum_label("prtMarkerSuppliesSupplyUnit", 19),
            Some("percent")
        );
        assert_eq!(
            enum_label("prtMarkerSuppliesLevel", -3),
            Some("somethingRemains")
        );
        assert_eq!(enum_label("prtMarkerSuppliesLevel", 40), None);
        assert_eq!(
            enum_label("prtAlertCode", 808),
            Some("inputMediaSupplyEmpty")
        );
        let mut o = oid_of("prtMarkerSuppliesClass");
        o.extend([1, 2]);
        assert_eq!(cell(&o, &Value::Int(3)), "supplyThatIsConsumed");
    }

    #[test]
    fn funzioni_pure() {
        assert_eq!(prefix_len([255, 255, 254, 0]), Some(23));
        assert_eq!(prefix_len([255, 255, 255, 255]), Some(32));
        assert_eq!(prefix_len([0, 0, 0, 0]), Some(0));
        assert_eq!(prefix_len([255, 0, 255, 0]), None);
        assert_eq!(
            services(72),
            ["livello 4 (host)", "livello 7 (applicazioni)"]
        );
        assert_eq!(capabilities(&[0x80 | 0x01]), ["host", "altro"]);
        assert!(capabilities(&[]).is_empty());
        assert_eq!(state(Some(2), Some(1)), "off");
        assert_eq!(state(Some(1), Some(1)), "up");
        assert_eq!(state(None, Some(7)), "down");
        // management address: with and without length, IPv6, unknown subtype
        assert_eq!(
            man_addr(&[1, 4, 192, 0, 2, 9]),
            Some((true, "192.0.2.9".into()))
        );
        assert_eq!(
            man_addr(&[1, 192, 0, 2, 9]),
            Some((true, "192.0.2.9".into()))
        );
        let mut v6 = vec![2, 16, 0x20, 0x01, 0x0d, 0xb8];
        v6.extend([0u32; 11]);
        v6.push(1);
        assert_eq!(man_addr(&v6), Some((false, "2001:db8::1".into())));
        assert_eq!(man_addr(&[6, 1, 2, 3]), None);
        assert_eq!(man_addr(&[1, 4, 300, 0, 2, 9]), None);
        assert_eq!(ago(41 * 86_400 + 5), "41 giorni");
        assert_eq!(ago(90_000), "1 giorno");
        assert_eq!(ago(7300), "2 ore");
        assert_eq!(ago(600), "10 minuti");
        assert_eq!(ago(30), "meno di 2 minuti");
        assert_eq!(fdb_kind(Some(2)), None);
        assert_eq!(fdb_kind(None), Some("dinamico"));
        // LLDP identifiers: MAC, IPv4 network address, text
        let mac = Value::Str(vec![2, 0, 0x5e, 1, 2, 3]);
        assert_eq!(lldp_id(4, 5, Some(4), &mac), "02:00:5e:01:02:03");
        assert_eq!(
            lldp_id(4, 5, Some(5), &Value::Str(vec![1, 192, 0, 2, 7])),
            "192.0.2.7"
        );
        assert_eq!(lldp_id(3, 4, Some(5), &Value::Str(b"1/1".to_vec())), "1/1");
    }

    /// A section that the agent refuses becomes a note, the others stay.
    #[test]
    fn note_e_tabelle_troncate() {
        let mut raw = Raw::default();
        raw.notes.push((
            a_nb(),
            "L'agente ha risposto con un errore: accesso negato (noAccess)".into(),
        ));
        raw.truncated.push("dot1qTpFdbPort");
        let v = build(&raw, ALL, None);
        assert!(v.system.name.is_empty() && v.interfaces.unwrap().list.is_empty());
        assert!(v.neighbors.unwrap().list.is_empty() && v.fdb.unwrap().list.is_empty());
        let c = v.checks;
        let n = names(&c);
        assert_eq!(n[0], (WARN, "Lettura incompleta"));
        assert_eq!(c[0].area, "Vicini");
        assert!(c[0].detail.contains("noAccess"));
        assert_eq!(n[1], (WARN, "Tabelle troncate"));
        assert!(n.contains(&(INFO, "Nessuna interfaccia")));
        assert!(n.contains(&(INFO, "Nessuna tabella")));
    }

    /// English messages: names, details and areas change, the machine codes do not.
    #[tokio::test]
    async fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(ago(41 * 86_400 + 5), "41 days");
        assert_eq!(ago(90_000), "1 day");
        assert_eq!(ago(30), "less than 2 minutes");
        assert_eq!(services(72), ["layer 4 (host)", "layer 7 (applications)"]);
        assert_eq!(capabilities(&[0x80 | 0x04]), ["phone", "other"]);

        let a = fake::agent(stampante(), "prova-lettura").await;
        let d = run(req(&a, "2c"), None, &Stop::new(), |_| {})
            .await
            .unwrap();
        let p = d.printer.as_ref().unwrap();
        assert_eq!(p.status, "Idle");
        assert_eq!(
            p.errors.iter().map(|e| e.label).collect::<Vec<_>>(),
            ["paper low", "toner low"]
        );
        let c = names(&d.checks);
        for want in [
            ("warn", "Supply running low"),
            ("warn", "Empty tray"),
            ("warn", "Printer warning"),
            ("warn", "Paper low"),
            ("info", "Status"),
        ] {
            assert!(c.contains(&want), "missing {want:?} in {c:?}");
        }
        for italian in ["Vassoio vuoto", "Materiale in esaurimento", "Stato"] {
            assert!(!c.iter().any(|(_, n)| *n == italian), "{italian}");
        }
        assert!(d.checks.iter().any(|c| c.area == "Printer"));
        assert!(d.checks.iter().all(|c| c.area != "Stampante"));
        let tray = d.checks.iter().find(|c| c.name == "Empty tray").unwrap();
        assert_eq!(tray.detail, "Cassetto 2: out of paper.");
        let last = d.checks.last().unwrap();
        assert_eq!((last.name.as_str(), last.area), ("Response", "Agent"));
        assert!(last.detail.contains(" values read in "), "{}", last.detail);

        let a = fake::agent(server(), "prova-lettura").await;
        let d = run(req(&a, "2c"), None, &Stop::new(), |_| {})
            .await
            .unwrap();
        let c = names(&d.checks);
        for want in [
            ("ok", "Processor"),
            ("ok", "Physical memory"),
            ("warn", "Disk to keep an eye on"),
            ("err", "Disk almost full"),
        ] {
            assert!(c.contains(&want), "missing {want:?} in {c:?}");
        }
        assert!(!c.iter().any(|(_, n)| *n == "Processore"));
        let cpu = d.checks.iter().find(|c| c.name == "Processor").unwrap();
        assert_eq!(
            cpu.detail,
            "Average load 24 % on 2 processors over the last minute."
        );
        assert_eq!(resources::size_text(36_000_000_000), "33.5 GB");
    }
}
