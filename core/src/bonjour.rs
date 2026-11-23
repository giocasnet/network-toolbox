//! Bonjour (mDNS / DNS-SD) browser: lists the services announced on the local
//! network (printers, AirPlay, file sharing, SSH, web interfaces...).
//!
//! Own client over `hickory-proto` messages. The queries leave from an ephemeral
//! port (not 5353) on every IPv4 adapter, so responders answer **unicast** to us
//! (legacy unicast, RFC 6762 §6.7) and nothing has to be shared with the system's
//! own mDNS responder. Collection follows DNS-SD (RFC 6763): the type list
//! (`_services._dns-sd._udp.local`), the instances of every type, then SRV and TXT
//! of every instance and the addresses of its host. Read only: it sends questions,
//! never announcements.
//!
//! `Book` (what has been heard), `build`, `checks`, `csv` are pure functions,
//! tested with hand-made messages; the network part (`run_with`) is tested with a
//! fake responder on 127.0.0.1.

use crate::http::analyze::{check, Check};
use crate::mcast::{csv_field, local_v4, open};
use crate::ping::Stop;
use crate::{t, tf};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const MDNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
const META: &str = "_services._dns-sd._udp.local.";
/// The questions are repeated every `RESEND` ticks (the rest only when something new arrives).
const RESEND: u32 = 4;
const AREA: &str = "Bonjour";

// ───────────────────────── request and response ─────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BonjourReq {
    /// Listening time in seconds (2 to 30, default 6).
    #[serde(default, deserialize_with = "crate::util::opt_u32")]
    pub seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BService {
    /// Instance name, e.g. "Office printer".
    pub instance: String,
    /// DNS-SD type, e.g. "_ipp._tcp".
    pub kind: String,
    /// Readable name of the type ("" if unknown).
    pub label: String,
    pub port: u16,
    /// TXT strings (`key=value`).
    pub txt: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BHost {
    /// Host name without the final dot, or the responder's address if the SRV is missing.
    pub name: String,
    /// IPv4 first, then IPv6.
    pub addrs: Vec<String>,
    pub services: Vec<BService>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TypeCount {
    pub kind: String,
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BonjourResult {
    pub hosts: Vec<BHost>,
    pub types: Vec<TypeCount>,
    pub n_hosts: usize,
    pub n_services: usize,
    pub n_types: usize,
    /// Adapters the questions were sent on.
    pub n_ifaces: usize,
    pub seconds: u64,
    /// Stopped by the user before the end.
    pub stopped: bool,
    pub checks: Vec<Check>,
    pub csv: String,
}

// ───────────────────────── what has been heard ─────────────────────────

#[derive(Default)]
struct Inst {
    fqdn: Option<Name>,
    label: String,
    kind: String,
    host: Option<Name>,
    port: u16,
    txt: Vec<String>,
    has_srv: bool,
    has_txt: bool,
    from: BTreeSet<IpAddr>,
}

#[derive(Default)]
pub(crate) struct Book {
    /// kind → "_ipp._tcp.local."
    types: BTreeMap<String, Name>,
    insts: BTreeMap<String, Inst>,
    /// host key → (name, addresses)
    hosts: BTreeMap<String, (Name, BTreeSet<IpAddr>)>,
    responders: BTreeSet<IpAddr>,
}

fn key(n: &Name) -> String {
    n.to_lowercase().to_string()
}

fn label_str(l: &[u8]) -> String {
    String::from_utf8_lossy(l).into_owned()
}

/// "_ipp._tcp.local." → "_ipp._tcp".
fn split_type(n: &Name) -> Option<String> {
    let l: Vec<&[u8]> = n.iter().collect();
    if l.len() == 3
        && l[0].starts_with(b"_")
        && (l[1].eq_ignore_ascii_case(b"_tcp") || l[1].eq_ignore_ascii_case(b"_udp"))
        && l[2].eq_ignore_ascii_case(b"local")
    {
        Some(format!("{}.{}", label_str(l[0]), label_str(l[1])).to_lowercase())
    } else {
        None
    }
}

/// "Office printer._ipp._tcp.local." → ("Office printer", "_ipp._tcp").
fn split_instance(n: &Name) -> Option<(String, String)> {
    let l: Vec<&[u8]> = n.iter().collect();
    let len = l.len();
    if len >= 4
        && l[len - 1].eq_ignore_ascii_case(b"local")
        && (l[len - 2].eq_ignore_ascii_case(b"_tcp") || l[len - 2].eq_ignore_ascii_case(b"_udp"))
        && l[len - 3].starts_with(b"_")
    {
        let kind = format!("{}.{}", label_str(l[len - 3]), label_str(l[len - 2])).to_lowercase();
        let label = l[..len - 3]
            .iter()
            .map(|x| label_str(x))
            .collect::<Vec<_>>()
            .join(".");
        Some((label, kind))
    } else {
        None
    }
}

fn trim_dot(n: &Name) -> String {
    n.to_utf8().trim_end_matches('.').to_string()
}

impl Book {
    fn inst(&mut self, name: &Name, from: IpAddr) -> Option<&mut Inst> {
        let (label, kind) = split_instance(name)?;
        let i = self.insts.entry(key(name)).or_default();
        if i.fqdn.is_none() {
            i.fqdn = Some(name.clone());
            i.label = label;
            i.kind = kind;
        }
        i.from.insert(from);
        Some(i)
    }

    /// Takes the records of a response. `true` if something new was learnt.
    pub(crate) fn ingest(&mut self, m: &Message, from: IpAddr) -> bool {
        if m.message_type() != MessageType::Response {
            return false;
        }
        self.responders.insert(from);
        let mut changed = false;
        for r in m
            .answers()
            .iter()
            .chain(m.additionals())
            .chain(m.name_servers())
        {
            // TTL 0 = goodbye
            if r.ttl() == 0 {
                continue;
            }
            let Some(data) = r.data() else { continue };
            match data {
                RData::PTR(p) => {
                    let target = &p.0;
                    if key(r.name()) == META {
                        if let Some(kind) = split_type(target) {
                            changed |= self.types.insert(kind, target.clone()).is_none();
                        }
                    } else if let (Some(kind), Some((_, k2))) =
                        (split_type(r.name()), split_instance(target))
                    {
                        if kind == k2 {
                            let before = self.insts.len();
                            self.inst(target, from);
                            changed |= self.insts.len() != before;
                        }
                    }
                }
                RData::SRV(s) => {
                    if let Some(i) = self.inst(r.name(), from) {
                        changed |= !i.has_srv;
                        i.has_srv = true;
                        i.host = Some(s.target().clone());
                        i.port = s.port();
                    }
                }
                RData::TXT(x) => {
                    if let Some(i) = self.inst(r.name(), from) {
                        changed |= !i.has_txt;
                        i.has_txt = true;
                        i.txt = x
                            .txt_data()
                            .iter()
                            .map(|b| label_str(b))
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                }
                RData::A(a) => changed |= self.addr(r.name(), IpAddr::V4(a.0)),
                RData::AAAA(a) => changed |= self.addr(r.name(), IpAddr::V6(a.0)),
                _ => {}
            }
        }
        changed
    }

    fn addr(&mut self, name: &Name, ip: IpAddr) -> bool {
        self.hosts
            .entry(key(name))
            .or_insert_with(|| (name.clone(), BTreeSet::new()))
            .1
            .insert(ip)
    }

    /// Questions still worth asking.
    fn queries(&self) -> Vec<(Name, RecordType)> {
        let mut q = Vec::new();
        if let Ok(n) = Name::from_ascii(META) {
            q.push((n, RecordType::PTR));
        }
        for n in self.types.values() {
            q.push((n.clone(), RecordType::PTR));
        }
        let mut hosts = BTreeMap::new();
        for i in self.insts.values() {
            let Some(f) = &i.fqdn else { continue };
            if !i.has_srv {
                q.push((f.clone(), RecordType::SRV));
            }
            if !i.has_txt {
                q.push((f.clone(), RecordType::TXT));
            }
            if let Some(h) = &i.host {
                if self.hosts.get(&key(h)).is_none_or(|x| x.1.is_empty()) {
                    hosts.insert(key(h), h.clone());
                }
            }
        }
        for h in hosts.into_values() {
            q.push((h.clone(), RecordType::A));
            q.push((h, RecordType::AAAA));
        }
        q
    }
}

fn packet(name: Name, rtype: RecordType) -> Option<Vec<u8>> {
    let mut m = Message::new();
    m.set_id(0x4e54)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false)
        .add_query(Query::query(name, rtype));
    m.to_vec().ok()
}

// ───────────────────────── readable names ─────────────────────────

/// Readable name of a service type, "" if unknown.
pub fn type_label(kind: &str) -> &'static str {
    match kind {
        "_http._tcp" => "Web (HTTP)",
        "_https._tcp" => "Web (HTTPS)",
        "_ipp._tcp" => t!("Stampante (IPP)", "Printer (IPP)"),
        "_ipps._tcp" => t!("Stampante (IPP sicuro)", "Printer (secure IPP)"),
        "_printer._tcp" => t!("Stampante (LPD)", "Printer (LPD)"),
        "_pdl-datastream._tcp" => t!("Stampante (RAW 9100)", "Printer (RAW 9100)"),
        "_scanner._tcp" | "_uscan._tcp" | "_uscans._tcp" => "Scanner",
        "_airplay._tcp" => "AirPlay",
        "_raop._tcp" => t!("AirPlay audio", "AirPlay audio"),
        "_googlecast._tcp" => "Google Cast",
        "_smb._tcp" => t!("Condivisione file (SMB)", "File sharing (SMB)"),
        "_afpovertcp._tcp" => t!("Condivisione file (AFP)", "File sharing (AFP)"),
        "_nfs._tcp" => "NFS",
        "_adisk._tcp" => t!(
            "Disco di rete / Time Machine",
            "Network disk / Time Machine"
        ),
        "_ssh._tcp" => "SSH",
        "_sftp-ssh._tcp" => "SFTP",
        "_ftp._tcp" => "FTP",
        "_telnet._tcp" => "Telnet",
        "_rfb._tcp" => t!("Condivisione schermo (VNC)", "Screen sharing (VNC)"),
        "_workstation._tcp" => "Workstation",
        "_device-info._tcp" => t!("Informazioni dispositivo", "Device information"),
        "_companion-link._tcp" => "Apple Companion Link",
        "_hap._tcp" | "_homekit._tcp" => "HomeKit",
        "_matter._tcp" | "_matterc._udp" => "Matter",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_daap._tcp" => "iTunes (DAAP)",
        "_snmp._udp" => "SNMP",
        "_mqtt._tcp" => "MQTT",
        "_sleep-proxy._udp" => "Sleep Proxy",
        "_services._dns-sd._udp" => "DNS-SD",
        _ => "",
    }
}

/// Services whose announcement deserves a note, with the reason's weight.
fn exposure(kind: &str) -> Option<&'static str> {
    match kind {
        "_telnet._tcp" | "_ftp._tcp" => Some("warn"),
        "_ssh._tcp" | "_sftp-ssh._tcp" | "_rfb._tcp" | "_smb._tcp" | "_afpovertcp._tcp"
        | "_nfs._tcp" => Some("info"),
        _ => None,
    }
}

// ───────────────────────── result ─────────────────────────

fn sort_addrs(set: &BTreeSet<IpAddr>) -> Vec<String> {
    let mut v: Vec<&IpAddr> = set.iter().collect();
    v.sort_by_key(|a| (a.is_ipv6(), **a));
    v.into_iter().map(|a| a.to_string()).collect()
}

pub(crate) fn build(book: &Book, n_ifaces: usize, seconds: u64) -> BonjourResult {
    // group by host name; an instance without SRV goes under its responder's address
    let mut groups: BTreeMap<String, BHost> = BTreeMap::new();
    for i in book.insts.values() {
        let (gk, name, addrs) = match &i.host {
            Some(h) => {
                let mut a = book
                    .hosts
                    .get(&key(h))
                    .map(|x| x.1.clone())
                    .unwrap_or_default();
                if a.is_empty() {
                    a = i.from.clone();
                }
                (key(h), trim_dot(h), a)
            }
            None => {
                let first = i.from.iter().next().map(|a| a.to_string());
                (
                    format!("ip:{}", first.clone().unwrap_or_default()),
                    first.unwrap_or_default(),
                    i.from.clone(),
                )
            }
        };
        let g = groups.entry(gk).or_insert_with(|| BHost {
            name,
            addrs: sort_addrs(&addrs),
            services: Vec::new(),
        });
        g.services.push(BService {
            instance: i.label.clone(),
            kind: i.kind.clone(),
            label: type_label(&i.kind).to_string(),
            port: i.port,
            txt: i.txt.clone(),
        });
    }
    let mut hosts: Vec<BHost> = groups.into_values().collect();
    for h in &mut hosts {
        h.services
            .sort_by(|a, b| (&a.kind, &a.instance).cmp(&(&b.kind, &b.instance)));
    }
    hosts.sort_by_key(|a| a.name.to_lowercase());

    let mut counts: BTreeMap<String, usize> = book.types.keys().map(|k| (k.clone(), 0)).collect();
    for i in book.insts.values() {
        *counts.entry(i.kind.clone()).or_default() += 1;
    }
    let types: Vec<TypeCount> = counts
        .into_iter()
        .map(|(kind, count)| TypeCount {
            label: type_label(&kind).to_string(),
            kind,
            count,
        })
        .collect();

    let mut res = BonjourResult {
        n_hosts: hosts.len(),
        n_services: book.insts.len(),
        n_types: types.len(),
        n_ifaces,
        seconds,
        stopped: false,
        hosts,
        types,
        checks: Vec::new(),
        csv: String::new(),
    };
    res.checks = checks(book, &res);
    res.csv = csv(&res);
    res
}

pub(crate) fn checks(book: &Book, r: &BonjourResult) -> Vec<Check> {
    let mut c = Vec::new();
    if book.responders.is_empty() {
        c.push(check(
            AREA,
            "warn",
            t!("Nessuna risposta", "No reply"),
            tf!(
                "Nessun dispositivo ha risposto in {s} s su {n} schede. Bonjour usa il multicast UDP 5353: controlla il firewall di questo PC, e ricorda che il multicast non attraversa i router (altra VLAN) e che alcuni access point Wi-Fi isolano i client.",
                "No device replied within {s} s on {n} adapters. Bonjour uses UDP 5353 multicast: check this PC's firewall, and remember that multicast does not cross routers (other VLAN) and that some Wi-Fi access points isolate clients.",
                s = r.seconds,
                n = r.n_ifaces
            ),
        ));
        return c;
    }
    c.push(check(
        AREA,
        "ok",
        t!("Servizi trovati", "Services found"),
        tf!(
            "{s} servizi di {t} tipi su {h} host, risposte da {n} indirizzi",
            "{s} services of {t} types on {h} hosts, replies from {n} addresses",
            s = r.n_services,
            t = r.types.iter().filter(|x| x.count > 0).count(),
            h = r.n_hosts,
            n = book.responders.len()
        ),
    ));
    // exposed services
    for (status, title) in [
        (
            "warn",
            t!(
                "Protocollo non cifrato annunciato",
                "Unencrypted protocol announced"
            ),
        ),
        (
            "info",
            t!(
                "Accesso remoto o condivisione annunciati",
                "Remote access or sharing announced"
            ),
        ),
    ] {
        let mut found: Vec<String> = Vec::new();
        for h in &r.hosts {
            for s in &h.services {
                if exposure(&s.kind) == Some(status) {
                    found.push(format!("{} ({})", h.name, s.kind));
                }
            }
        }
        if !found.is_empty() {
            found.sort();
            found.dedup();
            let shown: Vec<&str> = found.iter().take(6).map(String::as_str).collect();
            c.push(check(
                AREA,
                status,
                title,
                format!(
                    "{}{}",
                    shown.join(", "),
                    if found.len() > shown.len() {
                        format!(" +{}", found.len() - shown.len())
                    } else {
                        String::new()
                    }
                ),
            ));
        }
    }
    let nosrv = book.insts.values().filter(|i| !i.has_srv).count();
    if nosrv > 0 {
        c.push(check(
            AREA,
            "warn",
            t!("Servizi senza dettagli", "Services without details"),
            tf!(
                "{n} servizi annunciati non hanno risposto alla richiesta di host e porta",
                "{n} announced services did not answer the host and port request",
                n = nosrv
            ),
        ));
    }
    let noaddr = book
        .insts
        .values()
        .filter(|i| {
            i.host
                .as_ref()
                .is_some_and(|h| book.hosts.get(&key(h)).is_none_or(|x| x.1.is_empty()))
        })
        .count();
    if noaddr > 0 {
        c.push(check(
            AREA,
            "info",
            t!("Host senza indirizzo", "Hosts without an address"),
            tf!(
                "{n} servizi puntano a un host di cui non è arrivato l'indirizzo: è mostrato quello di chi ha risposto",
                "{n} services point to a host whose address did not arrive: the responder's address is shown",
                n = noaddr
            ),
        ));
    }
    c
}

pub fn csv(r: &BonjourResult) -> String {
    let mut out = vec![t!(
        "Host;Indirizzi;Istanza;Tipo;Descrizione;Porta;TXT",
        "Host;Addresses;Instance;Type;Description;Port;TXT"
    )
    .to_string()];
    for h in &r.hosts {
        for s in &h.services {
            out.push(
                [
                    h.name.as_str(),
                    &h.addrs.join(" "),
                    s.instance.as_str(),
                    s.kind.as_str(),
                    s.label.as_str(),
                    &s.port.to_string(),
                    &s.txt.join(" "),
                ]
                .iter()
                .map(|x| csv_field(x))
                .collect::<Vec<_>>()
                .join(";"),
            );
        }
    }
    out.join("\r\n")
}

// ───────────────────────── network ─────────────────────────

pub(crate) struct Env {
    pub dest: SocketAddr,
    pub locals: Vec<Ipv4Addr>,
    pub multicast: bool,
    /// Tick of the collection loop.
    pub step: Duration,
}

pub async fn run(req: BonjourReq, stop: &Stop) -> crate::Result<BonjourResult> {
    let s = req.seconds.unwrap_or(6);
    if !(2..=30).contains(&s) {
        return Err(t!("Durata: da 2 a 30 s", "Duration: 2 to 30 s").to_string());
    }
    run_with(
        Duration::from_secs(s as u64),
        Env {
            dest: MDNS,
            locals: local_v4(),
            multicast: true,
            step: Duration::from_millis(250),
        },
        stop,
    )
    .await
}

async fn send_round(book: &Book, socks: &[Arc<tokio::net::UdpSocket>], dest: SocketAddr) {
    for (name, rt) in book.queries() {
        if let Some(p) = packet(name, rt) {
            for s in socks {
                let _ = s.send_to(&p, dest).await;
            }
        }
    }
}

pub(crate) async fn run_with(dur: Duration, env: Env, stop: &Stop) -> crate::Result<BonjourResult> {
    let socks: Vec<Arc<tokio::net::UdpSocket>> = env
        .locals
        .iter()
        .filter_map(|ip| open(*ip, env.multicast).ok().map(Arc::new))
        .collect();
    if socks.is_empty() {
        return Err(t!(
            "Nessuna scheda di rete IPv4 attiva su cui cercare",
            "No active IPv4 adapter to search on"
        )
        .to_string());
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
    let mut readers = JoinSet::new();
    for s in &socks {
        let (s, tx) = (s.clone(), tx.clone());
        readers.spawn(async move {
            let mut buf = vec![0u8; 9000];
            loop {
                match s.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if tx.send((buf[..n].to_vec(), from)).is_err() {
                            break;
                        }
                    }
                    // Windows reports an ICMP "port unreachable" as an error here
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }
    drop(tx);

    let mut book = Book::default();
    let end = tokio::time::sleep(dur);
    tokio::pin!(end);
    // completes only if the stop arrives (`race` gives `None`)
    let stopper = stop.race(std::future::pending::<()>());
    tokio::pin!(stopper);
    let mut stopped = false;
    let mut tick = tokio::time::interval(env.step);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let (mut n, mut dirty) = (0u32, true);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if dirty || n.is_multiple_of(RESEND) {
                    send_round(&book, &socks, env.dest).await;
                    dirty = false;
                }
                n += 1;
            }
            Some((buf, from)) = rx.recv() => {
                if let Ok(m) = Message::from_vec(&buf) {
                    dirty |= book.ingest(&m, from.ip());
                }
            }
            _ = &mut end => break,
            _ = &mut stopper => {
                stopped = true;
                break;
            }
        }
    }
    readers.abort_all();
    let mut r = build(&book, socks.len(), dur.as_secs());
    r.stopped = stopped;
    if stopped {
        if r.hosts.is_empty() {
            r.checks = vec![check(
                AREA,
                "info",
                t!("Ricerca fermata", "Search stopped"),
                t!(
                    "Fermata prima di qualsiasi risposta",
                    "Stopped before any reply"
                ),
            )];
        } else {
            r.checks.push(check(
                AREA,
                "info",
                t!("Ricerca fermata", "Search stopped"),
                t!(
                    "L'elenco è parziale: ascolto interrotto dall'utente",
                    "The list is partial: listening was stopped by the user"
                ),
            ));
        }
    }
    Ok(r)
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, PTR, SRV, TXT};
    use hickory_proto::rr::Record;
    use tokio::net::UdpSocket;

    /// Name from dotted text; labels may contain spaces (instance names do).
    fn name(s: &str) -> Name {
        let mut n =
            Name::from_labels(s.trim_end_matches('.').split('.').map(|l| l.as_bytes())).unwrap();
        n.set_fqdn(true);
        n
    }

    /// Lowercase dotted text of a name, labels unescaped.
    fn plain(n: &Name) -> String {
        n.iter()
            .map(|l| String::from_utf8_lossy(l).to_lowercase() + ".")
            .collect()
    }

    fn response(records: Vec<(&str, RData)>) -> Message {
        let mut m = Message::new();
        m.set_message_type(MessageType::Response);
        for (n, d) in records {
            m.add_answer(Record::from_rdata(name(n), 10, d));
        }
        m
    }

    fn printer() -> Vec<(&'static str, RData)> {
        vec![
            (META, RData::PTR(PTR(name("_ipp._tcp.local.")))),
            (
                "_ipp._tcp.local.",
                RData::PTR(PTR(name("Office printer._ipp._tcp.local."))),
            ),
            (
                "Office printer._ipp._tcp.local.",
                RData::SRV(SRV::new(0, 0, 631, name("printer1.local."))),
            ),
            (
                "Office printer._ipp._tcp.local.",
                RData::TXT(TXT::new(vec![
                    "rp=ipp/print".into(),
                    "ty=Example 5000".into(),
                ])),
            ),
            (
                "printer1.local.",
                RData::A(A::from(Ipv4Addr::new(192, 0, 2, 10))),
            ),
            (
                "printer1.local.",
                RData::AAAA(AAAA::from(
                    "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap(),
                )),
            ),
        ]
    }

    #[test]
    fn instance_and_type_names() {
        assert_eq!(
            split_instance(&name("Office printer._ipp._tcp.local.")),
            Some(("Office printer".into(), "_ipp._tcp".into()))
        );
        assert_eq!(
            split_type(&name("_ipp._tcp.local.")),
            Some("_ipp._tcp".into())
        );
        assert_eq!(split_instance(&name("_ipp._tcp.local.")), None);
        assert_eq!(split_type(&name("host.example.com.")), None);
        assert_eq!(split_instance(&name("a._ipp._tcp.example.com.")), None);
    }

    #[test]
    fn book_collects_a_whole_service() {
        let mut b = Book::default();
        assert!(b.ingest(&response(printer()), "192.0.2.10".parse().unwrap()));
        // the same packet again teaches nothing
        assert!(!b.ingest(&response(printer()), "192.0.2.10".parse().unwrap()));
        let r = build(&b, 1, 5);
        assert_eq!((r.n_hosts, r.n_services, r.n_types), (1, 1, 1));
        let h = &r.hosts[0];
        assert_eq!(h.name, "printer1.local");
        assert_eq!(h.addrs, vec!["192.0.2.10", "2001:db8::10"]);
        let s = &h.services[0];
        assert_eq!(
            (s.instance.as_str(), s.kind.as_str(), s.port),
            ("Office printer", "_ipp._tcp", 631)
        );
        assert_eq!(s.txt, vec!["rp=ipp/print", "ty=Example 5000"]);
        assert_eq!(s.label, "Stampante (IPP)");
        assert!(r
            .csv
            .contains("printer1.local;192.0.2.10 2001:db8::10;Office printer;_ipp._tcp"));
    }

    #[test]
    fn goodbye_records_and_queries_are_ignored() {
        let mut b = Book::default();
        let mut bye = Message::new();
        bye.set_message_type(MessageType::Response);
        bye.add_answer(Record::from_rdata(
            name(META),
            0,
            RData::PTR(PTR(name("_ssh._tcp.local."))),
        ));
        assert!(!b.ingest(&bye, "192.0.2.1".parse().unwrap()));
        let mut q = response(printer());
        q.set_message_type(MessageType::Query);
        assert!(!b.ingest(&q, "192.0.2.1".parse().unwrap()));
        assert!(b.insts.is_empty() && b.types.is_empty());
    }

    #[test]
    fn follow_up_questions_follow_what_is_missing() {
        let mut b = Book::default();
        let mut only_ptr = printer();
        only_ptr.truncate(2);
        b.ingest(&response(only_ptr), "192.0.2.10".parse().unwrap());
        let q: Vec<(String, RecordType)> = b
            .queries()
            .into_iter()
            .map(|(n, t)| (plain(&n), t))
            .collect();
        assert!(q.contains(&("_services._dns-sd._udp.local.".into(), RecordType::PTR)));
        assert!(q.contains(&("_ipp._tcp.local.".into(), RecordType::PTR)));
        assert!(q.contains(&("office printer._ipp._tcp.local.".into(), RecordType::SRV)));
        assert!(q.iter().any(|x| x.1 == RecordType::TXT));
        assert!(!q.iter().any(|x| x.1 == RecordType::A));
        // after the SRV the host addresses are asked for
        b.ingest(
            &response(printer()[2..3].to_vec()),
            "192.0.2.10".parse().unwrap(),
        );
        let q: Vec<RecordType> = b.queries().into_iter().map(|x| x.1).collect();
        assert!(q.contains(&RecordType::A) && q.contains(&RecordType::AAAA));
        assert!(!q.contains(&RecordType::SRV));
    }

    #[test]
    fn checks_for_exposed_services_and_no_reply() {
        let mut b = Book::default();
        let r = build(&b, 2, 5);
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].status, "warn");
        assert!(r.checks[0].detail.contains("UDP 5353"));

        let mut recs = printer();
        recs.push((
            "_telnet._tcp.local.",
            RData::PTR(PTR(name("sw1._telnet._tcp.local."))),
        ));
        recs.push((
            "sw1._telnet._tcp.local.",
            RData::SRV(SRV::new(0, 0, 23, name("sw1.local."))),
        ));
        recs.push((META, RData::PTR(PTR(name("_telnet._tcp.local.")))));
        b.ingest(&response(recs), "192.0.2.20".parse().unwrap());
        let r = build(&b, 1, 5);
        assert!(r
            .checks
            .iter()
            .any(|c| c.status == "warn" && c.detail.contains("sw1.local (_telnet._tcp)")));
        // sw1 has no TXT and no address: the responder's one is used
        let sw = r.hosts.iter().find(|h| h.name == "sw1.local").unwrap();
        assert_eq!(sw.addrs, vec!["192.0.2.20"]);
        assert!(r.checks.iter().any(|c| c.name == "Host senza indirizzo"));
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let r = build(&Book::default(), 1, 5);
        assert_eq!(r.checks[0].name, "No reply");
        assert!(!r.checks[0].detail.contains("Nessun"));
        assert_eq!(type_label("_ipp._tcp"), "Printer (IPP)");
        assert!(r.csv.starts_with("Host;Addresses;"));
    }

    #[tokio::test]
    async fn duration_out_of_range() {
        let e = run(BonjourReq { seconds: Some(1) }, &Stop::new())
            .await
            .unwrap_err();
        assert_eq!(e, "Durata: da 2 a 30 s");
        let e = run(BonjourReq { seconds: Some(31) }, &Stop::new())
            .await
            .unwrap_err();
        assert!(e.contains("2 a 30"));
    }

    /// Fake responder: answers every question separately (no additional records),
    /// so the whole follow-up chain (types, instances, SRV/TXT, addresses) is exercised.
    async fn responder() -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2000];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let qn = plain(q.queries()[0].name());
                let rt = q.queries()[0].query_type();
                let mut rs: Vec<(&str, RData)> = Vec::new();
                let all = printer();
                match (qn.as_str(), rt) {
                    ("_services._dns-sd._udp.local.", RecordType::PTR) => {
                        rs.push((META, RData::PTR(PTR(name("_ipp._tcp.local.")))));
                        rs.push((META, RData::PTR(PTR(name("_ssh._tcp.local.")))));
                    }
                    ("_ipp._tcp.local.", RecordType::PTR) => rs.push(all[1].clone()),
                    ("office printer._ipp._tcp.local.", RecordType::SRV) => rs.push(all[2].clone()),
                    ("office printer._ipp._tcp.local.", RecordType::TXT) => rs.push(all[3].clone()),
                    ("printer1.local.", RecordType::A) => rs.push(all[4].clone()),
                    ("printer1.local.", RecordType::AAAA) => rs.push(all[5].clone()),
                    _ => {}
                }
                if rs.is_empty() {
                    continue;
                }
                let mut m = response(rs);
                m.add_query(q.queries()[0].clone());
                let _ = udp.send_to(&m.to_vec().unwrap(), from).await;
            }
        });
        addr
    }

    fn env(dest: SocketAddr) -> Env {
        Env {
            dest,
            locals: vec![Ipv4Addr::LOCALHOST],
            multicast: false,
            step: Duration::from_millis(30),
        }
    }

    #[tokio::test]
    async fn complete_browse_against_a_fake_responder() {
        let dest = responder().await;
        let r = run_with(Duration::from_millis(1500), env(dest), &Stop::new())
            .await
            .unwrap();
        assert_eq!(r.n_hosts, 1, "{r:?}");
        let h = &r.hosts[0];
        assert_eq!(h.name, "printer1.local");
        assert_eq!(h.addrs, vec!["192.0.2.10", "2001:db8::10"]);
        assert_eq!(h.services[0].port, 631);
        assert_eq!(h.services[0].txt[0], "rp=ipp/print");
        // _ssh._tcp was announced but has no instance
        let ssh = r.types.iter().find(|t| t.kind == "_ssh._tcp").unwrap();
        assert_eq!(ssh.count, 0);
        assert_eq!(r.n_ifaces, 1);
        assert!(r.checks.iter().any(|c| c.status == "ok"));
    }

    #[tokio::test]
    async fn silent_network_gives_a_warning_not_an_error() {
        // a socket that never answers
        let quiet = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r = run_with(
            Duration::from_millis(300),
            env(quiet.local_addr().unwrap()),
            &Stop::new(),
        )
        .await
        .unwrap();
        assert_eq!(r.n_services, 0);
        assert_eq!(r.checks[0].status, "warn");
    }

    #[tokio::test]
    async fn no_adapter_is_an_error() {
        let e = run_with(
            Duration::from_millis(100),
            Env {
                dest: MDNS,
                locals: vec![],
                multicast: true,
                step: Duration::from_millis(30),
            },
            &Stop::new(),
        )
        .await
        .unwrap_err();
        assert!(e.contains("scheda"));
    }

    #[tokio::test]
    async fn stop_ends_the_listening_early() {
        let quiet = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stop = Stop::new();
        let s2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            s2.stop();
        });
        let t = std::time::Instant::now();
        let r = run_with(
            Duration::from_secs(20),
            env(quiet.local_addr().unwrap()),
            &stop,
        )
        .await
        .unwrap();
        assert!(t.elapsed() < Duration::from_secs(3));
        assert!(r.stopped);
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].name, "Ricerca fermata");
    }
}
