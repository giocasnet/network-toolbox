//! Domain analysis: main records, delegation (registry and zone, one name server
//! at a time), DNSSEC and, on request, zone transfer.
//!
//! Three sources: this PC's DNS (records), the name servers of the domain and of the
//! parent zone queried directly (delegation, serials, DS) and a public resolver that
//! validates DNSSEC (same query, normal and with the CD bit). If port 53 towards the
//! outside is closed from the PC's network, direct queries do not get through: the
//! analysis says so and carries on with the PC's DNS only. Signatures are not verified
//! by the app: it checks that DS, keys and expiry dates are consistent.

use super::rdata::{self, Dnskey, Ds, Nsec3Param, Rrsig};
use super::{query_any_with, query_with, record_value, status_name, Opts};
use crate::http::analyze::{Check, ERR, INFO, OK, WARN};
use crate::{net, t, tf, util, Result};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Public resolvers that validate DNSSEC, in the order they are tried.
pub const VALIDATORS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];
/// Maximum time for a direct query (UDP, then TCP).
const DIRECT: Duration = Duration::from_secs(2);
const MAX_NS: usize = 13;

const A_DEL: &str = "Delega";
const A_SOA: &str = "SOA";
const A_SEC: &str = "DNSSEC";
const A_REC: &str = "Record";
const A_XFR: &str = "Trasferimento";

/// Like `http::analyze::check`, with the area translated to the current language.
fn check(area: &'static str, status: &'static str, name: &str, detail: impl Into<String>) -> Check {
    let area = match area {
        A_DEL => t!("Delega", "Delegation"),
        A_REC => t!("Record", "Records"),
        A_XFR => t!("Trasferimento", "Transfer"),
        other => other,
    };
    crate::http::analyze::check(area, status, name, detail)
}

#[derive(Debug, Deserialize)]
pub struct DomainReq {
    pub domain: String,
    /// Also tries the zone transfer (AXFR) on every name server.
    #[serde(default)]
    pub axfr: bool,
}

/// Where to send the queries (tests use fake servers on 127.0.0.x).
#[derive(Debug, Clone)]
pub struct Env {
    /// This PC's DNS.
    pub system: Vec<SocketAddr>,
    /// Resolvers that validate DNSSEC.
    pub validators: Vec<SocketAddr>,
    /// Port of the name servers queried directly (53).
    pub port: u16,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Rec {
    #[serde(rename = "type")]
    pub rtype: String,
    /// Empty if the record belongs to the domain itself.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct NsInfo {
    pub name: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// Delegated by the parent zone; `None` if the parent zone was not reached.
    pub parent: Option<bool>,
    /// Declared by the zone itself.
    pub zone: bool,
    pub responds: bool,
    pub authoritative: bool,
    pub serial: Option<u32>,
    pub time_ms: Option<u64>,
    /// "ok", "warn", "err", "info"
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// AXFR outcome: `None` if not tried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axfr: Option<bool>,
    #[serde(skip)]
    pub rcode: String,
    #[serde(skip)]
    pub recursion: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Row {
    pub status: &'static str,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub what: String,
    pub detail: String,
}

fn row(
    status: &'static str,
    name: impl Into<String>,
    what: impl Into<String>,
    detail: impl Into<String>,
) -> Row {
    Row {
        status,
        name: name.into(),
        what: what.into(),
        detail: detail.into(),
    }
}

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct Dnssec {
    /// "Signed and valid", "Unsigned", "Invalid"…
    pub label: String,
    /// "ok", "warn", "err" or empty (unsigned)
    pub level: &'static str,
    /// DS, keys, signatures, denial of existence.
    pub rows: Vec<Row>,
    /// Answers of the validating resolver and of the PC's DNS.
    pub validation: Vec<Row>,
}

#[derive(Debug, Serialize)]
pub struct DomainResult {
    /// Zone analysed.
    pub domain: String,
    /// Why the zone is not the name typed by the user (empty if they coincide).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub zone_note: String,
    pub checks: Vec<Check>,
    pub records: Vec<Rec>,
    /// Types asked for that got no answer.
    pub empty_types: Vec<String>,
    pub nameservers: Vec<NsInfo>,
    /// Parent zone ("com") and whether its name servers answered the direct queries.
    pub parent: String,
    pub parent_ok: bool,
    pub dnssec: Dnssec,
    pub addresses: Vec<String>,
    pub time_ms: u64,
}

/// Values of the SOA record.
#[derive(Debug, Clone, PartialEq)]
pub struct Soa {
    pub mname: String,
    pub serial: u32,
    pub refresh: i64,
    pub retry: i64,
    pub expire: i64,
    pub minimum: i64,
}

/// Answers of the validating resolver.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Validation {
    /// Address of the resolver used (empty if none answered).
    pub resolver: String,
    /// Normal query: response code and AD flag.
    pub normal: Option<(String, bool)>,
    /// Same query with the CD bit.
    pub cd: Option<String>,
    /// AD flag in the answer of the PC's DNS.
    pub system_ad: Option<bool>,
}

fn same(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

fn host_of(n: &hickory_proto::rr::Name) -> String {
    n.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

fn of_type(recs: &[Record], t: RecordType) -> impl Iterator<Item = &Record> {
    recs.iter().filter(move |r| r.record_type() == t)
}

fn raw_of(r: &Record) -> Option<&[u8]> {
    match &r.data {
        RData::Unknown { rdata, .. } => Some(&rdata.anything),
        _ => None,
    }
}

fn days_text(n: i64) -> String {
    if n == 1 {
        t!("1 giorno", "1 day").into()
    } else {
        tf!("{n} giorni", "{n} days")
    }
}

const MONTHS: [&str; 12] = [
    "gennaio",
    "febbraio",
    "marzo",
    "aprile",
    "maggio",
    "giugno",
    "luglio",
    "agosto",
    "settembre",
    "ottobre",
    "novembre",
    "dicembre",
];

const MONTHS_EN: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// "19 novembre 2026" (UTC); in English "19 November 2026".
pub fn date_it(secs: i64) -> String {
    let (y, m, d, ..) = util::civil(secs);
    let i = (m as usize).clamp(1, 12) - 1;
    format!("{d} {} {y}", t!(MONTHS[i], MONTHS_EN[i]))
}

fn names_list(v: &[String]) -> String {
    if v.is_empty() {
        t!("nessuno", "none").into()
    } else {
        v.join(", ")
    }
}

// ───────────────────────── checks (pure functions) ─────────────────────────

/// Delegation checks; fills in `status` and `note` of every name server.
/// `parent_known`: the parent zone answered the direct queries. `axfr`: test requested.
pub fn delegation_checks(ns: &mut [NsInfo], parent_known: bool, axfr: bool) -> Vec<Check> {
    let mut out = Vec::new();
    for n in ns.iter_mut() {
        n.status = OK;
        n.note.clear();
    }
    let probed = ns.iter().filter(|n| !n.ipv4.is_empty()).count();
    let up = ns.iter().filter(|n| n.responds).count();

    // nobody answers, not even the parent zone: it is the PC's network, not the domain
    let blocked = up == 0 && !parent_known;
    if blocked {
        for n in ns.iter_mut() {
            n.status = INFO;
            n.note = t!(
                "Non raggiungibile da questo PC.",
                "Not reachable from this PC."
            )
            .into();
        }
        out.push(check(
            A_DEL,
            INFO,
            t!("Name server", "Name servers"),
            t!(
                "nessun name server raggiungibile da questo PC (porta 53 verso l'esterno chiusa?): \
             delega letta solo dal DNS del PC, seriali e risposte autoritative non controllati",
                "no name server reachable from this PC (port 53 to the outside closed?): \
             delegation read from the PC's DNS only, serials and authoritative answers not checked"
            ),
        ));
    }

    for n in ns.iter_mut() {
        if n.ipv4.is_empty() && n.ipv6.is_empty() {
            n.status = ERR;
            n.note = t!("Il nome non ha indirizzi.", "The name has no addresses.").into();
            out.push(check(
                A_DEL,
                ERR,
                t!("Name server", "Name servers"),
                tf!(
                    "{} non ha indirizzi (né A né AAAA)",
                    "{} has no addresses (neither A nor AAAA)",
                    n.name
                ),
            ));
        } else if n.ipv4.is_empty() {
            n.status = INFO;
            n.note = t!(
                "Solo IPv6: non interrogato (l'app usa IPv4).",
                "IPv6 only: not queried (the app uses IPv4)."
            )
            .into();
        } else if !n.responds && !blocked {
            n.status = ERR;
            n.note = t!(
                "Non risponde da questo PC (UDP e TCP 53).",
                "No answer from this PC (UDP and TCP 53)."
            )
            .into();
            out.push(check(
                A_DEL,
                ERR,
                t!("Name server", "Name servers"),
                tf!(
                    "{} ({}) non risponde da questo PC, né su UDP né su TCP",
                    "{} ({}) does not answer from this PC, on neither UDP nor TCP",
                    n.name,
                    n.ipv4[0]
                ),
            ));
        } else if n.responds && (!n.authoritative || n.rcode != "NOERROR") {
            n.status = ERR;
            n.note = tf!(
                "Risponde {} senza essere autoritativo.",
                "Answers {} without being authoritative.",
                n.rcode
            );
            out.push(check(
                A_DEL,
                ERR,
                t!("Delega zoppa", "Lame delegation"),
                tf!(
                    "{} risponde {} ma non è autoritativo per la zona",
                    "{} answers {} but is not authoritative for the zone",
                    n.name,
                    n.rcode
                ),
            ));
        }
    }

    // serials: who is behind the most recent one
    let good: Vec<&NsInfo> = ns
        .iter()
        .filter(|n| n.responds && n.authoritative && n.serial.is_some())
        .collect();
    let newest = good.iter().filter_map(|n| n.serial).max();
    let behind: Vec<String> = good
        .iter()
        .filter(|n| n.serial != newest)
        .map(|n| tf!("{} ha {}", "{} has {}", n.name, n.serial.unwrap_or(0)))
        .collect();
    if let Some(top) = newest {
        if behind.is_empty() {
            if good.len() > 1 {
                out.push(check(
                    A_DEL,
                    OK,
                    t!("Seriale SOA", "SOA serial"),
                    tf!(
                        "uguale su tutti i name server che rispondono ({top})",
                        "the same on all name servers that answer ({top})"
                    ),
                ));
            }
        } else {
            out.push(check(
                A_DEL,
                ERR,
                t!("Seriale SOA", "SOA serial"),
                tf!(
                    "{}, gli altri {top}: zona non allineata",
                    "{}, the others {top}: zone out of sync",
                    behind.join(", ")
                ),
            ));
            for n in ns.iter_mut() {
                if n.responds && n.authoritative && n.serial.is_some() && n.serial != newest {
                    n.status = ERR;
                    n.note = t!(
                        "Seriale più vecchio degli altri: la zona non è allineata.",
                        "Serial older than the others: the zone is out of sync."
                    )
                    .into();
                }
            }
        }
    }

    // registry and zone
    if parent_known {
        let reg: Vec<String> = ns
            .iter()
            .filter(|n| n.parent == Some(true))
            .map(|n| n.name.clone())
            .collect();
        let zone: Vec<String> = ns
            .iter()
            .filter(|n| n.zone)
            .map(|n| n.name.clone())
            .collect();
        let differ = ns.iter().any(|n| (n.parent == Some(true)) != n.zone);
        if differ && !zone.is_empty() {
            out.push(check(
                A_DEL,
                WARN,
                t!("NS del registro e della zona", "Registry and zone NS"),
                tf!(
                    "il registro delega a {}; la zona dichiara {}",
                    "the registry delegates to {}; the zone declares {}",
                    names_list(&reg),
                    names_list(&zone)
                ),
            ));
            for n in ns.iter_mut() {
                let extra = if n.parent == Some(true) && !n.zone {
                    t!(
                        "Delegato dal registro ma non dichiarato dalla zona.",
                        "Delegated by the registry but not declared by the zone."
                    )
                } else if n.parent != Some(true) && n.zone {
                    t!(
                        "Dichiarato dalla zona ma non delegato dal registro.",
                        "Declared by the zone but not delegated by the registry."
                    )
                } else {
                    continue;
                };
                if n.status == OK {
                    n.status = WARN;
                    n.note = extra.into();
                } else if n.status == ERR {
                    n.note = format!("{} {extra}", n.note);
                }
            }
        } else if !zone.is_empty() {
            out.push(check(
                A_DEL,
                OK,
                t!("NS del registro e della zona", "Registry and zone NS"),
                t!("gli stessi name server", "the same name servers"),
            ));
        }
    }

    if ns.len() == 1 {
        out.push(check(
            A_DEL,
            WARN,
            t!("Numero", "Count"),
            t!(
                "un solo name server: se si ferma, il dominio sparisce",
                "only one name server: if it stops, the domain disappears"
            ),
        ));
    }
    // distinct /24 networks
    let mut nets: Vec<[u8; 3]> = ns
        .iter()
        .flat_map(|n| n.ipv4.iter())
        .filter_map(|a| a.parse::<Ipv4Addr>().ok())
        .map(|a| {
            let o = a.octets();
            [o[0], o[1], o[2]]
        })
        .collect();
    nets.sort();
    nets.dedup();
    if ns.len() > 1 && nets.len() == 1 {
        let n = nets[0];
        out.push(check(
            A_DEL,
            WARN,
            t!("Reti", "Networks"),
            tf!(
                "tutti i name server stanno sulla stessa rete ({}.{}.{}.0/24)",
                "all name servers are on the same network ({}.{}.{}.0/24)",
                n[0],
                n[1],
                n[2]
            ),
        ));
    } else if nets.len() > 1 {
        out.push(check(
            A_DEL,
            OK,
            t!("Reti", "Networks"),
            tf!(
                "i name server stanno su {} reti diverse",
                "the name servers are on {} different networks",
                nets.len()
            ),
        ));
    }

    if up > 0 && up == probed && out.iter().all(|c| c.status != ERR) {
        out.push(check(
            A_DEL,
            OK,
            t!("Name server", "Name servers"),
            tf!(
                "{up} su {probed} rispondono e sono autoritativi",
                "{up} of {probed} answer and are authoritative"
            ),
        ));
    }
    let open: Vec<String> = ns
        .iter()
        .filter(|n| n.responds && n.recursion)
        .map(|n| n.name.clone())
        .collect();
    if !open.is_empty() {
        out.push(check(
            A_DEL,
            INFO,
            t!("Ricorsione", "Recursion"),
            tf!(
                "{} dichiara di offrire anche la ricorsione (flag RA)",
                "{} states that it also offers recursion (RA flag)",
                open.join(", ")
            ),
        ));
    }

    // zone transfer
    if !axfr {
        out.push(check(
            A_XFR,
            INFO,
            "AXFR",
            t!("non provato (casella spenta)", "not tried (box unchecked)"),
        ));
    } else {
        let allowed: Vec<String> = ns
            .iter()
            .filter(|n| n.axfr == Some(true))
            .map(|n| n.name.clone())
            .collect();
        let tried = ns.iter().filter(|n| n.axfr.is_some()).count();
        if !allowed.is_empty() {
            out.push(check(
                A_XFR,
                ERR,
                "AXFR",
                tf!(
                    "trasferimento di zona consentito a chiunque da {}",
                    "zone transfer allowed to anyone by {}",
                    allowed.join(", ")
                ),
            ));
        } else if tried > 0 {
            out.push(check(
                A_XFR,
                OK,
                "AXFR",
                tf!(
                    "rifiutato da tutti i name server provati ({tried})",
                    "refused by all name servers tried ({tried})"
                ),
            ));
        } else {
            out.push(check(
                A_XFR,
                INFO,
                "AXFR",
                t!(
                    "non provabile: nessun name server raggiungibile",
                    "cannot be tried: no name server reachable"
                ),
            ));
        }
    }
    out
}

/// Checks on the SOA values; `ns` = names of the zone's name servers.
pub fn soa_checks(soa: &Soa, ns: &[String]) -> Vec<Check> {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    if soa.retry >= soa.refresh {
        bad.push(tf!(
            "retry ({}) non inferiore a refresh ({})",
            "retry ({}) not lower than refresh ({})",
            soa.retry,
            soa.refresh
        ));
    }
    if soa.expire < 604_800 {
        bad.push(tf!(
            "expire di {} s: meno di 7 giorni",
            "expire of {} s: less than 7 days",
            soa.expire
        ));
    }
    if soa.expire <= soa.refresh {
        bad.push(
            t!(
                "expire non superiore a refresh",
                "expire not higher than refresh"
            )
            .to_string(),
        );
    }
    if soa.minimum > 86_400 {
        bad.push(tf!(
            "minimo di {} s: le risposte negative restano in cache più di un giorno",
            "minimum of {} s: negative answers stay cached for more than a day",
            soa.minimum
        ));
    }
    let values = tf!(
        "refresh {}, retry {}, expire {}, minimo {}",
        "refresh {}, retry {}, expire {}, minimum {}",
        soa.refresh,
        soa.retry,
        soa.expire,
        soa.minimum
    );
    if bad.is_empty() {
        out.push(check(A_SOA, OK, t!("Valori", "Values"), values));
    } else {
        out.push(check(A_SOA, WARN, t!("Valori", "Values"), bad.join("; ")));
    }
    if !ns.is_empty() && !ns.iter().any(|n| same(n, &soa.mname)) {
        out.push(check(
            A_SOA,
            INFO,
            t!("Primario", "Primary"),
            tf!(
                "{} non è fra i name server pubblicati (primario nascosto)",
                "{} is not among the published name servers (hidden primary)",
                soa.mname.trim_end_matches('.')
            ),
        ));
    }
    out
}

/// Checks on the records read from the PC's DNS.
pub fn record_checks(records: &[Rec], wildcard: bool, domain: &str) -> Vec<Check> {
    let mut out = Vec::new();
    let has = |t: &str| records.iter().any(|r| r.rtype == t && r.name.is_empty());
    if let Some(ttl) = records
        .iter()
        .filter(|r| (r.rtype == "A" || r.rtype == "AAAA") && r.name.is_empty())
        .map(|r| r.ttl)
        .min()
        .filter(|t| *t < 60)
    {
        out.push(check(
            A_REC,
            INFO,
            "TTL",
            tf!(
                "indirizzi con TTL di {ttl} secondi: molto basso",
                "addresses with a TTL of {ttl} seconds: very low"
            ),
        ));
    }
    if wildcard {
        out.push(check(
            A_REC,
            INFO,
            t!("Jolly", "Wildcard"),
            tf!(
                "*.{domain} risponde: ogni nome inesistente viene risolto",
                "*.{domain} answers: every nonexistent name gets resolved"
            ),
        ));
    }
    let caa: Vec<&str> = records
        .iter()
        .filter(|r| r.rtype == "CAA")
        .map(|r| r.value.as_str())
        .collect();
    if caa.is_empty() {
        out.push(check(
            A_REC,
            INFO,
            "CAA",
            t!(
                "assente: qualsiasi autorità può emettere certificati per il dominio",
                "missing: any authority can issue certificates for the domain"
            ),
        ));
    } else {
        out.push(check(
            A_REC,
            OK,
            "CAA",
            tf!("presente: {}", "present: {}", caa.join("; ")),
        ));
    }
    if has("A") || has("AAAA") {
        if has("AAAA") {
            out.push(check(
                A_REC,
                OK,
                "IPv6",
                t!("record AAAA presente", "AAAA record present"),
            ));
        } else {
            out.push(check(
                A_REC,
                INFO,
                "IPv6",
                t!("nessun record AAAA", "no AAAA record"),
            ));
        }
    }
    out
}

/// DNSSEC state and related checks. `sigs` = signatures read (covered type included).
pub fn dnssec(
    domain: &str,
    ds: &[Ds],
    keys: &[Dnskey],
    sigs: &[Rrsig],
    nsec3: Option<&Nsec3Param>,
    v: &Validation,
    now: i64,
) -> (Dnssec, Vec<Check>) {
    let mut d = Dnssec::default();
    let mut out = Vec::new();
    let mut broken = false;
    let mut weak = false;

    // validation: rows common to all cases
    let signed_chain = !ds.is_empty();
    match &v.normal {
        None => d.validation.push(row(
            INFO,
            t!("Resolver che valida", "Validating resolver"),
            "",
            t!(
                "non raggiungibile da questo PC: validazione non controllata",
                "not reachable from this PC: validation not checked"
            ),
        )),
        Some((rcode, ad)) => {
            let who = tf!(
                "Resolver che valida ({})",
                "Validating resolver ({})",
                v.resolver
            );
            let cd =
                v.cd.clone()
                    .unwrap_or_else(|| t!("nessuna risposta", "no answer").into());
            if rcode == "SERVFAIL" && cd == "NOERROR" {
                broken = true;
                d.validation.push(row(
                    ERR,
                    tf!("{who}, query normale", "{who}, normal query"),
                    "",
                    t!(
                        "SERVFAIL: la validazione fallisce",
                        "SERVFAIL: validation fails"
                    ),
                ));
                d.validation.push(row(
                    INFO,
                    tf!("{who}, con CD", "{who}, with CD"),
                    "",
                    t!(
                        "NOERROR: senza validazione il dominio risponde",
                        "NOERROR: without validation the domain answers"
                    ),
                ));
                out.push(check(
                    A_SEC,
                    ERR,
                    t!("Validazione", "Validation"),
                    t!(
                        "fallisce: chi usa un resolver che valida DNSSEC non risolve il dominio \
                     (SERVFAIL, mentre con il bit CD la risposta arriva)",
                        "fails: anyone using a DNSSEC-validating resolver cannot resolve the domain \
                     (SERVFAIL, while with the CD bit the answer arrives)"
                    ),
                ));
            } else if rcode == "NOERROR" && *ad {
                d.validation.push(row(
                    OK,
                    tf!("{who}, query normale", "{who}, normal query"),
                    "",
                    t!(
                        "NOERROR con flag AD: la catena è valida",
                        "NOERROR with AD flag: the chain is valid"
                    ),
                ));
                d.validation.push(row(
                    if cd == "NOERROR" { OK } else { INFO },
                    tf!("{who}, con CD", "{who}, with CD"),
                    "",
                    tf!(
                        "{cd}: stessa risposta senza validazione",
                        "{cd}: same answer without validation"
                    ),
                ));
                out.push(check(
                    A_SEC,
                    OK,
                    t!("Validazione", "Validation"),
                    t!(
                        "il resolver che valida risponde con il flag AD",
                        "the validating resolver answers with the AD flag"
                    ),
                ));
            } else {
                let st = if signed_chain && rcode == "NOERROR" {
                    weak = true;
                    WARN
                } else {
                    INFO
                };
                d.validation.push(row(
                    st,
                    tf!("{who}, query normale", "{who}, normal query"),
                    "",
                    tf!(
                        "{rcode} senza flag AD{}",
                        "{rcode} without AD flag{}",
                        if signed_chain {
                            t!(
                                ": la zona ha un DS ma la risposta non risulta validata",
                                ": the zone has a DS but the answer is not validated"
                            )
                        } else {
                            t!(
                                ": zona non firmata, niente da validare",
                                ": zone not signed, nothing to validate"
                            )
                        }
                    ),
                ));
                d.validation.push(row(
                    INFO,
                    tf!("{who}, con CD", "{who}, with CD"),
                    "",
                    cd.clone(),
                ));
                if st == WARN {
                    out.push(check(
                        A_SEC,
                        WARN,
                        t!("Validazione", "Validation"),
                        t!(
                            "il resolver che valida risponde senza flag AD nonostante il DS",
                            "the validating resolver answers without the AD flag despite the DS"
                        ),
                    ));
                }
            }
        }
    }
    if let Some(ad) = v.system_ad {
        d.validation.push(row(
            INFO,
            t!("DNS di questo PC", "This PC's DNS"),
            "",
            if ad {
                t!(
                    "risponde con il flag AD: valida DNSSEC",
                    "answers with the AD flag: it validates DNSSEC"
                )
            } else {
                t!(
                    "risponde senza flag AD: non valida (o non lo dichiara)",
                    "answers without the AD flag: it does not validate (or does not say so)"
                )
            },
        ));
    }

    if ds.is_empty() && keys.is_empty() {
        d.label = t!("Non firmato", "Unsigned").into();
        out.insert(
            0,
            check(
                A_SEC,
                INFO,
                "DNSSEC",
                t!(
                    "zona non firmata: nessun DS e nessuna chiave",
                    "zone not signed: no DS and no key"
                ),
            ),
        );
        return (d, out);
    }

    // DS and keys
    let mut matched: Vec<u16> = Vec::new();
    for x in ds {
        let hit = keys
            .iter()
            .find(|k| k.tag == x.tag && k.algorithm == x.algorithm);
        let what = tf!(
            "id {} · algoritmo {} · digest {}",
            "id {} · algorithm {} · digest {}",
            x.tag,
            x.algorithm,
            rdata::digest_name(x.digest_type)
        );
        match hit.map(|k| (k, rdata::ds_matches(x, domain, k))) {
            Some((k, Some(true))) => {
                matched.push(k.tag);
                d.rows.push(row(
                    OK,
                    t!("DS nel registro", "DS in the registry"),
                    what,
                    tf!("corrisponde alla chiave {}", "matches key {}", k.tag),
                ));
            }
            Some((k, None)) => {
                matched.push(k.tag);
                d.rows.push(row(
                    INFO,
                    t!("DS nel registro", "DS in the registry"),
                    what,
                    tf!(
                        "chiave {} presente; digest non calcolabile dall'app",
                        "key {} present; digest cannot be computed by the app",
                        k.tag
                    ),
                ));
            }
            Some((_, Some(false))) => d.rows.push(row(
                ERR,
                t!("DS nel registro", "DS in the registry"),
                what,
                t!(
                    "il digest non corrisponde alla chiave con lo stesso id",
                    "the digest does not match the key with the same id"
                ),
            )),
            None => d.rows.push(row(
                if keys.is_empty() { ERR } else { WARN },
                t!("DS nel registro", "DS in the registry"),
                what,
                t!(
                    "nessuna chiave della zona con questo id",
                    "no zone key with this id"
                ),
            )),
        }
    }
    for k in keys {
        let (alg, _) = rdata::algorithm(k.algorithm);
        d.rows.push(row(
            if k.revoked() { WARN } else { OK },
            format!("DNSKEY {}", k.tag),
            format!("{} ({}) · {alg}", k.role(), k.flags),
            if k.revoked() {
                t!("revocata", "revoked")
            } else if k.sep() {
                t!("firma le chiavi della zona", "signs the zone's keys")
            } else {
                t!("firma i record", "signs the records")
            },
        ));
    }

    if ds.is_empty() {
        weak = true;
        out.push(check(
            A_SEC,
            WARN,
            "DS",
            t!(
                "la zona è firmata ma il registro non pubblica il DS: i resolver non la validano",
                "the zone is signed but the registry does not publish the DS: resolvers do not validate it"
            ),
        ));
    } else if keys.is_empty() {
        broken = true;
        out.push(check(
            A_SEC,
            ERR,
            t!("DS e DNSKEY", "DS and DNSKEY"),
            t!(
                "il registro pubblica un DS ma la zona non ha chiavi: per i resolver che validano \
             il dominio non risolve",
                "the registry publishes a DS but the zone has no keys: for validating resolvers \
             the domain does not resolve"
            ),
        ));
    } else if matched.is_empty() {
        broken = true;
        out.push(check(
            A_SEC,
            ERR,
            t!("DS e DNSKEY", "DS and DNSKEY"),
            t!(
                "nessun DS del registro corrisponde a una chiave della zona",
                "no DS in the registry matches a zone key"
            ),
        ));
    } else {
        matched.dedup();
        out.push(check(
            A_SEC,
            OK,
            t!("DS e DNSKEY", "DS and DNSKEY"),
            tf!(
                "il DS pubblicato nel registro corrisponde alla chiave {}",
                "the DS published in the registry matches key {}",
                matched
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if !ds.is_empty() && ds.iter().all(|x| x.digest_type == 1) {
        out.push(check(
            A_SEC,
            WARN,
            t!("Digest del DS", "DS digest"),
            t!(
                "solo SHA-1: pubblicare un DS con SHA-256",
                "SHA-1 only: publish a DS with SHA-256"
            ),
        ));
    }

    // algorithms
    let mut algs: Vec<u8> = keys.iter().map(|k| k.algorithm).collect();
    algs.sort();
    algs.dedup();
    for a in algs {
        let (name, old) = rdata::algorithm(a);
        out.push(check(
            A_SEC,
            if old { WARN } else { INFO },
            t!("Algoritmo", "Algorithm"),
            if old {
                tf!(
                    "{a} ({name}): sconsigliato, i resolver possono non validarlo",
                    "{a} ({name}): deprecated, resolvers may not validate it"
                )
            } else {
                format!("{a} ({name})")
            },
        ));
    }

    // signatures
    for s in sigs {
        let t = hickory_proto::rr::RecordType::from(s.covered).to_string();
        let left = s.expiration as i64 - now;
        let what = tf!(
            "chiave {} · valida dal {}",
            "key {} · valid from {}",
            s.tag,
            date_it(s.inception as i64)
        );
        let (st, detail) = if left < 0 {
            broken = true;
            (
                ERR,
                tf!(
                    "scaduta il {}",
                    "expired on {}",
                    date_it(s.expiration as i64)
                ),
            )
        } else if s.inception as i64 > now + 300 {
            broken = true;
            (
                ERR,
                tf!(
                    "non ancora valida: inizia il {}",
                    "not yet valid: starts on {}",
                    date_it(s.inception as i64)
                ),
            )
        } else if left < 86_400 {
            (
                WARN,
                tf!(
                    "scade il {} (tra {} ore)",
                    "expires on {} (in {} hours)",
                    date_it(s.expiration as i64),
                    left / 3600
                ),
            )
        } else {
            (
                OK,
                tf!(
                    "scade il {} ({})",
                    "expires on {} ({})",
                    date_it(s.expiration as i64),
                    days_text(left / 86_400)
                ),
            )
        };
        if st != OK {
            out.push(check(
                A_SEC,
                st,
                t!("Firme", "Signatures"),
                tf!(
                    "la firma del record {t}: {detail}",
                    "the signature of the {t} record: {detail}"
                ),
            ));
        }
        d.rows.push(row(
            st,
            tf!("Firma di {t}", "Signature of {t}"),
            what,
            detail,
        ));
    }
    if !sigs.is_empty() && sigs.iter().all(|s| s.expiration as i64 - now >= 86_400) {
        out.push(check(
            A_SEC,
            OK,
            t!("Firme", "Signatures"),
            t!("in corso di validità", "currently valid"),
        ));
    }

    // denial of existence
    match nsec3 {
        Some(p) => {
            let st = if p.iterations > 100 {
                WARN
            } else if p.iterations > 0 {
                INFO
            } else {
                OK
            };
            let detail = if p.iterations > 0 {
                t!(
                    "consigliate 0 iterazioni (RFC 9276)",
                    "0 iterations recommended (RFC 9276)"
                )
            } else {
                t!(
                    "nomi inesistenti provati senza elencare la zona",
                    "nonexistent names proven without listing the zone"
                )
            };
            d.rows.push(row(
                st,
                t!("Negazione", "Denial of existence"),
                tf!(
                    "NSEC3 · {} iterazioni · {}",
                    "NSEC3 · {} iterations · {}",
                    p.iterations,
                    if p.salt.is_empty() {
                        t!("senza sale", "no salt")
                    } else {
                        t!("con sale", "with salt")
                    }
                ),
                detail,
            ));
            if st != OK {
                out.push(check(
                    A_SEC,
                    st,
                    "NSEC3",
                    tf!(
                        "{} iterazioni: {detail}",
                        "{} iterations: {detail}",
                        p.iterations
                    ),
                ));
            }
        }
        None if !keys.is_empty() => d.rows.push(row(
            INFO,
            t!("Negazione", "Denial of existence"),
            "NSEC",
            t!(
                "nessun NSEC3PARAM: la zona usa NSEC (i nomi si possono elencare)",
                "no NSEC3PARAM: the zone uses NSEC (names can be enumerated)"
            ),
        )),
        None => {}
    }

    (d.label, d.level) = if broken {
        (t!("Non valido", "Invalid").into(), ERR)
    } else if ds.is_empty() {
        (t!("Firmato, senza DS", "Signed, no DS").into(), WARN)
    } else if weak {
        (
            t!("Firmato, non validato", "Signed, not validated").into(),
            WARN,
        )
    } else if matches!(&v.normal, Some((r, true)) if r == "NOERROR") {
        (t!("Firmato e valido", "Signed and valid").into(), OK)
    } else {
        (t!("Firmato", "Signed").into(), OK)
    };
    (d, out)
}

// ───────────────────────── data collection ─────────────────────────

async fn sys(env: &Env, name: &str, t: RecordType, opts: Opts) -> Option<Message> {
    query_any_with(name, t, &env.system, opts)
        .await
        .ok()
        .map(|(m, _, _)| m)
}

/// Direct query to a server: UDP, and TCP if no answer arrives.
async fn direct(
    name: &str,
    t: RecordType,
    addr: SocketAddr,
    opts: Opts,
) -> std::result::Result<(Message, u64), String> {
    let no_rd = Opts {
        no_recursion: true,
        ..opts
    };
    match query_with(name, t, addr, no_rd, DIRECT).await {
        Ok(x) => Ok(x),
        Err(_) => query_with(name, t, addr, Opts { tcp: true, ..no_rd }, DIRECT).await,
    }
}

/// IPv4 and IPv6 addresses of a name, from the PC's DNS.
async fn addresses(env: &Env, name: &str) -> (Vec<String>, Vec<String>) {
    let (a, aaaa) = tokio::join!(
        sys(env, name, RecordType::A, Opts::default()),
        sys(env, name, RecordType::AAAA, Opts::default())
    );
    let pick = |m: Option<Message>, t: RecordType| -> Vec<String> {
        m.map(|m| of_type(&m.answers, t).map(record_value).collect())
            .unwrap_or_default()
    };
    (pick(a, RecordType::A), pick(aaaa, RecordType::AAAA))
}

/// Zone transfer: the first message is enough to know whether it is allowed.
async fn axfr_allowed(domain: &str, addr: SocketAddr) -> Option<bool> {
    let opts = Opts {
        tcp: true,
        no_recursion: true,
        ..Opts::default()
    };
    match query_with(domain, RecordType::AXFR, addr, opts, Duration::from_secs(3)).await {
        Ok((m, _)) => {
            Some(m.metadata.response_code == ResponseCode::NoError && !m.answers.is_empty())
        }
        // connection closed or refused after the request: refused
        Err(e) if e.starts_with("ERRORE") || e.starts_with("ERROR") => Some(false),
        Err(_) => None,
    }
}

/// What a name server says about itself: SOA (serial, flags) and its NS.
async fn probe(domain: &str, mut n: NsInfo, port: u16, axfr: bool) -> (NsInfo, Vec<String>) {
    let mut zone_ns = Vec::new();
    let Some(ip) = n.ipv4.first().and_then(|a| a.parse::<Ipv4Addr>().ok()) else {
        return (n, zone_ns);
    };
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    if let Ok((m, ms)) = direct(domain, RecordType::SOA, addr, Opts::default()).await {
        n.responds = true;
        n.time_ms = Some(ms);
        n.authoritative = m.metadata.authoritative;
        n.recursion = m.metadata.recursion_available;
        n.rcode = status_name(m.metadata.response_code);
        n.serial = of_type(&m.answers, RecordType::SOA).find_map(|r| match &r.data {
            RData::SOA(s) => Some(s.serial),
            _ => None,
        });
        if let Ok((m, _)) = direct(domain, RecordType::NS, addr, Opts::default()).await {
            if m.metadata.authoritative {
                zone_ns = of_type(&m.answers, RecordType::NS)
                    .filter_map(|r| match &r.data {
                        RData::NS(x) => Some(host_of(&x.0)),
                        _ => None,
                    })
                    .collect();
            }
        }
        if axfr {
            n.axfr = axfr_allowed(domain, addr).await;
        }
    }
    (n, zone_ns)
}

/// Delegation as seen from the parent zone: name servers, glue addresses and DS.
struct Referral {
    ns: Vec<String>,
    glue: Vec<(String, IpAddr)>,
    ds: Vec<Ds>,
}

async fn referral(env: &Env, domain: &str, parent: &str) -> Option<Referral> {
    let pq = if parent.is_empty() { "." } else { parent };
    let m = sys(env, pq, RecordType::NS, Opts::default()).await?;
    let names: Vec<String> = of_type(&m.answers, RecordType::NS)
        .filter_map(|r| match &r.data {
            RData::NS(x) => Some(host_of(&x.0)),
            _ => None,
        })
        .take(3)
        .collect();
    for name in names {
        let (v4, _) = addresses(env, &name).await;
        let Some(ip) = v4.first().and_then(|a| a.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let addr = SocketAddr::new(IpAddr::V4(ip), env.port);
        let m = match direct(domain, RecordType::NS, addr, Opts::default()).await {
            Ok((m, _)) => m,
            // no answer on either UDP or TCP: the network does not let DNS out,
            // no point waiting for the other parent-zone servers too
            Err(e) if e == "TIMEOUT" => return None,
            Err(_) => continue,
        };
        let all: Vec<Record> = m
            .answers
            .iter()
            .chain(m.authorities.iter())
            .cloned()
            .collect();
        let ns: Vec<String> = of_type(&all, RecordType::NS)
            .filter(|r| same(&r.name.to_ascii(), domain))
            .filter_map(|r| match &r.data {
                RData::NS(x) => Some(host_of(&x.0)),
                _ => None,
            })
            .collect();
        if ns.is_empty() {
            continue;
        }
        let glue = m
            .additionals
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some((host_of(&r.name), IpAddr::V4(a.0))),
                RData::AAAA(a) => Some((host_of(&r.name), IpAddr::V6(a.0))),
                _ => None,
            })
            .collect();
        let dnssec_on = Opts {
            dnssec: true,
            ..Opts::default()
        };
        let ds = match direct(domain, RecordType::DS, addr, dnssec_on).await {
            Ok((m, _)) => of_type(&m.answers, RecordType::DS)
                .filter_map(|r| raw_of(r).and_then(rdata::ds))
                .collect(),
            Err(_) => vec![],
        };
        return Some(Referral { ns, glue, ds });
    }
    None
}

async fn validation(env: &Env, domain: &str) -> Validation {
    let mut v = Validation::default();
    let ask = Opts {
        dnssec: true,
        ad: true,
        ..Opts::default()
    };
    for r in &env.validators {
        let Ok((m, _)) = query_with(domain, RecordType::SOA, *r, ask, DIRECT).await else {
            continue;
        };
        v.resolver = r.ip().to_string();
        v.normal = Some((
            status_name(m.metadata.response_code),
            m.metadata.authentic_data,
        ));
        let cd = Opts { cd: true, ..ask };
        v.cd = query_with(domain, RecordType::SOA, *r, cd, DIRECT)
            .await
            .ok()
            .map(|(m, _)| status_name(m.metadata.response_code));
        break;
    }
    let ad = Opts {
        ad: true,
        ..Opts::default()
    };
    v.system_ad = sys(env, domain, RecordType::SOA, ad)
        .await
        .map(|m| m.metadata.authentic_data);
    v
}

fn soa_of(r: &Record) -> Option<Soa> {
    match &r.data {
        RData::SOA(s) => Some(Soa {
            mname: host_of(&s.mname),
            serial: s.serial,
            refresh: s.refresh as i64,
            retry: s.retry as i64,
            expire: s.expire as i64,
            minimum: s.minimum as i64,
        }),
        _ => None,
    }
}

/// Types asked of the PC's DNS for the records tab, in the order they are shown.
const SHOWN: [RecordType; 10] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::NS,
    RecordType::SOA,
    RecordType::MX,
    RecordType::TXT,
    RecordType::CAA,
    RecordType::HTTPS,
    RecordType::DNSKEY,
    RecordType::DS,
];

pub async fn analyze(req: DomainReq, env: &Env) -> Result<DomainResult> {
    let t0 = std::time::Instant::now();
    let asked = net::clean_host(&req.domain)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if asked.parse::<IpAddr>().is_ok() {
        return Err(t!(
            "Indica un dominio, non un indirizzo IP",
            "Enter a domain, not an IP address"
        )
        .into());
    }
    if !asked.contains('.') {
        return Err(t!(
            "Indica il dominio completo, per esempio example.com",
            "Enter the full domain, for example example.com"
        )
        .into());
    }

    // zone: the name typed, or the one that contains it
    let (m, _, _) = query_any_with(&asked, RecordType::SOA, &env.system, Opts::default())
        .await
        .map_err(|e| {
            tf!(
                "Il DNS di questo PC non risponde ({e})",
                "This PC's DNS does not answer ({e})"
            )
        })?;
    if m.metadata.response_code == ResponseCode::NXDomain {
        return Err(tf!(
            "Il dominio {asked} non esiste (NXDOMAIN)",
            "The domain {asked} does not exist (NXDOMAIN)"
        ));
    }
    let own = of_type(&m.answers, RecordType::SOA).next().cloned();
    let upper = of_type(&m.authorities, RecordType::SOA).next().cloned();
    let (soa_rec, domain, zone_note) = match (own, upper) {
        (Some(r), _) => (r, asked.clone(), String::new()),
        (None, Some(r)) => {
            let zone = host_of(&r.name);
            let note = tf!(
                "{asked} fa parte della zona {zone}: l'analisi riguarda la zona.",
                "{asked} is part of the zone {zone}: the analysis covers the zone."
            );
            (r, zone, note)
        }
        (None, None) => {
            return Err(tf!(
                "Nessuna zona trovata per {asked} ({})",
                "No zone found for {asked} ({})",
                status_name(m.metadata.response_code)
            ))
        }
    };
    let soa = soa_of(&soa_rec);
    let parent = domain
        .split_once('.')
        .map(|(_, p)| p)
        .unwrap_or("")
        .to_string();

    // records from the PC's DNS, all together
    let wild = {
        let mut b = [0u8; 6];
        let _ = getrandom::getrandom(&mut b);
        format!("ntb-{}.{domain}", rdata::hex(&b))
    };
    let tlsa_name = format!("_443._tcp.{domain}");
    let d = Opts::default();
    let jobs = SHOWN
        .iter()
        .filter(|t| **t != RecordType::SOA)
        .map(|t| sys(env, &domain, *t, d));
    let (answers, wild_m, tlsa_m, nsec3_m, parent_ref, valid) = tokio::join!(
        futures_join(jobs),
        sys(env, &wild, RecordType::A, d),
        sys(env, &tlsa_name, RecordType::TLSA, d),
        sys(env, &domain, RecordType::NSEC3PARAM, d),
        referral(env, &domain, &parent),
        validation(env, &domain)
    );

    let mut records = Vec::new();
    let mut empty_types = Vec::new();
    let mut by_type: Vec<(RecordType, Vec<Record>)> = Vec::new();
    let mut it = answers.into_iter();
    for t in SHOWN {
        let recs: Vec<Record> = if t == RecordType::SOA {
            vec![soa_rec.clone()]
        } else {
            it.next()
                .flatten()
                .map(|m| of_type(&m.answers, t).cloned().collect())
                .unwrap_or_default()
        };
        if recs.is_empty() {
            empty_types.push(t.to_string());
        }
        for r in &recs {
            let owner = host_of(&r.name);
            records.push(Rec {
                rtype: t.to_string(),
                name: if same(&owner, &domain) {
                    String::new()
                } else {
                    owner
                },
                value: record_value(r),
                ttl: r.ttl,
            });
        }
        by_type.push((t, recs));
    }
    let tlsa: Vec<Record> = tlsa_m
        .map(|m| of_type(&m.answers, RecordType::TLSA).cloned().collect())
        .unwrap_or_default();
    if tlsa.is_empty() {
        empty_types.push("TLSA".into());
    }
    for r in &tlsa {
        records.push(Rec {
            rtype: "TLSA".into(),
            name: tlsa_name.clone(),
            value: record_value(r),
            ttl: r.ttl,
        });
    }
    let get = |t: RecordType| -> &[Record] {
        by_type
            .iter()
            .find(|(x, _)| *x == t)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    };
    let wildcard = wild_m.is_some_and(|m| {
        m.metadata.response_code == ResponseCode::NoError && !m.answers.is_empty()
    });
    let addresses_out: Vec<String> = get(RecordType::A)
        .iter()
        .chain(get(RecordType::AAAA))
        .map(record_value)
        .collect();

    // name servers: those of the registry, then those only the zone declares
    let resolver_ns: Vec<String> = get(RecordType::NS)
        .iter()
        .filter_map(|r| match &r.data {
            RData::NS(x) => Some(host_of(&x.0)),
            _ => None,
        })
        .collect();
    let parent_ok = parent_ref.is_some();
    let mut list: Vec<NsInfo> = Vec::new();
    if let Some(p) = &parent_ref {
        for n in &p.ns {
            list.push(NsInfo {
                name: n.clone(),
                parent: Some(true),
                ..Default::default()
            });
        }
    }
    for n in &resolver_ns {
        if !list.iter().any(|x| same(&x.name, n)) {
            list.push(NsInfo {
                name: n.clone(),
                parent: parent_ok.then_some(false),
                ..Default::default()
            });
        }
    }
    list.truncate(MAX_NS);
    let glue = parent_ref
        .as_ref()
        .map(|p| p.glue.clone())
        .unwrap_or_default();
    let port = env.port;
    let axfr = req.axfr;
    let probes = list.into_iter().map(|mut n| {
        let glue = glue.clone();
        let domain = domain.clone();
        async move {
            let (mut v4, mut v6) = addresses(env, &n.name).await;
            for (g, ip) in &glue {
                if same(g, &n.name) {
                    let s = ip.to_string();
                    let list = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
                    if !list.contains(&s) {
                        list.push(s);
                    }
                }
            }
            n.ipv4 = v4;
            n.ipv6 = v6;
            probe(&domain, n, port, axfr).await
        }
    });
    let probed = futures_join(probes).await;
    // NS declared by the zone: from an authoritative name server, otherwise from the PC's DNS
    let zone_ns: Vec<String> = probed
        .iter()
        .map(|(_, z)| z)
        .find(|z| !z.is_empty())
        .cloned()
        .unwrap_or_else(|| resolver_ns.clone());
    let mut nameservers: Vec<NsInfo> = probed.into_iter().map(|(n, _)| n).collect();
    for n in nameservers.iter_mut() {
        n.zone = zone_ns.iter().any(|z| same(z, &n.name));
    }

    // DNSSEC: DS from the registry (or the PC's DNS), keys, signatures, NSEC3
    let ds: Vec<Ds> = match &parent_ref {
        Some(p) if !p.ds.is_empty() => p.ds.clone(),
        _ => get(RecordType::DS)
            .iter()
            .filter_map(|r| raw_of(r).and_then(rdata::ds))
            .collect(),
    };
    let keys: Vec<Dnskey> = get(RecordType::DNSKEY)
        .iter()
        .filter_map(|r| raw_of(r).and_then(rdata::dnskey))
        .collect();
    let mut sigs: Vec<Rrsig> = Vec::new();
    if !keys.is_empty() || !ds.is_empty() {
        let with_do = Opts {
            dnssec: true,
            ..Opts::default()
        };
        let auth = nameservers
            .iter()
            .find(|n| n.responds && n.authoritative)
            .and_then(|n| n.ipv4.first())
            .and_then(|a| a.parse::<Ipv4Addr>().ok())
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), port));
        for t in [RecordType::SOA, RecordType::DNSKEY] {
            let m = match auth {
                Some(a) => direct(&domain, t, a, with_do).await.ok().map(|(m, _)| m),
                None => sys(env, &domain, t, with_do).await,
            };
            if let Some(m) = m {
                sigs.extend(
                    of_type(&m.answers, RecordType::RRSIG)
                        .filter_map(|r| raw_of(r).and_then(rdata::rrsig)),
                );
            }
        }
    }
    let nsec3 = nsec3_m.and_then(|m| {
        of_type(&m.answers, RecordType::NSEC3PARAM)
            .find_map(|r| raw_of(r).and_then(rdata::nsec3param))
    });

    let mut checks = delegation_checks(&mut nameservers, parent_ok, axfr);
    if !parent_ok && nameservers.iter().any(|n| n.responds) {
        checks.push(check(
            A_DEL,
            INFO,
            t!("Registro", "Registry"),
            tf!(
                "i name server di {} non rispondono da questo PC: confronto con la zona non fatto",
                "the name servers of {} do not answer from this PC: comparison with the zone not done",
                if parent.is_empty() {
                    "."
                } else {
                    parent.as_str()
                }
            ),
        ));
    }
    if let Some(s) = &soa {
        checks.extend(soa_checks(s, &zone_ns));
    }
    let (sec, sec_checks) = dnssec(
        &domain,
        &ds,
        &keys,
        &sigs,
        nsec3.as_ref(),
        &valid,
        util::now_unix() as i64,
    );
    checks.extend(sec_checks);
    checks.extend(record_checks(&records, wildcard, &domain));

    Ok(DomainResult {
        domain,
        zone_note,
        checks,
        records,
        empty_types,
        nameservers,
        parent,
        parent_ok,
        dnssec: sec,
        addresses: addresses_out,
        time_ms: t0.elapsed().as_millis() as u64,
    })
}

/// All futures together, results in the order they were started (no extra dependencies).
pub(crate) async fn futures_join<F: std::future::Future>(
    it: impl Iterator<Item = F>,
) -> Vec<F::Output> {
    let mut pending: Vec<std::pin::Pin<Box<F>>> = it.map(Box::pin).collect();
    let mut done: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut all = true;
        for (i, f) in pending.iter_mut().enumerate() {
            if done[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => done[i] = Some(v),
                    std::task::Poll::Pending => all = false,
                }
            }
        }
        if all {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    done.into_iter().map(|v| v.unwrap()).collect()
}

pub async fn run(req: DomainReq) -> Result<DomainResult> {
    let system = super::system_dns()?.servers;
    let validators = VALIDATORS
        .iter()
        .map(|a| SocketAddr::new(a.parse().unwrap(), 53))
        .collect();
    let env = Env {
        system,
        validators,
        port: 53,
    };
    analyze(req, &env).await
}

#[cfg(test)]
mod tests {
    use super::super::rdata::tests::key_rdata;
    use super::*;
    use hickory_proto::rr::rdata::{self as rd, NULL};
    use hickory_proto::rr::Name;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    fn find<'a>(c: &'a [Check], area: &str, name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.area == area && x.name == name)
            .unwrap_or_else(|| panic!("manca {area}/{name}: {c:#?}"))
    }

    fn ns(name: &str, ip: &str, parent: Option<bool>, zone: bool, serial: Option<u32>) -> NsInfo {
        NsInfo {
            name: name.into(),
            ipv4: vec![ip.into()],
            parent,
            zone,
            responds: serial.is_some(),
            authoritative: serial.is_some(),
            serial,
            rcode: "NOERROR".into(),
            ..Default::default()
        }
    }

    #[test]
    fn delega_a_posto() {
        let mut v = vec![
            ns(
                "ns1.example.net",
                "198.51.100.51",
                Some(true),
                true,
                Some(7),
            ),
            ns("ns2.example.net", "203.0.113.52", Some(true), true, Some(7)),
        ];
        let c = delegation_checks(&mut v, true, false);
        assert!(
            c.iter().all(|x| x.status == OK || x.name == "AXFR"),
            "{c:#?}"
        );
        assert_eq!(
            find(&c, A_DEL, "Name server").detail,
            "2 su 2 rispondono e sono autoritativi"
        );
        assert!(find(&c, A_DEL, "Seriale SOA").detail.contains("(7)"));
        assert_eq!(find(&c, A_DEL, "Reti").status, OK);
        assert_eq!(find(&c, A_XFR, "AXFR").status, INFO);
        assert!(v.iter().all(|n| n.status == OK && n.note.is_empty()));
    }

    #[test]
    fn delega_con_difetti() {
        let mut v = vec![
            ns(
                "ns1.example.net",
                "198.51.100.51",
                Some(true),
                true,
                Some(2026111603),
            ),
            ns(
                "ns2.example.net",
                "198.51.100.52",
                Some(true),
                true,
                Some(2026111501),
            ),
            ns("ns3.example.net", "198.51.100.53", Some(true), false, None),
            ns(
                "ns4.example.net",
                "198.51.100.54",
                Some(false),
                true,
                Some(2026111603),
            ),
        ];
        v[0].axfr = Some(false);
        v[3].axfr = Some(true);
        v[3].recursion = true;
        let c = delegation_checks(&mut v, true, true);
        let down = find(&c, A_DEL, "Name server");
        assert_eq!(down.status, ERR);
        assert!(down
            .detail
            .starts_with("ns3.example.net (198.51.100.53) non risponde"));
        let ser = find(&c, A_DEL, "Seriale SOA");
        assert_eq!(ser.status, ERR);
        assert!(ser
            .detail
            .contains("ns2.example.net ha 2026111501, gli altri 2026111603"));
        let diff = find(&c, A_DEL, "NS del registro e della zona");
        assert_eq!(diff.status, WARN);
        assert!(diff
            .detail
            .contains("delega a ns1.example.net, ns2.example.net, ns3.example.net;"));
        assert!(diff
            .detail
            .ends_with("dichiara ns1.example.net, ns2.example.net, ns4.example.net"));
        assert_eq!(find(&c, A_DEL, "Reti").status, WARN);
        assert_eq!(find(&c, A_DEL, "Ricorsione").status, INFO);
        let x = find(&c, A_XFR, "AXFR");
        assert_eq!(x.status, ERR);
        assert!(x.detail.ends_with("ns4.example.net"));
        assert_eq!(
            v.iter().map(|n| n.status).collect::<Vec<_>>(),
            vec![OK, ERR, ERR, WARN]
        );
        assert!(
            v[2].note.contains("Non risponde") && v[2].note.contains("non dichiarato dalla zona")
        );
        assert!(v[3].note.contains("non delegato dal registro"));
    }

    #[test]
    fn delega_rete_chiusa_zoppa_e_senza_indirizzi() {
        // nothing answers and the parent zone is unreachable: information, not errors
        let mut v = vec![
            ns("ns1.example.net", "198.51.100.51", None, true, None),
            ns("ns2.example.net", "203.0.113.52", None, true, None),
        ];
        let c = delegation_checks(&mut v, false, true);
        assert!(c.iter().all(|x| x.status != ERR), "{c:#?}");
        assert!(find(&c, A_DEL, "Name server").detail.contains("porta 53"));
        assert!(find(&c, A_XFR, "AXFR").detail.contains("non provabile"));
        assert!(v.iter().all(|n| n.status == INFO));

        // the parent zone answers, the name servers do not: real errors
        let c = delegation_checks(&mut v, true, false);
        assert_eq!(c.iter().filter(|x| x.status == ERR).count(), 2);

        let mut lame = ns(
            "ns1.example.net",
            "198.51.100.51",
            Some(true),
            true,
            Some(1),
        );
        lame.authoritative = false;
        lame.rcode = "REFUSED".into();
        let mut none = ns("ns9.example.net", "", Some(true), true, None);
        none.ipv4.clear();
        let mut v = vec![lame, none];
        let c = delegation_checks(&mut v, true, false);
        assert!(find(&c, A_DEL, "Delega zoppa").detail.contains("REFUSED"));
        assert!(c
            .iter()
            .any(|x| x.detail.contains("ns9.example.net non ha indirizzi")));
        let mut one = vec![ns(
            "ns1.example.net",
            "198.51.100.51",
            Some(true),
            true,
            Some(1),
        )];
        assert_eq!(
            find(&delegation_checks(&mut one, true, false), A_DEL, "Numero").status,
            WARN
        );
    }

    #[test]
    fn valori_del_soa() {
        let good = Soa {
            mname: "ns1.example.net".into(),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 3600,
        };
        let names = vec!["ns1.example.net".to_string()];
        let c = soa_checks(&good, &names);
        assert_eq!(c.len(), 1);
        assert_eq!(
            c[0].detail,
            "refresh 7200, retry 3600, expire 1209600, minimo 3600"
        );
        let bad = Soa {
            mname: "nascosto.example.net.".into(),
            retry: 7200,
            expire: 3600,
            minimum: 172_800,
            ..good
        };
        let c = soa_checks(&bad, &names);
        let v = find(&c, A_SOA, "Valori");
        assert_eq!(v.status, WARN);
        assert!(
            v.detail.contains("retry")
                && v.detail.contains("7 giorni")
                && v.detail.contains("minimo")
        );
        assert!(find(&c, A_SOA, "Primario")
            .detail
            .starts_with("nascosto.example.net non è"));
    }

    fn rec(t: &str, value: &str, ttl: u32) -> Rec {
        Rec {
            rtype: t.into(),
            name: String::new(),
            value: value.into(),
            ttl,
        }
    }

    #[test]
    fn controlli_sui_record() {
        let r = vec![
            rec("A", "203.0.113.10", 30),
            rec("AAAA", "2001:db8::10", 3600),
            rec("CAA", "0 issue \"ca.example.net\"", 3600),
        ];
        let c = record_checks(&r, true, "example.com");
        assert!(find(&c, A_REC, "TTL").detail.contains("30 secondi"));
        assert!(find(&c, A_REC, "Jolly").detail.starts_with("*.example.com"));
        assert_eq!(find(&c, A_REC, "CAA").status, OK);
        assert_eq!(find(&c, A_REC, "IPv6").status, OK);
        let c = record_checks(&[rec("A", "203.0.113.10", 300)], false, "example.com");
        assert_eq!(c.len(), 2);
        assert_eq!(find(&c, A_REC, "CAA").status, INFO);
        assert_eq!(find(&c, A_REC, "IPv6").status, INFO);
        assert!(record_checks(&[], false, "example.com").len() == 1);
    }

    const NOW: i64 = 1_794_000_000;

    /// Consistent KSK, ZSK and DS (SHA-256) for `example.com`.
    fn keys() -> (Dnskey, Dnskey, Ds) {
        let ksk = rdata::dnskey(&key_rdata(257, 13, &[7u8; 64])).unwrap();
        let zsk = rdata::dnskey(&key_rdata(256, 13, &[9u8; 64])).unwrap();
        let mut data = b"\x07example\x03com\x00".to_vec();
        data.extend_from_slice(&ksk.raw);
        let ds = Ds {
            tag: ksk.tag,
            algorithm: 13,
            digest_type: 2,
            digest: Sha256::digest(&data).to_vec(),
        };
        (ksk, zsk, ds)
    }

    fn sig(covered: u16, tag: u16, left: i64) -> Rrsig {
        Rrsig {
            covered,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            expiration: (NOW + left) as u32,
            inception: (NOW - 86_400) as u32,
            tag,
            signer: "example.com.".into(),
        }
    }

    fn valid(normal: Option<(&str, bool)>, cd: Option<&str>) -> Validation {
        Validation {
            resolver: "192.0.2.53".into(),
            normal: normal.map(|(r, a)| (r.to_string(), a)),
            cd: cd.map(str::to_string),
            system_ad: Some(false),
        }
    }

    #[test]
    fn dnssec_valido() {
        let (ksk, zsk, ds) = keys();
        let sigs = [sig(6, zsk.tag, 10 * 86_400), sig(48, ksk.tag, 3 * 3600)];
        let p = Nsec3Param {
            hash: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
        };
        let v = valid(Some(("NOERROR", true)), Some("NOERROR"));
        let (d, c) = dnssec(
            "example.com",
            &[ds],
            &[ksk.clone(), zsk],
            &sigs,
            Some(&p),
            &v,
            NOW,
        );
        assert_eq!((d.label.as_str(), d.level), ("Firmato e valido", OK));
        assert!(find(&c, A_SEC, "DS e DNSKEY")
            .detail
            .ends_with(&format!("chiave {}", ksk.tag)));
        assert_eq!(find(&c, A_SEC, "Validazione").status, OK);
        assert_eq!(
            find(&c, A_SEC, "Algoritmo").detail,
            "13 (ECDSA P-256 con SHA-256)"
        );
        let f = find(&c, A_SEC, "Firme");
        assert_eq!(f.status, WARN);
        assert!(
            f.detail.contains("DNSKEY") && f.detail.contains("tra 3 ore"),
            "{}",
            f.detail
        );
        // rows: DS, two keys, two signatures, denial of existence
        assert_eq!(d.rows.len(), 6);
        assert_eq!(d.rows[0].status, OK);
        assert!(d.rows[1].what.starts_with("KSK (257)") && d.rows[2].what.starts_with("ZSK (256)"));
        assert!(d.rows[3].detail.contains("(10 giorni)"));
        assert!(d.rows[5].what.contains("NSEC3 · 0 iterazioni · senza sale"));
        assert_eq!(d.validation.len(), 3);
        assert!(
            d.validation[0].name.contains("192.0.2.53")
                && d.validation[0].detail.contains("flag AD")
        );
        assert!(d.validation[2].detail.contains("senza flag AD"));
    }

    #[test]
    fn dnssec_rotto() {
        let (ksk, zsk, ds) = keys();
        // validation fails
        let v = valid(Some(("SERVFAIL", false)), Some("NOERROR"));
        let (d, c) = dnssec(
            "example.com",
            std::slice::from_ref(&ds),
            &[ksk.clone(), zsk.clone()],
            &[],
            None,
            &v,
            NOW,
        );
        assert_eq!((d.label.as_str(), d.level), ("Non valido", ERR));
        assert_eq!(find(&c, A_SEC, "Validazione").status, ERR);
        assert!(d.rows.last().unwrap().what == "NSEC");

        // DS that matches no key
        let other = Ds {
            tag: 1,
            ..ds.clone()
        };
        let ok = valid(Some(("NOERROR", false)), Some("NOERROR"));
        let (d, c) = dnssec(
            "example.com",
            &[other],
            &[ksk.clone(), zsk.clone()],
            &[],
            None,
            &ok,
            NOW,
        );
        assert_eq!(d.level, ERR);
        assert!(find(&c, A_SEC, "DS e DNSKEY")
            .detail
            .starts_with("nessun DS"));
        // same id, wrong digest
        let wrong = Ds {
            digest: vec![0; 32],
            ..ds.clone()
        };
        let (d, _) = dnssec(
            "example.com",
            &[wrong],
            std::slice::from_ref(&ksk),
            &[],
            None,
            &ok,
            NOW,
        );
        assert_eq!((d.rows[0].status, d.level), (ERR, ERR));

        // DS without keys, expired signature
        let (d, c) = dnssec(
            "example.com",
            std::slice::from_ref(&ds),
            &[],
            &[sig(6, 5, -3600)],
            None,
            &ok,
            NOW,
        );
        assert_eq!(d.level, ERR);
        assert!(find(&c, A_SEC, "DS e DNSKEY")
            .detail
            .contains("non ha chiavi"));
        assert!(find(&c, A_SEC, "Firme").detail.contains("scaduta il"));
    }

    #[test]
    fn dnssec_altri_casi() {
        let (ksk, zsk, ds) = keys();
        let none = Validation::default();
        // unsigned
        let (d, c) = dnssec(
            "example.com",
            &[],
            &[],
            &[],
            None,
            &valid(Some(("NOERROR", false)), Some("NOERROR")),
            NOW,
        );
        assert_eq!((d.label.as_str(), d.level), ("Non firmato", ""));
        assert_eq!(c.len(), 1);
        assert!(d.rows.is_empty());
        assert!(d.validation[0].detail.contains("zona non firmata"));
        // signed but without DS
        let (d, c) = dnssec(
            "example.com",
            &[],
            &[ksk.clone(), zsk.clone()],
            &[],
            None,
            &none,
            NOW,
        );
        assert_eq!((d.label.as_str(), d.level), ("Firmato, senza DS", WARN));
        assert_eq!(find(&c, A_SEC, "DS").status, WARN);
        assert!(d.validation[0].detail.contains("non raggiungibile"));
        // resolver unreachable but structure fine
        let (d, _) = dnssec(
            "example.com",
            std::slice::from_ref(&ds),
            std::slice::from_ref(&ksk),
            &[],
            None,
            &none,
            NOW,
        );
        assert_eq!((d.label.as_str(), d.level), ("Firmato", OK));
        // DS present but answer without AD
        let v = valid(Some(("NOERROR", false)), Some("NOERROR"));
        let (d, c) = dnssec(
            "example.com",
            std::slice::from_ref(&ds),
            std::slice::from_ref(&ksk),
            &[],
            None,
            &v,
            NOW,
        );
        assert_eq!(d.label, "Firmato, non validato");
        assert_eq!(find(&c, A_SEC, "Validazione").status, WARN);
        // old algorithm, SHA-1-only DS, NSEC3 with iterations
        let old = rdata::dnskey(&key_rdata(257, 5, &[1u8; 130])).unwrap();
        let sha1 = Ds {
            tag: old.tag,
            algorithm: 5,
            digest_type: 1,
            digest: vec![0; 20],
        };
        let p = Nsec3Param {
            hash: 1,
            flags: 0,
            iterations: 150,
            salt: vec![1],
        };
        let (_, c) = dnssec("example.com", &[sha1], &[old], &[], Some(&p), &none, NOW);
        assert_eq!(find(&c, A_SEC, "Algoritmo").status, WARN);
        assert_eq!(find(&c, A_SEC, "Digest del DS").status, WARN);
        assert_eq!(find(&c, A_SEC, "NSEC3").status, WARN);
        assert_eq!(date_it(1_795_000_000), "18 novembre 2026");
    }

    // ---- fake DNS servers on 127.0.0.x ----------------------------------------

    /// (last octet of the address, query, over TCP) → response
    type Handler = Arc<dyn Fn(u8, &Message, bool) -> Option<Message> + Send + Sync>;

    /// Starts a server (UDP and TCP) on 127.0.0.<n> for each `n`, all on the same port.
    async fn farm(ips: &[u8], h: Handler) -> u16 {
        'again: loop {
            let first = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, ips[0]), 0))
                .await
                .unwrap();
            let port = first.local_addr().unwrap().port();
            let mut socks = Vec::new();
            for (i, ip) in ips.iter().enumerate() {
                let addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, *ip), port));
                let udp = if i == 0 {
                    None
                } else {
                    match UdpSocket::bind(addr).await {
                        Ok(u) => Some(u),
                        Err(_) => continue 'again,
                    }
                };
                let Ok(tcp) = TcpListener::bind(addr).await else {
                    continue 'again;
                };
                socks.push((*ip, udp, tcp));
            }
            let mut first = Some(first);
            for (ip, udp, tcp) in socks {
                let udp = udp.unwrap_or_else(|| first.take().unwrap());
                let hu = h.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    loop {
                        let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                            continue;
                        };
                        if let Some(r) = Message::from_vec(&buf[..n])
                            .ok()
                            .and_then(|q| hu(ip, &q, false))
                        {
                            let _ = udp.send_to(&r.to_vec().unwrap(), from).await;
                        }
                    }
                });
                let ht = h.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok((mut s, _)) = tcp.accept().await else {
                            return;
                        };
                        let Ok(len) = s.read_u16().await else {
                            continue;
                        };
                        let mut req = vec![0u8; len as usize];
                        if s.read_exact(&mut req).await.is_err() {
                            continue;
                        }
                        if let Some(r) = Message::from_vec(&req).ok().and_then(|q| ht(ip, &q, true))
                        {
                            let out = r.to_vec().unwrap();
                            let _ = s.write_all(&(out.len() as u16).to_be_bytes()).await;
                            let _ = s.write_all(&out).await;
                        }
                    }
                });
            }
            return port;
        }
    }

    fn reply(q: &Message) -> Message {
        let mut r = Message::response(q.metadata.id, hickory_proto::op::OpCode::Query);
        r.add_query(q.queries[0].clone());
        r
    }

    fn name(s: &str) -> Name {
        Name::from_ascii(format!("{}.", s.trim_end_matches('.'))).unwrap()
    }

    fn rr(owner: &str, ttl: u32, data: RData) -> Record {
        Record::from_rdata(name(owner), ttl, data)
    }

    fn raw(owner: &str, t: RecordType, bytes: Vec<u8>) -> Record {
        rr(
            owner,
            3600,
            RData::Unknown {
                code: t,
                rdata: NULL::with(bytes),
            },
        )
    }

    fn soa(serial: u32) -> Record {
        rr(
            "example.com",
            3600,
            RData::SOA(rd::SOA::new(
                name("ns1.example.net"),
                name("hostmaster.example.com"),
                serial,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        )
    }

    fn nsr(target: &str) -> Record {
        rr("example.com", 86_400, RData::NS(rd::NS(name(target))))
    }

    fn a(owner: &str, ttl: u32, last: u8) -> Record {
        rr(owner, ttl, RData::A(rd::A(Ipv4Addr::new(127, 0, 0, last))))
    }

    fn rrsig_raw(covered: u16, tag: u16, left: i64) -> Vec<u8> {
        let now = util::now_unix() as i64;
        let mut raw = covered.to_be_bytes().to_vec();
        raw.extend_from_slice(&[13, 2]);
        raw.extend_from_slice(&3600u32.to_be_bytes());
        raw.extend_from_slice(&((now + left) as u32).to_be_bytes());
        raw.extend_from_slice(&((now - 86_400) as u32).to_be_bytes());
        raw.extend_from_slice(&tag.to_be_bytes());
        raw.extend_from_slice(b"\x07example\x03com\x00");
        raw.extend_from_slice(&[5u8; 64]);
        raw
    }

    /// The preview domain: 127.0.0.1 acts as the PC's DNS, as validating resolver and as
    /// parent zone; ns1 = .11, ns2 = .12 (old serial), ns3 = .13 (down, registry only),
    /// ns4 = .14 (zone only, AXFR open).
    fn scenario() -> Handler {
        let (ksk, zsk, ds) = keys();
        let mut ds_raw = ds.tag.to_be_bytes().to_vec();
        ds_raw.extend_from_slice(&[13, 2]);
        ds_raw.extend_from_slice(&ds.digest);
        Arc::new(move |ip, q, tcp| {
            let qq = &q.queries[0];
            let (n, t) = (host_of(qq.name()), qq.query_type());
            let with_do = q.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
            let mut r = reply(q);
            let zone = n == "example.com";
            match ip {
                // parent zone (query without recursion)
                1 if !q.metadata.recursion_desired => {
                    r.metadata.authoritative = t == RecordType::DS;
                    match t {
                        RecordType::NS if zone => {
                            for x in ["ns1", "ns2", "ns3"] {
                                r.add_authority(nsr(&format!("{x}.example.net")));
                            }
                            r.add_additional(a("ns1.example.net", 3600, 11));
                        }
                        RecordType::DS if zone => {
                            r.add_answer(raw("example.com", RecordType::DS, ds_raw.clone()));
                        }
                        _ => {}
                    }
                }
                // the PC's DNS and validating resolver
                1 => {
                    r.metadata.recursion_available = true;
                    if with_do && q.metadata.authentic_data && t == RecordType::SOA {
                        r.metadata.authentic_data = !q.metadata.checking_disabled;
                    }
                    match (n.as_str(), t) {
                        ("example.com", RecordType::SOA) => {
                            r.add_answer(soa(2026111603));
                        }
                        ("www.example.com", RecordType::SOA) => {
                            r.add_authority(soa(2026111603));
                        }
                        ("nessuno.example", _) => {
                            r.metadata.response_code = ResponseCode::NXDomain;
                        }
                        ("example.com", RecordType::A) => {
                            r.add_answer(rr(
                                "example.com",
                                30,
                                RData::A(rd::A(Ipv4Addr::new(203, 0, 113, 10))),
                            ));
                        }
                        ("example.com", RecordType::AAAA) => {
                            r.add_answer(rr(
                                "example.com",
                                3600,
                                RData::AAAA(rd::AAAA("2001:db8::10".parse().unwrap())),
                            ));
                        }
                        ("example.com", RecordType::NS) => {
                            for x in ["ns1", "ns2", "ns4"] {
                                r.add_answer(nsr(&format!("{x}.example.net")));
                            }
                        }
                        ("example.com", RecordType::DNSKEY) => {
                            r.add_answer(raw("example.com", t, ksk.raw.clone()));
                            r.add_answer(raw("example.com", t, zsk.raw.clone()));
                        }
                        ("example.com", RecordType::DS) => {
                            r.add_answer(raw("example.com", t, ds_raw.clone()));
                        }
                        ("example.com", RecordType::NSEC3PARAM) => {
                            r.add_answer(raw("example.com", t, vec![1, 0, 0, 0, 0]));
                        }
                        ("com", RecordType::NS) => {
                            r.add_answer(rr(
                                "com",
                                3600,
                                RData::NS(rd::NS(name("a.registro.example"))),
                            ));
                        }
                        ("a.registro.example", RecordType::A) => {
                            r.add_answer(a(&n, 3600, 1));
                        }
                        (h, RecordType::A)
                            if h.starts_with("ns") && h.ends_with(".example.net") =>
                        {
                            let last = 10 + h.as_bytes()[2] - b'0';
                            r.add_answer(a(h, 3600, last));
                        }
                        (h, RecordType::A) if h.starts_with("ntb-") => {
                            r.add_answer(a(h, 60, 99));
                        }
                        _ => {}
                    }
                }
                // name servers of the zone
                11 | 12 | 14 => {
                    r.metadata.authoritative = true;
                    if !zone {
                        r.metadata.response_code = ResponseCode::Refused;
                        return Some(r);
                    }
                    match t {
                        RecordType::SOA => {
                            r.add_answer(soa(if ip == 12 { 2026111501 } else { 2026111603 }));
                            if with_do {
                                r.add_answer(raw(
                                    "example.com",
                                    RecordType::RRSIG,
                                    rrsig_raw(6, zsk.tag, 3 * 3600),
                                ));
                            }
                        }
                        RecordType::NS => {
                            for x in ["ns1", "ns2", "ns4"] {
                                r.add_answer(nsr(&format!("{x}.example.net")));
                            }
                        }
                        RecordType::DNSKEY => {
                            r.add_answer(raw("example.com", t, ksk.raw.clone()));
                            if with_do {
                                r.add_answer(raw(
                                    "example.com",
                                    RecordType::RRSIG,
                                    rrsig_raw(48, ksk.tag, 20 * 86_400),
                                ));
                            }
                        }
                        RecordType::AXFR if tcp && ip == 14 => {
                            r.add_answer(soa(2026111603));
                        }
                        RecordType::AXFR => {
                            r.metadata.response_code = ResponseCode::Refused;
                        }
                        _ => {}
                    }
                }
                _ => return None,
            }
            Some(r)
        })
    }

    fn env(port: u16, validator: u8) -> Env {
        let at = |n: u8| SocketAddr::from((Ipv4Addr::new(127, 0, 0, n), port));
        Env {
            system: vec![at(1)],
            validators: vec![at(validator)],
            port,
        }
    }

    #[tokio::test]
    #[allow(clippy::type_complexity)]
    async fn analisi_completa() {
        let port = farm(&[1, 11, 12, 14], scenario()).await;
        let req = DomainReq {
            domain: "Example.COM.".into(),
            axfr: true,
        };
        let r = analyze(req, &env(port, 1)).await.unwrap();
        assert_eq!(r.domain, "example.com");
        assert!(r.zone_note.is_empty());
        assert_eq!((r.parent.as_str(), r.parent_ok), ("com", true));
        assert_eq!(r.addresses, vec!["203.0.113.10", "2001:db8::10"]);

        // records: types in the tab's order, DNSKEY and DS readable
        let types: Vec<&str> = r.records.iter().map(|x| x.rtype.as_str()).collect();
        assert_eq!(
            types,
            vec!["A", "AAAA", "NS", "NS", "NS", "SOA", "DNSKEY", "DNSKEY", "DS"]
        );
        assert_eq!(r.empty_types, vec!["MX", "TXT", "CAA", "HTTPS", "TLSA"]);
        assert_eq!(r.records[0].ttl, 30);
        assert!(r.records[5]
            .value
            .starts_with("ns1.example.net. hostmaster.example.com. 2026111603"));
        assert!(
            r.records[6].value.starts_with("257 3 13 "),
            "{}",
            r.records[6].value
        );
        assert!(
            r.records[8].value.contains(" 13 2 "),
            "{}",
            r.records[8].value
        );

        // delegation: registry ns1-ns3, zone ns1, ns2, ns4
        let got: Vec<(&str, Option<bool>, bool, bool, Option<u32>, &str)> = r
            .nameservers
            .iter()
            .map(|n| {
                (
                    n.name.as_str(),
                    n.parent,
                    n.zone,
                    n.responds,
                    n.serial,
                    n.status,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "ns1.example.net",
                    Some(true),
                    true,
                    true,
                    Some(2026111603),
                    "ok"
                ),
                (
                    "ns2.example.net",
                    Some(true),
                    true,
                    true,
                    Some(2026111501),
                    "err"
                ),
                ("ns3.example.net", Some(true), false, false, None, "err"),
                (
                    "ns4.example.net",
                    Some(false),
                    true,
                    true,
                    Some(2026111603),
                    "warn"
                ),
            ]
        );
        assert_eq!(r.nameservers[0].ipv4, vec!["127.0.0.11"]);
        assert_eq!(
            r.nameservers.iter().map(|n| n.axfr).collect::<Vec<_>>(),
            vec![Some(false), Some(false), None, Some(true)]
        );
        let c = &r.checks;
        assert!(find(c, A_DEL, "Name server")
            .detail
            .starts_with("ns3.example.net (127.0.0.13)"));
        assert_eq!(find(c, A_DEL, "Seriale SOA").status, ERR);
        assert_eq!(find(c, A_DEL, "NS del registro e della zona").status, WARN);
        assert!(find(c, A_XFR, "AXFR")
            .detail
            .ends_with("da ns4.example.net"));
        assert_eq!(find(c, A_SOA, "Valori").status, OK);
        assert!(find(c, A_REC, "Jolly").detail.starts_with("*.example.com"));
        assert_eq!(find(c, A_REC, "TTL").status, INFO);

        // DNSSEC: DS taken from the registry, signatures read from a name server with the DO bit
        assert_eq!(
            (r.dnssec.label.as_str(), r.dnssec.level),
            ("Firmato e valido", "ok")
        );
        assert_eq!(find(c, A_SEC, "DS e DNSKEY").status, OK);
        assert_eq!(find(c, A_SEC, "Validazione").status, OK);
        let f = find(c, A_SEC, "Firme");
        assert!(
            f.status == WARN && f.detail.contains("record SOA"),
            "{}",
            f.detail
        );
        let names: Vec<&str> = r.dnssec.rows.iter().map(|x| x.name.as_str()).collect();
        assert!(
            names.contains(&"Firma di SOA")
                && names.contains(&"Firma di DNSKEY")
                && names.contains(&"Negazione"),
            "{names:?}"
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains(r#""type":"DNSKEY""#) && !json.contains("rcode"),
            "{json}"
        );
    }

    /// From the PC's network port 53 to the outside is closed: only the PC's DNS answers.
    #[tokio::test]
    async fn solo_il_dns_del_pc() {
        let base = scenario();
        // only .1 is up, and it is neither parent zone nor validating resolver
        let h: Handler = Arc::new(move |ip, q, tcp| {
            if !q.metadata.recursion_desired || (q.edns.is_some() && q.metadata.authentic_data) {
                return None;
            }
            base(ip, q, tcp)
        });
        let port = farm(&[1], h).await;
        let req = DomainReq {
            domain: "www.example.com".into(),
            axfr: false,
        };
        let r = analyze(req, &env(port, 77)).await.unwrap();
        assert_eq!(r.domain, "example.com");
        assert!(r
            .zone_note
            .starts_with("www.example.com fa parte della zona example.com"));
        assert!(!r.parent_ok);
        assert_eq!(r.nameservers.len(), 3);
        assert!(r
            .nameservers
            .iter()
            .all(|n| !n.responds && n.parent.is_none() && n.zone && n.status == "info"));
        let del: Vec<&Check> = r.checks.iter().filter(|c| c.area == A_DEL).collect();
        assert!(del.iter().all(|c| c.status != ERR), "{del:#?}");
        assert!(find(&r.checks, A_DEL, "Name server")
            .detail
            .contains("porta 53"));
        // DS and keys from the PC's DNS: structure fine, validation not checked
        assert_eq!(r.dnssec.label, "Firmato");
        assert!(r.dnssec.validation[0].detail.contains("non raggiungibile"));
        assert_eq!(find(&r.checks, A_SEC, "DS e DNSKEY").status, OK);
    }

    #[tokio::test]
    async fn domini_non_validi() {
        let port = farm(&[1], scenario()).await;
        let e = env(port, 1);
        let run = |d: &str| {
            let req = DomainReq {
                domain: d.to_string(),
                axfr: false,
            };
            let e = e.clone();
            async move { analyze(req, &e).await.unwrap_err() }
        };
        assert!(run("nessuno.example")
            .await
            .contains("non esiste (NXDOMAIN)"));
        assert!(run("192.0.2.1").await.contains("non un indirizzo IP"));
        assert!(run("srv01").await.contains("dominio completo"));
        assert!(run("vuoto.example.org")
            .await
            .contains("Nessuna zona trovata"));
    }

    #[tokio::test]
    async fn future_insieme() {
        let v = futures_join((0..4u64).map(|i| async move {
            tokio::time::sleep(Duration::from_millis(20 * (4 - i))).await;
            i
        }))
        .await;
        assert_eq!(v, vec![0, 1, 2, 3]);
        assert!(futures_join(std::iter::empty::<std::future::Ready<u8>>())
            .await
            .is_empty());
    }

    #[test]
    fn messages_in_english() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let mut v = vec![
            ns(
                "ns1.example.net",
                "198.51.100.51",
                Some(true),
                true,
                Some(7),
            ),
            ns(
                "ns2.example.net",
                "198.51.100.52",
                Some(true),
                true,
                Some(5),
            ),
        ];
        let c = delegation_checks(&mut v, true, false);
        let serial = find(&c, "Delegation", "SOA serial");
        assert!(
            serial.detail.contains("zone out of sync"),
            "{}",
            serial.detail
        );
        assert!(!serial.detail.contains("non allineata"));
        assert!(c.iter().all(|x| x.area != "Delega"));
        assert!(v[1].note.contains("older"), "{}", v[1].note);
        let (d, _) = dnssec("example.com", &[], &[], &[], None, &valid(None, None), NOW);
        assert_eq!(d.label, "Unsigned");
        assert_eq!(date_it(1_795_000_000), "18 November 2026");
        assert_eq!(days_text(3), "3 days");
        assert_eq!(rdata::algorithm(99).0, "unknown");
    }
}
