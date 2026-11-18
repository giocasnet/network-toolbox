//! SPF (RFC 7208): reading the record, tree of mechanisms with the DNS lookups that
//! count, and evaluation of an address. Pure functions only: the DNS data arrives already
//! gathered in [`Data`] (collected by `email::gather`), so everything can be tested offline.
//!
//! Lookups are counted in the worst case, i.e. walking the whole record: this is how you
//! see whether a recipient can end up exceeding the limit of 10.

use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::{t, tf};
use ipnet::IpNet;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;

/// DNS lookups allowed when evaluating a record (RFC 7208 §4.6.4).
pub const MAX_LOOKUPS: u32 = 10;
/// Void lookups allowed (non-existent name or no data).
pub const MAX_VOID: u32 = 2;
const MAX_DEPTH: u8 = 10;

/// DNS data gathered before the evaluation.
#[derive(Debug, Default, Clone)]
pub struct Data {
    /// TXT of every domain touched by the record (or the query error).
    pub txt: HashMap<String, std::result::Result<Vec<String>, String>>,
    /// A and AAAA addresses of every name.
    pub addr: HashMap<String, Vec<IpAddr>>,
    /// MX servers of every domain.
    pub mx: HashMap<String, Vec<String>>,
}

/// What is still needed to evaluate a record.
#[derive(Debug, Clone, PartialEq)]
pub enum Need {
    Spf(String),
    Addr(String),
    Mx(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Mech {
    All,
    Include(String),
    A(Option<String>, Option<u8>, Option<u8>),
    Mx(Option<String>, Option<u8>, Option<u8>),
    Ptr,
    Ip(IpNet),
    Exists(String),
    Redirect(String),
    /// Modifier with no effect on the evaluation (`exp=` and the like).
    Modifier,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
struct Term {
    raw: String,
    qual: char,
    mech: Mech,
}

fn norm(d: &str) -> String {
    d.trim_end_matches('.').to_ascii_lowercase()
}

/// The SPF records among the TXTs of a name.
pub fn records(txt: &[String]) -> Vec<String> {
    txt.iter()
        .map(|t| t.trim().to_string())
        .filter(|t| {
            let l = t.to_ascii_lowercase();
            l == "v=spf1" || l.starts_with("v=spf1 ")
        })
        .collect()
}

/// `name/24//64` → name, IPv4 prefix, IPv6 prefix.
fn dual_cidr(s: &str) -> (Option<String>, Option<u8>, Option<u8>) {
    let (name, cidr) = match s.find('/') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    let name = name.strip_prefix(':').unwrap_or(name);
    let (c4, c6) = match cidr.split_once("//") {
        Some((a, b)) => (a, b),
        None if cidr.starts_with('/') => ("", &cidr[1..]),
        None => (cidr, ""),
    };
    (
        (!name.is_empty()).then(|| norm(name)),
        c4.parse().ok(),
        c6.parse().ok(),
    )
}

fn parse(record: &str) -> Vec<Term> {
    record
        .split_whitespace()
        .skip(1)
        .map(|raw| {
            let (qual, body) = match raw.chars().next() {
                Some(c @ ('+' | '-' | '~' | '?')) => (c, &raw[1..]),
                _ => ('+', raw),
            };
            let low = body.to_ascii_lowercase();
            let mech = if low == "all" {
                Mech::All
            } else if let Some(d) = low.strip_prefix("include:") {
                Mech::Include(norm(d))
            } else if let Some(d) = low.strip_prefix("redirect=") {
                Mech::Redirect(norm(d))
            } else if let Some(n) = low.strip_prefix("ip4:").or(low.strip_prefix("ip6:")) {
                let net = n
                    .parse::<IpNet>()
                    .ok()
                    .or_else(|| n.parse::<IpAddr>().ok().map(IpNet::from));
                net.map(Mech::Ip).unwrap_or(Mech::Unknown)
            } else if let Some(d) = low.strip_prefix("exists:") {
                Mech::Exists(d.to_string())
            } else if low == "ptr" || low.starts_with("ptr:") {
                Mech::Ptr
            } else if low == "a" || low.starts_with("a:") || low.starts_with("a/") {
                let (n, c4, c6) = dual_cidr(&low[1..]);
                Mech::A(n, c4, c6)
            } else if low == "mx" || low.starts_with("mx:") || low.starts_with("mx/") {
                let (n, c4, c6) = dual_cidr(&low[2..]);
                Mech::Mx(n, c4, c6)
            } else if low.contains('=') {
                Mech::Modifier
            } else {
                Mech::Unknown
            };
            Term {
                raw: raw.to_string(),
                qual,
                mech,
            }
        })
        .collect()
}

/// What must be asked of the DNS to evaluate `record`, published by `domain`.
/// Names with a macro (`%{…}`) cannot be resolved without a message.
pub fn needs(record: &str, domain: &str) -> Vec<Need> {
    let own = norm(domain);
    let plain = |d: &String| !d.contains('%');
    parse(record)
        .into_iter()
        .filter_map(|t| match t.mech {
            Mech::Include(d) | Mech::Redirect(d) if plain(&d) => Some(Need::Spf(d)),
            Mech::A(n, ..) => {
                Some(Need::Addr(n.unwrap_or_else(|| own.clone()))).filter(|x| match x {
                    Need::Addr(d) => plain(d),
                    _ => true,
                })
            }
            Mech::Mx(n, ..) => {
                Some(Need::Mx(n.unwrap_or_else(|| own.clone()))).filter(|x| match x {
                    Need::Mx(d) => plain(d),
                    _ => true,
                })
            }
            Mech::Exists(d) if plain(&d) => Some(Need::Addr(norm(&d))),
            _ => None,
        })
        .collect()
}

/// A row of the tree.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Node {
    /// 0 = the domain's record, 1 = its mechanisms, 2 = those of an `include`…
    pub level: u8,
    /// As written in the record.
    pub mechanism: String,
    /// DNS lookups it costs (0 for ip4, ip6, all).
    pub lookups: u32,
    /// What it contains or what it resolves to.
    pub result: String,
    /// "" normal, "ok" = it is the mechanism that decides for the requested IP,
    /// "err" = error or lookup over the limit, "off" = not evaluated
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct Report {
    pub found: bool,
    /// The domain's record (the first, if there is more than one).
    pub record: String,
    /// How many `v=spf1` records the domain has.
    pub count: usize,
    pub nodes: Vec<Node>,
    /// DNS lookups in the worst case.
    pub lookups: u32,
    pub void_lookups: u32,
    /// How the record ends: "-all", "~all", "?all", "+all", or empty.
    pub all: String,
    /// IP checked, result ("pass", "fail", "softfail", "neutral", "permerror"…) and
    /// mechanism that decided.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip_result: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip_match: String,
    #[serde(skip)]
    pub uses_ptr: bool,
    #[serde(skip)]
    pub unknown: Vec<String>,
    #[serde(skip)]
    pub error: String,
}

fn verdict(q: char) -> &'static str {
    match q {
        '-' => "fail",
        '~' => "softfail",
        '?' => "neutral",
        _ => "pass",
    }
}

struct State<'a> {
    data: &'a Data,
    ip: Option<IpAddr>,
    nodes: Vec<Node>,
    lookups: u32,
    void: u32,
    over: bool,
    uses_ptr: bool,
    unknown: Vec<String>,
    matched: String,
    stack: Vec<String>,
}

fn in_net(ip: IpAddr, addr: IpAddr, c4: Option<u8>, c6: Option<u8>) -> bool {
    let len = match addr {
        IpAddr::V4(_) => c4.unwrap_or(32).min(32),
        IpAddr::V6(_) => c6.unwrap_or(128).min(128),
    };
    IpNet::new(addr, len).is_ok_and(|n| n.trunc().contains(&ip))
}

impl State<'_> {
    /// Counts a lookup; `false` if it is over the limit (the node is not evaluated).
    fn spend(&mut self, node: &mut Node) -> bool {
        if self.over {
            node.status = "off";
            node.result = t!(
                "non valutato (oltre il limite)",
                "not evaluated (over the limit)"
            )
            .into();
            return false;
        }
        self.lookups += node.lookups;
        if self.lookups > MAX_LOOKUPS {
            self.over = true;
            node.status = ERR;
            node.note = tf!(
                "Ricerca numero {}: oltre il limite di {MAX_LOOKUPS}, da qui in poi il record non viene più valutato.",
                "Lookup number {}: over the limit of {MAX_LOOKUPS}, from here on the record is no longer evaluated.",
                self.lookups
            );
        }
        true
    }

    /// Evaluates the mechanisms of the record of `domain` (rows at level `level`).
    /// `live`: this branch is still the one that decides for the IP. Returns the result.
    fn walk(&mut self, domain: &str, level: u8, live: bool) -> (&'static str, Option<usize>) {
        let recs = match self.data.txt.get(domain) {
            Some(Ok(t)) => records(t),
            Some(Err(_)) => return ("temperror", None),
            None => vec![],
        };
        if recs.len() != 1 || level > MAX_DEPTH || self.stack.iter().any(|d| d == domain) {
            return (if recs.is_empty() { "none" } else { "permerror" }, None);
        }
        self.stack.push(domain.to_string());
        let mut result: Option<&'static str> = None;
        // row of the deciding mechanism, if it is in this branch
        let mut mark: Option<usize> = None;
        let mut redirect = None;
        for t in parse(&recs[0]) {
            let mut node = Node {
                level,
                mechanism: t.raw.clone(),
                lookups: 0,
                result: String::new(),
                status: "",
                note: String::new(),
            };
            let open = live && result.is_none();
            let mut hit = false;
            match &t.mech {
                Mech::Modifier => continue,
                Mech::All => {
                    node.result = tf!("tutto il resto: {}", "everything else: {}", verdict(t.qual));
                    hit = true;
                }
                Mech::Ip(net) => {
                    hit = self.ip.is_some_and(|ip| net.trunc().contains(&ip));
                }
                Mech::Ptr => {
                    node.lookups = 1;
                    self.uses_ptr = true;
                    if self.spend(&mut node) {
                        node.result = t!(
                            "sconsigliato: lento e inaffidabile, non valutato",
                            "discouraged: slow and unreliable, not evaluated"
                        )
                        .into();
                    }
                }
                Mech::Unknown => {
                    node.status = ERR;
                    node.result = t!(
                        "meccanismo non riconosciuto: il record non è valido",
                        "mechanism not recognised: the record is not valid"
                    )
                    .into();
                    self.unknown.push(t.raw.clone());
                    if open {
                        result = Some("permerror");
                    }
                }
                Mech::A(n, c4, c6) => {
                    node.lookups = 1;
                    if self.spend(&mut node) {
                        let name = n.clone().unwrap_or_else(|| domain.to_string());
                        if name.contains('%') {
                            node.result = t!(
                                "contiene una macro: non valutabile senza un messaggio",
                                "contains a macro: cannot be evaluated without a message"
                            )
                            .into();
                        } else {
                            let addrs = self.data.addr.get(&name).cloned().unwrap_or_default();
                            if addrs.is_empty() {
                                self.void += 1;
                                node.result = tf!("{name}: nessun indirizzo", "{name}: no address");
                            } else {
                                node.result = addrs
                                    .iter()
                                    .map(IpAddr::to_string)
                                    .collect::<Vec<_>>()
                                    .join(" · ");
                                hit = self.ip.is_some_and(|ip| {
                                    addrs.iter().any(|a| in_net(ip, *a, *c4, *c6))
                                });
                            }
                        }
                    }
                }
                Mech::Mx(n, c4, c6) => {
                    node.lookups = 1;
                    if self.spend(&mut node) {
                        let name = n.clone().unwrap_or_else(|| domain.to_string());
                        let hosts = self.data.mx.get(&name).cloned().unwrap_or_default();
                        if hosts.is_empty() {
                            self.void += 1;
                            node.result = tf!("{name}: nessun MX", "{name}: no MX");
                        } else {
                            let mut parts = Vec::new();
                            for h in &hosts {
                                let addrs = self.data.addr.get(h).cloned().unwrap_or_default();
                                hit |= self.ip.is_some_and(|ip| {
                                    addrs.iter().any(|a| in_net(ip, *a, *c4, *c6))
                                });
                                parts.push(format!(
                                    "{h} {}",
                                    addrs
                                        .iter()
                                        .map(IpAddr::to_string)
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                ));
                            }
                            node.result = parts.join(" · ");
                        }
                    }
                }
                Mech::Exists(d) => {
                    node.lookups = 1;
                    if self.spend(&mut node) {
                        if d.contains('%') {
                            node.result = t!(
                                "contiene una macro: non valutabile senza un messaggio",
                                "contains a macro: cannot be evaluated without a message"
                            )
                            .into();
                        } else if self.data.addr.get(&norm(d)).is_some_and(|a| !a.is_empty()) {
                            node.result = t!("il nome esiste", "the name exists").into();
                            hit = true;
                        } else {
                            self.void += 1;
                            node.result =
                                t!("il nome non esiste", "the name does not exist").into();
                        }
                    }
                }
                Mech::Include(d) | Mech::Redirect(d) => {
                    node.lookups = 1;
                    let is_redirect = matches!(t.mech, Mech::Redirect(_));
                    if !self.spend(&mut node) {
                        self.nodes.push(node);
                        continue;
                    }
                    if d.contains('%') {
                        node.result = t!(
                            "contiene una macro: non valutabile senza un messaggio",
                            "contains a macro: cannot be evaluated without a message"
                        )
                        .into();
                        self.nodes.push(node);
                        continue;
                    }
                    let inner = match self.data.txt.get(d) {
                        Some(Ok(t)) => records(t),
                        _ => vec![],
                    };
                    let looped = self.stack.iter().any(|x| x == d);
                    if looped {
                        node.status = ERR;
                        node.result = t!(
                            "richiama un record già in valutazione: ciclo",
                            "calls a record already being evaluated: loop"
                        )
                        .into();
                    } else if inner.len() == 1 {
                        node.result = inner[0].clone();
                    } else {
                        node.status = ERR;
                        node.result = if inner.is_empty() {
                            self.void += 1;
                            tf!(
                                "{d} non ha un record SPF: il record non è valido",
                                "{d} has no SPF record: the record is not valid"
                            )
                        } else {
                            tf!(
                                "{d} ha {} record SPF: il record non è valido",
                                "{d} has {} SPF records: the record is not valid",
                                inner.len()
                            )
                        };
                    }
                    let bad = node.status == ERR;
                    self.nodes.push(node);
                    if is_redirect {
                        redirect = Some((d.clone(), bad));
                        continue;
                    }
                    let (sub, inner_mark) = if bad {
                        ("permerror", None)
                    } else {
                        self.walk(d, level + 1, open)
                    };
                    if open {
                        match sub {
                            "pass" => {
                                result = Some(verdict(t.qual));
                                mark = inner_mark;
                            }
                            "permerror" | "none" => result = Some("permerror"),
                            "temperror" => result = Some("temperror"),
                            _ => {}
                        }
                    }
                    continue;
                }
            }
            if hit && open {
                result = Some(verdict(t.qual));
                mark = Some(self.nodes.len());
            }
            self.nodes.push(node);
        }
        // redirect: only counts if no mechanism has decided (and there is no "all")
        let out = match (result, redirect) {
            (Some(r), Some((d, bad))) => {
                if !bad {
                    self.walk(&d, level + 1, false);
                }
                r
            }
            (None, Some((d, bad))) => {
                if bad {
                    "permerror"
                } else {
                    let (r, m) = self.walk(&d, level + 1, live);
                    mark = m;
                    if r == "none" {
                        "permerror"
                    } else {
                        r
                    }
                }
            }
            (Some(r), None) => r,
            (None, None) => "neutral",
        };
        self.stack.pop();
        (out, mark)
    }
}

/// Tree of the record of `domain` and, if `ip` is given, the result for that address.
pub fn evaluate(domain: &str, data: &Data, ip: Option<IpAddr>) -> Report {
    let domain = norm(domain);
    let mut r = Report::default();
    let recs = match data.txt.get(&domain) {
        Some(Ok(t)) => records(t),
        Some(Err(e)) => {
            r.error = e.clone();
            return r;
        }
        None => vec![],
    };
    r.count = recs.len();
    let Some(first) = recs.first() else {
        return r;
    };
    r.found = true;
    r.record = first.clone();
    r.all = parse(first)
        .iter()
        .find(|t| t.mech == Mech::All)
        .map(|t| format!("{}all", t.qual))
        .unwrap_or_default();
    let mut st = State {
        data,
        ip,
        nodes: vec![Node {
            level: 0,
            mechanism: first.clone(),
            lookups: 0,
            result: domain.clone(),
            status: "",
            note: String::new(),
        }],
        lookups: 0,
        void: 0,
        over: false,
        uses_ptr: false,
        unknown: vec![],
        matched: String::new(),
        stack: vec![],
    };
    let (res, mark) = if recs.len() > 1 {
        ("permerror", None)
    } else {
        st.walk(&domain, 1, ip.is_some())
    };
    // only the mechanism that really decides is marked (not the includes' "all")
    if let (Some(i), Some(ip)) = (mark, ip) {
        let n = &mut st.nodes[i];
        n.status = OK;
        if !n.mechanism.to_ascii_lowercase().ends_with("all") {
            n.result = if n.result.is_empty() {
                tf!("corrisponde a {ip}", "matches {ip}")
            } else {
                tf!("{} · corrisponde a {ip}", "{} · matches {ip}", n.result)
            };
        }
        st.matched = n.mechanism.clone();
    }
    r.lookups = st.lookups;
    r.void_lookups = st.void;
    r.uses_ptr = st.uses_ptr;
    r.unknown = st.unknown;
    if let Some(ip) = ip {
        r.ip = ip.to_string();
        r.ip_result = if st.lookups > MAX_LOOKUPS {
            "permerror".into()
        } else {
            res.to_string()
        };
        r.ip_match = st.matched;
    }
    r.nodes = st.nodes;
    r
}

/// Checks on the record.
pub fn checks(r: &Report) -> Vec<Check> {
    const A: &str = "SPF";
    let mut out = Vec::new();
    if !r.error.is_empty() {
        out.push(check(
            A,
            WARN,
            "Record",
            tf!("non leggibile: {}", "unreadable: {}", r.error),
        ));
        return out;
    }
    if !r.found {
        out.push(check(
            A,
            ERR,
            "Record",
            t!(
                "assente: chiunque può inviare posta a nome del dominio senza che SPF lo segnali",
                "missing: anyone can send mail on behalf of the domain without SPF flagging it"
            ),
        ));
        return out;
    }
    if r.count > 1 {
        out.push(check(
            A,
            ERR,
            "Record",
            tf!(
                "{} record v=spf1: deve essercene uno solo, altrimenti SPF non vale (permerror)",
                "{} v=spf1 records: there must be only one, otherwise SPF is void (permerror)",
                r.count
            ),
        ));
    }
    if r.lookups > MAX_LOOKUPS {
        out.push(check(
            A,
            ERR,
            t!("Limite di lookup", "Lookup limit"),
            tf!(
                "{} ricerche DNS, il massimo è {MAX_LOOKUPS}: i destinatari trattano il record come non valido (permerror)",
                "{} DNS lookups, the maximum is {MAX_LOOKUPS}: recipients treat the record as invalid (permerror)",
                r.lookups
            ),
        ));
    } else {
        out.push(check(
            A,
            OK,
            t!("Limite di lookup", "Lookup limit"),
            tf!(
                "{} ricerche DNS su {MAX_LOOKUPS}",
                "{} DNS lookups out of {MAX_LOOKUPS}",
                r.lookups
            ),
        ));
    }
    if !r.unknown.is_empty() {
        out.push(check(
            A,
            ERR,
            t!("Sintassi", "Syntax"),
            tf!(
                "meccanismi non riconosciuti: {}",
                "mechanisms not recognised: {}",
                r.unknown.join(", ")
            ),
        ));
    }
    let bad_inc: Vec<&str> = r
        .nodes
        .iter()
        .filter(|n| n.status == ERR && n.lookups > 0 && n.note.is_empty())
        .map(|n| n.mechanism.as_str())
        .collect();
    if !bad_inc.is_empty() {
        out.push(check(
            A,
            ERR,
            "Include",
            tf!(
                "non valutabili: {}",
                "cannot be evaluated: {}",
                bad_inc.join(", ")
            ),
        ));
    }
    if r.void_lookups > MAX_VOID {
        out.push(check(
            A,
            WARN,
            t!("Ricerche a vuoto", "Void lookups"),
            tf!(
                "{} nomi senza dati, il massimo è {MAX_VOID}: alcuni destinatari danno permerror",
                "{} names without data, the maximum is {MAX_VOID}: some recipients give permerror",
                r.void_lookups
            ),
        ));
    }
    if r.uses_ptr {
        out.push(check(
            A,
            WARN,
            "ptr",
            t!(
                "meccanismo sconsigliato dall'RFC 7208: lento e inaffidabile",
                "mechanism discouraged by RFC 7208: slow and unreliable"
            ),
        ));
    }
    let redirect = r
        .nodes
        .iter()
        .any(|n| n.level == 1 && n.mechanism.to_ascii_lowercase().starts_with("redirect="));
    match r.all.as_str() {
        "-all" => out.push(check(
            A,
            OK,
            t!("Chiusura", "Ending"),
            t!(
                "-all: tutto il resto viene rifiutato",
                "-all: everything else is rejected"
            ),
        )),
        "~all" => out.push(check(
            A,
            INFO,
            t!("Chiusura", "Ending"),
            t!(
                "~all: tutto il resto è sospetto ma accettato (softfail)",
                "~all: everything else is suspicious but accepted (softfail)"
            ),
        )),
        "?all" => out.push(check(
            A,
            WARN,
            t!("Chiusura", "Ending"),
            t!(
                "?all: nessuna indicazione per gli altri server (neutral)",
                "?all: no indication for other servers (neutral)"
            ),
        )),
        "+all" => out.push(check(
            A,
            ERR,
            t!("Chiusura", "Ending"),
            t!(
                "+all: qualsiasi server è autorizzato a inviare a nome del dominio",
                "+all: any server is authorised to send on behalf of the domain"
            ),
        )),
        _ if redirect => {}
        _ => out.push(check(
            A,
            WARN,
            t!("Chiusura", "Ending"),
            t!(
                "manca \"all\": per gli altri server l'esito è neutro",
                "\"all\" is missing: for other servers the result is neutral"
            ),
        )),
    }
    if !r.ip.is_empty() {
        out.push(check(
            A,
            INFO,
            &format!("IP {}", r.ip),
            if r.ip_match.is_empty() {
                r.ip_result.clone()
            } else {
                tf!(
                    "{}: decide {}",
                    "{}: decided by {}",
                    r.ip_result,
                    r.ip_match
                )
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(txt: &[(&str, &str)], addr: &[(&str, &[&str])], mx: &[(&str, &[&str])]) -> Data {
        let mut d = Data::default();
        for (n, t) in txt {
            d.txt
                .entry(n.to_string())
                .or_insert_with(|| Ok(vec![]))
                .as_mut()
                .unwrap()
                .push(t.to_string());
        }
        for (n, a) in addr {
            d.addr.insert(
                n.to_string(),
                a.iter().map(|x| x.parse().unwrap()).collect(),
            );
        }
        for (n, h) in mx {
            d.mx.insert(n.to_string(), h.iter().map(|x| x.to_string()).collect());
        }
        d
    }

    fn find<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("manca {name}: {c:#?}"))
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn lettura_del_record() {
        let t = parse("v=spf1 MX a:mail.Example.com/28 -ip4:192.0.2.0/24 ip6:2001:db8::/32 ~include:_spf.example.net exists:%{i}.x.example ptr exp=e.example.com boh ?all");
        let m: Vec<&Mech> = t.iter().map(|x| &x.mech).collect();
        assert_eq!(*m[0], Mech::Mx(None, None, None));
        assert_eq!(
            *m[1],
            Mech::A(Some("mail.example.com".into()), Some(28), None)
        );
        assert!(matches!(m[2], Mech::Ip(n) if n.to_string() == "192.0.2.0/24"));
        assert!(matches!(m[3], Mech::Ip(n) if n.to_string() == "2001:db8::/32"));
        assert_eq!(*m[4], Mech::Include("_spf.example.net".into()));
        assert_eq!(*m[5], Mech::Exists("%{i}.x.example".into()));
        assert_eq!(
            (m[6], m[7], m[8]),
            (&Mech::Ptr, &Mech::Modifier, &Mech::Unknown)
        );
        assert_eq!((t[2].qual, t[4].qual, t[9].qual), ('-', '~', '?'));
        assert_eq!(dual_cidr("/24//64"), (None, Some(24), Some(64)));
        assert_eq!(dual_cidr("//64"), (None, None, Some(64)));
        assert_eq!(
            dual_cidr(":mx.example.com"),
            (Some("mx.example.com".into()), None, None)
        );
        assert!(
            matches!(&parse("v=spf1 ip4:192.0.2.7")[0].mech, Mech::Ip(n) if n.prefix_len() == 32)
        );
        assert_eq!(
            records(&[
                "altro".into(),
                "V=SPF1 -all".into(),
                "v=spf10 x".into(),
                "v=spf1".into()
            ]),
            vec!["V=SPF1 -all", "v=spf1"]
        );
        assert_eq!(
            needs("v=spf1 mx a:out.example.org include:_spf.example.net redirect=r.example.net exists:%{i}.x ip4:192.0.2.1 -all", "Example.com."),
            vec![
                Need::Mx("example.com".into()),
                Need::Addr("out.example.org".into()),
                Need::Spf("_spf.example.net".into()),
                Need::Spf("r.example.net".into())
            ]
        );
    }

    fn sample() -> Data {
        data(
            &[
                (
                    "example.com",
                    "v=spf1 mx include:_spf.mail.example.net ip4:203.0.113.0/28 -all",
                ),
                ("example.com", "google-site-verification=abc"),
                (
                    "_spf.mail.example.net",
                    "v=spf1 include:_a.mail.example.net a:out.mail.example.net ~all",
                ),
                (
                    "_a.mail.example.net",
                    "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8:25::/48 ~all",
                ),
            ],
            &[
                ("mail1.example.com", &["203.0.113.40"]),
                ("out.mail.example.net", &["192.0.2.200", "2001:db8::200"]),
            ],
            &[("example.com", &["mail1.example.com"])],
        )
    }

    #[test]
    fn albero_e_conteggio() {
        let r = evaluate("Example.COM", &sample(), None);
        assert!(r.found && r.count == 1);
        assert_eq!((r.lookups, r.void_lookups, r.all.as_str()), (4, 0, "-all"));
        let shape: Vec<(u8, &str, u32)> = r
            .nodes
            .iter()
            .map(|n| (n.level, n.mechanism.as_str(), n.lookups))
            .collect();
        assert_eq!(
            shape,
            vec![
                (
                    0,
                    "v=spf1 mx include:_spf.mail.example.net ip4:203.0.113.0/28 -all",
                    0
                ),
                (1, "mx", 1),
                (1, "include:_spf.mail.example.net", 1),
                (2, "include:_a.mail.example.net", 1),
                (3, "ip4:198.51.100.0/24", 0),
                (3, "ip6:2001:db8:25::/48", 0),
                (3, "~all", 0),
                (2, "a:out.mail.example.net", 1),
                (2, "~all", 0),
                (1, "ip4:203.0.113.0/28", 0),
                (1, "-all", 0),
            ]
        );
        assert_eq!(r.nodes[0].result, "example.com");
        assert_eq!(r.nodes[1].result, "mail1.example.com 203.0.113.40");
        assert!(r.nodes[2].result.starts_with("v=spf1 include:_a.mail"));
        assert_eq!(r.nodes[7].result, "192.0.2.200 · 2001:db8::200");
        assert_eq!(r.nodes[10].result, "tutto il resto: fail");
        assert!(r.nodes.iter().all(|n| n.status.is_empty()) && r.ip.is_empty());
        let c = checks(&r);
        assert_eq!(find(&c, "Limite di lookup").detail, "4 ricerche DNS su 10");
        assert_eq!(find(&c, "Chiusura").status, OK);
        assert!(c.iter().all(|x| x.status == OK), "{c:#?}");
    }

    #[test]
    fn esito_per_un_indirizzo() {
        let d = sample();
        let go = |a: &str| evaluate("example.com", &d, ip(a));
        // the domain's ip4
        let r = go("203.0.113.5");
        assert_eq!(
            (r.ip_result.as_str(), r.ip_match.as_str()),
            ("pass", "ip4:203.0.113.0/28")
        );
        let hit: Vec<&Node> = r.nodes.iter().filter(|n| n.status == OK).collect();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].result, "corrisponde a 203.0.113.5");
        // the MX
        let r = go("203.0.113.40");
        assert_eq!((r.ip_result.as_str(), r.ip_match.as_str()), ("pass", "mx"));
        assert!(r.nodes[1].result.ends_with("· corrisponde a 203.0.113.40"));
        // inside two includes: the innermost ip4 decides, and the result is the include's (+)
        let r = go("198.51.100.77");
        assert_eq!(
            (r.ip_result.as_str(), r.ip_match.as_str()),
            ("pass", "ip4:198.51.100.0/24")
        );
        // IPv6 inside the include, and the AAAA address of "a:"
        assert_eq!(go("2001:db8:25:1::9").ip_result, "pass");
        let r = go("2001:db8::200");
        assert_eq!(
            (r.ip_result.as_str(), r.ip_match.as_str()),
            ("pass", "a:out.mail.example.net")
        );
        // none: the includes' "~all" does not decide, the domain's "-all" does
        let r = go("192.0.2.1");
        assert_eq!(
            (r.ip_result.as_str(), r.ip_match.as_str()),
            ("fail", "-all")
        );
        assert_eq!(r.nodes.iter().filter(|n| n.status == OK).count(), 1);
        assert_eq!(r.nodes.last().unwrap().status, OK);
        let c = checks(&r);
        assert_eq!(find(&c, "IP 192.0.2.1").detail, "fail: decide -all");
    }

    #[test]
    fn oltre_il_limite() {
        // 12 includes in a row: the eleventh is over the limit, the twelfth is not evaluated
        let mut txt: Vec<(String, String)> = vec![(
            "example.com".into(),
            format!(
                "v=spf1 {} -all",
                (1..=12)
                    .map(|i| format!("include:s{i}.example.net"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        )];
        for i in 1..=12 {
            txt.push((
                format!("s{i}.example.net"),
                format!("v=spf1 ip4:192.0.2.{i} ~all"),
            ));
        }
        let refs: Vec<(&str, &str)> = txt.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let d = data(&refs, &[], &[]);
        let r = evaluate("example.com", &d, ip("192.0.2.12"));
        assert_eq!(r.lookups, 11);
        let inc: Vec<&Node> = r
            .nodes
            .iter()
            .filter(|n| n.level == 1 && n.lookups == 1)
            .collect();
        assert_eq!(inc.len(), 12);
        assert!(inc[..10].iter().all(|n| n.status.is_empty()));
        assert_eq!(inc[10].status, ERR);
        assert!(inc[10].note.contains("Ricerca numero 11"));
        assert_eq!(inc[11].status, "off");
        assert_eq!(r.ip_result, "permerror");
        let c = checks(&r);
        let l = find(&c, "Limite di lookup");
        assert_eq!(l.status, ERR);
        assert!(l.detail.starts_with("11 ricerche DNS"));
        // the eleventh include is marked as the limit, not as "cannot be evaluated"
        assert!(!c.iter().any(|x| x.name == "Include"));
    }

    #[test]
    fn casi_particolari() {
        // no record, two records, unreadable record
        let r = evaluate("example.com", &Data::default(), None);
        assert!(!r.found);
        assert_eq!(find(&checks(&r), "Record").status, ERR);
        let d = data(
            &[
                ("example.com", "v=spf1 -all"),
                ("example.com", "v=spf1 mx -all"),
            ],
            &[],
            &[],
        );
        let r = evaluate("example.com", &d, ip("192.0.2.1"));
        assert_eq!((r.count, r.ip_result.as_str()), (2, "permerror"));
        assert!(find(&checks(&r), "Record").detail.starts_with("2 record"));
        let mut broken = Data::default();
        broken
            .txt
            .insert("example.com".into(), Err("TIMEOUT".into()));
        assert_eq!(
            find(&checks(&evaluate("example.com", &broken, None)), "Record").status,
            WARN
        );

        // include without a record, loop, macro, ptr, unknown mechanism, without all
        let d = data(
            &[
                ("example.com", "v=spf1 include:vuoto.example.net include:giro.example.net exists:%{i}.rbl.example.net a mx:altro.example.org ptr pippo"),
                ("giro.example.net", "v=spf1 include:example.com ~all"),
            ],
            &[],
            &[],
        );
        let r = evaluate("example.com", &d, None);
        let by = |m: &str| r.nodes.iter().find(|n| n.mechanism == m).unwrap();
        assert_eq!(by("include:vuoto.example.net").status, ERR);
        assert!(by("include:vuoto.example.net")
            .result
            .contains("non ha un record SPF"));
        assert!(by("include:example.com").result.contains("ciclo"));
        assert!(by("exists:%{i}.rbl.example.net").result.contains("macro"));
        assert_eq!(by("a").result, "example.com: nessun indirizzo");
        assert_eq!(
            by("mx:altro.example.org").result,
            "altro.example.org: nessun MX"
        );
        assert_eq!(by("pippo").status, ERR);
        assert_eq!((r.lookups, r.void_lookups), (7, 3));
        let c = checks(&r);
        assert_eq!(find(&c, "Sintassi").status, ERR);
        assert_eq!(find(&c, "ptr").status, WARN);
        assert_eq!(find(&c, "Ricerche a vuoto").status, WARN);
        assert!(find(&c, "Include")
            .detail
            .contains("include:vuoto.example.net"));
        assert!(find(&c, "Chiusura").detail.contains("manca"));

        // endings
        for (rec, st) in [
            ("v=spf1 +all", ERR),
            ("v=spf1 ?all", WARN),
            ("v=spf1 ~all", INFO),
        ] {
            let d = data(&[("example.com", rec)], &[], &[]);
            assert_eq!(
                find(&checks(&evaluate("example.com", &d, None)), "Chiusura").status,
                st,
                "{rec}"
            );
        }
    }

    #[test]
    fn redirect_ed_exists() {
        let d = data(
            &[
                (
                    "example.com",
                    "v=spf1 exists:ok.example.net redirect=_spf.example.net",
                ),
                ("_spf.example.net", "v=spf1 ip4:192.0.2.0/24 -all"),
            ],
            &[("ok.example.net", &["127.0.0.2"])],
            &[],
        );
        // exists with a name that exists decides for any address
        let r = evaluate("example.com", &d, ip("203.0.113.1"));
        assert_eq!(
            (r.ip_result.as_str(), r.ip_match.as_str()),
            ("pass", "exists:ok.example.net")
        );
        assert_eq!(r.lookups, 2);
        // without exists the redirect's record decides
        let d = data(
            &[
                ("example.com", "v=spf1 redirect=_spf.example.net"),
                ("_spf.example.net", "v=spf1 ip4:192.0.2.0/24 -all"),
            ],
            &[],
            &[],
        );
        assert_eq!(
            evaluate("example.com", &d, ip("192.0.2.9")).ip_result,
            "pass"
        );
        let r = evaluate("example.com", &d, ip("203.0.113.1"));
        assert_eq!(
            (r.ip_result.as_str(), r.ip_match.as_str()),
            ("fail", "-all")
        );
        assert_eq!(
            r.nodes.iter().map(|n| n.level).collect::<Vec<_>>(),
            vec![0, 1, 2, 2]
        );
        // with redirect there is no need for "all" in the domain's record
        assert!(!checks(&r).iter().any(|c| c.name == "Chiusura"));
        // redirect to a domain without SPF
        let d = data(
            &[("example.com", "v=spf1 redirect=vuoto.example.net")],
            &[],
            &[],
        );
        assert_eq!(
            evaluate("example.com", &d, ip("192.0.2.9")).ip_result,
            "permerror"
        );
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let r = evaluate("example.com", &sample(), ip("192.0.2.1"));
        let c = checks(&r);
        assert_eq!(find(&c, "Lookup limit").detail, "4 DNS lookups out of 10");
        assert_eq!(find(&c, "IP 192.0.2.1").detail, "fail: decided by -all");
        assert_eq!(r.nodes.last().unwrap().result, "everything else: fail");
        assert!(!c.iter().any(|x| x.name == "Limite di lookup"));
        let r = evaluate("example.com", &Data::default(), None);
        assert!(find(&checks(&r), "Record").detail.starts_with("missing:"));
    }
}
