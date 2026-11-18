//! Email: analysis of a domain (evaluated SPF, DMARC, DKIM, MX, MTA-STS, TLS-RPT, BIMI)
//! and of the headers of a message (path, authentication, anti-spam).
//!
//! The rules live in three modules of pure functions only ([`spf`], [`policy`],
//! [`message`]); here the data is gathered (the PC's DNS and, for MTA-STS, an HTTPS
//! request) through [`Lookup`], which in tests is an in-memory table.

use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::{dns, net, t, tf, whois, Result};
use hickory_proto::rr::{RData, RecordType};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

pub mod message;
pub mod policy;
pub mod spf;

/// DKIM selectors tried when the user does not give one.
pub const DKIM_SELECTORS: [&str; 12] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mail",
    "smtp",
    "dkim",
    "email",
    "s1",
    "s2",
];
/// Maximum SPF domains read for one record (nested includes included).
const MAX_SPF_DOMAINS: usize = 40;
const MAX_MX: usize = 10;

#[derive(Debug, Deserialize)]
pub struct EmailReq {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub raw_header: Option<String>,
    /// DKIM selectors to try, comma-separated (empty = the most common ones).
    #[serde(default)]
    pub selector: String,
    /// Address to evaluate against the SPF record (optional).
    #[serde(default)]
    pub ip: String,
}

/// Headers of a message: continuation lines joined, up to the first empty line.
pub fn parse_headers(raw: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            if out.is_empty() {
                continue;
            }
            break; // end of the headers, the body starts
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if !k.is_empty() && !k.contains(' ') {
                out.push((k.to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

/// IPv4 addresses in square brackets in Received headers.
pub fn bracket_ips(s: &str) -> Vec<Ipv4Addr> {
    let mut v = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find('[') {
        rest = &rest[i + 1..];
        if let Some(j) = rest.find(']') {
            if let Ok(ip) = rest[..j].parse() {
                v.push(ip);
            }
            rest = &rest[j + 1..];
        } else {
            break;
        }
    }
    v
}

/// SPF/DKIM/DMARC results from the **first** Authentication-Results, the one on top: it is
/// added by the last server that received the message (your own). The ones further
/// down may have been written by anyone, sender included, and are not used.
pub fn auth_results(headers: &[(String, String)]) -> Value {
    let all: Vec<&String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Authentication-Results"))
        .map(|(_, v)| v)
        .collect();
    let Some(first) = all.first() else {
        return Value::Null;
    };
    let parts: Vec<&str> = first.split(';').map(str::trim).collect();
    // authserv-id: first element, if it is not already a "method=result" (some services omit it)
    let server = parts
        .first()
        .filter(|p| !p.contains('='))
        .map(|p| p.to_string())
        .unwrap_or_default();
    let result = |method: &str| {
        parts.iter().find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim().eq_ignore_ascii_case(method).then(|| {
                v.split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
        })
    };
    json!({
        "server": server,
        "spf": result("spf"),
        "dkim": result("dkim"),
        "dmarc": result("dmarc"),
        "count": all.len(),
    })
}

// ───────────────────────── data sources ─────────────────────────

/// Where the data of a domain analysis comes from.
#[allow(async_fn_in_trait)]
pub trait Lookup {
    /// TXT records (the strings of one record joined). `Err` only if the DNS does not answer.
    async fn txt(&self, name: &str) -> std::result::Result<Vec<String>, String>;
    /// A and AAAA addresses.
    async fn addrs(&self, name: &str) -> Vec<IpAddr>;
    /// MX records: priority and server.
    async fn mx(&self, name: &str) -> Vec<(u16, String)>;
    async fn ptr(&self, ip: Ipv4Addr) -> String;
    /// MTA-STS policy downloaded over HTTPS.
    async fn policy(&self, url: &str) -> std::result::Result<String, String>;
}

/// This PC's DNS and, for the MTA-STS policy, an HTTPS request with the certificate
/// verified and without following redirects (RFC 8461 §3.3).
pub struct System {
    servers: Vec<SocketAddr>,
}

impl System {
    pub fn new() -> Result<Self> {
        Ok(System {
            servers: dns::system_dns()?.servers,
        })
    }
}

impl Lookup for System {
    async fn txt(&self, name: &str) -> std::result::Result<Vec<String>, String> {
        dns::txt(name, &self.servers).await
    }

    async fn addrs(&self, name: &str) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for t in [RecordType::A, RecordType::AAAA] {
            if let Ok((m, _, _)) = dns::query_any(name, t, &self.servers).await {
                for r in m.answers() {
                    match r.data() {
                        Some(RData::A(a)) => out.push(IpAddr::V4(a.0)),
                        Some(RData::AAAA(a)) => out.push(IpAddr::V6(a.0)),
                        _ => {}
                    }
                }
            }
        }
        out
    }

    async fn mx(&self, name: &str) -> Vec<(u16, String)> {
        dns::mx(name, &self.servers)
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|l| {
                let (p, h) = l.split_once(' ')?;
                Some((
                    p.parse().ok()?,
                    h.trim_end_matches('.').to_ascii_lowercase(),
                ))
            })
            .collect()
    }

    async fn ptr(&self, ip: Ipv4Addr) -> String {
        dns::ptr(ip).await
    }

    async fn policy(&self, url: &str) -> std::result::Result<String, String> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client.get(url).send().await.map_err(|e| {
            if e.is_timeout() {
                t!("nessuna risposta entro 8 s", "no response within 8 s").to_string()
            } else if e.is_connect() {
                t!(
                    "connessione o certificato non validi",
                    "connection or certificate not valid"
                )
                .to_string()
            } else {
                t!("richiesta HTTPS fallita", "HTTPS request failed").to_string()
            }
        })?;
        if resp.status().as_u16() != 200 {
            return Err(tf!(
                "risposta HTTP {}",
                "HTTP response {}",
                resp.status().as_u16()
            ));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|_| t!("risposta interrotta", "response interrupted").to_string())?;
        if body.len() > 64 * 1024 {
            return Err(t!("policy troppo grande", "policy too large").into());
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

/// Gathers everything needed to evaluate the SPF record of `domain`: the records of the
/// `include`s (at any depth), the addresses of the `a` mechanisms and of the MXs.
#[allow(clippy::map_entry)] // the entry is inserted after an await: no `entry`
pub async fn gather<L: Lookup>(l: &L, domain: &str) -> spf::Data {
    let mut data = spf::Data::default();
    let mut queue = vec![spf::Need::Spf(
        domain.trim_end_matches('.').to_ascii_lowercase(),
    )];
    let mut fetched = 0;
    while let Some(need) = queue.pop() {
        match need {
            spf::Need::Spf(d) => {
                if data.txt.contains_key(&d) || fetched >= MAX_SPF_DOMAINS {
                    continue;
                }
                fetched += 1;
                let r = l.txt(&d).await;
                if let Ok(t) = &r {
                    for rec in spf::records(t) {
                        queue.extend(spf::needs(&rec, &d));
                    }
                }
                data.txt.insert(d, r);
            }
            spf::Need::Addr(n) => {
                if !data.addr.contains_key(&n) {
                    let a = l.addrs(&n).await;
                    data.addr.insert(n, a);
                }
            }
            spf::Need::Mx(d) => {
                if !data.mx.contains_key(&d) {
                    let hosts: Vec<String> = l
                        .mx(&d)
                        .await
                        .into_iter()
                        .map(|(_, h)| h)
                        .take(MAX_MX)
                        .collect();
                    queue.extend(hosts.iter().cloned().map(spf::Need::Addr));
                    data.mx.insert(d, hosts);
                }
            }
        }
    }
    data
}

// ───────────────────────── domain analysis ─────────────────────────

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct MxHost {
    pub priority: u16,
    pub host: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// Reverse name of the first IPv4 address.
    pub ptr: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct DomainReport {
    pub domain: String,
    pub checks: Vec<Check>,
    pub spf: spf::Report,
    pub dmarc: policy::Dmarc,
    pub dkim: Vec<policy::DkimKey>,
    /// Selectors tried.
    pub selectors: Vec<String>,
    pub mx: Vec<MxHost>,
    pub mta_sts: policy::MtaSts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_rpt: Option<policy::Row>,
    pub bimi: String,
}

/// Checks on the MXs; fills in `status` and `note` of each server.
pub fn mx_checks(hosts: &mut [MxHost]) -> Vec<Check> {
    const A: &str = "MX";
    let mut out = Vec::new();
    if hosts.is_empty() {
        out.push(check(
            A,
            WARN,
            "Server",
            t!(
                "nessun record MX: la posta viene consegnata all'indirizzo del dominio, se esiste",
                "no MX record: mail is delivered to the domain's address, if it exists"
            ),
        ));
        return out;
    }
    if hosts.len() == 1 && (hosts[0].host.is_empty() || hosts[0].host == ".") {
        hosts[0].status = INFO;
        hosts[0].note = t!("MX nullo (RFC 7505)", "Null MX (RFC 7505)").into();
        out.push(check(
            A,
            INFO,
            "Server",
            t!(
                "MX nullo: il dominio dichiara di non ricevere posta",
                "Null MX: the domain declares that it does not receive mail"
            ),
        ));
        return out;
    }
    let mut no_ptr = Vec::new();
    for h in hosts.iter_mut() {
        h.status = OK;
        if h.host.parse::<IpAddr>().is_ok() {
            h.status = ERR;
            h.note = t!(
                "Un MX deve essere un nome, non un indirizzo.",
                "An MX must be a name, not an address."
            )
            .into();
            out.push(check(
                A,
                ERR,
                &h.host,
                t!(
                    "il record MX contiene un indirizzo IP invece di un nome",
                    "the MX record contains an IP address instead of a name"
                ),
            ));
        } else if h.ipv4.is_empty() && h.ipv6.is_empty() {
            h.status = ERR;
            h.note = t!("Il nome non ha indirizzi.", "The name has no addresses.").into();
            out.push(check(
                A,
                ERR,
                &h.host,
                t!(
                    "il nome non ha indirizzi (né A né AAAA)",
                    "the name has no addresses (neither A nor AAAA)"
                ),
            ));
        } else if h.ptr.is_empty() && !h.ipv4.is_empty() {
            no_ptr.push(h.host.clone());
            h.note = t!("Senza nome inverso.", "No reverse name.").into();
        }
    }
    if out.is_empty() {
        let n = hosts.len();
        out.push(check(
            A,
            OK,
            "Server",
            if n == 1 {
                t!("1 server, con indirizzo", "1 server, with an address").to_string()
            } else {
                tf!(
                    "{n} server, tutti con indirizzo",
                    "{n} servers, all with an address"
                )
            },
        ));
    }
    if !no_ptr.is_empty() {
        out.push(check(
            A,
            INFO,
            t!("Nome inverso", "Reverse name"),
            tf!("assente per {}", "missing for {}", no_ptr.join(", ")),
        ));
    }
    out
}

fn clean_selectors(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for s in raw
        .split([',', ' ', ';'])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
    {
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._".contains(c))
            || s.len() > 63
        {
            return Err(tf!(
                "Selettore DKIM non valido: {s}",
                "Invalid DKIM selector: {s}"
            ));
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.len() > 5 {
        return Err(t!("Massimo 5 selettori DKIM", "At most 5 DKIM selectors").into());
    }
    Ok(out)
}

pub async fn analyze_domain<L: Lookup>(l: &L, req: &EmailReq) -> Result<DomainReport> {
    let d = net::clean_host(req.domain.as_deref().unwrap_or(""))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if d.parse::<IpAddr>().is_ok() || !d.contains('.') {
        return Err(t!(
            "Indica un dominio, per esempio example.com",
            "Enter a domain, for example example.com"
        )
        .into());
    }
    let ip = match req.ip.trim() {
        "" => None,
        s => Some(s.parse::<IpAddr>().map_err(|_| {
            tf!(
                "IP da verificare non valido: {s}",
                "Invalid IP to check: {s}"
            )
        })?),
    };
    let asked = clean_selectors(&req.selector)?;
    let selectors: Vec<String> = if asked.is_empty() {
        DKIM_SELECTORS.iter().map(|s| s.to_string()).collect()
    } else {
        asked.clone()
    };
    let org = whois::registrable(&d);

    let dmarc_name = format!("_dmarc.{d}");
    let sts_name = format!("_mta-sts.{d}");
    let rpt_name = format!("_smtp._tls.{d}");
    let bimi_name = format!("default._bimi.{d}");
    let dkim_jobs = selectors.iter().map(|s| {
        let name = format!("{s}._domainkey.{d}");
        async move { l.txt(&name).await.unwrap_or_default().join("") }
    });
    let (data, dmarc_txt, mx_list, sts_txt, rpt_txt, bimi_txt, dkim_txt) = tokio::join!(
        gather(l, &d),
        l.txt(&dmarc_name),
        l.mx(&d),
        l.txt(&sts_name),
        l.txt(&rpt_name),
        l.txt(&bimi_name),
        dns::domain::futures_join(dkim_jobs),
    );

    // SPF
    let spf_report = spf::evaluate(&d, &data, ip);
    let mut checks = spf::checks(&spf_report);

    // DMARC: if the subdomain has no record, the organisational domain's one applies
    let mut dmarc_txt = dmarc_txt.unwrap_or_default();
    let mut dmarc_at = dmarc_name.clone();
    let has = |t: &[String]| {
        t.iter()
            .any(|x| x.trim().to_ascii_lowercase().starts_with("v=dmarc1"))
    };
    if !has(&dmarc_txt) && org != d {
        dmarc_at = format!("_dmarc.{org}");
        dmarc_txt = l.txt(&dmarc_at).await.unwrap_or_default();
    }
    let (dmarc, dmarc_checks) = policy::dmarc(&dmarc_txt, &dmarc_at, &org);
    checks.extend(dmarc_checks);
    if dmarc.found && dmarc_at != dmarc_name {
        checks.push(check(
            "DMARC",
            INFO,
            t!("Ereditato", "Inherited"),
            tf!(
                "{d} non ha un record suo: vale quello di {org}",
                "{d} has no record of its own: the one of {org} applies"
            ),
        ));
    }
    for ext in dmarc.external.iter().take(3) {
        let name = format!("{org}._report._dmarc.{ext}");
        if !has(&l.txt(&name).await.unwrap_or_default()) {
            checks.push(check(
                "DMARC",
                WARN,
                t!("Rapporti esterni", "External reports"),
                tf!(
                    "{ext} non ha autorizzato la ricezione dei rapporti (manca {name}): possono essere scartati",
                    "{ext} has not authorised the reception of reports ({name} is missing): they may be discarded"
                ),
            ));
        }
    }

    // DKIM
    let dkim: Vec<policy::DkimKey> = selectors
        .iter()
        .zip(dkim_txt)
        .filter(|(_, t)| t.contains("v=DKIM1") || t.contains("p="))
        .map(|(s, t)| policy::dkim_key(s, &t))
        .collect();
    checks.extend(policy::dkim_checks(&dkim, &asked));

    // MX
    let mut mx_sorted = mx_list;
    mx_sorted.sort();
    mx_sorted.truncate(MAX_MX);
    let mx_jobs = mx_sorted.iter().map(|(prio, host)| async move {
        let addrs = if host.is_empty() || host == "." {
            vec![]
        } else {
            l.addrs(host).await
        };
        let v4: Vec<Ipv4Addr> = addrs
            .iter()
            .filter_map(|a| match a {
                IpAddr::V4(x) => Some(*x),
                _ => None,
            })
            .collect();
        let ptr = match v4.first() {
            Some(ip) => l.ptr(*ip).await,
            None => String::new(),
        };
        MxHost {
            priority: *prio,
            host: host.clone(),
            ipv4: v4.iter().map(Ipv4Addr::to_string).collect(),
            ipv6: addrs
                .iter()
                .filter(|a| a.is_ipv6())
                .map(IpAddr::to_string)
                .collect(),
            ptr,
            status: OK,
            note: String::new(),
        }
    });
    let mut mx = dns::domain::futures_join(mx_jobs).await;
    checks.extend(mx_checks(&mut mx));

    // MTA-STS (the policy is only downloaded if the record exists) and TLS-RPT
    let sts_txt = sts_txt.unwrap_or_default();
    let sts_found = sts_txt
        .iter()
        .any(|t| t.trim().to_ascii_lowercase().starts_with("v=stsv1"));
    let fetched = if sts_found {
        Some(
            l.policy(&format!("https://mta-sts.{d}/.well-known/mta-sts.txt"))
                .await,
        )
    } else {
        None
    };
    let hosts: Vec<String> = mx
        .iter()
        .map(|h| h.host.clone())
        .filter(|h| !h.is_empty() && h != ".")
        .collect();
    let (mta_sts, sts_checks) = policy::mta_sts(&sts_txt, fetched.as_ref(), &hosts, &d);
    checks.extend(sts_checks);
    let (tls_rpt, rpt_check) = policy::tls_rpt(&rpt_txt.unwrap_or_default(), &d);
    checks.push(rpt_check);

    let bimi = bimi_txt
        .unwrap_or_default()
        .into_iter()
        .find(|t| t.to_ascii_lowercase().starts_with("v=bimi1"))
        .unwrap_or_default();
    checks.push(check(
        "BIMI",
        INFO,
        "Record",
        if bimi.is_empty() {
            t!("assente", "missing").to_string()
        } else {
            bimi.clone()
        },
    ));

    Ok(DomainReport {
        domain: d,
        checks,
        spf: spf_report,
        dmarc,
        dkim,
        selectors,
        mx,
        mta_sts,
        tls_rpt,
        bimi,
    })
}

/// Response of the `emailheader` command: `{"domain_report": …}` or `{"message": …}`.
pub async fn run(req: EmailReq) -> Result<Value> {
    let domain = req.domain.as_deref().map(str::trim).unwrap_or("");
    let raw = req.raw_header.as_deref().map(str::trim).unwrap_or("");
    if domain.is_empty() && raw.is_empty() {
        return Err(t!(
            "Dominio o raw header richiesto",
            "Domain or raw header required"
        )
        .into());
    }
    if raw.len() > 128 * 1024 {
        return Err(t!(
            "Header troppo lungo (max 128 KB)",
            "Header too long (max 128 KB)"
        )
        .into());
    }
    let mut out = serde_json::Map::new();
    if !domain.is_empty() {
        let report = analyze_domain(&System::new()?, &req).await?;
        out.insert(
            "domain_report".into(),
            serde_json::to_value(report).map_err(|e| e.to_string())?,
        );
    }
    if !raw.is_empty() {
        out.insert(
            "message".into(),
            serde_json::to_value(message::analyze(raw)).map_err(|e| e.to_string())?,
        );
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const SAMPLE: &str = "Received: from mail.example.com (mail.example.com [203.0.113.10])\r\n\tby mx.example.org with ESMTPS id 1;\r\n Fri, 30 Oct 2026 10:00:00 +0100\r\nReceived: from [10.0.0.5] by mail.example.com;\r\nAuthentication-Results: spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass\r\nFrom: Mario <mario@example.com>\r\nSubject: Prova\r\n  su due righe\r\n\r\nCorpo: non e' un header\r\n";

    #[test]
    fn header() {
        let h = parse_headers(SAMPLE);
        assert_eq!(h.len(), 5);
        assert_eq!(h[0].1, "from mail.example.com (mail.example.com [203.0.113.10]) by mx.example.org with ESMTPS id 1; Fri, 30 Oct 2026 10:00:00 +0100");
        assert_eq!(h[4], ("Subject".into(), "Prova su due righe".into()));
        let m = message::analyze(SAMPLE);
        assert_eq!(m.hops.len(), 2);
        assert_eq!(m.from, "mario@example.com");
        assert_eq!(m.subject, "Prova su due righe");
        assert!(!m.headers.iter().any(|(k, _)| k == "Corpo"));
    }

    #[test]
    fn ip_tra_parentesi() {
        assert_eq!(
            bracket_ips("a [1.2.3.4] b [IPv6:::1] c [5.6.7.8"),
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
    }

    #[test]
    fn solo_il_primo_authentication_results() {
        // on top the one from your own server (without authserv-id), below a fake one from the sender
        let raw = "Authentication-Results: spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=example.com; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=example.com;compauth=fail reason=000\r\n\
Received: from x by y;\r\n\
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass\r\n\
Subject: prova\r\n\r\n";
        let a = auth_results(&parse_headers(raw));
        assert_eq!(a["spf"], "fail");
        assert_eq!(a["dkim"], "none");
        assert_eq!(a["dmarc"], "fail");
        assert_eq!(a["server"], "");
        assert_eq!(a["count"], 2);
        let raw = "Authentication-Results: mx.google.com;\r\n       dkim=pass header.i=@example.com;\r\n       spf=softfail (google.com: ...) smtp.mailfrom=x@example.com\r\n\r\n";
        let a = auth_results(&parse_headers(raw));
        assert_eq!(a["server"], "mx.google.com");
        assert_eq!(a["spf"], "softfail");
        assert_eq!(a["dkim"], "pass");
        assert!(a["dmarc"].is_null());
        assert!(auth_results(&parse_headers("Subject: x\r\n\r\n")).is_null());
    }

    /// In-memory DNS: TXT, addresses, MX, PTR and policy; counts the requests.
    #[derive(Default)]
    struct Fake {
        txt: HashMap<String, Vec<String>>,
        addr: HashMap<String, Vec<IpAddr>>,
        mx: HashMap<String, Vec<(u16, String)>>,
        ptr: HashMap<Ipv4Addr, String>,
        policy: Option<std::result::Result<String, String>>,
        asked: Mutex<Vec<String>>,
    }

    impl Fake {
        fn t(mut self, name: &str, value: &str) -> Self {
            self.txt.entry(name.into()).or_default().push(value.into());
            self
        }
        fn a(mut self, name: &str, ips: &[&str]) -> Self {
            self.addr.insert(
                name.into(),
                ips.iter().map(|x| x.parse().unwrap()).collect(),
            );
            self
        }
        fn log(&self, what: String) {
            self.asked.lock().unwrap().push(what);
        }
        fn count(&self, prefix: &str) -> usize {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .filter(|x| x.starts_with(prefix))
                .count()
        }
    }

    impl Lookup for Fake {
        async fn txt(&self, name: &str) -> std::result::Result<Vec<String>, String> {
            self.log(format!("txt {name}"));
            Ok(self.txt.get(name).cloned().unwrap_or_default())
        }
        async fn addrs(&self, name: &str) -> Vec<IpAddr> {
            self.log(format!("addr {name}"));
            self.addr.get(name).cloned().unwrap_or_default()
        }
        async fn mx(&self, name: &str) -> Vec<(u16, String)> {
            self.log(format!("mx {name}"));
            self.mx.get(name).cloned().unwrap_or_default()
        }
        async fn ptr(&self, ip: Ipv4Addr) -> String {
            self.ptr.get(&ip).cloned().unwrap_or_default()
        }
        async fn policy(&self, url: &str) -> std::result::Result<String, String> {
            self.log(format!("policy {url}"));
            self.policy
                .clone()
                .unwrap_or_else(|| Err("non prevista".into()))
        }
    }

    fn req(domain: &str, selector: &str, ip: &str) -> EmailReq {
        EmailReq {
            domain: Some(domain.into()),
            raw_header: None,
            selector: selector.into(),
            ip: ip.into(),
        }
    }

    fn find<'a>(c: &'a [Check], area: &str, name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.area == area && x.name == name)
            .unwrap_or_else(|| panic!("manca {area}/{name}: {c:#?}"))
    }

    fn world() -> Fake {
        let mut f = Fake::default()
            .t(
                "example.com",
                "v=spf1 mx include:_spf.example.net ip4:203.0.113.0/28 -all",
            )
            .t("_spf.example.net", "v=spf1 ip4:198.51.100.0/24 ~all")
            .t(
                "_dmarc.example.com",
                "v=DMARC1; p=none; rua=mailto:dmarc@example.com,mailto:r@terzi.example.net",
            )
            .t(
                "selector1._domainkey.example.com",
                "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            )
            .t("_mta-sts.example.com", "v=STSv1; id=1")
            .t(
                "_smtp._tls.example.com",
                "v=TLSRPTv1; rua=mailto:tlsrpt@example.com",
            )
            .a("mail1.example.com", &["203.0.113.10", "2001:db8:25::10"])
            .a("mail2.example.com", &["203.0.113.11"]);
        f.mx.insert(
            "example.com".into(),
            vec![
                (20, "mail2.example.com".into()),
                (10, "mail1.example.com".into()),
            ],
        );
        f.ptr
            .insert("203.0.113.10".parse().unwrap(), "mail1.example.com".into());
        f.policy = Some(Ok(
            "version: STSv1\nmode: enforce\nmx: mail1.example.com\nmax_age: 604800\n".into(),
        ));
        f
    }

    #[tokio::test]
    async fn dominio_completo() {
        let f = world();
        let r = analyze_domain(&f, &req("Example.COM.", "", "203.0.113.11"))
            .await
            .unwrap();
        assert_eq!(r.domain, "example.com");
        // SPF: mx (1) + include (1), the MX decides for the requested address
        assert_eq!(
            (
                r.spf.lookups,
                r.spf.ip_result.as_str(),
                r.spf.ip_match.as_str()
            ),
            (2, "pass", "mx")
        );
        assert_eq!(find(&r.checks, "SPF", "Limite di lookup").status, OK);
        assert!(find(&r.checks, "SPF", "IP 203.0.113.11")
            .detail
            .starts_with("pass"));
        // DMARC: p=none, reports to an unauthorised external domain
        assert_eq!(r.dmarc.policy, "none");
        assert_eq!(find(&r.checks, "DMARC", "Policy").status, WARN);
        let ext = find(&r.checks, "DMARC", "Rapporti esterni");
        assert!(ext
            .detail
            .contains("example.com._report._dmarc.terzi.example.net"));
        // DKIM: of the twelve common selectors, one exists
        assert_eq!(r.selectors.len(), 12);
        let dkim_queries = f
            .asked
            .lock()
            .unwrap()
            .iter()
            .filter(|x| x.contains("._domainkey."))
            .count();
        assert_eq!(dkim_queries, 12);
        assert_eq!(r.dkim.len(), 1);
        assert_eq!(
            (r.dkim[0].selector.as_str(), r.dkim[0].key.as_str()),
            ("selector1", "Ed25519")
        );
        // MXs in priority order, with addresses and reverse name
        let mx: Vec<(u16, &str, usize, usize, &str)> =
            r.mx.iter()
                .map(|h| {
                    (
                        h.priority,
                        h.host.as_str(),
                        h.ipv4.len(),
                        h.ipv6.len(),
                        h.ptr.as_str(),
                    )
                })
                .collect();
        assert_eq!(
            mx,
            vec![
                (10, "mail1.example.com", 1, 1, "mail1.example.com"),
                (20, "mail2.example.com", 1, 0, "")
            ]
        );
        assert_eq!(find(&r.checks, "MX", "Server").status, OK);
        assert!(find(&r.checks, "MX", "Nome inverso")
            .detail
            .ends_with("mail2.example.com"));
        // MTA-STS: policy downloaded once, one MX not covered
        assert_eq!(
            f.count("policy https://mta-sts.example.com/.well-known/mta-sts.txt"),
            1
        );
        assert_eq!(r.mta_sts.mode, "enforce");
        let s = find(&r.checks, "MTA-STS", "Server");
        assert!(s.status == ERR && s.detail.contains("mail2.example.com"));
        assert!(r.tls_rpt.is_some());
        assert_eq!(find(&r.checks, "BIMI", "Record").detail, "assente");
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains(r#""mechanism":"mx""#) && !json.contains("uses_ptr"),
            "{json}"
        );
    }

    #[tokio::test]
    async fn dominio_vuoto_e_richieste_non_valide() {
        // nothing at all: no HTTPS request, requested selector not found
        let f = Fake::default();
        let r = analyze_domain(&f, &req("example.com", "Mio, altro", ""))
            .await
            .unwrap();
        assert_eq!(f.count("policy"), 0);
        assert_eq!(r.selectors, vec!["mio", "altro"]);
        assert_eq!(find(&r.checks, "SPF", "Record").status, ERR);
        assert_eq!(find(&r.checks, "DMARC", "Record").status, ERR);
        assert_eq!(find(&r.checks, "DKIM", "mio").status, ERR);
        assert_eq!(find(&r.checks, "MX", "Server").status, WARN);
        assert_eq!(find(&r.checks, "MTA-STS", "Record").status, INFO);
        assert!(r.spf.ip.is_empty() && r.mx.is_empty() && r.tls_rpt.is_none());

        // subdomain without DMARC: the organisational domain's one applies
        let f = Fake::default().t(
            "_dmarc.example.com",
            "v=DMARC1; p=reject; rua=mailto:d@example.com",
        );
        let r = analyze_domain(&f, &req("posta.example.com", "", ""))
            .await
            .unwrap();
        assert_eq!(r.dmarc.policy, "reject");
        assert!(find(&r.checks, "DMARC", "Ereditato")
            .detail
            .contains("vale quello di example.com"));

        // null MX, MX without addresses
        let mut f = Fake::default();
        f.mx.insert("example.com".into(), vec![(0, String::new())]);
        let r = analyze_domain(&f, &req("example.com", "", ""))
            .await
            .unwrap();
        assert!(find(&r.checks, "MX", "Server")
            .detail
            .starts_with("MX nullo"));
        let mut f = Fake::default();
        f.mx.insert("example.com".into(), vec![(10, "perso.example.com".into())]);
        let r = analyze_domain(&f, &req("example.com", "", ""))
            .await
            .unwrap();
        assert_eq!(find(&r.checks, "MX", "perso.example.com").status, ERR);
        assert_eq!(r.mx[0].status, ERR);

        let f = Fake::default();
        let e = |d: &'static str, s: &'static str, i: &'static str| {
            let f = &f;
            async move { analyze_domain(f, &req(d, s, i)).await.unwrap_err() }
        };
        assert!(e("example.com", "", "non-un-ip")
            .await
            .contains("IP da verificare non valido"));
        assert!(e("example.com", "a b c d e f", "")
            .await
            .contains("Massimo 5"));
        assert!(e("example.com", "sel/1", "")
            .await
            .contains("Selettore DKIM non valido"));
        assert!(e("192.0.2.1", "", "").await.contains("Indica un dominio"));
        assert!(e("srv01", "", "").await.contains("Indica un dominio"));
    }

    #[tokio::test]
    async fn raccolta_per_spf() {
        let mut f = Fake::default()
            .t("example.com", "v=spf1 mx a:out.example.org include:a.example.net include:a.example.net exists:%{i}.x.example redirect=r.example.net")
            .t("a.example.net", "v=spf1 include:b.example.net include:example.com ~all")
            .t("b.example.net", "v=spf1 ip4:192.0.2.0/24 ~all")
            .t("r.example.net", "v=spf1 -all")
            .a("out.example.org", &["192.0.2.200"])
            .a("mail1.example.com", &["203.0.113.10"]);
        f.mx.insert("example.com".into(), vec![(10, "mail1.example.com".into())]);
        let d = gather(&f, "Example.com").await;
        let mut names: Vec<&String> = d.txt.keys().collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "a.example.net",
                "b.example.net",
                "example.com",
                "r.example.net"
            ]
        );
        // each domain only once, even if included twice or in a loop
        assert_eq!(f.count("txt "), 4);
        assert_eq!(d.mx["example.com"], vec!["mail1.example.com"]);
        assert_eq!(d.addr["mail1.example.com"].len(), 1);
        assert_eq!(d.addr["out.example.org"].len(), 1);
        assert_eq!(f.count("addr "), 2);
        let r = spf::evaluate("example.com", &d, None);
        // mx, a, include:a twice (each with its two includes), exists, redirect
        assert_eq!(r.lookups, 10);
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let c = mx_checks(&mut []);
        assert!(c[0].detail.starts_with("no MX record"));
        assert_eq!(
            clean_selectors("a b c d e f").unwrap_err(),
            "At most 5 DKIM selectors"
        );
        assert_eq!(
            clean_selectors("sel/1").unwrap_err(),
            "Invalid DKIM selector: sel/1"
        );
    }
}
