//! DNSBL check: the reversed IP is queried in every list through this PC's
//! DNS. Reply 127.0.0.x = listed; NXDOMAIN = clean;
//! 127.255.255.x = query refused (e.g. Spamhaus from public DNS).

use crate::{dns, net, tf, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

pub const LISTS: [(&str, &str); 9] = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Mailspike", "bl.mailspike.net"),
    ("PSBL", "psbl.surriel.com"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("DroneBL", "dnsbl.dronebl.org"),
    ("s5h", "all.s5h.net"),
    ("GBUdb", "truncate.gbudb.net"),
];

#[derive(Debug, Deserialize)]
pub struct BlacklistReq {
    pub host: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListResult {
    pub list: String,
    pub zone: String,
    /// listed | clean | error
    pub state: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct BlacklistResponse {
    pub host: String,
    pub ip: String,
    pub ptr: String,
    pub resolver: String,
    pub results: Vec<ListResult>,
}

pub fn reversed(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

/// Classifies the return codes of a DNSBL.
pub fn classify(status: &str, codes: &[Ipv4Addr]) -> (&'static str, String) {
    if codes.is_empty() {
        return if status == "NXDOMAIN" || status == "NOERROR" {
            ("clean", String::new())
        } else {
            (
                "error",
                tf!(
                    "Nessuna risposta valida dalla lista ({status})",
                    "No valid response from the list ({status})"
                ),
            )
        };
    }
    let list = codes
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if codes.iter().any(|c| c.octets()[..3] == [127, 255, 255]) {
        return (
            "error",
            tf!(
                "Query rifiutata ({list}): la lista non accetta richieste dal DNS in uso",
                "Query refused ({list}): the list does not accept requests from the DNS in use"
            ),
        );
    }
    // DNSBLs reply with 127.0.0.0/8 codes: anything else (e.g. the IP of a courtesy
    // page from a DNS that resolves any name) does not mean "listed"
    if codes.iter().any(|c| c.octets()[0] != 127) {
        return (
            "error",
            tf!(
                "Risposta inattesa ({list}): non è un codice della lista (127.x.x.x); il DNS in uso risolve anche i nomi inesistenti?",
                "Unexpected response ({list}): not a list code (127.x.x.x); does the DNS in use also resolve non-existent names?"
            ),
        );
    }
    ("listed", list)
}

async fn check(rev: String, label: &str, zone: &str, servers: Vec<SocketAddr>) -> ListResult {
    let q = format!("{rev}.{zone}");
    let (state, mut detail) = match dns::lookup_a(&q, &servers).await {
        Ok((status, codes)) => classify(&status, &codes),
        Err(e) => ("error", tf!("Nessuna risposta: {e}", "No response: {e}")),
    };
    if state == "listed" {
        let txt = dns::lookup_txt(&q, &servers).await.join(" ");
        if !txt.is_empty() {
            detail = format!("{detail} — {txt}");
        }
    }
    ListResult {
        list: label.into(),
        zone: zone.into(),
        state: state.into(),
        detail,
    }
}

pub async fn run(req: BlacklistReq) -> Result<BlacklistResponse> {
    let host = net::clean_host(&req.host)?;
    let ip = net::resolve_v4(&host).await?;
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.octets()[0] >= 224
    {
        return Err(tf!(
            "{ip} non è un IP pubblico: le blacklist valgono solo per indirizzi pubblici",
            "{ip} is not a public IP: blacklists only apply to public addresses"
        ));
    }
    let sys = dns::system_dns()?;
    let rev = reversed(ip);
    // the PTR is looked up together with the lists, not afterwards
    let ptr = tokio::spawn(net::rdns(IpAddr::V4(ip), Duration::from_secs(2)));
    let jobs: Vec<_> = LISTS
        .iter()
        .map(|(label, zone)| tokio::spawn(check(rev.clone(), label, zone, sys.servers.clone())))
        .collect();
    let mut results = Vec::new();
    for j in jobs {
        results.push(j.await.map_err(|e| e.to_string())?);
    }
    Ok(BlacklistResponse {
        host,
        ip: ip.to_string(),
        ptr: ptr.await.unwrap_or_default(),
        resolver: sys.servers[0].ip().to_string(),
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classificazione() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(classify("NXDOMAIN", &[]).0, "clean");
        assert_eq!(classify("SERVFAIL", &[]).0, "error");
        assert_eq!(classify("NOERROR", &[ip("127.0.0.2")]).0, "listed");
        let (s, d) = classify("NOERROR", &[ip("127.255.255.254")]);
        assert_eq!(s, "error");
        assert!(d.contains("rifiutata"));
        // code outside 127/8: not a listing
        let (s, d) = classify("NOERROR", &[ip("198.51.100.7")]);
        assert_eq!(s, "error");
        assert!(d.contains("inattesa"), "{d}");
        assert_eq!(
            classify("NOERROR", &[ip("127.0.0.2"), ip("127.0.0.4")]).0,
            "listed"
        );
        assert_eq!(reversed(ip("185.10.20.30")), "30.20.10.185");
    }

    #[test]
    fn classificazione_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let (_, d) = classify("SERVFAIL", &[]);
        assert!(
            d.contains("No valid response") && !d.contains("Nessuna"),
            "{d}"
        );
        let (_, d) = classify("NOERROR", &[ip("127.255.255.254")]);
        assert!(d.contains("refused") && !d.contains("rifiutata"), "{d}");
        let (_, d) = classify("NOERROR", &[ip("198.51.100.7")]);
        assert!(d.contains("Unexpected") && !d.contains("inattesa"), "{d}");
    }
}
