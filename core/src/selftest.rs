//! Self-test of the scan engine on the PC it runs on: which echo is
//! used, whether the ARP table is readable, how long a TCP refusal takes.
//! Needed on Windows, where these parts cannot be tried elsewhere:
//!
//! ```text
//! cargo test -p ntb-core collaudo_motore -- --ignored --nocapture
//! $env:NTB_ICMP_SILENT = "172.16.1.250"   # optional: free IP on the PC's network
//! cargo test -p ntb-core collaudo_motore -- --ignored --nocapture
//! cargo test -p ntb-core collaudo_wifi -- --ignored --nocapture
//! $env:NTB_TLS_TEST = "srv01.corp.example:443"
//! cargo test -p ntb-core collaudo_tls -- --ignored --nocapture
//! ```

use crate::icmp::{self, ArpTable, Status};
use crate::tcp::{self, Conn};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

fn esito(s: Status) -> String {
    match s {
        Status::Reply => "risposta".into(),
        Status::Timeout => "nessuna risposta".into(),
        Status::TtlExpired => "TTL scaduto".into(),
        Status::Unreachable => "irraggiungibile".into(),
        Status::Error(c) => format!("errore {c}"),
    }
}

fn motore() -> &'static str {
    if icmp::scan_parallelism() > 256 {
        "motore asincrono (IcmpSendEcho2Ex)"
    } else {
        "echo bloccanti (motore asincrono non disponibile)"
    }
}

/// Runs the tests and returns one line per measurement. `silent` is an address
/// that does not answer (free on the PC's network: ARP stays unanswered and
/// nobody sends "unreachable"), to exercise the async engine's timeout;
/// `192.0.2.1` is not enough if the gateway refuses it immediately.
pub async fn run(silent: Option<Ipv4Addr>) -> Vec<String> {
    let mut out = Vec::new();
    let lo = Ipv4Addr::LOCALHOST;
    out.push(format!("Echo delle scansioni: {}", motore()));

    let a = icmp::echo(lo, 128, 1000).await;
    let b = icmp::echo_scan(lo, 128, 1000).await;
    out.push(format!(
        "127.0.0.1: echo di ping e traceroute {} in {:.3} ms, echo delle scansioni {} in {:.3} ms",
        esito(a.status),
        a.rtt_ms,
        esito(b.status),
        b.rtt_ms
    ));

    const BURST: usize = 128;
    let t0 = Instant::now();
    let mut set = JoinSet::new();
    for _ in 0..BURST {
        set.spawn(icmp::echo_scan(lo, 128, 1000));
    }
    let mut ok = 0;
    while let Some(r) = set.join_next().await {
        if matches!(r, Ok(e) if e.status == Status::Reply) {
            ok += 1;
        }
    }
    out.push(format!(
        "Raffica di {BURST} echo a 127.0.0.1: {ok} risposte in {} ms",
        t0.elapsed().as_millis()
    ));

    // 192.0.2.1 (TEST-NET-1) is not routed: the timeout must arrive, at 800 ms
    let t0 = Instant::now();
    let e = icmp::echo_scan(Ipv4Addr::new(192, 0, 2, 1), 128, 800).await;
    out.push(format!(
        "192.0.2.1 con timeout di 800 ms: {} dopo {} ms",
        esito(e.status),
        t0.elapsed().as_millis()
    ));

    match silent {
        Some(ip) => {
            let t0 = Instant::now();
            let e = icmp::echo_scan(ip, 128, 800).await;
            out.push(format!(
                "{ip} (muto) con timeout di 800 ms, echo delle scansioni: {} dopo {} ms; poi {}",
                esito(e.status),
                t0.elapsed().as_millis(),
                motore()
            ));
            let t0 = Instant::now();
            let e = icmp::echo(ip, 128, 800).await;
            out.push(format!(
                "{ip} (muto) con timeout di 800 ms, echo di ping e traceroute: {} dopo {} ms",
                esito(e.status),
                t0.elapsed().as_millis()
            ));
        }
        None => out.push(
            "IP muto: non indicato (NTB_ICMP_SILENT), timeout del motore asincrono non provato"
                .into(),
        ),
    }

    out.push(match icmp::neighbor_count() {
        Some(n) => format!("Tabella ARP del sistema: leggibile, {n} host"),
        None => "Tabella ARP del sistema: non leggibile (le scansioni usano SendARP)".into(),
    });
    match crate::netpath::default_route().and_then(|r| r.gateway) {
        Some(gw) => {
            let e = icmp::echo_scan(gw, 128, 1000).await;
            let mac = ArpTable::new()
                .mac(gw, e.status == Status::Reply)
                .await
                .unwrap_or_else(|| "non trovato".into());
            out.push(format!(
                "Gateway {gw}: {} in {:.2} ms, MAC {mac}",
                esito(e.status),
                e.rtt_ms
            ));
        }
        None => out.push("Gateway: nessuna route predefinita".into()),
    }

    out.push(format!(
        "Rifiuto TCP immediato (socket senza ritrasmissione del SYN): {}",
        if tcp::quick_available() {
            "disponibile"
        } else {
            "non disponibile"
        }
    ));
    let closed = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l.local_addr().ok(),
        Err(_) => None,
    }; // listener closed: the port refuses
    if let Some(addr) = closed {
        let t0 = Instant::now();
        let probe = match tcp::connect(addr, Duration::from_secs(5)).await {
            Conn::Open(_) => "aperta",
            Conn::Refused => "rifiutata",
            Conn::Failed(_) => "nessuna risposta",
        };
        let probe_ms = t0.elapsed().as_millis();
        let t0 = Instant::now();
        let _ = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
            .await;
        out.push(format!(
            "Porta chiusa su 127.0.0.1: {probe} in {probe_ms} ms con la sonda dell'app, {} ms con una connessione normale",
            t0.elapsed().as_millis()
        ));
    }

    out.push(format!("Echo delle scansioni dopo le prove: {}", motore()));
    out
}

#[cfg(test)]
mod tests {
    /// Verifies nothing: prints the measurements of the PC it runs on. With
    /// `NTB_ICMP_SILENT=<ip>` it also tests the timeout towards a silent address.
    #[tokio::test]
    #[ignore = "collaudo manuale: stampa le misure di questo PC"]
    async fn collaudo_motore() {
        let silent = match std::env::var("NTB_ICMP_SILENT") {
            Ok(s) => match s.trim().parse() {
                Ok(ip) => Some(ip),
                Err(_) => panic!("NTB_ICMP_SILENT: indirizzo IPv4 non valido: {s}"),
            },
            Err(_) => None,
        };
        for l in super::run(silent).await {
            println!("{l}");
        }
    }

    /// Wi-Fi: adapters, scan, networks, connection and monitor (to run on a
    /// PC with a Wi-Fi adapter).
    #[test]
    #[ignore = "collaudo manuale: stampa cosa restituisce il Wi-Fi di Windows"]
    fn collaudo_wifi() {
        for l in crate::wifi::diagnose() {
            println!("{l}");
        }
    }

    /// Neighbours: passive read of the PC's ARP/NDP table, with the path used
    /// (single table or IPv4 fallback). With `NTB_NEIGH_PROBE=1` it also sends the echo to
    /// `ff02::1` (one packet on the local network): only on request.
    #[tokio::test]
    #[ignore = "collaudo manuale: legge la tabella dei vicini del PC"]
    async fn collaudo_vicini() {
        use crate::neigh;
        let probe = std::env::var("NTB_NEIGH_PROBE").is_ok_and(|v| v == "1");
        let r = neigh::run(neigh::NeighReq { probe }, None, None).await;
        match r {
            Err(e) => println!("Vicini: errore: {e}"),
            Ok(r) => {
                println!(
                    "Vicini: percorso {}, {} dispositivi, {} IPv4, {} IPv6, {} non risolti, gateway {}",
                    r.source,
                    r.n_devices,
                    r.n_v4,
                    r.n_v6,
                    r.unresolved,
                    r.gateway.as_deref().unwrap_or("nessuno")
                );
                for x in &r.routers {
                    println!(
                        "  router IPv6 {} mac {} validita {:?} s",
                        x.addr, x.mac, x.lifetime_s
                    );
                }
                for x in &r.prefixes {
                    println!(
                        "  prefisso {} su {} on-link {}",
                        x.prefix, x.iface, x.on_link
                    );
                }
                for c in &r.checks {
                    println!("  [{}] {}: {}", c.status, c.name, c.detail);
                }
                match &r.probe {
                    Some(p) => println!(
                        "  echo ff02::1: {} schede, risposte {:?}, voci nuove {} ({})",
                        p.ifaces, p.replies, p.new_entries, p.note
                    ),
                    None => println!("  echo ff02::1: non richiesto"),
                }
            }
        }
    }

    /// TLS certificates: the three attempts (TLS 1.3+1.2, 1.2 only, compatibility
    /// probe) one by one on the server given in `NTB_TLS_TEST`.
    #[tokio::test]
    #[ignore = "collaudo manuale: NTB_TLS_TEST=host:porta"]
    async fn collaudo_tls() {
        let Ok(target) = std::env::var("NTB_TLS_TEST") else {
            println!("Impostare NTB_TLS_TEST=host:porta");
            return;
        };
        for l in crate::tls::diagnose(&target).await {
            println!("{l}");
        }
    }

    /// Analysis of a real domain (`NTB_DNS_TEST=domain`): says which sources
    /// answered (parent zone, name servers, validating resolver) and prints the checks.
    #[tokio::test]
    #[ignore = "collaudo manuale: NTB_DNS_TEST=dominio"]
    async fn collaudo_dns() {
        let Ok(domain) = std::env::var("NTB_DNS_TEST") else {
            println!("Impostare NTB_DNS_TEST=dominio");
            return;
        };
        let req = crate::dns::domain::DomainReq {
            domain,
            axfr: false,
        };
        match crate::dns::domain::run(req).await {
            Err(e) => println!("Errore: {e}"),
            Ok(r) => {
                println!("Zona: {} ({} ms) {}", r.domain, r.time_ms, r.zone_note);
                println!(
                    "Zona padre {}: {}",
                    r.parent,
                    if r.parent_ok {
                        "raggiunta con query dirette"
                    } else {
                        "non raggiunta, delega letta dal DNS del PC"
                    }
                );
                for n in &r.nameservers {
                    println!(
                        "  {} {:?} risponde={} autoritativo={} seriale={:?} {:?} ms [{}] {}",
                        n.name,
                        n.ipv4,
                        n.responds,
                        n.authoritative,
                        n.serial,
                        n.time_ms,
                        n.status,
                        n.note
                    );
                }
                println!("DNSSEC: {}", r.dnssec.label);
                for x in r.dnssec.rows.iter().chain(r.dnssec.validation.iter()) {
                    println!("  [{}] {}: {} {}", x.status, x.name, x.what, x.detail);
                }
                println!(
                    "Record: {}, senza risposta: {:?}",
                    r.records.len(),
                    r.empty_types
                );
                for c in &r.checks {
                    println!("  [{}] {} / {}: {}", c.status, c.area, c.name, c.detail);
                }
            }
        }
    }
}
