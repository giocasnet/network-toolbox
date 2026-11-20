//! Path MTU discovery: echo requests with "Do not fragment" and a growing payload,
//! looking for the largest packet that reaches the host.
//!
//! The search (`search`) is a pure function over a `probe` closure, tested with a
//! fake path; `run` plugs in the real echo.

use crate::icmp::{self, EchoOpts, Status};
use crate::ping::Stop;
use crate::{t, tf, Event, Result};
use std::future::Future;
use std::net::Ipv4Addr;

/// IPv4 header (20) + ICMP header (8): bytes added to the payload.
pub const HEADERS: usize = 28;
/// Payload of the first probe: small enough to pass everywhere (like a normal ping).
const BASE: usize = 32;
/// Payload that fills an Ethernet frame (MTU 1500).
const ETHERNET: usize = 1500 - HEADERS;
/// Upper limit of the search: a 9000-byte jumbo frame.
const JUMBO: usize = 9000 - HEADERS;

/// Outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The echo came back.
    Pass,
    /// Too large for the path (local MTU or "fragmentation needed").
    TooBig,
    /// No answer: too large for a router that drops silently, or a lost packet.
    Silent,
    /// Anything else (unreachable, system error): the search cannot continue.
    Error(String),
}

/// What the search found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Largest payload that passed.
    pub payload: usize,
    /// `true` if the limit of the search was reached without a failure.
    pub at_limit: bool,
    /// Steps that ended with no answer at all (the limit may be a router that drops).
    pub silent: u32,
}

impl Found {
    pub fn mtu(&self) -> usize {
        self.payload + HEADERS
    }
}

/// How the search ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Search {
    Done(Found),
    Stopped,
}

/// Binary search of the largest payload that passes. `probe(size)` returns `None` when
/// the user stopped; `step(size, outcome)` is called after every probe.
///
/// A step with no answer is repeated once before counting as a failure, so a lost
/// packet does not lower the result.
pub async fn search<P, Fut, S>(mut probe: P, mut step: S) -> Result<Search>
where
    P: FnMut(usize) -> Fut,
    Fut: Future<Output = Option<Outcome>>,
    S: FnMut(usize, &Outcome),
{
    let mut silent = 0;
    // One probe, with a single retry after silence. Err = stopped or aborted.
    macro_rules! ask {
        ($size:expr) => {{
            let size: usize = $size;
            let mut out = match probe(size).await {
                Some(o) => o,
                None => return Ok(Search::Stopped),
            };
            if out == Outcome::Silent {
                step(size, &out);
                out = match probe(size).await {
                    Some(o) => o,
                    None => return Ok(Search::Stopped),
                };
            }
            step(size, &out);
            if let Outcome::Error(e) = &out {
                return Err(e.clone());
            }
            if out == Outcome::Silent {
                silent += 1;
            }
            out == Outcome::Pass
        }};
    }

    if !ask!(BASE) {
        return Err(t!(
            "L'host non risponde nemmeno a un pacchetto piccolo con \"Non frammentare\": ICMP bloccato o host spento.",
            "The host does not answer even a small packet with \"Do not fragment\": ICMP is blocked or the host is down."
        )
        .into());
    }
    let (mut lo, mut hi);
    if ask!(ETHERNET) {
        // Ethernet passes: one more byte tells whether this is the usual 1500.
        if !ask!(ETHERNET + 1) {
            return Ok(Search::Done(Found {
                payload: ETHERNET,
                at_limit: false,
                silent,
            }));
        }
        if ask!(JUMBO) {
            return Ok(Search::Done(Found {
                payload: JUMBO,
                at_limit: true,
                silent,
            }));
        }
        lo = ETHERNET + 1;
        hi = JUMBO;
    } else {
        lo = BASE;
        hi = ETHERNET;
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if ask!(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(Search::Done(Found {
        payload: lo,
        at_limit: false,
        silent,
    }))
}

fn outcome_of(status: Status) -> Outcome {
    match status {
        Status::Reply => Outcome::Pass,
        Status::TooBig => Outcome::TooBig,
        Status::Timeout => Outcome::Silent,
        Status::Unreachable => Outcome::Error(
            t!(
                "Destinazione irraggiungibile durante la ricerca dell'MTU.",
                "Destination unreachable during the MTU search."
            )
            .into(),
        ),
        Status::TtlExpired => Outcome::Error(
            t!(
                "TTL scaduto durante la ricerca dell'MTU.",
                "TTL expired during the MTU search."
            )
            .into(),
        ),
        Status::Error(code) => Outcome::Error(tf!(
            "Errore di sistema {code} durante la ricerca dell'MTU.",
            "System error {code} during the MTU search."
        )),
    }
}

/// Text of a step, one line per probe.
fn step_line(size: usize, out: &Outcome) -> String {
    let total = size + HEADERS;
    match out {
        Outcome::Pass => tf!(
            "Pacchetto da {total} byte (dati {size}): risposta",
            "Packet of {total} bytes (data {size}): reply"
        ),
        Outcome::TooBig => tf!(
            "Pacchetto da {total} byte (dati {size}): troppo grande",
            "Packet of {total} bytes (data {size}): too large"
        ),
        Outcome::Silent => tf!(
            "Pacchetto da {total} byte (dati {size}): nessuna risposta",
            "Packet of {total} bytes (data {size}): no reply"
        ),
        Outcome::Error(_) => tf!(
            "Pacchetto da {total} byte (dati {size}): errore",
            "Packet of {total} bytes (data {size}): error"
        ),
    }
}

/// Final lines. The first one starts with `mtu=`: the UI reads the value from it.
pub(crate) fn result_lines(f: &Found) -> Vec<String> {
    let mtu = f.mtu();
    let payload = f.payload;
    let mut out = vec![
        String::new(),
        tf!(
            "mtu={mtu} (dati {payload} + {HEADERS} byte di intestazioni)",
            "mtu={mtu} (data {payload} + {HEADERS} bytes of headers)"
        ),
    ];
    if f.at_limit {
        out.push(
            t!(
                "Il percorso passa anche pacchetti da 9000 byte: la ricerca si ferma qui.",
                "The path also carries 9000-byte packets: the search stops here."
            )
            .into(),
        );
    }
    if f.silent > 0 {
        out.push(
            t!(
                "(!) Alcuni passi sono rimasti senza risposta: se un router scarta i pacchetti grandi senza avvisare, l'MTU reale può essere più bassa.",
                "(!) Some steps got no reply at all: if a router silently drops large packets, the real MTU may be lower."
            )
            .into(),
        );
    }
    out
}

/// Path MTU discovery towards `ip`. Returns `true` if stopped.
pub async fn run<F: FnMut(Event) + Send>(
    host: &str,
    ip: Ipv4Addr,
    timeout_ms: u32,
    stop: &Stop,
    emit: &mut F,
) -> Result<bool> {
    emit(Event::Line(tf!(
        "Ricerca dell'MTU verso {host} ({ip}) con \"Non frammentare\".",
        "Path MTU discovery to {host} ({ip}) with \"Do not fragment\"."
    )));
    let probe = |size: usize| async move {
        let opts = EchoOpts {
            ttl: 128,
            size,
            dont_fragment: true,
        };
        stop.race(icmp::echo_with(ip, opts, timeout_ms))
            .await
            .map(|e| outcome_of(e.status))
    };
    let res = search(probe, |size, out| {
        emit(Event::Line(step_line(size, out)));
    })
    .await;
    match res? {
        Search::Stopped => {
            emit(Event::Line(
                t!("Ricerca dell'MTU interrotta.", "MTU search stopped.").into(),
            ));
            Ok(true)
        }
        Search::Done(f) => {
            for l in result_lines(&f) {
                emit(Event::Line(l));
            }
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Fake path: payloads above `limit` are refused in the given way.
    async fn finto(
        limit: usize,
        refuse: Outcome,
        base_ok: bool,
    ) -> (Result<Search>, Vec<(usize, Outcome)>) {
        let log = RefCell::new(Vec::new());
        let res = search(
            |size| {
                let out = if size <= limit && (base_ok || size > BASE) {
                    Outcome::Pass
                } else {
                    refuse.clone()
                };
                async move { Some(out) }
            },
            |s, o| log.borrow_mut().push((s, o.clone())),
        )
        .await;
        (res, log.into_inner())
    }

    fn found(r: Result<Search>) -> Found {
        match r.unwrap() {
            Search::Done(f) => f,
            Search::Stopped => panic!("fermato"),
        }
    }

    #[tokio::test]
    async fn ethernet_classica() {
        let (r, log) = finto(1472, Outcome::TooBig, true).await;
        let f = found(r);
        assert_eq!(f.mtu(), 1500);
        assert!(!f.at_limit && f.silent == 0);
        // base, 1472, 1473: three probes
        assert_eq!(log.len(), 3, "{log:?}");
    }

    #[tokio::test]
    async fn mtu_ridotta_da_tunnel() {
        for mtu in [576usize, 1280, 1400, 1492, 1428] {
            let (r, _) = finto(mtu - HEADERS, Outcome::TooBig, true).await;
            assert_eq!(found(r).mtu(), mtu, "mtu {mtu}");
        }
    }

    #[tokio::test]
    async fn jumbo_frame() {
        let (r, _) = finto(8000 - HEADERS, Outcome::TooBig, true).await;
        assert_eq!(found(r).mtu(), 8000);
        let (r, _) = finto(65000, Outcome::TooBig, true).await;
        let f = found(r);
        assert!(f.at_limit);
        assert_eq!(f.mtu(), 9000);
    }

    #[tokio::test]
    async fn router_che_scarta_in_silenzio() {
        let (r, log) = finto(1400 - HEADERS, Outcome::Silent, true).await;
        let f = found(r);
        assert_eq!(f.mtu(), 1400);
        assert!(f.silent > 0);
        // a silent step is asked twice
        assert!(
            log.iter().filter(|(s, _)| *s == 1472).count() == 2,
            "{log:?}"
        );
    }

    #[tokio::test]
    async fn un_pacchetto_perso_non_abbassa_il_risultato() {
        let sent = RefCell::new(0);
        let r = search(
            |size| {
                *sent.borrow_mut() += 1;
                // the very first probe of 1472 is lost, the retry passes
                let lost = size == ETHERNET && *sent.borrow() == 2;
                async move {
                    Some(if lost {
                        Outcome::Silent
                    } else if size <= 1472 {
                        Outcome::Pass
                    } else {
                        Outcome::TooBig
                    })
                }
            },
            |_, _| {},
        )
        .await;
        assert_eq!(found(r).mtu(), 1500);
    }

    #[tokio::test]
    async fn host_che_non_risponde() {
        let (r, _) = finto(0, Outcome::Silent, false).await;
        assert!(r.unwrap_err().starts_with("L'host non risponde"));
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let (r, _) = finto(0, Outcome::TooBig, false).await;
        let e = r.unwrap_err();
        assert!(e.starts_with("The host does not answer"), "{e}");
    }

    #[tokio::test]
    async fn errore_e_stop() {
        let (r, _) = finto(1000, Outcome::Error("boom".into()), true).await;
        assert_eq!(r.unwrap_err(), "boom");
        let r = search(|_| async { None }, |_, _| {}).await.unwrap();
        assert_eq!(r, Search::Stopped);
    }

    #[test]
    fn messaggi_nelle_due_lingue() {
        let f = Found {
            payload: 1472,
            at_limit: false,
            silent: 1,
        };
        let it = result_lines(&f);
        assert_eq!(it[1], "mtu=1500 (dati 1472 + 28 byte di intestazioni)");
        assert!(it[2].starts_with("(!) Alcuni passi"));
        assert_eq!(
            step_line(1472, &Outcome::TooBig),
            "Pacchetto da 1500 byte (dati 1472): troppo grande"
        );
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let en = result_lines(&f);
        assert_eq!(en[1], "mtu=1500 (data 1472 + 28 bytes of headers)");
        assert!(!en
            .iter()
            .any(|l| l.contains("byte di") || l.contains("Alcuni")));
        assert_eq!(
            step_line(1472, &Outcome::Pass),
            "Packet of 1500 bytes (data 1472): reply"
        );
    }

    #[test]
    fn stati_dell_eco() {
        assert_eq!(outcome_of(Status::Reply), Outcome::Pass);
        assert_eq!(outcome_of(Status::TooBig), Outcome::TooBig);
        assert_eq!(outcome_of(Status::Timeout), Outcome::Silent);
        assert!(matches!(outcome_of(Status::Error(5)), Outcome::Error(_)));
        assert!(matches!(outcome_of(Status::Unreachable), Outcome::Error(_)));
    }
}
