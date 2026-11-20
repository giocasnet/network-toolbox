//! Ping. The output imitates the iputils-ping (Linux) format, so the UI
//! extracts packets, loss and RTT with the same code as the server version.

use crate::icmp::{self, Status, PAYLOAD};
use crate::net::{self, HostMeta, MetaLookup};
use crate::{t, tf, util, Event, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Debug, Default, Deserialize)]
pub struct PingReq {
    pub host: String,
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub count: Option<u32>,
    #[serde(default)]
    pub resolve: Option<bool>,
    /// Ping: milliseconds between one packet and the next.
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub interval_ms: Option<u32>,
    /// Maximum wait for the reply (ping: per packet; traceroute: per hop).
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub timeout_ms: Option<u32>,
    /// Traceroute: maximum number of hops.
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub max_hops: Option<u32>,
    /// Ping: data bytes in every packet (default 32).
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub size: Option<u32>,
    /// Ping: set the "Do not fragment" bit.
    #[serde(default)]
    pub dont_fragment: Option<bool>,
    /// Ping: instead of the normal test, look for the path MTU (always with "Do not fragment").
    #[serde(default)]
    pub mtu: Option<bool>,
}

/// Switch of a running ping or traceroute ("Stop" button).
/// Freely cloneable; `stop()` immediately wakes whoever is waiting for a reply
/// or for the interval between two packets.
#[derive(Clone)]
pub struct Stop(Arc<watch::Sender<bool>>);

impl Default for Stop {
    fn default() -> Self {
        Stop(Arc::new(watch::channel(false).0))
    }
}

impl Stop {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        self.0.send_replace(true);
    }

    pub fn is_stopped(&self) -> bool {
        *self.0.borrow()
    }

    /// Waits for `fut`; `None` if the stop arrives meanwhile (or had already arrived).
    pub async fn race<T>(&self, fut: impl Future<Output = T>) -> Option<T> {
        let mut rx = self.0.subscribe();
        tokio::select! {
            biased;
            _ = rx.wait_for(|stopped| *stopped) => None,
            v = fut => Some(v),
        }
    }
}

pub const TIMEOUT_MS: u32 = 2000;
pub const COUNT: u32 = 4;
pub const MAX_COUNT: u32 = 100;
pub const INTERVAL_MS: u32 = 1000;
pub const MIN_INTERVAL_MS: u32 = 100;
pub const MAX_INTERVAL_MS: u32 = 2000;
pub const MIN_TIMEOUT_MS: u32 = 100;
pub const MAX_TIMEOUT_MS: u32 = 5000;
pub const MAX_SIZE: u32 = icmp::MAX_PAYLOAD as u32;

/// Requested (or default) timeout, within the allowed limits.
pub(crate) fn timeout(req: &PingReq) -> Result<u32> {
    let t = req.timeout_ms.unwrap_or(TIMEOUT_MS);
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&t) {
        return Err(tf!(
            "Timeout: da {MIN_TIMEOUT_MS} a {MAX_TIMEOUT_MS} ms",
            "Timeout: {MIN_TIMEOUT_MS} to {MAX_TIMEOUT_MS} ms"
        ));
    }
    Ok(t)
}

/// Requested (or default) payload size, within the allowed limits.
pub(crate) fn size(req: &PingReq) -> Result<usize> {
    let n = req.size.unwrap_or(PAYLOAD as u32);
    if n > MAX_SIZE {
        return Err(tf!(
            "Dimensione: da 0 a {MAX_SIZE} byte",
            "Size: 0 to {MAX_SIZE} bytes"
        ));
    }
    Ok(n as usize)
}

/// Runs the ping. Returns `true` if it was stopped with `stop` before the
/// end: in that case the statistics cover the packets with an outcome.
pub async fn run<F: FnMut(Event) + Send>(req: PingReq, stop: &Stop, mut emit: F) -> Result<bool> {
    let host = net::clean_host(&req.host)?;
    let count = req.count.unwrap_or(COUNT);
    if !(1..=MAX_COUNT).contains(&count) {
        return Err(tf!(
            "Pacchetti: da 1 a {MAX_COUNT}",
            "Packets: 1 to {MAX_COUNT}"
        ));
    }
    let interval = req.interval_ms.unwrap_or(INTERVAL_MS);
    if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval) {
        return Err(tf!(
            "Intervallo: da {MIN_INTERVAL_MS} a {MAX_INTERVAL_MS} ms",
            "Interval: {MIN_INTERVAL_MS} to {MAX_INTERVAL_MS} ms"
        ));
    }
    let timeout_ms = timeout(&req)?;
    let size = size(&req)?;
    let dont_fragment = req.dont_fragment.unwrap_or(false);
    let resolve = req.resolve.unwrap_or(true);
    let Some(ip) = stop.race(net::resolve_v4(&host)).await else {
        emit(Event::Line(stopped_early().into()));
        return Ok(true);
    };
    let ip = ip?;
    if req.mtu == Some(true) {
        return crate::mtu::run(&host, ip, timeout_ms, stop, &mut emit).await;
    }
    // The target name is looked up while the first packet goes out: the test does not wait for it.
    let mut meta = MetaLookup::start(&host, ip);

    let mut names: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut rtts = Vec::new();
    emit(Event::Line(format!(
        "PING {host} ({ip}) {size} bytes of data."
    )));

    // Packets with an outcome (reply, error or timeout): the one pending
    // at the time of the stop does not count.
    let mut sent = 0;
    let mut stopped = false;
    for seq in 1..=count {
        let started = Instant::now();
        let Some(e) = stop
            .race(icmp::echo_with(
                ip,
                icmp::EchoOpts {
                    ttl: 128,
                    size,
                    dont_fragment,
                },
                timeout_ms,
            ))
            .await
        else {
            stopped = true;
            break;
        };
        sent = seq;
        // stopped during the name lookup: the line comes out with the IP only
        let who = match e.from {
            Some(addr) if resolve && addr == ip => match stop.race(meta.reverse_name()).await {
                Some(n) if !n.is_empty() => format!("{n} ({addr})"),
                _ => addr.to_string(),
            },
            Some(addr) => stop
                .race(label(addr, resolve, &mut names))
                .await
                .unwrap_or_else(|| addr.to_string()),
            None => ip.to_string(),
        };
        if let Some(m) = meta.ready().await {
            emit(Event::Meta(m));
        }
        let line = match e.status {
            Status::Reply => {
                rtts.push(e.rtt_ms);
                format!(
                    "{} bytes from {who}: icmp_seq={seq} ttl={} time={} ms",
                    size + 8,
                    e.ttl.map(|t| t.to_string()).unwrap_or_else(|| "?".into()),
                    fmt_rtt(e.rtt_ms)
                )
            }
            Status::Timeout => format!("Request timed out: icmp_seq={seq}"),
            Status::TtlExpired => format!("From {who} icmp_seq={seq} Time to live exceeded"),
            Status::Unreachable => format!("From {who} icmp_seq={seq} Destination unreachable"),
            Status::TooBig => format!("From {who} icmp_seq={seq} Frag needed and DF set"),
            Status::Error(code) => {
                tf!(
                    "Errore di sistema {code}: icmp_seq={seq}",
                    "System error {code}: icmp_seq={seq}"
                )
            }
        };
        emit(Event::Line(line));
        if seq < count {
            let wait = Duration::from_millis(interval as u64).saturating_sub(started.elapsed());
            if stop.race(tokio::time::sleep(wait)).await.is_none() {
                stopped = true;
                break;
            }
        }
    }

    if stopped {
        emit(Event::Line(match sent {
            0 => stopped_early().into(),
            1 => tf!(
                "Fermato dopo 1 pacchetto su {count}.",
                "Stopped after 1 packet out of {count}."
            ),
            n => tf!(
                "Fermato dopo {n} pacchetti su {count}.",
                "Stopped after {n} packets out of {count}."
            ),
        }));
    }
    if sent > 0 {
        for l in summary(&host, sent, &rtts) {
            emit(Event::Line(l));
        }
    }
    // The name reaches the UI as soon as it is available; when the test has finished it is awaited
    // (at most the 2 s of the lookup), when the test was stopped it is not.
    let m = if stopped {
        meta.ready().await
    } else {
        stop.race(meta.finish()).await.flatten()
    };
    if let Some(m) = m {
        emit(Event::Meta(m));
    }
    Ok(stopped)
}

/// Line shown when the test is stopped before a packet has an outcome.
pub(crate) fn stopped_early() -> &'static str {
    t!(
        "Fermato prima della risposta al primo pacchetto.",
        "Stopped before the reply to the first packet."
    )
}

/// "name (ip)" if resolution is on and there is a PTR, otherwise the IP.
pub(crate) async fn label(
    addr: Ipv4Addr,
    resolve: bool,
    cache: &mut HashMap<Ipv4Addr, String>,
) -> String {
    if !resolve {
        return addr.to_string();
    }
    if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(addr) {
        slot.insert(net::name_of(addr, Duration::from_millis(1500)).await);
    }
    match cache.get(&addr) {
        Some(n) if !n.is_empty() => format!("{n} ({addr})"),
        _ => addr.to_string(),
    }
}

pub(crate) fn fmt_rtt(ms: f64) -> String {
    if ms >= 100.0 {
        format!("{ms:.0}")
    } else if ms >= 10.0 {
        format!("{ms:.1}")
    } else {
        format!("{ms:.3}")
    }
}

/// Final lines with the statistics, in the format the UI expects.
pub(crate) fn summary(host: &str, sent: u32, rtts: &[f64]) -> Vec<String> {
    let recv = rtts.len() as u32;
    let loss = (sent - recv) as f64 * 100.0 / sent as f64;
    let mut out = vec![
        String::new(),
        format!("--- {host} ping statistics ---"),
        format!(
            "{sent} packets transmitted, {recv} received, {}% packet loss",
            util::fmt_pct(loss)
        ),
    ];
    if recv > 0 {
        let n = recv as f64;
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(0.0, f64::max);
        let avg = rtts.iter().sum::<f64>() / n;
        let mdev = (rtts.iter().map(|r| r * r).sum::<f64>() / n - avg * avg)
            .max(0.0)
            .sqrt();
        out.push(format!(
            "rtt min/avg/max/mdev = {min:.3}/{avg:.3}/{max:.3}/{mdev:.3} ms"
        ));
    }
    out
}

/// Convenience for non-live mode: collects everything into a single text.
/// The third value is `true` if the test was stopped.
pub async fn collect(req: PingReq, stop: &Stop) -> Result<(String, Option<HostMeta>, bool)> {
    let mut text = String::new();
    let mut meta = None;
    let stopped = run(req, stop, |e| match e {
        Event::Meta(m) => meta = Some(m),
        Event::Line(l) => {
            text.push_str(&l);
            text.push('\n');
        }
        Event::Done(_) => {}
    })
    .await?;
    Ok((text, meta, stopped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistiche() {
        let s = summary("srv01", 4, &[0.4, 0.5, 0.3]);
        assert_eq!(s[2], "4 packets transmitted, 3 received, 25% packet loss");
        assert_eq!(s[3], "rtt min/avg/max/mdev = 0.300/0.400/0.500/0.082 ms");
        let s = summary("x", 2, &[]);
        assert_eq!(s.len(), 3);
        assert!(s[2].ends_with("100% packet loss"));
    }

    #[tokio::test]
    async fn validazione() {
        let stop = Stop::new();
        let r = |h: &str, c: Option<u32>| {
            run(
                PingReq {
                    host: h.into(),
                    count: c,
                    resolve: None,
                    interval_ms: None,
                    timeout_ms: None,
                    max_hops: None,
                    ..Default::default()
                },
                &stop,
                |_| {},
            )
        };
        let opt = |i: Option<u32>, t: Option<u32>| {
            run(
                PingReq {
                    host: "1.2.3.4".into(),
                    count: Some(1),
                    resolve: None,
                    interval_ms: i,
                    timeout_ms: t,
                    max_hops: None,
                    ..Default::default()
                },
                &stop,
                |_| {},
            )
        };
        assert!(opt(Some(99), None)
            .await
            .unwrap_err()
            .starts_with("Intervallo"));
        assert!(opt(Some(2001), None)
            .await
            .unwrap_err()
            .starts_with("Intervallo"));
        assert!(opt(None, Some(5001))
            .await
            .unwrap_err()
            .starts_with("Timeout"));
        assert!(opt(None, Some(50))
            .await
            .unwrap_err()
            .starts_with("Timeout"));
        assert_eq!(r("", None).await.unwrap_err(), "Host richiesto");
        assert!(r("1.2.3.4", Some(0))
            .await
            .unwrap_err()
            .starts_with("Pacchetti"));
        assert_eq!(
            r("1.2.3.4", Some(101)).await.unwrap_err(),
            "Pacchetti: da 1 a 100"
        );
        assert!(r("-x", None).await.is_err());
    }

    fn req(host: &str, count: u32, interval_ms: u32, timeout_ms: u32) -> PingReq {
        PingReq {
            host: host.into(),
            count: Some(count),
            resolve: Some(false),
            interval_ms: Some(interval_ms),
            timeout_ms: Some(timeout_ms),
            max_hops: None,
            ..Default::default()
        }
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(
            stopped_early(),
            "Stopped before the reply to the first packet."
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let err = rt.block_on(run(req("1.2.3.4", 101, 1000, 1000), &Stop::new(), |_| {}));
        assert_eq!(err.unwrap_err(), "Packets: 1 to 100");
        let err = rt.block_on(run(req("1.2.3.4", 1, 99, 1000), &Stop::new(), |_| {}));
        assert_eq!(err.unwrap_err(), "Interval: 100 to 2000 ms");
        let err = rt.block_on(run(req("1.2.3.4", 1, 1000, 50), &Stop::new(), |_| {}));
        assert_eq!(err.unwrap_err(), "Timeout: 100 to 5000 ms");
    }

    #[test]
    fn dimensione_e_df() {
        let r = |size: Option<u32>| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(run(
                PingReq {
                    size,
                    ..req("127.0.0.1", 1, 1000, 1000)
                },
                &Stop::new(),
                |_| {},
            ))
        };
        assert_eq!(r(Some(65501)).unwrap_err(), "Dimensione: da 0 a 65500 byte");
        {
            let _g = crate::i18n::scoped(crate::i18n::Lang::En);
            assert_eq!(r(Some(65501)).unwrap_err(), "Size: 0 to 65500 bytes");
        }
        // an empty string from the form means "default"
        let q: PingReq =
            serde_json::from_str(r#"{"host":"x","size":"","dont_fragment":true}"#).unwrap();
        assert_eq!(q.size, None);
        assert_eq!(q.dont_fragment, Some(true));
        let q: PingReq = serde_json::from_str(r#"{"host":"x","size":"1472"}"#).unwrap();
        assert_eq!(q.size, Some(1472));
    }

    /// The header line and the reply lines carry the requested size.
    #[tokio::test]
    async fn dimensione_nelle_righe() {
        let (text, _, _) = collect(
            PingReq {
                size: Some(100),
                ..req("127.0.0.1", 1, 100, 1000)
            },
            &Stop::new(),
        )
        .await
        .unwrap();
        assert!(text.contains("100 bytes of data."), "{text}");
        assert!(
            text.contains("108 bytes from") || text.contains("Request timed out"),
            "{text}"
        );
    }

    #[test]
    fn interruttore() {
        let stop = Stop::new();
        let copia = stop.clone();
        assert!(!stop.is_stopped());
        copia.stop();
        assert!(stop.is_stopped());
    }

    /// Waiting for a reply is a blocking call (IcmpSendEcho) in
    /// `spawn_blocking`: the stop must not wait for it to finish.
    #[tokio::test]
    async fn stop_non_aspetta_una_chiamata_bloccante() {
        let stop = Stop::new();
        let t0 = Instant::now();
        let slow = tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(1500)));
        let (r, _) = tokio::join!(stop.race(slow), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            stop.stop();
        });
        assert!(r.is_none());
        assert!(
            t0.elapsed() < Duration::from_millis(1000),
            "{:?}",
            t0.elapsed()
        );
        // without a stop the result arrives
        assert_eq!(Stop::new().race(async { 7 }).await, Some(7));
    }

    /// Stop already received: no packet, no statistics.
    #[tokio::test]
    async fn fermato_prima_di_partire() {
        let stop = Stop::new();
        stop.stop();
        let (text, meta, stopped) = collect(req("127.0.0.1", 4, 1000, 1000), &stop)
            .await
            .unwrap();
        assert!(stopped);
        assert!(meta.is_none());
        assert_eq!(text.trim_end(), stopped_early());
    }

    /// Stop during the interval between two packets: it exits at once, with the
    /// statistics of the only packet that had an outcome.
    #[tokio::test]
    async fn fermato_nell_intervallo() {
        let stop = Stop::new();
        let mut lines = Vec::new();
        let mut stopped_at = None;
        let stopped = run(req("127.0.0.1", 5, 2000, 1000), &stop, |e| {
            if let Event::Line(l) = e {
                if l.contains("icmp_seq=1") {
                    stop.stop();
                    stopped_at = Some(Instant::now());
                }
                lines.push(l);
            }
        })
        .await
        .unwrap();
        assert!(stopped);
        // the interval is 2 s: after the stop it is not awaited
        let after = stopped_at
            .expect("nessun esito per il primo pacchetto")
            .elapsed();
        assert!(after < Duration::from_millis(1000), "{after:?}");
        assert!(
            lines.contains(&"Fermato dopo 1 pacchetto su 5.".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("1 packets transmitted")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("icmp_seq=2")), "{lines:?}");
    }

    /// Stop while waiting for a reply that never comes: the timeout is not awaited.
    #[tokio::test]
    async fn fermato_in_attesa_della_risposta() {
        let stop = Stop::new();
        let (res, stopped_at) =
            tokio::join!(collect(req("192.0.2.1", 3, 2000, 3000), &stop), async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                stop.stop();
                Instant::now()
            });
        let after = stopped_at.elapsed();
        let (text, _, stopped) = res.unwrap();
        assert!(stopped);
        // 3 s timeout and 2 s interval: after the stop neither is awaited
        assert!(after < Duration::from_millis(1000), "{after:?}");
        assert!(text.contains("Fermato"), "{text}");
        assert!(!text.contains("icmp_seq=2"), "{text}");
    }

    /// Without a stop the test runs to the end and says so.
    #[tokio::test]
    async fn completo_non_fermato() {
        let (text, _, stopped) = collect(req("127.0.0.1", 2, 100, 1000), &Stop::new())
            .await
            .unwrap();
        assert!(!stopped);
        assert!(text.contains("2 packets transmitted"), "{text}");
        assert!(!text.contains("Fermato"), "{text}");
    }
}
