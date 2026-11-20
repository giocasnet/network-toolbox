//! Traceroute with ICMP echoes at increasing TTL (like Windows `tracert`),
//! output in the Linux traceroute format.

use crate::icmp::{self, Echo, Status, PAYLOAD};
use crate::net::{self, MetaLookup};
use crate::ping::{self, fmt_rtt, PingReq, Stop};
use crate::{t, tf, Event, Result};
use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

/// Default maximum hops and the upper limit that can be set.
pub const MAX_HOPS: u8 = 30;
pub const MAX_HOPS_LIMIT: u32 = 64;
/// After this many consecutive hops without a reply it stops.
pub const MAX_SILENT: u8 = 8;
/// Hops tried together: a block that is entirely silent ends the traceroute.
pub const BATCH: u8 = 8;

/// Final line when the traceroute is stopped with `stop`.
pub(crate) fn stopped_line() -> &'static str {
    t!("    fermato prima della fine", "    stopped before the end")
}

/// Runs the traceroute. Returns `true` if it was stopped with `stop`.
///
/// Hops are tried in blocks of `BATCH` TTLs together (each packet expires on
/// a different router, so no router receives a burst) and the lines come out
/// in order, each as soon as it and all the previous ones are ready. The name of whoever
/// answers is looked up inside the same task, hence in parallel with the other hops.
pub async fn run<F: FnMut(Event) + Send>(req: PingReq, stop: &Stop, mut emit: F) -> Result<bool> {
    let host = net::clean_host(&req.host)?;
    let max_hops = req.max_hops.unwrap_or(MAX_HOPS as u32);
    if !(1..=MAX_HOPS_LIMIT).contains(&max_hops) {
        return Err(tf!(
            "Hop massimi: da 1 a {MAX_HOPS_LIMIT}",
            "Maximum hops: 1 to {MAX_HOPS_LIMIT}"
        ));
    }
    let max_hops = max_hops as u8;
    let hop_timeout = ping::timeout(&req)?;
    let resolve = req.resolve.unwrap_or(true);
    let Some(ip) = stop.race(net::resolve_v4(&host)).await else {
        emit(Event::Line(stopped_line().trim_start().into()));
        return Ok(true);
    };
    let ip = ip?;
    // The target name is looked up while the first hops go out.
    let mut meta = MetaLookup::start(&host, ip);
    emit(Event::Line(format!(
        "traceroute to {host} ({ip}), {max_hops} hops max, {PAYLOAD} byte packets"
    )));

    let names: Names = Arc::new(Mutex::new(HashMap::new()));
    let probe = |ttl| hop(ip, ttl, hop_timeout, resolve, names.clone());
    let stopped = hops(max_hops, probe, stop, &mut meta, &mut emit).await;
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

type Names = Arc<Mutex<HashMap<Ipv4Addr, String>>>;

/// "name (ip)" if resolution is on and there is a name, otherwise the IP.
async fn who(addr: Ipv4Addr, resolve: bool, names: &Names) -> String {
    if !resolve {
        return addr.to_string();
    }
    let cached = names.lock().ok().and_then(|m| m.get(&addr).cloned());
    let name = match cached {
        Some(n) => n,
        None => {
            let n = net::name_of(addr, Duration::from_millis(1500)).await;
            if let Ok(mut m) = names.lock() {
                m.insert(addr, n.clone());
            }
            n
        }
    };
    if name.is_empty() {
        addr.to_string()
    } else {
        format!("{name} ({addr})")
    }
}

/// One hop: the echo with the given TTL and the name of whoever answered.
async fn hop(
    ip: Ipv4Addr,
    ttl: u8,
    timeout_ms: u32,
    resolve: bool,
    names: Names,
) -> (Echo, String) {
    let e = icmp::echo(ip, ttl, timeout_ms).await;
    let label = match (e.status, e.from) {
        (Status::Reply | Status::TtlExpired | Status::Unreachable, Some(addr)) => {
            who(addr, resolve, &names).await
        }
        _ => String::new(),
    };
    (e, label)
}

/// Hops of a block still in progress are abandoned on exit
/// (destination reached, stop, too many silent hops).
struct Batch(Vec<JoinHandle<(Echo, String)>>);

impl Drop for Batch {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

/// Tries the hops and prints the lines. `true` if stopped with `stop`.
async fn hops<F, P, Fut>(
    max_hops: u8,
    probe: P,
    stop: &Stop,
    meta: &mut MetaLookup,
    emit: &mut F,
) -> bool
where
    F: FnMut(Event) + Send,
    P: Fn(u8) -> Fut,
    Fut: Future<Output = (Echo, String)> + Send + 'static,
{
    let mut silent = 0u8;
    let mut first = 1u8;
    while first <= max_hops {
        let last = first.saturating_add(BATCH - 1).min(max_hops);
        let mut batch = Batch((first..=last).map(|ttl| tokio::spawn(probe(ttl))).collect());
        for (i, task) in batch.0.iter_mut().enumerate() {
            let ttl = first + i as u8;
            let Some(res) = stop.race(task).await else {
                emit(Event::Line(stopped_line().into()));
                return true;
            };
            if let Some(m) = meta.ready().await {
                emit(Event::Meta(m));
            }
            let (e, label) = res.unwrap_or_else(|_| (Echo::timeout(), String::new()));
            match (e.status, e.from) {
                (Status::Reply | Status::TtlExpired | Status::Unreachable, Some(_)) => {
                    silent = 0;
                    let note = if e.status == Status::Unreachable {
                        "  !H"
                    } else {
                        ""
                    };
                    emit(Event::Line(format!(
                        "{ttl:>2}  {label}  {} ms{note}",
                        fmt_rtt(e.rtt_ms)
                    )));
                    if e.status != Status::TtlExpired {
                        return false;
                    }
                }
                (Status::Error(code), _) => {
                    emit(Event::Line(tf!(
                        "{ttl:>2}  errore di sistema {code}",
                        "{ttl:>2}  system error {code}"
                    )));
                    return false;
                }
                _ => {
                    silent += 1;
                    emit(Event::Line(format!("{ttl:>2}  *")));
                    if silent >= MAX_SILENT {
                        emit(Event::Line(tf!(
                            "    interrotto: {MAX_SILENT} salti consecutivi senza risposta",
                            "    aborted: {MAX_SILENT} consecutive hops without a reply"
                        )));
                        return false;
                    }
                }
            }
        }
        first = last + 1;
    }
    false
}

/// Collects everything into a single text; the third value is `true` if stopped.
pub async fn collect(req: PingReq, stop: &Stop) -> Result<(String, Option<net::HostMeta>, bool)> {
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
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn validazione() {
        let stop = Stop::new();
        let r = |h: Option<u32>, t: Option<u32>| {
            run(
                PingReq {
                    host: "1.2.3.4".into(),
                    count: None,
                    resolve: None,
                    interval_ms: None,
                    timeout_ms: t,
                    max_hops: h,
                    ..Default::default()
                },
                &stop,
                |_| {},
            )
        };
        assert!(r(Some(0), None)
            .await
            .unwrap_err()
            .starts_with("Hop massimi"));
        assert!(r(Some(65), None)
            .await
            .unwrap_err()
            .starts_with("Hop massimi"));
        assert!(r(None, Some(5001))
            .await
            .unwrap_err()
            .starts_with("Timeout"));
    }

    fn req(host: &str, timeout_ms: u32) -> PingReq {
        PingReq {
            host: host.into(),
            count: None,
            resolve: Some(false),
            interval_ms: None,
            timeout_ms: Some(timeout_ms),
            max_hops: None,
            ..Default::default()
        }
    }

    fn echo(status: Status, from: Option<[u8; 4]>, rtt_ms: f64) -> Echo {
        Echo {
            status,
            from: from.map(Ipv4Addr::from),
            rtt_ms,
            ttl: None,
        }
    }

    /// Fake path: `route(ttl)` says who answers and after how many milliseconds.
    async fn finto<R>(max_hops: u8, route: R, stop: &Stop) -> (Vec<String>, bool, Vec<u8>)
    where
        R: Fn(u8) -> (Echo, u64) + Send + Sync + 'static,
    {
        let route = Arc::new(route);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let s2 = sent.clone();
        let probe = move |ttl: u8| {
            let (route, sent) = (route.clone(), s2.clone());
            async move {
                sent.lock().unwrap().push(ttl);
                let (e, wait) = route(ttl);
                tokio::time::sleep(Duration::from_millis(wait)).await;
                let label = e.from.map(|a| a.to_string()).unwrap_or_default();
                (e, label)
            }
        };
        let mut meta = MetaLookup::start("203.0.113.9", Ipv4Addr::new(203, 0, 113, 9));
        let mut lines = Vec::new();
        let stopped = hops(max_hops, probe, stop, &mut meta, &mut |e| {
            if let Event::Line(l) = e {
                lines.push(l);
            }
        })
        .await;
        let mut sent = sent.lock().unwrap().clone();
        sent.sort_unstable();
        (lines, stopped, sent)
    }

    /// Destination at the fifth hop: hops come out in order even if the replies
    /// arrive out of order, and those beyond the destination are not printed.
    #[tokio::test]
    async fn salti_in_parallelo_in_ordine() {
        let t0 = Instant::now();
        let (lines, stopped, sent) = finto(
            30,
            |ttl| match ttl {
                1..=4 => (
                    echo(Status::TtlExpired, Some([192, 0, 2, ttl]), ttl as f64),
                    // the first hop answers last
                    200 - 40 * ttl as u64,
                ),
                _ => (echo(Status::Reply, Some([203, 0, 113, 9]), 9.5), 10),
            },
            &Stop::new(),
        )
        .await;
        assert!(!stopped);
        assert_eq!(
            lines,
            vec![
                " 1  192.0.2.1  1.000 ms",
                " 2  192.0.2.2  2.000 ms",
                " 3  192.0.2.3  3.000 ms",
                " 4  192.0.2.4  4.000 ms",
                " 5  203.0.113.9  9.500 ms",
            ]
        );
        // a single block, and the five hops together: 160 ms, not the sum (410 ms)
        assert_eq!(sent, (1..=BATCH).collect::<Vec<_>>());
        assert!(
            t0.elapsed() < Duration::from_millis(350),
            "{:?}",
            t0.elapsed()
        );
    }

    /// A silent hop in the middle does not stop the traceroute; the destination in the second
    /// block is reached and the hop count carries on from one block to the next.
    #[tokio::test]
    async fn secondo_blocco_e_salto_muto() {
        let (lines, stopped, sent) = finto(
            30,
            |ttl| match ttl {
                3 => (Echo::timeout(), 60),
                1..=10 => (echo(Status::TtlExpired, Some([192, 0, 2, ttl]), 1.0), 5),
                _ => (echo(Status::Unreachable, Some([192, 0, 2, 99]), 2.0), 5),
            },
            &Stop::new(),
        )
        .await;
        assert!(!stopped);
        assert_eq!(lines.len(), 11, "{lines:?}");
        assert_eq!(lines[2], " 3  *");
        assert_eq!(lines[10], "11  192.0.2.99  2.000 ms  !H");
        assert_eq!(sent, (1..=16).collect::<Vec<_>>());
    }

    /// No reply: it stops after `MAX_SILENT` hops, i.e. after the first
    /// block and a single timeout (not one per hop).
    #[tokio::test]
    async fn tutti_muti() {
        let t0 = Instant::now();
        let (lines, stopped, sent) = finto(30, |_| (Echo::timeout(), 150), &Stop::new()).await;
        assert!(!stopped);
        assert_eq!(lines.len(), MAX_SILENT as usize + 1, "{lines:?}");
        assert!(lines[8].contains("8 salti consecutivi senza risposta"));
        assert_eq!(sent.len(), MAX_SILENT as usize);
        assert!(
            t0.elapsed() < Duration::from_millis(600),
            "{:?}",
            t0.elapsed()
        );
    }

    /// The hop limit also applies midway through a block, and a system error ends it.
    #[tokio::test]
    async fn limite_dei_salti_ed_errore() {
        let (lines, _, sent) = finto(
            3,
            |ttl| (echo(Status::TtlExpired, Some([192, 0, 2, ttl]), 1.0), 1),
            &Stop::new(),
        )
        .await;
        assert_eq!(lines.len(), 3);
        assert_eq!(sent, vec![1, 2, 3]);
        let (lines, stopped, _) = finto(
            30,
            |ttl| match ttl {
                1 => (echo(Status::TtlExpired, Some([192, 0, 2, 1]), 1.0), 1),
                _ => (echo(Status::Error(1231), None, 0.0), 1),
            },
            &Stop::new(),
        )
        .await;
        assert!(!stopped);
        assert_eq!(lines.last().unwrap(), " 2  errore di sistema 1231");
        assert_eq!(lines.len(), 2);
    }

    /// "Stop" while waiting for a hop: the lines already ready and the note come out.
    #[tokio::test]
    async fn fermato_a_meta_blocco() {
        let stop = Stop::new();
        let (res, _) = tokio::join!(
            finto(
                30,
                |ttl| match ttl {
                    1 | 2 => (echo(Status::TtlExpired, Some([192, 0, 2, ttl]), 1.0), 5),
                    _ => (Echo::timeout(), 3000),
                },
                &stop
            ),
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                stop.stop();
            }
        );
        let (lines, stopped, _) = res;
        assert!(stopped);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(lines[2], stopped_line());
    }

    #[tokio::test]
    async fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let (lines, _, _) = finto(30, |_| (Echo::timeout(), 1), &Stop::new()).await;
        assert!(
            lines[8].contains("8 consecutive hops without a reply"),
            "{lines:?}"
        );
        assert!(!lines[8].contains("salti"));
        let (lines, _, _) = finto(30, |_| (Echo::timeout(), 1000), &{
            let s = Stop::new();
            s.stop();
            s
        })
        .await;
        assert_eq!(lines.last().unwrap(), "    stopped before the end");
        let (lines, _, _) =
            finto(30, |_| (echo(Status::Error(5), None, 0.0), 1), &Stop::new()).await;
        assert_eq!(lines[0], " 1  system error 5");
        let r = run(
            PingReq {
                host: "1.2.3.4".into(),
                count: None,
                resolve: None,
                interval_ms: None,
                timeout_ms: None,
                max_hops: Some(0),
                ..Default::default()
            },
            &Stop::new(),
            |_| {},
        )
        .await;
        assert_eq!(r.unwrap_err(), "Maximum hops: 1 to 64");
    }

    #[test]
    fn predefiniti() {
        assert_eq!(MAX_HOPS, 30);
        assert_eq!(MAX_HOPS_LIMIT, 64);
    }

    /// Stop already received: no hop.
    #[tokio::test]
    async fn fermato_prima_di_partire() {
        let stop = Stop::new();
        stop.stop();
        let (text, meta, stopped) = collect(req("127.0.0.1", 1000), &stop).await.unwrap();
        assert!(stopped);
        assert!(meta.is_none());
        assert_eq!(text.trim_end(), stopped_line().trim_start());
    }

    /// Stop while the hops do not answer: the other timeouts are not awaited.
    #[tokio::test]
    async fn fermato_durante_i_salti() {
        let stop = Stop::new();
        let (res, stopped_at) = tokio::join!(collect(req("192.0.2.1", 3000), &stop), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            stop.stop();
            Instant::now()
        });
        let after = stopped_at.elapsed();
        let (text, _, stopped) = res.unwrap();
        // if the destination answers or is unreachable at the first hop, the traceroute
        // ends by itself before the stop
        if stopped {
            // 3 s timeout per hop: after the stop it is not awaited
            assert!(after < Duration::from_millis(1000), "{after:?}");
            assert!(
                text.trim_end().ends_with(stopped_line().trim_start()),
                "{text}"
            );
        } else {
            assert!(!text.contains("fermato"), "{text}");
        }
    }

    /// Without a stop the traceroute to this PC runs to the end at the first hop.
    #[tokio::test]
    async fn completo_non_fermato() {
        let (text, _, stopped) = collect(req("127.0.0.1", 1000), &Stop::new()).await.unwrap();
        assert!(!stopped);
        assert!(!text.contains("fermato"), "{text}");
    }
}
