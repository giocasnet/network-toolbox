//! Subnet scan (up to /24), in two phases: first who is there (ICMP, ARP table
//! on the local subnet, optional TCP), then the names of the hosts found only. Hosts
//! are emitted as soon as they answer and the scan can be stopped.

use crate::icmp::{self, ArpTable};
use crate::net;
use crate::ping::Stop;
use crate::tcp::{self, Conn};
use crate::{t, tf, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Debug, Deserialize)]
pub struct SweepReq {
    pub cidr: String,
    #[serde(default)]
    pub tcp: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepHost {
    pub ip: String,
    pub via: String,
    pub rtt_ms: Option<f64>,
    pub mac: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct SweepResult {
    pub cidr: String,
    pub total: usize,
    pub alive: Vec<SweepHost>,
    pub tcp: bool,
    /// The network is one the PC is directly connected to (MAC available).
    pub local: bool,
    pub elapsed_s: f64,
    /// Interrupted with "Stop": `alive` holds the hosts found so far.
    pub stopped: bool,
    /// Addresses checked (equal to `total` if the scan reached the end).
    pub checked: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepStart {
    pub cidr: String,
    pub total: usize,
    pub local: bool,
    pub tcp: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepProgress {
    pub done: usize,
    pub total: usize,
}

/// Scan events: `{"start":{..}}`, `{"progress":{..}}`, `{"host":{..}}`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SweepEvent {
    Start(SweepStart),
    Progress(SweepProgress),
    Host(SweepHost),
}

pub const TCP_PORTS: [u16; 6] = [445, 3389, 135, 22, 80, 443];

pub fn parse_net(cidr: &str) -> Result<Ipv4Net> {
    parse_net_limit(cidr, 24)
}

/// Like `parse_net`, with the given minimum prefix (24 = at most 254 hosts).
pub fn parse_net_limit(cidr: &str, min_prefix: u8) -> Result<Ipv4Net> {
    let cidr = cidr.trim();
    if !cidr.contains('/') {
        return Err(t!(
            "Indica la rete con il prefisso, per esempio 172.16.24.0/24",
            "Specify the network with its prefix, for example 172.16.24.0/24"
        )
        .into());
    }
    let net: Ipv4Net = cidr
        .parse()
        .map_err(|_| tf!("Rete non valida: {cidr}", "Invalid network: {cidr}"))?;
    let net = net.trunc();
    if net.prefix_len() < min_prefix {
        return Err(tf!(
            "Rete troppo grande: massimo una /{min_prefix} ({} host)",
            "Network too large: at most a /{min_prefix} ({} hosts)",
            (1u32 << (32 - min_prefix)) - 2
        ));
    }
    let n = net.network();
    if n.is_loopback() || n.is_link_local() || n.is_multicast() || n.is_unspecified() {
        return Err(t!("Rete non consentita", "Network not allowed").into());
    }
    Ok(net)
}

pub fn targets(net: &Ipv4Net) -> Vec<Ipv4Addr> {
    let v: Vec<Ipv4Addr> = net.hosts().collect();
    if v.is_empty() {
        vec![net.network()]
    } else {
        v
    }
}

/// Is the requested network directly connected to an adapter of this PC?
pub(crate) fn is_local(net: &Ipv4Net) -> bool {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .any(|i| match i.addr {
            if_addrs::IfAddr::V4(a) if !a.ip.is_loopback() => {
                Ipv4Net::with_netmask(a.ip, a.netmask)
                    .map(|iface| iface.contains(&net.network()) || net.contains(&a.ip))
                    .unwrap_or(false)
            }
            _ => false,
        })
}

/// Host is up if one of the ports answers, even with a refusal (RST).
/// Ports are tried in parallel: on Windows the refusal arrives after about 1 s.
pub(crate) async fn tcp_probe(ip: Ipv4Addr) -> Option<u16> {
    let attempts = TCP_PORTS.map(|port| async move {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        match tcp::connect(addr, Duration::from_millis(1500)).await {
            Conn::Open(_) | Conn::Refused => Some(port),
            Conn::Failed(_) => None,
        }
    });
    let [a, b, c, d, e, f] = attempts;
    let (a, b, c, d, e, f) = tokio::join!(a, b, c, d, e, f);
    [a, b, c, d, e, f].into_iter().flatten().next()
}

/// Outcome of the search for a host at an address.
pub(crate) struct Presence {
    /// ICMP, ARP or "TCP <port>".
    pub via: String,
    pub rtt_ms: Option<f64>,
    pub mac: String,
}

/// Addresses started together, and the pause between one group and the next: echoes
/// to a local network trigger a broadcast ARP request per address,
/// and a whole network at once would be a pointless burst.
pub(crate) const BATCH: usize = 128;
pub(crate) const BATCH_EVERY: Duration = Duration::from_millis(250);

/// Silent addresses examined together with TCP (6 connections each).
static TCP_GATE: Semaphore = Semaphore::const_new(256);

/// Networks the adapters of this PC are directly connected to.
pub(crate) fn local_nets() -> Vec<Ipv4Net> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) if !a.ip.is_loopback() => {
                Ipv4Net::with_netmask(a.ip, a.netmask)
                    .ok()
                    .map(|n| n.trunc())
            }
            _ => None,
        })
        .collect()
}

/// Is there a host at this address? Ping (two attempts of 800 ms). If
/// the address is on the same network as one of the PC's adapters (`on_link`), the MAC from
/// the system ARP table, which also contains hosts that block ping (ARP cannot
/// be filtered): there an address without a MAC is empty, and nothing else is needed. For
/// addresses reached through a router, if requested, TCP for those still
/// silent. `None` if nobody answers or if the stop arrives before an
/// answer.
pub(crate) async fn presence(
    ip: Ipv4Addr,
    on_link: bool,
    tcp: bool,
    arp: &ArpTable,
    stop: &Stop,
) -> Option<Presence> {
    let mut rtt = None;
    for _ in 0..2 {
        let e = stop.race(icmp::echo_scan(ip, 128, 800)).await?;
        if e.status == icmp::Status::Reply {
            rtt = Some((e.rtt_ms * 100.0).round() / 100.0);
            break;
        }
    }
    // stopped while reading the MAC: a host that answered is still emitted, without it
    let mac = if on_link {
        stop.race(arp.mac(ip, rtt.is_some())).await.flatten()
    } else {
        None
    };
    let via = if rtt.is_some() {
        "ICMP".to_string()
    } else if mac.is_some() {
        "ARP".to_string()
    } else if tcp && !on_link {
        let probe = async {
            let _slot = TCP_GATE.acquire().await;
            tcp_probe(ip).await
        };
        format!("TCP {}", stop.race(probe).await??)
    } else {
        return None;
    };
    Some(Presence {
        via,
        rtt_ms: rtt,
        mac: mac.unwrap_or_default(),
    })
}

/// Two-phase scan. First presence: the host is emitted with `emit` as soon as it
/// answers, without a name. Then the name (PTR, otherwise NetBIOS): if there is one, the same
/// host is emitted a second time, complete (whoever receives the events updates the row
/// with the same address). The final response returns them all in address
/// order. With `stop` ("Stop" button) it ends at once, with the hosts
/// found so far; those waiting for the name stay without.
pub async fn run<F>(req: SweepReq, stop: &Stop, emit: F) -> Result<SweepResult>
where
    F: Fn(SweepEvent) + Send + Sync + 'static,
{
    let t0 = Instant::now();
    let net = parse_net(&req.cidr)?;
    let all = targets(&net);
    let total = all.len();
    let local = is_local(&net);
    let tcp = req.tcp;
    let emit = Arc::new(emit);
    emit(SweepEvent::Start(SweepStart {
        cidr: net.to_string(),
        total,
        local,
        tcp,
    }));

    let sem = Arc::new(Semaphore::new(icmp::scan_parallelism()));
    let arp = Arc::new(ArpTable::new());
    let nets = local_nets();
    let done = Arc::new(AtomicUsize::new(0));
    let mut set = JoinSet::new();
    for (i, ip) in all.into_iter().enumerate() {
        // after a stop no more addresses start
        if i > 0 && i % BATCH == 0 && stop.race(tokio::time::sleep(BATCH_EVERY)).await.is_none() {
            break;
        }
        let Some(permit) = stop.race(sem.clone().acquire_owned()).await else {
            break;
        };
        let permit = permit.expect("semaforo chiuso");
        let (emit, done, stop, arp) = (emit.clone(), done.clone(), stop.clone(), arp.clone());
        let on_link = nets.iter().any(|n| n.contains(&ip));
        set.spawn(async move {
            let found = presence(ip, on_link, tcp, &arp, &stop).await;
            drop(permit);
            let mut host = found.map(|p| SweepHost {
                ip: ip.to_string(),
                via: p.via,
                rtt_ms: p.rtt_ms,
                mac: p.mac,
                name: String::new(),
            });
            if let Some(h) = &host {
                emit(SweepEvent::Host(h.clone()));
            }
            // stopped midway: the address does not count among those checked
            if host.is_some() || !stop.is_stopped() {
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 16 == 0 || n == total {
                    emit(SweepEvent::Progress(SweepProgress { done: n, total }));
                }
            }
            if let Some(h) = host.as_mut() {
                let name = stop
                    .race(net::name_of(ip, Duration::from_millis(1500)))
                    .await
                    .unwrap_or_default();
                if !name.is_empty() {
                    h.name = name;
                    emit(SweepEvent::Host(h.clone()));
                }
            }
            host
        });
    }
    let mut found: BTreeMap<Ipv4Addr, SweepHost> = BTreeMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(h)) = r {
            if let Ok(ip) = h.ip.parse() {
                found.insert(ip, h);
            }
        }
    }

    Ok(SweepResult {
        cidr: net.to_string(),
        total,
        alive: found.into_values().collect(),
        tcp,
        local,
        elapsed_s: (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        stopped: stop.is_stopped(),
        checked: done.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reti() {
        assert_eq!(
            parse_net("172.16.24.7/24").unwrap().to_string(),
            "172.16.24.0/24"
        );
        assert_eq!(targets(&parse_net("172.16.24.0/24").unwrap()).len(), 254);
        assert_eq!(targets(&parse_net("172.16.24.0/30").unwrap()).len(), 2);
        assert_eq!(targets(&parse_net("172.16.24.5/32").unwrap()).len(), 1);
        assert!(parse_net("172.16.0.0/16")
            .unwrap_err()
            .contains("troppo grande"));
        assert!(parse_net("127.0.0.0/24").is_err());
        assert!(parse_net("169.254.1.0/24").is_err());
        assert!(parse_net("172.16.24.0").is_err());
        assert!(parse_net("pippo/24").is_err());
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(
            parse_net("172.16.0.0/16").unwrap_err(),
            "Network too large: at most a /24 (254 hosts)"
        );
        assert_eq!(
            parse_net("pippo/24").unwrap_err(),
            "Invalid network: pippo/24"
        );
        let e = parse_net("172.16.24.0").unwrap_err();
        assert!(
            e.contains("Specify the network") && !e.contains("Indica"),
            "{e}"
        );
        assert_eq!(
            parse_net("127.0.0.0/24").unwrap_err(),
            "Network not allowed"
        );
    }

    fn collector() -> (
        Arc<std::sync::Mutex<Vec<SweepEvent>>>,
        impl Fn(SweepEvent) + Send + Sync + 'static,
    ) {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let e2 = ev.clone();
        (ev, move |e| e2.lock().unwrap().push(e))
    }

    #[test]
    fn eventi_json() {
        let e = SweepEvent::Progress(SweepProgress { done: 3, total: 9 });
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"progress":{"done":3,"total":9}}"#
        );
        let e = SweepEvent::Host(SweepHost {
            ip: "192.0.2.7".into(),
            via: "ARP".into(),
            rtt_ms: None,
            mac: String::new(),
            name: String::new(),
        });
        assert!(serde_json::to_string(&e)
            .unwrap()
            .starts_with(r#"{"host":{"ip":"192.0.2.7","via":"ARP","rtt_ms":null"#));
    }

    /// Full scan of a network without hosts (TEST-NET-3): the start event first,
    /// progress up to the total, response consistent with the events.
    #[tokio::test]
    async fn scansione_completa() {
        let (ev, emit) = collector();
        let req = SweepReq {
            cidr: "203.0.113.9/29".into(),
            tcp: false,
        };
        let r = run(req, &Stop::new(), emit).await.unwrap();
        assert_eq!(
            (r.cidr.as_str(), r.total, r.checked),
            ("203.0.113.8/29", 6, 6)
        );
        assert!(!r.stopped && !r.tcp);
        let ev = ev.lock().unwrap();
        assert!(
            matches!(&ev[0], SweepEvent::Start(s) if s.total == 6 && s.cidr == "203.0.113.8/29")
        );
        assert!(ev
            .iter()
            .any(|e| matches!(e, SweepEvent::Progress(p) if p.done == 6 && p.total == 6)));
        let hosts: Vec<&str> = ev
            .iter()
            .filter_map(|e| match e {
                SweepEvent::Host(h) => Some(h.ip.as_str()),
                _ => None,
            })
            .collect();
        // a host is emitted once when it answers and a second time if it has a name
        let unique: std::collections::BTreeSet<&str> = hosts.iter().copied().collect();
        assert_eq!(unique.len(), r.alive.len());
        assert!(hosts.len() <= 2 * r.alive.len());
        // the final response is in address order
        let ips: Vec<Ipv4Addr> = r.alive.iter().map(|h| h.ip.parse().unwrap()).collect();
        assert!(ips.windows(2).all(|w| w[0] < w[1]));
    }

    /// Stop already received: no address starts.
    #[tokio::test]
    async fn fermata_prima_di_partire() {
        let (ev, emit) = collector();
        let stop = Stop::new();
        stop.stop();
        let req = SweepReq {
            cidr: "203.0.113.0/24".into(),
            tcp: true,
        };
        let t0 = Instant::now();
        let r = run(req, &stop, emit).await.unwrap();
        assert!(r.stopped && r.alive.is_empty());
        assert_eq!((r.total, r.checked), (254, 0));
        assert!(t0.elapsed() < Duration::from_millis(500));
        assert_eq!(ev.lock().unwrap().len(), 1); // only the start
    }

    /// Stop during the scan: it ends at once, without waiting for the TCP
    /// probes in progress (1.5 s each), and half-checked addresses do not count.
    #[tokio::test]
    async fn fermata_in_corso() {
        let (_ev, emit) = collector();
        let stop = Stop::new();
        let s2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            s2.stop();
        });
        let req = SweepReq {
            cidr: "203.0.113.0/24".into(),
            tcp: true,
        };
        let t0 = Instant::now();
        let r = run(req, &stop, emit).await.unwrap();
        assert!(r.stopped);
        assert!(r.checked < r.total, "{} su {}", r.checked, r.total);
        assert!(
            t0.elapsed() < Duration::from_millis(1200),
            "{:?}",
            t0.elapsed()
        );
    }
}
