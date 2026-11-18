//! ICMP echo and ARP, with one backend per platform.
//!
//! - Windows: IP Helper API. No administrator privileges needed. `echo`
//!   (`IcmpSendEcho`, one thread per probe) for ping, traceroute and the home
//!   screen; `echo_scan` (`IcmpSendEcho2Ex` on a dedicated thread) and `ArpTable`
//!   (neighbour table, `GetIpNetTable2`) for the scans, with `echo` and
//!   `SendARP` as a fallback.
//! - Linux: system `ping` command and `/proc/net/arp` table. Only for
//!   development and tests: the app targets Windows.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Data bytes in every echo request (like Windows `ping`).
pub const PAYLOAD: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Reply from the destination.
    Reply,
    /// A router discarded the packet because the TTL expired (traceroute hop).
    TtlExpired,
    /// No reply within the timeout.
    Timeout,
    /// Destination, network or protocol unreachable.
    Unreachable,
    /// Local error (system code).
    Error(u32),
}

#[derive(Debug, Clone)]
pub struct Echo {
    pub status: Status,
    /// Who replied: the destination or the intermediate router.
    pub from: Option<Ipv4Addr>,
    pub rtt_ms: f64,
    pub ttl: Option<u8>,
}

impl Echo {
    pub fn timeout() -> Self {
        Echo {
            status: Status::Timeout,
            from: None,
            rtt_ms: 0.0,
            ttl: None,
        }
    }
}

#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl;

#[cfg(not(windows))]
mod unix_impl;

#[cfg(not(windows))]
use unix_impl as backend;
#[cfg(windows)]
use windows_impl as backend;

/// On Windows `SendARP` queries the network; on Linux only the kernel cache is read.
pub const ARP_ACTIVE: bool = cfg!(windows);

/// Sends an echo request with the given TTL and waits for the reply.
pub async fn echo(dest: Ipv4Addr, ttl: u8, timeout_ms: u32) -> Echo {
    tokio::task::spawn_blocking(move || backend::echo_blocking(dest, ttl, timeout_ms))
        .await
        .unwrap_or_else(|_| Echo::timeout())
}

/// Echo on the Windows asynchronous engine, if available.
#[cfg(any(windows, ntb_check_windows))]
async fn echo_engine(dest: Ipv4Addr, ttl: u8, timeout_ms: u32) -> Option<Echo> {
    let rx = windows_impl::echo_async(dest, ttl, timeout_ms)?;
    // Windows always delivers an outcome within the request timeout: if after
    // another two seconds there is none, the engine is not working and is no longer used.
    let limit = Duration::from_millis(timeout_ms as u64 + 2000);
    match tokio::time::timeout(limit, rx).await {
        Ok(Ok(e)) => Some(e),
        _ => {
            windows_impl::disable_async();
            None
        }
    }
}

#[cfg(not(any(windows, ntb_check_windows)))]
async fn echo_engine(_dest: Ipv4Addr, _ttl: u8, _timeout_ms: u32) -> Option<Echo> {
    None
}

/// Echo for the scans: like `echo`, but on Windows without a thread per probe
/// (see `windows_impl`). If the asynchronous engine is missing, it uses `echo`.
pub async fn echo_scan(dest: Ipv4Addr, ttl: u8, timeout_ms: u32) -> Echo {
    match echo_engine(dest, ttl, timeout_ms).await {
        Some(e) => e,
        None => echo(dest, ttl, timeout_ms).await,
    }
}

/// How many addresses a scan can examine together: with the asynchronous engine
/// the limit only avoids keeping too many requests open; with blocking
/// echoes every probe occupies a thread.
pub fn scan_parallelism() -> usize {
    #[cfg(any(windows, ntb_check_windows))]
    if windows_impl::async_available() {
        return 2048;
    }
    256
}

fn fmt_mac(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// MAC of a host on the same subnet, formatted aa:bb:cc:dd:ee:ff.
/// On Windows this is `SendARP`: if the host is not there, the call lasts a few seconds.
pub async fn arp(ip: Ipv4Addr) -> Option<String> {
    tokio::task::spawn_blocking(move || backend::arp_blocking(ip))
        .await
        .ok()
        .flatten()
        .filter(|m| m.iter().any(|b| *b != 0))
        .map(fmt_mac)
}

/// Hosts in the system ARP table; `None` if it cannot be read.
pub fn neighbor_count() -> Option<usize> {
    backend::neighbors().map(|t| t.len())
}

/// System IPv4 ARP table (without state): used by Neighbours as a fallback.
pub fn neighbors_v4() -> Option<HashMap<Ipv4Addr, [u8; 6]>> {
    backend::neighbors()
}

type Neighbors = Arc<HashMap<Ipv4Addr, [u8; 6]>>;

/// System ARP table for a scan: after a ping the system has already
/// resolved the address (even if the host does not answer ping), so it is enough to
/// read the table, once for all the addresses, instead of querying
/// the network host by host. The reading is reused for a short interval.
pub struct ArpTable {
    read: fn() -> Option<HashMap<Ipv4Addr, [u8; 6]>>,
    snap: Mutex<Option<(Instant, Option<Neighbors>)>>,
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpTable {
    /// Validity of a reading.
    const FRESH: Duration = Duration::from_millis(150);

    pub fn new() -> Self {
        Self::with_reader(backend::neighbors)
    }

    fn with_reader(read: fn() -> Option<HashMap<Ipv4Addr, [u8; 6]>>) -> Self {
        ArpTable {
            read,
            snap: Mutex::new(None),
        }
    }

    /// Table read no more than `FRESH` ago; `None` if the system does not provide it.
    fn table(&self) -> Option<Neighbors> {
        let mut snap = self.snap.lock().ok()?;
        match snap.as_ref() {
            Some((at, t)) if at.elapsed() < Self::FRESH => t.clone(),
            _ => {
                let t = (self.read)().map(Arc::new);
                *snap = Some((Instant::now(), t.clone()));
                t
            }
        }
    }

    /// MAC of `ip`, formatted aa:bb:cc:dd:ee:ff. `replied` = the host has just
    /// answered the ping.
    ///
    /// A host that answered but is not in the reading at hand (read a moment
    /// earlier, or it is this PC, which is not in its own neighbour table) is
    /// asked to `arp`: on Windows that is `SendARP`, which answers at once for a present
    /// host; on Linux the table is read again once. If the table is not
    /// available `arp` is used for everyone, as in previous versions.
    pub async fn mac(&self, ip: Ipv4Addr, replied: bool) -> Option<String> {
        let Some(t) = self.table() else {
            return if ARP_ACTIVE { arp(ip).await } else { None };
        };
        if let Some(m) = t.get(&ip) {
            return Some(fmt_mac(*m));
        }
        if !replied {
            return None;
        }
        if ARP_ACTIVE {
            return arp(ip).await;
        }
        tokio::time::sleep(Self::FRESH + Duration::from_millis(50)).await;
        self.table()?.get(&ip).copied().map(fmt_mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn una_voce() -> Option<HashMap<Ipv4Addr, [u8; 6]>> {
        Some(HashMap::from([(
            Ipv4Addr::new(192, 0, 2, 9),
            [0x3c, 0x52, 0x82, 1, 2, 3],
        )]))
    }

    #[tokio::test]
    async fn mac_dalla_tabella() {
        let t = ArpTable::with_reader(una_voce);
        assert_eq!(
            t.mac(Ipv4Addr::new(192, 0, 2, 9), false).await.as_deref(),
            Some("3c:52:82:01:02:03")
        );
        // absent and no ping reply: no waiting
        let t0 = Instant::now();
        assert_eq!(t.mac(Ipv4Addr::new(192, 0, 2, 10), false).await, None);
        assert!(t0.elapsed() < Duration::from_millis(100));
    }

    /// Linux: a host that answered the ping but is not in the table makes the
    /// table be read again once, then it gives up (on Windows SendARP is asked).
    #[cfg(not(windows))]
    #[tokio::test]
    async fn mac_riletto_dopo_la_risposta() {
        let t = ArpTable::with_reader(una_voce);
        let t0 = Instant::now();
        assert_eq!(t.mac(Ipv4Addr::new(192, 0, 2, 10), true).await, None);
        assert!(t0.elapsed() >= ArpTable::FRESH);
    }

    /// Table not available: on Linux no MAC (on Windows SendARP would be used).
    #[cfg(not(windows))]
    #[tokio::test]
    async fn tabella_non_disponibile() {
        let t = ArpTable::with_reader(|| None);
        assert_eq!(t.mac(Ipv4Addr::new(192, 0, 2, 9), true).await, None);
    }

    /// Without the asynchronous engine the scan echo is the normal one.
    #[tokio::test]
    async fn echo_delle_scansioni() {
        let e = echo_scan(Ipv4Addr::LOCALHOST, 64, 1000).await;
        assert!(
            matches!(e.status, Status::Reply | Status::Error(_)),
            "{e:?}"
        );
        assert!(scan_parallelism() >= 256);
    }
}
