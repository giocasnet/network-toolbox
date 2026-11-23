//! Shared helpers for the multicast discovery tools (Bonjour, UPnP).
//!
//! Both protocols send one query per IPv4 adapter and collect the unicast
//! replies: every socket is bound to the adapter's address, so the system sends
//! the multicast packet out of that adapter and the replies come back to it.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::UdpSocket;

/// IPv4 addresses of the adapters to query: not loopback, not link-local
/// (an adapter without a network gets 169.254.x.x), no duplicates.
pub fn local_v4() -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) if !a.ip.is_loopback() && !a.ip.is_link_local() => Some(a.ip),
            _ => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// UDP socket bound to `local` on an ephemeral port. With `multicast` the
/// outgoing multicast interface is `local` too (TTL 255, as mDNS requires).
pub fn open(local: Ipv4Addr, multicast: bool) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.bind(&SocketAddrV4::new(local, 0).into())?;
    if multicast {
        s.set_multicast_if_v4(&local)?;
        s.set_multicast_ttl_v4(255)?;
    }
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

/// CSV field with `;` separator (same convention as the other tools).
pub fn csv_field(s: &str) -> String {
    if s.contains([';', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
