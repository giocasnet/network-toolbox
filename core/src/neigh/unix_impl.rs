//! Linux backend (development and tests): only the kernel ARP table.

use super::{NState, ProbeInfo, Raw, RawNeighbor};
use std::net::IpAddr;

pub fn read() -> Option<Raw> {
    let t = crate::icmp::neighbors_v4()?;
    let mut neighbors: Vec<RawNeighbor> = t
        .into_iter()
        .map(|(ip, mac)| RawNeighbor {
            ip: IpAddr::V4(ip),
            mac: Some(mac),
            state: NState::Reachable,
            iface: 0,
            is_router: false,
        })
        .collect();
    neighbors.sort_by_key(|n| n.ip);
    Some(Raw {
        neighbors,
        source: "linux-arp",
        notes: vec![crate::t!(
            "Su Linux si legge solo la tabella ARP IPv4.",
            "On Linux only the IPv4 ARP table is read."
        )
        .into()],
        ..Raw::default()
    })
}

pub fn probe() -> ProbeInfo {
    ProbeInfo {
        note: crate::t!(
            "L'echo a ff02::1 è disponibile solo su Windows.",
            "The ff02::1 echo is only available on Windows."
        )
        .into(),
        ..ProbeInfo::default()
    }
}
