//! Neighbours on Windows: ARP and NDP table with `GetIpNetTable2(AF_UNSPEC)`, IPv6
//! routes announced by routers with `GetIpForwardTable2`, adapter names with
//! `GetIfEntry2`, echo to `ff02::1` with `Icmp6SendEcho2`.
//!
//! Paths: if the unified table cannot be read it falls back to the IPv4-only table
//! already tested (`icmp::neighbors_v4`) and `source` says so; routes and adapters
//! that cannot be read become a note, not an error.

use super::{NState, ProbeInfo, Raw, RawNeighbor, RawRoute6};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceTable, GetIpNetTable2,
    Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, ICMPV6_ECHO_REPLY_LH, MIB_IF_ROW2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE,
    MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    NlnsDelay, NlnsIncomplete, NlnsPermanent, NlnsProbe, NlnsReachable, NlnsStale, AF_INET,
    AF_INET6, AF_UNSPEC, SOCKADDR_IN6, SOCKADDR_INET,
};

/// `NlroRouterAdvertisement` (NL_ROUTE_ORIGIN).
const ORIGIN_RA: i32 = 3;
const IF_OPER_UP: i32 = 1;
const IF_TYPE_LOOPBACK: u32 = 24;
const IF_TYPE_TUNNEL: u32 = 131;

fn wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end]).trim().to_string()
}

fn state_of(s: i32) -> NState {
    match s {
        x if x == NlnsReachable => NState::Reachable,
        x if x == NlnsStale => NState::Stale,
        x if x == NlnsDelay => NState::Delay,
        x if x == NlnsProbe => NState::Probe,
        x if x == NlnsPermanent => NState::Permanent,
        x if x == NlnsIncomplete => NState::Incomplete,
        _ => NState::Unreachable,
    }
}

unsafe fn sockaddr(a: &SOCKADDR_INET) -> Option<IpAddr> {
    if a.si_family == AF_INET {
        Some(IpAddr::V4(Ipv4Addr::from(
            a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
        )))
    } else if a.si_family == AF_INET6 {
        Some(IpAddr::V6(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte)))
    } else {
        None
    }
}

/// Name ("Ethernet", "Wi-Fi") and type of an adapter.
fn iface_info(index: u32) -> Option<(String, u32, bool)> {
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = index;
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return None;
    }
    Some((wide(&row.Alias), row.Type, row.OperStatus == IF_OPER_UP))
}

fn neighbors_all() -> Option<Vec<RawNeighbor>> {
    unsafe {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        if GetIpNetTable2(AF_UNSPEC, &mut table) != 0 || table.is_null() {
            return None;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table) as *const MIB_IPNET_ROW2,
            n,
        );
        let mut out = Vec::with_capacity(n);
        for r in rows {
            let Some(ip) = sockaddr(&r.Address) else {
                continue;
            };
            let mac = (r.PhysicalAddressLength == 6).then(|| {
                let mut m = [0u8; 6];
                m.copy_from_slice(&r.PhysicalAddress[..6]);
                m
            });
            out.push(RawNeighbor {
                ip,
                mac,
                state: state_of(r.State),
                iface: r.InterfaceIndex,
                // IsRouter is the first bit of the flags
                is_router: r.Anonymous.Flags & 1 != 0,
            });
        }
        FreeMibTable(table as *const c_void);
        Some(out)
    }
}

fn routes6() -> Option<Vec<RawRoute6>> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET6, &mut table) != 0 || table.is_null() {
            return None;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table) as *const MIB_IPFORWARD_ROW2,
            n,
        );
        let mut out = vec![];
        for r in rows {
            let (Some(IpAddr::V6(prefix)), Some(IpAddr::V6(next_hop))) =
                (sockaddr(&r.DestinationPrefix.Prefix), sockaddr(&r.NextHop))
            else {
                continue;
            };
            out.push(RawRoute6 {
                prefix,
                len: r.DestinationPrefix.PrefixLength,
                next_hop,
                iface: r.InterfaceIndex,
                valid_s: (r.ValidLifetime != u32::MAX).then_some(r.ValidLifetime),
                from_ra: r.Origin == ORIGIN_RA,
            });
        }
        FreeMibTable(table as *const c_void);
        Some(out)
    }
}

pub fn read() -> Option<Raw> {
    let mut raw = Raw::default();
    match neighbors_all() {
        Some(n) => {
            raw.neighbors = n;
            raw.source = "ip-helper";
        }
        None => {
            // fallback: the IPv4-only table already tested
            let t = crate::icmp::neighbors_v4()?;
            raw.neighbors = t
                .into_iter()
                .map(|(ip, mac)| RawNeighbor {
                    ip: IpAddr::V4(ip),
                    mac: Some(mac),
                    state: NState::Reachable,
                    iface: 0,
                    is_router: false,
                })
                .collect();
            raw.source = "ripiego-ipv4";
            raw.notes.push(
                crate::t!(
                    "GetIpNetTable2 non ha risposto: letta la sola tabella ARP IPv4 (niente IPv6).",
                    "GetIpNetTable2 did not respond: only the IPv4 ARP table was read (no IPv6)."
                )
                .into(),
            );
        }
    }
    match routes6() {
        Some(r) => raw.routes6 = r,
        None => raw.notes.push(
            crate::t!(
                "Route IPv6 non leggibili: router e prefissi non disponibili.",
                "IPv6 routes cannot be read: routers and prefixes not available."
            )
            .into(),
        ),
    }
    let mut seen: Vec<u32> = raw.neighbors.iter().map(|n| n.iface).collect();
    seen.extend(raw.routes6.iter().map(|r| r.iface));
    seen.sort_unstable();
    seen.dedup();
    for i in seen {
        if let Some((name, _, _)) = iface_info(i) {
            if !name.is_empty() {
                raw.ifaces.insert(i, name);
            }
        }
    }
    Some(raw)
}

/// Active adapters with IPv6 that are neither loopback nor tunnel.
fn ipv6_ifaces() -> Vec<u32> {
    let mut out = vec![];
    unsafe {
        let mut table: *mut MIB_IPINTERFACE_TABLE = std::ptr::null_mut();
        if GetIpInterfaceTable(AF_INET6, &mut table) != 0 || table.is_null() {
            return out;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table) as *const MIB_IPINTERFACE_ROW,
            n,
        );
        for r in rows {
            if let Some((_, ty, up)) = iface_info(r.InterfaceIndex) {
                if up
                    && ty != IF_TYPE_LOOPBACK
                    && ty != IF_TYPE_TUNNEL
                    && !out.contains(&r.InterfaceIndex)
                {
                    out.push(r.InterfaceIndex);
                }
            }
        }
        FreeMibTable(table as *const c_void);
    }
    out
}

/// One echo to `ff02::1` (all nodes on the link) on every adapter with IPv6.
/// `Icmp6SendEcho2` returns the replies Windows delivers (usually one);
/// the neighbours that answer then appear in the NDP table, which is re-read afterwards.
pub fn probe() -> ProbeInfo {
    let ifaces = ipv6_ifaces();
    if ifaces.is_empty() {
        return ProbeInfo {
            note: crate::t!(
                "nessuna scheda attiva con IPv6",
                "no active adapter with IPv6"
            )
            .into(),
            ..ProbeInfo::default()
        };
    }
    let h: HANDLE = unsafe { Icmp6CreateFile() };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return ProbeInfo {
            note: crate::t!(
                "impossibile aprire l'ICMPv6 su questo sistema (percorso: non disponibile)",
                "cannot open ICMPv6 on this system (path: not available)"
            )
            .into(),
            ..ProbeInfo::default()
        };
    }
    let mut info = ProbeInfo {
        note: crate::t!("percorso: Icmp6SendEcho2", "path: Icmp6SendEcho2").into(),
        ..ProbeInfo::default()
    };
    let payload = [0x61u8; 32];
    for idx in ifaces {
        let mut dst: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        dst.sin6_family = AF_INET6;
        dst.sin6_addr.u.Byte = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets();
        dst.Anonymous.sin6_scope_id = idx;
        let mut src: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        src.sin6_family = AF_INET6;
        let mut buf = vec![0u64; 128]; // 1 KB aligned
        let n = unsafe {
            Icmp6SendEcho2(
                h,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &src,
                &dst,
                payload.as_ptr() as *const c_void,
                payload.len() as u16,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * 8) as u32,
                1000,
            )
        };
        info.ifaces += 1;
        let max = (n as usize).min(8);
        let replies = buf.as_ptr() as *const ICMPV6_ECHO_REPLY_LH;
        for i in 0..max {
            let r = unsafe { &*replies.add(i) };
            if r.Status != 0 {
                continue;
            }
            let a = Ipv6Addr::from(r.Address.sin6_addr);
            let s = a.to_string();
            if !info.replies.contains(&s) {
                info.replies.push(s);
            }
        }
    }
    unsafe { IcmpCloseHandle(h) };
    info
}
