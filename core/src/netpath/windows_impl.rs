//! Default route on Windows: GetBestRoute towards 1.1.1.1, then GetIfEntry2 for the
//! adapter's name, description and type.

use super::{classify, Route};
use std::net::Ipv4Addr;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetBestRoute, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARDROW,
};

fn wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end]).trim().to_string()
}

pub fn default_route() -> Option<Route> {
    // IPv4 addresses in the IP Helper APIs are in network order (as in IN_ADDR)
    let dest = u32::from_ne_bytes([1, 1, 1, 1]);
    let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    if unsafe { GetBestRoute(dest, 0, &mut row) } != 0 {
        return None;
    }
    let hop = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
    let gateway = (!hop.is_unspecified() && hop != Ipv4Addr::new(1, 1, 1, 1)).then_some(hop);

    let mut ifr: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    ifr.InterfaceIndex = row.dwForwardIfIndex;
    let (name, descr, if_type) = if unsafe { GetIfEntry2(&mut ifr) } == 0 {
        (wide(&ifr.Alias), wide(&ifr.Description), ifr.Type)
    } else {
        (String::new(), String::new(), 0)
    };
    Some(Route {
        gateway,
        kind: classify(if_type, &name, &descr),
        if_name: name,
        if_descr: descr,
    })
}
