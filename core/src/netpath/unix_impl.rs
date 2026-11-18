//! Default route on Linux from /proc/net/route (development and tests only).

use super::{classify, Route};
use std::net::Ipv4Addr;

/// (adapter, gateway) of the default route; gateway 0 = none.
pub fn parse_proc_route(text: &str) -> Option<(String, Option<Ipv4Addr>)> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            return None;
        }
        let g = u32::from_str_radix(f[2], 16).ok()?;
        let gw = Ipv4Addr::from(g.to_le_bytes());
        Some((f[0].to_string(), (!gw.is_unspecified()).then_some(gw)))
    })
}

pub fn default_route() -> Option<Route> {
    let (name, gateway) = parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?)?;
    let wireless = std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists();
    let tunnel = ["tun", "tap", "wg", "ppp"]
        .iter()
        .any(|p| name.starts_with(p));
    let kind = if tunnel {
        "vpn"
    } else if wireless {
        "wifi"
    } else {
        classify(6, &name, "")
    };
    Some(Route {
        gateway,
        if_name: name,
        if_descr: String::new(),
        kind,
    })
}
