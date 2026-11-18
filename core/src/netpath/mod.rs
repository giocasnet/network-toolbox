//! Network path of this PC for the home screen: adapter with the default
//! route (cable, Wi-Fi or VPN), gateway with name and latency.

use crate::icmp;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl;

#[cfg(not(windows))]
mod unix_impl;

#[cfg(not(windows))]
use unix_impl as backend;
#[cfg(windows)]
use windows_impl as backend;

/// Default route: gateway (absent if the destination is on the same network)
/// and adapter used.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub gateway: Option<Ipv4Addr>,
    /// Adapter name ("Ethernet", "Wi-Fi", "eth0").
    pub if_name: String,
    /// Driver description (Windows only).
    pub if_descr: String,
    /// cable, wifi, vpn, other
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetPath {
    pub local_ip: Option<String>,
    pub if_name: String,
    pub if_descr: String,
    pub kind: &'static str,
    pub gateway: Option<String>,
    pub gateway_name: String,
    pub gateway_rtt_ms: Option<f64>,
}

/// Adapter type from the IANA type (ifType) and the description.
pub fn classify(if_type: u32, name: &str, descr: &str) -> &'static str {
    let t = format!("{name} {descr}").to_lowercase();
    const VPN: [&str; 10] = [
        "vpn",
        "fortinet",
        "forticlient",
        "wireguard",
        "openvpn",
        "tap-windows",
        "anyconnect",
        "globalprotect",
        "wintun",
        "zerotier",
    ];
    // 23 PPP, 53 proprietary virtual, 131 tunnel
    if matches!(if_type, 23 | 53 | 131) || VPN.iter().any(|w| t.contains(w)) {
        "vpn"
    } else if if_type == 71 || t.contains("wi-fi") || t.contains("wireless") || t.contains("wlan") {
        "wifi"
    } else if if_type == 6 {
        "cable"
    } else {
        "other"
    }
}

pub fn default_route() -> Option<Route> {
    backend::default_route()
}

/// Gateway names already resolved (they only change with the network).
static NAMES: Mutex<Option<HashMap<Ipv4Addr, String>>> = Mutex::new(None);

async fn gateway_name(ip: Ipv4Addr) -> String {
    if let Some(n) = NAMES
        .lock()
        .ok()
        .and_then(|m| m.as_ref()?.get(&ip).cloned())
    {
        return n;
    }
    let n = crate::net::name_of(ip, Duration::from_millis(1500)).await;
    if let Ok(mut m) = NAMES.lock() {
        m.get_or_insert_with(HashMap::new).insert(ip, n.clone());
    }
    n
}

pub async fn path() -> NetPath {
    let route = tokio::task::spawn_blocking(default_route)
        .await
        .ok()
        .flatten();
    let local_ip = crate::online::local_ip().map(|i| i.to_string());
    let mut p = NetPath {
        local_ip,
        if_name: String::new(),
        if_descr: String::new(),
        kind: "other",
        gateway: None,
        gateway_name: String::new(),
        gateway_rtt_ms: None,
    };
    let Some(r) = route else { return p };
    p.if_name = r.if_name;
    p.if_descr = r.if_descr;
    p.kind = r.kind;
    if let Some(gw) = r.gateway {
        let (echo, name) = tokio::join!(icmp::echo(gw, 128, 1000), gateway_name(gw));
        p.gateway = Some(gw.to_string());
        p.gateway_name = name;
        if echo.status == icmp::Status::Reply {
            p.gateway_rtt_ms = Some((echo.rtt_ms * 10.0).round() / 10.0);
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tipi_di_scheda() {
        assert_eq!(
            classify(6, "Ethernet", "Intel(R) Ethernet Connection I219-LM"),
            "cable"
        );
        assert_eq!(
            classify(71, "Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz"),
            "wifi"
        );
        assert_eq!(
            classify(6, "Ethernet 3", "Fortinet SSL VPN Virtual Ethernet Adapter"),
            "vpn"
        );
        assert_eq!(
            classify(53, "Local Area Connection", "TAP-Windows Adapter V9"),
            "vpn"
        );
        assert_eq!(classify(0, "wlan0", ""), "wifi");
        assert_eq!(classify(0, "wg0", "wireguard"), "vpn");
        assert_eq!(classify(24, "Loopback", ""), "other");
    }

    // unix_impl exists only outside Windows
    #[cfg(not(windows))]
    #[test]
    fn route_linux() {
        let t =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                 eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                 eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            unix_impl::parse_proc_route(t),
            Some(("eth0".to_string(), Some(Ipv4Addr::new(192, 168, 1, 1))))
        );
        assert_eq!(unix_impl::parse_proc_route("Iface\tDestination\n"), None);
    }
}
