//! Internet connectivity: a ping to well-known public destinations.
//! A single reply is enough to consider the Internet reachable.

use crate::icmp::{self, Echo, Status};
use serde::Serialize;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Destinations tried in order: Cloudflare, then Google.
pub const TARGETS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
pub const TIMEOUT_MS: u32 = 2000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OnlineStatus {
    pub online: bool,
    /// Destination that replied.
    pub target: Option<String>,
    pub rtt_ms: Option<f64>,
    /// IPv4 of this PC towards the network (adapter with the default route).
    pub local_ip: Option<String>,
}

/// IPv4 of the adapter that goes out to the Internet: a UDP socket "connected" to a
/// public IP makes the system pick the default route, without sending anything.
/// If there is no default route, the first non-loopback IPv4.
pub fn local_ip() -> Option<Ipv4Addr> {
    let routed = UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
        s.connect((TARGETS[0], 53)).ok()?;
        match s.local_addr().ok()?.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
            _ => None,
        }
    });
    routed.or_else(|| {
        if_addrs::get_if_addrs()
            .ok()?
            .into_iter()
            .find_map(|i| match i.ip() {
                IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() => Some(ip),
                _ => None,
            })
    })
}

/// Tries the destinations in order with the given echo function.
pub async fn check_with<F, Fut>(targets: &[Ipv4Addr], mut echo: F) -> OnlineStatus
where
    F: FnMut(Ipv4Addr) -> Fut,
    Fut: Future<Output = Echo>,
{
    for ip in targets {
        let e = echo(*ip).await;
        if e.status == Status::Reply {
            return OnlineStatus {
                online: true,
                target: Some(ip.to_string()),
                rtt_ms: Some((e.rtt_ms * 10.0).round() / 10.0),
                local_ip: None,
            };
        }
    }
    OnlineStatus {
        online: false,
        target: None,
        rtt_ms: None,
        local_ip: None,
    }
}

pub async fn check() -> OnlineStatus {
    let mut s = check_with(&TARGETS, |ip| icmp::echo(ip, 128, TIMEOUT_MS)).await;
    s.local_ip = local_ip().map(|ip| ip.to_string());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(rtt: f64) -> Echo {
        Echo {
            status: Status::Reply,
            from: None,
            rtt_ms: rtt,
            ttl: Some(57),
        }
    }

    #[test]
    fn ip_locale() {
        if let Some(ip) = local_ip() {
            assert!(!ip.is_loopback() && !ip.is_unspecified(), "{ip}");
        }
    }

    #[tokio::test]
    async fn primo_risponde() {
        let s = check_with(&TARGETS, |_| async { reply(12.34) }).await;
        assert_eq!(s.target.as_deref(), Some("1.1.1.1"));
        assert_eq!(s.rtt_ms, Some(12.3));
        assert!(s.online);
    }

    #[tokio::test]
    async fn passa_al_secondo() {
        let s = check_with(&TARGETS, |ip| async move {
            if ip == TARGETS[0] {
                Echo::timeout()
            } else {
                reply(20.0)
            }
        })
        .await;
        assert_eq!(s.target.as_deref(), Some("8.8.8.8"));
    }

    #[tokio::test]
    async fn nessuna_risposta() {
        let s = check_with(&TARGETS, |_| async {
            Echo {
                status: Status::Unreachable,
                from: Some(Ipv4Addr::new(192, 168, 7, 1)),
                rtt_ms: 1.0,
                ttl: None,
            }
        })
        .await;
        assert_eq!(
            s,
            OnlineStatus {
                online: false,
                target: None,
                rtt_ms: None,
                local_ip: None
            }
        );
    }
}
