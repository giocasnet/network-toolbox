//! Wake-on-LAN: magic packet (6 × 0xFF + 16 × MAC) via UDP broadcast.

use crate::{t, tf, util, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct WolReq {
    pub mac: String,
    #[serde(default)]
    pub broadcast: Option<String>,
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub port: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct WolResult {
    pub sent: u32,
    pub mac: String,
    pub broadcast: String,
    pub port: u16,
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let hex: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(t!(
            "MAC non valido (formato atteso: AA:BB:CC:DD:EE:FF)",
            "Invalid MAC (expected format: AA:BB:CC:DD:EE:FF)"
        )
        .into());
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(mac)
}

pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend_from_slice(&mac);
    }
    p
}

/// Broadcast address of every active IPv4 interface (loopback excluded).
fn interface_broadcasts() -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) if !a.ip.is_loopback() => a.broadcast,
            _ => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

pub async fn run(req: WolReq) -> Result<WolResult> {
    let mac = parse_mac(&req.mac)?;
    let port = req.port.unwrap_or(9);
    if port != 7 && port != 9 {
        return Err(t!("Porta WoL: 7 oppure 9", "WoL port: 7 or 9").into());
    }
    let raw = req
        .broadcast
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("255.255.255.255");
    let bcast: Ipv4Addr = raw.parse().map_err(|_| {
        t!(
            "Indirizzo di broadcast non valido",
            "Invalid broadcast address"
        )
        .to_string()
    })?;
    if bcast.is_loopback() || bcast.is_unspecified() || bcast.is_multicast() {
        return Err(t!(
            "Indirizzo di broadcast non consentito",
            "Broadcast address not allowed"
        )
        .into());
    }

    // With several network adapters, 255.255.255.255 leaves from a single interface:
    // we also send to each interface's broadcast, so it reaches all of them.
    let mut targets = vec![bcast];
    if bcast.is_broadcast() {
        targets.extend(interface_broadcasts());
    }

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| tf!("Socket UDP: {e}", "UDP socket: {e}"))?;
    sock.set_broadcast(true).map_err(|e| {
        tf!(
            "Broadcast non consentito: {e}",
            "Broadcast not allowed: {e}"
        )
    })?;
    let packet = magic_packet(mac);
    let mut sent = 0;
    for round in 0..3 {
        for t in &targets {
            if sock.send_to(&packet, (*t, port as u16)).await.is_ok() {
                sent += 1;
            }
        }
        if round < 2 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    if sent == 0 {
        return Err(t!(
            "Invio non riuscito su nessuna interfaccia",
            "Send failed on every interface"
        )
        .into());
    }
    Ok(WolResult {
        sent,
        mac: mac
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        broadcast: targets
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        port: port as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac() {
        let m = [0xd8, 0xbb, 0xc1, 0x0a, 0x11, 0x22];
        assert_eq!(parse_mac("D8:BB:C1:0A:11:22").unwrap(), m);
        assert_eq!(parse_mac("d8-bb-c1-0a-11-22").unwrap(), m);
        assert_eq!(parse_mac("d8bb.c10a.1122").unwrap(), m);
        assert!(parse_mac("zz").is_err());
        assert!(parse_mac("d8:bb:c1:0a:11").is_err());
    }

    #[test]
    fn pacchetto() {
        let p = magic_packet([1, 2, 3, 4, 5, 6]);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[96..], &[1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn validazione() {
        let r = |mac: &str, b: Option<&str>, p: Option<u32>| {
            run(WolReq {
                mac: mac.into(),
                broadcast: b.map(Into::into),
                port: p,
            })
        };
        assert!(r("zz", None, None).await.is_err());
        assert!(r("001122334455", Some("127.0.0.1"), None).await.is_err());
        assert!(r("001122334455", None, Some(80)).await.is_err());
    }

    #[tokio::test]
    async fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let run = |mac: &str, b: Option<&str>, p: Option<u32>| {
            run(WolReq {
                mac: mac.into(),
                broadcast: b.map(Into::into),
                port: p,
            })
        };
        let e = run("zz", None, None).await.unwrap_err();
        assert!(
            e.starts_with("Invalid MAC") && !e.contains("non valido"),
            "{e}"
        );
        assert_eq!(
            run("001122334455", None, Some(80)).await.unwrap_err(),
            "WoL port: 7 or 9"
        );
        assert_eq!(
            run("001122334455", Some("127.0.0.1"), None)
                .await
                .unwrap_err(),
            "Broadcast address not allowed"
        );
    }
}
