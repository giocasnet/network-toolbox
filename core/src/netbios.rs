//! NetBIOS name of a host (NBSTAT query, UDP 137). Fallback when the PTR
//! record is missing: Windows workstations answer with their own name.

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// NBSTAT query for the name "*": header + encoded name + type 0x21, class IN.
pub fn query_packet(id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    p.push(0x20);
    p.extend_from_slice(b"CK"); // '*' in first-level encoding
    p.extend(std::iter::repeat_n(b'A', 30)); // 15 null bytes
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
    p
}

/// Extracts the workstation name (suffix 0x00, unique name) from the response.
pub fn parse_response(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 || u16::from_be_bytes([buf[6], buf[7]]) == 0 {
        return None;
    }
    // Skip the name in the response (labels or compression pointer)
    let mut i = 12;
    loop {
        let len = *buf.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            i += 2;
            break;
        }
        i += 1 + len;
    }
    i += 2 + 2 + 4 + 2; // type, class, TTL, data length
    let count = *buf.get(i)? as usize;
    i += 1;
    for _ in 0..count {
        let entry = buf.get(i..i + 18)?;
        i += 18;
        let name = String::from_utf8_lossy(&entry[..15])
            .trim_end_matches([' ', '\0'])
            .to_string();
        let suffix = entry[15];
        let group = entry[16] & 0x80 != 0;
        if name.is_empty() || suffix != 0x00 {
            continue;
        }
        // Group names are the domain or workgroup: they do not identify the host
        if !group {
            return Some(name);
        }
    }
    None
}

pub async fn name(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let id = (u32::from(ip) as u16) ^ 0x4e54;
    sock.send_to(&query_packet(id), (ip, 137)).await.ok()?;
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n < 2 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    parse_response(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.push(suffix);
        e.extend_from_slice(&flags.to_be_bytes());
        e
    }

    fn response(entries: &[Vec<u8>], compressed: bool) -> Vec<u8> {
        let mut r = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        if compressed {
            r.extend_from_slice(&[0xC0, 0x0C]);
        } else {
            r.push(0x20);
            r.extend_from_slice(b"CK");
            r.extend(std::iter::repeat_n(b'A', 30));
            r.push(0);
        }
        r.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]);
        let data_len = 1 + entries.len() * 18 + 6;
        r.extend_from_slice(&(data_len as u16).to_be_bytes());
        r.push(entries.len() as u8);
        for e in entries {
            r.extend_from_slice(e);
        }
        r.extend_from_slice(&[0xd8, 0xbb, 0xc1, 0x0a, 0x11, 0x22]);
        r
    }

    #[test]
    fn pacchetto() {
        let p = query_packet(0x1234);
        assert_eq!(p.len(), 50);
        assert_eq!(&p[..2], &[0x12, 0x34]);
        assert_eq!(&p[13..15], b"CK");
    }

    #[test]
    fn nome_workstation() {
        let entries = [
            entry("DOMINIO", 0x00, 0x8400), // group (domain)
            entry("PC-TECNICO02", 0x20, 0x0400),
            entry("PC-TECNICO02", 0x00, 0x0400),
        ];
        assert_eq!(
            parse_response(&response(&entries, false)).as_deref(),
            Some("PC-TECNICO02")
        );
        assert_eq!(
            parse_response(&response(&entries, true)).as_deref(),
            Some("PC-TECNICO02")
        );
    }

    #[test]
    fn solo_gruppo_o_vuota() {
        assert_eq!(
            parse_response(&response(&[entry("DOMINIO", 0x00, 0x8400)], false)),
            None
        );
        assert_eq!(parse_response(&[0u8; 5]), None);
    }
}
