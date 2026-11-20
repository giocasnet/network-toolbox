//! Linux backend (development and tests): system `ping` and kernel ARP table.

use super::{Echo, EchoOpts, Status};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Instant;

pub fn echo_blocking(dest: Ipv4Addr, o: EchoOpts, timeout_ms: u32) -> Echo {
    let secs = timeout_ms.div_ceil(1000).max(1).to_string();
    let t0 = Instant::now();
    let mut cmd = Command::new("ping");
    cmd.args([
        "-n",
        "-c",
        "1",
        "-W",
        &secs,
        "-t",
        &o.ttl.to_string(),
        "-s",
        &o.size.to_string(),
    ]);
    if o.dont_fragment {
        cmd.args(["-M", "do"]);
    }
    let out = cmd.arg(dest.to_string()).output();
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
    match out {
        Ok(o) => {
            // "message too long" (local MTU) is written on stderr
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            parse_ping(&text, elapsed)
        }
        Err(_) => Echo {
            status: Status::Error(2),
            from: None,
            rtt_ms: 0.0,
            ttl: None,
        },
    }
}

/// Parses the iputils-ping output for a single packet.
pub(crate) fn parse_ping(out: &str, elapsed_ms: f64) -> Echo {
    for line in out.lines() {
        if line.contains("message too long") {
            return Echo {
                status: Status::TooBig,
                from: None,
                rtt_ms: elapsed_ms,
                ttl: None,
            };
        }
        if let Some(rest) = line.split(" bytes from ").nth(1) {
            let from = rest.split(':').next().and_then(|s| s.trim().parse().ok());
            let ttl = field(line, "ttl=").and_then(|v| v.parse().ok());
            let rtt = field(line, "time=")
                .and_then(|v| v.parse().ok())
                .unwrap_or(elapsed_ms);
            return Echo {
                status: Status::Reply,
                from,
                rtt_ms: rtt,
                ttl,
            };
        }
        if let Some(rest) = line.strip_prefix("From ") {
            let from = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.trim_end_matches(':').parse().ok());
            let status = if line.contains("Time to live exceeded") {
                Status::TtlExpired
            } else if line.contains("Frag needed") {
                Status::TooBig
            } else {
                Status::Unreachable
            };
            return Echo {
                status,
                from,
                rtt_ms: elapsed_ms,
                ttl: None,
            };
        }
    }
    Echo::timeout()
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(key).nth(1)?.split_whitespace().next()
}

/// Complete rows (flag 0x2) of `/proc/net/arp`: IPv4 → MAC.
pub(crate) fn parse_arp_table(table: &str) -> HashMap<Ipv4Addr, [u8; 6]> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() < 4 || p[2] != "0x2" {
                return None;
            }
            let b: Vec<u8> = p[3]
                .split(':')
                .filter_map(|x| u8::from_str_radix(x, 16).ok())
                .collect();
            Some((p[0].parse().ok()?, b.try_into().ok()?))
        })
        .collect()
}

/// Kernel ARP cache. `None` if it cannot be read.
pub fn neighbors() -> Option<HashMap<Ipv4Addr, [u8; 6]>> {
    std::fs::read_to_string("/proc/net/arp")
        .ok()
        .map(|t| parse_arp_table(&t))
}

pub fn arp_blocking(ip: Ipv4Addr) -> Option<[u8; 6]> {
    neighbors()?.get(&ip).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risposta() {
        let e = parse_ping("PING 172.16.24.1 (172.16.24.1) 56(84) bytes of data.\n64 bytes from 172.16.24.1: icmp_seq=1 ttl=255 time=0.412 ms\n", 1.0);
        assert_eq!(e.status, Status::Reply);
        assert_eq!(e.from, Some(Ipv4Addr::new(10, 1, 24, 1)));
        assert_eq!(e.ttl, Some(255));
        assert!((e.rtt_ms - 0.412).abs() < 1e-9);
    }

    #[test]
    fn ttl_scaduto() {
        let e = parse_ping("From 172.16.24.1 icmp_seq=1 Time to live exceeded\n", 3.0);
        assert_eq!(e.status, Status::TtlExpired);
        assert_eq!(e.from, Some(Ipv4Addr::new(10, 1, 24, 1)));
    }

    #[test]
    fn tabella_arp() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 192.0.2.1        0x1         0x2         00:50:56:aa:bb:01     *        eth0\n\
                 192.0.2.7        0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                 192.0.2.9        0x1         0x2         3c:52:82:01:02:03     *        eth0\n";
        let m = parse_arp_table(t);
        assert_eq!(m.len(), 2); // the incomplete row (0x0) does not count
        assert_eq!(
            m[&Ipv4Addr::new(192, 0, 2, 9)],
            [0x3c, 0x52, 0x82, 0x01, 0x02, 0x03]
        );
        assert!(!m.contains_key(&Ipv4Addr::new(192, 0, 2, 7)));
    }

    #[test]
    fn nessuna_risposta() {
        assert_eq!(
            parse_ping(
                "1 packets transmitted, 0 received, 100% packet loss\n",
                2000.0
            )
            .status,
            Status::Timeout
        );
    }
}
