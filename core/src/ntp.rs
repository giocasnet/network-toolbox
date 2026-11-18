//! SNTP client (RFC 4330): stratum, offset from the PC clock,
//! network delay and server fields.

use crate::{net, t, tf, util, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
const NTP_UNIX_DELTA: f64 = 2_208_988_800.0;

#[derive(Debug, Deserialize)]
pub struct NtpReq {
    pub host: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct NtpResult {
    pub host: String,
    pub stratum: u8,
    pub offset_ms: f64,
    pub delay_ms: f64,
    pub precision: i8,
    pub ref_id: String,
    pub ntp_time: String,
    pub local_time: String,
    pub leap: String,
    pub poll_interval: u32,
    pub root_delay_ms: f64,
    pub root_disp_ms: f64,
}

fn ts(buf: &[u8], at: usize) -> f64 {
    let secs = u32::from_be_bytes(buf[at..at + 4].try_into().unwrap()) as f64;
    let frac = u32::from_be_bytes(buf[at + 4..at + 8].try_into().unwrap()) as f64 / 4_294_967_296.0;
    secs + frac - NTP_UNIX_DELTA
}

fn put_ts(buf: &mut [u8], at: usize, unix: f64) {
    let t = unix + NTP_UNIX_DELTA;
    let secs = t.floor();
    buf[at..at + 4].copy_from_slice(&(secs as u32).to_be_bytes());
    buf[at + 4..at + 8].copy_from_slice(&(((t - secs) * 4_294_967_296.0) as u32).to_be_bytes());
}

fn fixed16(buf: &[u8], at: usize) -> f64 {
    u32::from_be_bytes(buf[at..at + 4].try_into().unwrap()) as f64 / 65_536.0
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

pub fn request(t1: f64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 0b00_100_011; // LI 0, version 4, client mode
    put_ts(&mut p, 40, t1);
    // last 16 bits of the fraction are random (under 16 µs): the transmit timestamp, which the
    // server sends back as originate, becomes unpredictable for anyone trying to inject replies
    let mut r = [0u8; 2];
    if getrandom::getrandom(&mut r).is_ok() {
        p[46..48].copy_from_slice(&r);
    }
    p
}

/// The reply counts only if it comes from a server (mode 4) and its originate timestamp
/// is identical to the request's transmit timestamp (RFC 4330 §5).
pub fn matches(resp: &[u8], req: &[u8; 48]) -> bool {
    resp.len() >= 48 && resp[0] & 0x07 == 4 && resp[24..32] == req[40..48]
}

/// Parses the reply; t1 = send time, t4 = receive time (local clock, Unix seconds).
pub fn parse(host: &str, buf: &[u8], t1: f64, t4: f64) -> Result<NtpResult> {
    if buf.len() < 48 {
        return Err(t!("Risposta NTP troppo corta", "NTP response too short").into());
    }
    let mode = buf[0] & 0x07;
    if mode != 4 && mode != 5 {
        return Err(tf!(
            "Risposta NTP non valida (modalità {mode})",
            "Invalid NTP response (mode {mode})"
        ));
    }
    let stratum = buf[1];
    if stratum == 0 {
        let code = String::from_utf8_lossy(&buf[12..16])
            .trim_end_matches('\0')
            .to_string();
        return Err(tf!(
            "Il server ha rifiutato la richiesta (kiss-of-death {code})",
            "The server refused the request (kiss-of-death {code})"
        ));
    }
    let leap = match buf[0] >> 6 {
        0 => "no warning",
        1 => "last minute of the day has 61 seconds",
        2 => "last minute of the day has 59 seconds",
        _ => "unsynchronized",
    };
    let ref_id = if stratum == 1 {
        String::from_utf8_lossy(&buf[12..16])
            .trim_end_matches(['\0', ' '])
            .to_string()
    } else {
        Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]).to_string()
    };
    let t2 = ts(buf, 32);
    let t3 = ts(buf, 40);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);
    Ok(NtpResult {
        host: host.to_string(),
        stratum,
        offset_ms: round3(offset * 1000.0),
        delay_ms: round3(delay * 1000.0),
        precision: buf[3] as i8,
        ref_id,
        ntp_time: util::utc_ms(t3),
        local_time: util::utc_ms(t4),
        leap: leap.into(),
        poll_interval: 1u32 << buf[2].min(17),
        root_delay_ms: round3(fixed16(buf, 4) * 1000.0),
        root_disp_ms: round3(fixed16(buf, 8) * 1000.0),
    })
}

pub async fn query(host: &str, server: SocketAddr) -> Result<NtpResult> {
    let err = |e: std::io::Error| format!("NTP: {e}");
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(err)?;
    // Connected socket: the system drops packets not coming from the server's IP and port 123
    sock.connect(server).await.map_err(err)?;
    let t1 = util::now_unix();
    let req = request(t1);
    sock.send(&req).await.map_err(err)?;
    let mut buf = [0u8; 512];
    let recv = async {
        loop {
            let n = sock.recv(&mut buf).await?;
            if matches(&buf[..n], &req) {
                return Ok::<usize, std::io::Error>(n);
            }
        }
    };
    let n = tokio::time::timeout(Duration::from_secs(5), recv)
        .await
        .map_err(|_| {
            tf!(
                "Nessuna risposta da {host} (UDP 123)",
                "No response from {host} (UDP 123)"
            )
        })?
        .map_err(err)?;
    let t4 = util::now_unix();
    parse(host, &buf[..n], t1, t4)
}

pub async fn run(req: NtpReq) -> Result<NtpResult> {
    let host = net::clean_host(&req.host)?;
    let ip = net::resolve_v4(&host).await?;
    query(&host, SocketAddr::new(IpAddr::V4(ip), 123)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test NTP server, with its clock 250 ms ahead.
    #[tokio::test]
    async fn server_di_prova() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            let (_, from) = srv.recv_from(&mut buf).await.unwrap();
            let now = util::now_unix() + 0.250;
            let mut r = [0u8; 48];
            r[0] = 0b00_100_100; // version 4, server mode
            r[1] = 1;
            r[2] = 6;
            r[3] = (-23i8) as u8;
            r[12..16].copy_from_slice(b"CTD\0");
            r[24..32].copy_from_slice(&buf[40..48]); // origin = client's transmit
            put_ts(&mut r, 32, now);
            put_ts(&mut r, 40, now);
            srv.send_to(&r, from).await.unwrap();
        });
        let r = query("prova", addr).await.unwrap();
        assert_eq!(r.stratum, 1);
        assert_eq!(r.ref_id, "CTD");
        assert_eq!(r.poll_interval, 64);
        assert_eq!(r.precision, -23);
        assert!((r.offset_ms - 250.0).abs() < 20.0, "offset {}", r.offset_ms);
        assert!(r.delay_ms.abs() < 20.0);
    }

    #[test]
    fn kiss_of_death_e_stratum2() {
        let mut r = [0u8; 48];
        r[0] = 0b00_100_100;
        r[12..16].copy_from_slice(b"RATE");
        assert!(parse("x", &r, 0.0, 0.0).unwrap_err().contains("RATE"));
        r[1] = 2;
        r[12..16].copy_from_slice(&[192, 0, 2, 53]);
        assert_eq!(parse("x", &r, 0.0, 0.0).unwrap().ref_id, "192.0.2.53");
        assert!(parse("x", &r[..20], 0.0, 0.0).is_err());
    }

    /// Before the real reply, a packet from another port and one with a wrong
    /// originate arrive: they are dropped and the offset stays the real server's.
    #[tokio::test]
    async fn risposte_false_scartate() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            let (_, from) = srv.recv_from(&mut buf).await.unwrap();
            let reply = |shift: f64, origin: &[u8]| {
                let now = util::now_unix() + shift;
                let mut r = [0u8; 48];
                r[0] = 0b00_100_100;
                r[1] = 2;
                r[24..32].copy_from_slice(origin);
                put_ts(&mut r, 32, now);
                put_ts(&mut r, 40, now);
                r
            };
            // right originate but from another port: one hour ahead
            spoof
                .send_to(&reply(3600.0, &buf[40..48]), from)
                .await
                .unwrap();
            // from the server but with a wrong originate
            srv.send_to(&reply(3600.0, &[0u8; 8]), from).await.unwrap();
            // client mode (packet sent back)
            srv.send_to(&buf, from).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            srv.send_to(&reply(0.1, &buf[40..48]), from).await.unwrap();
        });
        let r = query("prova", addr).await.unwrap();
        assert!((r.offset_ms - 100.0).abs() < 40.0, "offset {}", r.offset_ms);
        assert_eq!(r.stratum, 2);
    }

    #[test]
    fn messaggi_tradotti() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let mut r = [0u8; 48];
        r[0] = 0b00_100_100;
        r[12..16].copy_from_slice(b"RATE");
        let e = parse("x", &r, 0.0, 0.0).unwrap_err();
        assert!(
            e.contains("refused the request") && !e.contains("rifiutato"),
            "{e}"
        );
        let e = parse("x", &r[..20], 0.0, 0.0).unwrap_err();
        assert_eq!(e, "NTP response too short");
        r[0] = 0b00_100_011;
        let e = parse("x", &r, 0.0, 0.0).unwrap_err();
        assert!(
            e.contains("Invalid NTP response") && !e.contains("non valida"),
            "{e}"
        );
    }

    #[test]
    fn corrispondenza() {
        let req = request(util::now_unix());
        let mut r = [0u8; 48];
        r[0] = 0b00_100_100;
        r[24..32].copy_from_slice(&req[40..48]);
        assert!(matches(&r, &req));
        r[31] ^= 1;
        assert!(!matches(&r, &req));
        r[31] ^= 1;
        r[0] = 0b00_100_101; // broadcast
        assert!(!matches(&r, &req));
        assert!(!matches(&r[..40], &req));
    }
}
