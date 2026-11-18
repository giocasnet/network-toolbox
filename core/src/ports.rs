//! TCP port scan (connect) with service banner reading.
//! Accepts lists and ranges: "22,80,443,8000-8100". At most 1024 ports.
//! Open ports are emitted as they are found and the scan can be
//! stopped.

use crate::ping::Stop;
use crate::tcp::{self, Conn};
use crate::{net, t, tf, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub const DEFAULT_PORTS: &str = "21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443";
pub const MAX_PORTS: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Ports tried together.
const PARALLEL: usize = 500;

#[derive(Debug, Deserialize)]
pub struct PortReq {
    pub host: String,
    #[serde(default)]
    pub ports: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    /// OPEN | CLOSED (refused by the host) | FILTERED (no answer: firewall)
    pub status: String,
    pub banner: String,
}

#[derive(Debug, Serialize)]
pub struct PortResponse {
    pub host: String,
    pub ip: String,
    /// Ports with an outcome, in port-number order.
    pub results: Vec<PortResult>,
    /// Ports requested (equal to `results.len()` if the scan reached the end).
    pub total: usize,
    /// Interrupted with "Stop": `results` holds the ports checked so far.
    pub stopped: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortStart {
    pub host: String,
    pub ip: String,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortProgress {
    pub done: usize,
    pub total: usize,
}

/// Scan events: `{"start":{..}}`, `{"progress":{..}}` and `{"port":{..}}`
/// for each open port, in the order they are found.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortEvent {
    Start(PortStart),
    Progress(PortProgress),
    Port(PortResult),
}

pub fn parse_ports(raw: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in raw
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let bad = || tf!("Porta non valida: {part}", "Invalid port: {part}");
        let num = |s: &str| s.trim().parse::<u16>().ok().filter(|p| *p > 0);
        if let Some((a, b)) = part.split_once('-') {
            let (a, b) = (num(a).ok_or_else(bad)?, num(b).ok_or_else(bad)?);
            if a > b {
                return Err(bad());
            }
            if (b - a) as usize >= MAX_PORTS {
                return Err(tf!(
                    "Massimo {MAX_PORTS} porte per scansione",
                    "At most {MAX_PORTS} ports per scan"
                ));
            }
            ports.extend(a..=b);
        } else {
            ports.push(num(part).ok_or_else(bad)?);
        }
        if ports.len() > MAX_PORTS * 2 {
            break;
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(t!("Nessuna porta indicata", "No port specified").into());
    }
    if ports.len() > MAX_PORTS {
        return Err(tf!(
            "Massimo {MAX_PORTS} porte per scansione",
            "At most {MAX_PORTS} ports per scan"
        ));
    }
    Ok(ports)
}

/// First readable line of the banner, without control characters.
fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(|l| {
            l.chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string()
        })
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .chars()
        .take(160)
        .collect()
}

/// Reason for a failed connection without a refusal from the host.
pub(crate) fn connect_error(e: &std::io::Error) -> String {
    // 10013 WSAEACCES: connection blocked on the PC (Windows firewall, WFP, antivirus)
    if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(10013) {
        return tf!(
            "Bloccata su questo PC (firewall di Windows o antivirus): {e}",
            "Blocked on this PC (Windows firewall or antivirus): {e}"
        );
    }
    e.to_string()
}

pub(crate) async fn probe(ip: IpAddr, port: u16) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    // 3 s: a connection held back by the antivirus can arrive more than a second late
    let mut s = match tcp::connect(addr, CONNECT_TIMEOUT).await {
        Conn::Open(s) => s,
        Conn::Refused => {
            return PortResult {
                port,
                status: "CLOSED".into(),
                banner: String::new(),
            };
        }
        Conn::Failed(e) => {
            return PortResult {
                port,
                status: "FILTERED".into(),
                banner: e.as_ref().map(connect_error).unwrap_or_default(),
            }
        }
    };
    // Many services (SSH, SMTP, FTP) speak first; for the others HTTP is tried.
    let mut buf = [0u8; 512];
    let mut banner = match tokio::time::timeout(Duration::from_millis(700), s.read(&mut buf)).await
    {
        Ok(Ok(n)) if n > 0 => first_line(&buf[..n]),
        _ => String::new(),
    };
    if banner.is_empty() && s.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.is_ok() {
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1200), s.read(&mut buf)).await
        {
            banner = first_line(&buf[..n]);
        }
    }
    PortResult {
        port,
        status: "OPEN".into(),
        banner,
    }
}

/// Scan. Open ports are emitted with `emit` as soon as they are found; the final response
/// returns all the ports checked in port-number order. With `stop` ("Stop"
/// button) it ends at once: ports still being examined do not appear.
pub async fn run<F>(req: PortReq, stop: &Stop, emit: F) -> Result<PortResponse>
where
    F: Fn(PortEvent) + Send + Sync + 'static,
{
    let host = net::clean_host(&req.host)?;
    let raw = req
        .ports
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_PORTS);
    let ports = parse_ports(raw)?;
    let total = ports.len();
    let Some(ip) = stop.race(net::resolve_v4(&host)).await else {
        return Ok(PortResponse {
            host,
            ip: String::new(),
            results: Vec::new(),
            total,
            stopped: true,
        });
    };
    let ip = IpAddr::V4(ip?);
    let emit = Arc::new(emit);
    emit(PortEvent::Start(PortStart {
        host: host.clone(),
        ip: ip.to_string(),
        total,
    }));

    let sem = Arc::new(Semaphore::new(PARALLEL));
    let done = Arc::new(AtomicUsize::new(0));
    // progress on every port for short lists, every 16 for ranges
    let step = if total <= 64 { 1 } else { 16 };
    let mut set = JoinSet::new();
    for port in ports {
        // after a stop no more ports start
        let Some(permit) = stop.race(sem.clone().acquire_owned()).await else {
            break;
        };
        let permit = permit.expect("semaforo chiuso");
        let (emit, done, stop) = (emit.clone(), done.clone(), stop.clone());
        set.spawn(async move {
            let r = stop.race(probe(ip, port)).await?;
            drop(permit);
            if r.status == "OPEN" {
                emit(PortEvent::Port(r.clone()));
            }
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % step == 0 || n == total {
                emit(PortEvent::Progress(PortProgress { done: n, total }));
            }
            Some(r)
        });
    }
    let mut results = Vec::with_capacity(total);
    while let Some(r) = set.join_next().await {
        if let Ok(Some(r)) = r {
            results.push(r);
        }
    }
    results.sort_by_key(|r| r.port);
    Ok(PortResponse {
        host,
        ip: ip.to_string(),
        results,
        total,
        stopped: stop.is_stopped(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porte() {
        assert_eq!(parse_ports("443, 22,80,22").unwrap(), vec![22, 80, 443]);
        assert_eq!(
            parse_ports("8000-8003").unwrap(),
            vec![8000, 8001, 8002, 8003]
        );
        assert_eq!(parse_ports(DEFAULT_PORTS).unwrap().len(), 15);
        assert_eq!(parse_ports("1-1024").unwrap().len(), 1024);
        assert!(parse_ports("1-1025").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("100-90").is_err());
        assert!(parse_ports(" , ").is_err());
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(parse_ports("abc").unwrap_err(), "Invalid port: abc");
        assert_eq!(parse_ports(" , ").unwrap_err(), "No port specified");
        let e = parse_ports("1-1025").unwrap_err();
        assert!(
            e.contains("At most 1024 ports") && !e.contains("Massimo"),
            "{e}"
        );
        let e = connect_error(&std::io::Error::from_raw_os_error(10013));
        assert!(
            e.starts_with("Blocked on this PC") && !e.contains("Bloccata"),
            "{e}"
        );
    }

    #[test]
    fn banner() {
        assert_eq!(
            first_line(b"\r\nSSH-2.0-OpenSSH_9.6\r\n"),
            "SSH-2.0-OpenSSH_9.6"
        );
        assert_eq!(
            first_line(b"HTTP/1.1 301 Moved\r\nServer: x\r\n"),
            "HTTP/1.1 301 Moved"
        );
    }

    fn collector() -> (
        Arc<std::sync::Mutex<Vec<PortEvent>>>,
        impl Fn(PortEvent) + Send + Sync + 'static,
    ) {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let e2 = ev.clone();
        (ev, move |e| e2.lock().unwrap().push(e))
    }

    #[test]
    fn eventi_json() {
        let j = |e: PortEvent| serde_json::to_string(&e).unwrap();
        assert_eq!(
            j(PortEvent::Start(PortStart {
                host: "srv01".into(),
                ip: "192.0.2.10".into(),
                total: 15
            })),
            r#"{"start":{"host":"srv01","ip":"192.0.2.10","total":15}}"#
        );
        assert_eq!(
            j(PortEvent::Progress(PortProgress { done: 4, total: 15 })),
            r#"{"progress":{"done":4,"total":15}}"#
        );
        assert_eq!(
            j(PortEvent::Port(PortResult {
                port: 22,
                status: "OPEN".into(),
                banner: "SSH-2.0".into()
            })),
            r#"{"port":{"port":22,"status":"OPEN","banner":"SSH-2.0"}}"#
        );
    }

    /// One open port (with banner) and one closed: the open one is emitted at once as an event,
    /// the final response returns both in port-number order.
    #[tokio::test]
    async fn scansione_locale() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        }; // listener closed: the port answers with RST
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"220 test FTP ready\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let (ev, emit) = collector();
        let r = run(
            PortReq {
                host: "127.0.0.1".into(),
                ports: Some(format!("{port},{closed}")),
            },
            &Stop::new(),
            emit,
        )
        .await
        .unwrap();
        assert!(!r.stopped);
        assert_eq!((r.total, r.results.len()), (2, 2));
        assert!(r.results[0].port < r.results[1].port);
        let open = r.results.iter().find(|x| x.port == port).unwrap();
        assert_eq!(open.status, "OPEN");
        assert_eq!(open.banner, "220 test FTP ready");
        let shut = r.results.iter().find(|x| x.port == closed).unwrap();
        assert_eq!(shut.status, "CLOSED");
        let ev = ev.lock().unwrap();
        assert!(matches!(&ev[0], PortEvent::Start(s) if s.total == 2 && s.ip == "127.0.0.1"));
        let opened: Vec<u16> = ev
            .iter()
            .filter_map(|e| match e {
                PortEvent::Port(p) => Some(p.port),
                _ => None,
            })
            .collect();
        assert_eq!(opened, vec![port]);
        assert!(matches!(ev.last(), Some(PortEvent::Progress(p)) if p.done == 2 && p.total == 2));
    }

    /// Stop already received: no port checked.
    #[tokio::test]
    async fn fermata_prima_di_partire() {
        let stop = Stop::new();
        stop.stop();
        let (ev, emit) = collector();
        let r = run(
            PortReq {
                host: "127.0.0.1".into(),
                ports: Some("1-200".into()),
            },
            &stop,
            emit,
        )
        .await
        .unwrap();
        assert!(r.stopped);
        assert_eq!(r.total, 200);
        assert!(r.results.is_empty());
        assert!(ev.lock().unwrap().is_empty());
    }

    /// Stop during the scan: a service that accepts and stays silent keeps the
    /// banner read busy; the scan ends at once without waiting for it.
    #[tokio::test]
    async fn fermata_in_corso() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_s, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let stop = Stop::new();
        let (_, emit) = collector();
        let t0 = std::time::Instant::now();
        let (r, _) = tokio::join!(
            run(
                PortReq {
                    host: "127.0.0.1".into(),
                    ports: Some(port.to_string()),
                },
                &stop,
                emit,
            ),
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                stop.stop();
            }
        );
        let r = r.unwrap();
        assert!(r.stopped);
        assert!(r.results.is_empty());
        assert!(
            t0.elapsed() < Duration::from_millis(1000),
            "{:?}",
            t0.elapsed()
        );
    }
}
