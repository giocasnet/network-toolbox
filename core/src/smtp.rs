//! Test of an SMTP server: banner, reverse DNS, EHLO extensions, TLS (STARTTLS or
//! implicit), open relay, authentication and sending of a test message, with the
//! session transcript and the time of each reply.
//!
//! Security rules:
//! - the password is sent only over TLS with a verified certificate (never in clear nor
//!   with an invalid certificate) and it is always masked in the transcript;
//! - the open relay test stops at RCPT TO: it never sends DATA;
//! - after STARTTLS, data already received in clear aborts the session
//!   (command injection, CVE-2011-0411).

use crate::{net, ports, t, tf, tls, util, Event, Result};
use rustls::client::danger::ServerCertVerifier;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GREETING_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const DATA_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_RCPT: usize = 10;
pub const MAX_BODY: usize = 64 * 1024;
const MAX_SUBJECT: usize = 200;
const MAX_LINE: u64 = 4096;
const MAX_REPLY_LINES: usize = 200;
/// Reserved domains (RFC 2606): the relay test reaches nobody.
const RELAY_FROM: &str = "ntb-relay-test@example.com";
const RELAY_TO: &str = "ntb-relay-test@example.net";
const MASK: &str = "********";

/// Request from the UI. No `Debug`: it contains the password.
#[derive(Deserialize, Default)]
pub struct SmtpReq {
    pub host: String,
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub port: Option<u32>,
    /// auto (465 = implicit TLS, otherwise STARTTLS if offered) | starttls
    /// (mandatory) | implicit | none
    #[serde(default)]
    pub security: Option<String>,
    /// Name used in EHLO; empty = name of this PC.
    #[serde(default)]
    pub ehlo: Option<String>,
    #[serde(default)]
    pub relay: bool,
    #[serde(default)]
    pub auth: bool,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub send: bool,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    /// ok | warn | err | info
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct SmtpResult {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub ptr: String,
    pub ehlo_name: String,
    /// implicit | starttls | none
    pub tls_mode: String,
    pub banner: String,
    pub extensions: Vec<String>,
    pub auth_mechs: Vec<String>,
    pub tls: Option<tls::TlsResult>,
    pub checks: Vec<Check>,
    pub transcript: Vec<String>,
    pub connect_ms: u64,
    pub total_ms: u64,
    pub sent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Security {
    Auto,
    Starttls,
    Implicit,
    None,
}

struct Plan {
    host: String,
    port: u16,
    security: Security,
    ehlo: String,
    relay: bool,
    auth: Option<(String, String)>,
    send: Option<Mail>,
}

struct Mail {
    from: String,
    rcpts: Vec<String>,
    subject: String,
    body: String,
}

fn check(name: &str, status: &str, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
    }
}

// ───────────────────────── validation ─────────────────────────

fn has_ctl(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// Simple email address (ASCII, no comments or display names).
pub fn valid_addr(a: &str) -> bool {
    let Some((local, domain)) = a.rsplit_once('@') else {
        return false;
    };
    a.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && local.chars().all(|c| {
            c.is_ascii_graphic()
                && !matches!(
                    c,
                    '<' | '>' | '(' | ')' | ',' | ';' | ':' | '"' | '\\' | '[' | ']' | '@'
                )
        })
        && valid_domain(domain)
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Name of this PC for EHLO: PCNAME.domain on a domain-joined PC.
pub fn local_fqdn() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_default()
        .to_lowercase();
    let name = match std::env::var("USERDNSDOMAIN") {
        Ok(d) if !d.is_empty() && !host.is_empty() => format!("{host}.{}", d.to_lowercase()),
        _ => host,
    };
    if valid_domain(&name) {
        name
    } else {
        "localhost".into()
    }
}

fn plan(req: SmtpReq) -> Result<Plan> {
    let host = net::clean_host(&req.host)?;
    let port = req.port.unwrap_or(25);
    if !(1..=65535).contains(&port) {
        return Err(t!("Porta non valida: da 1 a 65535", "Invalid port: 1 to 65535").into());
    }
    let port = port as u16;
    let security = match req.security.as_deref().unwrap_or("auto") {
        "" | "auto" => Security::Auto,
        "starttls" => Security::Starttls,
        "implicit" => Security::Implicit,
        "none" => Security::None,
        other => {
            return Err(tf!(
                "Modalità TLS non valida: {other}",
                "Invalid TLS mode: {other}"
            ))
        }
    };
    let ehlo = match req.ehlo.as_deref().map(str::trim).unwrap_or("") {
        "" => local_fqdn(),
        e if valid_domain(e) => e.to_string(),
        e => {
            let lit = e.strip_prefix('[').and_then(|x| x.strip_suffix(']'));
            match lit.and_then(|x| x.parse::<Ipv4Addr>().ok()) {
                Some(_) => e.to_string(),
                None => {
                    return Err(tf!(
                        "Nome EHLO non valido: {e} (usa un nome DNS o [indirizzo IP])",
                        "Invalid EHLO name: {e} (use a DNS name or [IP address])"
                    ))
                }
            }
        }
    };
    let auth = if req.auth {
        let user = req.user.trim().to_string();
        if user.is_empty() {
            return Err(t!(
                "Indica l'utente per l'autenticazione",
                "Enter the user for authentication"
            )
            .into());
        }
        if req.password.is_empty() {
            return Err(t!(
                "Indica la password per l'autenticazione",
                "Enter the password for authentication"
            )
            .into());
        }
        if user.len() > 256 || req.password.len() > 256 {
            return Err(t!(
                "Utente o password troppo lunghi (massimo 256 caratteri)",
                "User or password too long (maximum 256 characters)"
            )
            .into());
        }
        if has_ctl(&user) || has_ctl(&req.password) {
            return Err(t!(
                "Utente e password non possono contenere caratteri di controllo",
                "User and password cannot contain control characters"
            )
            .into());
        }
        Some((user, req.password))
    } else {
        None
    };
    let send = if req.send {
        let from = req.from.trim().to_string();
        if !valid_addr(&from) {
            return Err(if from.is_empty() {
                t!("Indica il mittente", "Enter the sender").into()
            } else {
                tf!("Mittente non valido: {from}", "Invalid sender: {from}")
            });
        }
        let mut rcpts: Vec<String> = Vec::new();
        for r in req
            .to
            .split([',', ';', ' ', '\n', '\r', '\t'])
            .map(str::trim)
        {
            if r.is_empty() {
                continue;
            }
            if !valid_addr(r) {
                return Err(tf!(
                    "Destinatario non valido: {r}",
                    "Invalid recipient: {r}"
                ));
            }
            if !rcpts.iter().any(|x| x.eq_ignore_ascii_case(r)) {
                rcpts.push(r.to_string());
            }
        }
        if rcpts.is_empty() {
            return Err(t!(
                "Indica almeno un destinatario",
                "Enter at least one recipient"
            )
            .into());
        }
        if rcpts.len() > MAX_RCPT {
            return Err(tf!(
                "Massimo {MAX_RCPT} destinatari",
                "Maximum {MAX_RCPT} recipients"
            ));
        }
        let subject = req.subject.trim().to_string();
        if has_ctl(&subject) {
            return Err(t!(
                "L'oggetto non può contenere a capo o caratteri di controllo",
                "The subject cannot contain line breaks or control characters"
            )
            .into());
        }
        if subject.chars().count() > MAX_SUBJECT {
            return Err(tf!(
                "Oggetto troppo lungo (massimo {MAX_SUBJECT} caratteri)",
                "Subject too long (maximum {MAX_SUBJECT} characters)"
            ));
        }
        if req.body.len() > MAX_BODY {
            return Err(t!(
                "Corpo del messaggio troppo lungo (massimo 64 KB)",
                "Message body too long (maximum 64 KB)"
            )
            .into());
        }
        Some(Mail {
            from,
            rcpts,
            subject: if subject.is_empty() {
                "Test SMTP".into()
            } else {
                subject
            },
            body: req.body,
        })
    } else {
        None
    };
    Ok(Plan {
        host,
        port,
        security,
        ehlo,
        relay: req.relay,
        auth,
        send,
    })
}

// ───────────────────────── encodings ─────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Subject in RFC 2047 if it is not ASCII, split into words of at most 45 bytes.
fn encode_subject(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if cur.len() + ch.len_utf8() > 45 {
            words.push(std::mem::take(&mut cur));
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
        .iter()
        .map(|w| format!("=?UTF-8?B?{}?=", base64(w.as_bytes())))
        .collect::<Vec<_>>()
        .join("\r\n ")
}

/// "Wed, 04 Nov 2026 17:30:05 +0000" (RFC 5322).
fn rfc5322_date(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, mo, d, h, mi, s) = util::civil(secs);
    let wd = DAYS[secs.div_euclid(86_400).rem_euclid(7) as usize];
    format!(
        "{wd}, {d:02} {} {y} {h:02}:{mi:02}:{s:02} +0000",
        MONTHS[(mo - 1) as usize]
    )
}

/// Headers and body (base64, 76-column lines) with CRLF terminators, without the final "."
fn build_message(m: &Mail, ehlo: &str, secs: i64, id: &str) -> (Vec<String>, String) {
    let domain = ehlo.trim_start_matches('[').trim_end_matches(']');
    let body = if m.body.trim().is_empty() {
        tf!(
            "Messaggio di prova inviato da Network Toolbox ({ehlo}) il {}.\r\n",
            "Test message sent by Network Toolbox ({ehlo}) on {}.\r\n",
            util::utc_ms(secs as f64)
        )
    } else {
        m.body.replace("\r\n", "\n").replace('\n', "\r\n")
    };
    let headers = vec![
        format!("Date: {}", rfc5322_date(secs)),
        format!("From: <{}>", m.from),
        format!(
            "To: {}",
            m.rcpts
                .iter()
                .map(|r| format!("<{r}>"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("Subject: {}", encode_subject(&m.subject)),
        format!("Message-ID: <{id}@{domain}>"),
        "MIME-Version: 1.0".into(),
        "Content-Type: text/plain; charset=UTF-8".into(),
        "Content-Transfer-Encoding: base64".into(),
        format!("X-Mailer: Network Toolbox {}", env!("CARGO_PKG_VERSION")),
    ];
    let enc = base64(body.as_bytes());
    let mut data = headers.join("\r\n");
    data.push_str("\r\n\r\n");
    for chunk in enc.as_bytes().chunks(76) {
        data.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        data.push_str("\r\n");
    }
    (headers, dot_stuff(&data))
}

/// Doubles the dot at the start of a line (RFC 5321 §4.5.2).
fn dot_stuff(data: &str) -> String {
    let mut out = String::with_capacity(data.len() + 8);
    for line in data.split_inclusive("\r\n") {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
    }
    out
}

// ───────────────────────── DNS ─────────────────────────

/// The name looks automatically assigned by the provider (IP in the name, "dsl", "dyn"...).
fn generic_name(name: &str, ip: Ipv4Addr) -> bool {
    let n = name.to_lowercase();
    let o = ip.octets();
    let fw = [o[0], o[1], o[2], o[3]].map(|x| x.to_string());
    let rv = [o[3], o[2], o[1], o[0]].map(|x| x.to_string());
    for parts in [&fw, &rv] {
        for sep in [".", "-", "_"] {
            if n.contains(&parts.join(sep)) {
                return true;
            }
        }
    }
    n.split(['.', '-']).any(|l| {
        [
            "dsl",
            "adsl",
            "dyn",
            "dynamic",
            "dhcp",
            "pool",
            "ppp",
            "pppoe",
            "cable",
            "broadband",
            "dial",
            "dialup",
            "customer",
        ]
        .iter()
        .any(|k| l == *k || (l.starts_with(k) && l[k.len()..].chars().all(|c| c.is_ascii_digit())))
    })
}

async fn forward_v4(name: &str) -> Vec<Ipv4Addr> {
    let h = name.to_string();
    let job = tokio::task::spawn_blocking(move || {
        (h.as_str(), 0)
            .to_socket_addrs()
            .map(|a| a.collect::<Vec<_>>())
    });
    match tokio::time::timeout(Duration::from_secs(4), job).await {
        Ok(Ok(Ok(a))) => a
            .into_iter()
            .filter_map(|s| match s.ip() {
                IpAddr::V4(v) => Some(v),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

struct DnsInfo {
    ptr: String,
    forward: Vec<Ipv4Addr>,
}

async fn dns_info(ip: Ipv4Addr) -> DnsInfo {
    let ptr = net::rdns(IpAddr::V4(ip), Duration::from_secs(3)).await;
    let forward = if ptr.is_empty() {
        vec![]
    } else {
        forward_v4(&ptr).await
    };
    DnsInfo { ptr, forward }
}

fn dns_checks(ip: Ipv4Addr, d: &DnsInfo, banner_name: &str) -> Vec<Check> {
    let mut v = Vec::new();
    let private = ip.is_private() || ip.is_loopback() || ip.is_link_local();
    if d.ptr.is_empty() {
        v.push(check(
            "Reverse DNS",
            "warn",
            tf!(
                "Nessun record PTR per {ip}{}",
                "No PTR record for {ip}{}",
                if private {
                    t!(
                        " (IP privato: conta solo per i server esposti su Internet)",
                        " (private IP: only matters for servers exposed to the Internet)"
                    )
                } else {
                    t!(
                        ": molti server di posta rifiutano i messaggi da IP senza PTR",
                        ": many mail servers reject messages from IPs without PTR"
                    )
                }
            ),
        ));
        return v;
    }
    if d.forward.contains(&ip) {
        v.push(check(
            "Reverse DNS",
            "ok",
            tf!(
                "{ip} → {} → {ip} (diretto e inverso coincidono)",
                "{ip} → {} → {ip} (forward and reverse match)",
                d.ptr
            ),
        ));
    } else {
        v.push(check(
            "Reverse DNS",
            "warn",
            tf!(
                "{ip} → {}, ma il nome risolve in {}",
                "{ip} → {}, but the name resolves to {}",
                d.ptr,
                if d.forward.is_empty() {
                    t!("nessun indirizzo IPv4", "no IPv4 address").to_string()
                } else {
                    d.forward
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        ));
    }
    let fqdn = d.ptr.contains('.') && valid_domain(&d.ptr);
    if !fqdn {
        v.push(check(
            t!("Hostname valido", "Valid hostname"),
            "warn",
            tf!(
                "{} non è un nome DNS completo (FQDN)",
                "{} is not a fully qualified DNS name (FQDN)",
                d.ptr
            ),
        ));
    } else if generic_name(&d.ptr, ip) {
        v.push(check(
            t!("Hostname valido", "Valid hostname"),
            "warn",
            tf!(
                "{} sembra un nome generico del provider: molti filtri antispam lo penalizzano",
                "{} looks like a generic provider name: many antispam filters penalise it",
                d.ptr
            ),
        ));
    } else {
        v.push(check(
            t!("Hostname valido", "Valid hostname"),
            "ok",
            tf!("{} è un FQDN", "{} is an FQDN", d.ptr),
        ));
    }
    if !banner_name.is_empty() {
        if banner_name.eq_ignore_ascii_case(d.ptr.trim_end_matches('.')) {
            v.push(check(
                t!("Banner e reverse DNS", "Banner and reverse DNS"),
                "ok",
                tf!(
                    "Il nome nel banner coincide con il PTR ({banner_name})",
                    "The name in the banner matches the PTR ({banner_name})"
                ),
            ));
        } else {
            v.push(check(
                t!("Banner e reverse DNS", "Banner and reverse DNS"),
                "warn",
                tf!(
                    "Banner {banner_name}, PTR {}",
                    "Banner {banner_name}, PTR {}",
                    d.ptr
                ),
            ));
        }
    }
    v
}

// ───────────────────────── session ─────────────────────────

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn ok(&self) -> bool {
        (200..300).contains(&self.code)
    }
    /// Text of the last line, for messages ("250 2.1.0 Ok").
    fn text(&self) -> String {
        self.lines.last().cloned().unwrap_or_default()
    }
}

#[derive(Default)]
struct Caps {
    exts: Vec<String>,
    starttls: bool,
    auth: Vec<String>,
    size: Option<u64>,
    helo_only: bool,
}

impl Caps {
    fn from_reply(r: &Reply) -> Caps {
        let mut c = Caps::default();
        for l in r.lines.iter().skip(1) {
            let e = l.get(4..).unwrap_or("").trim().to_string();
            if e.is_empty() {
                continue;
            }
            let mut it = e.split_whitespace();
            let kw = it.next().unwrap_or("").to_uppercase();
            match kw.as_str() {
                "STARTTLS" => c.starttls = true,
                "AUTH" => {
                    for m in it {
                        let m = m.to_uppercase();
                        if !c.auth.contains(&m) {
                            c.auth.push(m);
                        }
                    }
                }
                "SIZE" => c.size = it.next().and_then(|n| n.parse().ok()),
                _ => {}
            }
            c.exts.push(e);
        }
        c
    }
}

struct Out {
    head: Vec<Check>,
    checks: Vec<Check>,
    banner: String,
    tls_mode: String,
    tls: Option<tls::TlsResult>,
    sent: bool,
}

struct Session<F: FnMut(Event)> {
    io: Option<BufReader<Box<dyn Io>>>,
    transcript: Vec<String>,
    emit: F,
    mark: Instant,
}

impl<F: FnMut(Event)> Session<F> {
    fn log(&mut self, line: String) {
        (self.emit)(Event::Line(line.clone()));
        self.transcript.push(line);
    }

    fn stream(&mut self) -> Result<&mut BufReader<Box<dyn Io>>> {
        self.io.as_mut().ok_or_else(|| {
            t!("Connessione non disponibile", "Connection not available").to_string()
        })
    }

    async fn write(&mut self, data: &[u8]) -> Result<()> {
        let s = self.stream()?.get_mut();
        tokio::time::timeout(REPLY_TIMEOUT, async {
            s.write_all(data).await?;
            s.flush().await
        })
        .await
        .map_err(|_| {
            t!(
                "Timeout nell'invio al server",
                "Timeout sending to the server"
            )
            .to_string()
        })?
        .map_err(|e| {
            tf!(
                "Invio al server fallito: {e}",
                "Sending to the server failed: {e}"
            )
        })
    }

    /// Sends a line; `shown` is what appears in the transcript.
    async fn send(&mut self, line: &str, shown: &str) -> Result<()> {
        self.log(shown.to_string());
        self.mark = Instant::now();
        self.write(format!("{line}\r\n").as_bytes()).await
    }

    async fn read_line(&mut self, deadline: Instant) -> Result<String> {
        let mut buf = Vec::new();
        let left = deadline.saturating_duration_since(Instant::now());
        let r = self.stream()?;
        let n = tokio::time::timeout(left, (&mut *r).take(MAX_LINE).read_until(b'\n', &mut buf))
            .await
            .map_err(|_| {
                t!(
                    "Timeout: il server non ha risposto",
                    "Timeout: the server did not respond"
                )
                .to_string()
            })?
            .map_err(|e| {
                tf!(
                    "Lettura dal server fallita: {e}",
                    "Reading from the server failed: {e}"
                )
            })?;
        if n == 0 {
            return Err(t!(
                "Il server ha chiuso la connessione",
                "The server closed the connection"
            )
            .into());
        }
        if !buf.ends_with(b"\n") {
            return Err(t!(
                "Risposta del server troppo lunga o incompleta",
                "Server response too long or incomplete"
            )
            .into());
        }
        let s: String = String::from_utf8_lossy(&buf)
            .trim_end_matches(['\r', '\n'])
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        Ok(s)
    }

    /// Reads a reply (possibly multi-line); the time goes on the last line.
    async fn reply(&mut self, timeout: Duration) -> Result<Reply> {
        let deadline = Instant::now() + timeout;
        let mut lines = Vec::new();
        let mut code = 0u16;
        loop {
            let l = self.read_line(deadline).await?;
            let b = l.as_bytes();
            let parsed = (b.len() >= 3 && b[..3].iter().all(u8::is_ascii_digit))
                .then(|| l[..3].parse::<u16>().ok())
                .flatten();
            let Some(c) = parsed.filter(|_| b.len() == 3 || b[3] == b' ' || b[3] == b'-') else {
                self.log(l.clone());
                return Err(tf!(
                    "Risposta non SMTP: {}",
                    "Not an SMTP response: {}",
                    l.chars().take(120).collect::<String>()
                ));
            };
            if !lines.is_empty() && c != code {
                self.log(l.clone());
                return Err(t!(
                    "Risposta su più righe con codici diversi",
                    "Multi-line response with different codes"
                )
                .into());
            }
            code = c;
            let last = b.len() == 3 || b[3] == b' ';
            if last {
                let ms = self.mark.elapsed().as_millis();
                self.log(format!("{l} [{ms} ms]"));
            } else {
                self.log(l.clone());
            }
            lines.push(l);
            if last {
                return Ok(Reply { code, lines });
            }
            if lines.len() >= MAX_REPLY_LINES {
                return Err(t!(
                    "Risposta del server troppo lunga",
                    "Server response too long"
                )
                .into());
            }
        }
    }

    async fn cmd(&mut self, line: &str, shown: &str, timeout: Duration) -> Result<Reply> {
        self.send(line, shown).await?;
        self.reply(timeout).await
    }

    async fn ehlo(&mut self, name: &str) -> Result<Caps> {
        let r = self
            .cmd(
                &format!("EHLO {name}"),
                &format!("EHLO {name}"),
                REPLY_TIMEOUT,
            )
            .await?;
        if r.ok() {
            return Ok(Caps::from_reply(&r));
        }
        let r = self
            .cmd(
                &format!("HELO {name}"),
                &format!("HELO {name}"),
                REPLY_TIMEOUT,
            )
            .await?;
        if r.ok() {
            Ok(Caps {
                helo_only: true,
                ..Caps::default()
            })
        } else {
            Err(tf!(
                "Il server rifiuta EHLO e HELO: {}",
                "The server rejects EHLO and HELO: {}",
                r.text()
            ))
        }
    }

    async fn start_tls(
        &mut self,
        host: &str,
        verifier: Option<Arc<dyn ServerCertVerifier>>,
    ) -> Result<tls::TlsResult> {
        let r = self.io.take().ok_or(t!(
            "Connessione non disponibile",
            "Connection not available"
        ))?;
        if !r.buffer().is_empty() {
            return Err(t!(
                "Dati ricevuti in chiaro prima dell'handshake TLS (possibile iniezione di comandi): sessione interrotta",
                "Data received in clear before the TLS handshake (possible command injection): session aborted"
            )
            .into());
        }
        let t0 = Instant::now();
        let (s, info) = tls::handshake(host, r.into_inner(), verifier).await?;
        self.io = Some(BufReader::new(Box::new(s)));
        self.log(tf!(
            "--- TLS: {}, {}, certificato {} [{} ms]",
            "--- TLS: {}, {}, certificate {} [{} ms]",
            info.tls_version,
            info.cipher,
            if info.verified {
                t!("verificato", "verified")
            } else {
                t!("NON verificato", "NOT verified")
            },
            t0.elapsed().as_millis()
        ));
        Ok(info)
    }

    async fn quit(&mut self) {
        if self.io.is_some() {
            let _ = self.cmd("QUIT", "QUIT", Duration::from_secs(5)).await;
        }
    }
}

fn tls_checks(t: &tls::TlsResult, mode: &str, out: &mut Vec<Check>) {
    let how = if mode == "implicit" {
        t!("TLS implicito", "implicit TLS")
    } else {
        "STARTTLS"
    };
    out.push(check(
        "TLS",
        if t.verified { "ok" } else { "warn" },
        format!("{}, {} ({how})", t.tls_version, t.cipher),
    ));
    let cn = t.subject.get("commonName").cloned().unwrap_or_default();
    let issuer = t
        .issuer
        .get("organizationName")
        .or(t.issuer.get("commonName"))
        .cloned()
        .unwrap_or_default();
    let validity = if t.expired {
        tf!(
            "scaduto da {} giorni",
            "expired {} days ago",
            -t.days_remaining
        )
    } else {
        tf!(
            "scade tra {} giorni",
            "expires in {} days",
            t.days_remaining
        )
    };
    let mut detail = tf!(
        "{cn}, emesso da {issuer}, {validity}",
        "{cn}, issued by {issuer}, {validity}"
    );
    if !t.verified {
        detail = tf!(
            "Non attendibile: {}. {detail}",
            "Untrusted: {}. {detail}",
            t.verify_error
        );
    }
    let st = if t.expired {
        "err"
    } else if !t.verified || t.expiring_soon {
        "warn"
    } else {
        "ok"
    };
    out.push(check(t!("Certificato", "Certificate"), st, detail));
}

fn auth_plain_offered(c: &Caps) -> bool {
    c.auth.iter().any(|m| m == "PLAIN" || m == "LOGIN")
}

async fn session<F: FnMut(Event)>(
    s: &mut Session<F>,
    p: &Plan,
    out: &mut Out,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<()> {
    let implicit =
        p.security == Security::Implicit || (p.security == Security::Auto && p.port == 465);
    if implicit {
        let t = s.start_tls(&p.host, verifier.clone()).await;
        match t {
            Ok(t) => {
                out.tls_mode = "implicit".into();
                tls_checks(&t, "implicit", &mut out.checks);
                out.tls = Some(t);
            }
            Err(e) => {
                out.checks.push(check("TLS", "err", e.clone()));
                return Err(e);
            }
        }
    }

    let greet = s.reply(GREETING_TIMEOUT).await?;
    out.banner = greet.lines.first().cloned().unwrap_or_default();
    if greet.code != 220 {
        out.head.push(check(
            "Banner",
            "err",
            tf!(
                "Il server rifiuta la connessione: {}",
                "The server refuses the connection: {}",
                greet.text()
            ),
        ));
        s.quit().await;
        return Ok(());
    }
    out.head.push(check("Banner", "ok", out.banner.clone()));

    let mut caps = s.ehlo(&p.ehlo).await?;
    if !implicit && p.security != Security::None {
        if caps.starttls {
            if auth_plain_offered(&caps) {
                out.checks.push(check(
                    t!("AUTH prima di TLS", "AUTH before TLS"),
                    "warn",
                    tf!(
                        "Il server offre {} anche in chiaro: un client mal configurato invierebbe la password senza cifratura",
                        "The server offers {} also in clear: a misconfigured client would send the password unencrypted",
                        caps.auth.join(" ")
                    ),
                ));
            }
            let r = s.cmd("STARTTLS", "STARTTLS", REPLY_TIMEOUT).await?;
            if r.code == 220 {
                match s.start_tls(&p.host, verifier.clone()).await {
                    Ok(t) => {
                        out.tls_mode = "starttls".into();
                        tls_checks(&t, "starttls", &mut out.checks);
                        out.tls = Some(t);
                        caps = s.ehlo(&p.ehlo).await?;
                    }
                    Err(e) => {
                        out.checks.push(check("TLS", "err", e.clone()));
                        return Err(e);
                    }
                }
            } else {
                out.checks.push(check(
                    "TLS",
                    "err",
                    tf!(
                        "STARTTLS offerto ma rifiutato: {}",
                        "STARTTLS offered but rejected: {}",
                        r.text()
                    ),
                ));
            }
        } else {
            let st = if p.security == Security::Starttls {
                "err"
            } else {
                "warn"
            };
            out.checks.push(check(
                "TLS",
                st,
                if caps.helo_only {
                    t!(
                        "Il server non supporta EHLO: niente STARTTLS",
                        "The server does not support EHLO: no STARTTLS"
                    )
                    .to_string()
                } else {
                    t!(
                        "STARTTLS non offerto: la sessione resta in chiaro",
                        "STARTTLS not offered: the session stays in clear"
                    )
                    .to_string()
                },
            ));
            if auth_plain_offered(&caps) {
                out.checks.push(check(
                    t!("AUTH in chiaro", "AUTH in clear"),
                    "warn",
                    tf!(
                        "Il server accetta {} senza TLS: le password viaggerebbero in chiaro",
                        "The server accepts {} without TLS: passwords would travel in clear",
                        caps.auth.join(" ")
                    ),
                ));
            }
            if p.security == Security::Starttls {
                s.quit().await;
                return Ok(());
            }
        }
    } else if p.security == Security::None {
        out.checks.push(check(
            "TLS",
            "info",
            tf!(
                "Non provato (scelto \"nessuna cifratura\"){}",
                "Not tested (\"no encryption\" chosen){}",
                if caps.starttls {
                    t!("; il server offre STARTTLS", "; the server offers STARTTLS")
                } else {
                    ""
                }
            ),
        ));
    }

    // extensions after the possible STARTTLS
    if caps.helo_only {
        out.checks.push(check(
            "EHLO",
            "warn",
            t!(
                "Il server accetta solo HELO (niente estensioni ESMTP)",
                "The server accepts only HELO (no ESMTP extensions)"
            ),
        ));
    } else {
        let list: Vec<String> = caps
            .exts
            .iter()
            .map(|e| e.split_whitespace().next().unwrap_or("").to_uppercase())
            .collect();
        out.checks.push(check("EHLO", "ok", list.join(", ")));
    }
    out.checks.push(check(
        t!("Autenticazione offerta", "Authentication offered"),
        "info",
        if caps.auth.is_empty() {
            t!("Nessun meccanismo AUTH", "No AUTH mechanism").to_string()
        } else {
            caps.auth.join(" ")
        },
    ));
    if let Some(sz) = caps.size.filter(|n| *n > 0) {
        out.checks.push(check(
            t!("Dimensione massima", "Maximum size"),
            "info",
            tf!(
                "{:.1} MB ({sz} byte)",
                "{:.1} MB ({sz} bytes)",
                sz as f64 / 1_048_576.0
            ),
        ));
    }
    let tls_ok = out.tls.as_ref().map(|t| t.verified);

    if p.relay {
        let r = s
            .cmd(
                &format!("MAIL FROM:<{RELAY_FROM}>"),
                &format!("MAIL FROM:<{RELAY_FROM}>"),
                REPLY_TIMEOUT,
            )
            .await?;
        if !r.ok() {
            out.checks.push(check(
                "Open relay",
                "warn",
                tf!(
                    "Non determinabile: il mittente di prova è stato rifiutato ({})",
                    "Cannot be determined: the test sender was rejected ({})",
                    r.text()
                ),
            ));
        } else {
            let r = s
                .cmd(
                    &format!("RCPT TO:<{RELAY_TO}>"),
                    &format!("RCPT TO:<{RELAY_TO}>"),
                    REPLY_TIMEOUT,
                )
                .await?;
            if r.ok() {
                out.checks.push(check(
                    "Open relay",
                    "err",
                    tf!(
                        "Relay aperto da questo PC: destinatario esterno accettato senza autenticazione ({}). Nessun messaggio inviato",
                        "Open relay from this PC: external recipient accepted without authentication ({}). No message sent",
                        r.text()
                    ),
                ));
            } else {
                out.checks.push(check(
                    "Open relay",
                    "ok",
                    tf!("Non è un open relay: {}", "Not an open relay: {}", r.text()),
                ));
            }
        }
        s.cmd("RSET", "RSET", REPLY_TIMEOUT).await?;
    }

    let mut auth_ok = true;
    if let Some((user, pass)) = &p.auth {
        auth_ok = false;
        let refuse = match tls_ok {
            None => Some(t!("connessione non cifrata", "unencrypted connection").to_string()),
            Some(false) => Some(tf!(
                "certificato non valido ({})",
                "invalid certificate ({})",
                out.tls
                    .as_ref()
                    .map(|t| t.verify_error.as_str())
                    .unwrap_or("")
            )),
            Some(true) => None,
        };
        if let Some(why) = refuse {
            out.checks.push(check(
                "Login",
                "err",
                tf!(
                    "Non eseguito: {why}. La password si invia solo su TLS con certificato verificato",
                    "Not performed: {why}. The password is sent only over TLS with a verified certificate"
                ),
            ));
        } else if caps.auth.iter().any(|m| m == "PLAIN") {
            let tok = base64(format!("\0{user}\0{pass}").as_bytes());
            let mut r = s
                .cmd(
                    &format!("AUTH PLAIN {tok}"),
                    &format!("AUTH PLAIN {MASK}"),
                    REPLY_TIMEOUT,
                )
                .await?;
            if r.code == 334 {
                r = s.cmd(&tok, MASK, REPLY_TIMEOUT).await?;
            }
            auth_ok = r.code == 235;
            out.checks.push(login_check(user, &r, "PLAIN"));
        } else if caps.auth.iter().any(|m| m == "LOGIN") {
            let mut r = s.cmd("AUTH LOGIN", "AUTH LOGIN", REPLY_TIMEOUT).await?;
            if r.code == 334 {
                let u = base64(user.as_bytes());
                r = s.cmd(&u, &u, REPLY_TIMEOUT).await?;
                if r.code == 334 {
                    r = s.cmd(&base64(pass.as_bytes()), MASK, REPLY_TIMEOUT).await?;
                }
            }
            auth_ok = r.code == 235;
            out.checks.push(login_check(user, &r, "LOGIN"));
        } else {
            out.checks.push(check(
                "Login",
                "err",
                tf!(
                    "Il server non offre AUTH PLAIN o LOGIN ({})",
                    "The server does not offer AUTH PLAIN or LOGIN ({})",
                    if caps.auth.is_empty() {
                        t!("nessun meccanismo", "no mechanism").to_string()
                    } else {
                        caps.auth.join(" ")
                    }
                ),
            ));
        }
    }

    if let Some(m) = &p.send {
        if !auth_ok {
            out.checks.push(check(
                t!("Invio di prova", "Test send"),
                "err",
                t!(
                    "Non eseguito: autenticazione non riuscita",
                    "Not performed: authentication failed"
                ),
            ));
        } else {
            send_mail(s, p, m, out).await?;
        }
    }

    s.quit().await;
    Ok(())
}

fn login_check(user: &str, r: &Reply, mech: &str) -> Check {
    if r.code == 235 {
        check(
            "Login",
            "ok",
            tf!(
                "Autenticato come {user} ({mech}): {}",
                "Authenticated as {user} ({mech}): {}",
                r.text()
            ),
        )
    } else {
        check(
            "Login",
            "err",
            tf!(
                "Autenticazione rifiutata ({mech}): {}",
                "Authentication rejected ({mech}): {}",
                r.text()
            ),
        )
    }
}

async fn send_mail<F: FnMut(Event)>(
    s: &mut Session<F>,
    p: &Plan,
    m: &Mail,
    out: &mut Out,
) -> Result<()> {
    let r = s
        .cmd(
            &format!("MAIL FROM:<{}>", m.from),
            &format!("MAIL FROM:<{}>", m.from),
            REPLY_TIMEOUT,
        )
        .await?;
    if !r.ok() {
        out.checks.push(check(
            t!("Invio di prova", "Test send"),
            "err",
            tf!("Mittente rifiutato: {}", "Sender rejected: {}", r.text()),
        ));
        s.cmd("RSET", "RSET", REPLY_TIMEOUT).await?;
        return Ok(());
    }
    let mut ok = Vec::new();
    let mut ko = Vec::new();
    for rc in &m.rcpts {
        let r = s
            .cmd(
                &format!("RCPT TO:<{rc}>"),
                &format!("RCPT TO:<{rc}>"),
                REPLY_TIMEOUT,
            )
            .await?;
        if r.ok() {
            ok.push(rc.clone());
        } else {
            ko.push(format!("{rc} ({})", r.text()));
        }
    }
    if ok.is_empty() {
        out.checks.push(check(
            t!("Invio di prova", "Test send"),
            "err",
            tf!(
                "Tutti i destinatari rifiutati: {}",
                "All recipients rejected: {}",
                ko.join("; ")
            ),
        ));
        s.cmd("RSET", "RSET", REPLY_TIMEOUT).await?;
        return Ok(());
    }
    let r = s.cmd("DATA", "DATA", REPLY_TIMEOUT).await?;
    if r.code != 354 {
        out.checks.push(check(
            t!("Invio di prova", "Test send"),
            "err",
            tf!("DATA rifiutato: {}", "DATA rejected: {}", r.text()),
        ));
        s.cmd("RSET", "RSET", REPLY_TIMEOUT).await?;
        return Ok(());
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| {
        tf!(
            "Generatore casuale non disponibile: {e}",
            "Random generator not available: {e}"
        )
    })?;
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let (headers, data) = build_message(m, &p.ehlo, util::now_unix() as i64, &id);
    for h in &headers {
        s.log(h.clone());
    }
    s.log(tf!(
        "(corpo in base64, messaggio di {} byte)",
        "(body in base64, message of {} bytes)",
        data.len()
    ));
    s.log(".".into());
    s.mark = Instant::now();
    s.write(data.as_bytes()).await?;
    s.write(b".\r\n").await?;
    let r = s.reply(DATA_TIMEOUT).await?;
    if r.ok() {
        out.sent = true;
        out.checks.push(check(
            t!("Invio di prova", "Test send"),
            if ko.is_empty() { "ok" } else { "warn" },
            tf!(
                "Messaggio accettato per {}: {}{}",
                "Message accepted for {}: {}{}",
                ok.join(", "),
                r.text(),
                if ko.is_empty() {
                    String::new()
                } else {
                    tf!(". Rifiutati: {}", ". Rejected: {}", ko.join("; "))
                }
            ),
        ));
    } else {
        out.checks.push(check(
            t!("Invio di prova", "Test send"),
            "err",
            tf!("Messaggio rifiutato: {}", "Message rejected: {}", r.text()),
        ));
    }
    Ok(())
}

// ───────────────────────── entry point ─────────────────────────

pub async fn run<F: FnMut(Event) + Send>(req: SmtpReq, emit: F) -> Result<SmtpResult> {
    run_with(req, emit, None).await
}

async fn run_with<F: FnMut(Event) + Send>(
    req: SmtpReq,
    emit: F,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<SmtpResult> {
    let p = plan(req)?;
    let ip = net::resolve_v4(&p.host).await?;
    let addr = SocketAddr::new(IpAddr::V4(ip), p.port);
    let dns = tokio::spawn(dns_info(ip));

    let mut s = Session {
        io: None,
        transcript: Vec::new(),
        emit,
        mark: Instant::now(),
    };
    s.log(tf!(
        "Connessione a {}:{} ({})",
        "Connecting to {}:{} ({})",
        ip,
        p.port,
        p.host
    ));
    let t0 = Instant::now();
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            dns.abort();
            return Err(tf!(
                "Porta {} chiusa su {} (connessione rifiutata)",
                "Port {} closed on {} (connection refused)",
                p.port,
                p.host
            ));
        }
        Ok(Err(e)) => {
            dns.abort();
            return Err(tf!(
                "Connessione a {addr} fallita: {}",
                "Connection to {addr} failed: {}",
                ports::connect_error(&e)
            ));
        }
        Err(_) => {
            dns.abort();
            return Err(tf!(
                "Nessuna risposta da {addr} entro {} s: porta filtrata da un firewall",
                "No response from {addr} within {} s: port filtered by a firewall",
                CONNECT_TIMEOUT.as_secs()
            ));
        }
    };
    let connect_ms = t0.elapsed().as_millis() as u64;
    s.mark = t0;
    s.io = Some(BufReader::new(Box::new(tcp)));

    let mut out = Out {
        head: vec![check(
            t!("Connessione", "Connection"),
            if connect_ms < 1000 { "ok" } else { "warn" },
            format!("{connect_ms} ms"),
        )],
        checks: Vec::new(),
        banner: String::new(),
        tls_mode: "none".into(),
        tls: None,
        sent: false,
    };
    if let Err(e) = session(&mut s, &p, &mut out, verifier).await {
        s.log(tf!(
            "--- Sessione interrotta: {e}",
            "--- Session aborted: {e}"
        ));
        out.checks.push(check(t!("Sessione", "Session"), "err", e));
    }
    drop(s.io.take());
    let total_ms = t0.elapsed().as_millis() as u64;
    out.checks.push(check(
        t!("Tempo di transazione", "Transaction time"),
        if total_ms < 5000 { "ok" } else { "warn" },
        format!("{:.3} s", total_ms as f64 / 1000.0),
    ));

    let dns = dns.await.unwrap_or(DnsInfo {
        ptr: String::new(),
        forward: vec![],
    });
    let banner_name = out
        .banner
        .get(4..)
        .and_then(|r| r.split_whitespace().next())
        .filter(|n| n.contains('.') && !n.starts_with('['))
        .unwrap_or("")
        .to_string();
    let mut checks = out.head;
    if !out.banner.is_empty() {
        checks.extend(dns_checks(ip, &dns, &banner_name));
    }
    checks.extend(out.checks);

    // extensions and AUTH mechanisms after the possible STARTTLS
    let extensions = checks
        .iter()
        .find(|c| c.name == "EHLO" && c.status == "ok")
        .map(|c| c.detail.split(", ").map(String::from).collect())
        .unwrap_or_default();
    let auth_mechs = checks
        .iter()
        .find(|c| c.name == t!("Autenticazione offerta", "Authentication offered"))
        .filter(|c| !c.detail.starts_with(t!("Nessun", "No ")))
        .map(|c| c.detail.split(' ').map(String::from).collect())
        .unwrap_or_default();

    Ok(SmtpResult {
        host: p.host,
        ip: ip.to_string(),
        port: p.port,
        ptr: dns.ptr,
        ehlo_name: p.ehlo,
        tls_mode: out.tls_mode,
        banner: out.banner,
        extensions,
        auth_mechs,
        tls: out.tls,
        checks,
        transcript: s.transcript,
        connect_ms,
        total_ms,
        sent: out.sent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    #[derive(Clone, Default)]
    struct Fake {
        /// STARTTLS available with this certificate
        tls: Option<Arc<rustls::ServerConfig>>,
        implicit: bool,
        auth_pre_tls: bool,
        open_relay: bool,
        /// answers STARTTLS with extra data in the same packet
        inject: bool,
        password: String,
    }

    #[derive(Default)]
    struct Seen {
        cmds: Vec<String>,
        data: String,
    }

    fn certs(names: &[&str]) -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "NTB Test CA");
        let ca = ca.self_signed(&ca_key).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut leaf =
            rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, names[0]);
        let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), ca.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        (Arc::new(cfg), ca.der().clone())
    }

    /// Verifier that trusts only the test CA.
    fn trust(ca: CertificateDer<'static>) -> Arc<dyn ServerCertVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap()
    }

    async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(
        io: S,
        f: &Fake,
        seen: &Mutex<Seen>,
        tls: bool,
    ) -> Option<S> {
        let mut r = BufReader::new(io);
        if !tls || f.implicit {
            r.get_mut()
                .write_all(b"220 mx.ntb.test ESMTP Fake\r\n")
                .await
                .ok()?;
        }
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).await.ok()? == 0 {
                return None;
            }
            let l = line.trim_end().to_string();
            if in_data {
                if l == "." {
                    in_data = false;
                    r.get_mut()
                        .write_all(b"250 2.0.0 Ok: queued as ABC123\r\n")
                        .await
                        .ok()?;
                } else {
                    let mut s = seen.lock().unwrap();
                    s.data.push_str(&l);
                    s.data.push('\n');
                }
                continue;
            }
            seen.lock().unwrap().cmds.push(l.clone());
            let up = l.to_uppercase();
            let resp: String = if up.starts_with("EHLO") {
                let mut v = vec![
                    "250-mx.ntb.test".to_string(),
                    "250-PIPELINING".into(),
                    "250-SIZE 10485760".into(),
                ];
                if f.tls.is_some() && !tls && !f.implicit {
                    v.push("250-STARTTLS".into());
                }
                if tls || f.auth_pre_tls {
                    v.push("250-AUTH PLAIN LOGIN".into());
                }
                v.push("250 8BITMIME".into());
                v.join("\r\n") + "\r\n"
            } else if up == "STARTTLS" {
                if f.inject {
                    r.get_mut()
                        .write_all(b"220 Ready\r\n250 iniettato\r\n")
                        .await
                        .ok()?;
                    continue;
                }
                r.get_mut()
                    .write_all(b"220 2.0.0 Ready to start TLS\r\n")
                    .await
                    .ok()?;
                return Some(r.into_inner());
            } else if up.starts_with("AUTH PLAIN ") {
                let tok = base64(format!("\0utente\0{}", f.password).as_bytes());
                if l[11..] == tok {
                    "235 2.7.0 Authentication successful\r\n".into()
                } else {
                    "535 5.7.8 Authentication failed\r\n".into()
                }
            } else if up.starts_with("MAIL FROM:") {
                "250 2.1.0 Ok\r\n".into()
            } else if up.starts_with("RCPT TO:") {
                if up.contains("EXAMPLE.NET") && !f.open_relay {
                    "454 4.7.1 <ntb-relay-test@example.net>: Relay access denied\r\n".into()
                } else if up.contains("NOBODY@") {
                    "550 5.1.1 User unknown\r\n".into()
                } else {
                    "250 2.1.5 Ok\r\n".into()
                }
            } else if up == "DATA" {
                in_data = true;
                "354 End data with <CR><LF>.<CR><LF>\r\n".into()
            } else if up == "RSET" {
                "250 2.0.0 Ok\r\n".into()
            } else if up == "QUIT" {
                r.get_mut().write_all(b"221 2.0.0 Bye\r\n").await.ok()?;
                return None;
            } else {
                "502 5.5.2 Error: command not recognized\r\n".into()
            };
            r.get_mut().write_all(resp.as_bytes()).await.ok()?;
        }
    }

    async fn fake(f: Fake) -> (u16, Arc<Mutex<Seen>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let sn = seen.clone();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            if f.implicit {
                let acc = tokio_rustls::TlsAcceptor::from(f.tls.clone().unwrap());
                let t = acc.accept(s).await.unwrap();
                serve_conn(t, &f, &sn, true).await;
            } else if let Some(plain) = serve_conn(s, &f, &sn, false).await {
                let acc = tokio_rustls::TlsAcceptor::from(f.tls.clone().unwrap());
                if let Ok(t) = acc.accept(plain).await {
                    serve_conn(t, &f, &sn, true).await;
                }
            }
        });
        (port, seen)
    }

    fn req(port: u16) -> SmtpReq {
        SmtpReq {
            host: "localhost".into(),
            port: Some(port as u32),
            ehlo: Some("pc.ntb.test".into()),
            ..SmtpReq::default()
        }
    }

    fn st<'a>(r: &'a SmtpResult, name: &str) -> &'a str {
        r.checks
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.status.as_str())
            .unwrap_or("assente")
    }

    #[test]
    fn codifica_base64() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"\0utente\0pw"), "AHV0ZW50ZQBwdw==");
    }

    #[test]
    fn indirizzi_e_validazione() {
        assert!(valid_addr("mario.rossi@example.com"));
        assert!(valid_addr("a+b@x.local"));
        assert!(!valid_addr("senza-chiocciola"));
        assert!(!valid_addr("a@"));
        assert!(!valid_addr("a b@x.it"));
        assert!(!valid_addr("a@x.it>\r\nRCPT TO:<b@y.it"));
        assert!(!valid_addr("à@x.it"));
        let mut r = req(25);
        r.send = true;
        r.from = "a@x.it".into();
        r.to = "b@y.it".into();
        r.subject = "ciao\r\nBcc: z@z.it".into();
        assert!(plan(r).err().unwrap().contains("oggetto"));
        let mut r = req(25);
        r.ehlo = Some("pc\r\nRSET".into());
        assert!(plan(r).is_err());
        let mut r = req(25);
        r.ehlo = Some("[192.0.2.10]".into());
        assert!(plan(r).is_ok());
        let mut r = req(25);
        r.auth = true;
        r.user = "u".into();
        assert!(plan(r).err().unwrap().contains("password"));
        let mut r = req(25);
        r.send = true;
        r.from = "a@x.it".into();
        r.to = (0..11)
            .map(|i| format!("u{i}@y.it"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(plan(r).err().unwrap().contains("Massimo 10"));
        let mut r = req(25);
        r.port = Some(70000);
        assert!(plan(r).is_err());
    }

    #[test]
    fn messaggio() {
        let m = Mail {
            from: "a@x.it".into(),
            rcpts: vec!["b@y.it".into(), "c@y.it".into()],
            subject: "Prova àèìòù".into(),
            body: ".riga col punto\nseconda".into(),
        };
        let (h, data) = build_message(&m, "pc.ntb.test", 1_793_812_087, "abc");
        assert_eq!(h[0], "Date: Wed, 04 Nov 2026 17:08:07 +0000");
        assert_eq!(h[2], "To: <b@y.it>, <c@y.it>");
        assert_eq!(
            h[3],
            format!("Subject: =?UTF-8?B?{}?=", base64("Prova àèìòù".as_bytes()))
        );
        assert_eq!(h[4], "Message-ID: <abc@pc.ntb.test>");
        assert!(data.contains(&base64(b".riga col punto\r\nseconda")));
        assert!(data.lines().all(|l| l.len() <= 998));
        assert_eq!(dot_stuff(".a\r\nb\r\n..c\r\n"), "..a\r\nb\r\n...c\r\n");
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        let lungo = "è".repeat(60);
        assert!(encode_subject(&lungo).contains("\r\n =?UTF-8?B?"));
    }

    #[test]
    fn nomi_generici() {
        let ip = Ipv4Addr::new(203, 0, 113, 130);
        assert!(generic_name("host130.113.0.203.isp.example", ip));
        assert!(generic_name("203-0-113-130.static.provider.it", ip));
        assert!(generic_name("dsl12.provider.it", ip));
        assert!(generic_name("dynamic.provider.it", ip));
        assert!(!generic_name("mail.example.com", ip));
        assert!(!generic_name("mail01.corp.example", ip));
    }

    #[tokio::test]
    async fn in_chiaro_relay_chiuso_e_invio() {
        let (port, seen) = fake(Fake {
            auth_pre_tls: true,
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.relay = true;
        r.send = true;
        r.from = "giorgio@ntb.test".into();
        r.to = "dest@ntb.test; nobody@ntb.test".into();
        r.subject = "Test SMTP".into();
        r.body = ".punto\nfine".into();
        let mut lines = Vec::new();
        let res = run(r, |e| {
            if let Event::Line(l) = e {
                lines.push(l)
            }
        })
        .await
        .unwrap();
        assert_eq!(lines, res.transcript);
        assert_eq!(res.banner, "220 mx.ntb.test ESMTP Fake");
        assert_eq!(st(&res, "Banner"), "ok");
        assert_eq!(st(&res, "TLS"), "warn");
        assert_eq!(st(&res, "AUTH in chiaro"), "warn");
        assert_eq!(st(&res, "Open relay"), "ok");
        assert_eq!(st(&res, "Invio di prova"), "warn"); // one recipient rejected
        assert_eq!(st(&res, "Dimensione massima"), "info");
        assert!(res.sent);
        assert_eq!(res.tls_mode, "none");
        assert!(res.extensions.contains(&"PIPELINING".to_string()));
        assert_eq!(res.auth_mechs, vec!["PLAIN", "LOGIN"]);
        assert!(res
            .transcript
            .iter()
            .any(|l| l.starts_with("250 2.1.0 Ok [")));
        let s = seen.lock().unwrap();
        assert!(s.cmds.contains(&"EHLO pc.ntb.test".to_string()));
        assert!(s.cmds.contains(&"RSET".to_string()));
        assert_eq!(s.cmds.iter().filter(|c| *c == "DATA").count(), 1);
        assert!(s.data.contains("X-Mailer: Network Toolbox"));
        assert!(s.data.contains(&base64(b".punto\r\nfine")));
        assert_eq!(s.cmds.last().unwrap(), "QUIT");
    }

    #[tokio::test]
    async fn open_relay_senza_data() {
        let (port, seen) = fake(Fake {
            open_relay: true,
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.relay = true;
        let res = run(r, |_| {}).await.unwrap();
        assert_eq!(st(&res, "Open relay"), "err");
        let s = seen.lock().unwrap();
        assert!(!s.cmds.iter().any(|c| c == "DATA"), "{:?}", s.cmds);
        assert!(s
            .cmds
            .contains(&"RCPT TO:<ntb-relay-test@example.net>".to_string()));
    }

    #[tokio::test]
    async fn auth_non_inviata_senza_tls() {
        let (port, seen) = fake(Fake {
            auth_pre_tls: true,
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.auth = true;
        r.user = "utente".into();
        r.password = "Segreta!1".into();
        r.send = true;
        r.from = "a@ntb.test".into();
        r.to = "b@ntb.test".into();
        let res = run(r, |_| {}).await.unwrap();
        assert_eq!(st(&res, "Login"), "err");
        assert_eq!(st(&res, "Invio di prova"), "err");
        let s = seen.lock().unwrap();
        assert!(
            !s.cmds.iter().any(|c| c.starts_with("AUTH") || c == "DATA"),
            "{:?}",
            s.cmds
        );
    }

    #[tokio::test]
    async fn starttls_certificato_non_attendibile() {
        let (cfg, _) = certs(&["localhost"]);
        let (port, seen) = fake(Fake {
            tls: Some(cfg),
            password: "Segreta!1".into(),
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.auth = true;
        r.user = "utente".into();
        r.password = "Segreta!1".into();
        // verifier that does not know the test CA
        let (_, other_ca) = certs(&["altro"]);
        let res = run_with(r, |_| {}, Some(trust(other_ca))).await.unwrap();
        assert_eq!(res.tls_mode, "starttls");
        assert_eq!(st(&res, "TLS"), "warn");
        assert_eq!(st(&res, "Certificato"), "warn");
        assert_eq!(st(&res, "Login"), "err");
        assert!(!res.tls.as_ref().unwrap().verified);
        let s = seen.lock().unwrap();
        assert!(
            !s.cmds.iter().any(|c| c.starts_with("AUTH")),
            "{:?}",
            s.cmds
        );
        assert_eq!(s.cmds.iter().filter(|c| c.starts_with("EHLO")).count(), 2);
    }

    #[tokio::test]
    async fn starttls_verificato_login_e_password_mascherata() {
        let (cfg, ca) = certs(&["localhost"]);
        let (port, seen) = fake(Fake {
            tls: Some(cfg),
            password: "Segreta!1".into(),
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.auth = true;
        r.user = "utente".into();
        r.password = "Segreta!1".into();
        r.send = true;
        r.from = "utente@ntb.test".into();
        r.to = "dest@ntb.test".into();
        let res = run_with(r, |_| {}, Some(trust(ca))).await.unwrap();
        assert_eq!(st(&res, "TLS"), "ok", "{:?}", res.checks);
        assert_eq!(st(&res, "Certificato"), "ok");
        assert_eq!(st(&res, "Login"), "ok");
        assert_eq!(st(&res, "Invio di prova"), "ok");
        assert_eq!(st(&res, "AUTH prima di TLS"), "assente");
        let tok = base64(b"\0utente\0Segreta!1");
        let all = res.transcript.join("\n");
        assert!(!all.contains(&tok) && !all.contains("Segreta"), "{all}");
        assert!(all.contains("AUTH PLAIN ********"));
        assert!(all.contains("--- TLS: TLSv1.3"));
        assert!(seen
            .lock()
            .unwrap()
            .cmds
            .contains(&format!("AUTH PLAIN {tok}")));
    }

    #[tokio::test]
    async fn password_sbagliata() {
        let (cfg, ca) = certs(&["localhost"]);
        let (port, _) = fake(Fake {
            tls: Some(cfg),
            password: "giusta".into(),
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.auth = true;
        r.user = "utente".into();
        r.password = "sbagliata".into();
        let res = run_with(r, |_| {}, Some(trust(ca))).await.unwrap();
        assert_eq!(st(&res, "Login"), "err");
    }

    #[tokio::test]
    async fn tls_implicito() {
        let (cfg, ca) = certs(&["localhost"]);
        let (port, _) = fake(Fake {
            tls: Some(cfg),
            implicit: true,
            ..Fake::default()
        })
        .await;
        let mut r = req(port);
        r.security = Some("implicit".into());
        let res = run_with(r, |_| {}, Some(trust(ca))).await.unwrap();
        assert_eq!(res.tls_mode, "implicit");
        assert_eq!(st(&res, "TLS"), "ok");
        assert_eq!(st(&res, "Banner"), "ok");
        assert!(res.auth_mechs.contains(&"PLAIN".to_string()));
    }

    #[tokio::test]
    async fn iniezione_starttls() {
        let (cfg, ca) = certs(&["localhost"]);
        let (port, _) = fake(Fake {
            tls: Some(cfg),
            inject: true,
            ..Fake::default()
        })
        .await;
        let res = run_with(req(port), |_| {}, Some(trust(ca))).await.unwrap();
        assert_eq!(st(&res, "TLS"), "err");
        assert_eq!(st(&res, "Sessione"), "err");
        assert!(res.tls.is_none());
    }

    #[tokio::test]
    async fn starttls_obbligatorio_assente() {
        let (port, seen) = fake(Fake::default()).await;
        let mut r = req(port);
        r.security = Some("starttls".into());
        r.relay = true;
        let res = run(r, |_| {}).await.unwrap();
        assert_eq!(st(&res, "TLS"), "err");
        assert_eq!(st(&res, "Open relay"), "assente");
        assert!(!seen
            .lock()
            .unwrap()
            .cmds
            .iter()
            .any(|c| c.starts_with("MAIL")));
    }

    #[test]
    fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let mut r = req(25);
        r.auth = true;
        r.user = "u".into();
        let e = plan(r).err().unwrap();
        assert!(e.contains("Enter the password"), "{e}");
        assert!(!e.contains("Indica"), "{e}");
        let d = DnsInfo {
            ptr: String::new(),
            forward: vec![],
        };
        let c = dns_checks(Ipv4Addr::new(192, 0, 2, 1), &d, "");
        assert!(c[0].detail.starts_with("No PTR record"), "{}", c[0].detail);
        assert!(!c[0].detail.contains("Nessun"));
        let m = Mail {
            from: "a@x.it".into(),
            rcpts: vec!["b@y.it".into()],
            subject: String::new(),
            body: String::new(),
        };
        let (_, data) = build_message(&m, "pc.ntb.test", 0, "abc");
        assert!(data.contains(&base64(b"Test message sent by Network Toolbox")[..20]));
    }

    #[tokio::test]
    async fn porta_chiusa() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let e = run(req(port), |_| {}).await.unwrap_err();
        assert!(e.contains("chiusa"), "{e}");
    }
}
