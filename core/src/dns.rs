//! DNS: direct queries to one or more servers (like `dig @server`), with response
//! code, time and records in dig format. The "system resolver" uses the DNS
//! servers and the search suffix configured on this PC.

use crate::{net, t, tf, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub mod domain;
pub mod rdata;

pub const TYPES: [&str; 17] = [
    "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA", "DNSKEY", "DS", "TLSA",
    "HTTPS", "SVCB", "NAPTR", "SSHFP",
];
/// Label of the system resolver, in the current language.
pub fn system_label() -> &'static str {
    t!("resolver di sistema", "system resolver")
}
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
pub struct DnsReq {
    pub host: String,
    #[serde(rename = "type", default)]
    pub rtype: Option<String>,
    /// Servers to query; "" means the system resolver.
    #[serde(default)]
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsResult {
    pub server: String,
    pub server_ip: String,
    /// NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT, ERROR...
    pub status: String,
    pub time_ms: Option<u64>,
    /// Records in dig format: "name TTL IN TYPE data"
    pub answers: Vec<String>,
    /// Only the data part of the records, sorted (for comparing servers)
    pub data: Vec<String>,
    /// Response flags: "AA" (authoritative), "RA" (recursion available),
    /// "AD" (data validated with DNSSEC by the server)
    pub flags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsResponse {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub results: Vec<DnsResult>,
}

/// DNS configuration of the PC: servers and first search suffix.
#[derive(Debug, Clone)]
pub struct SystemDns {
    pub servers: Vec<SocketAddr>,
    pub suffix: Option<String>,
}

/// Usable DNS servers: no site-local IPv6 addresses fec0::/10 (Windows puts
/// fec0:0:0:ffff::1-3 on IPv6 adapters without configured DNS), no link-local
/// or unspecified ones; IPv4 first.
pub fn usable_servers(all: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = Vec::new();
    for a in all {
        let ok = match a.ip() {
            IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_link_local(),
            IpAddr::V6(ip) => {
                let s = ip.segments()[0];
                !ip.is_unspecified() && (s & 0xffc0) != 0xfec0 && (s & 0xffc0) != 0xfe80
            }
        };
        if ok && !v.contains(&a) {
            v.push(a);
        }
    }
    v.sort_by_key(|a| a.is_ipv6());
    v
}

/// System DNS configuration, re-read at most every 30 seconds
/// (it changes when the VPN connects or disconnects).
pub fn system_dns() -> Result<SystemDns> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(Instant, SystemDns)>> = Mutex::new(None);
    if let Some((t, cfg)) = CACHE.lock().unwrap().as_ref() {
        if t.elapsed() < Duration::from_secs(30) {
            return Ok(cfg.clone());
        }
    }
    let cfg = read_system_dns()?;
    *CACHE.lock().unwrap() = Some((Instant::now(), cfg.clone()));
    Ok(cfg)
}

fn read_system_dns() -> Result<SystemDns> {
    let (cfg, _) = hickory_resolver::system_conf::read_system_conf().map_err(|e| {
        tf!(
            "Configurazione DNS di sistema non leggibile: {e}",
            "System DNS configuration cannot be read: {e}"
        )
    })?;
    let servers = usable_servers(cfg.name_servers().iter().map(|ns| ns.socket_addr));
    if servers.is_empty() {
        return Err(t!(
            "Nessun server DNS utilizzabile configurato su questo PC",
            "No usable DNS server configured on this PC"
        )
        .into());
    }
    let suffix = cfg
        .search()
        .first()
        .or(cfg.domain())
        .map(|n| n.to_ascii().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty());
    Ok(SystemDns { servers, suffix })
}

/// Name to query: IP → in-addr.arpa for PTR; short names completed with
/// the PC's DNS suffix ("srv01" → "srv01.corp.example").
pub fn query_name(host: &str, rtype: &str, suffix: Option<&str>) -> String {
    if rtype == "PTR" {
        if let Ok(IpAddr::V4(ip)) = host.parse::<IpAddr>() {
            let o = ip.octets();
            return format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
        }
    }
    match suffix {
        Some(s) if !host.contains('.') => format!("{host}.{s}"),
        _ => host.trim_end_matches('.').to_string(),
    }
}

pub(crate) fn status_name(rc: ResponseCode) -> String {
    match rc {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::Refused => "REFUSED".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        other => format!("{other:?}").to_uppercase(),
    }
}

/// Query ID: random (getrandom), unpredictable to anyone trying to inject responses.
fn query_id() -> std::result::Result<u16, String> {
    let mut b = [0u8; 2];
    getrandom::getrandom(&mut b).map_err(|e| {
        tf!(
            "ERRORE: generatore casuale ({e})",
            "ERROR: random generator ({e})"
        )
    })?;
    Ok(u16::from_be_bytes(b))
}

fn make_query(name: &str, rtype: RecordType) -> Result<Query> {
    let fqdn = Name::from_ascii(format!("{}.", name.trim_end_matches('.')))
        .map_err(|_| tf!("Nome non valido: {name}", "Invalid name: {name}"))?;
    Ok(Query::query(fqdn, rtype))
}

/// How to make a query: normally recursive, over UDP, without DNSSEC.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Opts {
    /// RD=0: to query an authoritative server directly.
    pub no_recursion: bool,
    /// AD bit in the query: asks the resolver to say whether it validated the answer.
    pub ad: bool,
    /// EDNS with the DO bit: the response also carries the signatures (RRSIG).
    pub dnssec: bool,
    /// CD bit: the resolver answers even if validation fails.
    pub cd: bool,
    /// Directly over TCP.
    pub tcp: bool,
}

pub fn build_query(name: &str, rtype: RecordType, id: u16) -> Result<Vec<u8>> {
    encode_query(&make_query(name, rtype)?, id, Opts::default())
}

fn encode_query(q: &Query, id: u16, o: Opts) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(!o.no_recursion)
        .set_authentic_data(o.ad)
        .set_checking_disabled(o.cd);
    if o.dnssec {
        let mut e = hickory_proto::op::Edns::new();
        e.set_dnssec_ok(true).set_max_payload(1232);
        msg.set_edns(e);
    }
    msg.add_query(q.clone());
    msg.to_vec()
        .map_err(|e| tf!("Query DNS non valida: {e}", "Invalid DNS query: {e}"))
}

/// Outcome of comparing a received packet with the query sent.
enum Reply {
    Ok(Box<Message>),
    /// Different ID or a response unrelated to the query: discard it and keep waiting
    Unrelated,
    /// Right ID but the packet cannot be parsed
    Invalid(String),
}

/// A response is valid only if it has the query's ID, is a response (QR=1) of type QUERY and
/// repeats the same question (name case-insensitive, type and class).
/// Without a question section only an error response is accepted (some servers omit it).
fn check_reply(raw: &[u8], id: u16, q: &Query) -> Reply {
    if raw.len() < 12 || u16::from_be_bytes([raw[0], raw[1]]) != id {
        return Reply::Unrelated;
    }
    let m = match Message::from_vec(raw) {
        Ok(m) => m,
        Err(e) => {
            return Reply::Invalid(tf!(
                "ERRORE: risposta non valida ({e})",
                "ERROR: invalid response ({e})"
            ))
        }
    };
    if m.message_type() != MessageType::Response || m.op_code() != OpCode::Query {
        return Reply::Unrelated;
    }
    match m.queries() {
        [one] if one == q => Reply::Ok(Box::new(m)),
        [] if m.response_code() != ResponseCode::NoError => Reply::Ok(Box::new(m)),
        _ => Reply::Unrelated,
    }
}

async fn exchange_udp(
    server: SocketAddr,
    packet: &[u8],
    id: u16,
    q: &Query,
) -> std::result::Result<Message, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let err = |e: std::io::Error| format!("ERRORE: {e}");
    let sock = UdpSocket::bind(bind).await.map_err(err)?;
    // Connected socket: the OS drops packets not coming from the server's IP and port
    sock.connect(server).await.map_err(err)?;
    sock.send(packet).await.map_err(err)?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await.map_err(err)?;
        match check_reply(&buf[..n], id, q) {
            Reply::Ok(m) => return Ok(*m),
            Reply::Unrelated => continue,
            Reply::Invalid(e) => return Err(e),
        }
    }
}

async fn exchange_tcp(server: SocketAddr, packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(server).await?;
    let mut out = (packet.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(packet);
    s.write_all(&out).await?;
    let len = s.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// One query to a server: UDP, and TCP if the response is truncated.
pub async fn query(
    name: &str,
    rtype: RecordType,
    server: SocketAddr,
) -> std::result::Result<(Message, u64), String> {
    query_with(name, rtype, server, Opts::default(), TIMEOUT).await
}

/// Like [`query`], with options and the maximum time (for UDP and, if needed, TCP).
pub async fn query_with(
    name: &str,
    rtype: RecordType,
    server: SocketAddr,
    opts: Opts,
    timeout: Duration,
) -> std::result::Result<(Message, u64), String> {
    let q = make_query(name, rtype)?;
    let t0 = Instant::now();
    let mut msg = None;
    if !opts.tcp {
        let id = query_id()?;
        let packet = encode_query(&q, id, opts)?;
        let m = tokio::time::timeout(timeout, exchange_udp(server, &packet, id, &q))
            .await
            .map_err(|_| "TIMEOUT".to_string())??;
        if !m.truncated() {
            msg = Some(m);
        }
    }
    let msg = match msg {
        Some(m) => m,
        None => tcp_query(&q, server, opts, timeout).await?,
    };
    Ok((msg, t0.elapsed().as_millis() as u64))
}

/// A query over TCP, with a new ID and the same response check.
async fn tcp_query(
    q: &Query,
    server: SocketAddr,
    opts: Opts,
    timeout: Duration,
) -> std::result::Result<Message, String> {
    let id = query_id()?;
    let packet = encode_query(q, id, opts)?;
    let raw = tokio::time::timeout(timeout, exchange_tcp(server, &packet))
        .await
        .map_err(|_| "TIMEOUT".to_string())?
        .map_err(|e| format!("ERRORE: {e}"))?;
    match check_reply(&raw, id, q) {
        Reply::Ok(m) => Ok(*m),
        Reply::Invalid(e) => Err(e),
        Reply::Unrelated => Err(t!(
            "ERRORE: la risposta TCP non corrisponde alla query",
            "ERROR: the TCP response does not match the query"
        )
        .into()),
    }
}

/// Tries the servers in order until one answers. Also returns the server used.
pub async fn query_any(
    name: &str,
    rtype: RecordType,
    servers: &[SocketAddr],
) -> std::result::Result<(Message, u64, SocketAddr), String> {
    query_any_with(name, rtype, servers, Opts::default()).await
}

pub async fn query_any_with(
    name: &str,
    rtype: RecordType,
    servers: &[SocketAddr],
    opts: Opts,
) -> std::result::Result<(Message, u64, SocketAddr), String> {
    let mut last = t!("Nessun server DNS", "No DNS server").to_string();
    for s in servers {
        match query_with(name, rtype, *s, opts, TIMEOUT).await {
            Ok((m, ms)) => return Ok((m, ms, *s)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Data of the DNSSEC types, which `hickory-proto` delivers as raw bytes.
fn raw_text(r: &hickory_proto::rr::Record) -> Option<String> {
    match r.data() {
        Some(hickory_proto::rr::RData::Unknown { code, rdata }) => {
            rdata::text(u16::from(*code), rdata.anything())
        }
        _ => None,
    }
}

/// Record in dig format: "name TTL IN TYPE data".
pub fn record_text(r: &hickory_proto::rr::Record) -> String {
    match raw_text(r) {
        Some(t) => format!(
            "{} {} {} {} {t}",
            r.name(),
            r.ttl(),
            r.dns_class(),
            r.record_type()
        ),
        None => r.to_string(),
    }
}

/// Only the data of a record.
pub fn record_value(r: &hickory_proto::rr::Record) -> String {
    raw_text(r).unwrap_or_else(|| record_data(&r.to_string()))
}

/// Response flags relevant to anyone comparing servers.
pub fn flags(msg: &Message) -> Vec<String> {
    [
        (msg.authoritative(), "AA"),
        (msg.recursion_available(), "RA"),
        (msg.authentic_data(), "AD"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, f)| f.to_string())
    .collect()
}

fn record_lines(msg: &Message) -> Vec<String> {
    msg.answers()
        .iter()
        .chain(msg.name_servers().iter())
        .map(record_text)
        .collect()
}

fn record_data(line: &str) -> String {
    line.split_whitespace()
        .skip(4)
        .collect::<Vec<_>>()
        .join(" ")
}

async fn one(name: &str, rtype: RecordType, label: String, servers: Vec<SocketAddr>) -> DnsResult {
    let mut r = DnsResult {
        server: label,
        server_ip: servers
            .first()
            .map(|s| s.ip().to_string())
            .unwrap_or_default(),
        status: String::new(),
        time_ms: None,
        answers: vec![],
        data: vec![],
        flags: vec![],
    };
    // with the AD bit in the query, a validating resolver says so in the response
    let opts = Opts {
        ad: true,
        ..Opts::default()
    };
    match query_any_with(name, rtype, &servers, opts).await {
        Ok((msg, ms, used)) => {
            r.server_ip = used.ip().to_string();
            r.status = status_name(msg.response_code());
            r.time_ms = Some(ms);
            r.answers = record_lines(&msg);
            r.flags = flags(&msg);
            let mut data: Vec<String> = msg.answers().iter().map(record_value).collect();
            data.sort();
            data.dedup();
            r.data = data;
        }
        Err(e) => r.status = e,
    }
    r
}

/// Address of a server given by the user: IP or name, port 53.
async fn server_addr(s: &str) -> Result<SocketAddr> {
    let host = net::clean_host(s)?;
    let ip = net::resolve_v4(&host).await?;
    Ok(SocketAddr::new(IpAddr::V4(ip), 53))
}

pub async fn run(req: DnsReq) -> Result<DnsResponse> {
    let host = net::clean_host(&req.host)?;
    let rtype = req.rtype.as_deref().unwrap_or("A").trim().to_uppercase();
    if !TYPES.contains(&rtype.as_str()) {
        return Err(t!("Tipo record non supportato", "Unsupported record type").into());
    }
    let rt = RecordType::from_str(&rtype)
        .map_err(|_| t!("Tipo record non supportato", "Unsupported record type").to_string())?;

    let mut servers: Vec<String> = Vec::new();
    for s in req.servers.iter().map(|s| s.trim().to_string()) {
        if !servers.contains(&s) {
            servers.push(s);
        }
    }
    if servers.is_empty() {
        servers.push(String::new());
    }
    if servers.len() > 6 {
        return Err(t!(
            "Massimo 6 server per confronto",
            "At most 6 servers per comparison"
        )
        .into());
    }

    let sys = system_dns().ok();
    let name = query_name(
        &host,
        &rtype,
        sys.as_ref().and_then(|s| s.suffix.as_deref()),
    );

    let mut jobs = Vec::new();
    for s in servers {
        let (label, addr) = if s.is_empty() {
            let sys = sys.as_ref().ok_or_else(|| {
                t!(
                    "Configurazione DNS di sistema non leggibile",
                    "System DNS configuration cannot be read"
                )
            })?;
            (system_label().to_string(), sys.servers.clone())
        } else {
            (
                s.clone(),
                vec![server_addr(&s)
                    .await
                    .map_err(|e| format!("Server {s}: {e}"))?],
            )
        };
        let name = name.clone();
        jobs.push(tokio::spawn(
            async move { one(&name, rt, label, addr).await },
        ));
    }
    let mut results = Vec::new();
    for j in jobs {
        results.push(j.await.map_err(|e| e.to_string())?);
    }
    Ok(DnsResponse {
        name,
        rtype,
        results,
    })
}

/// A addresses of a name (used by the blacklists): response code and addresses.
pub async fn lookup_a(
    name: &str,
    servers: &[SocketAddr],
) -> std::result::Result<(String, Vec<Ipv4Addr>), String> {
    let (msg, _, _) = query_any(name, RecordType::A, servers).await?;
    let ips = msg
        .answers()
        .iter()
        .filter_map(|r| record_data(&r.to_string()).parse().ok())
        .collect();
    Ok((status_name(msg.response_code()), ips))
}

pub async fn lookup_txt(name: &str, servers: &[SocketAddr]) -> Vec<String> {
    txt(name, servers).await.unwrap_or_default()
}

/// TXT records as text (the strings of a record are concatenated, as
/// SPF and DKIM do with long keys).
pub async fn txt(name: &str, servers: &[SocketAddr]) -> std::result::Result<Vec<String>, String> {
    use hickory_proto::rr::RData;
    let (msg, _, _) = query_any(name, RecordType::TXT, servers).await?;
    Ok(msg
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::TXT(t)) => Some(
                t.txt_data()
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect(),
            ),
            _ => None,
        })
        .collect())
}

/// MX records as "priority server", sorted by priority.
pub async fn mx(name: &str, servers: &[SocketAddr]) -> std::result::Result<Vec<String>, String> {
    use hickory_proto::rr::RData;
    let (msg, _, _) = query_any(name, RecordType::MX, servers).await?;
    let mut v: Vec<(u16, String)> = msg
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::MX(m)) => Some((m.preference(), m.exchange().to_ascii())),
            _ => None,
        })
        .collect();
    v.sort();
    Ok(v.into_iter().map(|(p, h)| format!("{p} {h}")).collect())
}

/// PTR record of an IPv4 through the PC's DNS. Empty if there is none.
pub async fn ptr(ip: Ipv4Addr) -> String {
    let Ok(sys) = system_dns() else {
        return String::new();
    };
    let o = ip.octets();
    let name = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    match query_any(&name, RecordType::PTR, &sys.servers).await {
        Ok((msg, _, _)) => msg
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::PTR)
            .map(|r| {
                record_data(&r.to_string())
                    .trim_end_matches('.')
                    .to_string()
            })
            .find(|n| !n.is_empty())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nomi() {
        assert_eq!(
            query_name("192.0.2.31", "PTR", None),
            "31.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            query_name("srv01", "A", Some("corp.example")),
            "srv01.corp.example"
        );
        assert_eq!(
            query_name("www.example.com", "A", Some("corp.example")),
            "www.example.com"
        );
        assert_eq!(query_name("example.com.", "MX", None), "example.com");
    }

    #[test]
    fn pacchetto_e_risposta() {
        let q = build_query("example.com", RecordType::MX, 0xBEEF).unwrap();
        let m = Message::from_vec(&q).unwrap();
        assert_eq!(m.id(), 0xBEEF);
        assert!(m.recursion_desired());
        assert_eq!(m.queries()[0].query_type(), RecordType::MX);
        assert_eq!(m.queries()[0].name().to_ascii(), "example.com.");
    }

    /// Test DNS server: over UDP it answers "truncated", over TCP with two MX records.
    async fn fake_server() -> SocketAddr {
        use hickory_proto::rr::rdata::MX;
        use hickory_proto::rr::{RData, Record};
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
        let reply = |req: &[u8], truncated: bool| {
            let q = Message::from_vec(req).unwrap();
            let mut r = Message::new();
            r.set_id(q.id())
                .set_message_type(MessageType::Response)
                .set_truncated(truncated);
            r.add_query(q.queries()[0].clone());
            if !truncated {
                let name = q.queries()[0].name().clone();
                for (pref, mx) in [(20, "mx2.example.com."), (10, "mx1.example.com.")] {
                    r.add_answer(Record::from_rdata(
                        name.clone(),
                        300,
                        RData::MX(MX::new(pref, Name::from_ascii(mx).unwrap())),
                    ));
                }
            }
            r.to_vec().unwrap()
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            udp.send_to(&reply(&buf[..n], true), from).await.unwrap();
        });
        tokio::spawn(async move {
            let (mut s, _) = tcp.accept().await.unwrap();
            let len = s.read_u16().await.unwrap() as usize;
            let mut req = vec![0u8; len];
            s.read_exact(&mut req).await.unwrap();
            let resp = reply(&req, false);
            s.write_all(&(resp.len() as u16).to_be_bytes())
                .await
                .unwrap();
            s.write_all(&resp).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn udp_troncato_poi_tcp() {
        let server = fake_server().await;
        let r = one("example.com", RecordType::MX, "prova".into(), vec![server]).await;
        assert_eq!(r.status, "NOERROR");
        assert_eq!(r.answers.len(), 2);
        assert!(
            r.answers[0].starts_with("example.com. 300 IN MX "),
            "{}",
            r.answers[0]
        );
        assert_eq!(r.data, vec!["10 mx1.example.com.", "20 mx2.example.com."]);
    }

    #[tokio::test]
    async fn txt_concatenato() {
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{RData, Record};
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut r = Message::new();
            r.set_id(q.id()).set_message_type(MessageType::Response);
            r.add_query(q.queries()[0].clone());
            let txt = TXT::new(vec!["v=DKIM1; k=rsa; p=AAAA".into(), "BBBB".into()]);
            r.add_answer(Record::from_rdata(
                q.queries()[0].name().clone(),
                3600,
                RData::TXT(txt),
            ));
            udp.send_to(&r.to_vec().unwrap(), from).await.unwrap();
        });
        let v = txt("selector1._domainkey.example.com", &[addr])
            .await
            .unwrap();
        assert_eq!(v, vec!["v=DKIM1; k=rsa; p=AAAABBBB"]);
    }

    #[tokio::test]
    async fn timeout_server_muto() {
        let muto = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r = one(
            "example.com",
            RecordType::A,
            "muto".into(),
            vec![muto.local_addr().unwrap()],
        )
        .await;
        assert_eq!(r.status, "TIMEOUT");
    }

    #[tokio::test]
    async fn passa_al_server_successivo() {
        let muto = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let buono = fake_server().await;
        let servers = vec![muto.local_addr().unwrap(), buono];
        let r = one("example.com", RecordType::MX, "sistema".into(), servers).await;
        assert_eq!(r.status, "NOERROR");
        assert_eq!(r.server_ip, "127.0.0.1");
        assert_eq!(r.data.len(), 2);
    }

    #[test]
    fn server_utilizzabili() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let v = usable_servers([
            a("[fec0:0:0:ffff::1]:53"),
            a("[fe80::1]:53"),
            a("[2001:db8::53]:53"),
            a("192.0.2.53:53"),
            a("192.0.2.53:53"),
            a("192.0.2.54:53"),
        ]);
        assert_eq!(
            v,
            vec![
                a("192.0.2.53:53"),
                a("192.0.2.54:53"),
                a("[2001:db8::53]:53")
            ]
        );
    }

    #[test]
    fn dati_record() {
        assert_eq!(
            record_data("example.com. 300 IN MX 10 mail.example.com."),
            "10 mail.example.com."
        );
        assert_eq!(status_name(ResponseCode::NXDomain), "NXDOMAIN");
    }

    /// A response for `name` with address `ip`, ID and question taken from `req` (or forced).
    fn a_reply(req: &[u8], id: Option<u16>, name: Option<&str>, ip: [u8; 4]) -> Vec<u8> {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};
        let q = Message::from_vec(req).unwrap();
        let mut query = q.queries()[0].clone();
        if let Some(n) = name {
            query.set_name(Name::from_ascii(n).unwrap());
        }
        let mut r = Message::new();
        r.set_id(id.unwrap_or(q.id()))
            .set_message_type(MessageType::Response);
        r.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A::from(Ipv4Addr::from(ip))),
        ));
        r.add_query(query);
        r.to_vec().unwrap()
    }

    #[tokio::test]
    async fn risposte_iniettate_scartate() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let req = buf[..n].to_vec();
            let id = u16::from_be_bytes([req[0], req[1]]);
            // right ID and question, but from another port
            spoof
                .send_to(&a_reply(&req, None, None, [6, 6, 6, 1]), from)
                .await
                .unwrap();
            // from the server, but with a different ID
            udp.send_to(&a_reply(&req, Some(id ^ 1), None, [6, 6, 6, 2]), from)
                .await
                .unwrap();
            // from the server with the right ID, but for another name
            udp.send_to(
                &a_reply(&req, None, Some("evil.example."), [6, 6, 6, 3]),
                from,
            )
            .await
            .unwrap();
            // the query sent back (QR=0)
            udp.send_to(&req, from).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            // the real one, with the name in upper case (0x20): still valid
            udp.send_to(
                &a_reply(&req, None, Some("WWW.Example.COM."), [192, 0, 2, 7]),
                from,
            )
            .await
            .unwrap();
        });
        let (status, ips) = lookup_a("www.example.com", &[addr]).await.unwrap();
        assert_eq!(status, "NOERROR");
        assert_eq!(ips, vec![Ipv4Addr::new(192, 0, 2, 7)]);
    }

    #[tokio::test]
    async fn tcp_con_domanda_diversa() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut r = Message::new();
            r.set_id(q.id())
                .set_message_type(MessageType::Response)
                .set_truncated(true);
            r.add_query(q.queries()[0].clone());
            udp.send_to(&r.to_vec().unwrap(), from).await.unwrap();
        });
        tokio::spawn(async move {
            let (mut s, _) = tcp.accept().await.unwrap();
            let len = s.read_u16().await.unwrap() as usize;
            let mut req = vec![0u8; len];
            s.read_exact(&mut req).await.unwrap();
            let resp = a_reply(&req, None, Some("evil.example."), [6, 6, 6, 6]);
            s.write_all(&(resp.len() as u16).to_be_bytes())
                .await
                .unwrap();
            s.write_all(&resp).await.unwrap();
        });
        let e = query("www.example.com", RecordType::A, addr)
            .await
            .unwrap_err();
        assert!(e.contains("non corrisponde"), "{e}");
    }

    #[test]
    fn id_casuali() {
        let ids: std::collections::HashSet<u16> = (0..200).map(|_| query_id().unwrap()).collect();
        assert!(ids.len() > 190, "{}", ids.len());
    }

    #[tokio::test]
    async fn errors_in_english() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let req = |t: &str| DnsReq {
            host: "example.com".into(),
            rtype: Some(t.into()),
            servers: vec![],
        };
        let e = run(req("ZZZ")).await.map(|_| ()).unwrap_err();
        assert_eq!(e, "Unsupported record type");
        let e = run(DnsReq {
            servers: (0..7).map(|i| format!("192.0.2.{i}")).collect(),
            ..req("A")
        })
        .await
        .map(|_| ())
        .unwrap_err();
        assert_eq!(e, "At most 6 servers per comparison");
        assert_eq!(system_label(), "system resolver");
        assert!(!e.contains("Massimo"));
    }
}
