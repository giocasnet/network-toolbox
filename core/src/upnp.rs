//! UPnP scan: finds the devices that answer SSDP (`M-SEARCH`) on the local
//! network and reads their description (manufacturer, model, services).
//!
//! Read only: it sends the multicast search to 239.255.255.250:1900 on every
//! IPv4 adapter, collects the unicast replies, then downloads the description XML
//! of every device (`LOCATION`) **only if the URL points to the address that
//! answered** (a device that points elsewhere would make the app fetch an
//! arbitrary URL: it is reported, not followed). No SOAP action is ever sent: the
//! port mappings of a gateway are not read.
//!
//! The XML is read with a small tag extractor (device descriptions are flat and
//! have no attributes of interest); `parse_response`, `parse_description`,
//! `build` and `checks` are pure functions.

use crate::http::analyze::{check, Check};
use crate::mcast::{local_v4, open};
use crate::ping::Stop;
use crate::util::csv_field;
use crate::{t, tf};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

const SSDP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
const AREA: &str = "UPnP";
/// The search is repeated at this tick interval (packets can be lost).
const RESEND: u32 = 4;
const MAX_XML: usize = 256 * 1024;
/// Descriptions read at the same time.
const FETCH_PARALLEL: usize = 8;
/// Devices described at most (the rest is listed without description).
const MAX_DESCRIBE: usize = 64;
/// Limits of one search: whatever the devices answer, memory stays bounded.
const MAX_FOUND: usize = 512;
const MAX_PER_FOUND: usize = 32;
/// Datagrams waiting to be read: beyond this they are dropped, as UDP would.
const QUEUE: usize = 512;

// ───────────────────────── request and response ─────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpnpReq {
    /// Listening time in seconds (2 to 30, default 5).
    #[serde(default, deserialize_with = "crate::util::opt_u32")]
    pub seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct USvc {
    pub service_type: String,
    /// "WANIPConnection" from "urn:schemas-upnp-org:service:WANIPConnection:1".
    pub short: String,
    pub control_url: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct UDevice {
    pub ip: String,
    pub location: String,
    pub server: String,
    /// Short device type ("InternetGatewayDevice"), "" if unknown.
    pub kind: String,
    /// Readable name of the type ("" if unknown).
    pub label: String,
    pub friendly_name: String,
    pub manufacturer: String,
    pub manufacturer_url: String,
    pub model_name: String,
    pub model_number: String,
    pub model_description: String,
    pub serial_number: String,
    pub udn: String,
    pub presentation_url: String,
    pub device_type: String,
    pub services: Vec<USvc>,
    /// Embedded devices (short types).
    pub embedded: Vec<String>,
    /// Search targets the device answered to.
    pub targets: Vec<String>,
    /// Was the description read?
    pub described: bool,
    /// Why it was not ("" if it was).
    pub note: String,
    /// Internet Gateway Device: can open ports on the router.
    pub igd: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpnpResult {
    pub devices: Vec<UDevice>,
    pub n_devices: usize,
    pub n_services: usize,
    pub n_ifaces: usize,
    pub seconds: u64,
    /// Stopped by the user before the end.
    pub stopped: bool,
    pub checks: Vec<Check>,
    pub csv: String,
}

// ───────────────────────── SSDP replies ─────────────────────────

/// A reply to the search, headers lowercase-keyed.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Reply {
    pub location: String,
    pub server: String,
    pub st: String,
    pub usn: String,
}

/// `None` if it is not an "HTTP/1.1 200" reply (a `NOTIFY` or a search of someone else).
pub(crate) fn parse_response(raw: &[u8]) -> Option<Reply> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let first = lines.next()?;
    if !(first.starts_with("HTTP/1.1 200") || first.starts_with("HTTP/1.0 200")) {
        return None;
    }
    let mut r = Reply::default();
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = clean(v);
        match k.trim().to_ascii_lowercase().as_str() {
            "location" => r.location = v,
            "server" => r.server = v,
            "st" => r.st = v,
            "usn" => r.usn = v,
            _ => {}
        }
    }
    (!r.location.is_empty() || !r.usn.is_empty()).then_some(r)
}

#[derive(Default)]
struct Found {
    from: BTreeSet<IpAddr>,
    server: String,
    location: String,
    targets: BTreeSet<String>,
    usn: BTreeSet<String>,
}

#[derive(Default)]
pub(crate) struct Book {
    /// location (or USN if missing) → what answered
    found: BTreeMap<String, Found>,
    /// a limit was reached: the result is partial
    capped: bool,
}

impl Book {
    /// `true` if something new was learnt.
    pub(crate) fn ingest(&mut self, r: Reply, from: IpAddr) -> bool {
        let k = if r.location.is_empty() {
            r.usn.split("::").next().unwrap_or("").to_string()
        } else {
            r.location.clone()
        };
        if !self.found.contains_key(&k) && self.found.len() >= MAX_FOUND {
            self.capped = true;
            return false;
        }
        let f = self.found.entry(k).or_default();
        let mut changed = false;
        if f.from.len() < MAX_PER_FOUND {
            changed |= f.from.insert(from);
        }
        if f.server.is_empty() {
            f.server = r.server;
        }
        if f.location.is_empty() {
            f.location = r.location;
        }
        if !r.st.is_empty() && f.targets.len() < MAX_PER_FOUND {
            changed |= f.targets.insert(r.st);
        }
        if !r.usn.is_empty() && f.usn.len() < MAX_PER_FOUND {
            changed |= f.usn.insert(r.usn);
        }
        changed
    }
}

// ───────────────────────── description XML ─────────────────────────

fn clean(s: &str) -> String {
    unescape(s.trim())
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_string()
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Content of the first `<name>…</name>`.
fn tag(xml: &str, name: &str) -> Option<String> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let a = xml.find(&open)? + open.len();
    let b = xml[a..].find(&close)? + a;
    Some(clean(&xml[a..b]))
}

/// All the `<name>…</name>` of the text.
fn tags(xml: &str, name: &str) -> Vec<String> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(a) = rest.find(&open) {
        let from = a + open.len();
        let Some(b) = rest[from..].find(&close) else {
            break;
        };
        out.push(clean(&rest[from..from + b]));
        rest = &rest[from + b + close.len()..];
    }
    out
}

/// "urn:schemas-upnp-org:device:MediaServer:1" → "MediaServer".
fn urn_short(s: &str) -> String {
    s.split(':').nth(3).unwrap_or(s).to_string()
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Desc {
    pub device_type: String,
    pub friendly_name: String,
    pub manufacturer: String,
    pub manufacturer_url: String,
    pub model_name: String,
    pub model_number: String,
    pub model_description: String,
    pub serial_number: String,
    pub udn: String,
    pub presentation_url: String,
    pub services: Vec<USvc>,
    pub embedded: Vec<String>,
}

pub(crate) fn parse_description(xml: &str) -> Option<Desc> {
    let start = xml.find("<device>")?;
    let xml = &xml[start..];
    // the embedded devices sit between the first <deviceList> and the last </deviceList>
    let (root, nested) = match (xml.find("<deviceList>"), xml.rfind("</deviceList>")) {
        (Some(a), Some(b)) if b > a => (
            format!("{}{}", &xml[..a], &xml[b + "</deviceList>".len()..]),
            xml[a..b].to_string(),
        ),
        _ => (xml.to_string(), String::new()),
    };
    let f = |n: &str| tag(&root, n).unwrap_or_default();
    let mut d = Desc {
        device_type: f("deviceType"),
        friendly_name: f("friendlyName"),
        manufacturer: f("manufacturer"),
        manufacturer_url: f("manufacturerURL"),
        model_name: f("modelName"),
        model_number: f("modelNumber"),
        model_description: f("modelDescription"),
        serial_number: f("serialNumber"),
        udn: f("UDN"),
        presentation_url: f("presentationURL"),
        ..Desc::default()
    };
    d.embedded = tags(&nested, "deviceType")
        .iter()
        .map(|s| urn_short(s))
        .collect();
    // every service, also those of the embedded devices
    let mut rest = xml;
    while let Some(a) = rest.find("<service>") {
        let Some(b) = rest[a..].find("</service>") else {
            break;
        };
        let block = &rest[a..a + b];
        let st = tag(block, "serviceType").unwrap_or_default();
        if !st.is_empty() {
            d.services.push(USvc {
                short: urn_short(&st),
                service_type: st,
                control_url: tag(block, "controlURL").unwrap_or_default(),
            });
        }
        rest = &rest[a + b + "</service>".len()..];
    }
    Some(d)
}

/// Readable name of a device type, "" if unknown.
pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "InternetGatewayDevice" => t!("Router / gateway (IGD)", "Router / gateway (IGD)"),
        "WANDevice" | "WANConnectionDevice" | "LANDevice" => {
            t!("Parte di un router", "Router part")
        }
        "MediaServer" => t!("Server multimediale (DLNA)", "Media server (DLNA)"),
        "MediaRenderer" => t!("Riproduttore multimediale (DLNA)", "Media renderer (DLNA)"),
        "Printer" | "PrinterBasic" | "PrinterEnhanced" => t!("Stampante", "Printer"),
        "ScannerDevice" => "Scanner",
        "WFADevice" => "Wi-Fi Alliance",
        "ZonePlayer" => "Sonos",
        "Basic" => t!("Dispositivo generico", "Generic device"),
        "DimmableLight" | "BinaryLight" => t!("Luce", "Light"),
        "HVAC_System" => "HVAC",
        _ => "",
    }
}

// ───────────────────────── result ─────────────────────────

fn is_igd(kind: &str, services: &[USvc], embedded: &[String], targets: &[String]) -> bool {
    kind == "InternetGatewayDevice"
        || embedded.iter().any(|e| e == "InternetGatewayDevice")
        || services
            .iter()
            .any(|s| matches!(s.short.as_str(), "WANIPConnection" | "WANPPPConnection"))
        || targets
            .iter()
            .any(|x| x.contains(":InternetGatewayDevice:"))
}

/// `described`: location → description (or the reason it was not read).
pub(crate) fn build(
    book: &Book,
    described: &BTreeMap<String, Result<Desc, String>>,
    n_ifaces: usize,
    seconds: u64,
) -> UpnpResult {
    let mut devices: Vec<UDevice> = Vec::new();
    for (k, f) in &book.found {
        let targets: Vec<String> = f.targets.iter().cloned().collect();
        // a type taken from the search targets, for devices that could not be described
        let st_kind = targets
            .iter()
            .filter(|x| x.contains(":device:"))
            .map(|x| urn_short(x))
            .find(|x| !x.is_empty())
            .unwrap_or_default();
        let mut d = UDevice {
            ip: f
                .from
                .iter()
                .next()
                .map(|a| a.to_string())
                .unwrap_or_default(),
            location: f.location.clone(),
            server: f.server.clone(),
            kind: st_kind,
            targets,
            ..UDevice::default()
        };
        if d.location.is_empty() {
            d.note = t!("Nessun LOCATION nella risposta", "No LOCATION in the reply").to_string();
        }
        match described.get(k) {
            Some(Ok(x)) => {
                d.described = true;
                d.device_type = x.device_type.clone();
                let short = urn_short(&x.device_type);
                if !short.is_empty() {
                    d.kind = short;
                }
                d.friendly_name = x.friendly_name.clone();
                d.manufacturer = x.manufacturer.clone();
                d.manufacturer_url = x.manufacturer_url.clone();
                d.model_name = x.model_name.clone();
                d.model_number = x.model_number.clone();
                d.model_description = x.model_description.clone();
                d.serial_number = x.serial_number.clone();
                d.udn = x.udn.clone();
                d.presentation_url = x.presentation_url.clone();
                d.services = x.services.clone();
                d.embedded = x.embedded.clone();
            }
            Some(Err(e)) => d.note = e.clone(),
            None => {}
        }
        d.label = kind_label(&d.kind).to_string();
        d.igd = is_igd(&d.kind, &d.services, &d.embedded, &d.targets);
        devices.push(d);
    }
    devices.sort_by(|a, b| {
        let ip = |x: &UDevice| x.ip.parse::<IpAddr>().ok();
        (ip(a), &a.location).cmp(&(ip(b), &b.location))
    });
    let mut r = UpnpResult {
        n_devices: devices.len(),
        n_services: devices.iter().map(|d| d.services.len()).sum(),
        n_ifaces,
        seconds,
        stopped: false,
        devices,
        checks: Vec::new(),
        csv: String::new(),
    };
    r.checks = checks(&r);
    r.csv = csv(&r);
    r
}

pub(crate) fn checks(r: &UpnpResult) -> Vec<Check> {
    let mut c = Vec::new();
    if r.devices.is_empty() {
        c.push(check(
            AREA,
            "info",
            t!("Nessuna risposta", "No reply"),
            tf!(
                "Nessun dispositivo UPnP ha risposto in {s} s su {n} schede. Normale su una rete senza router, stampanti o TV con UPnP; altrimenti controlla il firewall (UDP 1900) e ricorda che il multicast non attraversa i router.",
                "No UPnP device replied within {s} s on {n} adapters. Normal on a network without UPnP routers, printers or TVs; otherwise check the firewall (UDP 1900) and remember that multicast does not cross routers.",
                s = r.seconds,
                n = r.n_ifaces
            ),
        ));
        return c;
    }
    c.push(check(
        AREA,
        "ok",
        t!("Dispositivi trovati", "Devices found"),
        tf!(
            "{d} dispositivi UPnP, {s} servizi dichiarati",
            "{d} UPnP devices, {s} declared services",
            d = r.n_devices,
            s = r.n_services
        ),
    ));
    for d in r.devices.iter().filter(|d| d.igd) {
        c.push(check(
            AREA,
            "warn",
            t!("UPnP attivo su un router", "UPnP enabled on a router"),
            tf!(
                "{name} ({ip}) è un Internet Gateway Device: qualunque programma della rete può chiedergli di aprire porte verso Internet senza autenticazione. Se non serve, disattiva UPnP sul router.",
                "{name} ({ip}) is an Internet Gateway Device: any program on the network can ask it to open ports to the Internet without authentication. If it is not needed, turn UPnP off on the router.",
                name = if d.friendly_name.is_empty() { &d.ip } else { &d.friendly_name },
                ip = d.ip
            ),
        ));
    }
    let prefix = t!(
        "LOCATION su un altro indirizzo",
        "LOCATION on another address"
    );
    let moved: Vec<&str> = r
        .devices
        .iter()
        .filter(|d| d.note.starts_with(prefix))
        .map(|d| d.ip.as_str())
        .collect();
    if !moved.is_empty() {
        c.push(check(
            AREA,
            "warn",
            t!("LOCATION verso un altro indirizzo", "LOCATION pointing elsewhere"),
            tf!(
                "{n} dispositivi indicano un indirizzo diverso da quello che ha risposto ({l}): la descrizione non è stata letta. Può essere un ripetitore o un tentativo di far contattare un indirizzo arbitrario.",
                "{n} devices point to an address other than the one that replied ({l}): the description was not read. It may be a repeater or an attempt to make the app contact an arbitrary address.",
                n = moved.len(),
                l = moved.join(", ")
            ),
        ));
    }
    let failed = r
        .devices
        .iter()
        .filter(|d| {
            !d.described
                && !d.location.is_empty()
                && !d.note.is_empty()
                && !d.note.starts_with(prefix)
        })
        .count();
    if failed > 0 {
        c.push(check(
            AREA,
            "info",
            t!("Descrizione non letta", "Description not read"),
            tf!(
                "{n} dispositivi hanno risposto ma la loro descrizione non è stata scaricata (vedi la nota di ogni dispositivo)",
                "{n} devices replied but their description could not be downloaded (see each device's note)",
                n = failed
            ),
        ));
    }
    c
}

pub fn csv(r: &UpnpResult) -> String {
    let mut out = vec![t!(
        "IP;Nome;Produttore;Modello;Tipo;Servizi;Descrizione",
        "IP;Name;Manufacturer;Model;Type;Services;Description"
    )
    .to_string()];
    for d in &r.devices {
        let model = format!("{} {}", d.model_name, d.model_number);
        let svc = d
            .services
            .iter()
            .map(|s| s.short.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        out.push(
            [
                d.ip.as_str(),
                d.friendly_name.as_str(),
                d.manufacturer.as_str(),
                model.trim(),
                d.kind.as_str(),
                svc.as_str(),
                d.location.as_str(),
            ]
            .iter()
            .map(|x| csv_field(x))
            .collect::<Vec<_>>()
            .join(";"),
        );
    }
    out.join("\r\n")
}

// ───────────────────────── network ─────────────────────────

pub(crate) struct Env {
    pub dest: SocketAddr,
    pub locals: Vec<Ipv4Addr>,
    pub multicast: bool,
    pub step: Duration,
    pub fetch_timeout: Duration,
}

pub async fn run(req: UpnpReq, stop: &Stop) -> crate::Result<UpnpResult> {
    let s = req.seconds.unwrap_or(5);
    if !(2..=30).contains(&s) {
        return Err(t!("Durata: da 2 a 30 s", "Duration: 2 to 30 s").to_string());
    }
    run_with(
        Duration::from_secs(s as u64),
        Env {
            dest: SSDP,
            locals: local_v4(),
            multicast: true,
            step: Duration::from_millis(250),
            fetch_timeout: Duration::from_secs(3),
        },
        stop,
    )
    .await
}

fn search(st: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\nUSER-AGENT: NetworkToolbox\r\n\r\n"
    )
    .into_bytes()
}

/// Downloads and reads a description. The URL must point to the address that answered.
async fn fetch(
    client: &reqwest::Client,
    location: &str,
    from: &BTreeSet<IpAddr>,
) -> Result<Desc, String> {
    let url = reqwest::Url::parse(location)
        .map_err(|_| t!("LOCATION non valido", "Invalid LOCATION").to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(t!("LOCATION non valido", "Invalid LOCATION").to_string());
    }
    let host_ok = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| from.contains(&ip));
    if !host_ok {
        return Err(tf!(
            "LOCATION su un altro indirizzo ({h}): non letto",
            "LOCATION on another address ({h}): not read",
            h = url.host_str().unwrap_or("?")
        ));
    }
    let mut resp = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            t!(
                "nessuna risposta alla richiesta della descrizione",
                "no reply to the description request"
            )
            .to_string()
        } else {
            tf!(
                "descrizione non raggiungibile: {e}",
                "description not reachable: {e}"
            )
        }
    })?;
    if !resp.status().is_success() {
        return Err(tf!(
            "la descrizione risponde HTTP {c}",
            "the description answers HTTP {c}",
            c = resp.status().as_u16()
        ));
    }
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_XML {
            return Err(t!(
                "descrizione troppo grande (oltre 256 KB)",
                "description too large (over 256 KB)"
            )
            .to_string());
        }
    }
    parse_description(&String::from_utf8_lossy(&body)).ok_or_else(|| {
        t!(
            "descrizione non riconosciuta (XML senza <device>)",
            "description not recognised (XML without <device>)"
        )
        .to_string()
    })
}

pub(crate) async fn run_with(dur: Duration, env: Env, stop: &Stop) -> crate::Result<UpnpResult> {
    let socks: Vec<Arc<tokio::net::UdpSocket>> = env
        .locals
        .iter()
        .filter_map(|ip| open(*ip, env.multicast).ok().map(Arc::new))
        .collect();
    if socks.is_empty() {
        return Err(t!(
            "Nessuna scheda di rete IPv4 attiva su cui cercare",
            "No active IPv4 adapter to search on"
        )
        .to_string());
    }
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(QUEUE);
    let mut readers = JoinSet::new();
    for s in &socks {
        let (s, tx) = (s.clone(), tx.clone());
        readers.spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match s.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        // queue full: the datagram is dropped
                        if let Err(mpsc::error::TrySendError::Closed(_)) =
                            tx.try_send((buf[..n].to_vec(), from))
                        {
                            break;
                        }
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }
    drop(tx);

    let probes = [search("ssdp:all"), search("upnp:rootdevice")];
    let mut book = Book::default();
    let end = tokio::time::sleep(dur);
    tokio::pin!(end);
    // completes only if the stop arrives (`race` gives `None`)
    let stopper = stop.race(std::future::pending::<()>());
    tokio::pin!(stopper);
    let mut stopped = false;
    let mut tick = tokio::time::interval(env.step);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut n = 0u32;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                // three searches: now, after RESEND ticks and after twice as many
                if n.is_multiple_of(RESEND) && n <= 2 * RESEND {
                    for p in &probes {
                        for s in &socks {
                            let _ = s.send_to(p, env.dest).await;
                        }
                    }
                }
                n += 1;
            }
            Some((buf, from)) = rx.recv() => {
                if let Some(r) = parse_response(&buf) {
                    book.ingest(r, from.ip());
                }
            }
            _ = &mut end => break,
            _ = &mut stopper => {
                stopped = true;
                break;
            }
        }
    }
    readers.abort_all();

    // descriptions, a few at a time (skipped if the user stopped the search)
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(env.fetch_timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let gate = Arc::new(Semaphore::new(FETCH_PARALLEL));
    let mut jobs = JoinSet::new();
    for (k, f) in book
        .found
        .iter()
        .filter(|(_, f)| !f.location.is_empty() && !stopped)
        .take(MAX_DESCRIBE)
    {
        let (client, gate) = (client.clone(), gate.clone());
        let (k, loc, from) = (k.clone(), f.location.clone(), f.from.clone());
        jobs.spawn(async move {
            let _permit = gate.acquire().await;
            (k, fetch(&client, &loc, &from).await)
        });
    }
    // the stop also interrupts the descriptions: the devices already heard stay in the list
    let mut described = BTreeMap::new();
    loop {
        tokio::select! {
            j = jobs.join_next() => match j {
                Some(Ok((k, r))) => {
                    described.insert(k, r);
                }
                Some(Err(_)) => {}
                None => break,
            },
            _ = &mut stopper, if !stopped => {
                stopped = true;
                jobs.abort_all();
                break;
            }
        }
    }
    let mut r = build(&book, &described, socks.len(), dur.as_secs());
    r.stopped = stopped;
    if book.capped {
        r.checks.push(check(
            AREA,
            "warn",
            t!("Risultato parziale", "Partial result"),
            t!(
                "Le risposte hanno superato i limiti di una ricerca: l'elenco non è completo. Un dispositivo che risponde con centinaia di indirizzi diversi va verificato.",
                "The replies exceeded the limits of one search: the list is not complete. A device answering with hundreds of different addresses should be checked."
            ),
        ));
    }
    if stopped {
        if r.devices.is_empty() {
            r.checks = vec![check(
                AREA,
                "info",
                t!("Ricerca fermata", "Search stopped"),
                t!(
                    "Fermata prima di qualsiasi risposta",
                    "Stopped before any reply"
                ),
            )];
        } else {
            r.checks.push(check(
                AREA,
                "info",
                t!("Ricerca fermata", "Search stopped"),
                t!(
                    "L'elenco è parziale: ascolto interrotto dall'utente",
                    "The list is partial: listening was stopped by the user"
                ),
            ));
        }
    }
    Ok(r)
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    const XML: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Router &amp; Co</friendlyName><manufacturer>Example Corp</manufacturer>
<manufacturerURL>http://www.example.com/</manufacturerURL><modelDescription>Example router</modelDescription>
<modelName>ER-100</modelName><modelNumber>1.2</modelNumber><serialNumber>0001</serialNumber>
<UDN>uuid:11111111-2222-3333-4444-555555555555</UDN>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/ctl/L3F</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>WANDevice</friendlyName>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><friendlyName>WAN conn</friendlyName>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList>
</device></deviceList></device></deviceList>
<presentationURL>http://192.0.2.1/</presentationURL></device></root>"#;

    fn reply(loc: &str, st: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: {loc}\r\nSERVER: Linux/5.4 UPnP/1.1 MiniUPnPd/2.2\r\nST: {st}\r\nUSN: uuid:1111::{st}\r\n\r\n").into_bytes()
    }

    #[test]
    fn ssdp_reply_parsing() {
        let r = parse_response(&reply("http://192.0.2.1:5000/d.xml", "upnp:rootdevice")).unwrap();
        assert_eq!(r.location, "http://192.0.2.1:5000/d.xml");
        assert_eq!(r.st, "upnp:rootdevice");
        assert!(r.server.contains("MiniUPnPd"));
        // not replies
        assert!(parse_response(b"NOTIFY * HTTP/1.1\r\nLOCATION: http://x/\r\n\r\n").is_none());
        assert!(parse_response(b"M-SEARCH * HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
        assert!(parse_response(&[0xff, 0xfe, 0x00]).is_none());
    }

    /// Hundreds of different locations: the book stops at its limit.
    #[test]
    fn limits_of_a_search() {
        let mut b = Book::default();
        let from: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..MAX_FOUND + 50 {
            let r = parse_response(&reply(
                &format!("http://192.0.2.1:5000/d{i}.xml"),
                "upnp:rootdevice",
            ))
            .unwrap();
            b.ingest(r, from);
        }
        assert_eq!(b.found.len(), MAX_FOUND);
        assert!(b.capped);
        // targets of one device
        let mut b = Book::default();
        for i in 0..MAX_PER_FOUND + 5 {
            let r = parse_response(&reply("http://192.0.2.1:5000/d.xml", &format!("urn:x:{i}")))
                .unwrap();
            b.ingest(r, from);
        }
        assert_eq!(
            b.found.values().next().unwrap().targets.len(),
            MAX_PER_FOUND
        );
    }

    #[test]
    fn description_parsing() {
        let d = parse_description(XML).unwrap();
        assert_eq!(d.friendly_name, "Router & Co");
        assert_eq!(d.manufacturer, "Example Corp");
        assert_eq!(
            (d.model_name.as_str(), d.model_number.as_str()),
            ("ER-100", "1.2")
        );
        assert_eq!(d.presentation_url, "http://192.0.2.1/");
        assert_eq!(urn_short(&d.device_type), "InternetGatewayDevice");
        // the root's fields are not taken from the embedded devices
        assert_ne!(d.friendly_name, "WANDevice");
        assert_eq!(d.embedded, vec!["WANDevice", "WANConnectionDevice"]);
        let s: Vec<&str> = d.services.iter().map(|s| s.short.as_str()).collect();
        assert_eq!(s, vec!["Layer3Forwarding", "WANIPConnection"]);
        assert_eq!(d.services[1].control_url, "/ctl/IPConn");
        assert!(parse_description("<html>no</html>").is_none());
        // truncated XML does not panic
        let _ = parse_description("<device><friendlyName>abc");
    }

    #[test]
    fn xml_text_is_cleaned() {
        let d = parse_description("<device><friendlyName> a&lt;b\u{7}c </friendlyName></device>")
            .unwrap();
        assert_eq!(d.friendly_name, "a<bc");
        let long = format!(
            "<device><friendlyName>{}</friendlyName></device>",
            "x".repeat(500)
        );
        assert_eq!(parse_description(&long).unwrap().friendly_name.len(), 200);
    }

    fn book_with(loc: &str, from: &str) -> Book {
        let mut b = Book::default();
        assert!(b.ingest(
            parse_response(&reply(loc, "upnp:rootdevice")).unwrap(),
            from.parse().unwrap()
        ));
        b.ingest(
            parse_response(&reply(
                loc,
                "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            ))
            .unwrap(),
            from.parse().unwrap(),
        );
        b
    }

    #[test]
    fn replies_of_one_device_are_merged() {
        let b = book_with("http://192.0.2.1:5000/d.xml", "192.0.2.1");
        assert_eq!(b.found.len(), 1);
        let f = b.found.values().next().unwrap();
        assert_eq!(f.targets.len(), 2);
        // the same reply again changes nothing
        let mut b = b;
        let r = parse_response(&reply("http://192.0.2.1:5000/d.xml", "upnp:rootdevice")).unwrap();
        assert!(!b.ingest(r, "192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn igd_gets_the_security_warning() {
        let b = book_with("http://192.0.2.1:5000/d.xml", "192.0.2.1");
        let mut m = BTreeMap::new();
        m.insert(
            "http://192.0.2.1:5000/d.xml".to_string(),
            Ok(parse_description(XML).unwrap()),
        );
        let r = build(&b, &m, 1, 5);
        let d = &r.devices[0];
        assert!(d.igd && d.described);
        assert_eq!(
            (d.kind.as_str(), d.label.as_str()),
            ("InternetGatewayDevice", "Router / gateway (IGD)")
        );
        assert_eq!(r.n_services, 2);
        assert!(r
            .checks
            .iter()
            .any(|c| c.status == "warn" && c.detail.contains("Router & Co (192.0.2.1)")));
        assert!(r.csv.contains("192.0.2.1;Router & Co;Example Corp;ER-100 1.2;InternetGatewayDevice;Layer3Forwarding WANIPConnection;"));
        // without a description the type still comes from the search targets
        let r = build(&b, &BTreeMap::new(), 1, 5);
        assert!(r.devices[0].igd && !r.devices[0].described);
    }

    #[test]
    fn empty_result_is_information() {
        let r = build(&Book::default(), &BTreeMap::new(), 2, 5);
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].status, "info");
        assert!(r.checks[0].detail.contains("UDP 1900"));
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let r = build(&Book::default(), &BTreeMap::new(), 1, 5);
        assert_eq!(r.checks[0].name, "No reply");
        assert!(!r.checks[0].detail.contains("Nessun"));
        assert_eq!(kind_label("MediaServer"), "Media server (DLNA)");
        assert!(r.csv.starts_with("IP;Name;"));
    }

    #[tokio::test]
    async fn duration_out_of_range() {
        let e = run(UpnpReq { seconds: Some(1) }, &Stop::new())
            .await
            .unwrap_err();
        assert_eq!(e, "Durata: da 2 a 30 s");
    }

    /// Tiny HTTP server: `/desc.xml` = the description, anything else 404.
    async fn http_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let resp = if req.starts_with("GET /desc.xml") {
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{XML}", XML.len())
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    /// Fake SSDP responder: a device on the local server, one that points to another address,
    /// one with a 404 description and a search of someone else (ignored).
    async fn responder(http: u16) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2000];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                if !buf[..n].starts_with(b"M-SEARCH") {
                    continue;
                }
                for loc in [
                    format!("http://127.0.0.1:{http}/desc.xml"),
                    "http://192.0.2.99:80/other.xml".to_string(),
                    format!("http://127.0.0.1:{http}/missing.xml"),
                ] {
                    let _ = udp.send_to(&reply(&loc, "upnp:rootdevice"), from).await;
                }
                let _ = udp.send_to(b"NOTIFY * HTTP/1.1\r\n\r\n", from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn full_scan_against_fake_devices() {
        let dest = responder(http_server().await).await;
        let r = run_with(
            Duration::from_millis(800),
            Env {
                dest,
                locals: vec![Ipv4Addr::LOCALHOST],
                multicast: false,
                step: Duration::from_millis(30),
                fetch_timeout: Duration::from_secs(2),
            },
            &Stop::new(),
        )
        .await
        .unwrap();
        assert_eq!(r.n_devices, 3, "{r:?}");
        let ok = r.devices.iter().find(|d| d.described).unwrap();
        assert_eq!(ok.friendly_name, "Router & Co");
        assert!(ok.igd);
        let moved = r
            .devices
            .iter()
            .find(|d| d.location.contains("192.0.2.99"))
            .unwrap();
        assert!(!moved.described);
        assert!(moved.note.contains("altro indirizzo"), "{}", moved.note);
        let missing = r
            .devices
            .iter()
            .find(|d| d.location.ends_with("missing.xml"))
            .unwrap();
        assert!(missing.note.contains("404"));
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "LOCATION verso un altro indirizzo"));
        assert!(r.checks.iter().any(|c| c.name == "Descrizione non letta"));
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "UPnP attivo su un router"));
    }

    #[tokio::test]
    async fn stop_ends_the_search_and_skips_descriptions() {
        let dest = responder(http_server().await).await;
        let stop = Stop::new();
        let s2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            s2.stop();
        });
        let t = std::time::Instant::now();
        let r = run_with(
            Duration::from_secs(20),
            Env {
                dest,
                locals: vec![Ipv4Addr::LOCALHOST],
                multicast: false,
                step: Duration::from_millis(30),
                fetch_timeout: Duration::from_secs(2),
            },
            &stop,
        )
        .await
        .unwrap();
        assert!(t.elapsed() < Duration::from_secs(3));
        assert!(r.stopped);
        assert!(r.n_devices > 0 && r.devices.iter().all(|d| !d.described));
        assert!(r.checks.iter().any(|c| c.name == "Ricerca fermata"));
    }
}
