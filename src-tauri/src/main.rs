//! Network Toolbox — Tauri shell. Exposes the `ntb-core` tools to the UI
//! as commands; the live ones send their lines over a Channel.

// No console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ntb_core::lan::{self, OuiDb};
use ntb_core::net::HostMeta;
use ntb_core::ping::{PingReq, Stop};
use ntb_core::pwgen;
use ntb_core::sweep::{SweepEvent, SweepReq, SweepResult};
use ntb_core::wol::{WolReq, WolResult};
use ntb_core::{t, Event};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, RunEvent, State};

#[derive(Serialize)]
struct TextResult {
    output: String,
    meta: Option<HostMeta>,
    /// Test stopped with "Stop" before the end.
    stopped: bool,
}

/// Final response of streaming ping and traceroute.
#[derive(Serialize)]
struct StreamEnd {
    stopped: bool,
}

/// Ping, traceroute, subnet scan and port scan: switch of the running test,
/// one per tool.
#[derive(Default)]
struct ProbeState {
    ping: Mutex<Stop>,
    trace: Mutex<Stop>,
    sweep: Mutex<Stop>,
    ports: Mutex<Stop>,
    wifi: Mutex<Stop>,
    tls: Mutex<Stop>,
    snmp: Mutex<Stop>,
    snmp_mon: Mutex<Stop>,
}

/// Switch for a test that starts. A test of the same tool still running
/// is stopped: one runs at a time, and it is the one "Stop" interrupts.
fn new_stop(slot: &Mutex<Stop>) -> Stop {
    let stop = Stop::new();
    if let Ok(mut current) = slot.lock() {
        current.stop();
        *current = stop.clone();
    }
    stop
}

fn stop_current(slot: &Mutex<Stop>) {
    if let Ok(current) = slot.lock() {
        current.stop();
    }
}

#[derive(Serialize)]
struct AppInfo {
    hostname: String,
    /// This PC's IPv4 towards the network (empty if there is no network).
    ip: String,
    version: String,
    os: String,
}

#[tauri::command]
async fn ping(state: State<'_, ProbeState>, req: PingReq) -> Result<TextResult, String> {
    let stop = new_stop(&state.ping);
    let (output, meta, stopped) = ntb_core::ping::collect(req, &stop).await?;
    Ok(TextResult {
        output,
        meta,
        stopped,
    })
}

#[tauri::command]
async fn ping_stream(
    state: State<'_, ProbeState>,
    req: PingReq,
    on_event: Channel<Event>,
) -> Result<StreamEnd, String> {
    let stop = new_stop(&state.ping);
    let res = ntb_core::ping::run(req, &stop, |e| {
        let _ = on_event.send(e);
    })
    .await;
    let _ = on_event.send(Event::Done(true));
    res.map(|stopped| StreamEnd { stopped })
}

/// "Stop" button of ping.
#[tauri::command]
fn ping_stop(state: State<'_, ProbeState>) {
    stop_current(&state.ping);
}

#[tauri::command]
async fn traceroute(state: State<'_, ProbeState>, req: PingReq) -> Result<TextResult, String> {
    let stop = new_stop(&state.trace);
    let (output, meta, stopped) = ntb_core::trace::collect(req, &stop).await?;
    Ok(TextResult {
        output,
        meta,
        stopped,
    })
}

#[tauri::command]
async fn traceroute_stream(
    state: State<'_, ProbeState>,
    req: PingReq,
    on_event: Channel<Event>,
) -> Result<StreamEnd, String> {
    let stop = new_stop(&state.trace);
    let res = ntb_core::trace::run(req, &stop, |e| {
        let _ = on_event.send(e);
    })
    .await;
    let _ = on_event.send(Event::Done(true));
    res.map(|stopped| StreamEnd { stopped })
}

/// "Stop" button of traceroute.
#[tauri::command]
fn traceroute_stop(state: State<'_, ProbeState>) {
    stop_current(&state.trace);
}

/// Subnet scan: hosts arrive on the Channel as they are found,
/// the final response returns them all in address order.
#[tauri::command]
async fn sweep(
    state: State<'_, ProbeState>,
    req: SweepReq,
    on_event: Channel<SweepEvent>,
) -> Result<SweepResult, String> {
    let stop = new_stop(&state.sweep);
    ntb_core::sweep::run(req, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

/// "Stop" button of the subnet scan.
#[tauri::command]
fn sweep_stop(state: State<'_, ProbeState>) {
    stop_current(&state.sweep);
}

#[tauri::command]
async fn wol(req: WolReq) -> Result<WolResult, String> {
    ntb_core::wol::run(req).await
}

#[tauri::command]
async fn dns(req: ntb_core::dns::DnsReq) -> Result<ntb_core::dns::DnsResponse, String> {
    ntb_core::dns::run(req).await
}

/// Domain analysis: records, delegation, DNSSEC and (on request) zone transfer.
#[tauri::command]
async fn dns_domain(
    req: ntb_core::dns::domain::DomainReq,
) -> Result<ntb_core::dns::domain::DomainResult, String> {
    ntb_core::dns::domain::run(req).await
}

#[tauri::command]
async fn blacklist(
    req: ntb_core::blacklist::BlacklistReq,
) -> Result<ntb_core::blacklist::BlacklistResponse, String> {
    ntb_core::blacklist::run(req).await
}

/// Port scan: open ports arrive on the Channel as they are
/// found, the final response returns all those checked.
#[tauri::command]
async fn portscan(
    state: State<'_, ProbeState>,
    req: ntb_core::ports::PortReq,
    on_event: Channel<ntb_core::ports::PortEvent>,
) -> Result<ntb_core::ports::PortResponse, String> {
    let stop = new_stop(&state.ports);
    ntb_core::ports::run(req, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

/// "Stop" button of the port scan.
#[tauri::command]
fn portscan_stop(state: State<'_, ProbeState>) {
    stop_current(&state.ports);
}

#[tauri::command]
async fn whois(req: ntb_core::whois::WhoisReq) -> Result<ntb_core::whois::WhoisResponse, String> {
    ntb_core::whois::run(req).await
}

#[tauri::command]
fn subnet(req: ntb_core::subnet::SubnetReq) -> Result<ntb_core::subnet::SubnetResult, String> {
    ntb_core::subnet::run(req)
}

/// `req` is not used, but the UI always passes a `req` object.
#[tauri::command]
async fn myip(req: serde_json::Value) -> Result<serde_json::Value, String> {
    let _ = req;
    ntb_core::myip::run().await
}

#[tauri::command]
async fn headers(req: ntb_core::http::HeadersReq) -> Result<ntb_core::http::HeadersResult, String> {
    ntb_core::http::run(req).await
}

/// TLS certificates: with the version and cipher scan the certificate arrives on the
/// Channel as soon as it is read, then the suites as the server accepts them.
#[tauri::command]
async fn ssl(
    state: State<'_, ProbeState>,
    req: ntb_core::tls::TlsReq,
    on_event: Channel<ntb_core::tls::TlsEvent>,
) -> Result<ntb_core::tls::TlsResult, String> {
    let stop = new_stop(&state.tls);
    ntb_core::tls::run(req, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

/// "Stop" button of the TLS certificates (stops the version and cipher scan).
#[tauri::command]
fn ssl_stop(state: State<'_, ProbeState>) {
    stop_current(&state.tls);
}

#[tauri::command]
async fn emailheader(req: ntb_core::email::EmailReq) -> Result<serde_json::Value, String> {
    ntb_core::email::run(req).await
}

#[tauri::command]
async fn ntp(req: ntb_core::ntp::NtpReq) -> Result<ntb_core::ntp::NtpResult, String> {
    ntb_core::ntp::run(req).await
}

/// SMTP server test: the transcript arrives line by line on the Channel,
/// the final response contains the checks.
#[tauri::command]
async fn smtp_test(
    req: ntb_core::smtp::SmtpReq,
    on_event: Channel<Event>,
) -> Result<ntb_core::smtp::SmtpResult, String> {
    let res = ntb_core::smtp::run(req, |e| {
        let _ = on_event.send(e);
    })
    .await;
    let _ = on_event.send(Event::Done(true));
    res
}

/// SNMP: a value (GET), a branch (WALK) or a table of rows and columns.
#[tauri::command]
async fn snmp(
    state: State<'_, ProbeState>,
    req: ntb_core::snmp::SnmpReq,
) -> Result<ntb_core::snmp::SnmpResult, String> {
    let stop = new_stop(&state.snmp);
    ntb_core::snmp::run(req, &stop).await
}

/// SNMP, whole device: system, interfaces, LLDP neighbours, MAC and ARP tables. The
/// section being read arrives on the Channel; MAC vendors come from the OUI list.
#[tauri::command]
async fn snmp_device(
    app: AppHandle,
    state: State<'_, ProbeState>,
    lan: State<'_, LanState>,
    req: ntb_core::snmp::device::DeviceReq,
    on_event: Channel<ntb_core::snmp::device::DeviceEvent>,
) -> Result<ntb_core::snmp::device::DeviceResult, String> {
    let oui = lan.oui(&app);
    let stop = new_stop(&state.snmp);
    ntb_core::snmp::device::run(req, oui, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

/// "Stop" button of SNMP (reading a branch, a table or the device).
#[tauri::command]
fn snmp_stop(state: State<'_, ProbeState>) {
    stop_current(&state.snmp);
}

/// Live interface counters: one sample on the Channel per reading, until "Stop".
#[tauri::command]
async fn snmp_monitor(
    state: State<'_, ProbeState>,
    req: ntb_core::snmp::monitor::MonitorReq,
    on_event: Channel<ntb_core::snmp::monitor::MonitorMsg>,
) -> Result<ntb_core::snmp::monitor::MonitorEnd, String> {
    let stop = new_stop(&state.snmp_mon);
    ntb_core::snmp::monitor::run(req, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

#[tauri::command]
fn snmp_monitor_stop(state: State<'_, ProbeState>) {
    stop_current(&state.snmp_mon);
}

/// Built-in names of the standard MIBs, for the suggestions and the OID field tree.
#[tauri::command]
fn snmp_names() -> &'static [ntb_core::snmp::mib::Obj] {
    ntb_core::snmp::mib::OBJECTS
}

/// Language of the backend messages ("it" or "en"), sent by the UI at startup and on change.
#[tauri::command]
fn set_lang(lang: String) {
    ntb_core::i18n::set(ntb_core::i18n::parse(&lang));
}

#[tauri::command]
fn pwgen_password(req: pwgen::PasswordReq) -> Result<pwgen::PasswordResult, String> {
    pwgen::generate(req)
}

#[tauri::command]
fn pwgen_estimate(req: pwgen::PasswordReq) -> Result<pwgen::Estimate, String> {
    pwgen::estimate(&req)
}

#[tauri::command]
fn numconv(req: ntb_core::numconv::NumReq) -> Result<ntb_core::numconv::NumResult, String> {
    ntb_core::numconv::run(req)
}

#[tauri::command]
fn uuid_generate(req: ntb_core::uuid::UuidReq) -> Result<ntb_core::uuid::UuidResult, String> {
    ntb_core::uuid::generate(req)
}

#[tauri::command]
fn uuid_inspect(req: ntb_core::uuid::InspectReq) -> Result<ntb_core::uuid::InspectResult, String> {
    ntb_core::uuid::inspect(req)
}

/// Data file installed next to the executable (resources folder).
fn resource_path(app: &AppHandle, file: &str) -> PathBuf {
    let candidates: Vec<PathBuf> = [
        app.path().resource_dir().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.to_path_buf())),
    ]
    .into_iter()
    .flatten()
    .map(|d| d.join(file))
    .collect();
    candidates
        .iter()
        .find(|p| p.is_file())
        .or(candidates.first())
        .cloned()
        .unwrap_or_else(|| PathBuf::from(file))
}

/// Local network: vendor list (loaded at the first scan) and
/// switch of the running scan.
#[derive(Default)]
struct LanState {
    oui: Mutex<Option<Arc<OuiDb>>>,
    stop: Mutex<Stop>,
    /// Last neighbours reading, for comparison with the next one.
    neigh: Mutex<Option<ntb_core::neigh::NeighResult>>,
}

impl LanState {
    /// Vendor list; if missing the scan works all the same, without names.
    fn oui(&self, app: &AppHandle) -> Option<Arc<OuiDb>> {
        let mut slot = self.oui.lock().ok()?;
        if slot.is_none() {
            *slot = OuiDb::load(&resource_path(app, lan::OUI_FILE))
                .ok()
                .map(Arc::new);
        }
        slot.clone()
    }
}

/// This PC's network, to fill in the field.
#[tauri::command]
fn lan_default() -> Option<lan::LanDefault> {
    lan::default_network()
}

#[tauri::command]
async fn lan_scan(
    app: AppHandle,
    state: State<'_, LanState>,
    req: lan::LanReq,
    on_event: Channel<lan::LanEvent>,
) -> Result<lan::LanSummary, String> {
    let oui = state.oui(&app);
    let stop = new_stop(&state.stop); // one scan at a time
    lan::run(req, oui, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

/// Neighbours: this PC's ARP and NDP table, compared with the previous reading.
#[tauri::command]
async fn neigh_scan(
    app: AppHandle,
    state: State<'_, LanState>,
    req: ntb_core::neigh::NeighReq,
) -> Result<ntb_core::neigh::NeighResult, String> {
    let oui = state.oui(&app);
    let prev = state.neigh.lock().ok().and_then(|p| p.clone());
    let res = ntb_core::neigh::run(req, oui, prev).await?;
    if let Ok(mut p) = state.neigh.lock() {
        *p = Some(res.clone());
    }
    Ok(res)
}

#[tauri::command]
fn lan_stop(state: State<'_, LanState>) {
    stop_current(&state.stop);
}

/// Wi-Fi: adapters, current connection and nearby networks. With `scan` Windows does a
/// new scan (about 4 s).
#[tauri::command]
async fn wifi_scan(
    app: AppHandle,
    lan: State<'_, LanState>,
    req: ntb_core::wifi::WifiReq,
) -> Result<ntb_core::wifi::WifiResult, String> {
    let oui = lan.oui(&app);
    ntb_core::wifi::scan(req, oui).await
}

/// Signal monitor: samples and events on the Channel until "Stop".
#[tauri::command]
async fn wifi_monitor(
    state: State<'_, ProbeState>,
    req: ntb_core::wifi::MonitorReq,
    on_event: Channel<ntb_core::wifi::MonitorMsg>,
) -> Result<ntb_core::wifi::MonitorEnd, String> {
    let stop = new_stop(&state.wifi);
    ntb_core::wifi::monitor(req, &stop, move |e| {
        let _ = on_event.send(e);
    })
    .await
}

/// "Stop" button of the signal monitor.
#[tauri::command]
fn wifi_monitor_stop(state: State<'_, ProbeState>) {
    stop_current(&state.wifi);
}

/// Clipboard sequence number after the last password copy: when the app
/// closes the clipboard is emptied if it has not changed.
static LAST_SECRET: Mutex<Option<u32>> = Mutex::new(None);

#[derive(Deserialize)]
struct ClipReq {
    text: String,
}

/// Copies a password to the clipboard, outside the Win+V history, and clears it
/// after `CLEAR_AFTER_SECS` seconds if nothing else has been copied in the meantime.
#[tauri::command]
fn clipboard_secret(req: ClipReq) -> Result<u64, String> {
    use ntb_core::clipboard;
    let seq = clipboard::copy_secret(&req.text)?;
    if let Ok(mut l) = LAST_SECRET.lock() {
        *l = Some(seq);
    }
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(clipboard::CLEAR_AFTER_SECS));
        let _ = clipboard::clear_if_unchanged(seq);
    });
    Ok(clipboard::CLEAR_AFTER_SECS)
}

/// Network path for the home screen: adapter, gateway with name and latency.
#[tauri::command]
async fn net_path() -> ntb_core::netpath::NetPath {
    ntb_core::netpath::path().await
}

/// Internet connectivity (dot in the top bar).
#[tauri::command]
async fn internet_check() -> ntb_core::online::OnlineStatus {
    ntb_core::online::check().await
}

#[tauri::command]
fn app_info() -> AppInfo {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| t!("questo PC", "this PC").into());
    // On a domain-joined PC: PCNAME.domain
    let hostname = match std::env::var("USERDNSDOMAIN") {
        Ok(d) if !d.is_empty() => format!("{}.{}", host, d.to_lowercase()),
        _ => host,
    };
    AppInfo {
        hostname,
        ip: ntb_core::online::local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
    }
}

/// Marker file that turns on portable mode when it sits next to the executable.
const PORTABLE_MARKER: &str = "portable.txt";

/// Portable mode: WebView2 data (localStorage: language, theme, profiles) goes to a `data`
/// folder next to the executable instead of `%LOCALAPPDATA%`, so nothing is left on the host PC
/// and the settings travel with the USB stick. Returns `None` in the installed version, or if
/// the folder cannot be created (read-only stick): the app then behaves as installed.
fn portable_data_dir() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    if !dir.join(PORTABLE_MARKER).is_file() {
        return None;
    }
    let data = dir.join("data");
    std::fs::create_dir_all(&data).ok()?;
    Some(data)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // The main window is not created from the config (`"create": false`) so that its
            // data folder can be chosen here.
            let cfg = app
                .config()
                .app
                .windows
                .first()
                .cloned()
                .ok_or("finestra principale mancante nella configurazione")?;
            let mut win = tauri::WebviewWindowBuilder::from_config(app.handle(), &cfg)?;
            if let Some(dir) = portable_data_dir() {
                win = win.data_directory(dir);
            }
            win.build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ping,
            ping_stream,
            ping_stop,
            traceroute,
            traceroute_stream,
            traceroute_stop,
            sweep,
            sweep_stop,
            wol,
            dns,
            dns_domain,
            blacklist,
            portscan,
            portscan_stop,
            whois,
            subnet,
            myip,
            headers,
            ssl,
            ssl_stop,
            emailheader,
            ntp,
            snmp,
            snmp_device,
            snmp_stop,
            snmp_monitor,
            snmp_monitor_stop,
            snmp_names,
            smtp_test,
            pwgen_password,
            pwgen_estimate,
            clipboard_secret,
            numconv,
            uuid_generate,
            uuid_inspect,
            lan_default,
            lan_scan,
            lan_stop,
            neigh_scan,
            wifi_scan,
            wifi_monitor,
            wifi_monitor_stop,
            internet_check,
            net_path,
            app_info,
            set_lang
        ])
        .manage(LanState::default())
        .manage(ProbeState::default())
        .build(tauri::generate_context!())
        .expect("errore all'avvio di Network Toolbox")
        .run(|_, event| {
            if let RunEvent::Exit = event {
                if let Some(seq) = LAST_SECRET.lock().ok().and_then(|l| *l) {
                    let _ = ntb_core::clipboard::clear_if_unchanged(seq);
                }
            }
        });
}
