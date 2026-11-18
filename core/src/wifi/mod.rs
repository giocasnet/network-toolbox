//! Wi-Fi: nearby networks, current connection, channel utilisation and signal
//! trend. Data comes from the Windows Native Wi-Fi API (`wlanapi.dll`, loaded at
//! runtime: it does not exist on servers without the "Wireless LAN Service");
//! everything else (Information Elements, channels, security, advice, monitor) is
//! portable code, tested with hand-built data.

pub mod ie;

#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl;

#[cfg(not(windows))]
mod unix_impl;

#[cfg(not(windows))]
use unix_impl as backend;
#[cfg(windows)]
use windows_impl as backend;

use crate::lan::OuiDb;
use crate::ping::Stop;
use crate::{t, tf};
use ie::Ies;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ───────────────────────── raw backend data ─────────────────────────

/// Wi-Fi adapter as Windows sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct RawAdapter {
    /// Adapter GUID in the form "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
    pub id: String,
    pub name: String,
    pub connected: bool,
    pub radio: Radio,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Radio {
    On,
    /// Turned off by Windows (airplane mode, settings).
    SoftOff,
    /// Turned off by the adapter or laptop switch.
    HardOff,
    Unknown,
}

/// One entry of the Windows BSS list.
#[derive(Debug, Clone, PartialEq)]
pub struct RawBss {
    pub ssid: Vec<u8>,
    pub bssid: [u8; 6],
    pub rssi: i32,
    pub quality: u32,
    pub freq_khz: u32,
    /// DOT11_PHY_TYPE (10 = HE, 11 = EHT).
    pub phy: i32,
    pub capability: u16,
    pub ies: Vec<u8>,
}

/// Current connection (WLAN_CONNECTION_ATTRIBUTES plus RSSI and channel).
#[derive(Debug, Clone, PartialEq)]
pub struct RawConn {
    pub ssid: Vec<u8>,
    pub bssid: [u8; 6],
    pub phy: i32,
    pub quality: u32,
    pub rx_kbps: u32,
    pub tx_kbps: u32,
    pub auth: i32,
    pub cipher: i32,
    pub profile: String,
    pub rssi: Option<i32>,
    pub channel: Option<u32>,
    /// IPv4 index of the adapter, to get the IP address.
    pub if_index: Option<u32>,
}

/// Outcome of the request for a new scan to Windows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanOutcome {
    Done,
    NotRequested,
    Failed(u32),
    Timeout,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawScan {
    pub scan: ScanOutcome,
    /// BSS list, or error code (5 = location access denied).
    pub bss: Result<Vec<RawBss>, u32>,
    pub conn: Option<RawConn>,
    /// BSSIDs of hidden networks this PC has a profile for: (SSID, BSSID).
    pub hidden_profiles: Vec<(Vec<u8>, [u8; 6])>,
}

/// Errors that prevent using Wi-Fi altogether.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BackendError {
    /// `wlanapi.dll` missing (Windows Server without the feature).
    NoDll,
    /// WlanSvc service stopped.
    Service,
    /// System without Wi-Fi APIs (development on Linux).
    Unsupported,
    Other(u32),
}

/// Monitor sample.
#[derive(Debug, Clone, PartialEq)]
pub struct RawSample {
    pub conn: Option<RawConn>,
}

/// Windows notification for the monitor (roaming start and end, disconnection).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Notice {
    RoamStart(Instant),
    RoamEnd(Instant),
    Disconnected(Instant),
}

// ───────────────────────── responses to the UI ─────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Adapter {
    pub id: String,
    pub name: String,
    pub connected: bool,
    /// on, off (Windows), hw_off (switch)
    pub radio: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Problem {
    /// no_adapter, no_wlan, service, radio_off, location, unsupported, error
    pub code: &'static str,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Network {
    /// Broadcast SSID (empty for hidden networks).
    pub ssid: String,
    pub hidden: bool,
    /// Length of the name, if the AP sends it as null bytes.
    pub ssid_len: u8,
    /// Name of a hidden network taken from the profile saved on this PC.
    pub profile: Option<String>,
    /// SSID of another BSSID of the same access point (probable).
    pub same_ap: Option<String>,
    pub bssid: String,
    pub vendor: Option<String>,
    pub rssi: i32,
    pub quality: u32,
    /// "2.4", "5", "6"
    pub band: &'static str,
    pub channel: u16,
    pub freq_mhz: u32,
    pub width_mhz: u16,
    /// Centre of the occupied channel (for the chart).
    pub center_mhz: u32,
    /// be, ax, ac, n, a, g, b
    pub std: &'static str,
    /// "Wi-Fi 7", "Wi-Fi 6E", … or "" for standards without a commercial name.
    pub gen: &'static str,
    pub security: String,
    /// open, weak, wpa2, wpa3, ent, owe
    pub sec_class: &'static str,
    pub cipher: String,
    pub k: bool,
    pub v: bool,
    pub r: bool,
    pub mlo: bool,
    pub clients: Option<u16>,
    pub load_pct: Option<u8>,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Connection {
    pub ssid: String,
    pub bssid: String,
    pub vendor: Option<String>,
    pub profile: String,
    pub band: Option<&'static str>,
    pub channel: Option<u16>,
    pub width_mhz: Option<u16>,
    pub std: &'static str,
    pub gen: &'static str,
    pub rssi: Option<i32>,
    pub quality: u32,
    pub rx_mbps: f64,
    pub tx_mbps: f64,
    pub security: String,
    pub cipher: String,
    pub ip: Option<String>,
    /// Features announced by the AP (from its beacon, if it is in the list).
    pub k: Option<bool>,
    pub v: Option<bool>,
    pub r: Option<bool>,
    pub mlo: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Best5 {
    pub label: String,
    pub dfs: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WifiResult {
    pub adapters: Vec<Adapter>,
    /// Adapter used.
    pub adapter: Option<String>,
    /// Blocks the whole section (no adapter, service stopped…) or just the
    /// network list (location denied, Wi-Fi off).
    pub problem: Option<Problem>,
    /// Non-blocking warning (scan not completed).
    pub warning: Option<String>,
    pub connection: Option<Connection>,
    pub networks: Vec<Network>,
    /// Least busy channel among 1, 6 and 11.
    pub best24: Option<u8>,
    /// Least busy 80 MHz group among those allowed in Europe.
    pub best5: Option<Best5>,
    pub six_seen: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WifiReq {
    /// Adapter GUID; empty = the first one (preferring the connected one).
    #[serde(default)]
    pub adapter: String,
    /// Asks Windows for a new scan (about 4 s) instead of the cached list.
    #[serde(default = "yes")]
    pub scan: bool,
}

fn yes() -> bool {
    true
}

// ───────────────────────── channels, standards, security ─────────────────────────

/// Band and channel from the frequency in MHz.
pub fn band_channel(mhz: u32) -> Option<(&'static str, u16)> {
    match mhz {
        2484 => Some(("2.4", 14)),
        2412..=2472 => Some(("2.4", ((mhz - 2407) / 5) as u16)),
        5935 => Some(("6", 2)),
        5150..=5925 => Some(("5", ((mhz - 5000) / 5) as u16)),
        5945..=7125 => Some(("6", ((mhz - 5950) / 5) as u16)),
        _ => None,
    }
}

fn chan_mhz(band: &str, ch: u8) -> u32 {
    match band {
        "6" => 5950 + 5 * ch as u32,
        _ => 5000 + 5 * ch as u32,
    }
}

/// Channel width and centre frequency, from the operation elements.
pub fn width_center(band: &str, freq: u32, i: &Ies) -> (u16, u32) {
    let mut wc = (20, freq);
    match band {
        "2.4" => {
            if let Some(h) = i.ht_op.filter(|h| h.wide) {
                match h.secondary {
                    1 => wc = (40, freq + 10),
                    3 => wc = (40, freq - 10),
                    _ => {}
                }
            }
        }
        "5" => {
            if let Some(h) = i.ht_op.filter(|h| h.wide) {
                match h.secondary {
                    1 => wc = (40, freq + 10),
                    3 => wc = (40, freq - 10),
                    _ => {}
                }
            }
            if let Some(v) = i.vht_op {
                match v.width {
                    1 if v.ccfs1 == 0 => wc = (80, chan_mhz("5", v.ccfs0)),
                    1 if v.ccfs1.abs_diff(v.ccfs0) == 8 => wc = (160, chan_mhz("5", v.ccfs1)),
                    // 80+80: two separate blocks, the chart shows the primary one
                    1 | 3 => wc = (160, chan_mhz("5", v.ccfs0)),
                    2 => wc = (160, chan_mhz("5", v.ccfs0)),
                    _ => {}
                }
            }
            if let Some(e) = i.eht_op {
                if e.width >= 3 {
                    let c = if e.ccfs1 != 0 { e.ccfs1 } else { e.ccfs0 };
                    wc = (160, chan_mhz("5", c));
                }
            }
        }
        "6" => {
            if let Some(h) = i.he_6g {
                let w = [20, 40, 80, 160][h.width as usize & 3];
                let c = if w == 160 && h.ccfs1 != 0 {
                    h.ccfs1
                } else {
                    h.ccfs0
                };
                wc = (w, chan_mhz("6", c));
            }
            if let Some(e) = i.eht_op {
                let w = [20, 40, 80, 160, 320][(e.width as usize).min(4)];
                let c = if w >= 160 && e.ccfs1 != 0 {
                    e.ccfs1
                } else {
                    e.ccfs0
                };
                if w >= wc.0 && c != 0 {
                    wc = (w, chan_mhz("6", c));
                }
            }
        }
        _ => {}
    }
    wc
}

/// Standard from the elements, with the Windows PHY type as a fallback.
pub fn standard(band: &str, i: &Ies, phy: i32) -> &'static str {
    if i.eht || phy == 11 {
        "be"
    } else if i.he || phy == 10 {
        "ax"
    } else if (i.vht && band == "5") || phy == 8 {
        "ac"
    } else if i.ht || phy == 7 {
        "n"
    } else if band != "2.4" {
        "a"
    } else if i.max_rate > 22 || phy == 6 {
        "g"
    } else {
        "b"
    }
}

/// Commercial name (Wi-Fi Alliance).
pub fn generation(std: &str, band: &str) -> &'static str {
    match (std, band) {
        ("be", _) => "Wi-Fi 7",
        ("ax", "6") => "Wi-Fi 6E",
        ("ax", _) => "Wi-Fi 6",
        ("ac", _) => "Wi-Fi 5",
        ("n", _) => "Wi-Fi 4",
        _ => "",
    }
}

fn cipher_name(c: u8) -> &'static str {
    match c {
        1 | 5 => "WEP",
        2 => "TKIP",
        4 => "AES",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        _ => "",
    }
}

/// Security announced by an AP: (name, class, cipher).
pub fn security(privacy: bool, i: &Ies) -> (String, &'static str, String) {
    let Some(r) = i.rsn.as_ref().or(i.wpa.as_ref()) else {
        return if privacy {
            ("WEP".into(), "weak", "WEP".into())
        } else {
            (t!("Aperta", "Open").into(), "open", String::new())
        };
    };
    let mut ciphers: Vec<&str> = Vec::new();
    for c in &r.pairwise {
        let n = cipher_name(*c);
        if !n.is_empty() && !ciphers.contains(&n) {
            ciphers.push(n);
        }
    }
    let cipher = ciphers.join("+");
    let a = |list: &[u8]| r.akm.iter().any(|x| list.contains(x));
    let wpa1 = i.rsn.is_none();
    let tkip_only = ciphers == ["TKIP"];
    let (name, class) = if a(&[12]) {
        ("WPA3-Enterprise 192 bit", "ent")
    } else if a(&[1, 3, 5, 11, 13]) {
        if wpa1 {
            ("WPA-Enterprise", "weak")
        } else if a(&[5]) && r.mfpr {
            ("WPA3-Enterprise", "ent")
        } else {
            ("WPA2-Enterprise", "ent")
        }
    } else if a(&[8, 9, 24, 25]) {
        if a(&[2, 4, 6]) {
            ("WPA2/3-Personal", "wpa2")
        } else {
            ("WPA3-Personal", "wpa3")
        }
    } else if a(&[2, 4, 6]) {
        if wpa1 {
            ("WPA-Personal", "weak")
        } else {
            ("WPA2-Personal", "wpa2")
        }
    } else if a(&[18]) {
        ("OWE", "owe")
    } else {
        (t!("Sconosciuta", "Unknown"), "wpa2")
    };
    let class = if tkip_only && class != "open" {
        "weak"
    } else {
        class
    };
    (name.into(), class, cipher)
}

/// Connection security from DOT11_AUTH_ALGORITHM and DOT11_CIPHER_ALGORITHM.
pub fn conn_security(auth: i32, cipher: i32) -> (String, String) {
    let c = match cipher {
        0 => "",
        1 | 5 | 257 => "WEP",
        2 => "TKIP",
        4 => "AES",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        _ => "",
    };
    let a = match auth {
        1 if !c.is_empty() => "WEP",
        1 => t!("Aperta", "Open"),
        2 => "WEP",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise 192 bit",
        9 => "WPA3-Personal",
        10 => "OWE",
        11 => "WPA3-Enterprise",
        _ => t!("Sconosciuta", "Unknown"),
    };
    (a.into(), c.into())
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Two BSSIDs of the same access point (probable): same last 5 bytes (APs that
/// change the first byte for each SSID) or same first 5 bytes and last byte
/// in the same group of 16 (APs that count at the end).
pub fn same_ap(a: &[u8; 6], b: &[u8; 6]) -> bool {
    a != b && (a[1..] == b[1..] || (a[..5] == b[..5] && a[5] >> 4 == b[5] >> 4))
}

/// Network name for the UI: UTF-8 if valid, otherwise Latin-1.
pub fn ssid_text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|&c| c as char).collect(),
    }
}

/// Hidden network: SSID absent, empty or made of zeros. Also returns the
/// declared length when it is made of zeros.
pub fn hidden(b: &[u8]) -> (bool, u8) {
    if b.is_empty() {
        (true, 0)
    } else if b.iter().all(|&c| c == 0) {
        (true, b.len() as u8)
    } else {
        (false, 0)
    }
}

fn mw(dbm: i32) -> f64 {
    10f64.powf(dbm as f64 / 10.0)
}

fn overlap(n: &Network, lo: u32, hi: u32) -> bool {
    let w = n.width_mhz as u32 / 2;
    n.center_mhz.saturating_sub(w) < hi && n.center_mhz + w > lo
}

/// Least busy channel among 1, 6 and 11 (sum of the received powers of the APs
/// that overlap). On a tie the lowest wins.
pub fn best_24(nets: &[Network]) -> Option<u8> {
    let n24: Vec<&Network> = nets.iter().filter(|n| n.band == "2.4").collect();
    if n24.is_empty() {
        return None;
    }
    [1u8, 6, 11]
        .into_iter()
        .map(|c| {
            let f = 2407 + 5 * c as u32;
            let s: f64 = n24
                .iter()
                .filter(|n| overlap(n, f - 10, f + 10))
                .map(|n| mw(n.rssi))
                .sum();
            (c, s)
        })
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(c, _)| c)
}

/// 80 MHz groups allowed indoors in Europe (36-64, 100-128): 132-144 and
/// 149-165 have no 80 MHz block usable everywhere.
const GROUPS_5: [(u8, u8, bool); 4] = [
    (36, 48, false),
    (52, 64, true),
    (100, 112, true),
    (116, 128, true),
];

pub fn best_5(nets: &[Network]) -> Option<Best5> {
    let n5: Vec<&Network> = nets.iter().filter(|n| n.band == "5").collect();
    if n5.is_empty() {
        return None;
    }
    GROUPS_5
        .iter()
        .map(|&(lo, hi, dfs)| {
            let (a, b) = (chan_mhz("5", lo) - 10, chan_mhz("5", hi) + 10);
            let s: f64 = n5
                .iter()
                .filter(|n| overlap(n, a, b))
                .map(|n| mw(n.rssi))
                .sum();
            (lo, hi, dfs, s)
        })
        .min_by(|a, b| a.3.total_cmp(&b.3))
        .map(|(lo, hi, dfs, _)| Best5 {
            label: format!("{lo}–{hi}"),
            dfs,
        })
}

/// From the raw entry to the table row.
pub fn network(b: &RawBss, oui: Option<&OuiDb>) -> Option<Network> {
    let i = ie::parse(&b.ies);
    let freq = b.freq_khz / 1000;
    let (band, mut channel) = band_channel(freq)?;
    if band == "2.4" {
        if let Some(c) = i.ds_channel.filter(|c| (1..=14).contains(c)) {
            channel = c as u16;
        }
    }
    let ssid = i.ssid.clone().unwrap_or_else(|| b.ssid.clone());
    let (hid, ssid_len) = hidden(&ssid);
    let (width_mhz, center_mhz) = width_center(band, freq, &i);
    let std = standard(band, &i, b.phy);
    let (security, sec_class, cipher) = security(b.capability & 0x10 != 0, &i);
    let mac = fmt_mac(&b.bssid);
    Some(Network {
        ssid: if hid { String::new() } else { ssid_text(&ssid) },
        hidden: hid,
        ssid_len,
        profile: None,
        same_ap: None,
        vendor: oui.and_then(|o| o.lookup(&mac)).map(str::to_string),
        bssid: mac,
        rssi: b.rssi,
        quality: b.quality,
        band,
        channel,
        freq_mhz: freq,
        width_mhz,
        center_mhz,
        std,
        gen: generation(std, band),
        security,
        sec_class,
        cipher,
        k: i.rrm,
        v: i.btm,
        r: i.mdie,
        mlo: i.mlo,
        clients: i.load.map(|l| l.0),
        load_pct: i.load.map(|l| ((l.1 as u32 * 100 + 127) / 255) as u8),
        connected: false,
    })
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let v: Vec<u8> = s
        .split(':')
        .map(|x| u8::from_str_radix(x, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    v.try_into().ok()
}

/// Completes the list: hidden network names from profiles, twin APs,
/// vendors of locally administered BSSIDs, connected AP; sorts by signal.
pub fn finish(
    nets: &mut [Network],
    hidden_profiles: &[(Vec<u8>, [u8; 6])],
    connected: Option<&[u8; 6]>,
) {
    let macs: Vec<[u8; 6]> = nets
        .iter()
        .map(|n| parse_mac(&n.bssid).unwrap_or_default())
        .collect();
    for i in 0..nets.len() {
        if let Some(c) = connected {
            nets[i].connected = &macs[i] == c;
        }
        if nets[i].hidden {
            nets[i].profile = hidden_profiles
                .iter()
                .find(|(_, m)| *m == macs[i])
                .map(|(s, _)| ssid_text(s));
        }
        // named twin (preferably on the same frequency) and with a vendor
        let twins: Vec<usize> = (0..nets.len())
            .filter(|&j| same_ap(&macs[i], &macs[j]))
            .collect();
        if nets[i].hidden && nets[i].profile.is_none() {
            let named = |j: &&usize| !nets[**j].hidden;
            let pick = twins
                .iter()
                .filter(named)
                .find(|&&j| nets[j].freq_mhz == nets[i].freq_mhz)
                .or_else(|| twins.iter().find(named));
            nets[i].same_ap = pick.map(|&j| nets[j].ssid.clone());
        }
        if nets[i].vendor.is_none() {
            nets[i].vendor = twins.iter().find_map(|&j| nets[j].vendor.clone());
        }
    }
    nets.sort_by(|a, b| b.rssi.cmp(&a.rssi).then_with(|| a.bssid.cmp(&b.bssid)));
}

pub fn adapter(a: &RawAdapter) -> Adapter {
    Adapter {
        id: a.id.clone(),
        name: a.name.clone(),
        connected: a.connected,
        radio: match a.radio {
            Radio::SoftOff => "off",
            Radio::HardOff => "hw_off",
            _ => "on",
        },
    }
}

fn problem(code: &'static str, title: &str, detail: &str) -> Problem {
    Problem {
        code,
        title: title.into(),
        detail: detail.into(),
    }
}

pub fn backend_problem(e: BackendError) -> Problem {
    match e {
        BackendError::NoDll => problem(
            "no_wlan",
            t!(
                "Componente Wi-Fi di Windows non installato",
                "Windows Wi-Fi component not installed"
            ),
            t!(
                "Manca wlanapi.dll: succede su Windows Server senza la funzionalità \
             «Servizio LAN wireless» (Install-WindowsFeature Wireless-Networking, poi riavvio).",
                "wlanapi.dll is missing: this happens on Windows Server without the \
             \"Wireless LAN Service\" feature (Install-WindowsFeature Wireless-Networking, then reboot)."
            ),
        ),
        BackendError::Service => problem(
            "service",
            t!(
                "Servizio Configurazione automatica WLAN non attivo",
                "WLAN AutoConfig service not running"
            ),
            t!(
                "Il servizio WlanSvc è fermo o disattivato. Da PowerShell come amministratore: \
             Set-Service WlanSvc -StartupType Automatic; Start-Service WlanSvc",
                "The WlanSvc service is stopped or disabled. From PowerShell as administrator: \
             Set-Service WlanSvc -StartupType Automatic; Start-Service WlanSvc"
            ),
        ),
        BackendError::Unsupported => problem(
            "unsupported",
            t!(
                "Wi-Fi non disponibile su questo sistema",
                "Wi-Fi not available on this system"
            ),
            t!(
                "La sezione Wi-Fi usa le API di Windows.",
                "The Wi-Fi section uses the Windows APIs."
            ),
        ),
        BackendError::Other(c) => problem(
            "error",
            t!(
                "Errore delle API Wi-Fi di Windows",
                "Windows Wi-Fi API error"
            ),
            &tf!("Codice {c}.", "Code {c}."),
        ),
    }
}

pub fn no_adapter() -> Problem {
    problem(
        "no_adapter",
        t!(
            "Nessuna scheda Wi-Fi su questo PC",
            "No Wi-Fi adapter on this PC"
        ),
        t!(
            "Windows non segnala schede di rete wireless attive. Le funzioni di questa sezione \
         richiedono una scheda Wi-Fi: usale da un portatile. Se il PC ne ha una, controlla \
         che non sia disattivata: Get-NetAdapter -Physical",
            "Windows reports no active wireless network adapters. The features of this section \
         need a Wi-Fi adapter: use them from a laptop. If the PC has one, check \
         that it is not disabled: Get-NetAdapter -Physical"
        ),
    )
}

pub fn radio_problem(r: Radio) -> Option<Problem> {
    match r {
        Radio::SoftOff => Some(problem(
            "radio_off",
            t!("Wi-Fi spento", "Wi-Fi is off"),
            t!(
                "Il Wi-Fi è spento in Windows (modalità aereo o pulsante Wi-Fi): senza radio non \
             ci sono reti né connessione.",
                "Wi-Fi is turned off in Windows (airplane mode or Wi-Fi button): without the radio \
             there are no networks and no connection."
            ),
        )),
        Radio::HardOff => Some(problem(
            "radio_off",
            t!(
                "Wi-Fi spento dall'interruttore",
                "Wi-Fi turned off by the switch"
            ),
            t!(
                "La radio è spenta dall'interruttore fisico o da un tasto funzione del portatile.",
                "The radio is turned off by the physical switch or by a laptop function key."
            ),
        )),
        _ => None,
    }
}

pub fn location_problem() -> Problem {
    problem(
        "location",
        t!(
            "Windows nega l'accesso alla posizione",
            "Windows denies access to the location"
        ),
        t!(
            "Dalla versione 24H2 Windows mostra le reti vicine e i BSSID solo alle app desktop \
         con accesso alla posizione: Impostazioni › Privacy e sicurezza › Posizione, «Consenti \
         alle app desktop di accedere alla posizione». Sui PC di dominio può essere bloccato \
         da un criterio di gruppo.",
            "Since version 24H2 Windows shows nearby networks and BSSIDs only to desktop apps \
         with location access: Settings › Privacy & security › Location, \"Let desktop apps \
         access your location\". On domain PCs it may be blocked by a group policy."
        ),
    )
}

/// Picks the adapter: the requested one, otherwise the first connected, otherwise the first.
pub fn pick<'a>(list: &'a [RawAdapter], want: &str) -> Option<&'a RawAdapter> {
    list.iter()
        .find(|a| !want.is_empty() && a.id.eq_ignore_ascii_case(want))
        .or_else(|| list.iter().find(|a| a.connected))
        .or_else(|| list.first())
}

fn ipv4_of(index: Option<u32>) -> Option<String> {
    let idx = index?;
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|i| i.index == Some(idx) && matches!(i.addr, if_addrs::IfAddr::V4(_)))
        .map(|i| i.ip().to_string())
}

/// Current connection, completed with the beacon data of its AP.
pub fn connection(c: &RawConn, nets: &[Network], oui: Option<&OuiDb>) -> Connection {
    let mac = fmt_mac(&c.bssid);
    let ap = nets.iter().find(|n| n.bssid == mac);
    let (security, cipher) = conn_security(c.auth, c.cipher);
    let band = ap.map(|n| n.band);
    let std = match c.phy {
        11 => "be",
        10 => "ax",
        8 => "ac",
        7 => "n",
        4 => "a",
        6 => "g",
        5 => "b",
        _ => ap.map(|n| n.std).unwrap_or(""),
    };
    let gen = generation(std, band.unwrap_or(""));
    Connection {
        ssid: ssid_text(&c.ssid),
        vendor: ap
            .and_then(|n| n.vendor.clone())
            .or_else(|| oui.and_then(|o| o.lookup(&mac)).map(str::to_string)),
        bssid: mac,
        profile: c.profile.clone(),
        band,
        channel: ap.map(|n| n.channel).or(c.channel.map(|x| x as u16)),
        width_mhz: ap.map(|n| n.width_mhz),
        std,
        gen,
        rssi: c.rssi,
        quality: c.quality,
        rx_mbps: c.rx_kbps as f64 / 1000.0,
        tx_mbps: c.tx_kbps as f64 / 1000.0,
        security,
        cipher,
        ip: ipv4_of(c.if_index),
        k: ap.map(|n| n.k),
        v: ap.map(|n| n.v),
        r: ap.map(|n| n.r),
        mlo: ap.is_some_and(|n| n.mlo),
    }
}

/// Processes the raw outcome of a scan.
pub fn build(
    adapters: &[RawAdapter],
    chosen: &RawAdapter,
    raw: Result<RawScan, BackendError>,
    oui: Option<&OuiDb>,
) -> WifiResult {
    let mut res = WifiResult {
        adapters: adapters.iter().map(adapter).collect(),
        adapter: Some(chosen.id.clone()),
        problem: None,
        warning: None,
        connection: None,
        networks: Vec::new(),
        best24: None,
        best5: None,
        six_seen: false,
    };
    if let Some(p) = radio_problem(chosen.radio) {
        res.problem = Some(p);
        return res;
    }
    let raw = match raw {
        Ok(r) => r,
        Err(e) => {
            res.problem = Some(backend_problem(e));
            return res;
        }
    };
    match raw.bss {
        Ok(list) => {
            res.networks = list.iter().filter_map(|b| network(b, oui)).collect();
        }
        Err(5) => res.problem = Some(location_problem()),
        Err(c) => {
            res.warning = Some(tf!(
                "Windows non ha restituito l'elenco delle reti (codice {c}).",
                "Windows did not return the network list (code {c})."
            ))
        }
    }
    finish(
        &mut res.networks,
        &raw.hidden_profiles,
        raw.conn.as_ref().map(|c| &c.bssid),
    );
    match raw.scan {
        ScanOutcome::Failed(_) | ScanOutcome::Timeout if res.problem.is_none() => {
            res.warning = Some(
                t!(
                    "Windows non ha completato una scansione nuova: l'elenco è quello dell'ultima \
                 scansione disponibile.",
                    "Windows did not complete a new scan: the list is from the last \
                 scan available."
                )
                .into(),
            )
        }
        _ => {}
    }
    res.connection = raw.conn.as_ref().map(|c| connection(c, &res.networks, oui));
    res.best24 = best_24(&res.networks);
    res.best5 = best_5(&res.networks);
    res.six_seen = res.networks.iter().any(|n| n.band == "6");
    res
}

fn empty(problem: Problem) -> WifiResult {
    WifiResult {
        adapters: Vec::new(),
        adapter: None,
        problem: Some(problem),
        warning: None,
        connection: None,
        networks: Vec::new(),
        best24: None,
        best5: None,
        six_seen: false,
    }
}

/// Nearby networks and current connection.
pub async fn scan(req: WifiReq, oui: Option<Arc<OuiDb>>) -> crate::Result<WifiResult> {
    tokio::task::spawn_blocking(move || {
        let adapters = match backend::adapters() {
            Ok(a) => a,
            Err(e) => return empty(backend_problem(e)),
        };
        let Some(chosen) = pick(&adapters, &req.adapter).cloned() else {
            return empty(no_adapter());
        };
        let raw = if radio_problem(chosen.radio).is_some() {
            Err(BackendError::Other(0))
        } else {
            backend::scan(&chosen.id, req.scan)
        };
        build(&adapters, &chosen, raw, oui.as_deref())
    })
    .await
    .map_err(|_| t!("Scansione Wi-Fi interrotta", "Wi-Fi scan interrupted").to_string())
}

// ───────────────────────── signal monitor ─────────────────────────

pub const MONITOR_MS: u32 = 1000;
pub const MIN_MONITOR_MS: u32 = 500;
pub const MAX_MONITOR_MS: u32 = 5000;
/// Thresholds (dBm): voice and video, data.
pub const GOOD_DBM: i32 = -67;
pub const FAIR_DBM: i32 = -75;
const HYSTERESIS: i32 = 2;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MonitorReq {
    #[serde(default)]
    pub adapter: String,
    #[serde(default, deserialize_with = "crate::util::opt_u32")]
    pub interval_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Sample {
    /// Milliseconds since the monitor started.
    pub t: u64,
    pub rssi: Option<i32>,
    pub quality: Option<u32>,
    pub bssid: Option<String>,
    pub channel: Option<u16>,
    pub rx_mbps: Option<f64>,
    pub tx_mbps: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MonEvent {
    pub t: u64,
    /// start, roam, disconnect, connect, weak, fair, good
    pub kind: &'static str,
    pub text: String,
    /// Roaming: duration of the interruption according to Windows, if known.
    pub gap_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MonitorMsg {
    Sample(Sample),
    Event(MonEvent),
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MonitorEnd {
    pub stopped: bool,
    pub samples: u32,
    pub roams: u32,
}

/// Sample source: Windows in the program, a sequence in the tests.
pub trait Source: Send + 'static {
    fn sample(&mut self) -> Result<RawSample, BackendError>;
    /// Notifications received since the last call.
    fn notices(&mut self) -> Vec<Notice>;
    /// Channel of a BSSID (from the BSS list) for roaming messages.
    fn channel_of(&mut self, bssid: &[u8; 6]) -> Option<u16>;
}

fn dbm_of(c: &RawConn) -> i32 {
    c.rssi
        .unwrap_or_else(|| (c.quality.min(100) as i32) / 2 - 100)
}

fn zone(dbm: i32, prev: &'static str) -> &'static str {
    // hysteresis: the zone only changes when the threshold is passed by 2 dB
    let up = |th: i32| dbm >= th + HYSTERESIS;
    let down = |th: i32| dbm < th - HYSTERESIS;
    match prev {
        "good" if down(FAIR_DBM) => "weak",
        "good" if down(GOOD_DBM) => "fair",
        "fair" if up(GOOD_DBM) => "good",
        "fair" if down(FAIR_DBM) => "weak",
        "weak" if up(GOOD_DBM) => "good",
        "weak" if up(FAIR_DBM) => "fair",
        "" if dbm >= GOOD_DBM => "good",
        "" if dbm >= FAIR_DBM => "fair",
        "" => "weak",
        p => p,
    }
}

fn ch_txt(ch: Option<u16>) -> String {
    ch.map(|c| tf!(", canale {c}", ", channel {c}"))
        .unwrap_or_default()
}

/// Monitor loop: one sample every `interval`, roaming events,
/// disconnection and signal zone changes.
pub async fn monitor_with<S: Source>(
    mut src: S,
    interval: Duration,
    stop: &Stop,
    mut emit: impl FnMut(MonitorMsg),
) -> crate::Result<MonitorEnd> {
    let t0 = Instant::now();
    let ms = |t: Instant| t.saturating_duration_since(t0).as_millis() as u64;
    let mut end = MonitorEnd {
        stopped: false,
        samples: 0,
        roams: 0,
    };
    let mut last_bssid: Option<[u8; 6]> = None;
    let mut last_dbm: Option<i32> = None;
    let mut zone_now: &'static str = "";
    let mut roam_start: Option<Instant> = None;
    let mut roam_gap: Option<u64> = None;
    let mut first = true;
    loop {
        let tick = Instant::now();
        let job = tokio::task::spawn_blocking(move || {
            let s = src.sample();
            let n = src.notices();
            (src, s, n)
        });
        let Some(joined) = stop.race(job).await else {
            end.stopped = true;
            return Ok(end);
        };
        let (mut s, sample, notices) =
            joined.map_err(|_| t!("Monitor interrotto", "Monitor interrupted").to_string())?;
        for n in notices {
            match n {
                Notice::RoamStart(t) => roam_start = Some(t),
                Notice::RoamEnd(t) => {
                    roam_gap = roam_start
                        .take()
                        .map(|a| t.saturating_duration_since(a).as_millis() as u64)
                }
                Notice::Disconnected(_) => {}
            }
        }
        let conn = match sample {
            Ok(r) => r.conn,
            Err(e) if first => return Err(backend_problem(e).title),
            Err(_) => None,
        };
        let now = ms(Instant::now());
        match &conn {
            Some(c) => {
                let dbm = dbm_of(c);
                if first {
                    emit(MonitorMsg::Event(MonEvent {
                        t: now,
                        kind: "start",
                        text: tf!(
                            "Monitor avviato su {} · {}{}",
                            "Monitor started on {} · {}{}",
                            ssid_text(&c.ssid),
                            fmt_mac(&c.bssid),
                            ch_txt(c.channel.map(|x| x as u16))
                        ),
                        gap_ms: None,
                    }));
                } else if last_bssid.is_none() {
                    emit(MonitorMsg::Event(MonEvent {
                        t: now,
                        kind: "connect",
                        text: tf!(
                            "Connesso a {} · {}",
                            "Connected to {} · {}",
                            ssid_text(&c.ssid),
                            fmt_mac(&c.bssid)
                        ),
                        gap_ms: None,
                    }));
                } else if let Some(old) = last_bssid.filter(|o| *o != c.bssid) {
                    end.roams += 1;
                    let ch_old = s.channel_of(&old);
                    let ch_new = c
                        .channel
                        .map(|x| x as u16)
                        .or_else(|| s.channel_of(&c.bssid));
                    let gap = roam_gap.take();
                    emit(MonitorMsg::Event(MonEvent {
                        t: now,
                        kind: "roam",
                        text: tf!(
                            "Roaming da {}{}{} a {}{}, {} dBm",
                            "Roaming from {}{}{} to {}{}, {} dBm",
                            fmt_mac(&old),
                            ch_txt(ch_old),
                            last_dbm.map(|d| format!(", {d} dBm")).unwrap_or_default(),
                            fmt_mac(&c.bssid),
                            ch_txt(ch_new),
                            dbm
                        ),
                        gap_ms: gap,
                    }));
                }
                let z = zone(dbm, zone_now);
                if z != zone_now && !zone_now.is_empty() {
                    let text = match z {
                        "weak" => tf!(
                            "Segnale sotto {FAIR_DBM} dBm ({dbm} dBm)",
                            "Signal below {FAIR_DBM} dBm ({dbm} dBm)"
                        ),
                        "fair" if zone_now == "good" => {
                            tf!(
                                "Segnale sotto {GOOD_DBM} dBm ({dbm} dBm)",
                                "Signal below {GOOD_DBM} dBm ({dbm} dBm)"
                            )
                        }
                        "fair" => tf!(
                            "Segnale tornato sopra {FAIR_DBM} dBm ({dbm} dBm)",
                            "Signal back above {FAIR_DBM} dBm ({dbm} dBm)"
                        ),
                        _ => tf!(
                            "Segnale tornato sopra {GOOD_DBM} dBm ({dbm} dBm)",
                            "Signal back above {GOOD_DBM} dBm ({dbm} dBm)"
                        ),
                    };
                    emit(MonitorMsg::Event(MonEvent {
                        t: now,
                        kind: z,
                        text,
                        gap_ms: None,
                    }));
                }
                zone_now = z;
                last_bssid = Some(c.bssid);
                last_dbm = Some(dbm);
                end.samples += 1;
                emit(MonitorMsg::Sample(Sample {
                    t: now,
                    rssi: Some(dbm),
                    quality: Some(c.quality),
                    bssid: Some(fmt_mac(&c.bssid)),
                    channel: c.channel.map(|x| x as u16),
                    rx_mbps: Some(c.rx_kbps as f64 / 1000.0),
                    tx_mbps: Some(c.tx_kbps as f64 / 1000.0),
                }));
            }
            None => {
                if first {
                    return Err(t!(
                        "La scheda Wi-Fi non è connessa a nessuna rete: il monitor \
                                misura il segnale della connessione attuale.",
                        "The Wi-Fi adapter is not connected to any network: the monitor \
                                measures the signal of the current connection."
                    )
                    .into());
                }
                if last_bssid.is_some() {
                    emit(MonitorMsg::Event(MonEvent {
                        t: now,
                        kind: "disconnect",
                        text: t!("Connessione Wi-Fi persa", "Wi-Fi connection lost").into(),
                        gap_ms: None,
                    }));
                }
                last_bssid = None;
                zone_now = "";
                end.samples += 1;
                emit(MonitorMsg::Sample(Sample {
                    t: now,
                    rssi: None,
                    quality: None,
                    bssid: None,
                    channel: None,
                    rx_mbps: None,
                    tx_mbps: None,
                }));
            }
        }
        first = false;
        src = s;
        let wait = interval.saturating_sub(tick.elapsed());
        if stop.race(tokio::time::sleep(wait)).await.is_none() {
            end.stopped = true;
            return Ok(end);
        }
    }
}

pub fn monitor_interval(req: &MonitorReq) -> crate::Result<Duration> {
    let ms = req.interval_ms.unwrap_or(MONITOR_MS);
    if !(MIN_MONITOR_MS..=MAX_MONITOR_MS).contains(&ms) {
        return Err(tf!(
            "Intervallo: da {MIN_MONITOR_MS} a {MAX_MONITOR_MS} ms",
            "Interval: {MIN_MONITOR_MS} to {MAX_MONITOR_MS} ms"
        ));
    }
    Ok(Duration::from_millis(ms as u64))
}

/// Signal monitor of the current connection, until "Stop".
pub async fn monitor(
    req: MonitorReq,
    stop: &Stop,
    emit: impl FnMut(MonitorMsg),
) -> crate::Result<MonitorEnd> {
    let interval = monitor_interval(&req)?;
    let adapter = req.adapter.clone();
    let src = tokio::task::spawn_blocking(move || -> crate::Result<backend::Watch> {
        let list = backend::adapters().map_err(|e| backend_problem(e).title)?;
        let a = pick(&list, &adapter).ok_or_else(|| no_adapter().title)?;
        if let Some(p) = radio_problem(a.radio) {
            return Err(p.title);
        }
        backend::Watch::open(&a.id).map_err(|e| backend_problem(e).title)
    })
    .await
    .map_err(|_| t!("Monitor interrotto", "Monitor interrupted").to_string())??;
    monitor_with(src, interval, stop, emit).await
}

/// Self-test on the PC (`selftest::wifi`): what Windows returns, step by step.
pub fn diagnose() -> Vec<String> {
    let mut out = Vec::new();
    let t0 = Instant::now();
    let list = match backend::adapters() {
        Ok(l) => l,
        Err(e) => {
            let p = backend_problem(e);
            out.push(format!("Schede Wi-Fi: {} ({})", p.title, p.detail));
            return out;
        }
    };
    out.push(format!(
        "Schede Wi-Fi: {} (in {} ms)",
        list.len(),
        t0.elapsed().as_millis()
    ));
    for a in &list {
        out.push(format!(
            "  {} {} · connessa: {} · radio: {:?}",
            a.id,
            a.name,
            if a.connected { "sì" } else { "no" },
            a.radio
        ));
    }
    let Some(a) = pick(&list, "") else {
        out.push(no_adapter().title);
        return out;
    };
    for fresh in [true, false] {
        let t0 = Instant::now();
        match backend::scan(&a.id, fresh) {
            Err(e) => out.push(format!("Scansione: {}", backend_problem(e).title)),
            Ok(r) => {
                out.push(format!(
                    "Scansione {}: {:?} in {} ms",
                    if fresh { "nuova" } else { "dalla memoria" },
                    r.scan,
                    t0.elapsed().as_millis()
                ));
                match &r.bss {
                    Ok(l) => out.push(format!(
                        "  BSS: {} ({} con Information Element, {} nascoste); profili di reti nascoste: {}",
                        l.len(),
                        l.iter().filter(|b| !b.ies.is_empty()).count(),
                        l.iter().filter(|b| hidden(&b.ssid).0).count(),
                        r.hidden_profiles.len()
                    )),
                    Err(c) => out.push(format!("  BSS: errore {c} (5 = posizione negata)")),
                }
                match &r.conn {
                    Some(c) => out.push(format!(
                        "  Connessione: {} {} · PHY {} · qualità {} · RSSI {:?} · canale {:?} · {} / {} kbit/s · auth {} cifratura {} · indice {:?} · IP {:?}",
                        ssid_text(&c.ssid),
                        fmt_mac(&c.bssid),
                        c.phy,
                        c.quality,
                        c.rssi,
                        c.channel,
                        c.rx_kbps,
                        c.tx_kbps,
                        c.auth,
                        c.cipher,
                        c.if_index,
                        ipv4_of(c.if_index)
                    )),
                    None => out.push("  Connessione: nessuna".into()),
                }
                if fresh {
                    let res = build(&list, a, Ok(r), None);
                    for n in res.networks.iter().take(40) {
                        out.push(format!(
                            "  {:>4} dBm  {:<24} {}  {:>3} {:>3} GHz {:>3} MHz  {:<8} {:<20} k{} v{} r{} mlo{} client {:?}",
                            n.rssi,
                            if n.hidden {
                                format!("(nascosta {})", n.ssid_len)
                            } else {
                                n.ssid.clone()
                            },
                            n.bssid,
                            n.channel,
                            n.band,
                            n.width_mhz,
                            n.gen,
                            n.security,
                            n.k as u8,
                            n.v as u8,
                            n.r as u8,
                            n.mlo as u8,
                            n.clients
                        ));
                    }
                    out.push(format!(
                        "  Consigli: 2,4 GHz {:?}, 5 GHz {:?}; 6 GHz visti: {}",
                        res.best24, res.best5, res.six_seen
                    ));
                }
            }
        }
    }
    match backend::Watch::open(&a.id) {
        Err(e) => out.push(format!("Monitor: {}", backend_problem(e).title)),
        Ok(mut w) => {
            for i in 0..3 {
                let t0 = Instant::now();
                let s = w.sample();
                out.push(format!(
                    "Monitor, campione {}: {} ms, RSSI {:?}",
                    i + 1,
                    t0.elapsed().as_millis(),
                    s.ok().and_then(|s| s.conn).map(|c| (c.rssi, c.quality))
                ));
                std::thread::sleep(Duration::from_millis(500));
            }
            out.push(format!("Notifiche ricevute: {:?}", w.notices()));
        }
    }
    out
}

/// GUID as text, as in Windows: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
pub fn guid_text(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> String {
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

pub fn guid_parse(s: &str) -> Option<(u32, u16, u16, [u8; 8])> {
    let h: String = s
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .chars()
        .filter(|c| *c != '-')
        .collect();
    if h.len() != 32 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let b = |i: usize| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(0);
    let mut d4 = [0u8; 8];
    for (k, x) in d4.iter_mut().enumerate() {
        *x = b(8 + k);
    }
    Some((
        u32::from_str_radix(&h[..8], 16).ok()?,
        u16::from_str_radix(&h[8..12], 16).ok()?,
        u16::from_str_radix(&h[12..16], 16).ok()?,
        d4,
    ))
}

#[cfg(test)]
mod tests;
