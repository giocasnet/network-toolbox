//! Windows Native Wi-Fi API. `wlanapi.dll` is loaded at runtime with
//! `LoadLibraryExW`: on Windows Server without the "Wireless LAN Service" the DLL
//! does not exist, and a static import would prevent the whole app from starting.

use super::{
    band_channel, guid_parse, guid_text, BackendError, Notice, Radio, RawAdapter, RawBss, RawConn,
    RawSample, RawScan, ScanOutcome, Source,
};
use std::ffi::c_void;
use std::ptr::{addr_of, null, null_mut};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToIndex,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, dot11_BSS_type_infrastructure, dot11_radio_state_off, dot11_radio_state_on,
    wlan_interface_state_connected, wlan_intf_opcode_channel_number,
    wlan_intf_opcode_current_connection, wlan_intf_opcode_radio_state, wlan_intf_opcode_rssi,
    wlan_notification_acm_disconnected, wlan_notification_acm_scan_complete,
    wlan_notification_acm_scan_fail, wlan_notification_msm_roaming_end,
    wlan_notification_msm_roaming_start, DOT11_BSS_TYPE, DOT11_SSID, L2_NOTIFICATION_DATA,
    WLAN_AVAILABLE_NETWORK, WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
    WLAN_AVAILABLE_NETWORK_LIST, WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES,
    WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WLAN_INTF_OPCODE, WLAN_NOTIFICATION_CALLBACK,
    WLAN_NOTIFICATION_SOURCES, WLAN_NOTIFICATION_SOURCE_ACM, WLAN_NOTIFICATION_SOURCE_MSM,
    WLAN_OPCODE_VALUE_TYPE, WLAN_PHY_RADIO_STATE, WLAN_RAW_DATA,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

type OpenFn = unsafe extern "system" fn(u32, *const c_void, *mut u32, *mut HANDLE) -> u32;
type CloseFn = unsafe extern "system" fn(HANDLE, *const c_void) -> u32;
type EnumFn =
    unsafe extern "system" fn(HANDLE, *const c_void, *mut *mut WLAN_INTERFACE_INFO_LIST) -> u32;
type ScanFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    *const DOT11_SSID,
    *const WLAN_RAW_DATA,
    *const c_void,
) -> u32;
type BssFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    *const DOT11_SSID,
    DOT11_BSS_TYPE,
    BOOL,
    *const c_void,
    *mut *mut WLAN_BSS_LIST,
) -> u32;
type AvailFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    u32,
    *const c_void,
    *mut *mut WLAN_AVAILABLE_NETWORK_LIST,
) -> u32;
type QueryFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    WLAN_INTF_OPCODE,
    *const c_void,
    *mut u32,
    *mut *mut c_void,
    *mut WLAN_OPCODE_VALUE_TYPE,
) -> u32;
type FreeFn = unsafe extern "system" fn(*const c_void);
type NotifyFn = unsafe extern "system" fn(
    HANDLE,
    WLAN_NOTIFICATION_SOURCES,
    BOOL,
    WLAN_NOTIFICATION_CALLBACK,
    *const c_void,
    *const c_void,
    *mut u32,
) -> u32;

struct Api {
    open: OpenFn,
    close: CloseFn,
    enum_if: EnumFn,
    scan: ScanFn,
    bss: BssFn,
    avail: AvailFn,
    query: QueryFn,
    free: FreeFn,
    notify: NotifyFn,
}

static API: OnceLock<Option<Api>> = OnceLock::new();

fn load() -> Option<Api> {
    let name: Vec<u16> = "wlanapi.dll".encode_utf16().chain(Some(0)).collect();
    let m = unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if m.is_null() {
        return None;
    }
    macro_rules! f {
        ($n:literal, $t:ty) => {{
            let p = unsafe { GetProcAddress(m, concat!($n, "\0").as_ptr()) }?;
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $t>(p) }
        }};
    }
    // The DLL stays loaded for the whole life of the process.
    Some(Api {
        open: f!("WlanOpenHandle", OpenFn),
        close: f!("WlanCloseHandle", CloseFn),
        enum_if: f!("WlanEnumInterfaces", EnumFn),
        scan: f!("WlanScan", ScanFn),
        bss: f!("WlanGetNetworkBssList", BssFn),
        avail: f!("WlanGetAvailableNetworkList", AvailFn),
        query: f!("WlanQueryInterface", QueryFn),
        free: f!("WlanFreeMemory", FreeFn),
        notify: f!("WlanRegisterNotification", NotifyFn),
    })
}

fn api() -> Result<&'static Api, BackendError> {
    API.get_or_init(load).as_ref().ok_or(BackendError::NoDll)
}

/// WLAN client handle, closed at the end.
struct Client {
    api: &'static Api,
    h: HANDLE,
}

// WLAN handles can be used from any thread.
unsafe impl Send for Client {}

impl Client {
    fn open() -> Result<Self, BackendError> {
        let api = api()?;
        let (mut ver, mut h) = (0u32, null_mut());
        match unsafe { (api.open)(2, null(), &mut ver, &mut h) } {
            0 => Ok(Client { api, h }),
            // 1058 service disabled, 1062 service not started
            1058 | 1062 => Err(BackendError::Service),
            // 1060 service does not exist: feature not installed
            1060 => Err(BackendError::NoDll),
            c => Err(BackendError::Other(c)),
        }
    }

    /// Notifications reach `on_note` as long as the handle stays open.
    fn listen(&self, sources: WLAN_NOTIFICATION_SOURCES) {
        let mut prev = 0u32;
        unsafe {
            (self.api.notify)(self.h, sources, 1, Some(on_note), null(), null(), &mut prev);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.h, null()) };
    }
}

/// Memory returned by the WLAN APIs, freed at the end.
struct Mem(&'static Api, *mut c_void);

impl Drop for Mem {
    fn drop(&mut self) {
        if !self.1.is_null() {
            unsafe { (self.0.free)(self.1) };
        }
    }
}

// ───────────── notifications (scan complete, roaming, disconnection) ─────────────

struct Note {
    guid: u128,
    source: u32,
    code: u32,
    at: Instant,
}

static NOTES: Mutex<Vec<Note>> = Mutex::new(Vec::new());

fn guid_key(g: &GUID) -> u128 {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..].copy_from_slice(&g.data4);
    u128::from_le_bytes(b)
}

unsafe extern "system" fn on_note(d: *mut L2_NOTIFICATION_DATA, _ctx: *mut c_void) {
    if d.is_null() {
        return;
    }
    let d = unsafe { &*d };
    let at = Instant::now();
    if let Ok(mut q) = NOTES.lock() {
        q.retain(|n| at.duration_since(n.at) < Duration::from_secs(120));
        if q.len() < 4096 {
            q.push(Note {
                guid: guid_key(&d.InterfaceGuid),
                source: d.NotificationSource,
                code: d.NotificationCode,
                at,
            });
        }
    }
}

/// Notifications of an adapter that arrived after `since`.
fn notes_after(guid: u128, since: Instant) -> Vec<(u32, u32, Instant)> {
    NOTES
        .lock()
        .map(|q| {
            q.iter()
                .filter(|n| n.guid == guid && n.at > since)
                .map(|n| (n.source, n.code, n.at))
                .collect()
        })
        .unwrap_or_default()
}

// ───────────────────────── queries ─────────────────────────

fn to_guid(id: &str) -> Result<GUID, BackendError> {
    let (data1, data2, data3, data4) = guid_parse(id).ok_or(BackendError::Other(87))?;
    Ok(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end]).trim().to_string()
}

fn ssid_bytes(s: &DOT11_SSID) -> Vec<u8> {
    s.ucSSID[..(s.uSSIDLength as usize).min(32)].to_vec()
}

/// WlanQueryInterface: raw data and size.
fn query_raw(c: &Client, g: &GUID, op: WLAN_INTF_OPCODE) -> Result<(Mem, usize), u32> {
    let (mut size, mut p, mut vt) = (0u32, null_mut(), 0);
    let r = unsafe { (c.api.query)(c.h, g, op, null(), &mut size, &mut p, &mut vt) };
    if r != 0 {
        return Err(r);
    }
    if p.is_null() {
        return Err(13);
    }
    Ok((Mem(c.api, p), size as usize))
}

fn query<T: Copy>(c: &Client, g: &GUID, op: WLAN_INTF_OPCODE) -> Result<T, u32> {
    let (m, size) = query_raw(c, g, op)?;
    if size < std::mem::size_of::<T>() {
        return Err(13);
    }
    Ok(unsafe { std::ptr::read_unaligned(m.1 as *const T) })
}

fn radio(c: &Client, g: &GUID) -> Radio {
    let Ok((m, size)) = query_raw(c, g, wlan_intf_opcode_radio_state) else {
        return Radio::Unknown;
    };
    if size < 4 {
        return Radio::Unknown;
    }
    let n = unsafe { std::ptr::read_unaligned(m.1 as *const u32) } as usize;
    let each = std::mem::size_of::<WLAN_PHY_RADIO_STATE>();
    let n = n.min((size - 4) / each).min(64);
    let (mut on, mut hw_off, mut sw_off) = (false, false, false);
    for i in 0..n {
        let s: WLAN_PHY_RADIO_STATE =
            unsafe { std::ptr::read_unaligned((m.1 as *const u8).add(4 + i * each) as *const _) };
        let sw = s.dot11SoftwareRadioState;
        let hw = s.dot11HardwareRadioState;
        on |= sw == dot11_radio_state_on && hw == dot11_radio_state_on;
        hw_off |= hw == dot11_radio_state_off;
        sw_off |= sw == dot11_radio_state_off;
    }
    match (on, hw_off, sw_off) {
        (true, _, _) => Radio::On,
        (_, true, _) => Radio::HardOff,
        (_, _, true) => Radio::SoftOff,
        _ => Radio::Unknown,
    }
}

pub fn adapters() -> Result<Vec<RawAdapter>, BackendError> {
    let c = Client::open()?;
    let mut list = null_mut();
    let r = unsafe { (c.api.enum_if)(c.h, null(), &mut list) };
    if r != 0 {
        return Err(BackendError::Other(r));
    }
    let _m = Mem(c.api, list as *mut c_void);
    let n = unsafe { (*list).dwNumberOfItems } as usize;
    let base = unsafe { addr_of!((*list).InterfaceInfo) } as *const WLAN_INTERFACE_INFO;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let info = unsafe { &*base.add(i) };
        let g = info.InterfaceGuid;
        out.push(RawAdapter {
            id: guid_text(g.data1, g.data2, g.data3, g.data4),
            name: wide(&info.strInterfaceDescription),
            connected: info.isState == wlan_interface_state_connected,
            radio: radio(&c, &g),
        });
    }
    Ok(out)
}

/// BSS list (all networks, or only those with an SSID).
fn bss_list(c: &Client, g: &GUID, filter: Option<(&DOT11_SSID, bool)>) -> Result<Vec<RawBss>, u32> {
    let (ps, kind, sec): (*const DOT11_SSID, DOT11_BSS_TYPE, BOOL) = match filter {
        Some((s, secure)) => (s, dot11_BSS_type_infrastructure, secure as BOOL),
        None => (null(), dot11_BSS_type_any, 0),
    };
    let mut list = null_mut();
    let r = unsafe { (c.api.bss)(c.h, g, ps, kind, sec, null(), &mut list) };
    if r != 0 {
        return Err(r);
    }
    if list.is_null() {
        return Ok(Vec::new());
    }
    let _m = Mem(c.api, list as *mut c_void);
    let total = unsafe { (*list).dwTotalSize } as usize;
    let n = unsafe { (*list).dwNumberOfItems } as usize;
    let base = unsafe { addr_of!((*list).wlanBssEntries) } as *const WLAN_BSS_ENTRY;
    let start = list as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let e = unsafe { base.add(i) };
        let off = e as usize - start;
        if off + std::mem::size_of::<WLAN_BSS_ENTRY>() > total {
            break;
        }
        let ent = unsafe { &*e };
        let ie_off = off + ent.ulIeOffset as usize;
        let ies = if ent.ulIeSize > 0 && ie_off + ent.ulIeSize as usize <= total {
            unsafe {
                std::slice::from_raw_parts(
                    (e as *const u8).add(ent.ulIeOffset as usize),
                    ent.ulIeSize as usize,
                )
            }
            .to_vec()
        } else {
            Vec::new()
        };
        out.push(RawBss {
            ssid: ssid_bytes(&ent.dot11Ssid),
            bssid: ent.dot11Bssid,
            rssi: ent.lRssi,
            quality: ent.uLinkQuality,
            freq_khz: ent.ulChCenterFrequency,
            phy: ent.dot11BssPhyType,
            capability: ent.usCapabilityInformation,
            ies,
        });
    }
    Ok(out)
}

fn if_index(g: &GUID) -> Option<u32> {
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    if unsafe { ConvertInterfaceGuidToLuid(g, &mut luid) } != 0 {
        return None;
    }
    let mut idx = 0u32;
    (unsafe { ConvertInterfaceLuidToIndex(&luid, &mut idx) } == 0).then_some(idx)
}

fn current(c: &Client, g: &GUID) -> Option<RawConn> {
    let a: WLAN_CONNECTION_ATTRIBUTES = query(c, g, wlan_intf_opcode_current_connection).ok()?;
    if a.isState != wlan_interface_state_connected {
        return None;
    }
    let s = a.wlanAssociationAttributes;
    Some(RawConn {
        ssid: ssid_bytes(&s.dot11Ssid),
        bssid: s.dot11Bssid,
        phy: s.dot11PhyType,
        quality: s.wlanSignalQuality,
        rx_kbps: s.ulRxRate,
        tx_kbps: s.ulTxRate,
        auth: a.wlanSecurityAttributes.dot11AuthAlgorithm,
        cipher: a.wlanSecurityAttributes.dot11CipherAlgorithm,
        profile: wide(&a.strProfileName),
        rssi: query::<i32>(c, g, wlan_intf_opcode_rssi)
            .ok()
            .filter(|r| (-120..0).contains(r)),
        channel: query::<u32>(c, g, wlan_intf_opcode_channel_number)
            .ok()
            .filter(|&ch| ch > 0),
        if_index: if_index(g),
    })
}

/// BSSIDs of hidden networks with a profile on this PC: Windows looks them up by
/// name, so the list filtered by SSID returns them.
fn hidden_profiles(c: &Client, g: &GUID, visible: &[Vec<u8>]) -> Vec<(Vec<u8>, [u8; 6])> {
    let mut list = null_mut();
    let flags = WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES;
    if unsafe { (c.api.avail)(c.h, g, flags, null(), &mut list) } != 0 || list.is_null() {
        return Vec::new();
    }
    let _m = Mem(c.api, list as *mut c_void);
    let n = unsafe { (*list).dwNumberOfItems } as usize;
    let base = unsafe { addr_of!((*list).Network) } as *const WLAN_AVAILABLE_NETWORK;
    let mut out = Vec::new();
    for i in 0..n.min(256) {
        let net = unsafe { &*base.add(i) };
        let ssid = ssid_bytes(&net.dot11Ssid);
        if net.strProfileName[0] == 0
            || ssid.is_empty()
            || net.uNumberOfBssids == 0
            || visible.contains(&ssid)
        {
            continue;
        }
        if let Ok(bss) = bss_list(c, g, Some((&net.dot11Ssid, net.bSecurityEnabled != 0))) {
            out.extend(bss.into_iter().map(|b| (ssid.clone(), b.bssid)));
        }
    }
    out
}

/// Waits for the end of the scan requested at `t0` (Windows notification).
fn wait_scan(key: u128, t0: Instant) -> ScanOutcome {
    let limit = t0 + Duration::from_secs(6);
    while Instant::now() < limit {
        for (src, code, _) in notes_after(key, t0) {
            if src == WLAN_NOTIFICATION_SOURCE_ACM {
                if code == wlan_notification_acm_scan_complete as u32 {
                    return ScanOutcome::Done;
                }
                if code == wlan_notification_acm_scan_fail as u32 {
                    return ScanOutcome::Failed(0);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    ScanOutcome::Timeout
}

pub fn scan(id: &str, fresh: bool) -> Result<RawScan, BackendError> {
    let g = to_guid(id)?;
    let c = Client::open()?;
    let mut outcome = ScanOutcome::NotRequested;
    if fresh {
        c.listen(WLAN_NOTIFICATION_SOURCE_ACM);
        let t0 = Instant::now();
        let r = unsafe { (c.api.scan)(c.h, &g, null(), null(), null()) };
        outcome = if r == 0 {
            wait_scan(guid_key(&g), t0)
        } else {
            ScanOutcome::Failed(r)
        };
    }
    let bss = bss_list(&c, &g, None);
    let hidden_profiles = match &bss {
        Ok(list) if list.iter().any(|b| super::hidden(&b.ssid).0) => {
            let visible: Vec<Vec<u8>> = list
                .iter()
                .filter(|b| !super::hidden(&b.ssid).0)
                .map(|b| b.ssid.clone())
                .collect();
            hidden_profiles(&c, &g, &visible)
        }
        _ => Vec::new(),
    };
    Ok(RawScan {
        scan: outcome,
        conn: current(&c, &g),
        bss,
        hidden_profiles,
    })
}

/// Monitor: handle kept open with roaming notifications for its whole duration.
pub struct Watch {
    c: Client,
    g: GUID,
    key: u128,
    since: Instant,
}

// GUID is plain data; Client is Send.
unsafe impl Send for Watch {}

impl Watch {
    pub fn open(id: &str) -> Result<Self, BackendError> {
        let g = to_guid(id)?;
        let c = Client::open()?;
        c.listen(WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM);
        Ok(Watch {
            key: guid_key(&g),
            c,
            g,
            since: Instant::now(),
        })
    }
}

impl Source for Watch {
    fn sample(&mut self) -> Result<RawSample, BackendError> {
        Ok(RawSample {
            conn: current(&self.c, &self.g),
        })
    }

    fn notices(&mut self) -> Vec<Notice> {
        let list = notes_after(self.key, self.since);
        let mut out = Vec::new();
        for (src, code, at) in list {
            self.since = self.since.max(at);
            if src == WLAN_NOTIFICATION_SOURCE_MSM {
                if code == wlan_notification_msm_roaming_start as u32 {
                    out.push(Notice::RoamStart(at));
                } else if code == wlan_notification_msm_roaming_end as u32 {
                    out.push(Notice::RoamEnd(at));
                }
            } else if src == WLAN_NOTIFICATION_SOURCE_ACM
                && code == wlan_notification_acm_disconnected as u32
            {
                out.push(Notice::Disconnected(at));
            }
        }
        out
    }

    fn channel_of(&mut self, bssid: &[u8; 6]) -> Option<u16> {
        let list = bss_list(&self.c, &self.g, None).ok()?;
        let b = list.iter().find(|b| &b.bssid == bssid)?;
        band_channel(b.freq_khz / 1000).map(|(_, ch)| ch)
    }
}
