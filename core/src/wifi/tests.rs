use super::ie::build::*;
use super::*;
use std::collections::VecDeque;

fn bss(ssid: &[u8], mac: [u8; 6], rssi: i32, mhz: u32, ies: Vec<u8>) -> RawBss {
    let mut all = el(0, ssid);
    all.extend(ies);
    RawBss {
        ssid: ssid.to_vec(),
        bssid: mac,
        rssi,
        quality: (2 * (rssi + 100)).clamp(0, 100) as u32,
        freq_khz: mhz * 1000,
        phy: 0,
        capability: 0x0011,
        ies: all,
    }
}

fn wpa2_ent() -> Vec<u8> {
    rsn(&[4], &[1, 3], false)
}

#[test]
fn bande_e_canali() {
    assert_eq!(band_channel(2412), Some(("2.4", 1)));
    assert_eq!(band_channel(2472), Some(("2.4", 13)));
    assert_eq!(band_channel(2484), Some(("2.4", 14)));
    assert_eq!(band_channel(5180), Some(("5", 36)));
    assert_eq!(band_channel(5825), Some(("5", 165)));
    assert_eq!(band_channel(5955), Some(("6", 1)));
    assert_eq!(band_channel(6135), Some(("6", 37)));
    assert_eq!(band_channel(5935), Some(("6", 2)));
    assert_eq!(band_channel(900), None);
}

#[test]
fn larghezza_e_centro() {
    // 2.4 GHz, HT40 with secondary below (channel 11 -> block 7-11)
    let i = ie::parse(&el(61, &[11, 0x07, 0, 0, 0, 0]));
    assert_eq!(width_center("2.4", 2462, &i), (40, 2452));
    // without "STA channel width" it stays at 20
    let i = ie::parse(&el(61, &[11, 0x03, 0, 0, 0, 0]));
    assert_eq!(width_center("2.4", 2462, &i), (20, 2462));
    // 5 GHz: VHT 80 on channel 36 (centre 42)
    let mut b = el(61, &[36, 0x05, 0, 0, 0, 0]);
    b.extend(el(192, &[1, 42, 0]));
    assert_eq!(width_center("5", 5180, &ie::parse(&b)), (80, 5210));
    // VHT 160 (CCFS0 = 80 primary, CCFS1 = centre of the 160)
    let mut b = el(61, &[100, 0x05, 0, 0, 0, 0]);
    b.extend(el(192, &[1, 106, 114]));
    assert_eq!(width_center("5", 5500, &ie::parse(&b)), (160, 5570));
    // 6 GHz: HE 6 GHz at 80, then EHT at 320 (channel 37, block 320-1 centred on 31)
    let he_params: u32 = 1 << 17;
    let mut he = he_params.to_le_bytes()[..3].to_vec();
    he.extend([0, 0, 0, 37, 0x02, 39, 0, 0]);
    let i = ie::parse(&ext(36, &he));
    assert_eq!(width_center("6", 6135, &i), (80, 6145));
    let mut b = ext(36, &he);
    b.extend(ext(106, &[0x01, 0, 0, 0, 0, 0x04, 47, 31]));
    assert_eq!(width_center("6", 6135, &ie::parse(&b)), (320, 6105));
}

#[test]
fn standard_e_nome_commerciale() {
    let none = Ies::default();
    assert_eq!(standard("2.4", &none, 0), "b");
    let g = ie::parse(&el(1, &[0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]));
    assert_eq!(standard("2.4", &g, 0), "g");
    assert_eq!(standard("5", &none, 0), "a");
    let ht = ie::parse(&el(45, &[0; 26]));
    assert_eq!(standard("2.4", &ht, 0), "n");
    let mut vht = el(45, &[0; 26]);
    vht.extend(el(191, &[0; 12]));
    assert_eq!(standard("5", &ie::parse(&vht), 0), "ac");
    // VHT in 2.4 GHz (proprietary extensions) stays 802.11n
    assert_eq!(standard("2.4", &ie::parse(&vht), 0), "n");
    assert_eq!(standard("5", &ie::parse(&ext(35, &[0; 20])), 0), "ax");
    assert_eq!(standard("6", &ie::parse(&ext(108, &[0; 10])), 0), "be");
    // Windows PHY type when the elements are missing
    assert_eq!(standard("5", &none, 11), "be");
    assert_eq!(standard("5", &none, 10), "ax");
    assert_eq!(generation("be", "6"), "Wi-Fi 7");
    assert_eq!(generation("ax", "6"), "Wi-Fi 6E");
    assert_eq!(generation("ax", "5"), "Wi-Fi 6");
    assert_eq!(generation("ac", "5"), "Wi-Fi 5");
    assert_eq!(generation("n", "2.4"), "Wi-Fi 4");
    assert_eq!(generation("g", "2.4"), "");
}

#[test]
fn sicurezza_annunciata() {
    let s = |b: Vec<u8>, privacy| {
        let (n, c, k) = security(privacy, &ie::parse(&b));
        (n, c, k)
    };
    assert_eq!(s(vec![], false), ("Aperta".into(), "open", "".into()));
    assert_eq!(s(vec![], true), ("WEP".into(), "weak", "WEP".into()));
    assert_eq!(
        s(rsn(&[4], &[2], false), true),
        ("WPA2-Personal".into(), "wpa2", "AES".into())
    );
    assert_eq!(
        s(rsn(&[4], &[8], true), true),
        ("WPA3-Personal".into(), "wpa3", "AES".into())
    );
    assert_eq!(
        s(rsn(&[4], &[2, 8], false), true),
        ("WPA2/3-Personal".into(), "wpa2", "AES".into())
    );
    assert_eq!(
        s(rsn(&[4], &[1, 3], false), true),
        ("WPA2-Enterprise".into(), "ent", "AES".into())
    );
    assert_eq!(
        s(rsn(&[4], &[5], true), true),
        ("WPA3-Enterprise".into(), "ent", "AES".into())
    );
    assert_eq!(
        s(rsn(&[9], &[12], true), true),
        ("WPA3-Enterprise 192 bit".into(), "ent", "GCMP-256".into())
    );
    assert_eq!(
        s(rsn(&[4], &[18], true), true),
        ("OWE".into(), "owe", "AES".into())
    );
    assert_eq!(
        s(rsn(&[2], &[2], false), true),
        ("WPA2-Personal".into(), "weak", "TKIP".into())
    );
    assert_eq!(
        s(rsn(&[4, 2], &[2], false), true),
        ("WPA2-Personal".into(), "wpa2", "AES+TKIP".into())
    );
    // WPA only (first version)
    let wpa = [
        0x00, 0x50, 0xf2, 1, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00,
        0x50, 0xf2, 2,
    ];
    assert_eq!(
        s(el(221, &wpa), true),
        ("WPA-Personal".into(), "weak", "TKIP".into())
    );
}

#[test]
fn sicurezza_della_connessione() {
    assert_eq!(
        conn_security(6, 4),
        ("WPA2-Enterprise".into(), "AES".into())
    );
    assert_eq!(conn_security(7, 4), ("WPA2-Personal".into(), "AES".into()));
    assert_eq!(conn_security(9, 8), ("WPA3-Personal".into(), "GCMP".into()));
    assert_eq!(
        conn_security(11, 9),
        ("WPA3-Enterprise".into(), "GCMP-256".into())
    );
    assert_eq!(conn_security(1, 0), ("Aperta".into(), "".into()));
    assert_eq!(conn_security(1, 257), ("WEP".into(), "WEP".into()));
}

#[test]
fn reti_nascoste_e_gemelli() {
    assert_eq!(hidden(b""), (true, 0));
    assert_eq!(hidden(&[0; 9]), (true, 9));
    assert_eq!(hidden(b"CORP"), (false, 0));
    let a = [0x74, 0xac, 0xb9, 0x12, 0x8f, 0xa2];
    assert!(same_ap(&a, &[0x7e, 0xac, 0xb9, 0x12, 0x8f, 0xa2]));
    assert!(same_ap(&a, &[0x74, 0xac, 0xb9, 0x12, 0x8f, 0xa1]));
    assert!(!same_ap(&a, &a));
    assert!(!same_ap(&a, &[0x74, 0xac, 0xb9, 0x12, 0x8f, 0xb2]));
    assert!(!same_ap(&a, &[0x10, 0x20, 0x30, 0x12, 0x8f, 0xa2]));
    assert_eq!(ssid_text(b"Caf\xc3\xa8"), "Cafè");
    assert_eq!(ssid_text(b"Caf\xe8"), "Cafè");
}

fn oui() -> OuiDb {
    OuiDb::parse("74ACB9\tUbiquiti Inc\nC056E3\tHangzhou Hikvision\n").unwrap()
}

#[test]
fn lista_completa() {
    let me = [0x74, 0xac, 0xb9, 0x3e, 0x41, 0xc2];
    let raw = [
        bss(
            b"corp",
            [0x74, 0xac, 0xb9, 0x12, 0x8f, 0xa2],
            -67,
            5500,
            wpa2_ent(),
        ),
        bss(
            b"",
            [0x7e, 0xac, 0xb9, 0x12, 0x8f, 0xa2],
            -68,
            5500,
            rsn(&[4], &[8], true),
        ),
        bss(b"corp", me, -48, 5180, wpa2_ent()),
        bss(
            b"",
            [0x7e, 0xac, 0xb9, 0x3e, 0x41, 0xc2],
            -49,
            5180,
            wpa2_ent(),
        ),
        bss(
            &[0; 9],
            [0xc0, 0x56, 0xe3, 0x9a, 0x11, 0x04],
            -82,
            2462,
            rsn(&[4], &[2], false),
        ),
    ];
    let db = oui();
    let mut nets: Vec<Network> = raw.iter().filter_map(|b| network(b, Some(&db))).collect();
    let profiles = vec![(b"mgmt".to_vec(), [0x7e, 0xac, 0xb9, 0x3e, 0x41, 0xc2])];
    finish(&mut nets, &profiles, Some(&me));
    let sig: Vec<i32> = nets.iter().map(|n| n.rssi).collect();
    assert_eq!(sig, vec![-48, -49, -67, -68, -82]);
    assert!(nets[0].connected && !nets[1].connected);
    // hidden with a saved profile
    assert!(nets[1].hidden);
    assert_eq!(nets[1].profile.as_deref(), Some("mgmt"));
    assert_eq!(nets[1].same_ap, None);
    // hidden without a profile: twin on the same frequency
    assert_eq!(nets[3].same_ap.as_deref(), Some("corp"));
    assert_eq!(nets[3].vendor.as_deref(), Some("Ubiquiti Inc"));
    assert_eq!(nets[3].security, "WPA3-Personal");
    // hidden with the name length
    assert_eq!((nets[4].hidden, nets[4].ssid_len), (true, 9));
    assert_eq!(nets[4].ssid, "");
    assert_eq!(nets[4].vendor.as_deref(), Some("Hangzhou Hikvision"));
    assert_eq!((nets[4].band, nets[4].channel), ("2.4", 11));
}

#[test]
fn ap_wifi7_con_mlo() {
    let he_params: u32 = 1 << 17;
    let mut he = he_params.to_le_bytes()[..3].to_vec();
    he.extend([0, 0, 0, 37, 0x03, 39, 47, 0]);
    let mut ies = ext(36, &he);
    ies.extend(ext(108, &[0; 10]));
    ies.extend(ext(106, &[0x01, 0, 0, 0, 0, 0x04, 47, 31]));
    ies.extend(ext(107, &[0x10, 0x01]));
    ies.extend(rsn(&[4, 9], &[8, 24], true));
    ies.extend(el(11, &[4, 0, 51, 0, 0]));
    ies.extend(el(70, &[0; 5]));
    ies.extend(el(127, &[0, 0, 0x08]));
    ies.extend(el(54, &[0, 0, 1]));
    let n = network(
        &bss(
            b"logistica",
            [0xa8, 0x42, 0xa1, 0x5d, 0x07, 0x3c],
            -72,
            6135,
            ies,
        ),
        None,
    )
    .unwrap();
    assert_eq!((n.band, n.channel), ("6", 37));
    assert_eq!((n.width_mhz, n.center_mhz), (320, 6105));
    assert_eq!((n.std, n.gen), ("be", "Wi-Fi 7"));
    assert!(n.mlo && n.k && n.v && n.r);
    assert_eq!(n.security, "WPA3-Personal");
    assert_eq!(n.cipher, "AES+GCMP-256");
    assert_eq!((n.clients, n.load_pct), (Some(4), Some(20)));
}

fn net(band: &'static str, center: u32, width: u16, rssi: i32) -> Network {
    let mut n = network(&bss(b"x", [2, 0, 0, 0, 0, 1], rssi, 2412, vec![]), None).unwrap();
    n.band = band;
    n.center_mhz = center;
    n.width_mhz = width;
    n
}

#[test]
fn canali_consigliati() {
    assert_eq!(best_24(&[]), None);
    // strong APs on 6, a weak one on 1: the least busy is 11
    let l = vec![net("2.4", 2437, 20, -50), net("2.4", 2412, 20, -80)];
    assert_eq!(best_24(&l), Some(11));
    // a 40 MHz on 9 (7-11) also occupies 11
    let l = vec![
        net("2.4", 2437, 20, -50),
        net("2.4", 2452, 40, -55),
        net("2.4", 2412, 20, -85),
    ];
    assert_eq!(best_24(&l), Some(1));
    // 5 GHz: 36-48 and 100-112 busy, 52-64 wins (DFS)
    let l = vec![net("5", 5210, 80, -48), net("5", 5530, 80, -60)];
    assert_eq!(
        best_5(&l),
        Some(Best5 {
            label: "52–64".into(),
            dfs: true
        })
    );
    // a 160 on 36-64 also occupies 52-64
    let l = vec![net("5", 5250, 160, -50), net("5", 5530, 80, -60)];
    assert_eq!(best_5(&l).unwrap().label, "116–128");
    assert_eq!(best_5(&[net("2.4", 2437, 20, -50)]), None);
}

fn adapter_on(connected: bool) -> RawAdapter {
    RawAdapter {
        id: "{11111111-2222-3333-4444-555555555555}".into(),
        name: "Scheda di prova".into(),
        connected,
        radio: Radio::On,
    }
}

fn conn(mac: [u8; 6], rssi: i32) -> RawConn {
    RawConn {
        ssid: b"corp".to_vec(),
        bssid: mac,
        phy: 10,
        quality: 90,
        rx_kbps: 1_201_000,
        tx_kbps: 960_700,
        auth: 6,
        cipher: 4,
        profile: "corp".into(),
        rssi: Some(rssi),
        channel: Some(36),
        if_index: None,
    }
}

#[test]
fn risultato_della_scansione() {
    let me = [0x74, 0xac, 0xb9, 0x3e, 0x41, 0xc2];
    let mut ies = wpa2_ent();
    ies.extend(el(70, &[0; 5]));
    ies.extend(el(54, &[0, 0, 1]));
    ies.extend(el(192, &[1, 42, 0]));
    ies.extend(ext(35, &[0; 20]));
    let raw = RawScan {
        scan: ScanOutcome::Done,
        bss: Ok(vec![
            bss(b"corp", me, -48, 5180, ies),
            bss(
                b"vicini",
                [0x3c, 0x58, 0x5d, 0xc0, 0xa1, 0xf2],
                -79,
                2412,
                vec![],
            ),
        ]),
        conn: Some(conn(me, -48)),
        hidden_profiles: vec![],
    };
    let a = adapter_on(true);
    let r = build(std::slice::from_ref(&a), &a, Ok(raw.clone()), Some(&oui()));
    assert!(r.problem.is_none() && r.warning.is_none());
    assert_eq!(r.networks.len(), 2);
    let c = r.connection.unwrap();
    assert_eq!(c.ssid, "corp");
    assert_eq!(c.vendor.as_deref(), Some("Ubiquiti Inc"));
    assert_eq!(
        (c.band, c.channel, c.width_mhz),
        (Some("5"), Some(36), Some(80))
    );
    assert_eq!((c.std, c.gen), ("ax", "Wi-Fi 6"));
    assert_eq!((c.k, c.v, c.r), (Some(true), Some(false), Some(true)));
    assert_eq!((c.rx_mbps, c.tx_mbps), (1201.0, 960.7));
    assert_eq!(
        (c.security.as_str(), c.cipher.as_str()),
        ("WPA2-Enterprise", "AES")
    );
    assert_eq!(r.best24, Some(6));
    assert!(!r.six_seen);

    // location denied: no networks, the connection remains
    let mut denied = raw.clone();
    denied.bss = Err(5);
    let r = build(std::slice::from_ref(&a), &a, Ok(denied), None);
    assert_eq!(r.problem.unwrap().code, "location");
    assert!(r.networks.is_empty());
    let c = r.connection.unwrap();
    assert_eq!((c.band, c.channel), (None, Some(36)));

    // scan not completed: warning, list still present
    let mut late = raw.clone();
    late.scan = ScanOutcome::Timeout;
    let r = build(std::slice::from_ref(&a), &a, Ok(late), None);
    assert!(r.warning.unwrap().contains("ultima scansione"));
    assert_eq!(r.networks.len(), 2);

    // radio off
    let mut off = adapter_on(false);
    off.radio = Radio::SoftOff;
    let r = build(std::slice::from_ref(&off), &off, Ok(raw), None);
    assert_eq!(r.problem.unwrap().code, "radio_off");
    assert_eq!(r.adapters[0].radio, "off");

    // service stopped
    let r = build(
        std::slice::from_ref(&a),
        &a,
        Err(BackendError::Service),
        None,
    );
    assert!(r.problem.unwrap().detail.contains("Start-Service WlanSvc"));
}

#[test]
fn scelta_della_scheda() {
    let mut a = adapter_on(false);
    let mut b = adapter_on(true);
    a.id = "{AAAAAAAA-0000-0000-0000-000000000000}".into();
    b.id = "{BBBBBBBB-0000-0000-0000-000000000000}".into();
    let l = vec![a, b];
    assert_eq!(pick(&l, "").unwrap().id, l[1].id);
    assert_eq!(pick(&l, &l[0].id.to_lowercase()).unwrap().id, l[0].id);
    assert_eq!(pick(&l, "{sconosciuta}").unwrap().id, l[1].id);
    assert!(pick(&[], "").is_none());
}

#[cfg(not(windows))]
#[tokio::test]
async fn senza_api_wifi() {
    let r = scan(WifiReq::default(), None).await.unwrap();
    assert_eq!(r.problem.unwrap().code, "unsupported");
    let e = monitor(MonitorReq::default(), &Stop::new(), |_| {})
        .await
        .unwrap_err();
    assert!(e.contains("non disponibile"));
}

#[test]
fn guid() {
    let g = guid_text(
        0x0123_4567,
        0x89ab,
        0xcdef,
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    );
    assert_eq!(g, "{01234567-89AB-CDEF-0123-456789ABCDEF}");
    assert_eq!(
        guid_parse(&g.to_lowercase()),
        Some((
            0x0123_4567,
            0x89ab,
            0xcdef,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        ))
    );
    assert_eq!(guid_parse("{1234}"), None);
}

#[test]
fn intervallo_del_monitor() {
    let r = |ms| MonitorReq {
        adapter: String::new(),
        interval_ms: ms,
    };
    assert_eq!(monitor_interval(&r(None)), Ok(Duration::from_millis(1000)));
    assert_eq!(
        monitor_interval(&r(Some(500))),
        Ok(Duration::from_millis(500))
    );
    assert!(monitor_interval(&r(Some(100)))
        .unwrap_err()
        .contains("da 500 a 5000"));
    assert!(monitor_interval(&r(Some(6000))).is_err());
}

/// Fake source: a sequence of samples and notifications.
struct Fake {
    steps: VecDeque<(Option<RawConn>, Vec<Notice>)>,
    pending: Vec<Notice>,
}

impl Source for Fake {
    fn sample(&mut self) -> Result<RawSample, BackendError> {
        let (c, n) = self.steps.pop_front().unwrap_or((None, vec![]));
        self.pending = n;
        Ok(RawSample { conn: c })
    }
    fn notices(&mut self) -> Vec<Notice> {
        std::mem::take(&mut self.pending)
    }
    fn channel_of(&mut self, b: &[u8; 6]) -> Option<u16> {
        Some(if b[5] == 0xc2 { 36 } else { 100 })
    }
}

#[tokio::test]
async fn monitor_roaming_soglie_e_disconnessione() {
    let a = [0x74, 0xac, 0xb9, 0x3e, 0x41, 0xc2];
    let b = [0x74, 0xac, 0xb9, 0x12, 0x8f, 0xa2];
    let t = Instant::now();
    let mut roamed = conn(b, -58);
    roamed.channel = Some(100);
    let steps = VecDeque::from(vec![
        (Some(conn(a, -50)), vec![]),
        (Some(conn(a, -66)), vec![]),
        (Some(conn(a, -70)), vec![]),
        (Some(conn(a, -78)), vec![Notice::RoamStart(t)]),
        (
            Some(roamed),
            vec![Notice::RoamEnd(t + Duration::from_millis(38))],
        ),
        (None, vec![Notice::Disconnected(t)]),
        (Some(conn(b, -60)), vec![]),
    ]);
    let src = Fake {
        steps,
        pending: vec![],
    };
    let stop = Stop::new();
    let st = stop.clone();
    let mut msgs = Vec::new();
    let mut n = 0;
    let end = monitor_with(src, Duration::from_millis(5), &stop, |m| {
        if matches!(m, MonitorMsg::Sample(_)) {
            n += 1;
            if n == 7 {
                st.stop();
            }
        }
        msgs.push(m);
    })
    .await
    .unwrap();
    assert!(end.stopped);
    assert_eq!((end.samples, end.roams), (7, 1));
    let ev: Vec<(&str, String, Option<u64>)> = msgs
        .iter()
        .filter_map(|m| match m {
            MonitorMsg::Event(e) => Some((e.kind, e.text.clone(), e.gap_ms)),
            _ => None,
        })
        .collect();
    let kinds: Vec<&str> = ev.iter().map(|e| e.0).collect();
    // -66 stays "good" (hysteresis), -70 drops below -67, -78 below -75,
    // roaming at -58 goes back above -67
    assert_eq!(
        kinds,
        vec![
            "start",
            "fair",
            "weak",
            "roam",
            "good",
            "disconnect",
            "connect"
        ]
    );
    assert!(ev[0].1.contains("corp · 74:ac:b9:3e:41:c2, canale 36"));
    assert_eq!(
        ev[3].1,
        "Roaming da 74:ac:b9:3e:41:c2, canale 36, -78 dBm a 74:ac:b9:12:8f:a2, canale 100, -58 dBm"
    );
    assert_eq!(ev[3].2, Some(38));
    let samples: Vec<Option<i32>> = msgs
        .iter()
        .filter_map(|m| match m {
            MonitorMsg::Sample(s) => Some(s.rssi),
            _ => None,
        })
        .collect();
    assert_eq!(
        samples,
        vec![
            Some(-50),
            Some(-66),
            Some(-70),
            Some(-78),
            Some(-58),
            None,
            Some(-60)
        ]
    );
}

#[tokio::test]
async fn monitor_senza_connessione_e_stop() {
    let src = Fake {
        steps: VecDeque::from(vec![(None, vec![])]),
        pending: vec![],
    };
    let e = monitor_with(src, Duration::from_millis(5), &Stop::new(), |_| {})
        .await
        .unwrap_err();
    assert!(e.contains("non è connessa"));
    // stop before starting
    let stop = Stop::new();
    stop.stop();
    let src = Fake {
        steps: VecDeque::from(vec![(Some(conn([1; 6], -50)), vec![])]),
        pending: vec![],
    };
    let end = monitor_with(src, Duration::from_millis(5), &stop, |_| {})
        .await
        .unwrap();
    assert!(end.stopped);
    assert_eq!(end.samples, 0);
}

#[test]
fn messaggi_in_inglese() {
    let _g = crate::i18n::scoped(crate::i18n::Lang::En);
    let p = location_problem();
    assert!(p.title.contains("denies access"));
    assert!(!p.title.contains("nega"));
    assert_eq!(no_adapter().title, "No Wi-Fi adapter on this PC");
    assert_eq!(conn_security(1, 0).0, "Open");
    assert_eq!(security(false, &Ies::default()).0, "Open");
    assert!(!security(false, &Ies::default()).0.contains("Aperta"));
    assert_eq!(
        monitor_interval(&MonitorReq {
            adapter: String::new(),
            interval_ms: Some(10)
        })
        .unwrap_err(),
        "Interval: 500 to 5000 ms"
    );
    assert_eq!(ch_txt(Some(6)), ", channel 6");
}
