//! Information Elements of beacons and probe responses (IEEE 802.11-2020,
//! 802.11ax-2021, 802.11be-2024). Portable code: used by the Windows backend,
//! but testable on any system with hand-built beacons.

/// Content of the elements the Wi-Fi section needs.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Ies {
    /// SSID (possibly empty or all zeros, for hidden networks).
    pub ssid: Option<Vec<u8>>,
    /// Channel from the DS Parameter Set (2.4 GHz).
    pub ds_channel: Option<u8>,
    /// Maximum rate across Supported Rates and Extended Supported Rates, in units of 500 kbit/s.
    pub max_rate: u8,
    pub ht: bool,
    pub ht_op: Option<HtOp>,
    pub vht: bool,
    pub vht_op: Option<VhtOp>,
    pub he: bool,
    /// HE Operation, 6 GHz information.
    pub he_6g: Option<ChanOp>,
    pub eht: bool,
    pub eht_op: Option<ChanOp>,
    /// Basic Multi-Link element: Wi-Fi 7 AP with MLO.
    pub mlo: bool,
    pub rsn: Option<Rsn>,
    /// WPA element (first version, vendor 00:50:F2 type 1).
    pub wpa: Option<Rsn>,
    /// 802.11k: RM Enabled Capabilities.
    pub rrm: bool,
    /// 802.11v: BSS Transition in the Extended Capabilities.
    pub btm: bool,
    /// 802.11r: Mobility Domain.
    pub mdie: bool,
    /// BSS Load: associated clients and channel utilisation (0-255).
    pub load: Option<(u16, u8)>,
    /// Country (Country element), e.g. "IT".
    pub country: Option<String>,
}

/// HT Operation.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct HtOp {
    pub primary: u8,
    /// 0 none, 1 above, 3 below.
    pub secondary: u8,
    /// STA Channel Width: 40 MHz allowed.
    pub wide: bool,
}

/// VHT Operation.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct VhtOp {
    /// 0 = 20/40, 1 = 80/160/80+80, 2 = 160 (legacy), 3 = 80+80 (legacy).
    pub width: u8,
    pub ccfs0: u8,
    pub ccfs1: u8,
}

/// Operating channel of HE (6 GHz) and EHT.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct ChanOp {
    /// Primary channel (HE 6 GHz only; 0 for EHT).
    pub primary: u8,
    /// HE 6 GHz: 0 = 20, 1 = 40, 2 = 80, 3 = 160/80+80. EHT: 0–4 = 20, 40, 80, 160, 320.
    pub width: u8,
    pub ccfs0: u8,
    pub ccfs1: u8,
}

/// RSN (or WPA): suites as type numbers. Vendor-specific suites
/// become 255.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Rsn {
    pub group: u8,
    pub pairwise: Vec<u8>,
    pub akm: Vec<u8>,
    /// Management Frame Protection required.
    pub mfpr: bool,
}

const OUI_IEEE: [u8; 3] = [0x00, 0x0f, 0xac];
const OUI_MS: [u8; 3] = [0x00, 0x50, 0xf2];

fn u16le(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Reads a list of suites (16-bit count + 4-byte suites) from `pos`.
fn suites(b: &[u8], pos: &mut usize, oui: [u8; 3]) -> Option<Vec<u8>> {
    let n = u16le(b, *pos)? as usize;
    *pos += 2;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let s = b.get(*pos..*pos + 4)?;
        v.push(if s[..3] == oui { s[3] } else { 255 });
        *pos += 4;
    }
    Some(v)
}

/// RSN or WPA. Missing trailing fields take the standard defaults
/// (CCMP and 802.1X for RSN, TKIP and 802.1X for WPA).
fn parse_rsn(b: &[u8], oui: [u8; 3]) -> Option<Rsn> {
    let wpa = oui == OUI_MS;
    let (def_cipher, def_akm) = if wpa { (2, 1) } else { (4, 1) };
    if u16le(b, 0)? != 1 {
        return None;
    }
    let mut r = Rsn {
        group: def_cipher,
        pairwise: vec![def_cipher],
        akm: vec![def_akm],
        mfpr: false,
    };
    let Some(g) = b.get(2..6) else { return Some(r) };
    r.group = if g[..3] == oui { g[3] } else { 255 };
    let mut pos = 6;
    if pos >= b.len() {
        return Some(r);
    }
    r.pairwise = suites(b, &mut pos, oui)?;
    if pos >= b.len() {
        return Some(r);
    }
    r.akm = suites(b, &mut pos, oui)?;
    if let Some(caps) = u16le(b, pos) {
        r.mfpr = !wpa && caps & 0x40 != 0;
    }
    Some(r)
}

/// HE Operation: the optional "6 GHz Operation Information" field (bit 17).
fn parse_he_op(b: &[u8]) -> Option<ChanOp> {
    let p = u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, 0]);
    // parameters (3) + BSS color (1) + Basic HE-MCS (2)
    let mut pos = 6;
    if p & (1 << 14) != 0 {
        pos += 3; // VHT Operation Information
    }
    if p & (1 << 15) != 0 {
        pos += 1; // Max Co-Hosted BSSID Indicator
    }
    if p & (1 << 17) == 0 {
        return None;
    }
    let s = b.get(pos..pos + 4)?;
    Some(ChanOp {
        primary: s[0],
        width: s[1] & 0x03,
        ccfs0: s[2],
        ccfs1: s[3],
    })
}

/// EHT Operation: parameters (1) + Basic EHT-MCS (4) + optional information.
fn parse_eht_op(b: &[u8]) -> Option<ChanOp> {
    if b.first()? & 0x01 == 0 {
        return None;
    }
    let s = b.get(5..8)?;
    Some(ChanOp {
        primary: 0,
        width: s[0] & 0x07,
        ccfs0: s[1],
        ccfs1: s[2],
    })
}

/// Parses the elements; stops at the first truncated element.
pub fn parse(data: &[u8]) -> Ies {
    let mut ies = Ies::default();
    let mut i = 0;
    while i + 2 <= data.len() {
        let (id, len) = (data[i], data[i + 1] as usize);
        let Some(b) = data.get(i + 2..i + 2 + len) else {
            break;
        };
        i += 2 + len;
        match id {
            0 if ies.ssid.is_none() => ies.ssid = Some(b.to_vec()),
            1 | 50 => {
                let m = b.iter().map(|r| r & 0x7f).max().unwrap_or(0);
                ies.max_rate = ies.max_rate.max(m);
            }
            3 => ies.ds_channel = b.first().copied(),
            7 if b.len() >= 2 => {
                let c: String = b[..2]
                    .iter()
                    .filter(|c| c.is_ascii_alphabetic())
                    .map(|&c| c as char)
                    .collect();
                if c.len() == 2 {
                    ies.country = Some(c);
                }
            }
            11 if b.len() >= 3 => {
                ies.load = Some((u16::from_le_bytes([b[0], b[1]]), b[2]));
            }
            45 => ies.ht = true,
            48 => ies.rsn = parse_rsn(b, OUI_IEEE),
            54 => ies.mdie = true,
            61 if b.len() >= 2 => {
                ies.ht_op = Some(HtOp {
                    primary: b[0],
                    secondary: b[1] & 0x03,
                    wide: b[1] & 0x04 != 0,
                })
            }
            70 => ies.rrm = true,
            127 => ies.btm = b.get(2).is_some_and(|x| x & 0x08 != 0),
            191 => ies.vht = true,
            192 if b.len() >= 3 => {
                ies.vht_op = Some(VhtOp {
                    width: b[0],
                    ccfs0: b[1],
                    ccfs1: b[2],
                })
            }
            221 if b.len() >= 4 && b[..3] == OUI_MS && b[3] == 1 => {
                ies.wpa = parse_rsn(&b[4..], OUI_MS);
            }
            255 if !b.is_empty() => {
                let ext = &b[1..];
                match b[0] {
                    35 => ies.he = true,
                    36 => {
                        ies.he = true;
                        ies.he_6g = parse_he_op(ext);
                    }
                    106 => {
                        ies.eht = true;
                        ies.eht_op = parse_eht_op(ext);
                    }
                    107 => {
                        // Basic Multi-Link: type 0 in the low 3 bits of the Multi-Link Control
                        if ext.first().is_some_and(|c| c & 0x07 == 0) {
                            ies.mlo = true;
                        }
                    }
                    108 => ies.eht = true,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    ies
}

#[cfg(test)]
pub mod build {
    //! Building of test beacons.

    pub fn el(id: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![id, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    pub fn ext(id: u8, data: &[u8]) -> Vec<u8> {
        let mut d = vec![id];
        d.extend_from_slice(data);
        el(255, &d)
    }

    /// RSN with the given AKMs and ciphers (IEEE suites 00-0F-AC).
    pub fn rsn(pairwise: &[u8], akm: &[u8], mfpr: bool) -> Vec<u8> {
        let mut d = vec![1, 0, 0x00, 0x0f, 0xac, pairwise[0]];
        d.extend_from_slice(&(pairwise.len() as u16).to_le_bytes());
        for p in pairwise {
            d.extend_from_slice(&[0x00, 0x0f, 0xac, *p]);
        }
        d.extend_from_slice(&(akm.len() as u16).to_le_bytes());
        for a in akm {
            d.extend_from_slice(&[0x00, 0x0f, 0xac, *a]);
        }
        let caps: u16 = if mfpr { 0xc0 } else { 0x80 };
        d.extend_from_slice(&caps.to_le_bytes());
        el(48, &d)
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn elementi_di_base() {
        let mut b = el(0, b"ufficio");
        b.extend(el(1, &[0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]));
        b.extend(el(3, &[6]));
        b.extend(el(7, b"IT\x20\x01\x0d\x14"));
        b.extend(el(11, &[9, 0, 60, 0, 0]));
        b.extend(el(45, &[0; 26]));
        b.extend(el(61, &[6, 0x07, 0, 0, 0, 0]));
        b.extend(rsn(&[4], &[2, 8], false));
        b.extend(el(54, &[0x12, 0x34, 0x01]));
        b.extend(el(70, &[0x73, 0, 0, 0, 0]));
        b.extend(el(127, &[0x04, 0x00, 0x08, 0x00]));
        let i = parse(&b);
        assert_eq!(i.ssid.as_deref(), Some(&b"ufficio"[..]));
        assert_eq!(i.ds_channel, Some(6));
        assert_eq!(i.max_rate, 0x6c);
        assert_eq!(i.country.as_deref(), Some("IT"));
        assert_eq!(i.load, Some((9, 60)));
        assert!(i.ht && !i.vht && !i.he && !i.eht);
        assert_eq!(
            i.ht_op,
            Some(HtOp {
                primary: 6,
                secondary: 3,
                wide: true
            })
        );
        let r = i.rsn.unwrap();
        assert_eq!(
            (r.group, r.pairwise, r.akm, r.mfpr),
            (4, vec![4], vec![2, 8], false)
        );
        assert!(i.rrm && i.btm && i.mdie);
    }

    #[test]
    fn elemento_troncato_e_rsn_corto() {
        // The last element declares 10 bytes but has 2: it is ignored
        let mut b = el(0, b"x");
        b.extend([48, 10, 1, 0]);
        let i = parse(&b);
        assert_eq!(i.ssid.as_deref(), Some(&b"x"[..]));
        assert!(i.rsn.is_none());
        // RSN with only version and group: default values
        let i = parse(&el(48, &[1, 0, 0x00, 0x0f, 0xac, 4]));
        let r = i.rsn.unwrap();
        assert_eq!((r.pairwise, r.akm), (vec![4], vec![1]));
        // unknown version
        assert!(parse(&el(48, &[2, 0])).rsn.is_none());
    }

    #[test]
    fn wpa_prima_versione() {
        let wpa = [
            0x00, 0x50, 0xf2, 1, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00,
            0x50, 0xf2, 2,
        ];
        let i = parse(&el(221, &wpa));
        let r = i.wpa.unwrap();
        assert_eq!((r.pairwise, r.akm), (vec![2], vec![2]));
        // other vendor elements ignored
        assert!(parse(&el(221, &[0x00, 0x50, 0xf2, 4, 0x10])).wpa.is_none());
    }

    #[test]
    fn vht_he_eht() {
        let mut b = el(191, &[0; 12]);
        b.extend(el(192, &[1, 42, 50]));
        b.extend(ext(35, &[0; 20]));
        // HE Operation with 6 GHz Operation Information (bit 17) and VHT info (bit 14)
        let params: u32 = (1 << 17) | (1 << 14);
        let mut he = params.to_le_bytes()[..3].to_vec();
        he.extend([0x01, 0xfc, 0xff]); // BSS color, Basic HE-MCS
        he.extend([0, 0, 0]); // VHT Operation Information
        he.extend([37, 0x03, 39, 47, 0x00]); // primary 37, 160 MHz
        b.extend(ext(36, &he));
        b.extend(ext(108, &[0; 10]));
        b.extend(ext(106, &[0x01, 0, 0, 0, 0, 0x04, 15, 31]));
        b.extend(ext(107, &[0x10, 0x01]));
        let i = parse(&b);
        assert!(i.vht && i.he && i.eht && i.mlo);
        assert_eq!(
            i.vht_op,
            Some(VhtOp {
                width: 1,
                ccfs0: 42,
                ccfs1: 50
            })
        );
        assert_eq!(
            i.he_6g,
            Some(ChanOp {
                primary: 37,
                width: 3,
                ccfs0: 39,
                ccfs1: 47
            })
        );
        assert_eq!(
            i.eht_op,
            Some(ChanOp {
                primary: 0,
                width: 4,
                ccfs0: 15,
                ccfs1: 31
            })
        );
        // Multi-Link of a type other than Basic (e.g. 1 = Probe Request): no MLO
        assert!(!parse(&ext(107, &[0x11, 0x00])).mlo);
        // EHT Operation without channel information
        assert_eq!(parse(&ext(106, &[0x00, 0, 0, 0, 0])).eht_op, None);
    }
}
