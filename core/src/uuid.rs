//! UUID generator and analyser (RFC 9562).
//!
//! - v4: 122 random bits from the system's cryptographic generator (`getrandom`).
//! - v7: Unix milliseconds (48 bits) + 74 random bits; within a batch the values
//!   are strictly increasing even in the same millisecond.
//! - v5: SHA-1 of namespace + name: same name, same UUID.
//!
//! The interface always receives the lowercase canonical form with hyphens and
//! formats it (uppercase, braces, urn) without regenerating.

use crate::{t, tf, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

pub const MAX_COUNT: u32 = 100;
const DEFAULT_COUNT: u32 = 5;
const MAX_NAME: usize = 1024;

/// Predefined namespaces (RFC 9562, appendix C).
pub const NS_DNS: [u8; 16] = ns(0x10);
pub const NS_URL: [u8; 16] = ns(0x11);
pub const NS_OID: [u8; 16] = ns(0x12);
pub const NS_X500: [u8; 16] = ns(0x14);

const fn ns(b3: u8) -> [u8; 16] {
    [
        0x6b, 0xa7, 0xb8, b3, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]
}

#[derive(Debug, Deserialize)]
pub struct UuidReq {
    /// "4", "7" or "5".
    pub version: String,
    #[serde(default, deserialize_with = "crate::util::opt_u32")]
    pub count: Option<u32>,
    /// v5: "dns", "url", "oid", "x500" or a UUID.
    #[serde(default)]
    pub namespace: String,
    /// v5: one name per line.
    #[serde(default)]
    pub names: String,
}

#[derive(Debug, Serialize)]
pub struct UuidResult {
    pub version: u8,
    pub uuids: Vec<String>,
    /// v5: the name of each UUID, in the same order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// v5: namespace used, in canonical form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InspectReq {
    pub text: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct InspectResult {
    pub canonical: String,
    pub version: u8,
    pub version_name: String,
    pub variant: String,
    /// Encoded instant (v1, v6, v7), in Unix milliseconds and readable UTC.
    pub time_ms: Option<i64>,
    pub time_utc: Option<String>,
    /// v1/v6: node (MAC) and clock sequence.
    pub node: Option<String>,
    pub node_random: bool,
    pub clock_seq: Option<u16>,
    /// Bytes in Windows order (GUID, Active Directory `objectGUID`):
    /// the first three fields are little endian.
    pub guid_bytes: String,
    /// LDAP filter to look up an AD object with this `objectGUID`.
    pub ldap_filter: String,
}

// ───────────────────────── text form ─────────────────────────

pub fn format(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Reads a UUID with or without hyphens, in braces, with `urn:uuid:`, upper or lower case.
pub fn parse(s: &str) -> Result<[u8; 16]> {
    let t = s.trim();
    let t = t
        .get(..9)
        .filter(|p| p.eq_ignore_ascii_case("urn:uuid:"))
        .map_or(t, |_| &t[9..]);
    let t = t
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(t);
    let hex: String = t
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(t!(
            "UUID non valido: servono 32 cifre esadecimali (es. 550e8400-e29b-41d4-a716-446655440000)",
            "Invalid UUID: 32 hexadecimal digits are required (e.g. 550e8400-e29b-41d4-a716-446655440000)"
        )
        .into());
    }
    let mut b = [0u8; 16];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
    }
    Ok(b)
}

fn set_version(b: &mut [u8; 16], v: u8) {
    b[6] = (b[6] & 0x0f) | (v << 4);
    b[8] = (b[8] & 0x3f) | 0x80; // RFC variant
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| {
        tf!(
            "Generatore casuale del sistema non disponibile: {e}",
            "System random generator not available: {e}"
        )
    })?;
    Ok(b)
}

// ───────────────────────── generation ─────────────────────────

pub fn v4() -> Result<[u8; 16]> {
    let mut b = random::<16>()?;
    set_version(&mut b, 4);
    Ok(b)
}

/// Strictly increasing batch of v7 (RFC 9562, §6.2 method 2: if the
/// millisecond does not advance, the random part is incremented by a random value).
pub fn v7_batch(n: usize, now_ms: u64) -> Result<Vec<[u8; 16]>> {
    const RAND_BITS: u32 = 74;
    const RAND_MAX: u128 = (1u128 << RAND_BITS) - 1;
    let mut out = Vec::with_capacity(n);
    let mut ms = now_ms & 0xffff_ffff_ffff;
    // the first value leaves room for the increments (top bit at 0)
    let mut rnd = u128::from_le_bytes(pad16(random::<10>()?)) & (RAND_MAX >> 1);
    for i in 0..n {
        if i > 0 {
            let step = 1 + u16::from_le_bytes(random::<2>()?) as u128;
            rnd += step;
            if rnd > RAND_MAX {
                // counter overflow: move on to the next millisecond
                ms += 1;
                rnd = u128::from_le_bytes(pad16(random::<10>()?)) & (RAND_MAX >> 1);
            }
        }
        out.push(v7_from(ms, rnd));
    }
    Ok(out)
}

fn pad16(b: [u8; 10]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[..10].copy_from_slice(&b);
    o
}

/// Builds a v7: 48 bits of ms, version, 12 bits (rand_a), variant, 62 bits (rand_b).
fn v7_from(ms: u64, rnd: u128) -> [u8; 16] {
    let rand_a = (rnd >> 62) as u16 & 0x0fff;
    let rand_b = rnd & ((1u128 << 62) - 1);
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6..8].copy_from_slice(&rand_a.to_be_bytes());
    b[8..].copy_from_slice(&(rand_b as u64).to_be_bytes());
    set_version(&mut b, 7);
    b
}

pub fn v5(namespace: &[u8; 16], name: &str) -> [u8; 16] {
    let mut h = Sha1::new();
    h.update(namespace);
    h.update(name.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    set_version(&mut b, 5);
    b
}

fn namespace(s: &str) -> Result<[u8; 16]> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "dns" => Ok(NS_DNS),
        "url" => Ok(NS_URL),
        "oid" => Ok(NS_OID),
        "x500" => Ok(NS_X500),
        other => parse(other).map_err(|_| {
            t!(
                "Namespace non valido: scegli DNS, URL, OID, X.500 o scrivi un UUID",
                "Invalid namespace: choose DNS, URL, OID, X.500 or enter a UUID"
            )
            .to_string()
        }),
    }
}

pub fn generate(req: UuidReq) -> Result<UuidResult> {
    match req.version.trim() {
        "4" | "7" => {
            let n = req.count.unwrap_or(DEFAULT_COUNT);
            if !(1..=MAX_COUNT).contains(&n) {
                return Err(tf!(
                    "Quantità: da 1 a {MAX_COUNT}",
                    "Quantity: 1 to {MAX_COUNT}"
                ));
            }
            let list = if req.version.trim() == "4" {
                (0..n).map(|_| v4()).collect::<Result<Vec<_>>>()?
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                v7_batch(n as usize, now)?
            };
            Ok(UuidResult {
                version: req.version.trim().parse().unwrap_or(4),
                uuids: list.iter().map(format).collect(),
                names: None,
                namespace: None,
            })
        }
        "5" => {
            let ns = namespace(&req.namespace)?;
            let names: Vec<String> = req
                .names
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            if names.is_empty() {
                return Err(t!(
                    "Scrivi almeno un nome (uno per riga)",
                    "Enter at least one name (one per line)"
                )
                .into());
            }
            if names.len() > MAX_COUNT as usize {
                return Err(tf!(
                    "Al massimo {MAX_COUNT} nomi per volta",
                    "At most {MAX_COUNT} names at a time"
                ));
            }
            if let Some(n) = names.iter().find(|n| n.len() > MAX_NAME) {
                return Err(tf!(
                    "Nome troppo lungo ({} caratteri, massimo {MAX_NAME})",
                    "Name too long ({} characters, maximum {MAX_NAME})",
                    n.chars().count()
                ));
            }
            Ok(UuidResult {
                version: 5,
                uuids: names.iter().map(|n| format(&v5(&ns, n))).collect(),
                names: Some(names),
                namespace: Some(format(&ns)),
            })
        }
        v => Err(tf!(
            "Versione non supportata: {v} (4, 7 o 5)",
            "Unsupported version: {v} (4, 7 or 5)"
        )),
    }
}

// ───────────────────────── analysis ─────────────────────────

/// "2026-11-04 08:00:00.123 UTC" from Unix milliseconds (integers only: no rounding).
fn utc_ms(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = crate::util::civil(ms.div_euclid(1000));
    format!(
        "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{:03} UTC",
        ms.rem_euclid(1000)
    )
}

/// 100 ns intervals between 15/10/1582 (UUID epoch) and 1/1/1970.
const GREGORIAN_OFFSET: u64 = 0x01B2_1DD2_1381_4000;

pub fn inspect(req: InspectReq) -> Result<InspectResult> {
    let b = parse(&req.text)?;
    let canonical = format(&b);
    let nil = b == [0u8; 16];
    let max = b == [0xffu8; 16];
    let variant_bits = b[8] >> 5;
    let variant = if nil || max {
        "—"
    } else if variant_bits & 0b100 == 0 {
        t!(
            "NCS (riservata, retrocompatibilità)",
            "NCS (reserved, backward compatibility)"
        )
    } else if variant_bits & 0b110 == 0b100 {
        "RFC 9562 (standard)"
    } else if variant_bits == 0b110 {
        t!("Microsoft (GUID storico)", "Microsoft (legacy GUID)")
    } else {
        t!("riservata per usi futuri", "reserved for future use")
    }
    .to_string();
    let rfc = variant_bits & 0b110 == 0b100;
    let version = if rfc { b[6] >> 4 } else { 0 };
    let version_name = if nil {
        t!("UUID nullo (tutti zero)", "UUID nil (all zeros)")
    } else if max {
        t!("UUID massimo (tutti F)", "UUID max (all F)")
    } else if !rfc {
        t!(
            "non definita (variante non standard)",
            "undefined (non-standard variant)"
        )
    } else {
        match version {
            1 => t!(
                "v1 — data e ora + nodo (MAC)",
                "v1 — date and time + node (MAC)"
            ),
            2 => "v2 — DCE Security",
            3 => t!("v3 — da nome, MD5", "v3 — from name, MD5"),
            4 => t!("v4 — casuale", "v4 — random"),
            5 => t!("v5 — da nome, SHA-1", "v5 — from name, SHA-1"),
            6 => t!(
                "v6 — data e ora riordinate + nodo",
                "v6 — reordered date and time + node"
            ),
            7 => t!(
                "v7 — ordinato nel tempo (ms Unix)",
                "v7 — time-ordered (Unix ms)"
            ),
            8 => t!("v8 — personalizzato", "v8 — custom"),
            _ => t!("versione sconosciuta", "unknown version"),
        }
    }
    .to_string();

    let be16 = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]) as u64;
    let be32 = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u64;
    let gregorian = |ts: u64| (ts as i64 - GREGORIAN_OFFSET as i64).div_euclid(10_000);
    let time_ms = match (rfc, version) {
        (true, 1) => Some(gregorian(
            ((be16(6) & 0x0fff) << 48) | (be16(4) << 32) | be32(0),
        )),
        (true, 6) => Some(gregorian(
            (be32(0) << 28) | (be16(4) << 12) | (be16(6) & 0x0fff),
        )),
        (true, 7) => Some(((be32(0) << 16) | be16(4)) as i64),
        _ => None,
    };
    let (node, node_random, clock_seq) = if rfc && (version == 1 || version == 6) {
        let mac: Vec<String> = b[10..].iter().map(|x| format!("{x:02X}")).collect();
        (
            Some(mac.join(":")),
            b[10] & 1 == 1, // multicast bit: random node, not a real MAC
            Some(be16(8) as u16 & 0x3fff),
        )
    } else {
        (None, false, None)
    };
    // Windows order: Data1 (4 bytes), Data2 and Data3 (2 bytes) little endian
    let mut ms = b;
    ms[..4].reverse();
    ms[4..6].reverse();
    ms[6..8].reverse();
    Ok(InspectResult {
        canonical,
        version,
        version_name,
        variant,
        time_utc: time_ms.map(utc_ms),
        time_ms,
        node,
        node_random,
        clock_seq,
        guid_bytes: ms
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        ldap_filter: format!(
            "(objectGUID={})",
            ms.iter().map(|x| format!("\\{x:02X}")).collect::<String>()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(version: &str, count: &str) -> UuidReq {
        UuidReq {
            version: version.into(),
            count: count.parse().ok(),
            namespace: String::new(),
            names: String::new(),
        }
    }
    fn insp(s: &str) -> InspectResult {
        inspect(InspectReq { text: s.into() }).unwrap()
    }

    #[test]
    fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let e = generate(req("4", "0")).unwrap_err();
        assert_eq!(e, "Quantity: 1 to 100");
        assert!(generate(req("3", "1"))
            .unwrap_err()
            .contains("Unsupported version"));
        let e = parse("zz").unwrap_err();
        assert!(
            e.starts_with("Invalid UUID") && !e.contains("non valido"),
            "{e}"
        );
        let n = insp("00000000-0000-0000-0000-000000000000");
        assert!(n.version_name.starts_with("UUID") && !n.version_name.contains("nullo"));
        let v = insp("f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
        assert!(v.variant.starts_with("RFC"), "{}", v.variant);
        assert_eq!(v.version_name, "v1 — date and time + node (MAC)");
        let w = insp("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert!(w.version_name.starts_with("v1"));
    }

    #[test]
    fn v4_formato_e_unicita() {
        let r = generate(req("4", "100")).unwrap();
        assert_eq!(r.uuids.len(), 100);
        let mut set = std::collections::HashSet::new();
        for u in &r.uuids {
            assert_eq!(u.len(), 36);
            assert_eq!(&u[14..15], "4");
            assert!("89ab".contains(&u[19..20]), "{u}");
            assert!(set.insert(u.clone()));
        }
        assert_eq!(generate(req("4", "")).unwrap().uuids.len(), 5);
        assert!(generate(req("4", "0")).unwrap_err().contains("da 1 a 100"));
        assert!(generate(req("4", "101")).is_err());
        assert!(generate(req("3", "1"))
            .unwrap_err()
            .contains("non supportata"));
    }

    #[test]
    fn v7_crescenti_e_tempo() {
        let now = 1_762_243_200_123u64; // 2025-11-04 08:00:00.123 UTC
        let list = v7_batch(100, now).unwrap();
        let s: Vec<String> = list.iter().map(format).collect();
        let mut sorted = s.clone();
        sorted.sort();
        assert_eq!(s, sorted, "non ordinati");
        sorted.dedup();
        assert_eq!(sorted.len(), 100);
        let i = insp(&s[0]);
        assert_eq!(i.version, 7);
        assert_eq!(i.time_ms, Some(now as i64));
        assert_eq!(i.time_utc.as_deref(), Some("2025-11-04 08:00:00.123 UTC"));
        assert!(i.variant.starts_with("RFC"));
        // counter overflow: moves on to the next millisecond without losing the order
        let a = v7_from(5, (1u128 << 74) - 1);
        let b = v7_from(6, 0);
        assert!(format(&a) < format(&b));
        let r = generate(req("7", "3")).unwrap();
        assert_eq!(&r.uuids[0][14..15], "7");
    }

    #[test]
    fn v5_vettori_noti() {
        // Python reference values: uuid.uuid5(uuid.NAMESPACE_DNS, "python.org") ecc.
        assert_eq!(
            format(&v5(&NS_DNS, "python.org")),
            "886313e1-3b8a-5372-9b90-0c9aee199e5d"
        );
        assert_eq!(
            format(&v5(&NS_URL, "https://www.python.org/")),
            "5406f80d-92e9-51cd-a176-77445955e733"
        );
        let r = generate(UuidReq {
            version: "5".into(),
            count: None,
            namespace: "dns".into(),
            names: "python.org\n\n  example.com  \n".into(),
        })
        .unwrap();
        assert_eq!(r.uuids.len(), 2);
        assert_eq!(r.uuids[0], "886313e1-3b8a-5372-9b90-0c9aee199e5d");
        assert_eq!(r.names.unwrap()[1], "example.com");
        // custom namespace and same name → same UUID
        let a = generate(UuidReq {
            version: "5".into(),
            count: None,
            namespace: "{886313E1-3B8A-5372-9B90-0C9AEE199E5D}".into(),
            names: "x".into(),
        })
        .unwrap();
        let b = generate(UuidReq {
            version: "5".into(),
            count: None,
            namespace: "886313e13b8a53729b900c9aee199e5d".into(),
            names: "x".into(),
        })
        .unwrap();
        assert_eq!(a.uuids, b.uuids);
        let e = generate(UuidReq {
            version: "5".into(),
            count: None,
            namespace: "pippo".into(),
            names: "x".into(),
        })
        .unwrap_err();
        assert!(e.contains("Namespace"));
        let e = generate(UuidReq {
            version: "5".into(),
            count: None,
            namespace: "dns".into(),
            names: " \n ".into(),
        })
        .unwrap_err();
        assert!(e.contains("almeno un nome"));
    }

    #[test]
    fn analisi() {
        // RFC 9562 v1 (appendix A.1)
        let i = insp("C232AB00-9414-11EC-B3C8-9F6BDECED846");
        assert_eq!(i.canonical, "c232ab00-9414-11ec-b3c8-9f6bdeced846");
        assert_eq!(i.version, 1);
        assert_eq!(i.time_utc.as_deref(), Some("2022-02-22 19:22:22.000 UTC"));
        assert_eq!(i.node.as_deref(), Some("9F:6B:DE:CE:D8:46"));
        assert!(i.node_random);
        assert_eq!(i.clock_seq, Some(0x33c8));
        // v6 (A.5): same instant as the v1
        let i6 = insp("1EC9414C-232A-6B00-B3C8-9F6BDECED846");
        assert_eq!((i6.version, i6.time_ms), (6, i.time_ms));
        // v7 (A.6)
        let i7 = insp("urn:uuid:017F22E2-79B0-7CC3-98C4-DC0C0C07398F");
        assert_eq!(i7.time_utc.as_deref(), Some("2022-02-22 19:22:22.000 UTC"));
        // Windows order and LDAP filter
        let g = insp("{886313e1-3b8a-5372-9b90-0c9aee199e5d}");
        assert_eq!(
            g.guid_bytes,
            "E1 13 63 88 8A 3B 72 53 9B 90 0C 9A EE 19 9E 5D"
        );
        assert_eq!(
            g.ldap_filter,
            "(objectGUID=\\E1\\13\\63\\88\\8A\\3B\\72\\53\\9B\\90\\0C\\9A\\EE\\19\\9E\\5D)"
        );
        assert_eq!(g.version, 5);
        assert!(insp("00000000-0000-0000-0000-000000000000")
            .version_name
            .contains("nullo"));
        assert!(insp("ffffffff-ffff-ffff-ffff-ffffffffffff")
            .version_name
            .contains("massimo"));
        // legacy Microsoft GUID (variant 110)
        assert!(insp("00000000-0000-0000-C000-000000000046")
            .variant
            .starts_with("Microsoft"));
        assert!(inspect(InspectReq { text: "123".into() })
            .unwrap_err()
            .contains("32 cifre"));
        assert!(inspect(InspectReq {
            text: "886313e1-3b8a-5372-9b90-0c9aee199e5z".into()
        })
        .is_err());
    }
}
