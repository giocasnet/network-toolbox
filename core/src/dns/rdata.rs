//! DNSSEC records read from raw data. `hickory-proto` without the `dnssec` feature (which
//! would pull in a cryptographic library) delivers DNSKEY, DS, RRSIG and NSEC3PARAM
//! as bytes: here they are interpreted and written in dig format. Pure functions only.
//! The app does not verify signatures: it checks that the structure is consistent.

use crate::t;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

pub const T_DS: u16 = 43;
pub const T_RRSIG: u16 = 46;
pub const T_DNSKEY: u16 = 48;
pub const T_NSEC3PARAM: u16 = 51;

#[derive(Debug, Clone, PartialEq)]
pub struct Dnskey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub key: Vec<u8>,
    /// Key tag (RFC 4034, appendix B).
    pub tag: u16,
    /// Full RDATA, used to compute the DS digest.
    pub raw: Vec<u8>,
}

impl Dnskey {
    /// Zone key (bit 7 of the flags).
    pub fn zone(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    /// Secure Entry Point: the key that signs the keys (KSK).
    pub fn sep(&self) -> bool {
        self.flags & 0x0001 != 0
    }
    pub fn revoked(&self) -> bool {
        self.flags & 0x0080 != 0
    }
    pub fn role(&self) -> &'static str {
        if self.sep() {
            "KSK"
        } else {
            "ZSK"
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ds {
    pub tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rrsig {
    pub covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    /// Unix seconds (serial number arithmetic ignored: valid until 2106).
    pub expiration: u32,
    pub inception: u32,
    pub tag: u16,
    pub signer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Nsec3Param {
    pub hash: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

/// Key tag from its RDATA.
pub fn key_tag(rdata: &[u8]) -> u16 {
    // algorithm 1 (RSA/MD5) uses a different formula
    if rdata.len() >= 4 && rdata[3] == 1 {
        let n = rdata.len();
        return if n >= 7 {
            u16::from_be_bytes([rdata[n - 3], rdata[n - 2]])
        } else {
            0
        };
    }
    let mut acc: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        acc += if i & 1 == 0 {
            (*b as u32) << 8
        } else {
            *b as u32
        };
    }
    acc += (acc >> 16) & 0xffff;
    (acc & 0xffff) as u16
}

pub fn dnskey(raw: &[u8]) -> Option<Dnskey> {
    if raw.len() < 5 {
        return None;
    }
    Some(Dnskey {
        flags: u16::from_be_bytes([raw[0], raw[1]]),
        protocol: raw[2],
        algorithm: raw[3],
        key: raw[4..].to_vec(),
        tag: key_tag(raw),
        raw: raw.to_vec(),
    })
}

pub fn ds(raw: &[u8]) -> Option<Ds> {
    if raw.len() < 5 {
        return None;
    }
    Some(Ds {
        tag: u16::from_be_bytes([raw[0], raw[1]]),
        algorithm: raw[2],
        digest_type: raw[3],
        digest: raw[4..].to_vec(),
    })
}

/// Uncompressed wire-format name (as in the "signer" field of RRSIG).
fn wire_name(raw: &[u8]) -> Option<(String, usize)> {
    let mut i = 0;
    let mut out = String::new();
    loop {
        let l = *raw.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l > 63 {
            return None;
        }
        let label = raw.get(i..i + l)?;
        out.push_str(&String::from_utf8_lossy(label));
        out.push('.');
        i += l;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some((out, i))
}

pub fn rrsig(raw: &[u8]) -> Option<Rrsig> {
    if raw.len() < 19 {
        return None;
    }
    let u32at = |i: usize| u32::from_be_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
    let (signer, _) = wire_name(&raw[18..])?;
    Some(Rrsig {
        covered: u16::from_be_bytes([raw[0], raw[1]]),
        algorithm: raw[2],
        labels: raw[3],
        original_ttl: u32at(4),
        expiration: u32at(8),
        inception: u32at(12),
        tag: u16::from_be_bytes([raw[16], raw[17]]),
        signer,
    })
}

pub fn nsec3param(raw: &[u8]) -> Option<Nsec3Param> {
    if raw.len() < 5 {
        return None;
    }
    let n = raw[4] as usize;
    Some(Nsec3Param {
        hash: raw[0],
        flags: raw[1],
        iterations: u16::from_be_bytes([raw[2], raw[3]]),
        salt: raw.get(5..5 + n)?.to_vec(),
    })
}

/// Signing algorithm name and judgement: `true` = discouraged or no longer allowed.
pub fn algorithm(a: u8) -> (&'static str, bool) {
    match a {
        1 => ("RSA/MD5", true),
        3 => ("DSA/SHA-1", true),
        5 => ("RSA/SHA-1", true),
        6 => ("DSA-NSEC3/SHA-1", true),
        7 => ("RSA/SHA-1 (NSEC3)", true),
        8 => ("RSA/SHA-256", false),
        10 => ("RSA/SHA-512", false),
        12 => ("GOST R 34.10-2001", true),
        13 => (
            t!("ECDSA P-256 con SHA-256", "ECDSA P-256 with SHA-256"),
            false,
        ),
        14 => (
            t!("ECDSA P-384 con SHA-384", "ECDSA P-384 with SHA-384"),
            false,
        ),
        15 => ("Ed25519", false),
        16 => ("Ed448", false),
        _ => (t!("sconosciuto", "unknown"), false),
    }
}

pub fn digest_name(t: u8) -> &'static str {
    match t {
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "GOST R 34.11-94",
        4 => "SHA-384",
        _ => t!("sconosciuto", "unknown"),
    }
}

/// Name in canonical form (lower case, wire format) for the DS digest.
fn canonical_owner(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    out
}

/// Is the DS the digest of this key? `None` if the digest type is not handled.
pub fn ds_matches(d: &Ds, owner: &str, key: &Dnskey) -> Option<bool> {
    let mut data = canonical_owner(owner);
    data.extend_from_slice(&key.raw);
    let digest: Vec<u8> = match d.digest_type {
        1 => Sha1::digest(&data).to_vec(),
        2 => Sha256::digest(&data).to_vec(),
        4 => Sha384::digest(&data).to_vec(),
        _ => return None,
    };
    Some(digest == d.digest)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// "20261119083000" (UTC), as dig writes signature dates.
fn sig_time(t: u32) -> String {
    let (y, mo, d, h, mi, s) = crate::util::civil(t as i64);
    format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}")
}

/// Mnemonic name of the types that can appear in "type covered".
fn type_name(t: u16) -> String {
    let rt = hickory_proto::rr::RecordType::from(t);
    match rt {
        hickory_proto::rr::RecordType::Unknown(c) => format!("TYPE{c}"),
        other => other.to_string(),
    }
}

/// Record data in dig format; `None` if the type is not among those handled here
/// or the data is invalid.
pub fn text(rtype: u16, raw: &[u8]) -> Option<String> {
    match rtype {
        T_DNSKEY => {
            let k = dnskey(raw)?;
            Some(format!(
                "{} {} {} {}",
                k.flags,
                k.protocol,
                k.algorithm,
                base64(&k.key)
            ))
        }
        T_DS => {
            let d = ds(raw)?;
            Some(format!(
                "{} {} {} {}",
                d.tag,
                d.algorithm,
                d.digest_type,
                hex(&d.digest)
            ))
        }
        T_RRSIG => {
            let s = rrsig(raw)?;
            Some(format!(
                "{} {} {} {} {} {} {} {}",
                type_name(s.covered),
                s.algorithm,
                s.labels,
                s.original_ttl,
                sig_time(s.expiration),
                sig_time(s.inception),
                s.tag,
                s.signer
            ))
        }
        T_NSEC3PARAM => {
            let p = nsec3param(raw)?;
            Some(format!(
                "{} {} {} {}",
                p.hash,
                p.flags,
                p.iterations,
                if p.salt.is_empty() {
                    "-".to_string()
                } else {
                    hex(&p.salt)
                }
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn unbase64(s: &str) -> Vec<u8> {
        let v = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                _ => 63,
            }
        };
        let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
        let mut out = Vec::new();
        for c in clean.chunks(4) {
            let pad = c.iter().filter(|x| **x == b'=').count();
            let n = c
                .iter()
                .fold(0u32, |a, x| a << 6 | if *x == b'=' { 0 } else { v(*x) });
            out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
        }
        out
    }

    /// RDATA of a DNSKEY: flags, protocol 3, algorithm, key.
    pub(crate) fn key_rdata(flags: u16, alg: u8, key: &[u8]) -> Vec<u8> {
        let mut r = flags.to_be_bytes().to_vec();
        r.extend_from_slice(&[3, alg]);
        r.extend_from_slice(key);
        r
    }

    /// Vector from RFC 4034 §5.4: DNSKEY of dskey.example.com and its DS (SHA-1).
    #[test]
    fn ds_dell_rfc_4034() {
        let key = unbase64(
            "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ\
             DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc\
             nOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
        );
        let k = dnskey(&key_rdata(256, 5, &key)).unwrap();
        assert_eq!(k.tag, 60485);
        assert!(k.zone() && !k.sep());
        assert_eq!(k.role(), "ZSK");
        let d = Ds {
            tag: 60485,
            algorithm: 5,
            digest_type: 1,
            digest: unhex(
                "2BB183AF5F22588179A53B0A98631FAD1A292118"
                    .to_lowercase()
                    .as_str(),
            ),
        };
        assert_eq!(ds_matches(&d, "dskey.example.com.", &k), Some(true));
        // the name matters, and is case-insensitive
        assert_eq!(ds_matches(&d, "DSKEY.Example.COM", &k), Some(true));
        assert_eq!(ds_matches(&d, "altro.example.com", &k), Some(false));
        let gost = Ds {
            digest_type: 3,
            ..d.clone()
        };
        assert_eq!(ds_matches(&gost, "dskey.example.com", &k), None);
        assert_eq!(
            text(T_DS, &{
                let mut r = vec![0xec, 0x45, 5, 1];
                r.extend_from_slice(&d.digest);
                r
            })
            .unwrap(),
            "60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118"
        );
    }

    #[test]
    fn digest_sha256_e_ruoli() {
        let k = dnskey(&key_rdata(257, 13, &[7u8; 64])).unwrap();
        assert!(k.sep() && k.zone() && !k.revoked());
        assert_eq!(k.role(), "KSK");
        let mut data = canonical_owner("Example.COM.");
        assert_eq!(data, b"\x07example\x03com\x00");
        data.extend_from_slice(&k.raw);
        let d = Ds {
            tag: k.tag,
            algorithm: 13,
            digest_type: 2,
            digest: Sha256::digest(&data).to_vec(),
        };
        assert_eq!(ds_matches(&d, "example.com", &k), Some(true));
        let other = dnskey(&key_rdata(257, 13, &[8u8; 64])).unwrap();
        assert_eq!(ds_matches(&d, "example.com", &other), Some(false));
        assert_ne!(k.tag, other.tag);
        assert!(text(T_DNSKEY, &k.raw)
            .unwrap()
            .starts_with("257 3 13 BwcHBwcH"));
        assert_eq!(algorithm(13), ("ECDSA P-256 con SHA-256", false));
        assert!(algorithm(5).1 && algorithm(7).1 && !algorithm(8).1);
        assert_eq!(digest_name(2), "SHA-256");
    }

    #[test]
    fn firma_e_nsec3() {
        // type A (1), algorithm 13, 2 labels, TTL 300, expiry, inception, key tag 40111, signer
        let mut raw = vec![0, 1, 13, 2];
        raw.extend_from_slice(&300u32.to_be_bytes());
        raw.extend_from_slice(&1_795_000_000u32.to_be_bytes());
        raw.extend_from_slice(&1_794_000_000u32.to_be_bytes());
        raw.extend_from_slice(&40111u16.to_be_bytes());
        raw.extend_from_slice(b"\x07example\x03com\x00");
        raw.extend_from_slice(&[9u8; 64]);
        let s = rrsig(&raw).unwrap();
        assert_eq!((s.covered, s.algorithm, s.tag), (1, 13, 40111));
        assert_eq!(s.signer, "example.com.");
        assert_eq!(s.expiration, 1_795_000_000);
        let t = text(T_RRSIG, &raw).unwrap();
        assert!(t.starts_with("A 13 2 300 2026"), "{t}");
        assert!(t.ends_with(" 40111 example.com."), "{t}");
        assert!(rrsig(&raw[..18]).is_none());

        let p = nsec3param(&[1, 0, 0, 10, 2, 0xab, 0xcd]).unwrap();
        assert_eq!(
            (p.hash, p.iterations, p.salt.clone()),
            (1, 10, vec![0xab, 0xcd])
        );
        assert_eq!(text(T_NSEC3PARAM, &[1, 0, 0, 0, 0]).unwrap(), "1 0 0 -");
        assert_eq!(
            text(T_NSEC3PARAM, &[1, 0, 0, 10, 2, 0xab, 0xcd]).unwrap(),
            "1 0 10 abcd"
        );
        assert!(nsec3param(&[1, 0, 0, 0, 4, 1]).is_none());
        assert!(text(1, &[1, 2, 3, 4]).is_none());
    }

    #[test]
    fn base64_e_nomi() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(unbase64("Zm9vYmE="), b"fooba");
        assert_eq!(wire_name(b"\x00").unwrap().0, ".");
        assert!(wire_name(b"\x05ab").is_none());
    }
}
