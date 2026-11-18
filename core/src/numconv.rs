//! Number converter: decimal, hexadecimal, binary (and 32-bit IPv4).
//!
//! Fixed widths of 8/16/32/64 bits, signed or unsigned (two's complement), or
//! free width up to `MAX_BITS` bits, unsigned only. Everything is local.

use crate::{t, tf, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Limit of the free width.
pub const MAX_BITS: u32 = 1024;

#[derive(Debug, Deserialize)]
pub struct NumReq {
    /// Text typed by the user in the `base` field.
    pub value: String,
    /// "dec", "hex", "bin" or "ip".
    pub base: String,
    /// "8", "16", "32", "64" or "free" (empty = free).
    #[serde(default)]
    pub width: String,
    #[serde(default)]
    pub signed: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct NumResult {
    /// Bits shown (chosen width or, if free, a multiple of 8).
    pub bits: u32,
    /// Values for the fields: decimal (with the sign if requested), hexadecimal
    /// by byte, binary in groups of 4.
    pub dec: String,
    pub hex: String,
    pub bin: String,
    /// The `bits` bits, most significant first, without spaces (bit grid).
    pub raw: String,
    /// Interpretations, with the thousands separator.
    pub unsigned: String,
    pub signed: Option<String>,
    pub bytes_le: String,
    /// Value read with the bytes in reverse order (little endian), unsigned.
    pub swapped: Option<String>,
    pub ipv4: Option<String>,
    pub ascii: Option<String>,
    /// Bits set to 1 and position of the highest bit set to 1.
    pub ones: u32,
    pub msb: Option<u32>,
    /// Warning (truncated value, outside the signed range...).
    pub warning: Option<String>,
}

// ───────────────────────── unsigned integer of arbitrary length ─────────────────────────

/// Unsigned integer in 32-bit limbs, least significant first.
#[derive(Debug, Clone, PartialEq, Default)]
struct Big(Vec<u32>);

impl Big {
    fn trim(mut self) -> Self {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    fn from_u128(v: u128) -> Self {
        Big((0..4).map(|i| (v >> (32 * i)) as u32).collect()).trim()
    }

    fn bit_len(&self) -> u32 {
        match self.0.last() {
            None => 0,
            Some(&top) => (self.0.len() as u32 - 1) * 32 + (32 - top.leading_zeros()),
        }
    }

    fn bit(&self, i: u32) -> bool {
        self.0
            .get((i / 32) as usize)
            .is_some_and(|l| (l >> (i % 32)) & 1 == 1)
    }

    /// `self * m + a`
    fn mul_add(&mut self, m: u32, a: u32) {
        let mut carry = a as u64;
        for l in self.0.iter_mut() {
            let v = *l as u64 * m as u64 + carry;
            *l = v as u32;
            carry = v >> 32;
        }
        if carry > 0 {
            self.0.push(carry as u32);
        }
    }

    /// Divides by `d` and returns the remainder.
    fn div_rem(&mut self, d: u32) -> u32 {
        let mut rem = 0u64;
        for l in self.0.iter_mut().rev() {
            let v = (rem << 32) | *l as u64;
            *l = (v / d as u64) as u32;
            rem = v % d as u64;
        }
        let t = std::mem::take(self).trim();
        *self = t;
        rem as u32
    }

    fn to_u128(&self) -> Option<u128> {
        (self.bit_len() <= 128).then(|| {
            self.0
                .iter()
                .enumerate()
                .fold(0u128, |acc, (i, &l)| acc | (l as u128) << (32 * i))
        })
    }

    fn to_dec(&self) -> String {
        if self.0.is_empty() {
            return "0".into();
        }
        let mut n = self.clone();
        let mut parts = Vec::new();
        while !n.0.is_empty() {
            parts.push(n.div_rem(1_000_000_000));
        }
        let mut s = parts.pop().unwrap_or(0).to_string();
        for p in parts.iter().rev() {
            s.push_str(&format!("{p:09}"));
        }
        s
    }

    /// The `bits` least significant bits, highest first.
    fn to_bits(&self, bits: u32) -> String {
        (0..bits)
            .rev()
            .map(|i| if self.bit(i) { '1' } else { '0' })
            .collect()
    }

    fn from_bits(bits: &str) -> Self {
        let mut n = Big::default();
        for c in bits.bytes() {
            n.mul_add(2, (c == b'1') as u32);
        }
        n.trim()
    }
}

// ───────────────────────── reading the input ─────────────────────────

/// Value read: magnitude, sign and bits "declared" by the digits written
/// (e.g. `00FF` = 16 bits), used with the free width.
struct Parsed {
    mag: Big,
    neg: bool,
    digits_bits: u32,
}

fn clean(s: &str, extra: &[char]) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && !extra.contains(c))
        .collect()
}

fn parse_dec(s: &str) -> Result<Parsed> {
    let s = s.trim();
    let (neg, rest) = match s.strip_prefix('-').or_else(|| s.strip_prefix('−')) {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    // accepted thousands separators: space, _, ' and the Italian-style dot
    let raw = clean(rest, &['\'']);
    let digits = if raw.contains('.') {
        let groups: Vec<&str> = raw.split('.').collect();
        let ok = !groups[0].is_empty()
            && groups[0].len() <= 3
            && groups[1..].iter().all(|g| g.len() == 3);
        if !ok {
            return Err(t!(
                "Decimale non valido: il punto si usa solo come separatore delle migliaia (1.000.000)",
                "Invalid decimal: the dot is only used as a thousands separator (1.000.000)"
            )
            .into());
        }
        groups.concat()
    } else {
        raw
    };
    if digits.is_empty() {
        return Err(t!("Scrivi un numero decimale", "Enter a decimal number").into());
    }
    let mut mag = Big::default();
    for c in digits.chars() {
        let d = c.to_digit(10).ok_or_else(|| {
            tf!(
                "Carattere non valido nel decimale: \"{c}\" (ammessi 0–9 e il segno meno)",
                "Invalid character in the decimal: \"{c}\" (allowed: 0–9 and the minus sign)"
            )
        })?;
        mag.mul_add(10, d);
        if mag.bit_len() > MAX_BITS {
            return Err(tf!(
                "Numero troppo grande: massimo {MAX_BITS} bit",
                "Number too large: maximum {MAX_BITS} bits"
            ));
        }
    }
    let mag = mag.trim();
    Ok(Parsed {
        neg: neg && mag.bit_len() > 0,
        mag,
        digits_bits: 0,
    })
}

fn no_minus(s: &str) -> Result<()> {
    if s.trim_start().starts_with('-') {
        return Err(t!(
            "Il segno meno si scrive nel campo decimale",
            "The minus sign is entered in the decimal field"
        )
        .into());
    }
    Ok(())
}

fn parse_hex(s: &str) -> Result<Parsed> {
    no_minus(s)?;
    // 0x… or …h; MAC and dump separators: space, _, :, -, .
    let t = clean(s, &[':', '-', '.']);
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(&t);
    let t = t
        .strip_suffix('h')
        .or_else(|| t.strip_suffix('H'))
        .unwrap_or(t);
    if t.is_empty() {
        return Err(t!("Scrivi un numero esadecimale", "Enter a hexadecimal number").into());
    }
    if let Some(c) = t.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(tf!(
            "Carattere non valido nell'esadecimale: \"{c}\" (ammessi 0–9 e A–F)",
            "Invalid character in the hexadecimal: \"{c}\" (allowed: 0–9 and A–F)"
        ));
    }
    let digits_bits = t.len() as u32 * 4;
    if digits_bits > MAX_BITS {
        return Err(tf!(
            "Numero troppo lungo: massimo {MAX_BITS} bit",
            "Number too long: maximum {MAX_BITS} bits"
        ));
    }
    let bits: String = t
        .chars()
        .map(|c| format!("{:04b}", c.to_digit(16).unwrap_or(0)))
        .collect();
    Ok(Parsed {
        mag: Big::from_bits(&bits),
        neg: false,
        digits_bits,
    })
}

fn parse_bin(s: &str) -> Result<Parsed> {
    no_minus(s)?;
    let t = clean(s, &['.', ':', '-']);
    let t = t
        .strip_prefix("0b")
        .or_else(|| t.strip_prefix("0B"))
        .unwrap_or(&t);
    if t.is_empty() {
        return Err(t!("Scrivi un numero binario", "Enter a binary number").into());
    }
    if let Some(c) = t.chars().find(|c| *c != '0' && *c != '1') {
        return Err(tf!(
            "Carattere non valido nel binario: \"{c}\" (ammessi solo 0 e 1)",
            "Invalid character in the binary: \"{c}\" (only 0 and 1 allowed)"
        ));
    }
    let digits_bits = t.len() as u32;
    if digits_bits > MAX_BITS {
        return Err(tf!(
            "Numero troppo lungo: massimo {MAX_BITS} bit",
            "Number too long: maximum {MAX_BITS} bits"
        ));
    }
    Ok(Parsed {
        mag: Big::from_bits(t),
        neg: false,
        digits_bits,
    })
}

fn parse_ip(s: &str) -> Result<Parsed> {
    let ip: Ipv4Addr = s.trim().parse().map_err(|_| {
        t!(
            "Indirizzo IPv4 non valido (es. 192.0.2.10)",
            "Invalid IPv4 address (e.g. 192.0.2.10)"
        )
        .to_string()
    })?;
    Ok(Parsed {
        mag: Big::from_u128(u32::from(ip) as u128),
        neg: false,
        digits_bits: 32,
    })
}

// ───────────────────────── formatting ─────────────────────────

/// Thousands with a dot, Italian style (the same in both languages).
fn group_thousands(s: &str) -> String {
    let (sign, digits) = match s.strip_prefix('-') {
        Some(d) => ("-", d),
        None => ("", s),
    };
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push('.');
        }
        out.push(c);
    }
    format!("{sign}{out}")
}

fn chunks(s: &str, n: usize) -> Vec<String> {
    s.as_bytes()
        .chunks(n)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

const CONTROL: [&str; 32] = [
    "NUL",
    "SOH",
    "STX",
    "ETX",
    "EOT",
    "ENQ",
    "ACK",
    "BEL (campanello)", // translated by `control()`
    "BS (backspace)",
    "TAB",
    "LF (a capo)",
    "VT",
    "FF",
    "CR (ritorno carrello)",
    "SO",
    "SI",
    "DLE",
    "DC1 (XON)",
    "DC2",
    "DC3 (XOFF)",
    "DC4",
    "NAK",
    "SYN",
    "ETB",
    "CAN",
    "EM",
    "SUB",
    "ESC",
    "FS",
    "GS",
    "RS",
    "US",
];

/// Name of a control character (only the entries with a description are translated).
fn control(i: usize) -> &'static str {
    match i {
        7 => t!("BEL (campanello)", "BEL (bell)"),
        10 => t!("LF (a capo)", "LF (line feed)"),
        13 => t!("CR (ritorno carrello)", "CR (carriage return)"),
        _ => CONTROL[i],
    }
}

/// ASCII text of the bytes: a single byte (even a control one) or a sequence
/// of all printable characters.
fn ascii(bytes: &[u8]) -> Option<String> {
    match bytes {
        [b] if *b < 32 => Some(tf!(
            "{} — carattere di controllo",
            "{} — control character",
            control(*b as usize)
        )),
        [127] => Some(t!("DEL — carattere di controllo", "DEL — control character").into()),
        [b] if *b == b' ' => Some(t!("spazio", "space").into()),
        [b] if b.is_ascii_graphic() => Some(format!("\"{}\"", *b as char)),
        _ if bytes.len() > 1 && bytes.iter().all(|b| (32..127).contains(b)) => Some(format!(
            "\"{}\"",
            bytes.iter().map(|&b| b as char).collect::<String>()
        )),
        _ => None,
    }
}

// ───────────────────────── conversion ─────────────────────────

pub fn run(req: NumReq) -> Result<NumResult> {
    let width: Option<u32> = match req.width.trim() {
        "" | "free" | "libera" => None,
        w => match w.parse() {
            Ok(n @ (8 | 16 | 32 | 64)) => Some(n),
            _ => {
                return Err(t!(
                    "Larghezza non valida: 8, 16, 32, 64 bit o libera",
                    "Invalid width: 8, 16, 32, 64 bits or free"
                )
                .into())
            }
        },
    };
    let p = match req.base.as_str() {
        "dec" => parse_dec(&req.value)?,
        "hex" => parse_hex(&req.value)?,
        "bin" => parse_bin(&req.value)?,
        "ip" => parse_ip(&req.value)?,
        b => return Err(tf!("Base non valida: {b}", "Invalid base: {b}")),
    };

    let mut warning = None;
    let (bits, raw) = match width {
        None => {
            if p.neg {
                return Err(t!(
                    "Con larghezza libera i numeri negativi non sono ammessi: scegli 8, 16, 32 o 64 bit",
                    "With free width negative numbers are not allowed: choose 8, 16, 32 or 64 bits"
                )
                .into());
            }
            let need = p.mag.bit_len().max(p.digits_bits).max(1);
            let bits = need.div_ceil(8) * 8;
            (bits, p.mag)
        }
        Some(w) => {
            let mask: u128 = (1u128 << w) - 1;
            let fits = p.mag.bit_len() <= w;
            // modulo 2^w (any bits beyond the width are lost)
            let low = Big(p.mag.0.iter().take(2).copied().collect())
                .to_u128()
                .unwrap_or(0)
                & mask;
            let label = |v: &str| match req.base.as_str() {
                "dec" => v.to_string(),
                _ => format!("{} bit", p.mag.bit_len()),
            };
            let raw = if p.neg {
                let min = 1u128 << (w - 1); // |signed minimum|
                let m = p.mag.to_u128();
                if !req.signed {
                    warning = Some(tf!(
                        "Valore negativo in modalità senza segno: mostrato in complemento a due su {w} bit",
                        "Negative value in unsigned mode: shown in two's complement on {w} bits"
                    ));
                } else if !matches!(m, Some(m) if m <= min) {
                    warning = Some(tf!(
                        "-{} non entra in un intero con segno a {w} bit (da -{min} a {}): tenuti i {w} bit meno significativi",
                        "-{} does not fit in a {w}-bit signed integer (from -{min} to {}): kept the {w} least significant bits",
                        p.mag.to_dec(),
                        min - 1
                    ));
                }
                low.wrapping_neg() & mask
            } else {
                if !fits {
                    warning = Some(tf!(
                        "{} non entra in {w} bit: tenuti i {w} bit meno significativi",
                        "{} does not fit in {w} bits: kept the {w} least significant bits",
                        label(&p.mag.to_dec())
                    ));
                } else if req.signed && req.base == "dec" && low >> (w - 1) == 1 {
                    let s = low as i128 - (1i128 << w);
                    warning = Some(tf!(
                        "{} supera il massimo con segno a {w} bit ({}): interpretato come {s}",
                        "{} exceeds the {w}-bit signed maximum ({}): interpreted as {s}",
                        p.mag.to_dec(),
                        (1u128 << (w - 1)) - 1
                    ));
                }
                low
            };
            (w, Big::from_u128(raw))
        }
    };

    let raw_bits = raw.to_bits(bits);
    let unsigned_dec = raw.to_dec();
    let signed_dec = width.map(|w| {
        let v = raw.to_u128().unwrap_or(0);
        if v >> (w - 1) == 1 {
            (v as i128 - (1i128 << w)).to_string()
        } else {
            v.to_string()
        }
    });
    let bytes: Vec<u8> = chunks(&raw_bits, 8)
        .iter()
        .map(|b| u8::from_str_radix(b, 2).unwrap_or(0))
        .collect();
    let hex_be: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    let hex_le: Vec<String> = hex_be.iter().rev().cloned().collect();
    let swapped = (bytes.len() > 1).then(|| {
        let le: String = bytes.iter().rev().map(|b| format!("{b:08b}")).collect();
        group_thousands(&Big::from_bits(&le).to_dec())
    });
    let ipv4 = match width {
        Some(32) => raw.to_u128(),
        None if raw.bit_len() <= 32 && bits <= 32 => raw.to_u128(),
        _ => None,
    }
    .map(|v| Ipv4Addr::from(v as u32).to_string());
    let ones = raw_bits.bytes().filter(|&b| b == b'1').count() as u32;
    let msb = raw.bit_len().checked_sub(1);

    let dec = match (&signed_dec, req.signed) {
        (Some(s), true) => s.clone(),
        _ => unsigned_dec.clone(),
    };
    Ok(NumResult {
        bits,
        dec,
        hex: hex_be.join(" "),
        bin: chunks(&raw_bits, 4).join(" "),
        unsigned: group_thousands(&unsigned_dec),
        signed: signed_dec.as_deref().map(group_thousands),
        bytes_le: hex_le.join(" "),
        swapped,
        ipv4,
        ascii: ascii(&bytes),
        ones,
        msb,
        warning,
        raw: raw_bits,
    })
}

/// Compact hexadecimal (no spaces) of a bit string: used in tests.
#[cfg(test)]
fn hex_compact(raw: &str) -> String {
    chunks(raw, 4)
        .iter()
        .map(|n| format!("{:X}", u8::from_str_radix(n, 2).unwrap_or(0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(value: &str, base: &str, width: &str, signed: bool) -> NumResult {
        run(NumReq {
            value: value.into(),
            base: base.into(),
            width: width.into(),
            signed,
        })
        .unwrap_or_else(|e| panic!("{value} ({base}, {width}): {e}"))
    }
    fn err(value: &str, base: &str, width: &str, signed: bool) -> String {
        run(NumReq {
            value: value.into(),
            base: base.into(),
            width: width.into(),
            signed,
        })
        .unwrap_err()
    }

    #[test]
    fn base_e_formati() {
        let r = conv("192.0.2.10", "ip", "32", false);
        assert_eq!(r.hex, "C0 00 02 0A");
        assert_eq!(r.dec, "3221225994");
        assert_eq!(r.unsigned, "3.221.225.994");
        assert_eq!(r.bin, "1100 0000 0000 0000 0000 0010 0000 1010");
        assert_eq!(r.bytes_le, "0A 02 00 C0");
        assert_eq!(r.ipv4.as_deref(), Some("192.0.2.10"));
        assert_eq!(r.signed.as_deref(), Some("-1.073.741.302"));
        assert_eq!((r.bits, r.ones, r.msb), (32, 5, Some(31)));
        assert!(r.warning.is_none());
        // same bits from every base and with the usual prefixes/separators
        for (v, b) in [
            ("3221225994", "dec"),
            ("3.221.225.994", "dec"),
            ("3 221 225 994", "dec"),
            ("0xC000020A", "hex"),
            ("c000 020a", "hex"),
            ("C000020Ah", "hex"),
            ("c0:00:02:0a", "hex"),
            ("0b11000000_00000000_00000010_00001010", "bin"),
        ] {
            assert_eq!(conv(v, b, "32", false).raw, r.raw, "{v}");
        }
        assert_eq!(hex_compact(&r.raw), "C000020A");
    }

    #[test]
    fn con_segno() {
        let r = conv("-1", "dec", "8", true);
        assert_eq!((r.hex.as_str(), r.dec.as_str()), ("FF", "-1"));
        assert_eq!(r.unsigned, "255");
        assert!(r.warning.is_none());
        let r = conv("-128", "dec", "8", true);
        assert_eq!((r.hex.as_str(), r.warning.is_none()), ("80", true));
        let r = conv("-129", "dec", "8", true);
        assert_eq!(r.hex, "7F");
        assert!(r.warning.unwrap().contains("da -128 a 127"));
        let r = conv("200", "dec", "8", true);
        assert_eq!((r.hex.as_str(), r.dec.as_str()), ("C8", "-56"));
        assert!(r.warning.unwrap().contains("interpretato come -56"));
        // from hexadecimal: raw bits, no warning
        let r = conv("FFFE", "hex", "16", true);
        assert_eq!((r.dec.as_str(), r.warning), ("-2", None));
        let r = conv("-9223372036854775808", "dec", "64", true);
        assert_eq!(r.hex, "80 00 00 00 00 00 00 00");
        assert_eq!(r.signed.as_deref(), Some("-9.223.372.036.854.775.808"));
        let r = conv("18446744073709551615", "dec", "64", false);
        assert_eq!(r.hex, "FF FF FF FF FF FF FF FF");
        assert_eq!(r.signed.as_deref(), Some("-1"));
        // negative unsigned: two's complement with a warning
        let r = conv("-1", "dec", "16", false);
        assert_eq!((r.hex.as_str(), r.dec.as_str()), ("FF FF", "65535"));
        assert!(r.warning.unwrap().contains("complemento a due"));
    }

    #[test]
    fn troncamento() {
        let r = conv("256", "dec", "8", false);
        assert_eq!(r.hex, "00");
        assert!(r.warning.unwrap().contains("non entra in 8 bit"));
        let r = conv("1FF", "hex", "8", false);
        assert_eq!(r.hex, "FF");
        assert!(r.warning.unwrap().contains("9 bit"));
        let r = conv("10.0.0.1", "ip", "16", false);
        assert_eq!(r.hex, "00 01");
        assert!(r.warning.is_some());
        // leading zeros in fixed width: no truncation
        assert!(conv("0000FF", "hex", "8", false).warning.is_none());
    }

    #[test]
    fn larghezza_libera() {
        let r = conv("255", "dec", "free", false);
        assert_eq!((r.bits, r.hex.as_str(), r.signed), (8, "FF", None));
        assert_eq!(r.ascii, None);
        let r = conv("256", "dec", "", false);
        assert_eq!((r.bits, r.hex.as_str()), (16, "01 00"));
        // the digits written decide the width: 00FF = 16 bits
        assert_eq!(conv("00FF", "hex", "free", false).bits, 16);
        assert_eq!(conv("0", "dec", "free", false).bits, 8);
        // pasted MAC
        let r = conv("00-17-C8-11-22-33", "hex", "free", false);
        assert_eq!((r.bits, r.hex.as_str()), (48, "00 17 C8 11 22 33"));
        assert_eq!(r.ipv4, None);
        assert_eq!(r.dec, "102140813875");
        // 128 bits and beyond
        let max128 = "340282366920938463463374607431768211455";
        let r = conv(max128, "dec", "free", false);
        assert_eq!((r.bits, r.ones), (128, 128));
        assert_eq!(r.hex, ["FF"; 16].join(" "));
        let r = conv(
            "340282366920938463463374607431768211456",
            "dec",
            "free",
            false,
        );
        assert_eq!((r.bits, r.msb), (136, Some(128)));
        assert_eq!(conv(&r.hex, "hex", "free", false).dec, r.dec);
        let big = "1".repeat(MAX_BITS as usize);
        assert_eq!(conv(&big, "bin", "free", false).bits, MAX_BITS);
        assert!(err(&format!("1{big}"), "bin", "free", false).contains("massimo 1024 bit"));
        assert!(err("-5", "dec", "free", false).contains("negativi"));
        // IPv4 only up to 32 bits
        assert_eq!(
            conv("C0000201", "hex", "free", false).ipv4.as_deref(),
            Some("192.0.2.1")
        );
    }

    #[test]
    fn ascii_e_byte() {
        assert_eq!(
            conv("65", "dec", "8", false).ascii.as_deref(),
            Some("\"A\"")
        );
        assert!(conv("10", "dec", "8", false)
            .ascii
            .unwrap()
            .starts_with("LF"));
        assert_eq!(
            conv("32", "dec", "8", false).ascii.as_deref(),
            Some("spazio")
        );
        assert_eq!(conv("200", "dec", "8", false).ascii, None);
        assert_eq!(
            conv("0x4E54", "hex", "16", false).ascii.as_deref(),
            Some("\"NT\"")
        );
        let r = conv("1", "dec", "16", false);
        assert_eq!(r.swapped.as_deref(), Some("256"));
        assert_eq!(conv("1", "dec", "8", false).swapped, None);
    }

    #[test]
    fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert!(err("12a", "dec", "32", false).contains("Invalid character in the decimal"));
        assert!(err("1.00", "dec", "32", false).contains("thousands separator"));
        assert!(err("", "hex", "32", false).contains("hexadecimal number"));
        assert!(err("1", "dec", "12", false).contains("Invalid width"));
        assert!(err("-5", "dec", "free", false).contains("not allowed"));
        let w = conv("-1", "dec", "8", false).warning.unwrap();
        assert!(
            w.contains("two's complement") && !w.contains("complemento"),
            "{w}"
        );
        let a = conv("10", "dec", "8", false).ascii.unwrap();
        assert_eq!(a, "LF (line feed) — control character");
        assert_eq!(
            conv("32", "dec", "8", false).ascii.as_deref(),
            Some("space")
        );
    }

    #[test]
    fn errori_in_italiano() {
        assert!(err("12a", "dec", "32", false).contains("\"a\""));
        assert!(err("1.00", "dec", "32", false).contains("migliaia"));
        assert!(err("0xG1", "hex", "32", false).contains("\"G\""));
        assert!(err("102", "bin", "32", false).contains("\"2\""));
        assert!(err("-0x1", "hex", "32", false).contains("decimale"));
        assert!(err("300.1.1.1", "ip", "32", false).contains("IPv4"));
        assert!(err("1", "dec", "12", false).contains("Larghezza"));
        assert!(err("", "hex", "32", false).contains("esadecimale"));
        assert!(err("", "dec", "32", false).contains("decimale"));
    }

    #[test]
    fn big_dec_andata_e_ritorno() {
        for s in [
            "0",
            "1",
            "999999999",
            "1000000000",
            "1000000000000000000000000000001",
        ] {
            let p = parse_dec(s).unwrap();
            assert_eq!(p.mag.to_dec(), s);
        }
    }
}
