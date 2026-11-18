//! Deserialisation helpers: the interface sends numbers taken from text fields
//! as strings ("4"), so we accept both numbers and strings.

use serde::{de, Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(untagged)]
enum NumOrStr {
    N(u64),
    S(String),
}

pub fn opt_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    match Option::<NumOrStr>::deserialize(d)? {
        None => Ok(None),
        Some(NumOrStr::N(n)) => u32::try_from(n).map(Some).map_err(de::Error::custom),
        Some(NumOrStr::S(s)) => {
            let s = s.trim();
            if s.is_empty() {
                Ok(None)
            } else {
                s.parse().map(Some).map_err(|_| {
                    de::Error::custom(crate::tf!(
                        "valore numerico non valido: {s}",
                        "invalid numeric value: {s}"
                    ))
                })
            }
        }
    }
}

/// Percentage as ping prints it: "0", "25", "33.3".
pub fn fmt_pct(v: f64) -> String {
    let r = (v * 10.0).round() / 10.0;
    if r.fract() == 0.0 {
        format!("{r:.0}")
    } else {
        format!("{r:.1}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct T {
        #[serde(default, deserialize_with = "opt_u32")]
        n: Option<u32>,
    }

    #[test]
    fn numeri_e_stringhe() {
        let p = |s: &str| serde_json::from_str::<T>(s).map(|t| t.n);
        assert_eq!(p(r#"{"n":4}"#).unwrap(), Some(4));
        assert_eq!(p(r#"{"n":"12"}"#).unwrap(), Some(12));
        assert_eq!(p(r#"{"n":" "}"#).unwrap(), None);
        assert_eq!(p(r#"{}"#).unwrap(), None);
        assert!(p(r#"{"n":"abc"}"#).is_err());
    }

    #[test]
    fn errore_tradotto() {
        let p = |s: &str| serde_json::from_str::<T>(s).map(|t| t.n);
        let it = p(r#"{"n":"abc"}"#).err().unwrap().to_string();
        assert!(it.contains("valore numerico non valido"), "{it}");
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let en = p(r#"{"n":"abc"}"#).err().unwrap().to_string();
        assert!(en.contains("invalid numeric value"), "{en}");
        assert!(!en.contains("non valido"), "{en}");
    }

    #[test]
    fn percentuali() {
        assert_eq!(fmt_pct(0.0), "0");
        assert_eq!(fmt_pct(25.0), "25");
        assert_eq!(fmt_pct(100.0 / 3.0), "33.3");
    }
}

/// UTC date and time from Unix seconds: (year, month, day, hours, minutes, seconds).
/// H. Hinnant's "days from civil" algorithm, with no external dependencies.
pub fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (
        y,
        m,
        d,
        (sod / 3600) as u32,
        (sod % 3600 / 60) as u32,
        (sod % 60) as u32,
    )
}

/// "2026-10-30T14:03:30"
pub fn iso(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}

/// "2026-10-30 14:03:30.123 UTC"
pub fn utc_ms(secs: f64) -> String {
    let whole = secs.floor();
    let ms = ((secs - whole) * 1000.0).floor() as u32;
    let (y, mo, d, h, mi, s) = civil(whole as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{ms:03} UTC")
}

pub fn now_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn date() {
        assert_eq!(iso(0), "1970-01-01T00:00:00");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00");
        assert_eq!(iso(1_793_370_210), "2026-10-30T14:23:30");
        assert_eq!(iso(-86_400), "1969-12-31T00:00:00");
        assert_eq!(utc_ms(1_793_370_210.123_9), "2026-10-30 14:23:30.123 UTC");
    }
}
