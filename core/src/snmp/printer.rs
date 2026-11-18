//! Printer (Printer-MIB, RFC 3805, and hrPrinterTable): status, supplies, trays, alerts
//! and page counter. Only pure functions on `Raw`.

use super::client::Value;
use super::device::{num, text, Raw};
use super::mib;
use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::{t, tf};
use serde::Serialize;
use std::collections::BTreeMap;

/// Name of the area of the checks (shown to the user).
pub fn area() -> &'static str {
    t!("Stampante", "Printer")
}

/// Supply thresholds: below 15 % left is a warning, below 5 % an error;
/// a container (waste toner) is full above 85 % and at its limit above 95 %.
const LOW: u32 = 15;
const EMPTY: u32 = 5;
const FULL: u32 = 85;
const OVER: u32 = 95;

#[derive(Debug, Serialize, PartialEq)]
pub struct Supply {
    pub name: String,
    /// Type from the MIB: `toner`, `wasteToner`, `fuser`, `opc`...
    pub kind: &'static str,
    /// `consumed` (gets used up) or `filled` (gets filled up).
    pub class: &'static str,
    /// `black`, `cyan`, `magenta`, `yellow`, `other` or empty if it has no colour.
    pub color: &'static str,
    /// Percentage of the capacity: remaining if consumed, occupied if filled.
    pub level: Option<u32>,
    /// The printer only says that at least one unit is left (level -3).
    pub some: bool,
    /// `ok`, `warn`, `err` or `unknown`.
    pub state: &'static str,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Tray {
    pub name: String,
    pub media: String,
    pub level: Option<u32>,
    pub current: Option<i64>,
    pub max: Option<i64>,
    pub some: bool,
    /// `ok`, `empty` or `unknown`.
    pub state: &'static str,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Alert {
    /// `critical`, `warning` or `other`.
    pub severity: &'static str,
    pub text: String,
    pub group: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PrinterError {
    pub label: &'static str,
    pub severe: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Printer {
    pub name: String,
    /// Status in the current language ("Inattiva"/"Idle", ...), empty if there is no hrPrinterStatus.
    pub status: &'static str,
    pub serial: String,
    pub pages: Option<u64>,
    pub errors: Vec<PrinterError>,
    pub supplies: Vec<Supply>,
    pub trays: Vec<Tray>,
    pub alerts: Vec<Alert>,
}

pub fn present(raw: &Raw) -> bool {
    raw.has("hrPrinterStatus")
        || raw.has("prtMarkerSuppliesDescription")
        || raw.has("prtMarkerLifeCount")
        || raw.has("prtInputMaxCapacity")
}

/// Column with a two-number index (device, row).
fn pairs<'a>(raw: &'a Raw, name: &str) -> BTreeMap<(u32, u32), &'a Value> {
    raw.col(name)
        .filter(|(i, _)| i.len() == 2)
        .map(|(i, v)| ((i[0], i[1]), v))
        .collect()
}

fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        _ => num(v).and_then(|n| i64::try_from(n).ok()),
    }
}

/// Colour from the colorant name or, failing that, from the description.
fn color_of(s: &str) -> &'static str {
    let s = s.to_lowercase();
    let has = |w: &[&str]| w.iter().any(|x| s.contains(x));
    if has(&["black", "nero", "noir", "schwarz", "negro"]) {
        "black"
    } else if has(&["cyan", "ciano", "cian"]) {
        "cyan"
    } else if has(&["magenta"]) {
        "magenta"
    } else if has(&["yellow", "giallo", "jaune", "gelb", "amarillo"]) {
        "yellow"
    } else {
        ""
    }
}

/// Percentage of the capacity. Negative levels: -1 other, -2 unknown, -3 "at least one left".
fn percent(level: i64, max: i64, unit: Option<i64>) -> Option<u32> {
    if level < 0 {
        None
    } else if max > 0 {
        Some(((level as u128 * 100 + max as u128 / 2) / max as u128).min(100) as u32)
    } else if unit == Some(19) {
        Some(level.min(100) as u32)
    } else {
        None
    }
}

fn supply_state(filled: bool, level: Option<u32>, some: bool) -> &'static str {
    match level {
        Some(p) if filled => match p {
            OVER.. => "err",
            FULL.. => "warn",
            _ => "ok",
        },
        Some(p) => match p {
            0..=EMPTY => "err",
            _ if p <= LOW => "warn",
            _ => "ok",
        },
        None if some => "ok",
        None => "unknown",
    }
}

fn supplies(raw: &Raw) -> Vec<Supply> {
    let (descr, class, ty, unit, max, level, colorant) = (
        pairs(raw, "prtMarkerSuppliesDescription"),
        pairs(raw, "prtMarkerSuppliesClass"),
        pairs(raw, "prtMarkerSuppliesType"),
        pairs(raw, "prtMarkerSuppliesSupplyUnit"),
        pairs(raw, "prtMarkerSuppliesMaxCapacity"),
        pairs(raw, "prtMarkerSuppliesLevel"),
        pairs(raw, "prtMarkerSuppliesColorantIndex"),
    );
    let colors = pairs(raw, "prtMarkerColorantValue");
    let keys: std::collections::BTreeSet<_> = descr.keys().chain(level.keys()).copied().collect();
    keys.into_iter()
        .map(|k| {
            let type_n = ty.get(&k).and_then(|v| int(v)).unwrap_or(2);
            let kind = mib::supply_type(type_n).unwrap_or("other");
            let filled = class.get(&k).and_then(|v| int(v)) == Some(4)
                || matches!(type_n, 4 | 8 | 14 | 24 | 26);
            let name = descr
                .get(&k)
                .map(|v| text(v))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| kind.to_string());
            let color = colorant
                .get(&k)
                .and_then(|v| int(v))
                .filter(|c| *c > 0)
                .and_then(|c| colors.get(&(k.0, c as u32)))
                .map(|v| color_of(&text(v)))
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| if filled { "" } else { color_of(&name) });
            let lv = level.get(&k).and_then(|v| int(v));
            let pct = lv.and_then(|l| {
                percent(
                    l,
                    max.get(&k).and_then(|v| int(v)).unwrap_or(-2),
                    unit.get(&k).and_then(|v| int(v)),
                )
            });
            let some = lv == Some(-3);
            Supply {
                state: supply_state(filled, pct, some),
                name,
                kind,
                class: if filled { "filled" } else { "consumed" },
                color,
                level: pct,
                some,
            }
        })
        .collect()
}

fn trays(raw: &Raw) -> Vec<Tray> {
    let (name, media, max, cur) = (
        pairs(raw, "prtInputName"),
        pairs(raw, "prtInputMediaName"),
        pairs(raw, "prtInputMaxCapacity"),
        pairs(raw, "prtInputCurrentLevel"),
    );
    let unit = pairs(raw, "prtInputCapacityUnit");
    let keys: std::collections::BTreeSet<_> = name.keys().chain(cur.keys()).copied().collect();
    keys.into_iter()
        .enumerate()
        .map(|(n, k)| {
            let m = max.get(&k).and_then(|v| int(v));
            let c = cur.get(&k).and_then(|v| int(v));
            let some = c == Some(-3);
            let level =
                c.and_then(|c| percent(c, m.unwrap_or(-2), unit.get(&k).and_then(|v| int(v))));
            Tray {
                name: name
                    .get(&k)
                    .map(|v| text(v))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| tf!("Vassoio {}", "Tray {}", n + 1)),
                media: media.get(&k).map(|v| text(v)).unwrap_or_default(),
                state: match c {
                    Some(0) => "empty",
                    Some(_) => "ok",
                    None => "unknown",
                },
                level,
                current: c.filter(|c| *c >= 0),
                max: m.filter(|m| *m > 0),
                some,
            }
        })
        .collect()
}

fn alerts(raw: &Raw) -> Vec<Alert> {
    let (sev, group, code, descr) = (
        pairs(raw, "prtAlertSeverityLevel"),
        pairs(raw, "prtAlertGroup"),
        pairs(raw, "prtAlertCode"),
        pairs(raw, "prtAlertDescription"),
    );
    let keys: std::collections::BTreeSet<_> = descr.keys().chain(code.keys()).copied().collect();
    let mut out: Vec<Alert> = keys
        .into_iter()
        .map(|k| {
            let label = |m: &BTreeMap<(u32, u32), &Value>, obj: &str| {
                m.get(&k)
                    .and_then(|v| int(v))
                    .and_then(|n| mib::enum_label(obj, n))
                    .unwrap_or("")
            };
            let text = descr
                .get(&k)
                .map(|v| text_of(v))
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| label(&code, "prtAlertCode").to_string());
            Alert {
                severity: match sev.get(&k).and_then(|v| int(v)) {
                    Some(3) => "critical",
                    Some(4) => "warning",
                    _ => "other",
                },
                text: if text.is_empty() {
                    t!("avviso senza testo", "alert without text").into()
                } else {
                    text
                },
                group: label(&group, "prtAlertGroup").to_string(),
            }
        })
        .collect();
    out.sort_by_key(|a| match a.severity {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    });
    out
}

fn text_of(v: &Value) -> String {
    text(v)
}

fn status(n: u64) -> &'static str {
    match n {
        3 => t!("Inattiva", "Idle"),
        4 => t!("In stampa", "Printing"),
        5 => t!("In riscaldamento", "Warming up"),
        1 => t!("Altro", "Other"),
        _ => t!("Sconosciuto", "Unknown"),
    }
}

/// hrPrinterDetectedErrorState: two bytes of bits (RFC 2790).
pub fn error_state(b: &[u8]) -> Vec<PrinterError> {
    let first: [(u8, &'static str, bool); 8] = [
        (0x80, t!("carta in esaurimento", "paper low"), false),
        (0x40, t!("carta esaurita", "out of paper"), true),
        (0x20, t!("toner in esaurimento", "toner low"), false),
        (0x10, t!("toner esaurito", "out of toner"), true),
        (0x08, t!("sportello aperto", "door open"), true),
        (0x04, t!("carta inceppata", "paper jam"), true),
        (0x02, t!("fuori linea", "offline"), false),
        (
            0x01,
            t!("richiesta di assistenza", "service requested"),
            false,
        ),
    ];
    let second: [(u8, &'static str, bool); 7] = [
        (
            0x80,
            t!("vassoio di ingresso mancante", "input tray missing"),
            false,
        ),
        (
            0x40,
            t!("vassoio di uscita mancante", "output tray missing"),
            false,
        ),
        (
            0x20,
            t!("materiale di consumo mancante", "supply missing"),
            false,
        ),
        (0x10, t!("uscita quasi piena", "output almost full"), false),
        (0x08, t!("uscita piena", "output full"), true),
        (
            0x04,
            t!("vassoio di ingresso vuoto", "input tray empty"),
            false,
        ),
        (
            0x02,
            t!("manutenzione in ritardo", "maintenance overdue"),
            false,
        ),
    ];
    let mut out = Vec::new();
    for (byte, table) in [(b.first(), &first[..]), (b.get(1), &second[..])] {
        for (bit, label, severe) in table {
            if byte.is_some_and(|x| x & bit != 0) {
                out.push(PrinterError {
                    label,
                    severe: *severe,
                });
            }
        }
    }
    out
}

pub fn printer(raw: &Raw) -> Printer {
    let st = raw.by_num("hrPrinterStatus");
    let first = st.keys().next().copied();
    let descr = raw.by_num("hrDeviceDescr");
    let mut pages = 0u64;
    let mut any = false;
    let units = pairs(raw, "prtMarkerCounterUnit");
    for (k, v) in pairs(raw, "prtMarkerLifeCount") {
        // pages or sheets; without a unit they are assumed to be pages
        if matches!(units.get(&k).and_then(|u| int(u)), None | Some(7) | Some(8)) {
            if let Some(n) = num(v) {
                pages += n;
                any = true;
            }
        }
    }
    Printer {
        name: first
            .and_then(|i| descr.get(&i))
            .map(|d| text(d))
            .unwrap_or_default(),
        status: first
            .and_then(|i| st.get(&i))
            .and_then(|v| num(v))
            .map(status)
            .unwrap_or(""),
        serial: raw
            .col("prtGeneralSerialNumber")
            .map(|(_, v)| text(v))
            .find(|s| !s.is_empty())
            .unwrap_or_default(),
        pages: any.then_some(pages),
        errors: raw
            .col("hrPrinterDetectedErrorState")
            .next()
            .map(|(_, v)| match v {
                Value::Str(b) => error_state(b),
                _ => Vec::new(),
            })
            .unwrap_or_default(),
        supplies: supplies(raw),
        trays: trays(raw),
        alerts: alerts(raw),
    }
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

pub fn checks(p: &Printer) -> Vec<Check> {
    let mut out = Vec::new();
    if !p.status.is_empty() {
        out.push(check(
            area(),
            INFO,
            t!("Stato", "Status"),
            format!("{}.", p.status),
        ));
    }
    for e in &p.errors {
        out.push(check(
            area(),
            if e.severe { ERR } else { WARN },
            &cap(e.label),
            tf!(
                "La stampante segnala: {} (hrPrinterDetectedErrorState).",
                "The printer reports: {} (hrPrinterDetectedErrorState).",
                e.label
            ),
        ));
    }
    let mut flagged = 0;
    for s in &p.supplies {
        let filled = s.class == "filled";
        let (status, title) = match (s.state, filled) {
            ("err", false) => (ERR, t!("Materiale esaurito", "Supply depleted")),
            ("warn", false) => (WARN, t!("Materiale in esaurimento", "Supply running low")),
            ("err", true) => (ERR, t!("Contenitore pieno", "Container full")),
            ("warn", true) => (WARN, t!("Contenitore quasi pieno", "Container almost full")),
            _ => continue,
        };
        flagged += 1;
        let p = s.level.unwrap_or(0);
        out.push(check(
            area(),
            status,
            title,
            if filled {
                tf!("{}: pieno al {p} %.", "{}: {p} % full.", s.name)
            } else {
                tf!("{}: rimasto il {p} %.", "{}: {p} % left.", s.name)
            },
        ));
    }
    let known = p.supplies.iter().filter(|s| s.state != "unknown").count();
    if known > 0 && flagged == 0 {
        out.push(check(
            area(),
            OK,
            t!("Materiali di consumo", "Supplies"),
            tf!(
                "{} {}: nessuno vicino al limite.",
                "{} {}: none close to the limit.",
                known,
                if known == 1 {
                    t!("materiale letto", "supply read")
                } else {
                    t!("materiali letti", "supplies read")
                }
            ),
        ));
    }
    for t in p.trays.iter().filter(|t| t.state == "empty") {
        out.push(check(
            area(),
            WARN,
            t!("Vassoio vuoto", "Empty tray"),
            tf!("{}: carta esaurita.", "{}: out of paper.", t.name),
        ));
    }
    for a in &p.alerts {
        let (status, title) = match a.severity {
            "critical" => (ERR, t!("Allarme critico", "Critical alert")),
            "warning" => (WARN, t!("Avviso della stampante", "Printer warning")),
            _ => (INFO, t!("Segnalazione della stampante", "Printer notice")),
        };
        out.push(check(
            area(),
            status,
            title,
            if a.group.is_empty() {
                format!("{}.", a.text.trim_end_matches('.'))
            } else {
                format!("{} ({}).", a.text.trim_end_matches('.'), a.group)
            },
        ));
    }
    out
}
