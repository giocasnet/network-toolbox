//! Resources of a server (HOST-RESOURCES-MIB): processors, memory, disks and processes.
//!
//! Only pure functions on `Raw`, tested with hand-written values and with the fake agent.

use super::client::Value;
use super::device::{num, text, Raw};
use crate::http::analyze::{check, Check, ERR, OK, WARN};
use crate::{t, tf};
use serde::Serialize;

/// Name of the area of the checks (shown to the user).
pub fn area() -> &'static str {
    t!("Risorse", "Resources")
}

/// Processes shown: the top ones by memory.
const TOP: usize = 10;

#[derive(Debug, Serialize, PartialEq)]
pub struct Cpu {
    pub name: String,
    /// Average load over the last minute, 0-100.
    pub load: u32,
}

/// Memory or disk: sizes in bytes (allocation units x blocks).
#[derive(Debug, Serialize, PartialEq)]
pub struct Store {
    pub name: String,
    /// `ram`, `virtual`, `disk`, `removable`, `ramdisk`, `flash`, `network`.
    pub kind: &'static str,
    pub size: u64,
    pub used: u64,
    /// Percentage used, rounded.
    pub pct: u32,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Proc {
    pub name: String,
    pub mem_kb: u64,
    /// CPU time in seconds.
    pub cpu_s: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Resources {
    /// Operating system uptime (hrSystemUptime), in seconds.
    pub uptime_s: Option<u64>,
    pub users: Option<u64>,
    pub processes: Option<u64>,
    /// Declared physical memory (hrMemorySize), in KB.
    pub memory_kb: Option<u64>,
    pub cpu: Vec<Cpu>,
    pub cpu_avg: Option<u32>,
    pub memory: Vec<Store>,
    pub disks: Vec<Store>,
    pub top: Vec<Proc>,
    /// Processes read (may be fewer than `processes` if the reading is truncated).
    pub process_total: usize,
}

/// Does the device expose anything from HOST-RESOURCES-MIB that this view needs?
pub fn present(raw: &Raw) -> bool {
    raw.has("hrStorageSize") || raw.has("hrProcessorLoad") || raw.has("hrSWRunName")
}

/// Size in words, with the decimal separator of the language: "34,6 GB" / "34.6 GB".
pub fn size_text(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        let s = format!("{v:.1} {}", U[i]);
        if crate::i18n::is_en() {
            s
        } else {
            s.replace('.', ",")
        }
    }
}

fn scalar(raw: &Raw, name: &str, index: &[u32]) -> Option<u64> {
    raw.col(name)
        .find(|(i, _)| *i == index)
        .and_then(|(_, v)| num(v))
}

/// Type of memory or disk from the hrStorageType identifier.
fn kind(v: &Value) -> Option<&'static str> {
    let Value::Oid(o) = v else { return None };
    if !o.starts_with(&[1, 3, 6, 1, 2, 1, 25, 2, 1]) || o.len() != 10 {
        return None;
    }
    Some(match o[9] {
        2 => "ram",
        3 => "virtual",
        4 => "disk",
        5 => "removable",
        8 => "ramdisk",
        9 => "flash",
        10 => "network",
        _ => return None,
    })
}

/// Volume name without the serial number that Windows appends.
fn volume_name(s: String) -> String {
    match s.find(" Serial Number") {
        Some(i) => s[..i].trim_end().to_string(),
        None => s,
    }
}

fn stores(raw: &Raw) -> Vec<Store> {
    let (ty, descr, unit, size, used) = (
        raw.by_num("hrStorageType"),
        raw.by_num("hrStorageDescr"),
        raw.by_num("hrStorageAllocationUnits"),
        raw.by_num("hrStorageSize"),
        raw.by_num("hrStorageUsed"),
    );
    let mut out = Vec::new();
    for (i, s) in &size {
        let (Some(kind), Some(unit), Some(size), Some(used)) = (
            ty.get(i).and_then(|v| kind(v)),
            unit.get(i).and_then(|v| num(v)),
            num(s),
            used.get(i).and_then(|v| num(v)),
        ) else {
            continue;
        };
        if size == 0 || unit == 0 {
            continue;
        }
        let used = used.min(size);
        out.push(Store {
            name: descr
                .get(i)
                .map(|v| volume_name(text(v)))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| tf!("Volume {i}", "Volume {i}")),
            kind,
            size: size.saturating_mul(unit),
            used: used.saturating_mul(unit),
            pct: ((used as u128 * 100 + size as u128 / 2) / size as u128) as u32,
        });
    }
    out
}

pub fn resources(raw: &Raw) -> Resources {
    let descr = raw.by_num("hrDeviceDescr");
    let cpu: Vec<Cpu> = raw
        .by_num("hrProcessorLoad")
        .into_iter()
        .filter_map(|(i, v)| {
            Some(Cpu {
                name: descr
                    .get(&i)
                    .map(|d| text(d))
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| tf!("Processore {i}", "Processor {i}")),
                load: num(v)?.min(100) as u32,
            })
        })
        .collect();
    let cpu_avg = (!cpu.is_empty()).then(|| {
        (cpu.iter().map(|c| c.load as f64).sum::<f64>() / cpu.len() as f64).round() as u32
    });

    let (mut memory, mut disks) = (Vec::new(), Vec::new());
    for s in stores(raw) {
        match s.kind {
            "ram" | "virtual" => memory.push(s),
            _ => disks.push(s),
        }
    }

    let (mem, perf) = (raw.by_num("hrSWRunPerfMem"), raw.by_num("hrSWRunPerfCPU"));
    let names = raw.by_num("hrSWRunName");
    let mut top: Vec<Proc> = names
        .iter()
        .map(|(i, n)| Proc {
            name: text(n),
            mem_kb: mem.get(i).and_then(|v| num(v)).unwrap_or(0),
            cpu_s: perf.get(i).and_then(|v| num(v)).unwrap_or(0) / 100,
        })
        .collect();
    top.sort_by(|a, b| b.mem_kb.cmp(&a.mem_kb).then(b.cpu_s.cmp(&a.cpu_s)));
    top.truncate(TOP);

    Resources {
        uptime_s: scalar(raw, "hrSystem", &[1, 0]).map(|t| t / 100),
        users: scalar(raw, "hrSystem", &[5, 0]),
        processes: scalar(raw, "hrSystem", &[6, 0]),
        memory_kb: scalar(raw, "hrMemorySize", &[0]),
        cpu,
        cpu_avg,
        memory,
        disks,
        top,
        process_total: names.len(),
    }
}

/// Checks on the resources: load, memory and disk space.
pub fn checks(r: &Resources) -> Vec<Check> {
    let mut out = Vec::new();
    if let Some(avg) = r.cpu_avg {
        let n = r.cpu.len();
        let cores = if n == 1 {
            t!("1 processore", "1 processor").to_string()
        } else {
            tf!("{n} processori", "{n} processors")
        };
        if avg >= 90 {
            out.push(check(
                area(),
                WARN,
                t!("Processore molto carico", "Processor heavily loaded"),
                tf!(
                    "Carico medio {avg} % su {cores} nell'ultimo minuto.",
                    "Average load {avg} % on {cores} over the last minute."
                ),
            ));
        } else {
            out.push(check(
                area(),
                OK,
                t!("Processore", "Processor"),
                tf!(
                    "Carico medio {avg} % su {cores} nell'ultimo minuto.",
                    "Average load {avg} % on {cores} over the last minute."
                ),
            ));
        }
    }
    for m in &r.memory {
        let detail = tf!(
            "{}: {} % usato ({} su {}).",
            "{}: {} % used ({} of {}).",
            m.name,
            m.pct,
            size_text(m.used),
            size_text(m.size)
        );
        match (m.kind, m.pct >= 95) {
            ("ram", true) => out.push(check(
                area(),
                WARN,
                t!(
                    "Memoria fisica quasi esaurita",
                    "Physical memory almost exhausted"
                ),
                tf!(
                    "{detail} Alcuni agenti contano anche la cache come memoria usata.",
                    "{detail} Some agents also count the cache as used memory."
                ),
            )),
            ("ram", false) => out.push(check(
                area(),
                OK,
                t!("Memoria fisica", "Physical memory"),
                detail,
            )),
            (_, true) => out.push(check(
                area(),
                WARN,
                t!(
                    "Memoria virtuale quasi esaurita",
                    "Virtual memory almost exhausted"
                ),
                detail,
            )),
            _ => {}
        }
    }
    let mut flagged = 0;
    for d in &r.disks {
        let (status, name) = match d.pct {
            95.. => (ERR, t!("Disco quasi pieno", "Disk almost full")),
            85..=94 => (
                WARN,
                t!("Disco da tenere d'occhio", "Disk to keep an eye on"),
            ),
            _ => continue,
        };
        flagged += 1;
        out.push(check(
            area(),
            status,
            name,
            tf!(
                "{}: {} % usato, {} liberi su {}.",
                "{}: {} % used, {} free of {}.",
                d.name,
                d.pct,
                size_text(d.size - d.used),
                size_text(d.size)
            ),
        ));
    }
    if !r.disks.is_empty() && flagged == 0 {
        let n = r.disks.len();
        let volumes = if n == 1 {
            t!("1 volume", "1 volume").to_string()
        } else {
            tf!("{n} volumi", "{n} volumes")
        };
        out.push(check(
            area(),
            OK,
            t!("Spazio sui dischi", "Disk space"),
            tf!(
                "{volumes} sotto l'85 % di spazio usato.",
                "{volumes} under 85 % of space used."
            ),
        ));
    }
    out
}
