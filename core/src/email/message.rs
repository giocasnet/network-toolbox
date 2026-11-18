//! Analysis of the headers of a message: path between servers with delays, SPF, DKIM and
//! DMARC results with alignment to the sender, anti-spam scores. Pure functions only:
//! it works on the pasted text, no queries.

use super::policy::Row;
use super::{auth_results, parse_headers};
use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::whois::registrable;
use crate::{t, tf};
use serde::Serialize;
use serde_json::Value;
use std::net::IpAddr;

/// Delay between two servers beyond which the step is flagged.
pub const SLOW_S: i64 = 30;

// Check areas (translated when used)
fn a_auth() -> &'static str {
    t!("Autenticazione", "Authentication")
}
fn a_from() -> &'static str {
    t!("Mittente", "Sender")
}
fn a_path() -> &'static str {
    t!("Percorso", "Path")
}
fn a_spam() -> &'static str {
    t!("Antispam", "Anti-spam")
}

/// A hop between two servers (a `Received` header), in time order.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Hop {
    pub from: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from_ip: String,
    pub by: String,
    /// "ESMTPS", "ESMTPSA", "HTTP"…
    pub with: String,
    /// "TLS 1.3", "TLS" (encrypted, version not stated) or empty
    pub tls: String,
    /// Unix seconds of the time written by the server; `None` if it cannot be read.
    pub time: Option<i64>,
    /// Seconds since the previous step.
    pub delay_s: Option<i64>,
    /// "warn" if the delay is high, otherwise empty
    pub status: &'static str,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Signature {
    pub domain: String,
    pub selector: String,
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub subject: String,
    /// Sender address (From header) and its domain.
    pub from: String,
    pub from_domain: String,
    pub return_path: String,
    pub checks: Vec<Check>,
    pub hops: Vec<Hop>,
    /// Seconds from the first to the last server.
    pub total_s: Option<i64>,
    /// Results of the first Authentication-Results (`server`, `spf`, `dkim`, `dmarc`, `count`).
    pub auth: Value,
    pub scores: Vec<Row>,
    /// DKIM signatures present: domain and selector (to verify the key in DNS).
    pub signatures: Vec<Signature>,
    pub headers: Vec<(String, String)>,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Date in the header format (RFC 5322): "Fri, 30 Oct 2026 10:00:00 +0100 (CET)".
pub fn parse_date(s: &str) -> Option<i64> {
    let s = s.split('(').next().unwrap_or(s);
    let toks: Vec<&str> = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let mi = toks.iter().position(|t| {
        t.len() >= 3
            && MONTHS.contains(&t[..3].to_ascii_lowercase().as_str())
            && t.len() <= 9
            && t.chars().all(|c| c.is_ascii_alphabetic())
            && MONTHS.iter().any(|m| t.to_ascii_lowercase().starts_with(m))
    })?;
    if mi == 0 || mi + 2 >= toks.len() {
        return None;
    }
    let month = MONTHS
        .iter()
        .position(|m| toks[mi].to_ascii_lowercase().starts_with(m))? as i64
        + 1;
    let day: i64 = toks[mi - 1].parse().ok()?;
    let mut year: i64 = toks[mi + 1].parse().ok()?;
    if year < 100 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let mut hms = toks[mi + 2].split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let mi_: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    if !(1..=31).contains(&day) || h > 23 || mi_ > 59 || sec > 60 {
        return None;
    }
    let zone = toks.get(mi + 3).copied().unwrap_or("+0000");
    let off = if let Some(z) = zone.strip_prefix('+').or_else(|| zone.strip_prefix('-')) {
        let n: i64 = z.parse().ok()?;
        let secs = (n / 100) * 3600 + (n % 100) * 60;
        if zone.starts_with('-') {
            -secs
        } else {
            secs
        }
    } else {
        match zone.to_ascii_uppercase().as_str() {
            "EST" => -5 * 3600,
            "EDT" => -4 * 3600,
            "CST" => -6 * 3600,
            "CDT" => -5 * 3600,
            "MST" => -7 * 3600,
            "MDT" => -6 * 3600,
            "PST" => -8 * 3600,
            "PDT" => -7 * 3600,
            _ => 0, // GMT, UT, UTC, Z
        }
    };
    Some(days_from_civil(year, month, day) * 86_400 + h * 3600 + mi_ * 60 + sec - off)
}

/// Word following `key` (already lowercase, with surrounding spaces).
fn word_after(text: &str, lower: &str, key: &str) -> String {
    let start = if lower.starts_with(key.trim_start()) {
        Some(key.trim_start().len())
    } else {
        lower.find(key).map(|i| i + key.len())
    };
    start
        .and_then(|i| text[i..].split_whitespace().next())
        .unwrap_or("")
        .trim_matches(|c| c == ';' || c == ',')
        .to_string()
}

/// TLS version written in the header ("TLS1_3", "TLSv1.2", "version=TLS1_2"…).
fn tls_version(lower: &str) -> Option<String> {
    let mut rest = lower;
    while let Some(i) = rest.find("tls") {
        let tail: String = rest[i + 3..]
            .chars()
            .skip_while(|c| *c == 'v' || *c == ' ' || *c == '=')
            .take(3)
            .collect();
        let b = tail.as_bytes();
        if b.len() == 3 && b[0] == b'1' && (b[1] == b'_' || b[1] == b'.') && b[2].is_ascii_digit() {
            return Some(format!("TLS 1.{}", b[2] as char));
        }
        rest = &rest[i + 3..];
    }
    None
}

/// Reads a `Received` header.
pub fn received(v: &str) -> Hop {
    let lower = v.to_ascii_lowercase();
    let (head, date) = match v.rfind(';') {
        Some(i) => (&v[..i], &v[i + 1..]),
        None => (v, ""),
    };
    let head_l = head.to_ascii_lowercase();
    let from = word_after(head, &head_l, " from ");
    let by = word_after(head, &head_l, " by ");
    let with = word_after(head, &head_l, " with ").to_ascii_uppercase();
    // address in brackets in the "from … by" part
    let from_part = head_l.find(" by ").map(|i| &head[..i]).unwrap_or(head);
    let from_ip = from_part
        .split('[')
        .skip(1)
        .filter_map(|x| x.split(']').next())
        .map(|x| x.strip_prefix("IPv6:").unwrap_or(x))
        .find_map(|x| x.parse::<IpAddr>().ok())
        .map(|i| i.to_string())
        .unwrap_or_default();
    let tls = tls_version(&lower).unwrap_or_else(|| {
        // ESMTPS, ESMTPSA, LMTPS, UTF8SMTPS: the S after the protocol says TLS was used
        let w = with.as_str();
        let secure = ["SMTP", "LMTP"]
            .iter()
            .any(|p| w.split(p).nth(1).is_some_and(|t| t.starts_with('S')));
        if secure {
            "TLS".into()
        } else {
            String::new()
        }
    });
    Hop {
        from: if from.starts_with('[') {
            String::new()
        } else {
            from
        },
        from_ip,
        by,
        with,
        tls,
        time: parse_date(date),
        delay_s: None,
        status: "",
    }
}

/// Address inside a header (`Name <a@b>` or `a@b`) and display name.
pub fn address(v: &str) -> (String, String) {
    let (name, addr) = match (v.rfind('<'), v.rfind('>')) {
        (Some(a), Some(b)) if a < b => (v[..a].trim().trim_matches('"').to_string(), &v[a + 1..b]),
        _ => (String::new(), v.trim()),
    };
    (addr.trim().to_ascii_lowercase(), name)
}

fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('.').to_string())
        .unwrap_or_default()
}

fn aligned(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && registrable(a).eq_ignore_ascii_case(&registrable(b))
}

/// `key=value` inside an Authentication-Results ("smtp.mailfrom", "header.d"…).
fn prop(first: &str, key: &str) -> String {
    let lower = first.to_ascii_lowercase();
    lower
        .find(&format!("{key}="))
        .map(|i| {
            first[i + key.len() + 1..]
                .split(|c: char| c.is_whitespace() || c == ';')
                .next()
                .unwrap_or("")
                .trim_matches(|c| c == '"' || c == '<' || c == '>')
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

fn get<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn secs_text(s: i64) -> String {
    if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min", s / 60)
    } else {
        format!("{} h", s / 3600)
    }
}

/// Anti-spam scores: every header that mentions them, with a verdict where the meaning is known.
fn scores(h: &[(String, String)]) -> (Vec<Row>, Vec<Check>) {
    let mut rows = Vec::new();
    let mut flagged = Vec::new();
    for (k, v) in h {
        let kl = k.to_ascii_lowercase();
        let is_scl = kl.ends_with("-scl");
        if !(kl.contains("spam") || is_scl) || kl.contains("report") && v.len() > 200 {
            continue;
        }
        let vl = v.to_ascii_lowercase();
        let (status, detail) = if is_scl {
            match v.trim().parse::<i32>() {
                Ok(n) if n >= 5 => (
                    WARN,
                    t!(
                        "5 o più: trattato come posta indesiderata",
                        "5 or more: treated as junk mail"
                    )
                    .to_string(),
                ),
                Ok(n) if n < 0 => (
                    INFO,
                    t!(
                        "controllo antispam saltato (mittente attendibile)",
                        "anti-spam check skipped (trusted sender)"
                    )
                    .to_string(),
                ),
                Ok(_) => (
                    OK,
                    t!(
                        "sotto la soglia della posta indesiderata",
                        "below the junk mail threshold"
                    )
                    .to_string(),
                ),
                Err(_) => ("", String::new()),
            }
        } else if kl.ends_with("spam-flag") || kl.ends_with("spam-status") {
            if vl.starts_with("yes") {
                (
                    WARN,
                    t!("segnato come posta indesiderata", "marked as junk mail").to_string(),
                )
            } else if vl.starts_with("no") {
                (
                    OK,
                    t!(
                        "non segnato come posta indesiderata",
                        "not marked as junk mail"
                    )
                    .to_string(),
                )
            } else {
                ("", String::new())
            }
        } else {
            ("", String::new())
        };
        if status == WARN {
            flagged.push(k.clone());
        }
        rows.push(Row {
            status,
            name: k.clone(),
            value: v.chars().take(160).collect(),
            detail,
        });
    }
    let mut out = Vec::new();
    if !flagged.is_empty() {
        out.push(check(
            a_spam(),
            WARN,
            t!("Giudizio", "Verdict"),
            tf!(
                "segnato come posta indesiderata da {}",
                "marked as junk mail by {}",
                flagged.join(", ")
            ),
        ));
    } else if !rows.is_empty() {
        let short: Vec<String> = rows
            .iter()
            .take(3)
            .map(|r| {
                format!(
                    "{} {}",
                    r.name,
                    r.value.chars().take(30).collect::<String>()
                )
            })
            .collect();
        out.push(check(
            a_spam(),
            INFO,
            t!("Punteggi", "Scores"),
            short.join(" · "),
        ));
    }
    (rows, out)
}

pub fn analyze(raw: &str) -> Message {
    let headers = parse_headers(raw);
    let mut checks = Vec::new();

    // sender
    let (from, display) = get(&headers, "From").map(address).unwrap_or_default();
    let from_domain = domain_of(&from);
    let return_path = get(&headers, "Return-Path")
        .map(|v| address(v).0)
        .unwrap_or_default();
    let rp_domain = domain_of(&return_path);

    // authentication: only the first Authentication-Results
    let auth = auth_results(&headers);
    let first = get(&headers, "Authentication-Results").unwrap_or("");
    let res = |k: &str| {
        auth.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let how = |r: &str| match r {
        "pass" => OK,
        "fail" | "permerror" => ERR,
        "" => INFO,
        _ => WARN,
    };
    if auth.is_null() {
        checks.push(check(
            a_auth(),
            INFO,
            t!("Esiti", "Results"),
            t!(
                "nessun Authentication-Results: SPF, DKIM e DMARC non sono verificabili da qui",
                "no Authentication-Results: SPF, DKIM and DMARC cannot be verified from here"
            ),
        ));
    } else {
        let server = res("server");
        let spf = res("spf");
        let mailfrom = domain_of(&prop(first, "smtp.mailfrom")).to_string();
        let mailfrom = if mailfrom.is_empty() {
            prop(first, "smtp.mailfrom")
        } else {
            mailfrom
        };
        let al = |d: &str| {
            if d.is_empty() || from_domain.is_empty() {
                String::new()
            } else if aligned(d, &from_domain) {
                t!(", allineato al mittente", ", aligned with the sender").to_string()
            } else {
                tf!(
                    ", non allineato al mittente ({from_domain})",
                    ", not aligned with the sender ({from_domain})"
                )
            }
        };
        if !spf.is_empty() {
            checks.push(check(
                a_auth(),
                how(&spf),
                "SPF",
                if mailfrom.is_empty() {
                    spf.clone()
                } else {
                    tf!(
                        "{spf} per {mailfrom}{}",
                        "{spf} for {mailfrom}{}",
                        al(&mailfrom)
                    )
                },
            ));
        }
        let dkim = res("dkim");
        let d = prop(first, "header.d");
        let d = if d.is_empty() {
            domain_of(&prop(first, "header.i"))
        } else {
            d
        };
        if !dkim.is_empty() {
            checks.push(check(
                a_auth(),
                how(&dkim),
                "DKIM",
                if d.is_empty() || d == "none" {
                    dkim.clone()
                } else {
                    tf!(
                        "{dkim}, firma di {d}{}",
                        "{dkim}, signature of {d}{}",
                        al(&d)
                    )
                },
            ));
        }
        let dmarc = res("dmarc");
        if !dmarc.is_empty() {
            let hf = prop(first, "header.from");
            checks.push(check(
                a_auth(),
                how(&dmarc),
                "DMARC",
                if hf.is_empty() {
                    dmarc.clone()
                } else {
                    tf!("{dmarc} per {hf}", "{dmarc} for {hf}")
                },
            ));
        }
        let count = auth.get("count").and_then(Value::as_u64).unwrap_or(1);
        checks.push(check(
            a_auth(),
            INFO,
            t!("Chi lo dice", "Who says so"),
            tf!(
                "esiti dal primo Authentication-Results{}: controlla che sia il tuo server di posta{}",
                "results from the first Authentication-Results{}: check that it is your mail server{}",
                if server.is_empty() { String::new() } else { format!(" ({server})") },
                if count > 1 {
                    tf!(
                        "; gli altri {} più in basso possono venire dal mittente e non sono considerati",
                        "; the other {} further down may come from the sender and are not considered",
                        count - 1
                    )
                } else {
                    String::new()
                }
            ),
        ));
    }

    if !from_domain.is_empty() && !rp_domain.is_empty() {
        if aligned(&from_domain, &rp_domain) {
            checks.push(check(
                a_from(),
                OK,
                t!("From e Return-Path", "From and Return-Path"),
                tf!(
                    "stesso dominio: {}",
                    "same domain: {}",
                    registrable(&from_domain)
                ),
            ));
        } else {
            checks.push(check(
                a_from(),
                INFO,
                t!("From e Return-Path", "From and Return-Path"),
                tf!(
                    "domini diversi: {from_domain} e {rp_domain} (normale con i servizi di invio)",
                    "different domains: {from_domain} and {rp_domain} (normal with sending services)"
                ),
            ));
        }
    }
    if let Some(rt) = get(&headers, "Reply-To") {
        let rd = domain_of(&address(rt).0);
        if !rd.is_empty() && !from_domain.is_empty() && !aligned(&rd, &from_domain) {
            checks.push(check(
                a_from(),
                WARN,
                "Reply-To",
                tf!(
                    "risposte verso un altro dominio: {}",
                    "replies go to another domain: {}",
                    address(rt).0
                ),
            ));
        }
    }
    // display name that contains another address
    if let Some(i) = display.find('@') {
        let fake: String = display[..i]
            .rsplit(|c: char| c.is_whitespace() || c == '<' || c == '"' || c == '(')
            .next()
            .unwrap_or("")
            .to_string()
            + display[i..]
                .split(|c: char| c.is_whitespace() || c == '>' || c == '"' || c == ')')
                .next()
                .unwrap_or("");
        if !fake.eq_ignore_ascii_case(&from) && fake.len() > 3 {
            checks.push(check(
                a_from(),
                WARN,
                t!("Nome visualizzato", "Display name"),
                tf!(
                    "mostra {fake}, ma l'indirizzo vero è {from}",
                    "shows {fake}, but the real address is {from}"
                ),
            ));
        }
    }

    // path: the Received headers go from the most recent to the oldest
    let mut hops: Vec<Hop> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Received"))
        .map(|(_, v)| received(v))
        .collect();
    hops.reverse();
    let mut prev: Option<i64> = None;
    let mut slow = Vec::new();
    for (i, h) in hops.iter_mut().enumerate() {
        if let (Some(t), Some(p)) = (h.time, prev) {
            let d = (t - p).max(0);
            h.delay_s = Some(d);
            if d >= SLOW_S {
                h.status = WARN;
                slow.push(tf!(
                    "{} prima di {} (passo {})",
                    "{} before {} (step {})",
                    secs_text(d),
                    h.by,
                    i + 1
                ));
            }
        }
        if h.time.is_some() {
            prev = h.time;
        }
    }
    let times: Vec<i64> = hops.iter().filter_map(|h| h.time).collect();
    let total_s = match (times.first(), times.last()) {
        (Some(a), Some(b)) if times.len() > 1 => Some((b - a).max(0)),
        _ => None,
    };
    if !slow.is_empty() {
        checks.push(check(
            a_path(),
            WARN,
            t!("Ritardo", "Delay"),
            slow.join("; "),
        ));
    } else if let Some(t) = total_s {
        checks.push(check(
            a_path(),
            OK,
            t!("Tempi", "Timing"),
            tf!(
                "{} dal primo all'ultimo server, nessun passo lento",
                "{} from the first to the last server, no slow step",
                secs_text(t)
            ),
        ));
    }
    if !hops.is_empty() {
        let enc = hops.iter().filter(|h| !h.tls.is_empty()).count();
        checks.push(check(
            a_path(),
            INFO,
            t!("Cifratura", "Encryption"),
            tf!(
                "TLS dichiarato su {enc} passi su {}",
                "TLS declared on {enc} steps out of {}",
                hops.len()
            ),
        ));
    }

    let (score_rows, score_checks) = scores(&headers);
    checks.extend(score_checks);

    let signatures: Vec<Signature> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("DKIM-Signature"))
        .filter_map(|(_, v)| {
            let t = super::policy::tags(v);
            let f = |k: &str| {
                t.iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, x)| x.to_ascii_lowercase())
            };
            Some(Signature {
                domain: f("d")?,
                selector: f("s")?,
            })
        })
        .collect();

    Message {
        subject: get(&headers, "Subject").unwrap_or("").to_string(),
        from,
        from_domain,
        return_path,
        checks,
        hops,
        total_s,
        auth,
        scores: score_rows,
        signatures,
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("manca {name}: {c:#?}"))
    }

    #[test]
    fn date_degli_header() {
        // 30 October 2026 09:00:00 UTC
        let t = 1_793_350_800;
        assert_eq!(parse_date(" Fri, 30 Oct 2026 10:00:00 +0100"), Some(t));
        assert_eq!(parse_date("Fri, 30 Oct 2026 09:00:00 +0000 (UTC)"), Some(t));
        assert_eq!(parse_date("30 Oct 2026 04:00:00 -0500"), Some(t));
        assert_eq!(parse_date("Fri, 30 Oct 2026 09:00 GMT"), Some(t));
        assert_eq!(parse_date("Fri, 30 Oct 2026 01:00:00 PST"), Some(t));
        assert_eq!(parse_date("Fri, 30 October 2026 14:30:00 +0530"), Some(t));
        assert_eq!(parse_date("1 Jan 70 00:00:00 +0000"), Some(0));
        assert_eq!(
            parse_date("29 Feb 2024 00:00:00 +0000"),
            Some(1_709_164_800)
        );
        assert_eq!(parse_date("ieri"), None);
        assert_eq!(parse_date("Fri, 30 Oct 2026"), None);
        assert_eq!(parse_date("Fri, 30 Oct 2026 25:00:00 +0000"), None);
    }

    #[test]
    fn header_received() {
        let h = received("from mail-out.example.org (mail-out.example.org [198.51.100.25]) by mx1.example.com (Postfix) with ESMTPS id 4XyZ for <a@example.com>; Fri, 30 Oct 2026 10:00:04 +0100 (CET)");
        assert_eq!(
            (
                h.from.as_str(),
                h.from_ip.as_str(),
                h.by.as_str(),
                h.with.as_str(),
                h.tls.as_str()
            ),
            (
                "mail-out.example.org",
                "198.51.100.25",
                "mx1.example.com",
                "ESMTPS",
                "TLS"
            )
        );
        assert_eq!(h.time, Some(1_793_350_804));
        let h = received("from srv (srv.example.org. [IPv6:2001:db8::25]) by mx.example.com with ESMTPS id x (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256); Fri, 30 Oct 2026 09:00:00 +0000");
        assert_eq!(
            (h.from_ip.as_str(), h.tls.as_str()),
            ("2001:db8::25", "TLS 1.3")
        );
        let h = received("from a.example.org ([192.0.2.9]) by b.example.com with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2; Fri, 30 Oct 2026 09:00:00 +0000");
        assert_eq!((h.with.as_str(), h.tls.as_str()), ("MICROSOFT", "TLS 1.2"));
        let h = received("from spam01.corp.example ([172.16.7.20]) by mail01.corp.example with ESMTP; Fri, 30 Oct 2026 09:00:00 +0000");
        assert_eq!((h.with.as_str(), h.tls.as_str()), ("ESMTP", ""));
        let h = received("by mail01.corp.example with HTTP; senza data");
        assert_eq!(
            (h.from.as_str(), h.by.as_str(), h.time),
            ("", "mail01.corp.example", None)
        );
        let h = received("from [192.0.2.44] by mail-out.example.org with ESMTPSA (TLSv1.3); 30 Oct 2026 09:00:00 +0000");
        assert_eq!(
            (h.from.as_str(), h.from_ip.as_str(), h.tls.as_str()),
            ("", "192.0.2.44", "TLS 1.3")
        );
        assert_eq!(
            address("\"Ufficio Ordini\" <Ordini@Example.org>"),
            ("ordini@example.org".into(), "Ufficio Ordini".into())
        );
        assert_eq!(
            address("ordini@example.org"),
            ("ordini@example.org".into(), String::new())
        );
    }

    const MSG: &str = "Received: from spam01.corp.example ([172.16.7.20]) by mail01.corp.example with ESMTP; Fri, 30 Oct 2026 10:14:46 +0100\r\n\
Authentication-Results: spam01.corp.example; spf=pass smtp.mailfrom=bounce@invio.example.org; dkim=pass header.d=example.org header.s=s1; dmarc=pass (p=reject) header.from=example.org\r\n\
Received: from mx1.example.com ([203.0.113.10]) by spam01.corp.example with ESMTPS (TLS1.2); Fri, 30 Oct 2026 10:14:45 +0100\r\n\
Received: from mail-out.example.org ([198.51.100.25]) by mx1.example.com with ESMTPS (version=TLS1_3); Fri, 30 Oct 2026 09:14:04 +0000\r\n\
Received: from [192.0.2.44] by mail-out.example.org with ESMTPSA (TLSv1.3); Fri, 30 Oct 2026 09:14:02 +0000\r\n\
Authentication-Results: falso.example.net; spf=fail; dkim=fail; dmarc=fail\r\n\
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=Example.org; s=S1; h=from:subject; bh=abc=; b=def=\r\n\
From: \"Ufficio Ordini\" <ordini@example.org>\r\n\
Return-Path: <bounce@invio.example.org>\r\n\
Reply-To: assistenza@example.net\r\n\
Subject: Ordine n. 4012\r\n\
X-Spam-Status: No, score=2.1 required=5.0\r\n\
X-MS-Exchange-Organization-SCL: 1\r\n\
\r\nCorpo\r\n";

    #[test]
    fn messaggio_completo() {
        let m = analyze(MSG);
        assert_eq!(
            (m.subject.as_str(), m.from.as_str(), m.from_domain.as_str()),
            ("Ordine n. 4012", "ordini@example.org", "example.org")
        );
        assert_eq!(m.return_path, "bounce@invio.example.org");
        // path in time order, with the delays
        let path: Vec<(&str, &str, Option<i64>, &str)> = m
            .hops
            .iter()
            .map(|h| (h.by.as_str(), h.tls.as_str(), h.delay_s, h.status))
            .collect();
        assert_eq!(
            path,
            vec![
                ("mail-out.example.org", "TLS 1.3", None, ""),
                ("mx1.example.com", "TLS 1.3", Some(2), ""),
                ("spam01.corp.example", "TLS 1.2", Some(41), "warn"),
                ("mail01.corp.example", "", Some(1), ""),
            ]
        );
        assert_eq!(m.hops[0].from_ip, "192.0.2.44");
        assert_eq!(m.total_s, Some(44));
        let c = &m.checks;
        assert_eq!(
            find(c, "SPF").detail,
            "pass per invio.example.org, allineato al mittente"
        );
        assert_eq!(
            find(c, "DKIM").detail,
            "pass, firma di example.org, allineato al mittente"
        );
        assert_eq!(find(c, "DMARC").detail, "pass per example.org");
        assert!(find(c, "Chi lo dice")
            .detail
            .contains("(spam01.corp.example)"));
        assert!(find(c, "Chi lo dice")
            .detail
            .contains("gli altri 1 più in basso"));
        assert_eq!(find(c, "From e Return-Path").status, OK);
        let r = find(c, "Reply-To");
        assert!(r.status == WARN && r.detail.ends_with("assistenza@example.net"));
        let d = find(c, "Ritardo");
        assert_eq!(d.detail, "41 s prima di spam01.corp.example (passo 3)");
        assert_eq!(
            find(c, "Cifratura").detail,
            "TLS dichiarato su 3 passi su 4"
        );
        assert_eq!(find(c, "Punteggi").status, INFO);
        assert_eq!(m.scores.len(), 2);
        assert_eq!((m.scores[0].status, m.scores[1].status), (OK, OK));
        assert_eq!(
            m.signatures,
            vec![Signature {
                domain: "example.org".into(),
                selector: "s1".into()
            }]
        );
        assert_eq!(m.headers.len(), 13);
        assert_eq!(m.auth["count"], 2);
    }

    #[test]
    fn messaggio_sospetto() {
        let raw = "Authentication-Results: mx.example.com; spf=softfail smtp.mailfrom=x@altro.example.net; dkim=none; dmarc=fail header.from=example.org\r\n\
Received: from a by b; data illeggibile\r\n\
From: \"direzione@example.org\" <tizio@altro.example.net>\r\n\
Return-Path: <x@altro.example.net>\r\n\
X-Spam-Flag: YES\r\n\
X-Forefront-Antispam-Report-Untrusted: breve\r\n\
X-Test-SCL: 9\r\n\r\n";
        let m = analyze(raw);
        let c = &m.checks;
        assert_eq!(find(c, "SPF").status, WARN);
        assert!(find(c, "SPF").detail.ends_with("allineato al mittente"));
        assert_eq!(find(c, "DKIM").detail, "none");
        assert_eq!(find(c, "DMARC").status, ERR);
        let n = find(c, "Nome visualizzato");
        assert!(
            n.status == WARN
                && n.detail.contains("direzione@example.org")
                && n.detail.contains("tizio@altro.example.net")
        );
        let g = find(c, "Giudizio");
        assert!(g.detail.contains("X-Spam-Flag") && g.detail.contains("X-Test-SCL"));
        assert_eq!(m.hops.len(), 1);
        assert_eq!((m.hops[0].time, m.total_s), (None, None));
        assert!(!c.iter().any(|x| x.name == "Ritardo" || x.name == "Tempi"));
        assert!(m.signatures.is_empty());

        // without Authentication-Results, different From and Return-Path
        let m = analyze("From: a@example.org\r\nReturn-Path: <b@invii.example.net>\r\n\r\n");
        assert_eq!(find(&m.checks, "Esiti").status, INFO);
        assert_eq!(find(&m.checks, "From e Return-Path").status, INFO);
        assert!(m.hops.is_empty() && m.scores.is_empty());
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let m = analyze(MSG);
        let c = &m.checks;
        assert_eq!(
            find(c, "SPF").detail,
            "pass for invio.example.org, aligned with the sender"
        );
        assert_eq!(
            find(c, "Delay").detail,
            "41 s before spam01.corp.example (step 3)"
        );
        assert_eq!(find(c, "Delay").area, "Path");
        assert_eq!(
            find(c, "Encryption").detail,
            "TLS declared on 3 steps out of 4"
        );
        assert!(!c.iter().any(|x| x.name == "Ritardo"));
    }
}
