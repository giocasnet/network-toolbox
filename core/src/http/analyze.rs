//! Analysis of the headers of an HTTP response: cookies, Content-Security-Policy, HSTS,
//! CDN and headers that reveal the software. Pure functions only: no network requests.

use crate::{t, tf};
use serde::Serialize;
use std::collections::BTreeMap;

pub const OK: &str = "ok";
pub const WARN: &str = "warn";
pub const ERR: &str = "err";
pub const INFO: &str = "info";

/// A check with its outcome, ready for the list shown by the interface.
#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Check {
    /// "Trasporto" (Transport), "Header", "CSP", "Cookie", "Server"
    pub area: &'static str,
    /// "ok", "warn", "err", "info"
    pub status: &'static str,
    pub name: String,
    pub detail: String,
}

pub fn check(
    area: &'static str,
    status: &'static str,
    name: &str,
    detail: impl Into<String>,
) -> Check {
    Check {
        area,
        status,
        name: name.to_string(),
        detail: detail.into(),
    }
}

// ───────────────────────── cookie ─────────────────────────

/// A cookie set by the response. The value is never kept.
#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Cookie {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    /// "Strict", "Lax", "None" or empty if the attribute is missing
    pub same_site: String,
    /// Empty = only the host that set it
    pub domain: String,
    pub path: String,
    /// "sessione", "365 giorni", "eliminato" (session, 365 days, deleted)…
    pub lifetime: String,
    /// Index (from 0) of the chain step that set it
    pub hop: usize,
    pub status: &'static str,
    /// Reason for the status, empty if there is nothing to report
    pub note: String,
}

/// Names that usually hold a session or an access token.
fn session_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["sess", "sid", "token", "auth", "login", "jwt"]
        .iter()
        .any(|k| n.contains(k))
}

fn plural(n: i64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Human-readable duration of a number of seconds.
pub fn duration_text(secs: i64) -> String {
    if secs <= 0 {
        t!("eliminato", "deleted").into()
    } else if secs < 3600 {
        plural(
            (secs / 60).max(1),
            t!("minuto", "minute"),
            t!("minuti", "minutes"),
        )
    } else if secs < 86_400 {
        plural(secs / 3600, t!("ora", "hour"), t!("ore", "hours"))
    } else if secs < 730 * 86_400 {
        plural(secs / 86_400, t!("giorno", "day"), t!("giorni", "days"))
    } else {
        plural(
            secs / (365 * 86_400),
            t!("anno", "year"),
            t!("anni", "years"),
        )
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `Expires` date in Unix seconds. Accepts "Wed, 21 Oct 2026 07:28:00 GMT" and the
/// form with hyphens ("21-Oct-2026", "21-Oct-26"); `None` if it cannot be read.
pub fn http_date(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let (mut day, mut month, mut year, mut time) = (None, None, None, None);
    for tok in s.split([' ', ',', '-']).filter(|t| !t.is_empty()) {
        let low = tok.to_ascii_lowercase();
        if tok.contains(':') {
            let p: Vec<i64> = tok.split(':').filter_map(|x| x.parse().ok()).collect();
            if p.len() == 3 {
                time = Some(p[0] * 3600 + p[1] * 60 + p[2]);
            }
        } else if let Some(m) = MONTHS.iter().position(|m| low.starts_with(m)) {
            if low.len() >= 3 && month.is_none() && !low.chars().any(|c| c.is_ascii_digit()) {
                month = Some(m as i64 + 1);
            }
        } else if let Ok(n) = tok.parse::<i64>() {
            if day.is_none() && (1..=31).contains(&n) && tok.len() <= 2 {
                day = Some(n);
            } else if year.is_none() {
                year = Some(match n {
                    0..=69 => 2000 + n,
                    70..=99 => 1900 + n,
                    _ => n,
                });
            }
        }
    }
    Some(days_from_civil(year?, month?, day?) * 86_400 + time.unwrap_or(0))
}

/// Parses a `Set-Cookie` header. `https` = the step that sets it is on HTTPS.
pub fn parse_cookie(raw: &str, https: bool, hop: usize, now: i64) -> Option<Cookie> {
    let mut parts = raw.split(';');
    let (name, _value) = parts.next()?.split_once('=')?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut c = Cookie {
        name,
        secure: false,
        http_only: false,
        same_site: String::new(),
        domain: String::new(),
        path: String::new(),
        lifetime: t!("sessione", "session").into(),
        hop,
        status: OK,
        note: String::new(),
    };
    let (mut max_age, mut expires) = (None, None);
    for p in parts {
        let (k, v) = match p.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
            None => (p.trim().to_ascii_lowercase(), ""),
        };
        match k.as_str() {
            "secure" => c.secure = true,
            "httponly" => c.http_only = true,
            "samesite" => {
                c.same_site = match v.to_ascii_lowercase().as_str() {
                    "strict" => "Strict".into(),
                    "lax" => "Lax".into(),
                    "none" => "None".into(),
                    _ => String::new(),
                }
            }
            "domain" => c.domain = v.to_ascii_lowercase(),
            "path" => c.path = v.to_string(),
            "max-age" => max_age = v.parse::<i64>().ok(),
            "expires" => expires = http_date(v),
            _ => {}
        }
    }
    // Max-Age takes precedence over Expires (RFC 6265 §5.3)
    let deleted = match (max_age, expires) {
        (Some(s), _) => {
            c.lifetime = duration_text(s);
            s <= 0
        }
        (None, Some(t)) => {
            c.lifetime = duration_text(t - now);
            t <= now
        }
        _ => false,
    };
    if deleted {
        return Some(c); // the server is deleting it: nothing to evaluate
    }

    let mut worst = OK;
    let mut notes: Vec<String> = Vec::new();
    let mut flag = |status: &'static str, why: &str| {
        notes.push(why.to_string());
        if rank(status) < rank(worst) {
            worst = status;
        }
    };
    let sensitive = c.http_only || session_like(&c.name);
    if c.name.starts_with("__Host-") && !(c.secure && c.path == "/" && c.domain.is_empty()) {
        flag(
            ERR,
            t!(
                "prefisso __Host- senza Secure, Path=/ e senza Domain: il browser lo scarta",
                "__Host- prefix without Secure, Path=/ and without Domain: the browser discards it"
            ),
        );
    } else if c.name.starts_with("__Secure-") && !c.secure {
        flag(
            ERR,
            t!(
                "prefisso __Secure- senza Secure: il browser lo scarta",
                "__Secure- prefix without Secure: the browser discards it"
            ),
        );
    }
    if c.same_site == "None" && !c.secure {
        flag(
            ERR,
            t!(
                "SameSite=None senza Secure: il browser lo scarta",
                "SameSite=None without Secure: the browser discards it"
            ),
        );
    } else if !c.secure && https {
        flag(
            if sensitive { ERR } else { WARN },
            t!(
                "senza Secure: viaggia anche su HTTP",
                "without Secure: also travels over HTTP"
            ),
        );
    }
    if !https {
        flag(
            WARN,
            t!("impostato su HTTP in chiaro", "set over plain HTTP"),
        );
    }
    if !c.http_only && session_like(&c.name) {
        flag(
            WARN,
            t!(
                "senza HttpOnly: leggibile dagli script della pagina",
                "without HttpOnly: readable by the page's scripts"
            ),
        );
    }
    if c.same_site.is_empty() {
        flag(
            INFO,
            t!(
                "senza SameSite (il browser applica Lax)",
                "without SameSite (the browser applies Lax)"
            ),
        );
    }
    c.status = worst;
    c.note = notes.join("; ");
    Some(c)
}

/// Severity order: errors, warnings, information, passed.
pub fn rank(status: &str) -> u8 {
    match status {
        ERR => 0,
        WARN => 1,
        INFO => 2,
        _ => 3,
    }
}

/// `Set-Cookie` with the value hidden, for the table of all headers.
pub fn mask_cookie(raw: &str) -> String {
    let (first, rest) = match raw.split_once(';') {
        Some((f, r)) => (f, Some(r)),
        None => (raw, None),
    };
    let name = first
        .split_once('=')
        .map(|(n, _)| n)
        .unwrap_or(first)
        .trim();
    let hidden = t!("(nascosto)", "(hidden)");
    match rest {
        Some(r) => format!("{name}={hidden};{r}"),
        None => format!("{name}={hidden}"),
    }
}

// ───────────────────────── Content-Security-Policy ─────────────────────────

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct CspSource {
    pub value: String,
    /// "" (normal), "weak", "bad" (dangerous)
    pub level: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct CspDirective {
    pub name: String,
    pub sources: Vec<CspSource>,
    /// "", "ok", "warn", "err"
    pub status: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Clone, Default)]
pub struct Csp {
    /// Only `Content-Security-Policy-Report-Only`: the policy is not enforced
    pub report_only: bool,
    pub directives: Vec<CspDirective>,
    /// Important directives that are missing and not covered by `default-src`
    pub missing: Vec<String>,
    /// Number of policies sent (several headers): the first one is analysed
    pub policies: usize,
}

impl Csp {
    pub fn directive(&self, name: &str) -> Option<&CspDirective> {
        self.directives.iter().find(|d| d.name == name)
    }
}

fn join_e(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [head @ .., last] => format!("{}{}{last}", head.join(", "), t!(" e ", " and ")),
    }
}

/// Parses a policy. Returns the structure for the interface and the checks.
pub fn parse_csp(policy: &str, report_only: bool, policies: usize) -> (Csp, Vec<Check>) {
    let mut csp = Csp {
        report_only,
        policies,
        ..Csp::default()
    };
    let mut checks = Vec::new();
    let mut raw: Vec<(String, Vec<String>)> = Vec::new();
    for part in policy.split(';') {
        let mut t = part.split_whitespace();
        let Some(name) = t.next() else { continue };
        let name = name.to_ascii_lowercase();
        if raw.iter().any(|(n, _)| *n == name) {
            continue; // a repeated directive is ignored by browsers
        }
        raw.push((name, t.map(str::to_string).collect()));
    }
    let has = |n: &str| raw.iter().any(|(d, _)| d == n);
    let has_script = has("script-src");
    let has_default = has("default-src");

    for (name, sources) in &raw {
        // what decides for scripts: script-src, or default-src if script-src is missing
        let scripts = name == "script-src" || (name == "default-src" && !has_script);
        let low: Vec<String> = sources.iter().map(|s| s.to_ascii_lowercase()).collect();
        // with a nonce, hash or strict-dynamic browsers ignore 'unsafe-inline'
        let guarded = low
            .iter()
            .any(|s| s.starts_with("'nonce-") || s.starts_with("'sha") || s == "'strict-dynamic'");
        let fetch = name.ends_with("-src");
        let mut out = Vec::new();
        for (s, l) in sources.iter().zip(&low) {
            let level = match l.as_str() {
                "'unsafe-inline'" if scripts && !guarded => "bad",
                "'unsafe-inline'" if name == "style-src" || name == "default-src" => "weak",
                "'unsafe-eval'" if scripts => "bad",
                "*" | "https:" | "http:" | "data:" if scripts => "bad",
                "*" | "http:" if fetch && name != "img-src" && name != "media-src" => "weak",
                "http:" => "weak",
                "*" if name == "frame-ancestors" || name == "form-action" || name == "base-uri" => {
                    "weak"
                }
                _ => "",
            };
            out.push(CspSource {
                value: s.clone(),
                level,
            });
        }
        let bad: Vec<&str> = out
            .iter()
            .filter(|s| s.level == "bad")
            .map(|s| s.value.as_str())
            .collect();
        let weak: Vec<&str> = out
            .iter()
            .filter(|s| s.level == "weak")
            .map(|s| s.value.as_str())
            .collect();
        let status = if !bad.is_empty() {
            checks.push(check(
                "CSP",
                ERR,
                name,
                tf!(
                    "{} {} script non previsti",
                    "{} {} unexpected scripts",
                    join_e(&bad),
                    if bad.len() == 1 {
                        t!("permette", "allows")
                    } else {
                        t!("permettono", "allow")
                    }
                ),
            ));
            ERR
        } else if !weak.is_empty() {
            checks.push(check(
                "CSP",
                WARN,
                name,
                tf!(
                    "{} {} la protezione",
                    "{} {} the protection",
                    join_e(&weak),
                    if weak.len() == 1 {
                        t!("indebolisce", "weakens")
                    } else {
                        t!("indeboliscono", "weaken")
                    }
                ),
            ));
            WARN
        } else if name == "frame-ancestors" {
            OK
        } else {
            ""
        };
        csp.directives.push(CspDirective {
            name: name.clone(),
            sources: out,
            status,
        });
    }

    if !has_script && !has_default {
        checks.push(check(
            "CSP",
            ERR,
            "script-src",
            t!(
                "né script-src né default-src: nessun limite agli script",
                "neither script-src nor default-src: no limit on scripts"
            ),
        ));
        csp.missing.push("script-src".into());
    }
    // object-src falls back to default-src; base-uri falls back to nothing
    if !has("object-src") && !has_default {
        csp.missing.push("object-src".into());
    }
    if !has("base-uri") {
        csp.missing.push("base-uri".into());
    }
    let late: Vec<&str> = csp
        .missing
        .iter()
        .map(String::as_str)
        .filter(|m| *m != "script-src")
        .collect();
    if !late.is_empty() {
        checks.push(check(
            "CSP",
            WARN,
            &late.join(", "),
            if late.len() == 1 {
                t!(
                    "assente: non è coperta da default-src",
                    "missing: not covered by default-src"
                )
            } else {
                t!(
                    "assenti: non sono coperte da default-src",
                    "missing: not covered by default-src"
                )
            },
        ));
    }
    if report_only {
        checks.insert(
            0,
            check(
                "CSP",
                WARN,
                "Content-Security-Policy",
                t!(
                    "solo Report-Only: le violazioni sono segnalate ma non bloccate",
                    "Report-Only only: violations are reported but not blocked"
                ),
            ),
        );
    } else if checks.is_empty() {
        checks.push(check(
            "CSP",
            OK,
            "Content-Security-Policy",
            t!(
                "presente, senza sorgenti deboli",
                "present, without weak sources"
            ),
        ));
    }
    if policies > 1 {
        checks.push(check(
            "CSP",
            INFO,
            "Content-Security-Policy",
            tf!(
                "{policies} policy inviate (valgono tutte insieme): analizzata la prima",
                "{policies} policies sent (they all apply together): the first one was analysed"
            ),
        ));
    }
    (csp, checks)
}

// ───────────────────────── HSTS ─────────────────────────

pub const HSTS_MIN: u64 = 15_552_000; // 180 days
pub const HSTS_PRELOAD: u64 = 31_536_000; // 1 year

/// Evaluates a `Strict-Transport-Security` header received over HTTPS.
pub fn hsts(value: &str) -> (&'static str, String) {
    let v = value.to_ascii_lowercase();
    let parts: Vec<&str> = v.split(';').map(str::trim).collect();
    let max_age = parts
        .iter()
        .find_map(|p| p.strip_prefix("max-age="))
        .and_then(|n| n.trim_matches('"').parse::<u64>().ok());
    let sub = parts.contains(&"includesubdomains");
    let preload = parts.contains(&"preload");
    let Some(age) = max_age else {
        return (
            ERR,
            t!(
                "max-age mancante o non valido",
                "max-age missing or invalid"
            )
            .into(),
        );
    };
    if age == 0 {
        return (
            ERR,
            t!("max-age=0 disattiva HSTS", "max-age=0 disables HSTS").into(),
        );
    }
    let mut detail = format!("max-age={age} ({})", duration_text(age as i64));
    let mut status = OK;
    if age < HSTS_MIN {
        status = WARN;
        detail.push_str(t!(
            ": consigliato almeno 6 mesi",
            ": at least 6 months recommended"
        ));
    }
    if !sub {
        detail.push_str(t!(
            "; senza includeSubDomains",
            "; without includeSubDomains"
        ));
    } else {
        detail.push_str("; includeSubDomains");
    }
    if preload {
        if age >= HSTS_PRELOAD && sub {
            detail.push_str("; preload");
        } else {
            status = WARN;
            detail.push_str(t!(
                "; preload richiede max-age di almeno 1 anno e includeSubDomains",
                "; preload requires max-age of at least 1 year and includeSubDomains"
            ));
        }
    }
    (status, detail)
}

/// `true` if the header really enables HSTS (for the intermediate steps of the chain).
pub fn hsts_active(value: &str) -> bool {
    hsts(value).0 != ERR
}

// ───────────────────────── headers of the final response ─────────────────────────

/// Checks on the security headers of the final response (CSP aside).
/// `frame_ancestors` = the applied CSP has the `frame-ancestors` directive.
pub fn header_checks(h: &BTreeMap<String, String>, frame_ancestors: Option<&str>) -> Vec<Check> {
    let mut out = Vec::new();
    let get = |n: &str| h.get(n).map(|v| v.trim()).filter(|v| !v.is_empty());

    match get("X-Content-Type-Options") {
        Some(v) if v.eq_ignore_ascii_case("nosniff") => {
            out.push(check("Header", OK, "X-Content-Type-Options", "nosniff"))
        }
        Some(v) => out.push(check(
            "Header",
            WARN,
            "X-Content-Type-Options",
            tf!(
                "{v}: l'unico valore valido è nosniff",
                "{v}: the only valid value is nosniff"
            ),
        )),
        None => out.push(check(
            "Header",
            ERR,
            "X-Content-Type-Options",
            t!("assente", "missing"),
        )),
    }

    let xfo = get("X-Frame-Options");
    match (frame_ancestors, xfo) {
        (Some(fa), _) => out.push(check(
            "Header",
            OK,
            t!("Protezione dai frame", "Frame protection"),
            tf!(
                "CSP frame-ancestors {fa} (X-Frame-Options non serve)",
                "CSP frame-ancestors {fa} (X-Frame-Options is not needed)"
            ),
        )),
        (None, Some(v)) if matches!(v.to_ascii_lowercase().as_str(), "deny" | "sameorigin") => out
            .push(check(
                "Header",
                OK,
                t!("Protezione dai frame", "Frame protection"),
                format!("X-Frame-Options: {v}"),
            )),
        (None, Some(v)) => out.push(check(
            "Header",
            WARN,
            t!("Protezione dai frame", "Frame protection"),
            tf!(
                "X-Frame-Options: {v} (valori validi: DENY o SAMEORIGIN)",
                "X-Frame-Options: {v} (valid values: DENY or SAMEORIGIN)"
            ),
        )),
        (None, None) => out.push(check(
            "Header",
            ERR,
            t!("Protezione dai frame", "Frame protection"),
            t!(
                "né X-Frame-Options né CSP frame-ancestors",
                "neither X-Frame-Options nor CSP frame-ancestors"
            ),
        )),
    }

    match get("Referrer-Policy") {
        Some(v)
            if v.split(',')
                .next_back()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                == Some("unsafe-url".into()) =>
        {
            out.push(check(
                "Header",
                WARN,
                "Referrer-Policy",
                t!(
                    "unsafe-url invia sempre l'URL completo",
                    "unsafe-url always sends the full URL"
                ),
            ))
        }
        Some(v) => out.push(check("Header", OK, "Referrer-Policy", v)),
        None => out.push(check(
            "Header",
            WARN,
            "Referrer-Policy",
            t!(
                "assente (i browser applicano strict-origin-when-cross-origin)",
                "missing (browsers apply strict-origin-when-cross-origin)"
            ),
        )),
    }

    match get("Permissions-Policy") {
        Some(_) => out.push(check(
            "Header",
            OK,
            "Permissions-Policy",
            t!("presente", "present"),
        )),
        None => out.push(check(
            "Header",
            WARN,
            "Permissions-Policy",
            t!("assente", "missing"),
        )),
    }

    let iso: Vec<String> = [
        ("Cross-Origin-Opener-Policy", "COOP"),
        ("Cross-Origin-Embedder-Policy", "COEP"),
        ("Cross-Origin-Resource-Policy", "CORP"),
    ]
    .iter()
    .filter_map(|(n, short)| get(n).map(|v| format!("{short} {v}")))
    .collect();
    if iso.is_empty() {
        out.push(check(
            "Header",
            INFO,
            t!("Isolamento cross-origin", "Cross-origin isolation"),
            t!("COOP, COEP e CORP assenti", "COOP, COEP and CORP missing"),
        ));
    } else {
        out.push(check(
            "Header",
            OK,
            t!("Isolamento cross-origin", "Cross-origin isolation"),
            iso.join(", "),
        ));
    }

    for (n, why) in [
        (
            "X-Xss-Protection",
            t!(
                "obsoleto: i browser lo ignorano",
                "obsolete: browsers ignore it"
            ),
        ),
        (
            "Expect-Ct",
            t!(
                "obsoleto: i browser lo ignorano",
                "obsolete: browsers ignore it"
            ),
        ),
        (
            "Public-Key-Pins",
            t!(
                "obsoleto e rischioso: rimosso dai browser",
                "obsolete and risky: removed from browsers"
            ),
        ),
    ] {
        if h.contains_key(n) {
            out.push(check("Header", INFO, n, why));
        }
    }
    out
}

// ───────────────────────── server and CDN ─────────────────────────

/// CDN or proxy recognised from the headers: (short label, detail).
pub fn cdn(h: &BTreeMap<String, String>) -> Option<(String, String)> {
    let get = |n: &str| h.get(n).map(|v| v.trim()).filter(|v| !v.is_empty());
    let server = get("Server").unwrap_or("").to_ascii_lowercase();
    let via = get("Via").unwrap_or("").to_ascii_lowercase();
    let with = |name: &str, pop: Option<&str>, cache: Option<&str>| {
        let label = match pop {
            Some(p) => format!("{name} · {p}"),
            None => name.to_string(),
        };
        let mut detail = name.to_string();
        if let Some(p) = pop {
            detail.push_str(&tf!(", datacenter {p}", ", data centre {p}"));
        }
        if let Some(c) = cache {
            detail.push_str(&format!(", cache {c}"));
        }
        Some((label, detail))
    };
    if let Some(ray) = get("Cf-Ray") {
        let pop = ray.rsplit_once('-').map(|(_, p)| p);
        return with("Cloudflare", pop, get("Cf-Cache-Status"));
    }
    if server == "cloudflare" {
        return with("Cloudflare", None, get("Cf-Cache-Status"));
    }
    if get("X-Amz-Cf-Id").is_some() || via.contains("cloudfront") {
        // "MXP64-P1" → MXP
        let pop = get("X-Amz-Cf-Pop").map(|p| p.get(..3).unwrap_or(p));
        return with("CloudFront", pop, get("X-Cache"));
    }
    if get("X-Azure-Ref").is_some() {
        return with("Azure Front Door", None, get("X-Cache"));
    }
    if server.contains("akamai") || h.keys().any(|k| k.starts_with("X-Akamai")) {
        return with("Akamai", None, get("X-Cache"));
    }
    if get("X-Fastly-Request-Id").is_some()
        || (via.contains("varnish") && get("X-Served-By").is_some_and(|v| v.contains("cache-")))
    {
        // "cache-mxp6931-MXP" → MXP
        let pop = get("X-Served-By").and_then(|v| v.rsplit_once('-').map(|(_, p)| p));
        return with("Fastly", pop, get("X-Cache"));
    }
    None
}

/// Headers that reveal software and versions, plus the recognised CDN.
pub fn server_checks(h: &BTreeMap<String, String>) -> Vec<Check> {
    let mut out = Vec::new();
    if let Some(v) = h.get("Server") {
        // a version is a digit after "/" or a space: "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)"
        let version = v
            .split(['/', ' '])
            .skip(1)
            .any(|p| p.chars().next().is_some_and(|c| c.is_ascii_digit()));
        if version {
            out.push(check(
                "Server",
                WARN,
                "Server",
                tf!("rivela la versione: {v}", "reveals the version: {v}"),
            ));
        }
    }
    for n in [
        "X-Powered-By",
        "X-Aspnet-Version",
        "X-Aspnetmvc-Version",
        "X-Generator",
    ] {
        if let Some(v) = h.get(n) {
            out.push(check(
                "Server",
                WARN,
                n,
                tf!("rivela il software: {v}", "reveals the software: {v}"),
            ));
        }
    }
    if let Some((_, detail)) = cdn(h) {
        out.push(check("Server", INFO, "CDN", detail));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    fn ck(raw: &str, https: bool) -> Cookie {
        parse_cookie(raw, https, 0, NOW).unwrap()
    }

    #[test]
    fn cookie_attributi() {
        let c = ck(
            "__Host-sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
            true,
        );
        assert_eq!(c.name, "__Host-sid");
        assert!(c.secure && c.http_only);
        assert_eq!(
            (c.same_site.as_str(), c.path.as_str(), c.lifetime.as_str()),
            ("Strict", "/", "sessione")
        );
        assert_eq!((c.status, c.note.as_str()), (OK, ""));

        let c = ck("lang=it; Max-Age=31536000; Secure; SameSite=lax", true);
        assert_eq!(c.lifetime, "365 giorni");
        assert_eq!(c.same_site, "Lax");
        assert_eq!(c.status, OK);

        // Max-Age wins over Expires
        let c = ck(
            "a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Max-Age=7200; Secure; SameSite=Lax",
            true,
        );
        assert_eq!(c.lifetime, "2 ore");
        assert!(parse_cookie("senza-uguale", true, 0, NOW).is_none());
        assert!(parse_cookie("=x", true, 0, NOW).is_none());
    }

    #[test]
    fn cookie_segnalazioni() {
        // session without Secure over HTTPS: error
        let c = ck(
            "sessionid=xyz; Domain=.Example.com; Path=/; HttpOnly; SameSite=Lax",
            true,
        );
        assert_eq!(c.status, ERR);
        assert!(c.note.contains("senza Secure"));
        assert_eq!(c.domain, ".example.com");
        // any cookie without Secure: warning
        let c = ck("tema=scuro; SameSite=Lax", true);
        assert_eq!(c.status, WARN);
        // SameSite=None without Secure: discarded by the browser
        let c = ck("_track=1; SameSite=None", true);
        assert_eq!(c.status, ERR);
        assert!(c.note.contains("SameSite=None senza Secure"));
        assert!(!c.note.contains("viaggia"), "{}", c.note);
        // only SameSite missing: information
        let c = ck("pref=1; Secure", true);
        assert_eq!(c.status, INFO);
        // prefixes
        assert_eq!(
            ck(
                "__Host-a=1; Secure; Path=/; Domain=example.com; SameSite=Lax",
                true
            )
            .status,
            ERR
        );
        assert_eq!(ck("__Secure-a=1; SameSite=Lax", true).status, ERR);
        // token readable by scripts
        let c = ck("auth_token=1; Secure; SameSite=Strict", true);
        assert_eq!(c.status, WARN);
        assert!(c.note.contains("HttpOnly"));
        // over plain HTTP
        let c = ck("a=1; SameSite=Lax", false);
        assert_eq!(c.status, WARN);
        assert!(c.note.contains("HTTP in chiaro"));
        // a deleted cookie is not evaluated
        let c = ck("sessionid=; Max-Age=0", true);
        assert_eq!((c.lifetime.as_str(), c.status), ("eliminato", OK));
        let c = ck("sessionid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT", true);
        assert_eq!((c.lifetime.as_str(), c.status), ("eliminato", OK));
    }

    #[test]
    fn date_e_durate() {
        assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            http_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(1_445_412_480)
        );
        assert_eq!(
            http_date("Wed, 21-Oct-2015 07:28:00 GMT"),
            Some(1_445_412_480)
        );
        assert_eq!(
            http_date("Wed, 21-Oct-15 07:28:00 GMT"),
            Some(1_445_412_480)
        );
        assert_eq!(http_date("domani"), None);
        assert_eq!(duration_text(0), "eliminato");
        assert_eq!(duration_text(30), "1 minuto");
        assert_eq!(duration_text(3600), "1 ora");
        assert_eq!(duration_text(86_400), "1 giorno");
        assert_eq!(duration_text(63_072_000), "2 anni");
    }

    #[test]
    fn valore_del_cookie_nascosto() {
        assert_eq!(
            mask_cookie("sid=SEGRETO; Path=/; Secure"),
            "sid=(nascosto); Path=/; Secure"
        );
        assert_eq!(mask_cookie("sid=SEGRETO"), "sid=(nascosto)");
        // an "=" in the value leaks nothing
        assert!(!mask_cookie("t=a=b=c; HttpOnly").contains("a=b"));
    }

    #[test]
    fn csp_debole() {
        let (csp, checks) = parse_csp(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'self'",
            false,
            1,
        );
        let s = csp.directive("script-src").unwrap();
        assert_eq!(s.status, ERR);
        let levels: Vec<&str> = s.sources.iter().map(|x| x.level).collect();
        assert_eq!(levels, ["", "bad", "bad", ""]);
        assert_eq!(csp.directive("style-src").unwrap().status, WARN);
        assert_eq!(csp.directive("img-src").unwrap().status, "");
        assert_eq!(csp.directive("frame-ancestors").unwrap().status, OK);
        assert_eq!(csp.directive("default-src").unwrap().status, "");
        // object-src is covered by default-src, base-uri is not
        assert_eq!(csp.missing, ["base-uri"]);
        let err: Vec<&Check> = checks.iter().filter(|c| c.status == ERR).collect();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].name, "script-src");
        assert!(err[0]
            .detail
            .contains("'unsafe-inline' e 'unsafe-eval' permettono"));
        assert!(checks
            .iter()
            .any(|c| c.name == "base-uri" && c.status == WARN));
    }

    #[test]
    fn csp_solida_e_casi_limite() {
        // nonce: 'unsafe-inline' is ignored by browsers, so it is not a defect
        let (csp, checks) = parse_csp(
            "default-src 'none'; script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'; base-uri 'none'; object-src 'none'",
            false,
            1,
        );
        assert_eq!(csp.directive("script-src").unwrap().status, "");
        assert!(csp.missing.is_empty());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, OK);

        // without script-src, default-src decides
        let (csp, checks) = parse_csp("default-src * 'unsafe-inline'", false, 1);
        assert_eq!(csp.directive("default-src").unwrap().status, ERR);
        assert!(checks
            .iter()
            .any(|c| c.status == ERR && c.name == "default-src"));

        // no limit on scripts
        let (csp, checks) = parse_csp("frame-ancestors 'none'", false, 1);
        assert_eq!(csp.missing, ["script-src", "object-src", "base-uri"]);
        assert!(checks
            .iter()
            .any(|c| c.status == ERR && c.name == "script-src"));
        assert!(checks.iter().any(|c| c.name == "object-src, base-uri"));

        // Report-Only and multiple policies
        let (csp, checks) = parse_csp("default-src 'self'; base-uri 'self'", true, 2);
        assert!(csp.report_only);
        assert_eq!(checks[0].status, WARN);
        assert!(checks[0].detail.contains("Report-Only"));
        assert!(checks
            .iter()
            .any(|c| c.status == INFO && c.detail.contains("2 policy")));

        // repeated directive: the first one counts; capitals in names
        let (csp, _) = parse_csp("Script-Src 'self'; script-src *", false, 1);
        assert_eq!(csp.directives.len(), 1);
        assert_eq!(csp.directives[0].sources[0].value, "'self'");
    }

    #[test]
    fn hsts_valori() {
        let (s, d) = hsts("max-age=31536000; includeSubDomains; preload");
        assert_eq!(s, OK);
        assert!(d.contains("365 giorni") && d.ends_with("preload"), "{d}");
        let (s, d) = hsts("max-age=86400");
        assert_eq!(s, WARN);
        assert!(
            d.contains("1 giorno") && d.contains("6 mesi") && d.contains("senza includeSubDomains")
        );
        let (s, d) = hsts("max-age=31536000");
        assert_eq!(s, OK);
        assert!(d.contains("senza includeSubDomains"));
        let (s, d) = hsts("max-age=31536000; preload");
        assert_eq!(s, WARN);
        assert!(d.contains("preload richiede"));
        assert_eq!(hsts("max-age=0").0, ERR);
        assert_eq!(hsts("includeSubDomains").0, ERR);
        assert_eq!(hsts("MAX-AGE=\"600\"").0, WARN);
        assert!(hsts_active("max-age=600") && !hsts_active("max-age=0"));
    }

    fn map(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn find<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("manca {name}: {c:?}"))
    }

    #[test]
    fn header_di_sicurezza() {
        let c = header_checks(&map(&[]), None);
        assert_eq!(find(&c, "X-Content-Type-Options").status, ERR);
        assert_eq!(find(&c, "Protezione dai frame").status, ERR);
        assert_eq!(find(&c, "Referrer-Policy").status, WARN);
        assert_eq!(find(&c, "Permissions-Policy").status, WARN);
        assert_eq!(find(&c, "Isolamento cross-origin").status, INFO);

        let h = map(&[
            ("X-Content-Type-Options", "NoSniff"),
            ("X-Frame-Options", "ALLOWALL"),
            ("Referrer-Policy", "no-referrer, unsafe-url"),
            ("Permissions-Policy", "geolocation=()"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("X-Xss-Protection", "1; mode=block"),
        ]);
        let c = header_checks(&h, None);
        assert_eq!(find(&c, "X-Content-Type-Options").status, OK);
        assert_eq!(find(&c, "Protezione dai frame").status, WARN);
        assert_eq!(find(&c, "Referrer-Policy").status, WARN);
        assert_eq!(find(&c, "Permissions-Policy").status, OK);
        assert_eq!(
            find(&c, "Isolamento cross-origin").detail,
            "COOP same-origin"
        );
        assert_eq!(find(&c, "X-Xss-Protection").status, INFO);

        // the CSP's frame-ancestors replaces X-Frame-Options, even if the latter is missing
        let c = header_checks(&map(&[]), Some("'self'"));
        let f = find(&c, "Protezione dai frame");
        assert_eq!(f.status, OK);
        assert!(f.detail.contains("frame-ancestors 'self'"));
        let c = header_checks(&map(&[("X-Frame-Options", "deny")]), None);
        assert_eq!(find(&c, "Protezione dai frame").status, OK);
    }

    #[test]
    fn cdn_e_software() {
        let h = map(&[
            ("Cf-Ray", "8a1b2c3d4e5f6789-MXP"),
            ("Cf-Cache-Status", "HIT"),
            ("Server", "cloudflare"),
        ]);
        assert_eq!(
            cdn(&h).unwrap(),
            (
                "Cloudflare · MXP".to_string(),
                "Cloudflare, datacenter MXP, cache HIT".to_string()
            )
        );
        let h = map(&[
            ("X-Amz-Cf-Id", "abc"),
            ("X-Amz-Cf-Pop", "MXP64-P1"),
            ("X-Cache", "Miss from cloudfront"),
        ]);
        assert_eq!(cdn(&h).unwrap().0, "CloudFront · MXP");
        let h = map(&[("Via", "1.1 varnish"), ("X-Served-By", "cache-mxp6931-MXP")]);
        assert_eq!(cdn(&h).unwrap().0, "Fastly · MXP");
        assert_eq!(
            cdn(&map(&[("X-Azure-Ref", "x")])).unwrap().0,
            "Azure Front Door"
        );
        assert_eq!(cdn(&map(&[("Server", "AkamaiGHost")])).unwrap().0, "Akamai");
        assert!(cdn(&map(&[("Server", "nginx")])).is_none());

        let c = server_checks(&map(&[
            ("Server", "nginx/1.18.0"),
            ("X-Powered-By", "PHP/7.4.3"),
        ]));
        assert_eq!(find(&c, "Server").status, WARN);
        assert!(find(&c, "X-Powered-By").detail.contains("PHP/7.4.3"));
        // without a version it is not a defect
        assert!(server_checks(&map(&[("Server", "nginx")])).is_empty());
        assert!(server_checks(&map(&[("Server", "Apache/2.4.41 (Ubuntu)")]))
            .iter()
            .any(|x| x.name == "Server"));
        assert!(server_checks(&map(&[("Server", "Microsoft-IIS/10.0")]))
            .iter()
            .any(|x| x.name == "Server"));
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let c = ck("sessionid=xyz; Path=/; HttpOnly; SameSite=Lax", true);
        assert!(c.note.contains("without Secure"), "{}", c.note);
        assert!(!c.note.contains("senza"));
        assert_eq!(duration_text(86_400), "1 day");
        assert_eq!(mask_cookie("sid=X; Path=/"), "sid=(hidden); Path=/");
        let (_, d) = hsts("max-age=86400");
        assert!(d.contains("6 months") && !d.contains("consigliato"), "{d}");
        let c = header_checks(&map(&[]), None);
        assert_eq!(
            find(&c, "Frame protection").detail,
            "neither X-Frame-Options nor CSP frame-ancestors"
        );
        let (_, checks) = parse_csp("script-src 'unsafe-inline' 'unsafe-eval'", false, 1);
        assert!(checks[0]
            .detail
            .contains("'unsafe-inline' and 'unsafe-eval' allow unexpected scripts"));
    }
}
