//! Mail policy records: DMARC, DKIM keys, MTA-STS and TLS-RPT. Pure functions only:
//! they read the text of the records (or of the downloaded policy) and say what applies.

use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::{t, tf};
use serde::Serialize;

/// A row of the tab: tag, value and what it means.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Row {
    /// "ok", "warn", "err", "info" or empty (descriptive row only)
    pub status: &'static str,
    pub name: String,
    pub value: String,
    pub detail: String,
}

fn row(
    status: &'static str,
    name: &str,
    value: impl Into<String>,
    detail: impl Into<String>,
) -> Row {
    Row {
        status,
        name: name.to_string(),
        value: value.into(),
        detail: detail.into(),
    }
}

/// `tag=value` pairs separated by `;` (DMARC, DKIM, MTA-STS TXT, TLS-RPT).
pub fn tags(record: &str) -> Vec<(String, String)> {
    record
        .split(';')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            let k = k.trim().to_ascii_lowercase();
            (!k.is_empty()).then(|| (k, v.trim().to_string()))
        })
        .collect()
}

fn tag<'a>(t: &'a [(String, String)], k: &str) -> Option<&'a str> {
    t.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

// ───────────────────────── DMARC ─────────────────────────

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct Dmarc {
    pub found: bool,
    pub record: String,
    /// Name queried (`_dmarc.domain`), or that of the organisational domain.
    pub name: String,
    /// "none", "quarantine", "reject" or empty
    pub policy: String,
    pub rows: Vec<Row>,
    /// External domains that receive the reports (to be authorised with a dedicated record).
    #[serde(skip)]
    pub external: Vec<String>,
}

fn mail_domains(list: &str) -> Vec<String> {
    list.split(',')
        .filter_map(|u| {
            let u = u.trim();
            let addr = u
                .strip_prefix("mailto:")
                .or_else(|| u.strip_prefix("MAILTO:"))?;
            let addr = addr.split('!').next().unwrap_or(addr);
            addr.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase())
        })
        .collect()
}

/// Reads the TXT records of `_dmarc`. `org` is the organisational domain (to recognise
/// the report addresses that are outside it).
pub fn dmarc(txt: &[String], name: &str, org: &str) -> (Dmarc, Vec<Check>) {
    const A: &str = "DMARC";
    let recs: Vec<&String> = txt
        .iter()
        .filter(|t| t.trim().to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();
    let mut d = Dmarc {
        name: name.to_string(),
        ..Default::default()
    };
    let mut out = Vec::new();
    let Some(first) = recs.first() else {
        out.push(check(
            A,
            ERR,
            "Record",
            t!(
                "assente: nessuna indicazione ai destinatari su che cosa fare dei messaggi falsi",
                "missing: no indication to recipients on what to do with fake messages"
            ),
        ));
        return (d, out);
    };
    d.found = true;
    d.record = first.trim().to_string();
    if recs.len() > 1 {
        out.push(check(
            A,
            ERR,
            "Record",
            tf!(
                "{} record v=DMARC1: deve essercene uno solo, altrimenti vengono ignorati",
                "{} v=DMARC1 records: there must be only one, otherwise they are ignored",
                recs.len()
            ),
        ));
    }
    let t = tags(&d.record);
    let p = tag(&t, "p").unwrap_or("").to_ascii_lowercase();
    d.policy = p.clone();
    match p.as_str() {
        "reject" => {
            d.rows.push(row(
                OK,
                "p",
                "reject",
                t!(
                    "i messaggi che falliscono vengono rifiutati",
                    "messages that fail are rejected"
                ),
            ));
            out.push(check(
                A,
                OK,
                "Policy",
                t!(
                    "p=reject: i messaggi che falliscono vengono rifiutati",
                    "p=reject: messages that fail are rejected"
                ),
            ));
        }
        "quarantine" => {
            d.rows.push(row(
                OK,
                "p",
                "quarantine",
                t!(
                    "i messaggi che falliscono vanno nella posta indesiderata",
                    "messages that fail go to the junk folder"
                ),
            ));
            out.push(check(
                A,
                OK,
                "Policy",
                t!(
                    "p=quarantine: i messaggi che falliscono vanno nella posta indesiderata",
                    "p=quarantine: messages that fail go to the junk folder"
                ),
            ));
        }
        "none" => {
            d.rows.push(row(
                WARN,
                "p",
                "none",
                t!(
                    "nessuna azione sui messaggi che falliscono",
                    "no action on messages that fail"
                ),
            ));
            out.push(check(
                A,
                WARN,
                "Policy",
                t!(
                    "p=none: i messaggi che falliscono vengono consegnati lo stesso (solo monitoraggio)",
                    "p=none: messages that fail are delivered anyway (monitoring only)"
                ),
            ));
        }
        other => {
            d.rows.push(row(
                ERR,
                "p",
                if other.is_empty() {
                    t!("(mancante)", "(missing)")
                } else {
                    other
                },
                t!("valore non valido", "invalid value"),
            ));
            out.push(check(
                A,
                ERR,
                "Policy",
                t!(
                    "tag p mancante o non valido: il record viene ignorato",
                    "tag p missing or invalid: the record is ignored"
                ),
            ));
        }
    }
    match tag(&t, "sp") {
        Some(sp) => d.rows.push(row(
            if sp.eq_ignore_ascii_case("none") && p != "none" {
                WARN
            } else {
                ""
            },
            "sp",
            sp,
            t!("policy per i sottodomini", "policy for subdomains"),
        )),
        None => d.rows.push(row(
            "",
            "sp",
            t!("(non indicata)", "(not specified)"),
            tf!("i sottodomini ereditano p={p}", "subdomains inherit p={p}"),
        )),
    }
    if let Some(sp) = tag(&t, "sp") {
        if sp.eq_ignore_ascii_case("none") && p != "none" {
            out.push(check(
                A,
                WARN,
                t!("Sottodomini", "Subdomains"),
                t!(
                    "sp=none: i sottodomini restano senza protezione",
                    "sp=none: subdomains remain unprotected"
                ),
            ));
        }
    }
    let pct = tag(&t, "pct")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(100);
    d.rows.push(row(
        if pct < 100 { WARN } else { "" },
        "pct",
        pct.to_string(),
        if pct < 100 {
            t!(
                "applicata solo a una parte dei messaggi",
                "applied to only part of the messages"
            )
        } else {
            t!("applicata a tutti i messaggi", "applied to all messages")
        },
    ));
    if pct < 100 && p != "none" {
        out.push(check(
            A,
            WARN,
            t!("Percentuale", "Percentage"),
            tf!(
                "pct={pct}: la policy vale solo per il {pct}% dei messaggi",
                "pct={pct}: the policy applies to only {pct}% of messages"
            ),
        ));
    }
    match tag(&t, "rua") {
        Some(rua) if !rua.is_empty() => {
            d.rows.push(row(
                OK,
                "rua",
                rua,
                t!("rapporti aggregati", "aggregate reports"),
            ));
            out.push(check(
                A,
                OK,
                t!("Rapporti", "Reports"),
                tf!(
                    "aggregati inviati a {rua}",
                    "aggregate reports sent to {rua}"
                ),
            ));
            let org = org.to_ascii_lowercase();
            for dom in mail_domains(rua) {
                if dom != org && !dom.ends_with(&format!(".{org}")) && !d.external.contains(&dom) {
                    d.external.push(dom);
                }
            }
        }
        _ => {
            d.rows.push(row(
                WARN,
                "rua",
                t!("(non indicato)", "(not specified)"),
                t!("nessun rapporto aggregato", "no aggregate reports"),
            ));
            out.push(check(
                A,
                WARN,
                t!("Rapporti", "Reports"),
                t!(
                    "manca rua: nessuno riceve i rapporti, i problemi restano invisibili",
                    "rua is missing: nobody receives the reports, problems stay invisible"
                ),
            ));
        }
    }
    d.rows.push(row(
        "",
        "ruf",
        tag(&t, "ruf")
            .filter(|v| !v.is_empty())
            .unwrap_or(t!("(non indicato)", "(not specified)")),
        t!(
            "rapporti sui singoli messaggi",
            "reports on individual messages"
        ),
    ));
    let al = |k: &str| match tag(&t, k).map(str::to_ascii_lowercase).as_deref() {
        Some("s") => "s",
        _ => "r",
    };
    let (adkim, aspf) = (al("adkim"), al("aspf"));
    d.rows.push(row(
        "",
        "adkim / aspf",
        format!("{adkim} / {aspf}"),
        if adkim == "r" && aspf == "r" {
            t!(
                "allineamento rilassato: vale anche un sottodominio",
                "relaxed alignment: a subdomain is also accepted"
            )
        } else {
            t!(
                "s = stretto: il dominio deve coincidere esattamente",
                "s = strict: the domain must match exactly"
            )
        },
    ));
    (d, out)
}

// ───────────────────────── DKIM ─────────────────────────

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct DkimKey {
    pub selector: String,
    /// "RSA 2048 bit", "Ed25519", "revocata" (revoked)…
    pub key: String,
    pub record: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// Decodes base64 (whitespace ignored); `None` if there are invalid characters.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u8);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A DER element: (tag, content, rest).
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, start) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let body = b.get(start..start + len)?;
    Some((tag, body, &b[start + len..]))
}

/// Modulus bits of an RSA key in SubjectPublicKeyInfo format (the one DKIM uses).
pub fn rsa_bits(spki: &[u8]) -> Option<usize> {
    let (0x30, seq, _) = der(spki)? else {
        return None;
    };
    let (0x30, _alg, rest) = der(seq)? else {
        return None;
    };
    let (0x03, bits, _) = der(rest)? else {
        return None;
    };
    // BIT STRING: first byte = unused bits, then RSAPublicKey
    let (0x30, key, _) = der(bits.get(1..)?)? else {
        return None;
    };
    let (0x02, modulus, _) = der(key)? else {
        return None;
    };
    let m = &modulus[modulus.iter().position(|b| *b != 0)?..];
    Some(m.len() * 8 - m[0].leading_zeros() as usize)
}

/// Reads the TXT record of a selector.
pub fn dkim_key(selector: &str, record: &str) -> DkimKey {
    let t = tags(record);
    let kind = tag(&t, "k").unwrap_or("rsa").to_ascii_lowercase();
    let p = tag(&t, "p").unwrap_or("");
    let testing = tag(&t, "t").is_some_and(|v| v.split(':').any(|f| f.trim() == "y"));
    let mut k = DkimKey {
        selector: selector.to_string(),
        key: String::new(),
        record: record.to_string(),
        status: OK,
        note: String::new(),
    };
    if p.is_empty() {
        k.key = t!("revocata", "revoked").into();
        k.status = WARN;
        k.note = t!(
            "p vuoto: la chiave è stata revocata, le firme con questo selettore non valgono",
            "p is empty: the key has been revoked, signatures with this selector are not valid"
        )
        .into();
    } else if kind == "ed25519" {
        k.key = "Ed25519".into();
    } else if kind == "rsa" {
        match b64_decode(p).as_deref().and_then(rsa_bits) {
            Some(bits) => {
                k.key = format!("RSA {bits} bit");
                if bits < 1024 {
                    k.status = ERR;
                    k.note = t!(
                        "chiave troppo corta: i destinatari ignorano la firma",
                        "key too short: recipients ignore the signature"
                    )
                    .into();
                } else if bits < 2048 {
                    k.status = WARN;
                    k.note = t!("chiave corta: usare 2048 bit", "short key: use 2048 bits").into();
                }
            }
            None => {
                k.key = t!("RSA, chiave non leggibile", "RSA, unreadable key").into();
                k.status = ERR;
                k.note = t!(
                    "il valore di p non è una chiave valida",
                    "the value of p is not a valid key"
                )
                .into();
            }
        }
    } else {
        k.key = kind;
        k.status = WARN;
        k.note = t!("tipo di chiave non riconosciuto", "key type not recognised").into();
    }
    if testing && k.status == OK {
        k.status = WARN;
        k.note = t!(
            "t=y: selettore in prova, i destinatari possono ignorare le firme",
            "t=y: selector in testing, recipients may ignore the signatures"
        )
        .into();
    }
    k
}

/// Checks on the selectors. `asked`: selectors requested by the user (empty = common list).
pub fn dkim_checks(keys: &[DkimKey], asked: &[String]) -> Vec<Check> {
    const A: &str = "DKIM";
    let mut out = Vec::new();
    for s in asked {
        if !keys.iter().any(|k| &k.selector == s) {
            out.push(check(
                A,
                ERR,
                s,
                t!(
                    "nessun record per questo selettore",
                    "no record for this selector"
                ),
            ));
        }
    }
    if keys.is_empty() && asked.is_empty() {
        out.push(check(
            A,
            INFO,
            t!("Selettori", "Selectors"),
            t!(
                "nessuno dei nomi più comuni: il selettore vero può avere un altro nome (si legge dagli header di un messaggio)",
                "none of the most common names: the real selector may have another name (it can be read from a message's headers)"
            ),
        ));
    }
    for k in keys {
        let detail = if k.note.is_empty() {
            tf!("chiave {}", "key {}", k.key)
        } else {
            format!("{}: {}", k.key, k.note)
        };
        out.push(check(A, k.status, &k.selector, detail));
    }
    out
}

// ───────────────────────── MTA-STS and TLS-RPT ─────────────────────────

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct MtaSts {
    /// The `_mta-sts` TXT record exists.
    pub found: bool,
    /// "enforce", "testing", "none" or empty if the policy was not read
    pub mode: String,
    pub rows: Vec<Row>,
    /// Address the policy was read from.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub url: String,
}

/// The MX name is covered by a policy pattern (`*.example.com` matches a single
/// label).
pub fn mx_covered(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    match p.strip_prefix("*.") {
        Some(rest) => h
            .split_once('.')
            .is_some_and(|(first, tail)| !first.is_empty() && tail == rest),
        None => p == h,
    }
}

/// `txt` = records of `_mta-sts.domain`; `policy` = text downloaded over HTTPS (or the reason
/// it was not possible); `mx` = the domain's MX servers.
pub fn mta_sts(
    txt: &[String],
    policy: Option<&std::result::Result<String, String>>,
    mx: &[String],
    domain: &str,
) -> (MtaSts, Vec<Check>) {
    const A: &str = "MTA-STS";
    let mut m = MtaSts::default();
    let mut out = Vec::new();
    let Some(rec) = txt
        .iter()
        .find(|t| t.trim().to_ascii_lowercase().starts_with("v=stsv1"))
    else {
        out.push(check(
            A,
            INFO,
            "Record",
            t!(
                "assente: il TLS verso il dominio resta facoltativo",
                "missing: TLS towards the domain remains optional"
            ),
        ));
        return (m, out);
    };
    m.found = true;
    let id = tags(rec)
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    m.rows.push(row(
        if id.is_empty() { WARN } else { OK },
        "Record",
        format!("_mta-sts.{domain}"),
        rec.trim().to_string(),
    ));
    m.url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let text = match policy {
        Some(Ok(t)) => t,
        Some(Err(e)) => {
            m.rows
                .push(row(ERR, "Policy", t!("non letta", "not read"), e.clone()));
            out.push(check(
                A,
                ERR,
                "Policy",
                tf!(
                    "il record c'è ma la policy non si scarica ({e}): MTA-STS non è attivo",
                    "the record exists but the policy cannot be downloaded ({e}): MTA-STS is not active"
                ),
            ));
            return (m, out);
        }
        None => return (m, out),
    };
    let mut mode = String::new();
    let mut max_age = None;
    let mut patterns = Vec::new();
    let mut version = false;
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "version" => version = v.eq_ignore_ascii_case("STSv1"),
            "mode" => mode = v.to_ascii_lowercase(),
            "mx" => patterns.push(v.to_string()),
            "max_age" => max_age = v.parse::<u64>().ok(),
            _ => {}
        }
    }
    m.mode = mode.clone();
    if !version {
        m.rows.push(row(
            ERR,
            "version",
            t!("(mancante)", "(missing)"),
            t!(
                "la policy deve iniziare con version: STSv1",
                "the policy must start with version: STSv1"
            ),
        ));
        out.push(check(
            A,
            ERR,
            "Policy",
            t!(
                "manca \"version: STSv1\": la policy non è valida",
                "\"version: STSv1\" is missing: the policy is not valid"
            ),
        ));
    }
    match mode.as_str() {
        "enforce" => {
            m.rows.push(row(
                OK,
                "mode",
                "enforce",
                t!(
                    "chi non offre TLS valido viene rifiutato",
                    "whoever does not offer valid TLS is rejected"
                ),
            ));
            out.push(check(
                A,
                OK,
                "Policy",
                t!(
                    "mode=enforce: consegna solo con TLS valido",
                    "mode=enforce: delivery only with valid TLS"
                ),
            ));
        }
        "testing" => {
            m.rows.push(row(
                WARN,
                "mode",
                "testing",
                t!(
                    "solo rapporti: nessun rifiuto",
                    "reports only: no rejection"
                ),
            ));
            out.push(check(
                A,
                WARN,
                "Policy",
                t!(
                    "mode=testing: i server senza TLS valido non vengono rifiutati",
                    "mode=testing: servers without valid TLS are not rejected"
                ),
            ));
        }
        "none" => {
            m.rows.push(row(
                INFO,
                "mode",
                "none",
                t!("policy disattivata", "policy disabled"),
            ));
            out.push(check(
                A,
                INFO,
                "Policy",
                t!(
                    "mode=none: MTA-STS dichiarato ma disattivato",
                    "mode=none: MTA-STS declared but disabled"
                ),
            ));
        }
        other => {
            m.rows.push(row(
                ERR,
                "mode",
                if other.is_empty() {
                    t!("(mancante)", "(missing)")
                } else {
                    other
                },
                t!("valore non valido", "invalid value"),
            ));
            out.push(check(
                A,
                ERR,
                "Policy",
                t!("mode mancante o non valido", "mode missing or invalid"),
            ));
        }
    }
    let missing: Vec<&String> = mx
        .iter()
        .filter(|h| !patterns.iter().any(|p| mx_covered(p, h)))
        .collect();
    if patterns.is_empty() && mode != "none" {
        m.rows.push(row(
            ERR,
            "mx",
            t!("(nessuno)", "(none)"),
            t!("la policy non elenca server", "the policy lists no servers"),
        ));
        out.push(check(
            A,
            ERR,
            "Server",
            t!("la policy non elenca nessun mx", "the policy lists no mx"),
        ));
    } else if !patterns.is_empty() {
        let ok = missing.is_empty();
        m.rows.push(row(
            if ok { OK } else { ERR },
            "mx",
            patterns.join(", "),
            if ok {
                t!(
                    "copre tutti gli MX del dominio",
                    "covers all the domain's MXs"
                )
                .to_string()
            } else {
                tf!(
                    "non copre {}",
                    "does not cover {}",
                    missing
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        ));
        if ok {
            out.push(check(
                A,
                OK,
                "Server",
                t!(
                    "la policy copre tutti gli MX del dominio",
                    "the policy covers all the domain's MXs"
                ),
            ));
        } else {
            out.push(check(
                A,
                ERR,
                "Server",
                tf!(
                    "MX non coperti dalla policy: {} (con enforce la posta verso questi server viene respinta)",
                    "MXs not covered by the policy: {} (with enforce, mail to these servers is rejected)",
                    missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    match max_age {
        Some(a) => {
            let days = a / 86_400;
            let short = a < 86_400;
            m.rows.push(row(
                if short { WARN } else { "" },
                "max_age",
                a.to_string(),
                if days >= 1 {
                    tf!("{days} giorni", "{days} days")
                } else {
                    t!("meno di un giorno", "less than a day").to_string()
                },
            ));
            if short {
                out.push(check(
                    A,
                    WARN,
                    t!("Durata", "Duration"),
                    tf!(
                        "max_age={a}: meno di un giorno, la policy protegge poco",
                        "max_age={a}: less than a day, the policy protects little"
                    ),
                ));
            }
        }
        None => {
            m.rows.push(row(
                ERR,
                "max_age",
                t!("(mancante)", "(missing)"),
                t!("obbligatorio", "mandatory"),
            ));
            out.push(check(
                A,
                ERR,
                t!("Durata", "Duration"),
                t!("manca max_age", "max_age is missing"),
            ));
        }
    }
    (m, out)
}

/// TLS-RPT (`_smtp._tls`): row for the tab and check.
pub fn tls_rpt(txt: &[String], domain: &str) -> (Option<Row>, Check) {
    const A: &str = "TLS-RPT";
    match txt
        .iter()
        .find(|t| t.trim().to_ascii_lowercase().starts_with("v=tlsrptv1"))
    {
        Some(rec) => {
            let rua = tags(rec)
                .iter()
                .find(|(k, _)| k == "rua")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let ok = !rua.is_empty();
            (
                Some(row(
                    if ok { OK } else { WARN },
                    "TLS-RPT",
                    format!("_smtp._tls.{domain}"),
                    rec.trim().to_string(),
                )),
                if ok {
                    check(
                        A,
                        INFO,
                        t!("Rapporti", "Reports"),
                        tf!("inviati a {rua}", "sent to {rua}"),
                    )
                } else {
                    check(
                        A,
                        WARN,
                        t!("Rapporti", "Reports"),
                        t!(
                            "record senza rua: nessuno riceve i rapporti",
                            "record without rua: nobody receives the reports"
                        ),
                    )
                },
            )
        }
        None => (
            None,
            check(
                A,
                INFO,
                t!("Rapporti", "Reports"),
                t!(
                    "assente: nessun rapporto sui problemi di TLS",
                    "missing: no reports on TLS problems"
                ),
            ),
        ),
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

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dmarc_letto() {
        let (d, c) = dmarc(
            &v(&[
                "altro",
                "v=DMARC1; p=none; rua=mailto:dmarc@example.com, mailto:rep@terzi.example.net!10m",
            ]),
            "_dmarc.example.com",
            "example.com",
        );
        assert!(d.found);
        assert_eq!(d.policy, "none");
        assert_eq!(find(&c, "Policy").status, WARN);
        assert_eq!(find(&c, "Rapporti").status, OK);
        assert_eq!(d.external, vec!["terzi.example.net"]);
        let names: Vec<&str> = d.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["p", "sp", "pct", "rua", "ruf", "adkim / aspf"]);
        assert_eq!(d.rows[1].detail, "i sottodomini ereditano p=none");
        assert_eq!(d.rows[5].value, "r / r");

        let (d, c) = dmarc(
            &v(&["v=DMARC1;p=reject;sp=none;pct=25;adkim=s"]),
            "_dmarc.example.com",
            "example.com",
        );
        assert_eq!(d.policy, "reject");
        assert_eq!(find(&c, "Policy").status, OK);
        assert_eq!(find(&c, "Sottodomini").status, WARN);
        assert!(find(&c, "Percentuale").detail.contains("25%"));
        assert_eq!(find(&c, "Rapporti").status, WARN);
        assert_eq!(d.rows[5].value, "s / r");
        assert!(d.external.is_empty());

        let (d, c) = dmarc(&[], "_dmarc.example.com", "example.com");
        assert!(!d.found && c.len() == 1 && c[0].status == ERR);
        let (_, c) = dmarc(
            &v(&["v=DMARC1; p=boh", "v=DMARC1; p=none"]),
            "x",
            "example.com",
        );
        assert!(find(&c, "Record").detail.starts_with("2 record"));
        assert_eq!(find(&c, "Policy").status, ERR);
        let (d, _) = dmarc(
            &v(&["v=DMARC1; p=quarantine; rua=mailto:a@sub.example.com"]),
            "x",
            "example.com",
        );
        assert!(d.external.is_empty() && d.rows[0].status == OK);
    }

    /// RSA SubjectPublicKeyInfo with a modulus of `bytes` bytes (first byte 0x80 if `full`).
    fn spki(bytes: usize, first: u8) -> Vec<u8> {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            let n = body.len();
            if n < 0x80 {
                out.push(n as u8);
            } else if n < 0x100 {
                out.extend_from_slice(&[0x81, n as u8]);
            } else {
                out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
            }
            out.extend_from_slice(body);
            out
        }
        let mut modulus = vec![0u8, first];
        modulus.extend(std::iter::repeat_n(0x55, bytes - 1));
        let key = tlv(0x30, &[tlv(0x02, &modulus), tlv(0x02, &[1, 0, 1])].concat());
        let mut bits = vec![0u8];
        bits.extend_from_slice(&key);
        let alg = tlv(
            0x30,
            &[6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1, 5, 0],
        );
        tlv(0x30, &[alg, tlv(0x03, &bits)].concat())
    }

    fn b64(data: &[u8]) -> String {
        crate::dns::rdata::base64(data)
    }

    #[test]
    fn chiavi_dkim() {
        assert_eq!(rsa_bits(&spki(256, 0xc1)), Some(2048));
        assert_eq!(rsa_bits(&spki(128, 0x80)), Some(1024));
        assert_eq!(rsa_bits(&spki(128, 0x01)), Some(1017));
        assert_eq!(rsa_bits(&[0x30, 3, 1, 2, 3]), None);
        assert_eq!(b64_decode("Zm9v YmE="), Some(b"fooba".to_vec()));
        assert_eq!(b64_decode("Zm9v!"), None);

        let k = dkim_key(
            "selector1",
            &format!("v=DKIM1; k=rsa; p={}", b64(&spki(256, 0xc1))),
        );
        assert_eq!((k.key.as_str(), k.status), ("RSA 2048 bit", OK));
        let k1024 = dkim_key(
            "selector2",
            &format!("v=DKIM1; p={}", b64(&spki(128, 0x90))),
        );
        assert_eq!((k1024.key.as_str(), k1024.status), ("RSA 1024 bit", WARN));
        let k512 = dkim_key("old", &format!("p={}", b64(&spki(64, 0x90))));
        assert_eq!(k512.status, ERR);
        let ed = dkim_key(
            "ed",
            "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
        );
        assert_eq!((ed.key.as_str(), ed.status), ("Ed25519", OK));
        let rev = dkim_key("via", "v=DKIM1; p=");
        assert_eq!((rev.key.as_str(), rev.status), ("revocata", WARN));
        assert_eq!(dkim_key("x", "v=DKIM1; p=!!!").status, ERR);
        let test = dkim_key("t", &format!("v=DKIM1; t=y:s; p={}", b64(&spki(256, 0xc1))));
        assert!(test.status == WARN && test.note.contains("in prova"));

        let c = dkim_checks(&[k.clone(), k1024], &[]);
        assert_eq!(find(&c, "selector1").detail, "chiave RSA 2048 bit");
        assert!(find(&c, "selector2")
            .detail
            .starts_with("RSA 1024 bit: chiave corta"));
        let c = dkim_checks(&[k], &v(&["selector1", "mio"]));
        assert_eq!(find(&c, "mio").status, ERR);
        assert_eq!(c.len(), 2);
        let c = dkim_checks(&[], &[]);
        assert_eq!((c.len(), c[0].status), (1, INFO));
    }

    const POLICY: &str = "version: STSv1\r\nmode: testing\r\nmx: mail1.example.com\r\nmx: *.mx.example.com\r\nmax_age: 604800\r\n";

    #[test]
    fn mta_sts_e_tls_rpt() {
        assert!(mx_covered("*.mx.example.com", "a.mx.example.com."));
        assert!(!mx_covered("*.mx.example.com", "a.b.mx.example.com"));
        assert!(!mx_covered("*.mx.example.com", "mx.example.com"));
        assert!(mx_covered("Mail1.Example.com", "mail1.example.com"));

        let txt = v(&["v=STSv1; id=20261102T101500"]);
        let mx = v(&["mail1.example.com", "a.mx.example.com"]);
        let (m, c) = mta_sts(&txt, Some(&Ok(POLICY.to_string())), &mx, "example.com");
        assert!(m.found);
        assert_eq!(m.mode, "testing");
        assert_eq!(m.url, "https://mta-sts.example.com/.well-known/mta-sts.txt");
        assert_eq!(find(&c, "Policy").status, WARN);
        assert_eq!(find(&c, "Server").status, OK);
        let names: Vec<&str> = m.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["Record", "mode", "mx", "max_age"]);
        assert_eq!(m.rows[3].detail, "7 giorni");

        // an MX outside the policy, enforce, short duration
        let p = POLICY
            .replace("testing", "enforce")
            .replace("604800", "3600");
        let mx2 = v(&["mail1.example.com", "mail9.example.org"]);
        let (m, c) = mta_sts(&txt, Some(&Ok(p)), &mx2, "example.com");
        assert_eq!(find(&c, "Policy").status, OK);
        let s = find(&c, "Server");
        assert!(s.status == ERR && s.detail.contains("mail9.example.org"));
        assert_eq!(find(&c, "Durata").status, WARN);
        assert_eq!(m.rows[2].status, ERR);

        // record present, policy not downloadable; record missing; policy without version
        let (m, c) = mta_sts(&txt, Some(&Err("HTTP 404".into())), &mx, "example.com");
        assert!(m.found && m.mode.is_empty());
        assert!(find(&c, "Policy").detail.contains("HTTP 404"));
        let (m, c) = mta_sts(&[], None, &mx, "example.com");
        assert!(!m.found && c[0].status == INFO);
        let (_, c) = mta_sts(
            &txt,
            Some(&Ok("mode: enforce\nmx: mail1.example.com\n".into())),
            &mx[..1],
            "example.com",
        );
        assert!(c.iter().any(|x| x.detail.contains("version: STSv1")));
        assert!(c.iter().any(|x| x.name == "Durata" && x.status == ERR));

        let (r, c) = tls_rpt(
            &v(&["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"]),
            "example.com",
        );
        assert_eq!(r.unwrap().value, "_smtp._tls.example.com");
        assert_eq!(c.detail, "inviati a mailto:tlsrpt@example.com");
        let (r, c) = tls_rpt(&[], "example.com");
        assert!(r.is_none() && c.status == INFO);
        assert_eq!(
            tags("v=DMARC1; P = none ;; rua=mailto:a@b"),
            vec![
                ("v".into(), "DMARC1".into()),
                ("p".into(), "none".into()),
                ("rua".into(), "mailto:a@b".into())
            ]
        );
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let (_, c) = dmarc(&v(&["v=DMARC1; p=none"]), "x", "example.com");
        assert!(find(&c, "Policy")
            .detail
            .starts_with("p=none: messages that fail"));
        assert!(find(&c, "Reports").detail.starts_with("rua is missing"));
        assert!(!c.iter().any(|x| x.name == "Rapporti"));
        let k = dkim_key("old", "v=DKIM1; p=");
        assert_eq!(k.key, "revoked");
        assert!(k.note.starts_with("p is empty"));
        let (_, c) = tls_rpt(&[], "example.com");
        assert_eq!(c.name, "Reports");
    }
}
