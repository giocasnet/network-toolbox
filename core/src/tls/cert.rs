//! Analysis of a certificate and of the chain presented by a server. Pure functions
//! only: no connection, tested with hand-built certificates.

use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::{t, tf, util};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

fn area_cert() -> &'static str {
    t!("Certificato", "Certificate")
}
fn area_chain() -> &'static str {
    t!("Catena", "Chain")
}
fn area_rev() -> &'static str {
    t!("Revoca", "Revocation")
}

/// Maximum lifetime accepted by browsers for public CA certificates.
pub const MAX_PUBLIC_DAYS: i64 = 398;

/// Everything that can be read from a certificate.
#[derive(Debug, Serialize, Default, Clone, PartialEq)]
pub struct CertDetails {
    /// Short name: common name, or the full subject if missing.
    pub name: String,
    pub issuer_name: String,
    /// Full subject and issuer (DN).
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub lifetime_days: i64,
    pub expired: bool,
    pub not_yet_valid: bool,
    /// "RSA 2048 bit", "ECDSA P-256", "Ed25519"
    pub key: String,
    /// "SHA-256 con RSA" (localised)
    pub signature: String,
    /// Extended key usages, localised; empty = no restriction.
    pub usage: Vec<String>,
    pub serial: String,
    pub sha256: String,
    pub sha1: String,
    pub sans: Vec<String>,
    pub ocsp: Vec<String>,
    pub crl: Vec<String>,
    /// Addresses to download the issuer certificate from (AIA).
    pub ca_issuers: Vec<String>,
    /// Embedded Signed Certificate Timestamps (Certificate Transparency).
    pub sct: usize,
    pub self_signed: bool,
    pub is_ca: bool,
    #[serde(skip)]
    pub key_bits: usize,
    #[serde(skip)]
    pub key_rsa: bool,
    /// Signature with SHA-1 or MD5.
    #[serde(skip)]
    pub weak_signature: bool,
    /// The extended key usage extension is present and does not include server authentication.
    #[serde(skip)]
    pub no_server_auth: bool,
}

fn hex_colon(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn short_name(n: &X509Name<'_>) -> String {
    n.iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| n.to_string())
}

/// Signature algorithm from its OID: readable name and "weak" flag (SHA-1, MD5).
fn signature_name(oid: &str) -> (String, bool) {
    let (name, weak) = match oid {
        "1.2.840.113549.1.1.4" => (t!("MD5 con RSA", "MD5 with RSA"), true),
        "1.2.840.113549.1.1.5" => (t!("SHA-1 con RSA", "SHA-1 with RSA"), true),
        "1.2.840.113549.1.1.11" => (t!("SHA-256 con RSA", "SHA-256 with RSA"), false),
        "1.2.840.113549.1.1.12" => (t!("SHA-384 con RSA", "SHA-384 with RSA"), false),
        "1.2.840.113549.1.1.13" => (t!("SHA-512 con RSA", "SHA-512 with RSA"), false),
        "1.2.840.113549.1.1.10" => ("RSA-PSS", false),
        "1.2.840.10045.4.1" => (t!("SHA-1 con ECDSA", "SHA-1 with ECDSA"), true),
        "1.2.840.10045.4.3.2" => (t!("SHA-256 con ECDSA", "SHA-256 with ECDSA"), false),
        "1.2.840.10045.4.3.3" => (t!("SHA-384 con ECDSA", "SHA-384 with ECDSA"), false),
        "1.2.840.10045.4.3.4" => (t!("SHA-512 con ECDSA", "SHA-512 with ECDSA"), false),
        "1.3.101.112" => ("Ed25519", false),
        "1.3.101.113" => ("Ed448", false),
        other => return (other.to_string(), false),
    };
    (name.to_string(), weak)
}

/// Public key: description, bits, is RSA.
fn key_name(spki: &SubjectPublicKeyInfo<'_>) -> (String, usize, bool) {
    let alg = spki.algorithm.algorithm.to_id_string();
    match alg.as_str() {
        "1.2.840.113549.1.1.1" => {
            let bits = match spki.parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(r)) => r.key_size(),
                _ => 0,
            };
            if bits == 0 {
                ("RSA".into(), 0, true)
            } else {
                (format!("RSA {bits} bit"), bits, true)
            }
        }
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            let (name, bits) = match curve.as_str() {
                "1.2.840.10045.3.1.7" => ("ECDSA P-256", 256),
                "1.3.132.0.34" => ("ECDSA P-384", 384),
                "1.3.132.0.35" => ("ECDSA P-521", 521),
                _ => ("ECDSA", 0),
            };
            (name.into(), bits, false)
        }
        "1.3.101.112" => ("Ed25519".into(), 256, false),
        "1.3.101.113" => ("Ed448".into(), 448, false),
        "1.2.840.10040.4.1" => ("DSA".into(), 0, false),
        other => (other.to_string(), 0, false),
    }
}

fn general_names(names: &[GeneralName<'_>], out: &mut Vec<String>) {
    for g in names {
        match g {
            GeneralName::DNSName(d) => out.push(format!("DNS: {d}")),
            GeneralName::IPAddress(b) if b.len() == 4 => {
                out.push(format!("IP: {}.{}.{}.{}", b[0], b[1], b[2], b[3]))
            }
            GeneralName::IPAddress(b) if b.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                out.push(format!("IP: {}", std::net::Ipv6Addr::from(a)));
            }
            _ => {}
        }
    }
}

/// Reads a certificate (DER). `now` in Unix seconds.
pub fn details(der: &[u8], now: i64) -> crate::Result<CertDetails> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
        tf!(
            "Certificato non leggibile: {e}",
            "Unreadable certificate: {e}"
        )
    })?;
    let nb = cert.validity().not_before.timestamp();
    let na = cert.validity().not_after.timestamp();
    let (key, key_bits, key_rsa) = key_name(cert.public_key());
    let (signature, weak_signature) =
        signature_name(&cert.signature_algorithm.algorithm.to_id_string());

    let mut d = CertDetails {
        name: short_name(cert.subject()),
        issuer_name: short_name(cert.issuer()),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: util::iso(nb),
        not_after: util::iso(na),
        days_remaining: (na - now).div_euclid(86_400),
        // a "90-day" certificate lasts 90 days minus one second
        lifetime_days: (na - nb + 86_399).div_euclid(86_400),
        expired: na < now,
        not_yet_valid: nb > now,
        key,
        signature,
        serial: cert.raw_serial_as_string().replace(':', "").to_uppercase(),
        sha256: hex_colon(&Sha256::digest(der)),
        sha1: hex_colon(&Sha1::digest(der)),
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
        is_ca: cert.is_ca(),
        key_bits,
        key_rsa,
        weak_signature,
        ..Default::default()
    };

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                general_names(&san.general_names, &mut d.sans)
            }
            ParsedExtension::ExtendedKeyUsage(u) => {
                for (on, label) in [
                    (u.any, t!("Qualsiasi uso", "Any usage")),
                    (
                        u.server_auth,
                        t!("Autenticazione server", "Server authentication"),
                    ),
                    (
                        u.client_auth,
                        t!("Autenticazione client", "Client authentication"),
                    ),
                    (u.code_signing, t!("Firma del codice", "Code signing")),
                    (
                        u.email_protection,
                        t!("Protezione della posta", "Email protection"),
                    ),
                    (u.time_stamping, t!("Marca temporale", "Time stamping")),
                    (u.ocsp_signing, t!("Firma OCSP", "OCSP signing")),
                ] {
                    if on {
                        d.usage.push(label.to_string());
                    }
                }
                if !u.other.is_empty() {
                    d.usage.push(tf!("altri {}", "{} others", u.other.len()));
                }
                d.no_server_auth = !u.any && !u.server_auth;
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for a in &aia.accessdescs {
                    if let GeneralName::URI(u) = &a.access_location {
                        match a.access_method.to_id_string().as_str() {
                            "1.3.6.1.5.5.7.48.1" => d.ocsp.push(u.to_string()),
                            "1.3.6.1.5.5.7.48.2" => d.ca_issuers.push(u.to_string()),
                            _ => {}
                        }
                    }
                }
            }
            ParsedExtension::CRLDistributionPoints(c) => {
                for p in &c.points {
                    if let Some(DistributionPointName::FullName(names)) = &p.distribution_point {
                        for g in names {
                            if let GeneralName::URI(u) = g {
                                d.crl.push(u.to_string());
                            }
                        }
                    }
                }
            }
            ParsedExtension::SCT(list) => d.sct = list.len(),
            _ => {}
        }
    }
    Ok(d)
}

/// Is the name (or address) covered by the alternative names? Browsers no longer look at
/// the common name. The wildcard matches a single label, the first one.
pub fn covers(sans: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return sans.iter().any(|s| {
            s.strip_prefix("IP: ")
                .and_then(|x| x.parse::<std::net::IpAddr>().ok())
                == Some(ip)
        });
    }
    sans.iter()
        .filter_map(|s| s.strip_prefix("DNS: "))
        .any(|pat| {
            let pat = pat.trim_end_matches('.').to_ascii_lowercase();
            if pat == host {
                return true;
            }
            match (pat.strip_prefix("*."), host.split_once('.')) {
                (Some(rest), Some((first, tail))) => !first.is_empty() && rest == tail,
                _ => false,
            }
        })
}

fn days_text(n: i64) -> String {
    if n == 1 {
        t!("1 giorno", "1 day").into()
    } else {
        tf!("{n} giorni", "{n} days")
    }
}

/// Checks on the server certificate. `name` is the verified name (SNI or host);
/// `verify_error` is empty if the chain is trusted by this PC.
pub fn leaf_checks(d: &CertDetails, name: &str, verify_error: &str) -> Vec<Check> {
    let mut out = Vec::new();
    if verify_error.is_empty() {
        out.push(check(
            area_cert(),
            OK,
            t!("Attendibilità", "Trust"),
            t!(
                "catena verificata con l'archivio dei certificati di questo PC",
                "chain verified with this PC's certificate store"
            ),
        ));
    } else {
        out.push(check(
            area_cert(),
            ERR,
            t!("Attendibilità", "Trust"),
            verify_error,
        ));
    }

    let date = d.not_after.split('T').next().unwrap_or_default();
    if d.not_yet_valid {
        out.push(check(
            area_cert(),
            ERR,
            t!("Validità", "Validity"),
            tf!(
                "non ancora valido: inizia il {}",
                "not yet valid: starts on {}",
                d.not_before.split('T').next().unwrap_or_default()
            ),
        ));
    }
    if d.expired {
        out.push(check(
            area_cert(),
            ERR,
            t!("Scadenza", "Expiry"),
            tf!(
                "scaduto da {} ({date})",
                "expired {} ago ({date})",
                days_text(-d.days_remaining)
            ),
        ));
    } else {
        let st = if d.days_remaining <= 30 { WARN } else { OK };
        out.push(check(
            area_cert(),
            st,
            t!("Scadenza", "Expiry"),
            tf!(
                "tra {} ({date})",
                "in {} ({date})",
                days_text(d.days_remaining)
            ),
        ));
    }

    if covers(&d.sans, name) {
        out.push(check(
            area_cert(),
            OK,
            t!("Nome", "Name"),
            tf!(
                "{name} coperto dai nomi alternativi",
                "{name} covered by the alternative names"
            ),
        ));
    } else if d.sans.is_empty() {
        out.push(check(
            area_cert(),
            ERR,
            t!("Nome", "Name"),
            t!(
                "nessun nome alternativo: i client moderni non guardano il common name",
                "no alternative names: modern clients do not look at the common name"
            ),
        ));
    } else {
        out.push(check(
            area_cert(),
            ERR,
            t!("Nome", "Name"),
            tf!(
                "{name} non è tra i nomi coperti",
                "{name} is not among the covered names"
            ),
        ));
    }

    let key_st = if d.key_rsa && d.key_bits > 0 && d.key_bits < 2048 {
        ERR
    } else {
        OK
    };
    let key_detail = if key_st == ERR {
        tf!(
            "{}: troppo corta, servono almeno 2048 bit",
            "{}: too short, at least 2048 bits are required",
            d.key
        )
    } else {
        d.key.clone()
    };
    out.push(check(area_cert(), key_st, t!("Chiave", "Key"), key_detail));

    if d.weak_signature && !d.self_signed {
        out.push(check(
            area_cert(),
            ERR,
            t!("Firma", "Signature"),
            tf!(
                "{}: algoritmo non più accettato",
                "{}: algorithm no longer accepted",
                d.signature
            ),
        ));
    } else {
        out.push(check(
            area_cert(),
            OK,
            t!("Firma", "Signature"),
            d.signature.clone(),
        ));
    }

    if d.lifetime_days > MAX_PUBLIC_DAYS {
        out.push(check(
            area_cert(),
            INFO,
            t!("Durata", "Lifetime"),
            tf!(
                "{}: oltre i {MAX_PUBLIC_DAYS} ammessi dai browser per le CA pubbliche \
                 (non vale per le CA interne)",
                "{}: over the {MAX_PUBLIC_DAYS} allowed by browsers for public CAs \
                 (does not apply to internal CAs)",
                days_text(d.lifetime_days)
            ),
        ));
    } else {
        out.push(check(
            area_cert(),
            OK,
            t!("Durata", "Lifetime"),
            days_text(d.lifetime_days),
        ));
    }

    if d.no_server_auth {
        out.push(check(
            area_cert(),
            WARN,
            t!("Uso", "Usage"),
            tf!(
                "non comprende l'autenticazione del server ({})",
                "does not include server authentication ({})",
                d.usage.join(", ")
            ),
        ));
    }

    out.push(match d.sct {
        0 => check(
            area_cert(),
            INFO,
            t!("Trasparenza", "Transparency"),
            t!(
                "nessun SCT nel certificato (normale per le CA interne)",
                "no SCT in the certificate (normal for internal CAs)"
            ),
        ),
        n => check(
            area_cert(),
            INFO,
            t!("Trasparenza", "Transparency"),
            tf!(
                "{n} SCT incorporati nel certificato",
                "{n} SCTs embedded in the certificate"
            ),
        ),
    });
    out
}

/// Revocation check: only reads what the server and the certificate declare.
/// `stapled`: `None` if the handshake was not completed (compatibility probe).
pub fn revocation_check(d: &CertDetails, stapled: Option<bool>) -> Check {
    let source = match (d.ocsp.is_empty(), d.crl.is_empty()) {
        (false, false) => t!(
            "il certificato indica un server OCSP e una CRL",
            "the certificate points to an OCSP server and a CRL"
        ),
        (false, true) => t!(
            "il certificato indica un server OCSP",
            "the certificate points to an OCSP server"
        ),
        (true, false) => t!(
            "il certificato indica una CRL",
            "the certificate points to a CRL"
        ),
        (true, true) => t!(
            "il certificato non indica né OCSP né CRL",
            "the certificate points to neither OCSP nor CRL"
        ),
    };
    match stapled {
        Some(true) => check(
            area_rev(),
            OK,
            "OCSP stapling",
            tf!(
                "risposta OCSP inviata dal server; {source}",
                "OCSP response sent by the server; {source}"
            ),
        ),
        Some(false) => check(
            area_rev(),
            INFO,
            "OCSP stapling",
            tf!("non inviato; {source}", "not sent; {source}"),
        ),
        None => check(area_rev(), INFO, t!("Revoca", "Revocation"), source),
    }
}

/// A certificate of the chain, from the server towards the root.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct ChainEntry {
    /// "Server", "Intermedia", "Radice", "Estraneo"
    pub role: &'static str,
    pub name: String,
    pub issuer_name: String,
    pub key: String,
    pub signature: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub expired: bool,
    pub self_signed: bool,
    /// "sent" = sent by the server, "missing" = not sent (retrieved by the PC),
    /// "store" = root in the PC store, "extra" = sent but outside the chain
    pub sent: &'static str,
    /// "ok", "warn", "err"
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// Lines up the certificates sent by following subject and issuer.
fn linearize(sent: &[(Vec<u8>, CertDetails)]) -> Vec<usize> {
    let mut path = vec![0usize];
    loop {
        let cur = &sent[*path.last().unwrap()].1;
        if cur.self_signed {
            break;
        }
        match (0..sent.len()).find(|i| !path.contains(i) && sent[*i].1.subject == cur.issuer) {
            Some(i) => path.push(i),
            None => break,
        }
    }
    path
}

/// Chain and related checks. `sent` = certificates in the order the server sent
/// them; `built` = chain built by the system (on Windows, root included), if
/// available; `verified` = verification outcome.
pub fn chain(
    sent: &[Vec<u8>],
    built: Option<&[Vec<u8>]>,
    verified: bool,
    now: i64,
) -> (Vec<ChainEntry>, Vec<Check>) {
    let parsed: Vec<(Vec<u8>, CertDetails)> = sent
        .iter()
        .filter_map(|d| details(d, now).ok().map(|c| (d.clone(), c)))
        .collect();
    if parsed.is_empty() {
        return (vec![], vec![]);
    }
    // (certificate, position among those sent)
    let mut path: Vec<(CertDetails, Option<usize>)> = Vec::new();
    match built.filter(|b| b.first() == sent.first() && !b.is_empty()) {
        Some(b) => {
            for der in b {
                let pos = parsed.iter().position(|(d, _)| d == der);
                match (pos, details(der, now)) {
                    (Some(i), _) => path.push((parsed[i].1.clone(), Some(i))),
                    (None, Ok(c)) => path.push((c, None)),
                    (None, Err(_)) => {}
                }
            }
        }
        None => {
            for i in linearize(&parsed) {
                path.push((parsed[i].1.clone(), Some(i)));
            }
        }
    }

    let mut entries = Vec::new();
    let mut checks = Vec::new();
    let mut missing = Vec::new();
    for (n, (c, pos)) in path.iter().enumerate() {
        let role = if n == 0 {
            t!("Server", "Server")
        } else if c.self_signed {
            t!("Radice", "Root")
        } else {
            t!("Intermedia", "Intermediate")
        };
        let sent_how = match pos {
            Some(_) => "sent",
            None if c.self_signed => "store",
            None => "missing",
        };
        let mut status = OK;
        let mut note = String::new();
        if sent_how == "missing" {
            status = ERR;
            note = t!(
                "Non inviata dal server: questo PC l'ha recuperata da solo.",
                "Not sent by the server: this PC retrieved it on its own."
            )
            .into();
            missing.push(c.name.clone());
        } else if c.expired {
            status = ERR;
            note = t!("Scaduto.", "Expired.").into();
            if n > 0 {
                checks.push(check(
                    area_chain(),
                    ERR,
                    t!("Scadenza", "Expiry"),
                    tf!(
                        "{} è scaduto il {}",
                        "{} expired on {}",
                        c.name,
                        &c.not_after[..10]
                    ),
                ));
            }
        } else if c.weak_signature && !c.self_signed && n > 0 {
            status = ERR;
            note = tf!(
                "Firma {}: non più accettata.",
                "Signature {}: no longer accepted.",
                c.signature
            );
            checks.push(check(
                area_chain(),
                ERR,
                t!("Firma", "Signature"),
                tf!(
                    "{} è firmato con {}",
                    "{} is signed with {}",
                    c.name,
                    c.signature
                ),
            ));
        } else if c.days_remaining <= 30 {
            status = WARN;
            if n > 0 {
                checks.push(check(
                    area_chain(),
                    WARN,
                    t!("Scadenza", "Expiry"),
                    tf!(
                        "{} scade tra {}",
                        "{} expires in {}",
                        c.name,
                        days_text(c.days_remaining)
                    ),
                ));
            }
        } else if n > 0 && c.self_signed && sent_how == "sent" && path.len() > 1 {
            note = t!(
                "Inviata dal server: non serve, i client usano la propria copia.",
                "Sent by the server: not needed, clients use their own copy."
            )
            .into();
        }
        entries.push(ChainEntry {
            role,
            name: c.name.clone(),
            issuer_name: c.issuer_name.clone(),
            key: c.key.clone(),
            signature: c.signature.clone(),
            not_after: c.not_after.clone(),
            days_remaining: c.days_remaining,
            expired: c.expired,
            self_signed: c.self_signed,
            sent: sent_how,
            status,
            note,
        });
    }

    // certificates sent that are not part of the chain
    let used: Vec<usize> = path.iter().filter_map(|(_, p)| *p).collect();
    let mut extra = Vec::new();
    for (i, (_, c)) in parsed.iter().enumerate() {
        if !used.contains(&i) {
            extra.push(c.name.clone());
            entries.push(ChainEntry {
                role: t!("Estraneo", "Extraneous"),
                name: c.name.clone(),
                issuer_name: c.issuer_name.clone(),
                key: c.key.clone(),
                signature: c.signature.clone(),
                not_after: c.not_after.clone(),
                days_remaining: c.days_remaining,
                expired: c.expired,
                self_signed: c.self_signed,
                sent: "extra",
                status: WARN,
                note: t!(
                    "Inviato dal server ma non fa parte della catena.",
                    "Sent by the server but not part of the chain."
                )
                .into(),
            });
        }
    }

    let mut clean = true;
    if !missing.is_empty() {
        clean = false;
        checks.push(check(
            area_chain(),
            ERR,
            t!("Certificato intermedio", "Intermediate certificate"),
            tf!(
                "non inviato dal server ({}): questo PC lo ha recuperato da solo, altri \
                 client rifiutano la connessione",
                "not sent by the server ({}): this PC retrieved it on its own, other \
                 clients refuse the connection",
                missing.join(", ")
            ),
        ));
    }
    let last = &path.last().unwrap().0;
    if built.is_none() && !verified && !last.self_signed && sent.len() == 1 {
        clean = false;
        checks.push(check(
            area_chain(),
            WARN,
            t!("Catena incompleta", "Incomplete chain"),
            tf!(
                "il server invia solo il proprio certificato, emesso da {}: se è una CA \
                 intermedia deve inviare anche quella",
                "the server sends only its own certificate, issued by {}: if that is an \
                 intermediate CA it must send it too",
                last.issuer_name
            ),
        ));
    }
    if used.windows(2).any(|w| w[0] > w[1]) || used.first() != Some(&0) {
        clean = false;
        checks.push(check(
            area_chain(),
            WARN,
            t!("Ordine", "Order"),
            t!(
                "i certificati non sono inviati nell'ordine corretto (server, poi le intermedie)",
                "the certificates are not sent in the correct order (server, then the intermediates)"
            ),
        ));
    }
    if !extra.is_empty() {
        clean = false;
        checks.push(check(
            area_chain(),
            WARN,
            t!("Certificati in più", "Extra certificates"),
            tf!(
                "inviati ma fuori dalla catena: {}",
                "sent but outside the chain: {}",
                extra.join(", ")
            ),
        ));
    }
    let root_sent = path.len() > 1
        && path
            .last()
            .is_some_and(|(c, p)| c.self_signed && p.is_some());
    if root_sent {
        checks.push(check(
            area_chain(),
            INFO,
            t!("Radice inviata", "Root sent"),
            t!(
                "il server invia anche la radice: non serve, i client usano la propria copia",
                "the server also sends the root: not needed, clients use their own copy"
            ),
        ));
    }
    if clean {
        let n = used.len();
        checks.push(check(
            area_chain(),
            OK,
            t!("Catena", "Chain"),
            if n == 1 {
                t!("1 certificato inviato", "1 certificate sent").to_string()
            } else {
                tf!(
                    "{n} certificati inviati, nell'ordine corretto",
                    "{n} certificates sent, in the correct order"
                )
            },
        ));
    }
    (entries, checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ca {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
    }

    fn ca(name: &str, parent: Option<&Ca>) -> Ca {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        let cert = match parent {
            Some(pa) => p.signed_by(&key, &pa.cert, &pa.key).unwrap(),
            None => p.self_signed(&key).unwrap(),
        };
        Ca { cert, key }
    }

    fn leaf(names: &[&str], days: i64, parent: &Ca) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p =
            rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "srv01.corp.example");
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let now = std::time::SystemTime::now();
        p.not_before = (now - std::time::Duration::from_secs(86_400)).into();
        p.not_after = (now + std::time::Duration::from_secs(days as u64 * 86_400)).into();
        p.signed_by(&key, &parent.cert, &parent.key)
            .unwrap()
            .der()
            .to_vec()
    }

    fn now() -> i64 {
        util::now_unix() as i64
    }

    fn find<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("manca il controllo {name}: {c:?}"))
    }

    #[test]
    fn dettagli_del_certificato() {
        let root = ca("Example Root CA", None);
        let der = leaf(
            &["srv01.corp.example", "192.0.2.10", "2001:db8::10"],
            90,
            &root,
        );
        let d = details(&der, now()).unwrap();
        assert_eq!(d.name, "srv01.corp.example");
        assert_eq!(d.issuer_name, "Example Root CA");
        assert_eq!(d.key, "ECDSA P-256");
        assert_eq!(d.signature, "SHA-256 con ECDSA");
        assert_eq!(d.usage, vec!["Autenticazione server"]);
        assert_eq!(
            d.sans,
            vec![
                "DNS: srv01.corp.example",
                "IP: 192.0.2.10",
                "IP: 2001:db8::10"
            ]
        );
        assert_eq!(d.lifetime_days, 91);
        assert!(
            (89..=90).contains(&d.days_remaining),
            "{}",
            d.days_remaining
        );
        assert!(!d.self_signed && !d.is_ca && !d.expired);
        // fingerprints: 32 and 20 bytes separated by colons
        assert_eq!(d.sha256.len(), 32 * 3 - 1);
        assert_eq!(d.sha1.len(), 20 * 3 - 1);
        assert!(d.sha256.chars().all(|c| c == ':' || c.is_ascii_hexdigit()));

        let r = details(root.cert.der(), now()).unwrap();
        assert!(r.self_signed && r.is_ca);
    }

    #[test]
    fn nomi_coperti() {
        let sans: Vec<String> = [
            "DNS: www.example.com",
            "DNS: *.cdn.example.com",
            "IP: 192.0.2.10",
            "IP: 2001:db8::10",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert!(covers(&sans, "www.example.com"));
        assert!(covers(&sans, "WWW.Example.COM."));
        assert!(covers(&sans, "a.cdn.example.com"));
        assert!(!covers(&sans, "a.b.cdn.example.com"));
        assert!(!covers(&sans, "cdn.example.com"));
        assert!(!covers(&sans, "example.com"));
        assert!(covers(&sans, "192.0.2.10"));
        assert!(covers(&sans, "2001:db8:0:0::10"));
        assert!(!covers(&sans, "192.0.2.11"));
    }

    #[test]
    fn controlli_del_certificato() {
        let root = ca("Example Root CA", None);
        let d = details(&leaf(&["srv01.corp.example"], 20, &root), now()).unwrap();
        let c = leaf_checks(&d, "srv01.corp.example", "");
        assert_eq!(find(&c, "Attendibilità").status, OK);
        assert_eq!(find(&c, "Scadenza").status, WARN);
        assert_eq!(find(&c, "Nome").status, OK);
        assert_eq!(find(&c, "Chiave").status, OK);
        assert_eq!(find(&c, "Firma").status, OK);
        assert_eq!(find(&c, "Durata").status, OK);
        assert_eq!(find(&c, "Trasparenza").status, INFO);
        assert!(!c.iter().any(|x| x.name == "Uso"));

        let d = details(&leaf(&["srv01.corp.example"], 800, &root), now()).unwrap();
        let c = leaf_checks(&d, "altro.corp.example", "Autorità non attendibile");
        assert_eq!(find(&c, "Attendibilità").status, ERR);
        assert_eq!(find(&c, "Scadenza").status, OK);
        assert_eq!(find(&c, "Nome").status, ERR);
        assert_eq!(find(&c, "Durata").status, INFO);

        // short RSA key, SHA-1 signature, usage without server authentication
        let weak = CertDetails {
            key: "RSA 1024 bit".into(),
            key_bits: 1024,
            key_rsa: true,
            signature: "SHA-1 con RSA".into(),
            weak_signature: true,
            no_server_auth: true,
            usage: vec!["Autenticazione client".into()],
            expired: true,
            days_remaining: -3,
            not_after: "2026-01-01T00:00:00".into(),
            ..Default::default()
        };
        let c = leaf_checks(&weak, "srv01", "");
        assert_eq!(find(&c, "Chiave").status, ERR);
        assert_eq!(find(&c, "Firma").status, ERR);
        assert_eq!(find(&c, "Uso").status, WARN);
        assert_eq!(find(&c, "Scadenza").status, ERR);
        assert!(find(&c, "Scadenza").detail.contains("3 giorni"));
        assert_eq!(find(&c, "Nome").status, ERR);
    }

    #[test]
    fn controlli_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let root = ca("Example Root CA", None);
        let d = details(&leaf(&["srv01.corp.example"], 20, &root), now()).unwrap();
        assert_eq!(d.signature, "SHA-256 with ECDSA");
        assert_eq!(d.usage, vec!["Server authentication"]);
        let c = leaf_checks(&d, "altro.corp.example", "");
        assert_eq!(find(&c, "Trust").status, OK);
        assert_eq!(find(&c, "Expiry").status, WARN);
        assert!(find(&c, "Name")
            .detail
            .contains("not among the covered names"));
        assert!(!c.iter().any(|x| x.name == "Nome" || x.name == "Scadenza"));
        let (l, i, r) = pki();
        let built = [l.clone(), i, r];
        let (e, c) = chain(std::slice::from_ref(&l), Some(&built), true, now());
        assert_eq!(
            (e[0].role, e[1].role, e[2].role),
            ("Server", "Intermediate", "Root")
        );
        assert_eq!(find(&c, "Intermediate certificate").status, ERR);
        assert!(e[1].note.starts_with("Not sent by the server"));
    }

    #[test]
    fn revoca() {
        let mut d = CertDetails::default();
        assert_eq!(revocation_check(&d, Some(false)).status, INFO);
        d.ocsp.push("http://ocsp.ca.example.net".into());
        let c = revocation_check(&d, Some(true));
        assert_eq!((c.status, c.name.as_str()), (OK, "OCSP stapling"));
        assert!(c.detail.contains("server OCSP"));
        assert_eq!(revocation_check(&d, None).name, "Revoca");
    }

    /// Complete chain: server, intermediate, root.
    fn pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = ca("Example Root CA", None);
        let inter = ca("Example Issuing CA", Some(&root));
        let l = leaf(&["srv01.corp.example"], 90, &inter);
        (l, inter.cert.der().to_vec(), root.cert.der().to_vec())
    }

    #[test]
    fn catena_corretta() {
        let (l, i, r) = pki();
        let (e, c) = chain(&[l.clone(), i.clone()], None, true, now());
        assert_eq!(
            e.iter().map(|x| (x.role, x.sent)).collect::<Vec<_>>(),
            vec![("Server", "sent"), ("Intermedia", "sent")]
        );
        assert_eq!(find(&c, "Catena").status, OK);
        assert!(find(&c, "Catena").detail.contains("2 certificati"));

        // with the system chain the root from the store appears
        let built = [l.clone(), i.clone(), r.clone()];
        let (e, c) = chain(&[l, i], Some(&built), true, now());
        assert_eq!(e.len(), 3);
        assert_eq!((e[2].role, e[2].sent, e[2].status), ("Radice", "store", OK));
        assert_eq!(e[2].name, "Example Root CA");
        assert_eq!(find(&c, "Catena").status, OK);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn intermedio_mancante() {
        let (l, i, r) = pki();
        let built = [l.clone(), i, r];
        let (e, c) = chain(std::slice::from_ref(&l), Some(&built), true, now());
        assert_eq!(
            (e[1].role, e[1].sent, e[1].status),
            ("Intermedia", "missing", ERR)
        );
        let m = find(&c, "Certificato intermedio");
        assert_eq!(m.status, ERR);
        assert!(m.detail.contains("Example Issuing CA"));
        assert!(!c.iter().any(|x| x.name == "Catena"));

        // without the system chain and with failed verification: only a warning
        let (e, c) = chain(&[l], None, false, now());
        assert_eq!(e.len(), 1);
        assert_eq!(find(&c, "Catena incompleta").status, WARN);
    }

    #[test]
    fn ordine_radice_ed_estranei() {
        let (l, i, r) = pki();
        let other = ca("Altra CA", None).cert.der().to_vec();
        // root sent, intermediate after the root, an extraneous certificate
        let (e, c) = chain(&[l, r, i, other], None, true, now());
        assert_eq!(
            e.iter().map(|x| x.role).collect::<Vec<_>>(),
            vec!["Server", "Intermedia", "Radice", "Estraneo"]
        );
        assert_eq!(find(&c, "Ordine").status, WARN);
        assert_eq!(find(&c, "Radice inviata").status, INFO);
        assert_eq!(find(&c, "Certificati in più").status, WARN);
        assert!(find(&c, "Certificati in più").detail.contains("Altra CA"));
        assert!(e[2].note.contains("non serve"));
    }

    #[test]
    fn autofirmato() {
        let root = ca("srv01", None);
        let (e, c) = chain(&[root.cert.der().to_vec()], None, false, now());
        assert_eq!(e.len(), 1);
        assert_eq!((e[0].role, e[0].self_signed), ("Server", true));
        assert_eq!(find(&c, "Catena").status, OK);
    }
}
