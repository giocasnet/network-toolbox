//! Optional scan of the versions and ciphers accepted by a server.
//!
//! TLS 1.3: one rustls handshake per suite (there are three). TLS 1.2, 1.1 and 1.0:
//! [`legacy`] probe with the version fixed, offering each time the ciphers not yet chosen:
//! the server picks one, it is removed and the probe is repeated until the server refuses.
//! That is dozens of connections, one after the other: for this reason it starts only on
//! request and can be stopped. No vulnerability testing: it only looks at what the server
//! accepts.

use super::{legacy, Target};
use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::ping::Stop;
use crate::{t, tf};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScanCipher {
    /// IANA name.
    pub name: String,
    /// "" = safe, "weak" = weak (CBC or no forward secrecy), "bad" = to be removed
    pub level: &'static str,
    /// "ECDHE", "DHE", "RSA"
    pub kx: &'static str,
    /// "AES-256 GCM", "3DES CBC"…
    pub enc: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScanVersion {
    /// "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"
    pub name: &'static str,
    pub accepted: bool,
    /// "ok", "warn", "err"; "off" = not accepted
    pub status: &'static str,
    /// In the order in which the server chose them.
    pub ciphers: Vec<ScanCipher>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct ScanResult {
    pub versions: Vec<ScanVersion>,
    /// Connections made.
    pub tried: usize,
    pub time_ms: u64,
    pub stopped: bool,
    /// Why the scan stopped before the end (empty if complete).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// Events: `{"cipher":{version, cipher}}` for each suite found, `{"version":{..}}`
/// at the end of each version, `{"progress":{tried}}` at every connection.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanEvent {
    Cipher {
        version: &'static str,
        cipher: ScanCipher,
    },
    Version(ScanVersion),
    Progress {
        tried: usize,
    },
}

/// Assessment of a suite from its IANA name.
pub fn classify(name: &str) -> ScanCipher {
    let kx = if !name.contains("_WITH_") || name.contains("_ECDHE_") {
        "ECDHE"
    } else if name.contains("_DHE_") {
        "DHE"
    } else {
        "RSA"
    };
    // the part between "_WITH_" (or "TLS_" for TLS 1.3) and the final hash
    let body = name
        .split("_WITH_")
        .nth(1)
        .unwrap_or_else(|| name.strip_prefix("TLS_").unwrap_or(name));
    let body = body.rsplit_once('_').map(|(a, _)| a).unwrap_or(body);
    let enc = match body {
        "3DES_EDE_CBC" => "3DES CBC".to_string(),
        "RC4_128" => "RC4".to_string(),
        "CHACHA20_POLY1305" => "ChaCha20-Poly1305".to_string(),
        other => match other.split('_').collect::<Vec<_>>()[..] {
            ["AES", bits, mode] => format!("AES-{bits} {mode}"),
            _ => other.replace('_', " "),
        },
    };
    let level = if name.contains("3DES") || name.contains("RC4") || name.ends_with("_MD5") {
        "bad"
    } else if name.contains("_CBC_") || kx == "RSA" {
        "weak"
    } else {
        ""
    };
    ScanCipher {
        name: name.to_string(),
        level,
        kx,
        enc,
    }
}

/// Verifier that accepts everything: here only whether the server accepts the suite matters.
#[derive(Debug)]
struct AcceptAll(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The provider's TLS 1.3 suites, with the IANA name ("TLS13_AES…" → "TLS_AES…").
fn tls13_suites() -> Vec<(rustls::SupportedCipherSuite, String)> {
    rustls::crypto::ring::default_provider()
        .cipher_suites
        .into_iter()
        .filter(|s| s.tls13().is_some())
        .map(|s| {
            let n = format!("{:?}", s.suite()).replacen("TLS13_", "TLS_", 1);
            (s, n)
        })
        .collect()
}

/// A TLS 1.3 handshake with a single suite: `Ok(true)` if the server accepts it,
/// `Ok(false)` if it refuses, `Err` if the connection cannot be made.
async fn try13(
    target: &Target,
    sni: &str,
    suite: rustls::SupportedCipherSuite,
) -> crate::Result<bool> {
    let io = target.open().await?;
    let provider = Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        ..rustls::crypto::ring::default_provider()
    });
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(sni.to_string())
        .map_err(|_| tf!("Nome non valido: {sni}", "Invalid name: {sni}"))?;
    let hs = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io);
    match tokio::time::timeout(Duration::from_secs(8), hs).await {
        Err(_) => Err(t!(
            "timeout durante l'handshake",
            "timeout during the handshake"
        )
        .into()),
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) if super::is_rejection(&e) => Ok(false),
        Ok(Err(e)) => Err(e.to_string()),
    }
}

const LEGACY: [(u16, &str); 3] = [
    (0x0303, "TLS 1.2"),
    (0x0302, "TLS 1.1"),
    (0x0301, "TLS 1.0"),
];

fn version_status(name: &str, accepted: bool) -> &'static str {
    match (accepted, name) {
        (false, _) => "off",
        (true, "TLS 1.0") => ERR,
        (true, "TLS 1.1") => WARN,
        _ => OK,
    }
}

/// Full scan. `sni` is the name sent to the server.
pub(crate) async fn run(
    target: &Target,
    sni: &str,
    stop: &Stop,
    emit: impl Fn(ScanEvent),
) -> ScanResult {
    let t0 = Instant::now();
    let mut res = ScanResult::default();
    let finish = |mut r: ScanResult| {
        r.time_ms = t0.elapsed().as_millis() as u64;
        r
    };
    let close = |name: &'static str, ciphers: Vec<ScanCipher>| {
        let accepted = !ciphers.is_empty();
        let v = ScanVersion {
            name,
            accepted,
            status: version_status(name, accepted),
            ciphers,
        };
        emit(ScanEvent::Version(v.clone()));
        v
    };

    // TLS 1.3
    let mut found = Vec::new();
    for (suite, name) in tls13_suites() {
        res.tried += 1;
        emit(ScanEvent::Progress { tried: res.tried });
        match stop.race(try13(target, sni, suite)).await {
            None => res.stopped = true,
            Some(Ok(true)) => {
                let c = classify(&name);
                emit(ScanEvent::Cipher {
                    version: "TLS 1.3",
                    cipher: c.clone(),
                });
                found.push(c);
                continue;
            }
            Some(Ok(false)) => continue,
            Some(Err(e)) => {
                res.note = tf!(
                    "Scansione interrotta su TLS 1.3: {e}",
                    "Scan interrupted on TLS 1.3: {e}"
                )
            }
        }
        break;
    }
    if res.stopped || !res.note.is_empty() {
        if !found.is_empty() {
            res.versions.push(close("TLS 1.3", found));
        }
        return finish(res);
    }
    res.versions.push(close("TLS 1.3", found));

    // TLS 1.2, 1.1, 1.0
    for (ver, vname) in LEGACY {
        let mut left: Vec<(u16, &str)> = legacy::CIPHERS
            .iter()
            .filter(|(_, n)| ver == 0x0303 || !legacy::tls12_only(n))
            .copied()
            .collect();
        let mut found = Vec::new();
        while !left.is_empty() {
            res.tried += 1;
            emit(ScanEvent::Progress { tried: res.tried });
            let ids: Vec<u16> = left.iter().map(|(c, _)| *c).collect();
            let one = async {
                let hello = legacy::client_hello_with(sni, ver, &ids)
                    .map_err(legacy::HelloError::Failed)?;
                let io = target.open().await.map_err(legacy::HelloError::Failed)?;
                legacy::server_hello(io, hello).await
            };
            match stop.race(one).await {
                None => res.stopped = true,
                Some(Ok((v, c))) if v == ver => {
                    if let Some(i) = left.iter().position(|(id, _)| *id == c) {
                        let c = classify(left.remove(i).1);
                        emit(ScanEvent::Cipher {
                            version: vname,
                            cipher: c.clone(),
                        });
                        found.push(c);
                        continue;
                    }
                    // cipher not offered: non-compliant server, stop on this version
                }
                // the server answers with another version, or refuses: done
                Some(Ok(_)) | Some(Err(legacy::HelloError::Rejected(_))) => {}
                Some(Err(legacy::HelloError::Failed(e))) => {
                    res.note = tf!(
                        "Scansione interrotta su {vname}: {e}",
                        "Scan interrupted on {vname}: {e}"
                    )
                }
            }
            break;
        }
        if res.stopped || !res.note.is_empty() {
            if !found.is_empty() {
                res.versions.push(close(vname, found));
            }
            return finish(res);
        }
        res.versions.push(close(vname, found));
    }
    finish(res)
}

/// Checks derived from the scan.
pub fn checks(s: &ScanResult) -> Vec<Check> {
    let p = t!("Protocolli", "Protocols");
    let c_area = "Cipher";
    let mut out = Vec::new();
    let has = |n: &str| s.versions.iter().find(|v| v.name == n).map(|v| v.accepted);
    let complete = !s.stopped && s.note.is_empty();

    if has("TLS 1.0") == Some(true) {
        out.push(check(
            p,
            ERR,
            "TLS 1.0",
            t!(
                "accettato: obsoleto, da disattivare",
                "accepted: obsolete, should be disabled"
            ),
        ));
    }
    if has("TLS 1.1") == Some(true) {
        out.push(check(
            p,
            WARN,
            "TLS 1.1",
            t!(
                "accettato: obsoleto, da disattivare",
                "accepted: obsolete, should be disabled"
            ),
        ));
    }
    match (has("TLS 1.3"), has("TLS 1.2")) {
        (Some(true), Some(true)) => out.push(check(
            p,
            OK,
            t!("TLS 1.3 e TLS 1.2", "TLS 1.3 and TLS 1.2"),
            t!("accettati", "accepted"),
        )),
        (Some(true), Some(false)) => out.push(check(
            p,
            OK,
            "TLS 1.3",
            t!("accettato (TLS 1.2 no)", "accepted (TLS 1.2 not)"),
        )),
        (Some(false), Some(true)) => {
            out.push(check(p, OK, "TLS 1.2", t!("accettato", "accepted")));
            out.push(check(
                p,
                WARN,
                "TLS 1.3",
                t!("non accettato", "not accepted"),
            ));
        }
        (Some(false), Some(false)) => out.push(check(
            p,
            ERR,
            t!("Versioni", "Versions"),
            t!(
                "il server non accetta né TLS 1.3 né TLS 1.2 con le cipher provate",
                "the server accepts neither TLS 1.3 nor TLS 1.2 with the ciphers tried"
            ),
        )),
        _ => {}
    }
    if complete && has("TLS 1.0") == Some(false) && has("TLS 1.1") == Some(false) {
        out.push(check(
            p,
            OK,
            t!("Versioni obsolete", "Obsolete versions"),
            t!("TLS 1.0 e TLS 1.1 rifiutati", "TLS 1.0 and TLS 1.1 refused"),
        ));
    }

    // ciphers: each name once, with the versions in which it appears
    let mut seen: Vec<(&ScanCipher, Vec<&str>)> = Vec::new();
    for v in &s.versions {
        for c in &v.ciphers {
            match seen.iter_mut().find(|(x, _)| x.name == c.name) {
                Some((_, vs)) => vs.push(v.name),
                None => seen.push((c, vec![v.name])),
            }
        }
    }
    for (label, pat) in [("3DES", "3DES"), ("RC4", "RC4")] {
        let hit: Vec<_> = seen.iter().filter(|(c, _)| c.name.contains(pat)).collect();
        if let Some((_, vs)) = hit.first() {
            let mut vs = vs.clone();
            vs.sort();
            out.push(check(
                c_area,
                ERR,
                label,
                tf!(
                    "accettata con {}: {}",
                    "accepted with {}: {}",
                    vs.join(", "),
                    hit.iter()
                        .map(|(c, _)| c.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    let n = |k: usize| {
        if k == 1 {
            t!("1 suite", "1 suite").to_string()
        } else {
            tf!("{k} suite", "{k} suites")
        }
    };
    let rsa = seen.iter().filter(|(c, _)| c.kx == "RSA").count();
    if rsa > 0 {
        out.push(check(
            c_area,
            WARN,
            "Forward secrecy",
            tf!(
                "{} con scambio RSA: senza forward secrecy",
                "{} with RSA key exchange: no forward secrecy",
                n(rsa)
            ),
        ));
    }
    let cbc = seen
        .iter()
        .filter(|(c, _)| c.name.contains("_CBC_") && c.level != "bad")
        .count();
    if cbc > 0 {
        out.push(check(
            c_area,
            INFO,
            "CBC",
            tf!(
                "{} CBC: meglio GCM o ChaCha20-Poly1305",
                "{} CBC: GCM or ChaCha20-Poly1305 is better",
                n(cbc)
            ),
        ));
    }
    if !seen.is_empty() && seen.iter().all(|(c, _)| c.level.is_empty()) {
        out.push(check(
            c_area,
            OK,
            "Cipher",
            tf!(
                "{}, tutte con forward secrecy e cifratura autenticata",
                "{}, all with forward secrecy and authenticated encryption",
                n(seen.len())
            ),
        ));
    }
    if s.stopped {
        out.push(check(
            p,
            INFO,
            t!("Scansione", "Scan"),
            t!("fermata: risultato parziale", "stopped: partial result"),
        ));
    } else if !s.note.is_empty() {
        out.push(check(p, INFO, t!("Scansione", "Scan"), s.note.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn giudizio_delle_suite() {
        let c = classify("TLS_AES_256_GCM_SHA384");
        assert_eq!(
            (c.level, c.kx, c.enc.as_str()),
            ("", "ECDHE", "AES-256 GCM")
        );
        let c = classify("TLS_CHACHA20_POLY1305_SHA256");
        assert_eq!(
            (c.level, c.kx, c.enc.as_str()),
            ("", "ECDHE", "ChaCha20-Poly1305")
        );
        let c = classify("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(
            (c.level, c.kx, c.enc.as_str()),
            ("", "ECDHE", "AES-128 GCM")
        );
        let c = classify("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        assert_eq!(
            (c.level, c.kx, c.enc.as_str()),
            ("weak", "ECDHE", "AES-256 CBC")
        );
        let c = classify("TLS_RSA_WITH_AES_256_GCM_SHA384");
        assert_eq!((c.level, c.kx), ("weak", "RSA"));
        let c = classify("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        assert_eq!(
            (c.level, c.kx, c.enc.as_str()),
            ("weak", "DHE", "AES-128 CBC")
        );
        let c = classify("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!((c.level, c.kx, c.enc.as_str()), ("bad", "RSA", "3DES CBC"));
        let c = classify("TLS_RSA_WITH_RC4_128_MD5");
        assert_eq!((c.level, c.enc.as_str()), ("bad", "RC4"));
        // every suite offered by the probe has a readable assessment
        for (_, n) in legacy::CIPHERS {
            let c = classify(n);
            assert!(!c.enc.is_empty() && !c.enc.contains('_'), "{n}: {}", c.enc);
        }
        assert_eq!(tls13_suites().len(), 3);
        assert!(tls13_suites().iter().all(|(_, n)| n.starts_with("TLS_")));
    }

    fn ver(name: &'static str, suites: &[&str]) -> ScanVersion {
        ScanVersion {
            name,
            accepted: !suites.is_empty(),
            status: version_status(name, !suites.is_empty()),
            ciphers: suites.iter().map(|s| classify(s)).collect(),
        }
    }

    fn find<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter()
            .find(|x| x.name == name)
            .unwrap_or_else(|| panic!("manca {name}: {c:?}"))
    }

    #[test]
    fn controlli_server_moderno() {
        let s = ScanResult {
            versions: vec![
                ver("TLS 1.3", &["TLS_AES_256_GCM_SHA384"]),
                ver("TLS 1.2", &["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]),
                ver("TLS 1.1", &[]),
                ver("TLS 1.0", &[]),
            ],
            ..Default::default()
        };
        let c = checks(&s);
        assert_eq!(find(&c, "TLS 1.3 e TLS 1.2").status, OK);
        assert_eq!(find(&c, "Versioni obsolete").status, OK);
        assert_eq!(find(&c, "Cipher").status, OK);
        assert!(c.iter().all(|x| x.status == OK), "{c:?}");
    }

    #[test]
    fn controlli_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let s = ScanResult {
            versions: vec![
                ver("TLS 1.3", &["TLS_AES_256_GCM_SHA384"]),
                ver("TLS 1.2", &["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]),
                ver("TLS 1.1", &[]),
                ver("TLS 1.0", &[]),
            ],
            ..Default::default()
        };
        let c = checks(&s);
        assert_eq!(find(&c, "TLS 1.3 and TLS 1.2").detail, "accepted");
        assert_eq!(find(&c, "Obsolete versions").status, OK);
        assert!(find(&c, "Cipher")
            .detail
            .contains("authenticated encryption"));
        assert!(!c.iter().any(|x| x.name == "Versioni obsolete"));
    }

    #[test]
    fn controlli_server_vecchio() {
        let old = [
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ];
        let s = ScanResult {
            versions: vec![
                ver("TLS 1.3", &[]),
                ver(
                    "TLS 1.2",
                    &["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", old[1], old[2]],
                ),
                ver("TLS 1.1", &old),
                ver("TLS 1.0", &old),
            ],
            ..Default::default()
        };
        assert_eq!(s.versions[3].status, ERR);
        assert_eq!(s.versions[2].status, WARN);
        assert_eq!(s.versions[0].status, "off");
        let c = checks(&s);
        assert_eq!(find(&c, "TLS 1.0").status, ERR);
        assert_eq!(find(&c, "TLS 1.1").status, WARN);
        assert_eq!(find(&c, "TLS 1.3").status, WARN);
        assert_eq!(find(&c, "TLS 1.2").status, OK);
        let d = find(&c, "3DES");
        assert_eq!(d.status, ERR);
        assert!(
            d.detail.contains("TLS 1.0, TLS 1.1, TLS 1.2"),
            "{}",
            d.detail
        );
        // AES_128_CBC_SHA and 3DES: two suites with RSA exchange, counted once
        assert!(find(&c, "Forward secrecy").detail.starts_with("2 suite"));
        assert!(find(&c, "CBC").detail.starts_with("2 suite"));
        assert!(!c.iter().any(|x| x.name == "Cipher"));

        let stopped = ScanResult {
            versions: vec![ver("TLS 1.3", &["TLS_AES_256_GCM_SHA384"])],
            stopped: true,
            ..Default::default()
        };
        let c = checks(&stopped);
        assert_eq!(find(&c, "Scansione").status, INFO);
        assert!(!c.iter().any(|x| x.name == "Versioni obsolete"));
    }
}
