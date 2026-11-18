//! TLS certificate of a server. The handshake uses rustls; the chain is
//! verified with the system certificate store (on Windows also the corporate
//! CAs and imported mkcert ones), but the details are read even if it is not valid.
//!
//! Legacy servers (since 1.15.0): if the server rejects the handshake (reset, close,
//! protocol or cipher alert) a new connection is tried offering only
//! TLS 1.2 and, if that is not enough, a compatibility probe ([`legacy`]) that offers
//! TLS 1.0–1.2 and obsolete ciphers and reads the certificate from the ServerHello,
//! without completing the handshake. With a modern server the first attempt succeeds
//! and the behaviour is the same as before.

use crate::{net, t, tf, util, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use x509_parser::prelude::*;

pub mod cert;
mod legacy;
pub mod scan;
pub mod starttls;
#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl;

use crate::http::analyze::{check, Check, INFO, OK, WARN};
use crate::ping::Stop;
pub use starttls::Proto;

#[derive(Debug, Deserialize)]
pub struct TlsReq {
    pub host: String,
    #[serde(default, deserialize_with = "util::opt_u32")]
    pub port: Option<u32>,
    /// "auto" (from the port), "tls", "smtp", "imap", "pop3", "rdp"
    #[serde(default)]
    pub protocol: String,
    /// Name to send as SNI and to verify in the certificate; empty = `host`.
    #[serde(default)]
    pub sni: String,
    /// Also tries the accepted versions and ciphers (dozens of connections).
    #[serde(default)]
    pub scan: bool,
}

/// Events of the `ssl` command: `{"result":{..}}` as soon as the certificate has been read
/// (the scan, if requested, has yet to start), then `{"scan":{..}}`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsEvent {
    Result(Box<TlsResult>),
    Scan(scan::ScanEvent),
}

/// Where to connect and how to reach the handshake.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Target {
    pub addr: SocketAddr,
    pub proto: Proto,
}

impl Target {
    /// New connection, brought up to the point where the ClientHello is sent.
    pub(crate) async fn open(&self) -> Result<TcpStream> {
        let mut s = connect(self.addr).await?;
        starttls::prepare(&mut s, self.proto).await?;
        Ok(s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsResult {
    pub host: String,
    pub port: u16,
    pub verified: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub verify_error: String,
    pub subject: BTreeMap<String, String>,
    pub issuer: BTreeMap<String, String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub serial: String,
    pub sans: Vec<String>,
    pub cipher: String,
    pub tls_version: String,
    pub expired: bool,
    pub expiring_soon: bool,
    /// Common name of each certificate received, from the server towards the root.
    pub chain: Vec<String>,
    /// How the result was reached when the first handshake was rejected
    /// (empty with modern servers).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub compat: String,
    /// Handshake not completed: the certificate was read from the ServerHello of the
    /// compatibility probe. The chain is verified, but the server has not proved
    /// that it owns the private key.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
    /// Everything that can be read from the server certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<cert::CertDetails>,
    /// Chain from the server to the root, with what the server sent and what is missing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chain_info: Vec<cert::ChainEntry>,
    /// Checks (`area`, `status`, `name`, `detail`): the UI sorts them by severity.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,
    /// The server stapled an OCSP response (`None` if the handshake is not complete).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp_stapled: Option<bool>,
    /// How TLS was reached: "TLS diretto", "SMTP con STARTTLS"…
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    /// Name sent as SNI, if different from `host`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<scan::ScanResult>,
    /// Certificates sent by the server (DER), in the order received.
    #[serde(skip)]
    pub ders: Vec<Vec<u8>>,
}

/// Verifier that delegates to the system one, records its outcome and lets the
/// handshake go on anyway (the handshake signatures are still verified).
#[derive(Debug)]
struct Recorder {
    inner: Arc<dyn ServerCertVerifier>,
    provider: Arc<CryptoProvider>,
    /// Verification outcome (empty = valid) and whether an OCSP response was stapled.
    outcome: Arc<Mutex<Option<(String, bool)>>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let r = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now);
        let msg = match r {
            Ok(_) => String::new(),
            Err(e) => describe(&e, server_name),
        };
        *self.outcome.lock().unwrap() = Some((msg, !ocsp.is_empty()));
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
            &self.provider.signature_verification_algorithms,
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn describe(e: &rustls::Error, name: &ServerName<'_>) -> String {
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::UnknownIssuer => t!(
                "Autorità di certificazione non attendibile per questo PC",
                "Certificate authority not trusted by this PC"
            )
            .into(),
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                t!("Certificato scaduto", "Certificate expired").into()
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                t!("Certificato non ancora valido", "Certificate not yet valid").into()
            }
            CertificateError::Revoked => t!("Certificato revocato", "Certificate revoked").into(),
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                tf!(
                    "Il certificato non copre il nome {}",
                    "The certificate does not cover the name {}",
                    name.to_str()
                )
            }
            other => tf!(
                "Certificato non valido: {other:?}",
                "Invalid certificate: {other:?}"
            ),
        },
        other => other.to_string(),
    }
}

fn names(n: &X509Name<'_>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(cn) = n.iter_common_name().next().and_then(|a| a.as_str().ok()) {
        m.insert("commonName".into(), cn.to_string());
    }
    if let Some(o) = n.iter_organization().next().and_then(|a| a.as_str().ok()) {
        m.insert("organizationName".into(), o.to_string());
    }
    m
}

fn tls_version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        other => version_name(u16::from(other)),
    }
}

/// Version name from the protocol value (obsolete ones too).
pub(crate) fn version_name(v: u16) -> String {
    match v {
        0x0304 => "TLSv1.3".into(),
        0x0303 => "TLSv1.2".into(),
        0x0302 => "TLSv1.1".into(),
        0x0301 => "TLSv1.0".into(),
        0x0300 => "SSLv3".into(),
        other => format!("0x{other:04X}"),
    }
}

/// Data common to the full handshake and the probe: first certificate and chain names.
fn from_certs(certs: &[CertificateDer<'_>]) -> Result<TlsResult> {
    let first = certs.first().ok_or(t!(
        "Il server non ha inviato certificati",
        "The server sent no certificates"
    ))?;
    let mut r = describe_cert(first.as_ref(), util::now_unix() as i64)?;
    r.ders = certs.iter().map(|c| c.as_ref().to_vec()).collect();
    r.chain = certs
        .iter()
        .filter_map(|c| X509Certificate::from_der(c.as_ref()).ok())
        .map(|(_, c)| {
            names(c.subject())
                .get("commonName")
                .cloned()
                .unwrap_or_else(|| c.subject().to_string())
        })
        .collect();
    Ok(r)
}

/// Extracts the data from the server certificate (DER).
pub fn describe_cert(der: &[u8], now: i64) -> Result<TlsResult> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
        tf!(
            "Certificato non leggibile: {e}",
            "Unreadable certificate: {e}"
        )
    })?;
    let d = cert::details(der, now)?;
    Ok(TlsResult {
        host: String::new(),
        port: 0,
        verified: false,
        verify_error: String::new(),
        subject: names(cert.subject()),
        issuer: names(cert.issuer()),
        not_before: d.not_before.clone(),
        not_after: d.not_after.clone(),
        days_remaining: d.days_remaining,
        serial: d.serial.clone(),
        sans: d.sans.clone(),
        cipher: String::new(),
        tls_version: String::new(),
        expired: d.expired,
        expiring_soon: !d.expired && d.days_remaining <= 30,
        chain: vec![],
        compat: String::new(),
        partial: false,
        cert: Some(d),
        chain_info: vec![],
        checks: vec![],
        ocsp_stapled: None,
        protocol: String::new(),
        sni: String::new(),
        scan: None,
        ders: vec![],
    })
}

fn platform_verifier(provider: Arc<CryptoProvider>) -> Result<Arc<dyn ServerCertVerifier>> {
    let v = rustls_platform_verifier::Verifier::new().with_provider(provider);
    Ok(Arc::new(v))
}

async fn connect(addr: SocketAddr) -> Result<TcpStream> {
    tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| {
            tf!(
                "Timeout di connessione a {addr}",
                "Connection timeout to {addr}"
            )
        })?
        .map_err(|e| tf!("Connessione fallita: {e}", "Connection failed: {e}"))
}

pub async fn inspect(host: &str, addr: SocketAddr) -> Result<TlsResult> {
    inspect_with(host, addr, None).await
}

/// Versions offered by rustls in one attempt.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Versions {
    /// TLS 1.3 and 1.2 (default, the usual ClientHello).
    Modern,
    /// TLS 1.2 only: for servers that close on a TLS 1.3 ClientHello.
    Tls12,
}

/// Outcome of a failed rustls handshake: `rejected` = the server rejected the
/// offer (worth retrying with a different offer).
struct HsError {
    msg: String,
    rejected: bool,
}

/// The server rejected the handshake (and not: timeout, non-TLS port, local error).
fn is_rejection(e: &std::io::Error) -> bool {
    use rustls::AlertDescription as A;
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionReset | K::ConnectionAborted | K::UnexpectedEof | K::BrokenPipe => true,
        K::InvalidData => match e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
            Some(rustls::Error::AlertReceived(a)) => matches!(
                a,
                A::HandshakeFailure
                    | A::ProtocolVersion
                    | A::InsufficientSecurity
                    | A::IllegalParameter
                    | A::DecodeError
                    | A::InternalError
            ),
            Some(rustls::Error::PeerIncompatible(_)) => true,
            Some(rustls::Error::PeerMisbehaved(_)) => true,
            _ => false,
        },
        _ => false,
    }
}

/// Like [`inspect`], with a verifier for tests (`None` = system store).
pub(crate) async fn inspect_with(
    host: &str,
    addr: SocketAddr,
    inner: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<TlsResult> {
    let target = Target {
        addr,
        proto: Proto::Tls,
    };
    inspect_target(host, &target, inner).await
}

/// The three attempts on `target`; `host` is the name sent as SNI and verified.
pub(crate) async fn inspect_target(
    host: &str,
    target: &Target,
    inner: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<TlsResult> {
    let addr = target.addr;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = match inner {
        Some(v) => v,
        None => platform_verifier(provider.clone())?,
    };

    // A: normal offer (TLS 1.3 + 1.2), identical to previous versions.
    let first = match attempt(host, target.open().await?, inner.clone(), Versions::Modern).await {
        Ok((_, mut r)) => {
            r.port = addr.port();
            return Ok(r);
        }
        Err(e) if !e.rejected => return Err(e.msg),
        Err(e) => e.msg,
    };

    // B: TLS 1.2 only, on a new connection.
    match attempt(host, target.open().await?, inner.clone(), Versions::Tls12).await {
        Ok((_, mut r)) => {
            r.port = addr.port();
            r.compat = tf!(
                "Il server rifiuta il ClientHello con TLS 1.3 ({first}): handshake \
                 riuscito offrendo solo TLS 1.2.",
                "The server rejects the ClientHello with TLS 1.3 ({first}): handshake \
                 succeeded when offering only TLS 1.2."
            );
            return Ok(r);
        }
        Err(e) if !e.rejected => return Err(e.msg),
        Err(_) => {}
    }

    // C: compatibility probe (TLS 1.0–1.2, obsolete ciphers), read-only.
    let tcp = target.open().await?;
    match legacy::probe(host, tcp).await {
        Ok(p) => {
            let mut r = from_certs(&p.certs)?;
            let name = ServerName::try_from(host.to_string())
                .map_err(|_| tf!("Nome non valido: {host}", "Invalid name: {host}"))?;
            let err = match inner.verify_server_cert(
                &p.certs[0],
                &p.certs[1..],
                &name,
                &[],
                UnixTime::now(),
            ) {
                Ok(_) => String::new(),
                Err(e) => describe(&e, &name),
            };
            r.verified = err.is_empty();
            r.verify_error = err;
            r.host = host.to_string();
            r.port = addr.port();
            r.tls_version = version_name(p.version);
            r.cipher = legacy::cipher_name(p.cipher);
            r.partial = true;
            r.compat = tf!(
                "Il server rifiuta l'handshake di questa app sia con TLS 1.3 sia con \
                 TLS 1.2 (primo errore: {first}). Con l'offerta di compatibilità sceglie \
                 {} con {}, che l'app non supporta: certificato letto dal ServerHello, \
                 senza completare l'handshake.",
                "The server rejects this app's handshake with both TLS 1.3 and \
                 TLS 1.2 (first error: {first}). With the compatibility offer it picks \
                 {} with {}, which the app does not support: certificate read from the \
                 ServerHello, without completing the handshake.",
                r.tls_version,
                r.cipher
            );
            Ok(r)
        }
        Err(e) => Err(tf!(
            "Handshake TLS fallito: il server rifiuta TLS 1.3, TLS 1.2 e anche \
             l'offerta di compatibilità (TLS 1.0–1.2, cipher obsolete). \
             Primo errore: {first}. Ultimo: {e}. Cause possibili: servizio non TLS \
             sulla porta, IPS o firewall che blocca il PC, server che accetta solo \
             client specifici.",
            "TLS handshake failed: the server rejects TLS 1.3, TLS 1.2 and also \
             the compatibility offer (TLS 1.0–1.2, obsolete ciphers). \
             First error: {first}. Last: {e}. Possible causes: non-TLS service \
             on the port, IPS or firewall blocking this PC, server that accepts only \
             specific clients."
        )),
    }
}

/// TLS handshake on an already open connection (also after STARTTLS): returns the
/// encrypted stream and the certificate data. The chain is verified with the system
/// store (or with `inner`, used by tests), but the outcome does not interrupt the
/// handshake: whoever uses the stream must check `verified` before sending
/// confidential data.
pub(crate) async fn handshake<IO>(
    host: &str,
    io: IO,
    inner: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<(tokio_rustls::client::TlsStream<IO>, TlsResult)>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let inner = match inner {
        Some(v) => v,
        None => platform_verifier(Arc::new(rustls::crypto::ring::default_provider()))?,
    };
    attempt(host, io, inner, Versions::Modern)
        .await
        .map_err(|e| e.msg)
}

async fn attempt<IO>(
    host: &str,
    io: IO,
    inner: Arc<dyn ServerCertVerifier>,
    versions: Versions,
) -> std::result::Result<(tokio_rustls::client::TlsStream<IO>, TlsResult), HsError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let fail = |msg: String| HsError {
        msg,
        rejected: false,
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let outcome = Arc::new(Mutex::new(None));
    let recorder = Recorder {
        inner,
        provider: provider.clone(),
        outcome: outcome.clone(),
    };
    let builder = ClientConfig::builder_with_provider(provider);
    let builder = match versions {
        Versions::Modern => builder.with_safe_default_protocol_versions(),
        Versions::Tls12 => builder.with_protocol_versions(&[&rustls::version::TLS12]),
    }
    .map_err(|e| fail(e.to_string()))?;
    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(recorder))
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| fail(tf!("Nome non valido: {host}", "Invalid name: {host}")))?;

    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io),
    )
    .await
    .map_err(|_| {
        fail(
            t!(
                "Timeout durante l'handshake TLS",
                "Timeout during the TLS handshake"
            )
            .to_string(),
        )
    })?
    .map_err(|e| {
        let m = e.to_string();
        let msg = if m.contains("ProtocolVersion") || m.contains("protocol version") {
            t!(
                "Il server non supporta TLS 1.2 o 1.3 (solo protocolli obsoleti)",
                "The server does not support TLS 1.2 or 1.3 (obsolete protocols only)"
            )
            .to_string()
        } else {
            tf!("Handshake TLS fallito: {m}", "TLS handshake failed: {m}")
        };
        HsError {
            msg,
            rejected: is_rejection(&e),
        }
    })?;
    let r = {
        let (_, conn) = tls.get_ref();
        let certs = conn.peer_certificates().ok_or_else(|| {
            fail(
                t!(
                    "Il server non ha inviato certificati",
                    "The server sent no certificates"
                )
                .into(),
            )
        })?;
        let mut r = from_certs(certs).map_err(fail)?;
        r.tls_version = conn
            .protocol_version()
            .map(tls_version_name)
            .unwrap_or_default();
        r.cipher = conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_default();
        let (err, stapled) = outcome.lock().unwrap().clone().unwrap_or_else(|| {
            (
                t!("Verifica non eseguita", "Verification not performed").into(),
                false,
            )
        });
        r.ocsp_stapled = Some(stapled);
        r.verified = err.is_empty();
        r.verify_error = err;
        r.host = host.to_string();
        r
    };
    Ok((tls, r))
}

/// Manual self-test (`selftest`): tries the three attempts one by one on `target`
/// (`host:port`) and reports the outcome of each, then the result of `inspect`.
pub async fn diagnose(target: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (h, p) = target.rsplit_once(':').unwrap_or((target, "443"));
    let port: u16 = p.parse().unwrap_or(443);
    let host = match net::clean_host(h) {
        Ok(h) => h,
        Err(e) => return vec![format!("Host non valido: {e}")],
    };
    let ip = match net::resolve_v4(&host).await {
        Ok(ip) => ip,
        Err(e) => return vec![format!("Risoluzione di {host}: {e}")],
    };
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    out.push(format!("Destinazione: {host} ({addr})"));
    let inner = match platform_verifier(Arc::new(rustls::crypto::ring::default_provider())) {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    for (label, v) in [
        ("A  rustls TLS 1.3+1.2", Versions::Modern),
        ("B  rustls solo TLS 1.2", Versions::Tls12),
    ] {
        let t = std::time::Instant::now();
        let line = match connect(addr).await {
            Err(e) => e,
            Ok(tcp) => match attempt(&host, tcp, inner.clone(), v).await {
                Ok((_, r)) => format!(
                    "ok: {} {} verificato={} {}",
                    r.tls_version, r.cipher, r.verified, r.verify_error
                ),
                Err(e) => format!("{} [rifiuto={}]", e.msg, e.rejected),
            },
        };
        out.push(format!("{label}: {line} ({} ms)", t.elapsed().as_millis()));
    }
    let t = std::time::Instant::now();
    let line = match connect(addr).await {
        Err(e) => e,
        Ok(tcp) => match legacy::probe(&host, tcp).await {
            Ok(p) => format!(
                "ok: il server sceglie {} {} ({} certificati)",
                version_name(p.version),
                legacy::cipher_name(p.cipher),
                p.certs.len()
            ),
            Err(e) => e,
        },
    };
    out.push(format!(
        "C  sonda di compatibilità: {line} ({} ms)",
        t.elapsed().as_millis()
    ));
    let t = std::time::Instant::now();
    let res = inspect(&host, addr).await;
    out.push(match &res {
        Ok(r) => format!(
            "Risultato dell'app: {} {} verificato={} parziale={} ({} ms){}{}",
            r.tls_version,
            r.cipher,
            r.verified,
            r.partial,
            t.elapsed().as_millis(),
            if r.verify_error.is_empty() {
                String::new()
            } else {
                format!("\n  Motivo: {}", r.verify_error)
            },
            if r.compat.is_empty() {
                String::new()
            } else {
                format!("\n  Nota: {}", r.compat)
            },
        ),
        Err(e) => format!(
            "Risultato dell'app: errore ({} ms): {e}",
            t.elapsed().as_millis()
        ),
    });
    // Chain: which path was used (system, or only the certificates sent).
    if let Ok(r) = res {
        let t = std::time::Instant::now();
        let built = system_chain(r.ders.clone()).await;
        out.push(match &built {
            Some(b) => format!(
                "Catena del sistema: {} certificati ({} inviati dal server, {} ms)",
                b.len(),
                r.ders.len(),
                t.elapsed().as_millis()
            ),
            None => format!(
                "Catena del sistema: non disponibile, uso i {} certificati inviati",
                r.ders.len()
            ),
        });
        let (entries, _) = cert::chain(
            &r.ders,
            built.as_deref(),
            r.verified,
            util::now_unix() as i64,
        );
        for e in entries {
            out.push(format!("  {}: {} [{}] {}", e.role, e.name, e.sent, e.key));
        }
    }
    out
}

/// Chain built by the system (on Windows, root included). `None` elsewhere, if
/// Windows does not build it or if it takes too long.
async fn system_chain(sent: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    #[cfg(windows)]
    {
        let work = tokio::task::spawn_blocking(move || windows_impl::system_chain(&sent));
        tokio::time::timeout(Duration::from_secs(10), work)
            .await
            .ok()?
            .ok()?
    }
    #[cfg(not(windows))]
    {
        let _ = sent;
        None
    }
}

/// Verifier that always rejects: used only as the inner one of [`Recorder`] when
/// the verification outcome does not matter.
#[derive(Debug)]
struct Reject;

impl ServerCertVerifier for Reject {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Err(rustls::Error::General("non verificato".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("non verificato".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("non verificato".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![]
    }
}

/// Certificate that the server presents to a client that does not send the name (SNI):
/// SHA-256 fingerprint and name, or `None` if the handshake fails without SNI.
async fn without_sni(name: &str, target: &Target) -> Option<(String, String)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // the inner verifier does not matter: Recorder lets the handshake go on anyway
    let recorder = Recorder {
        inner: Arc::new(Reject),
        provider: provider.clone(),
        outcome: Arc::new(Mutex::new(None)),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(recorder))
        .with_no_client_auth();
    config.enable_sni = false;
    let name = ServerName::try_from(name.to_string()).ok()?;
    let io = target.open().await.ok()?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io),
    )
    .await
    .ok()?
    .ok()?;
    let (_, conn) = tls.get_ref();
    let der = conn.peer_certificates()?.first()?;
    let d = cert::details(der.as_ref(), util::now_unix() as i64).ok()?;
    Some((d.sha256, d.name))
}

/// Adds the chain and the checks to `r`. `name` is the verified name, `built` the
/// system chain, `no_sni` the outcome of the test without SNI (`None` = not done,
/// `Some(None)` = handshake failed).
pub(crate) fn analyze(
    r: &mut TlsResult,
    name: &str,
    built: Option<&[Vec<u8>]>,
    no_sni: Option<Option<(String, String)>>,
) {
    let now = util::now_unix() as i64;
    let Some(d) = r.cert.clone() else {
        return;
    };
    let mut checks = cert::leaf_checks(&d, name, &r.verify_error);
    let (entries, chain_checks) = cert::chain(&r.ders, built, r.verified, now);
    r.chain_info = entries;
    checks.extend(chain_checks);
    checks.push(cert::revocation_check(&d, r.ocsp_stapled));

    let p = t!("Protocolli", "Protocols");
    let old = matches!(r.tls_version.as_str(), "TLSv1.0" | "TLSv1.1" | "SSLv3");
    let version = r.tls_version.replace("TLSv", "TLS ");
    let cipher = r.cipher.replacen("TLS13_", "TLS_", 1);
    if !r.compat.is_empty() {
        checks.push(check(
            p,
            WARN,
            t!("Compatibilità", "Compatibility"),
            r.compat.clone(),
        ));
    }
    checks.push(check(
        p,
        if old { WARN } else { OK },
        if r.partial {
            t!("Scelta del server", "Server choice")
        } else {
            t!("Negoziato", "Negotiated")
        },
        if old {
            tf!(
                "{version} con {cipher}: versione obsoleta",
                "{version} with {cipher}: obsolete version"
            )
        } else {
            tf!("{version} con {cipher}", "{version} with {cipher}")
        },
    ));
    match no_sni {
        Some(Some((fp, other))) if fp != d.sha256 => checks.push(check(
            t!("Certificato", "Certificate"),
            INFO,
            "SNI",
            tf!(
                "senza SNI il server presenta un altro certificato ({other})",
                "without SNI the server presents a different certificate ({other})"
            ),
        )),
        Some(None) => checks.push(check(
            t!("Certificato", "Certificate"),
            INFO,
            "SNI",
            t!(
                "senza SNI il server non completa l'handshake",
                "without SNI the server does not complete the handshake"
            ),
        )),
        _ => {}
    }
    r.checks = checks;
}

pub async fn run(req: TlsReq, stop: &Stop, emit: impl Fn(TlsEvent)) -> Result<TlsResult> {
    run_with(req, stop, emit, None).await
}

/// Like [`run`], with a verifier for tests (`None` = system store; in that case the
/// chain is also requested from the system).
pub(crate) async fn run_with(
    req: TlsReq,
    stop: &Stop,
    emit: impl Fn(TlsEvent),
    inner: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<TlsResult> {
    let host = net::clean_host(&req.host)?;
    let port = req.port.unwrap_or(443);
    if !(1..=65535).contains(&port) {
        return Err(t!("Porta non valida", "Invalid port").into());
    }
    let proto = Proto::parse(&req.protocol, port as u16)?;
    let name = if req.sni.trim().is_empty() {
        host.clone()
    } else {
        net::clean_host(&req.sni)
            .map_err(|e| tf!("Nome SNI non valido: {e}", "Invalid SNI name: {e}"))?
    };
    let system = inner.is_none();
    let work = async {
        let ip = net::resolve_v4(&host).await?;
        let target = Target {
            addr: SocketAddr::new(IpAddr::V4(ip), port as u16),
            proto,
        };
        let mut r = inspect_target(&name, &target, inner).await?;
        r.host = host.clone();
        r.protocol = proto.label().to_string();
        if name != host {
            r.sni = name.clone();
        }
        let built = if system {
            system_chain(r.ders.clone()).await
        } else {
            None
        };
        // without SNI: only if there is a name not to send and the handshake is complete
        let no_sni = if name.parse::<IpAddr>().is_err() && !r.partial {
            Some(without_sni(&name, &target).await)
        } else {
            None
        };
        analyze(&mut r, &name, built.as_deref(), no_sni);
        Ok::<_, String>((r, target))
    };
    let (mut r, target) = stop
        .race(work)
        .await
        .ok_or_else(|| t!("Controllo fermato.", "Check stopped.").to_string())??;
    if req.scan {
        emit(TlsEvent::Result(Box::new(r.clone())));
        let s = scan::run(&target, &name, stop, |e| emit(TlsEvent::Scan(e))).await;
        r.checks.extend(scan::checks(&s));
        r.scan = Some(s);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// Test TLS server with a self-signed certificate: the details must
    /// be read and the chain must turn out untrusted.
    #[tokio::test]
    async fn certificato_autofirmato() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "ntb.test".into()])
            .unwrap();
        let cert = ck.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let _tls = acceptor.accept(s).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let r = inspect("localhost", addr).await.unwrap();
        assert!(!r.verified);
        assert!(!r.verify_error.is_empty());
        assert_eq!(r.tls_version, "TLSv1.3");
        assert!(r.cipher.starts_with("TLS13_"), "{}", r.cipher);
        assert_eq!(r.sans, vec!["DNS: localhost", "DNS: ntb.test"]);
        assert_eq!(
            r.subject.get("commonName").map(String::as_str),
            Some("rcgen self signed cert")
        );
        assert!(!r.expired);
        assert!(r.days_remaining > 1000);
        assert_eq!(r.chain.len(), 1);
        // Modern server: no fallback, no note.
        assert!(r.compat.is_empty());
        assert!(!r.partial);
    }

    // ---- Fake legacy servers --------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Test CA + server certificate for `localhost`, signed by the CA.
    struct Pki {
        leaf: CertificateDer<'static>,
        ca: CertificateDer<'static>,
        key: Vec<u8>,
    }

    fn pki() -> Pki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "NTB Test CA");
        let ca = ca.self_signed(&ca_key).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "legacy.test");
        let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
        Pki {
            leaf: leaf.der().clone(),
            ca: ca.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn trust(ca: &CertificateDer<'static>) -> Arc<dyn ServerCertVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap()
    }

    /// Reads (without consuming it) the first record and returns the versions announced in
    /// `supported_versions` and the ciphers offered.
    async fn peek_hello(s: &tokio::net::TcpStream) -> (Vec<u16>, Vec<u16>) {
        let mut buf = vec![0u8; 4096];
        let n = loop {
            let n = s.peek(&mut buf).await.unwrap();
            if n >= 5 && n >= 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize {
                break n;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let m = &buf[9..n];
        let mut i = 2 + 32;
        i += 1 + m[i] as usize;
        let cl = u16::from_be_bytes([m[i], m[i + 1]]) as usize;
        let ciphers = m[i + 2..i + 2 + cl]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        i += 2 + cl;
        i += 1 + m[i] as usize;
        let end = i + 2 + u16::from_be_bytes([m[i], m[i + 1]]) as usize;
        i += 2;
        let mut versions = Vec::new();
        while i + 4 <= end {
            let id = u16::from_be_bytes([m[i], m[i + 1]]);
            let l = u16::from_be_bytes([m[i + 2], m[i + 3]]) as usize;
            if id == 43 {
                versions = m[i + 5..i + 4 + l]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
            }
            i += 4 + l;
        }
        (versions, ciphers)
    }

    /// Closes with RST (like Schannel facing a ClientHello it does not like).
    fn reset(s: tokio::net::TcpStream) {
        let s = s.into_std().unwrap();
        socket2_free_linger(&s);
        drop(s);
    }

    /// SO_LINGER = 0 without extra dependencies: on Linux with the system libc.
    #[cfg(unix)]
    fn socket2_free_linger(s: &std::net::TcpStream) {
        use std::os::fd::AsRawFd;
        #[repr(C)]
        struct Linger {
            l_onoff: i32,
            l_linger: i32,
        }
        extern "C" {
            fn setsockopt(fd: i32, level: i32, name: i32, val: *const Linger, len: u32) -> i32;
        }
        let l = Linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SOL_SOCKET = 1, SO_LINGER = 13 on Linux
        unsafe {
            setsockopt(
                s.as_raw_fd(),
                1,
                13,
                &l,
                std::mem::size_of::<Linger>() as u32,
            );
        }
    }

    #[cfg(not(unix))]
    fn socket2_free_linger(_s: &std::net::TcpStream) {}

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        /// Closes if the ClientHello announces TLS 1.3, otherwise TLS 1.2 with rustls.
        ResetOnTls13,
        /// Like a Schannel with only RSA-CBC ciphers: closes if 0x002F is missing,
        /// otherwise TLS 1.0 ServerHello + Certificate (split into two records).
        OnlyRsaCbc,
        /// Always closes.
        ResetAll,
        /// Always answers with the handshake_failure alert.
        AlertAll,
        /// Not TLS (a plain HTTP server on the port).
        Plain,
    }

    async fn server(mode: Mode, p: &Pki) -> (SocketAddr, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let count = conns.clone();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![p.leaf.clone(), p.ca.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.key.clone())),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let (leaf, ca) = (p.leaf.clone(), p.ca.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                if mode == Mode::Plain {
                    tokio::spawn(answer_then_wait(s, b"HTTP/1.1 400 Bad Request\r\n\r\n"));
                    continue;
                }
                let (versions, ciphers) = peek_hello(&s).await;
                match mode {
                    Mode::ResetAll => reset(s),
                    Mode::AlertAll => {
                        tokio::spawn(answer_then_wait(s, &[0x15, 3, 3, 0, 2, 2, 40]));
                    }
                    Mode::ResetOnTls13 if versions.contains(&0x0304) => reset(s),
                    Mode::ResetOnTls13 => {
                        let acc = acceptor.clone();
                        tokio::spawn(async move {
                            let _t = acc.accept(s).await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        });
                    }
                    Mode::OnlyRsaCbc if !ciphers.contains(&0x002f) => reset(s),
                    Mode::OnlyRsaCbc => {
                        let (leaf, ca) = (leaf.clone(), ca.clone());
                        tokio::spawn(async move {
                            let mut head = [0u8; 5];
                            s.read_exact(&mut head).await.unwrap();
                            let mut rest =
                                vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
                            s.read_exact(&mut rest).await.unwrap();
                            let hs = legacy_flight(&leaf, &ca);
                            let (a, b) = hs.split_at(hs.len() / 2);
                            for part in [a, b] {
                                let mut rec = vec![0x16, 3, 1];
                                rec.extend_from_slice(&(part.len() as u16).to_be_bytes());
                                rec.extend_from_slice(part);
                                s.write_all(&rec).await.unwrap();
                            }
                            let mut sink = [0u8; 64];
                            let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut sink))
                                .await;
                        });
                    }
                    Mode::Plain => unreachable!(),
                }
            }
        });
        (addr, conns)
    }

    /// Reads what the client sends, answers and waits for it to close: closing
    /// with unread data would cause an RST (on Windows the client would lose the reply).
    async fn answer_then_wait(mut s: tokio::net::TcpStream, reply: &'static [u8]) {
        let mut buf = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await;
        let _ = s.write_all(reply).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
    }

    /// ServerHello (TLS 1.0, TLS_RSA_WITH_AES_128_CBC_SHA) + Certificate + ServerHelloDone.
    fn legacy_flight(leaf: &CertificateDer<'_>, ca: &CertificateDer<'_>) -> Vec<u8> {
        fn msg(out: &mut Vec<u8>, typ: u8, body: &[u8]) {
            out.push(typ);
            out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            out.extend_from_slice(body);
        }
        let mut out = Vec::new();
        let mut sh = vec![3, 1];
        sh.extend_from_slice(&[7u8; 32]);
        sh.push(0);
        sh.extend_from_slice(&[0x00, 0x2f, 0]);
        msg(&mut out, 2, &sh);
        let mut list = Vec::new();
        for c in [leaf.as_ref(), ca.as_ref()] {
            list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
            list.extend_from_slice(c);
        }
        let mut cert = (list.len() as u32).to_be_bytes()[1..].to_vec();
        cert.extend_from_slice(&list);
        msg(&mut out, 11, &cert);
        msg(&mut out, 14, &[]);
        out
    }

    /// Server that closes on TLS 1.3: second attempt with TLS 1.2 only,
    /// complete handshake and verified chain.
    #[tokio::test]
    async fn ripiego_tls12_se_reset_su_tls13() {
        let p = pki();
        let (addr, conns) = server(Mode::ResetOnTls13, &p).await;
        let r = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap();
        assert_eq!(conns.load(Ordering::SeqCst), 2);
        assert_eq!(r.tls_version, "TLSv1.2");
        assert!(r.cipher.starts_with("TLS_ECDHE_"), "{}", r.cipher);
        assert!(r.verified, "{}", r.verify_error);
        assert!(!r.partial);
        assert!(r.compat.contains("solo TLS 1.2"), "{}", r.compat);
        assert_eq!(r.chain, vec!["legacy.test", "NTB Test CA"]);
        assert_eq!(r.port, addr.port());
    }

    /// Server with only ciphers that rustls lacks: the probe reads the certificate.
    #[tokio::test]
    async fn sonda_legacy_legge_il_certificato() {
        let p = pki();
        let (addr, conns) = server(Mode::OnlyRsaCbc, &p).await;
        let r = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap();
        assert_eq!(conns.load(Ordering::SeqCst), 3);
        assert!(r.partial);
        assert_eq!(r.tls_version, "TLSv1.0");
        assert_eq!(r.cipher, "TLS_RSA_WITH_AES_128_CBC_SHA");
        assert!(r.verified, "{}", r.verify_error);
        assert_eq!(r.sans, vec!["DNS: localhost"]);
        assert_eq!(r.chain, vec!["legacy.test", "NTB Test CA"]);
        assert!(r.compat.contains("senza completare"), "{}", r.compat);

        // Same server, name that the certificate does not cover: chain read, name reported.
        let r = inspect_with("127.0.0.1", addr, Some(trust(&p.ca)))
            .await
            .unwrap();
        assert!(r.partial && !r.verified);
        assert!(r.verify_error.contains("non copre"), "{}", r.verify_error);
    }

    /// Server that rejects everything: error summarising the three attempts.
    #[tokio::test]
    async fn rifiuto_totale() {
        let p = pki();
        let (addr, conns) = server(Mode::ResetAll, &p).await;
        let e = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap_err();
        assert_eq!(conns.load(Ordering::SeqCst), 3);
        assert!(e.contains("rifiuta TLS 1.3, TLS 1.2"), "{e}");

        let (addr, _) = server(Mode::AlertAll, &p).await;
        let e = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap_err();
        assert!(e.contains("handshake_failure"), "{e}");
    }

    /// Non-TLS port: no fallback (a single attempt, the usual error).
    #[tokio::test]
    async fn porta_non_tls_senza_ripiego() {
        let p = pki();
        let (addr, conns) = server(Mode::Plain, &p).await;
        let e = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap_err();
        assert_eq!(conns.load(Ordering::SeqCst), 1);
        assert!(e.starts_with("Handshake TLS fallito"), "{e}");
        assert!(!e.contains("compatibilità"), "{e}");
    }

    // ---- Full analysis, STARTTLS and scan ----------------------------------

    /// rustls server (TLS 1.3 and 1.2) that accepts every incoming connection;
    /// with `smtp` it first runs the SMTP dialogue up to STARTTLS.
    async fn tls_server(p: &Pki, smtp: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![p.leaf.clone(), p.ca.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.key.clone())),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let count = conns.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if smtp {
                        let mut buf = [0u8; 256];
                        s.write_all(b"220 mail01.corp.example ESMTP\r\n")
                            .await
                            .unwrap();
                        let _ = s.read(&mut buf).await;
                        s.write_all(b"250-mail01.corp.example\r\n250 STARTTLS\r\n")
                            .await
                            .unwrap();
                        let _ = s.read(&mut buf).await;
                        s.write_all(b"220 Go ahead\r\n").await.unwrap();
                    }
                    if let Ok(mut t) = acc.accept(s).await {
                        let mut sink = [0u8; 64];
                        let _ =
                            tokio::time::timeout(Duration::from_secs(2), t.read(&mut sink)).await;
                    }
                });
            }
        });
        (addr, conns)
    }

    fn req(addr: SocketAddr, protocol: &str, scan: bool) -> TlsReq {
        TlsReq {
            host: "127.0.0.1".into(),
            port: Some(addr.port() as u32),
            protocol: protocol.into(),
            sni: "localhost".into(),
            scan,
        }
    }

    fn status_of<'a>(r: &'a TlsResult, name: &str) -> &'a str {
        r.checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("manca il controllo {name}: {:?}", r.checks))
            .status
    }

    /// Full analysis with SNI different from the host, and scan: the rustls server accepts
    /// the three TLS 1.3 suites and, with an ECDSA certificate, three TLS 1.2 suites.
    #[tokio::test]
    async fn analisi_e_scansione() {
        let p = pki();
        let (addr, _) = tls_server(&p, false).await;
        let events = Mutex::new(Vec::new());
        let r = run_with(
            req(addr, "", true),
            &Stop::new(),
            |e| events.lock().unwrap().push(e),
            Some(trust(&p.ca)),
        )
        .await
        .unwrap();
        assert!(r.verified, "{}", r.verify_error);
        assert_eq!(r.host, "127.0.0.1");
        assert_eq!(r.sni, "localhost");
        assert_eq!(r.protocol, "TLS diretto");
        assert_eq!(r.ocsp_stapled, Some(false));
        let c = r.cert.as_ref().unwrap();
        assert_eq!(c.key, "ECDSA P-256");
        assert_eq!(c.name, "legacy.test");
        assert_eq!(
            r.chain_info
                .iter()
                .map(|e| (e.role, e.sent))
                .collect::<Vec<_>>(),
            vec![("Server", "sent"), ("Radice", "sent")]
        );
        assert_eq!(status_of(&r, "Attendibilità"), "ok");
        assert_eq!(status_of(&r, "Nome"), "ok");
        assert_eq!(status_of(&r, "Radice inviata"), "info");
        assert_eq!(status_of(&r, "Negoziato"), "ok");
        // same certificate even without SNI: nothing reported
        assert!(!r.checks.iter().any(|c| c.name == "SNI"));

        let s = r.scan.as_ref().unwrap();
        assert!(!s.stopped && s.note.is_empty(), "{}", s.note);
        let got: Vec<(&str, bool, usize)> = s
            .versions
            .iter()
            .map(|v| (v.name, v.accepted, v.ciphers.len()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("TLS 1.3", true, 3),
                ("TLS 1.2", true, 3),
                ("TLS 1.1", false, 0),
                ("TLS 1.0", false, 0)
            ]
        );
        assert!(s.versions[1]
            .ciphers
            .iter()
            .all(|c| c.name.starts_with("TLS_ECDHE_ECDSA_") && c.level.is_empty()));
        // 3 + (3 accepted + 1 rejection) + 1 + 1 connections
        assert_eq!(s.tried, 9);
        assert_eq!(status_of(&r, "TLS 1.3 e TLS 1.2"), "ok");
        assert_eq!(status_of(&r, "Versioni obsolete"), "ok");
        assert_eq!(status_of(&r, "Cipher"), "ok");

        // events: first the result without scan, then the suites as they come
        let ev = events.lock().unwrap();
        assert!(matches!(&ev[0], TlsEvent::Result(x) if x.scan.is_none() && !x.checks.is_empty()));
        let ciphers = ev
            .iter()
            .filter(|e| matches!(e, TlsEvent::Scan(scan::ScanEvent::Cipher { .. })))
            .count();
        assert_eq!(ciphers, 6);
        let json = serde_json::to_string(&*ev).unwrap();
        assert!(
            json.contains(r#"{"scan":{"cipher":{"version":"TLS 1.3""#),
            "{json}"
        );
        assert!(
            json.contains(r#"{"scan":{"progress":{"tried":1}}}"#),
            "{json}"
        );
    }

    /// STARTTLS over SMTP chosen from the UI, without scan: no events.
    #[tokio::test]
    async fn starttls_smtp_e_ferma() {
        let p = pki();
        let (addr, conns) = tls_server(&p, true).await;
        let r = run_with(
            req(addr, "smtp", false),
            &Stop::new(),
            |_| panic!("nessun evento senza scansione"),
            Some(trust(&p.ca)),
        )
        .await
        .unwrap();
        assert!(r.verified, "{}", r.verify_error);
        assert_eq!(r.protocol, "SMTP con STARTTLS");
        assert_eq!(r.tls_version, "TLSv1.3");
        assert!(r.scan.is_none());
        // handshake + test without SNI
        assert_eq!(conns.load(Ordering::SeqCst), 2);

        // the same server taken as direct TLS: the SMTP banner is not TLS
        let e = run_with(
            req(addr, "tls", false),
            &Stop::new(),
            |_| {},
            Some(trust(&p.ca)),
        )
        .await
        .unwrap_err();
        assert!(e.starts_with("Handshake TLS fallito"), "{e}");

        // name not covered by the certificate
        let mut q = req(addr, "smtp", false);
        q.sni = "altro.corp.example".into();
        let r = run_with(q, &Stop::new(), |_| {}, Some(trust(&p.ca)))
            .await
            .unwrap();
        assert!(!r.verified);
        assert_eq!(status_of(&r, "Nome"), "err");
        assert_eq!(status_of(&r, "Attendibilità"), "err");

        // already stopped: no connections
        let before = conns.load(Ordering::SeqCst);
        let stop = Stop::new();
        stop.stop();
        let e = run_with(req(addr, "smtp", true), &stop, |_| {}, Some(trust(&p.ca)))
            .await
            .unwrap_err();
        assert_eq!(e, "Controllo fermato.");
        assert_eq!(conns.load(Ordering::SeqCst), before);

        assert!(
            run_with(req(addr, "ftp", false), &Stop::new(), |_| {}, None)
                .await
                .unwrap_err()
                .contains("Protocollo non valido")
        );
    }

    /// Scan stopped after the first suite: partial result, certificate read anyway.
    #[tokio::test]
    async fn scansione_fermata() {
        let p = pki();
        let (addr, _) = tls_server(&p, false).await;
        let stop = Stop::new();
        let r = run_with(
            req(addr, "", true),
            &stop,
            |e| {
                if matches!(e, TlsEvent::Scan(scan::ScanEvent::Cipher { .. })) {
                    stop.stop();
                }
            },
            Some(trust(&p.ca)),
        )
        .await
        .unwrap();
        let s = r.scan.as_ref().unwrap();
        assert!(s.stopped);
        assert_eq!(s.versions.len(), 1);
        assert_eq!(s.versions[0].ciphers.len(), 1);
        assert_eq!(status_of(&r, "Scansione"), "info");
        assert!(r.verified);
    }

    /// Chain requested from the system: on Windows `CertGetCertificateChain` must return
    /// server and CA even if the test CA is not trusted; elsewhere there is none.
    #[tokio::test]
    async fn catena_del_sistema() {
        let p = pki();
        let sent = vec![p.leaf.as_ref().to_vec(), p.ca.as_ref().to_vec()];
        let built = system_chain(sent.clone()).await;
        assert_eq!(built.is_some(), cfg!(windows));
        if let Some(b) = built {
            assert_eq!(b, sent);
            let (entries, _) = cert::chain(&sent, Some(&b), false, util::now_unix() as i64);
            assert_eq!(entries.len(), 2);
            assert_eq!((entries[1].role, entries[1].sent), ("Radice", "sent"));
        }
        // only the server certificate: the chain stops there (no CA to find)
        if let Some(b) = system_chain(sent[..1].to_vec()).await {
            assert_eq!(b, sent[..1]);
        }
    }

    #[tokio::test]
    async fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let p = pki();
        let (addr, _) = server(Mode::ResetAll, &p).await;
        let e = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap_err();
        assert!(
            e.starts_with("TLS handshake failed: the server rejects"),
            "{e}"
        );
        assert!(!e.contains("rifiuta"), "{e}");
        let (addr, _) = server(Mode::Plain, &p).await;
        let e = inspect_with("localhost", addr, Some(trust(&p.ca)))
            .await
            .unwrap_err();
        assert!(e.starts_with("TLS handshake failed"), "{e}");
        let mut q = req(addr, "tls", false);
        q.port = Some(70000);
        let e = run_with(q, &Stop::new(), |_| {}, None).await.unwrap_err();
        assert_eq!(e, "Invalid port");
        let name = ServerName::try_from("localhost").unwrap();
        let d = describe(
            &rustls::Error::InvalidCertificate(CertificateError::Expired),
            &name,
        );
        assert_eq!(d, "Certificate expired");
    }

    #[test]
    fn client_hello_di_compatibilita() {
        let h = legacy::client_hello("srv01.corp.example").unwrap();
        assert_eq!(&h[..3], &[0x16, 3, 1]);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 1); // ClientHello
        assert_eq!(&h[9..11], &[3, 3]);
        // no supported_versions (43): no TLS 1.3
        let find = |id: u16| h.windows(2).any(|w| w == id.to_be_bytes());
        assert!(find(0x002f) && find(0x000a) && find(0xc013));
        assert!(h.windows(18).any(|w| w == b"srv01.corp.example"));
        // with an IP no SNI
        let h = legacy::client_hello("192.0.2.10").unwrap();
        assert!(!h.windows(10).any(|w| w == b"192.0.2.10"));
        assert_eq!(legacy::cipher_name(0x000a), "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!(legacy::cipher_name(0x1234), "0x1234");
        assert_eq!(version_name(0x0300), "SSLv3");
        assert_eq!(version_name(0x0302), "TLSv1.1");
    }
}
