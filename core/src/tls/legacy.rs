//! Compatibility probe for legacy TLS servers: a hand-built ClientHello that offers
//! TLS 1.0–1.2 (without the `supported_versions` extension, hence without TLS 1.3) and
//! also ciphers that rustls does not implement (CBC, RSA exchange, DHE, 3DES, RC4). Up to
//! TLS 1.2 the ServerHello and Certificate travel in clear: they are read and the
//! connection is closed, without completing the handshake. It only serves to see the
//! certificate: no application data.

use crate::{t, tf, Result};
use rustls::pki_types::CertificateDer;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Ciphers offered, in order of preference, with the IANA name.
pub(crate) const CIPHERS: &[(u16, &str)] = &[
    (0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    (0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    (0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
];

/// IANA name of the cipher chosen by the server (or the code, if it is not among those offered).
pub(crate) fn cipher_name(c: u16) -> String {
    CIPHERS
        .iter()
        .find(|(id, _)| *id == c)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("0x{c:04X}"))
}

/// What the probe read from the server.
#[derive(Debug)]
pub(crate) struct Probe {
    pub version: u16,
    pub cipher: u16,
    pub certs: Vec<CertificateDer<'static>>,
}

const MAX_BYTES: usize = 256 * 1024;

fn ext(out: &mut Vec<u8>, id: u16, body: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Compatibility ClientHello (record 1.0, client_version 1.2, no TLS 1.3).
pub(crate) fn client_hello(host: &str) -> Result<Vec<u8>> {
    let all: Vec<u16> = CIPHERS.iter().map(|(c, _)| *c).collect();
    client_hello_with(host, 0x0303, &all)
}

/// The ciphers that exist only from TLS 1.2 (AEAD and SHA-2 MAC): pointless to offer them
/// with an earlier version.
pub(crate) fn tls12_only(name: &str) -> bool {
    name.contains("_GCM_")
        || name.contains("CHACHA20")
        || name.ends_with("_SHA256")
        || name.ends_with("_SHA384")
}

/// ClientHello with the given maximum version and ciphers (TLS 1.0–1.2, never 1.3):
/// used by the scan, which asks the server for one version and one group of ciphers at a time.
pub(crate) fn client_hello_with(host: &str, version: u16, ciphers: &[u16]) -> Result<Vec<u8>> {
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random)
        .map_err(|e| tf!("Generatore casuale: {e}", "Random generator: {e}"))?;

    let mut exts = Vec::new();
    // server_name: only for names, not for IP addresses (RFC 6066).
    if host.parse::<std::net::IpAddr>().is_err() {
        let h = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((h.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(h.len() as u16).to_be_bytes());
        sni.extend_from_slice(h);
        ext(&mut exts, 0x0000, &sni);
    }
    // supported_groups: x25519, P-256, P-384, P-521.
    ext(
        &mut exts,
        0x000a,
        &[0, 8, 0, 0x1d, 0, 0x17, 0, 0x18, 0, 0x19],
    );
    // ec_point_formats: uncompressed.
    ext(&mut exts, 0x000b, &[1, 0]);
    // signature_algorithms, including RSA/ECDSA with SHA-1 for old servers.
    let algs: [u16; 11] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0603, 0x0201, 0x0203,
    ];
    let mut sa = ((algs.len() * 2) as u16).to_be_bytes().to_vec();
    for a in algs {
        sa.extend_from_slice(&a.to_be_bytes());
    }
    ext(&mut exts, 0x000d, &sa);
    // empty extended_master_secret and renegotiation_info.
    ext(&mut exts, 0x0017, &[]);
    ext(&mut exts, 0xff01, &[0]);

    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(0); // empty session_id
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // compression: none
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![1u8];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    Ok(rec)
}

/// Localised description of the most common alerts of a server that refuses.
pub(crate) fn alert_text(code: u8) -> String {
    let what = match code {
        40 => t!(
            "nessuna cipher o parametro in comune (handshake_failure)",
            "no common cipher or parameter (handshake_failure)"
        ),
        70 => t!(
            "versione del protocollo non accettata (protocol_version)",
            "protocol version not accepted (protocol_version)"
        ),
        71 => t!(
            "sicurezza insufficiente (insufficient_security)",
            "insufficient security (insufficient_security)"
        ),
        47 => t!(
            "parametro non accettato (illegal_parameter)",
            "parameter not accepted (illegal_parameter)"
        ),
        50 => t!(
            "messaggio non decodificabile (decode_error)",
            "message cannot be decoded (decode_error)"
        ),
        80 => t!(
            "errore interno del server (internal_error)",
            "internal server error (internal_error)"
        ),
        112 => t!(
            "nome del server sconosciuto (unrecognized_name)",
            "unknown server name (unrecognized_name)"
        ),
        _ => "",
    };
    if what.is_empty() {
        tf!("alert TLS {code}", "TLS alert {code}")
    } else {
        tf!("alert TLS: {what}", "TLS alert: {what}")
    }
}

fn u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

/// Parses the accumulated handshake messages. `Some` when both ServerHello and
/// Certificate are present (or ServerHelloDone without a certificate: error).
fn parse(hs: &[u8], out: &mut Option<(u16, u16)>) -> Result<Option<Vec<CertificateDer<'static>>>> {
    let mut i = 0;
    while hs.len() >= i + 4 {
        let typ = hs[i];
        let len = u24(&hs[i + 1..i + 4]);
        if hs.len() < i + 4 + len {
            return Ok(None); // message not complete yet
        }
        let m = &hs[i + 4..i + 4 + len];
        match typ {
            2 => {
                // ServerHello: version, random(32), session_id, cipher
                if m.len() < 38 {
                    return Err(t!("ServerHello troppo corto", "ServerHello too short").into());
                }
                let ver = u16::from_be_bytes([m[0], m[1]]);
                let sid = m[34] as usize;
                if m.len() < 35 + sid + 2 {
                    return Err(t!("ServerHello troppo corto", "ServerHello too short").into());
                }
                let cipher = u16::from_be_bytes([m[35 + sid], m[36 + sid]]);
                *out = Some((ver, cipher));
            }
            11 => {
                if out.is_none() {
                    return Err(t!(
                        "Certificate prima del ServerHello",
                        "Certificate before the ServerHello"
                    )
                    .into());
                }
                if m.len() < 3 {
                    return Err(t!(
                        "Messaggio Certificate non valido",
                        "Invalid Certificate message"
                    )
                    .into());
                }
                let total = u24(&m[..3]);
                let list = m.get(3..3 + total).ok_or(t!(
                    "Messaggio Certificate non valido",
                    "Invalid Certificate message"
                ))?;
                let mut certs = Vec::new();
                let mut j = 0;
                while j + 3 <= list.len() {
                    let l = u24(&list[j..j + 3]);
                    let c = list.get(j + 3..j + 3 + l).ok_or(t!(
                        "Messaggio Certificate non valido",
                        "Invalid Certificate message"
                    ))?;
                    certs.push(CertificateDer::from(c.to_vec()));
                    j += 3 + l;
                }
                if certs.is_empty() {
                    return Err(t!(
                        "Il server non ha inviato certificati",
                        "The server sent no certificates"
                    )
                    .into());
                }
                return Ok(Some(certs));
            }
            14 => {
                return Err(t!(
                    "Il server non ha inviato certificati",
                    "The server sent no certificates"
                )
                .into())
            }
            _ => {}
        }
        i += 4 + len;
    }
    Ok(None)
}

/// Sends the compatibility ClientHello and reads version, cipher and chain.
pub(crate) async fn probe<IO>(host: &str, mut io: IO) -> Result<Probe>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let hello = client_hello(host)?;
    tokio::time::timeout(Duration::from_secs(10), async move {
        io.write_all(&hello)
            .await
            .map_err(|e| tf!("invio del ClientHello: {e}", "sending the ClientHello: {e}"))?;
        let mut hs = Vec::new();
        let mut hello_seen = None;
        let mut total = 0usize;
        loop {
            let mut head = [0u8; 5];
            io.read_exact(&mut head).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    t!(
                        "il server ha chiuso la connessione",
                        "the server closed the connection"
                    )
                    .to_string()
                } else {
                    e.to_string()
                }
            })?;
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            total += 5 + len;
            if len > 18 * 1024 || total > MAX_BYTES {
                return Err(t!(
                    "risposta non TLS o troppo grande",
                    "response is not TLS or too large"
                )
                .into());
            }
            let mut body = vec![0u8; len];
            io.read_exact(&mut body)
                .await
                .map_err(|e| tf!("risposta interrotta: {e}", "response interrupted: {e}"))?;
            match head[0] {
                0x16 => {
                    hs.extend_from_slice(&body);
                    if let Some(certs) = parse(&hs, &mut hello_seen)? {
                        let (version, cipher) = hello_seen.unwrap_or_default();
                        let _ = io.shutdown().await;
                        return Ok(Probe {
                            version,
                            cipher,
                            certs,
                        });
                    }
                }
                0x15 if body.len() >= 2 => return Err(alert_text(body[1])),
                _ => return Err(t!("risposta non TLS", "response is not TLS").into()),
            }
        }
    })
    .await
    .map_err(|_| {
        t!(
            "timeout della sonda di compatibilità",
            "compatibility probe timeout"
        )
        .to_string()
    })?
}

/// Why a scan offer did not get a ServerHello.
#[derive(Debug, PartialEq)]
pub(crate) enum HelloError {
    /// The server rejected the offer (alert, close, reset): normal outcome.
    Rejected(String),
    /// Timeout or non-TLS response: the scan cannot continue.
    Failed(String),
}

/// Sends a ClientHello and reads only the ServerHello: version and cipher chosen by the
/// server. It does not read the certificate and does not complete the handshake.
pub(crate) async fn server_hello<IO>(
    mut io: IO,
    hello: Vec<u8>,
) -> std::result::Result<(u16, u16), HelloError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    use std::io::ErrorKind as K;
    let closed = |e: std::io::Error| match e.kind() {
        K::UnexpectedEof | K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe => {
            HelloError::Rejected(
                t!(
                    "connessione chiusa dal server",
                    "connection closed by the server"
                )
                .into(),
            )
        }
        _ => HelloError::Failed(e.to_string()),
    };
    let work = async move {
        io.write_all(&hello).await.map_err(closed)?;
        let mut hs = Vec::new();
        loop {
            let mut head = [0u8; 5];
            io.read_exact(&mut head).await.map_err(closed)?;
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            if len > 18 * 1024 || hs.len() > MAX_BYTES {
                return Err(HelloError::Failed(
                    t!("risposta non TLS", "response is not TLS").into(),
                ));
            }
            let mut body = vec![0u8; len];
            io.read_exact(&mut body).await.map_err(closed)?;
            match head[0] {
                0x16 => {
                    hs.extend_from_slice(&body);
                    if hs.len() >= 4 && hs[0] != 2 {
                        return Err(HelloError::Failed(
                            t!("risposta TLS inattesa", "unexpected TLS response").into(),
                        ));
                    }
                    if hs.len() >= 4 && hs.len() >= 4 + u24(&hs[1..4]) {
                        let mut seen = None;
                        // a Certificate in the same record is of no interest
                        let _ = parse(&hs[..4 + u24(&hs[1..4])], &mut seen);
                        let _ = io.shutdown().await;
                        return seen.ok_or_else(|| {
                            HelloError::Failed(
                                t!("ServerHello non valido", "Invalid ServerHello").into(),
                            )
                        });
                    }
                }
                0x15 if body.len() >= 2 => return Err(HelloError::Rejected(alert_text(body[1]))),
                _ => {
                    return Err(HelloError::Failed(
                        t!("risposta non TLS", "response is not TLS").into(),
                    ))
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(8), work)
        .await
        .map_err(|_| {
            HelloError::Failed(
                t!(
                    "timeout in attesa del ServerHello",
                    "timeout waiting for the ServerHello"
                )
                .into(),
            )
        })?
}
