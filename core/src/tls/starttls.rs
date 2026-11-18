//! Switching to TLS on protocols that start in clear: SMTP (STARTTLS), IMAP
//! (STARTTLS), POP3 (STLS) and RDP (X.224 negotiation). After `prepare` the stream is
//! ready for the ClientHello. No authentication: it only asks to switch to TLS.

use crate::{t, tf, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    /// TLS from the first byte (HTTPS, SMTPS, IMAPS, LDAPS…).
    Tls,
    Smtp,
    Imap,
    Pop3,
    Rdp,
}

impl Proto {
    /// From the UI choice; empty or "auto" = from the port.
    pub fn parse(s: &str, port: u16) -> Result<Proto> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => match port {
                25 | 587 => Proto::Smtp,
                143 => Proto::Imap,
                110 => Proto::Pop3,
                3389 => Proto::Rdp,
                _ => Proto::Tls,
            },
            "tls" => Proto::Tls,
            "smtp" => Proto::Smtp,
            "imap" => Proto::Imap,
            "pop3" => Proto::Pop3,
            "rdp" => Proto::Rdp,
            other => {
                return Err(tf!(
                    "Protocollo non valido: {other}",
                    "Invalid protocol: {other}"
                ))
            }
        })
    }

    pub fn key(self) -> &'static str {
        match self {
            Proto::Tls => "tls",
            Proto::Smtp => "smtp",
            Proto::Imap => "imap",
            Proto::Pop3 => "pop3",
            Proto::Rdp => "rdp",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Proto::Tls => t!("TLS diretto", "Direct TLS"),
            Proto::Smtp => t!("SMTP con STARTTLS", "SMTP with STARTTLS"),
            Proto::Imap => t!("IMAP con STARTTLS", "IMAP with STARTTLS"),
            Proto::Pop3 => t!("POP3 con STLS", "POP3 with STLS"),
            Proto::Rdp => "RDP",
        }
    }
}

const MAX_LINE: usize = 2048;
const MAX_LINES: usize = 100;

/// One line, read one byte at a time: nothing must be left in a buffer when the
/// handshake starts.
async fn line<IO: AsyncRead + Unpin>(io: &mut IO) -> Result<String> {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match io.read(&mut b).await {
            Ok(0) => {
                return Err(t!(
                    "il server ha chiuso la connessione",
                    "the server closed the connection"
                )
                .into())
            }
            Ok(_) => {}
            Err(e) => return Err(tf!("lettura interrotta: {e}", "read interrupted: {e}")),
        }
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
        if out.len() > MAX_LINE {
            return Err(t!(
                "risposta troppo lunga: non sembra il protocollo scelto",
                "response too long: it does not look like the chosen protocol"
            )
            .into());
        }
    }
    Ok(String::from_utf8_lossy(&out).trim_end().to_string())
}

/// SMTP reply, possibly multi-line ("250-…" then "250 …"): code and lines.
async fn smtp_reply<IO: AsyncRead + Unpin>(io: &mut IO) -> Result<(String, Vec<String>)> {
    let mut lines = Vec::new();
    loop {
        let l = line(io).await?;
        let last = l.as_bytes().get(3) != Some(&b'-');
        lines.push(l);
        if last {
            break;
        }
        if lines.len() > MAX_LINES {
            return Err(t!("risposta SMTP troppo lunga", "SMTP response too long").into());
        }
    }
    let code: String = lines.last().unwrap().chars().take(3).collect();
    Ok((code, lines))
}

async fn send<IO: AsyncWrite + Unpin>(io: &mut IO, data: &[u8]) -> Result<()> {
    io.write_all(data)
        .await
        .map_err(|e| tf!("invio interrotto: {e}", "send interrupted: {e}"))
}

async fn smtp<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO) -> Result<()> {
    let (code, lines) = smtp_reply(io).await?;
    if code != "220" {
        return Err(tf!(
            "il server SMTP non è pronto: {}",
            "the SMTP server is not ready: {}",
            lines.last().unwrap()
        ));
    }
    send(io, b"EHLO nettoolbox.invalid\r\n").await?;
    let (code, lines) = smtp_reply(io).await?;
    if code != "250" {
        return Err(tf!(
            "EHLO rifiutato: {}",
            "EHLO rejected: {}",
            lines.last().unwrap()
        ));
    }
    let offered = lines.iter().any(|l| {
        l.get(4..)
            .is_some_and(|x| x.trim().eq_ignore_ascii_case("STARTTLS"))
    });
    if !offered {
        return Err(t!(
            "il server SMTP non offre STARTTLS",
            "the SMTP server does not offer STARTTLS"
        )
        .into());
    }
    send(io, b"STARTTLS\r\n").await?;
    let (code, lines) = smtp_reply(io).await?;
    if code != "220" {
        return Err(tf!(
            "STARTTLS rifiutato: {}",
            "STARTTLS rejected: {}",
            lines.last().unwrap()
        ));
    }
    Ok(())
}

async fn imap<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO) -> Result<()> {
    let greet = line(io).await?;
    if !greet.to_ascii_uppercase().starts_with("* OK") {
        return Err(tf!(
            "il server IMAP non è pronto: {greet}",
            "the IMAP server is not ready: {greet}"
        ));
    }
    send(io, b"a1 STARTTLS\r\n").await?;
    for _ in 0..MAX_LINES {
        let l = line(io).await?;
        let up = l.to_ascii_uppercase();
        if up.starts_with("A1 OK") {
            return Ok(());
        }
        if up.starts_with("A1 ") {
            return Err(tf!("STARTTLS rifiutato: {l}", "STARTTLS rejected: {l}"));
        }
    }
    Err(t!("risposta IMAP troppo lunga", "IMAP response too long").into())
}

async fn pop3<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO) -> Result<()> {
    let greet = line(io).await?;
    if !greet.starts_with("+OK") {
        return Err(tf!(
            "il server POP3 non è pronto: {greet}",
            "the POP3 server is not ready: {greet}"
        ));
    }
    send(io, b"STLS\r\n").await?;
    let l = line(io).await?;
    if !l.starts_with("+OK") {
        return Err(tf!("STLS rifiutato: {l}", "STLS rejected: {l}"));
    }
    Ok(())
}

/// X.224 Connection Request with RDP Negotiation Request: TLS or NLA (CredSSP), which
/// starts with a TLS handshake anyway. No cookie, no user name.
pub(crate) const RDP_REQUEST: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, // TPKT, 19 bytes
    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 Connection Request
    0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ, 8 bytes
    0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL | PROTOCOL_HYBRID
];

async fn rdp<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO) -> Result<()> {
    send(io, &RDP_REQUEST).await?;
    let mut head = [0u8; 4];
    io.read_exact(&mut head).await.map_err(|_| {
        t!(
            "il server ha chiuso la connessione: non sembra RDP",
            "the server closed the connection: it does not look like RDP"
        )
        .to_string()
    })?;
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    if head[0] != 3 || !(11..=64).contains(&len) {
        return Err(t!("risposta non RDP", "response is not RDP").into());
    }
    let mut body = vec![0u8; len - 4];
    io.read_exact(&mut body).await.map_err(|e| {
        tf!(
            "risposta RDP interrotta: {e}",
            "RDP response interrupted: {e}"
        )
    })?;
    // body: X.224 Connection Confirm (7 bytes) + RDP_NEG_RSP / RDP_NEG_FAILURE (8 bytes)
    if body.get(1) != Some(&0xd0) {
        return Err(t!("risposta RDP inattesa", "unexpected RDP response").into());
    }
    match body.get(7) {
        Some(2) => Ok(()),
        Some(3) => {
            let code = body.get(11).copied().unwrap_or(0);
            Err(match code {
                1 => t!(
                    "il server RDP richiede TLS ma non lo ha accettato",
                    "the RDP server requires TLS but did not accept it"
                )
                .into(),
                2 => t!(
                    "il server RDP non usa TLS (solo la sicurezza RDP classica)",
                    "the RDP server does not use TLS (classic RDP security only)"
                )
                .into(),
                3 => t!(
                    "il server RDP non ha un certificato",
                    "the RDP server has no certificate"
                )
                .into(),
                _ => tf!(
                    "il server RDP rifiuta la negoziazione (codice {code})",
                    "the RDP server rejects the negotiation (code {code})"
                ),
            })
        }
        _ => Err(t!(
            "il server RDP non usa TLS (solo la sicurezza RDP classica)",
            "the RDP server does not use TLS (classic RDP security only)"
        )
        .into()),
    }
}

/// Brings the stream to the point where the TLS handshake starts.
pub(crate) async fn prepare<IO>(io: &mut IO, proto: Proto) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let work = async {
        match proto {
            Proto::Tls => Ok(()),
            Proto::Smtp => smtp(io).await,
            Proto::Imap => imap(io).await,
            Proto::Pop3 => pop3(io).await,
            Proto::Rdp => rdp(io).await,
        }
    };
    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .map_err(|_| {
            tf!(
                "Timeout in attesa del server ({})",
                "Timeout waiting for the server ({})",
                proto.label()
            )
        })?
        .map_err(|e| format!("{}: {e}", proto.label()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocollo_dalla_porta() {
        assert_eq!(Proto::parse("", 443).unwrap(), Proto::Tls);
        assert_eq!(Proto::parse("auto", 25).unwrap(), Proto::Smtp);
        assert_eq!(Proto::parse("auto", 587).unwrap(), Proto::Smtp);
        assert_eq!(Proto::parse("auto", 465).unwrap(), Proto::Tls);
        assert_eq!(Proto::parse("auto", 143).unwrap(), Proto::Imap);
        assert_eq!(Proto::parse("auto", 993).unwrap(), Proto::Tls);
        assert_eq!(Proto::parse("auto", 110).unwrap(), Proto::Pop3);
        assert_eq!(Proto::parse("auto", 3389).unwrap(), Proto::Rdp);
        assert_eq!(Proto::parse("TLS", 25).unwrap(), Proto::Tls);
        assert_eq!(Proto::parse("rdp", 13389).unwrap(), Proto::Rdp);
        assert!(Proto::parse("ftp", 21).unwrap_err().contains("ftp"));
    }

    #[test]
    fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let e = Proto::parse("ftp", 21).unwrap_err();
        assert!(e.starts_with("Invalid protocol"), "{e}");
        assert_eq!(Proto::Tls.label(), "Direct TLS");
        assert_eq!(Proto::Smtp.label(), "SMTP with STARTTLS");
    }

    /// Fake server: sends `script` in pieces, one after each line received from the client
    /// (the first immediately), and returns what the client wrote.
    async fn talk(proto: Proto, script: &[&[u8]]) -> (Result<()>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let script: Vec<Vec<u8>> = script.iter().map(|s| s.to_vec()).collect();
        let srv = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            let lead = usize::from(proto != Proto::Rdp);
            if lead == 1 {
                server.write_all(&script[0]).await.unwrap();
            }
            for part in &script[lead..] {
                match server.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
                server.write_all(part).await.unwrap();
            }
            // what the client still sends (nothing, if it stopped)
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(50), server.read(&mut buf)).await
            {
                got.extend_from_slice(&buf[..n]);
            }
            got
        });
        let r = prepare(&mut client, proto).await;
        drop(client);
        (r, srv.await.unwrap())
    }

    #[tokio::test]
    async fn smtp_starttls() {
        let (r, got) = talk(
            Proto::Smtp,
            &[
                b"220-mail01.corp.example ESMTP\r\n220 pronto\r\n",
                b"250-mail01.corp.example\r\n250-SIZE 1000\r\n250-STARTTLS\r\n250 HELP\r\n",
                b"220 Go ahead\r\n",
            ],
        )
        .await;
        r.unwrap();
        assert_eq!(got, b"EHLO nettoolbox.invalid\r\nSTARTTLS\r\n");

        let (r, got) = talk(
            Proto::Smtp,
            &[
                b"220 mail01.corp.example\r\n",
                b"250-mail01\r\n250 HELP\r\n",
            ],
        )
        .await;
        assert!(r.unwrap_err().contains("non offre STARTTLS"));
        assert_eq!(got, b"EHLO nettoolbox.invalid\r\n");

        let (r, _) = talk(Proto::Smtp, &[b"554 No service\r\n"]).await;
        assert!(r.unwrap_err().contains("554 No service"));
    }

    #[tokio::test]
    async fn imap_e_pop3() {
        let (r, got) = talk(
            Proto::Imap,
            &[
                b"* OK [CAPABILITY IMAP4rev1 STARTTLS] pronto\r\n",
                b"* note\r\na1 OK Begin TLS\r\n",
            ],
        )
        .await;
        r.unwrap();
        assert_eq!(got, b"a1 STARTTLS\r\n");
        let (r, _) = talk(Proto::Imap, &[b"* OK pronto\r\n", b"a1 BAD no\r\n"]).await;
        assert!(r.unwrap_err().contains("a1 BAD no"));

        let (r, got) = talk(Proto::Pop3, &[b"+OK pronto\r\n", b"+OK Begin TLS\r\n"]).await;
        r.unwrap();
        assert_eq!(got, b"STLS\r\n");
        let (r, _) = talk(Proto::Pop3, &[b"+OK pronto\r\n", b"-ERR no\r\n"]).await;
        assert!(r.unwrap_err().contains("-ERR no"));
        // an SMTP server on the port chosen as POP3
        let (r, _) = talk(Proto::Pop3, &[b"220 mail01\r\n"]).await;
        assert!(r.unwrap_err().starts_with("POP3 con STLS: "));
    }

    #[tokio::test]
    async fn rdp_negoziazione() {
        // Connection Confirm with RDP_NEG_RSP, chosen protocol: HYBRID
        let ok: &[u8] = &[
            3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0x1f, 8, 0, 2, 0, 0, 0,
        ];
        let (r, got) = talk(Proto::Rdp, &[ok]).await;
        r.unwrap();
        assert_eq!(got, RDP_REQUEST);

        // RDP_NEG_FAILURE: SSL_NOT_ALLOWED_BY_SERVER
        let no: &[u8] = &[
            3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 3, 0, 8, 0, 2, 0, 0, 0,
        ];
        let (r, _) = talk(Proto::Rdp, &[no]).await;
        assert!(r.unwrap_err().contains("non usa TLS"));

        // response without negotiation (old server)
        let old: &[u8] = &[3, 0, 0, 0x0b, 0x06, 0xd0, 0, 0, 0x12, 0x34, 0];
        let (r, _) = talk(Proto::Rdp, &[old]).await;
        assert!(r.unwrap_err().contains("classica"));

        let (r, _) = talk(Proto::Rdp, &[b"HTTP/1.1 400 Bad Request\r\n\r\n"]).await;
        assert!(r.unwrap_err().contains("non RDP"));
    }
}
