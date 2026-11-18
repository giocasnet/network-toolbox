//! Whois (TCP 43): starts from whois.iana.org and follows the referrals to the
//! relevant registry (RIPE, ARIN, nic.it, Verisign → registrar...).

use crate::{net, tf, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
pub struct WhoisReq {
    pub host: String,
}

#[derive(Debug, Serialize)]
pub struct WhoisResponse {
    pub output: String,
    pub geo: serde_json::Value,
}

pub async fn query(server: &str, q: &str) -> Result<String> {
    let addr = format!("{server}:43");
    let mut s = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&addr))
        .await
        .map_err(|_| {
            tf!(
                "{server}: timeout di connessione",
                "{server}: connection timeout"
            )
        })?
        .map_err(|e| format!("{server}: {e}"))?;
    s.write_all(format!("{q}\r\n").as_bytes())
        .await
        .map_err(|e| format!("{server}: {e}"))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let read = async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() > MAX_BYTES {
                        break;
                    }
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(12), read).await;
    Ok(String::from_utf8_lossy(&out).replace("\r\n", "\n"))
}

/// Server a whois response refers to ("refer:", "whois:", "Registrar WHOIS Server:").
pub fn referral(text: &str, current: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim();
        let lower = l.to_ascii_lowercase();
        for key in [
            "refer:",
            "whois:",
            "registrar whois server:",
            "referralserver:",
        ] {
            if let Some(v) = lower.strip_prefix(key) {
                let v = v
                    .trim()
                    .trim_start_matches("whois://")
                    .trim_end_matches('/');
                let v = v.split(':').next().unwrap_or("").to_string();
                if !v.is_empty()
                    && v.contains('.')
                    && !v.eq_ignore_ascii_case(current)
                    && !v.contains(' ')
                {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Registrable domain: registries know "example.com", not
/// "www.example.com". Handles the second levels of ccTLDs (bbc.co.uk).
pub fn registrable(host: &str) -> String {
    let host = host.trim_end_matches('.');
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host.to_string();
    }
    const SECOND_LEVEL: [&str; 10] = [
        "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go",
    ];
    let take = if labels[n - 1].len() == 2 && SECOND_LEVEL.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    labels[n - take..].join(".")
}

/// Location of a public IP, in the format the interface expects.
async fn geo(host: &str) -> serde_json::Value {
    let Ok(ip) = net::resolve_v4(host).await else {
        return serde_json::json!({});
    };
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        return serde_json::json!({"status": "private", "query": ip.to_string()});
    }
    match crate::myip::ip_info(ip).await {
        Ok(v) => serde_json::json!({
            "status": "success",
            "query": ip.to_string(),
            "country": v.get("country").and_then(|c| c.as_str()).unwrap_or(""),
            "regionName": v.get("region").and_then(|c| c.as_str()).unwrap_or(""),
            "city": v.get("city").and_then(|c| c.as_str()).unwrap_or(""),
            "org": v.get("org").and_then(|c| c.as_str()).unwrap_or(""),
        }),
        Err(_) => serde_json::json!({"status": "success", "query": ip.to_string()}),
    }
}

pub async fn run(req: WhoisReq) -> Result<WhoisResponse> {
    let input = net::clean_host(&req.host)?;
    let host = registrable(&input);
    let ip: Option<Ipv4Addr> = host.parse().ok();
    let geo_job = tokio::spawn({
        let input = input.clone();
        async move { geo(&input).await }
    });

    let mut server = "whois.iana.org".to_string();
    let mut text = query(&server, &host).await?;
    let mut sections = vec![(server.clone(), text.clone())];
    for _ in 0..2 {
        let Some(next) = referral(&text, &server) else {
            break;
        };
        // ARIN returns the network data only with the "n +" prefix
        let q = if next.contains("arin.net") && ip.is_some() {
            format!("n + {host}")
        } else {
            host.clone()
        };
        match query(&next, &q).await {
            Ok(t) if !t.trim().is_empty() => {
                server = next;
                text = t;
                sections.push((server.clone(), text.clone()));
            }
            _ => break,
        }
    }
    // Show the relevant registry; IANA only if there was no referral
    let shown: Vec<&(String, String)> = if sections.len() > 1 {
        sections[1..].iter().collect()
    } else {
        sections.iter().collect()
    };
    let output = shown
        .iter()
        .map(|(s, t)| format!("% Server: {s}\n\n{}", t.trim()))
        .collect::<Vec<_>>()
        .join("\n\n");

    let output = if host != input {
        tf!(
            "% Dominio interrogato: {host}\n\n{output}",
            "% Queried domain: {host}\n\n{output}"
        )
    } else {
        output
    };
    let geo = geo_job.await.unwrap_or_else(|_| serde_json::json!({}));
    Ok(WhoisResponse { output, geo })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dominio_registrabile() {
        assert_eq!(registrable("www.example.com"), "example.com");
        assert_eq!(registrable("a.b.example.it"), "example.it");
        assert_eq!(registrable("example.it"), "example.it");
        assert_eq!(registrable("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable("203.0.113.47"), "203.0.113.47");
        assert_eq!(registrable("srv01"), "srv01");
    }

    #[test]
    fn messaggi_tradotti() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let m = tf!(
            "% Dominio interrogato: {}",
            "% Queried domain: {}",
            "example.com"
        );
        assert_eq!(m, "% Queried domain: example.com");
    }

    #[test]
    fn rimandi() {
        assert_eq!(
            referral("domain: IT\nrefer:        whois.nic.it\n", "whois.iana.org").as_deref(),
            Some("whois.nic.it")
        );
        assert_eq!(
            referral(
                "   Registrar WHOIS Server: whois.markmonitor.com\n",
                "whois.verisign-grs.com"
            )
            .as_deref(),
            Some("whois.markmonitor.com")
        );
        assert_eq!(
            referral("ReferralServer:  whois://rwhois.example.net:4321\n", "x").as_deref(),
            Some("rwhois.example.net")
        );
        assert_eq!(referral("refer: whois.nic.it\n", "whois.nic.it"), None);
        assert_eq!(referral("nessun rimando\n", "x"), None);
    }
}
