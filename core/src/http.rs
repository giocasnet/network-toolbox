//! HTTP headers: follows redirects one by one (so the chain is visible) and analyses the
//! security of the response: transport and HSTS, security headers, Content-Security-Policy,
//! cookies, CDN and headers that reveal the software (`analyze`). Certificates are verified;
//! if verification fails the request is repeated without it, but the step is marked as
//! unauthenticated. GET is used (some servers answer HEAD without cookies or without CSP):
//! only the headers are read and the connection is closed without downloading the body.

pub mod analyze;

use crate::{t, tf, Result};
use analyze::{check, Check, Cookie, Csp, ERR, INFO, OK, WARN};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MAX_REDIRECTS: usize = 6;
/// Wait for the `http://` probe: short, because a filtered port 80 never answers.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub struct HeadersReq {
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct HeadersResult {
    pub status_code: u16,
    pub status_text: String,
    /// Headers of the final response; cookie values are hidden
    pub headers: BTreeMap<String, String>,
    /// The whole chain is on HTTPS with a valid certificate
    pub authenticated: bool,
    pub redirects: Vec<String>,
    pub hops: Vec<Hop>,
    pub final_url: String,
    /// Cookies set by all steps of the chain (without value)
    pub cookies: Vec<Cookie>,
    /// Enforced policy, or the Report-Only one if it is the only one
    pub csp: Option<Csp>,
    /// All checks, in area order (the interface sorts them by severity)
    pub checks: Vec<Check>,
    /// Recognised CDN or proxy ("Cloudflare · MXP"), empty if none
    pub cdn: String,
}

/// "strict-transport-security" → "Strict-Transport-Security"
pub fn title_case(name: &str) -> String {
    name.split('-')
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

pub fn normalize_url(raw: &str) -> Result<reqwest::Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(t!("URL richiesto", "URL required").into());
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let url = reqwest::Url::parse(&with_scheme)
        .map_err(|_| tf!("URL non valido: {raw}", "Invalid URL: {raw}"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(tf!("URL non valido: {raw}", "Invalid URL: {raw}"));
    }
    Ok(url)
}

/// A step of the redirect chain, with the transport state.
#[derive(Debug, Serialize, PartialEq)]
pub struct Hop {
    pub url: String,
    pub status: u16,
    /// "https" (valid certificate), "https-invalid" (invalid: unauthenticated response), "http"
    pub transport: String,
    /// Reason why the certificate was not accepted
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_error: String,
    /// Time until the response headers
    pub time_ms: u64,
    /// On HTTPS: the response enables HSTS. `None` on HTTP, where the header does not count.
    pub hsts: Option<bool>,
    /// Cookies set by this step
    pub cookies: usize,
}

/// HTTP client: redirects followed by hand; `verify` = certificates verified (system store).
fn client(verify: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(!verify)
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("NetworkToolbox/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

/// Headers of a response with normalised names; several values of the same header go
/// on separate lines. Cookie values never leave here.
fn header_map(h: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in h {
        let mut v = String::from_utf8_lossy(v.as_bytes()).to_string();
        if k == reqwest::header::SET_COOKIE {
            v = analyze::mask_cookie(&v);
        }
        out.entry(title_case(k.as_str()))
            .and_modify(|e| {
                e.push('\n');
                e.push_str(&v)
            })
            .or_insert(v);
    }
    out
}

/// The redirect chain with the headers of the final response.
struct Chain {
    hops: Vec<Hop>,
    cookies: Vec<Cookie>,
    status: reqwest::StatusCode,
    headers: BTreeMap<String, String>,
    url: reqwest::Url,
}

async fn chain(
    mut url: reqwest::Url,
    verified: &reqwest::Client,
    unverified: &reqwest::Client,
) -> Result<Chain> {
    let now = crate::util::now_unix() as i64;
    let mut hops: Vec<Hop> = Vec::new();
    let mut cookies: Vec<Cookie> = Vec::new();
    loop {
        let https = url.scheme() == "https";
        // First with the certificate verified; if the connection fails it is retried without
        // verification: if that succeeds, the problem was the certificate and the response is
        // not authenticated (anyone in between may have written it).
        let mut t0 = Instant::now();
        let (resp, transport, tls_error) = match verified.get(url.clone()).send().await {
            Ok(r) => (r, if https { "https" } else { "http" }, String::new()),
            Err(e) if https && !e.is_timeout() => {
                t0 = Instant::now();
                match unverified.get(url.clone()).send().await {
                    Ok(r) => (r, "https-invalid", root_cause(&e)),
                    Err(_) => return Err(describe(e)),
                }
            }
            Err(e) => return Err(describe(e)),
        };
        let time_ms = t0.elapsed().as_millis() as u64;
        let status = resp.status();
        let before = cookies.len();
        cookies.extend(
            resp.headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .filter_map(|v| {
                    analyze::parse_cookie(
                        &String::from_utf8_lossy(v.as_bytes()),
                        https,
                        hops.len(),
                        now,
                    )
                }),
        );
        let headers = header_map(resp.headers());
        hops.push(Hop {
            url: url.to_string(),
            status: status.as_u16(),
            transport: transport.into(),
            tls_error,
            time_ms,
            hsts: https.then(|| {
                headers
                    .get("Strict-Transport-Security")
                    .is_some_and(|v| analyze::hsts_active(v))
            }),
            cookies: cookies.len() - before,
        });
        if status.is_redirection() {
            if let Some(loc) = headers.get("Location") {
                if hops.len() > MAX_REDIRECTS {
                    return Err(t!("Troppi redirect", "Too many redirects").into());
                }
                url = url
                    .join(loc)
                    .map_err(|_| tf!("Redirect non valido: {loc}", "Invalid redirect: {loc}"))?;
                continue;
            }
        }
        return Ok(Chain {
            hops,
            cookies,
            status,
            headers,
            url,
        });
    }
}

/// A request to `http://…` (without following redirects) to see whether it leads to HTTPS.
pub async fn http_upgrade(c: &reqwest::Client, url: &reqwest::Url) -> Check {
    let name = t!("HTTP porta a HTTPS", "HTTP leads to HTTPS");
    let area = t!("Trasporto", "Transport");
    let t0 = Instant::now();
    let resp = match c.get(url.clone()).timeout(UPGRADE_TIMEOUT).send().await {
        Ok(r) => r,
        Err(_) => {
            return check(
                area,
                INFO,
                name,
                tf!(
                    "{url} non risponde (porta chiusa o filtrata)",
                    "{url} does not respond (port closed or filtered)"
                ),
            )
        }
    };
    let ms = t0.elapsed().as_millis();
    let status = resp.status();
    let target = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .filter(|_| status.is_redirection())
        .and_then(|loc| url.join(loc).ok());
    match target {
        Some(t) if t.scheme() == "https" => check(
            area,
            OK,
            name,
            format!("{url} → {} → {t} ({ms} ms)", status.as_u16()),
        ),
        Some(t) => check(
            area,
            WARN,
            name,
            tf!(
                "{url} → {} → {t}: il redirect resta su HTTP",
                "{url} → {} → {t}: the redirect stays on HTTP",
                status.as_u16()
            ),
        ),
        None => check(
            area,
            WARN,
            name,
            tf!(
                "{url} risponde {} in chiaro, senza redirect",
                "{url} answers {} in clear, without a redirect",
                status.as_u16()
            ),
        ),
    }
}

/// Transport checks derived from the chain: certificate, clear-text steps, HSTS.
fn transport_checks(c: &Chain) -> Vec<Check> {
    let mut out = Vec::new();
    let area = t!("Trasporto", "Transport");
    let hops = &c.hops;
    let last = hops.len() - 1;
    let step = |i: usize| {
        if i == last {
            t!("destinazione", "destination").to_string()
        } else {
            tf!("passo {}", "step {}", i + 1)
        }
    };

    if let Some(i) = hops.iter().position(|h| h.transport == "https-invalid") {
        out.push(check(
            area,
            ERR,
            t!("Certificato", "Certificate"),
            tf!(
                "non valido ({}): la risposta non è autenticata. {}",
                "invalid ({}): the response is not authenticated. {}",
                step(i),
                hops[i].tls_error
            ),
        ));
    } else if hops.iter().any(|h| h.transport == "https") {
        out.push(check(
            area,
            OK,
            t!("Certificato", "Certificate"),
            if hops.iter().filter(|h| h.transport == "https").count() > 1 {
                t!("valido su tutti i passi HTTPS", "valid on all HTTPS steps")
            } else {
                t!("valido", "valid")
            },
        ));
    }

    let down = (0..last).find(|&i| hops[i].transport != "http" && hops[i + 1].transport == "http");
    if let Some(i) = down {
        out.push(check(
            area,
            ERR,
            "Redirect",
            tf!(
                "da HTTPS a HTTP in chiaro ({}): {}",
                "from HTTPS to clear-text HTTP ({}): {}",
                step(i),
                hops[i + 1].url
            ),
        ));
    } else if hops[last].transport == "http" {
        out.push(check(
            area,
            ERR,
            t!("Trasporto", "Transport"),
            t!("HTTP in chiaro", "Clear-text HTTP"),
        ));
    } else if hops[0].transport == "http" {
        // the typed address was http://: the chain itself shows the switch to HTTPS
        let i = hops
            .iter()
            .position(|h| h.transport != "http")
            .unwrap_or(last);
        out.push(check(
            area,
            OK,
            t!("HTTP porta a HTTPS", "HTTP leads to HTTPS"),
            format!(
                "{} → {} → {}",
                hops[i - 1].url,
                hops[i - 1].status,
                hops[i].url
            ),
        ));
    }

    let value = c.headers.get("Strict-Transport-Security");
    match (hops[last].transport.as_str(), value) {
        ("http", Some(_)) => out.push(check(
            area,
            WARN,
            "HSTS",
            t!(
                "ignorato dai browser su HTTP (RFC 6797)",
                "ignored by browsers over HTTP (RFC 6797)"
            ),
        )),
        ("http", None) => {}
        (_, Some(v)) => {
            let (status, detail) = analyze::hsts(v);
            out.push(check(area, status, "HSTS", detail));
        }
        (_, None) => out.push(check(area, ERR, "HSTS", t!("assente", "missing"))),
    }
    // HSTS applies to the host that sends it: a redirect from another host must have its own
    let final_host = c.url.host_str().unwrap_or("");
    for (i, h) in hops.iter().enumerate().take(last) {
        let other = reqwest::Url::parse(&h.url)
            .ok()
            .is_some_and(|u| u.host_str() != Some(final_host));
        if other && h.hsts == Some(false) {
            out.push(check(
                area,
                WARN,
                t!("HSTS sui redirect", "HSTS on redirects"),
                tf!(
                    "assente su {} (passo {})",
                    "missing on {} (step {})",
                    h.url,
                    i + 1
                ),
            ));
        }
    }
    out
}

/// Full analysis of a chain already walked. `upgrade` = result of the `http://` probe.
fn analyze_chain(c: Chain, upgrade: Option<Check>) -> HeadersResult {
    let mut checks: Vec<Check> = Vec::new();
    checks.extend(upgrade);
    checks.extend(transport_checks(&c));

    // Several CSP headers arrive on separate lines: the first one is analysed
    let policy = |name: &str| {
        c.headers.get(name).map(|v| {
            let all: Vec<&str> = v.split('\n').filter(|p| !p.trim().is_empty()).collect();
            (all.first().copied().unwrap_or("").to_string(), all.len())
        })
    };
    let (csp, csp_checks) = match (
        policy("Content-Security-Policy"),
        policy("Content-Security-Policy-Report-Only"),
    ) {
        (Some((p, n)), _) => {
            let (csp, ch) = analyze::parse_csp(&p, false, n);
            (Some(csp), ch)
        }
        (None, Some((p, n))) => {
            let (csp, ch) = analyze::parse_csp(&p, true, n);
            (Some(csp), ch)
        }
        (None, None) => (
            None,
            vec![check(
                "CSP",
                ERR,
                "Content-Security-Policy",
                t!("assente", "missing"),
            )],
        ),
    };
    // frame-ancestors only counts if the policy is enforced
    let frame_ancestors = csp
        .as_ref()
        .filter(|p| !p.report_only)
        .and_then(|p| p.directive("frame-ancestors"))
        .map(|d| {
            d.sources
                .iter()
                .map(|s| s.value.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });
    checks.extend(analyze::header_checks(
        &c.headers,
        frame_ancestors.as_deref(),
    ));
    checks.extend(csp_checks);
    checks.extend(
        c.cookies
            .iter()
            .filter(|k| !k.note.is_empty())
            .map(|k| check("Cookie", k.status, &k.name, k.note.clone())),
    );
    checks.extend(analyze::server_checks(&c.headers));

    HeadersResult {
        status_code: c.status.as_u16(),
        status_text: c.status.canonical_reason().unwrap_or("").to_string(),
        authenticated: c.hops.iter().all(|h| h.transport == "https"),
        final_url: c.url.to_string(),
        redirects: c.hops.iter().map(|h| h.url.clone()).collect(),
        cdn: analyze::cdn(&c.headers).map(|(l, _)| l).unwrap_or_default(),
        headers: c.headers,
        hops: c.hops,
        cookies: c.cookies,
        csp,
        checks,
    }
}

pub async fn run(req: HeadersReq) -> Result<HeadersResult> {
    let url = normalize_url(&req.url)?;
    let verified = client(true)?;
    let unverified = client(false)?;
    // With an https:// address on the standard port, http:// on the same host is also
    // tried, together with the chain (a single request, without following the redirect).
    let plain = (url.scheme() == "https" && url.port().is_none())
        .then(|| {
            let mut u = url.clone();
            u.set_scheme("http").ok().map(|_| u)
        })
        .flatten();
    let upgrade = async {
        match &plain {
            Some(u) => Some(http_upgrade(&verified, u).await),
            None => None,
        }
    };
    let (c, upgrade) = tokio::join!(chain(url, &verified, &unverified), upgrade);
    Ok(analyze_chain(c?, upgrade))
}

fn describe(e: reqwest::Error) -> String {
    if e.is_timeout() {
        t!(
            "Timeout: il server non ha risposto entro 10 secondi",
            "Timeout: the server did not respond within 10 seconds"
        )
        .into()
    } else if e.is_connect() {
        tf!(
            "Connessione fallita: {}",
            "Connection failed: {}",
            root_cause(&e)
        )
    } else {
        root_cause(&e)
    }
}

fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn nomi_e_url() {
        assert_eq!(
            title_case("strict-transport-security"),
            "Strict-Transport-Security"
        );
        assert_eq!(title_case("x-frame-options"), "X-Frame-Options");
        assert_eq!(
            normalize_url("www.example.com").unwrap().as_str(),
            "https://www.example.com/"
        );
        assert!(normalize_url("ftp://x").is_err());
        assert!(normalize_url("").is_err());
    }

    /// Test HTTP server on 127.0.0.1: `reply(first line of the request)` gives the response.
    async fn serve(reply: impl Fn(&str) -> String + Send + 'static) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp = reply(req.lines().next().unwrap_or(""));
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        port
    }

    fn find<'a>(r: &'a HeadersResult, name: &str) -> &'a Check {
        r.checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("manca {name}: {:?}", r.checks))
    }

    /// / → 301 /home (with a cookie), /home → 200 with cookies, CSP and CDN headers.
    /// GET is used, the cookies of all steps are collected and their values never leak.
    #[tokio::test]
    async fn catena_cookie_e_analisi() {
        let port = serve(|line| {
            if line.starts_with("GET / ") {
                "HTTP/1.1 301 Moved Permanently\r\nLocation: /home\r\nSet-Cookie: _track=SEGRETO0; SameSite=None\r\nContent-Length: 0\r\n\r\n".into()
            } else if line.starts_with("GET /home ") {
                "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nSet-Cookie: sessionid=SEGRETO1; HttpOnly; SameSite=Lax\r\nSet-Cookie: lang=SEGRETO2; Max-Age=86400\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'\r\nCf-Ray: 8a1b2c3d4e5f6789-MXP\r\nServer: nginx/1.18.0\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Length: 2\r\n\r\nok".into()
            } else {
                // HEAD or anything else: the test fails on the status
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n".into()
            }
        })
        .await;
        let r = run(HeadersReq {
            url: format!("http://127.0.0.1:{port}/"),
        })
        .await
        .unwrap();
        assert_eq!(r.status_code, 200);
        assert_eq!(r.redirects.len(), 2);
        assert!(r.final_url.ends_with("/home"));
        assert!(!r.authenticated);
        assert_eq!(r.hops[0].status, 301);
        assert!(r
            .hops
            .iter()
            .all(|h| h.transport == "http" && h.hsts.is_none()));
        assert_eq!((r.hops[0].cookies, r.hops[1].cookies), (1, 2));

        // cookies of all steps, with the step that set them
        let names: Vec<(&str, usize)> =
            r.cookies.iter().map(|c| (c.name.as_str(), c.hop)).collect();
        assert_eq!(names, [("_track", 0), ("sessionid", 1), ("lang", 1)]);
        assert_eq!(r.cookies[2].lifetime, "1 giorno");
        assert_eq!(
            r.headers["Set-Cookie"],
            "sessionid=(nascosto); HttpOnly; SameSite=Lax\nlang=(nascosto); Max-Age=86400"
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("SEGRETO"), "{json}");

        // checks: clear-text transport, HSTS ignored over HTTP, weak CSP, cookies, server, CDN
        assert_eq!(find(&r, "Trasporto").status, ERR);
        assert_eq!(find(&r, "HSTS").status, WARN);
        assert_eq!(find(&r, "script-src").status, ERR);
        assert_eq!(find(&r, "Protezione dai frame").status, OK);
        assert_eq!(find(&r, "_track").status, ERR);
        assert_eq!(find(&r, "sessionid").area, "Cookie");
        assert_eq!(find(&r, "Server").status, WARN);
        assert_eq!(r.cdn, "Cloudflare · MXP");
        assert_eq!(find(&r, "CDN").status, INFO);
        assert!(r.csp.as_ref().unwrap().directive("script-src").is_some());
        // non-standard port and http:// address: no separate http:// probe
        assert!(!r.checks.iter().any(|c| c.name == "HTTP porta a HTTPS"));
    }

    /// Without CSP: error; with Report-Only alone: warning, and frame-ancestors does not count.
    #[tokio::test]
    async fn csp_assente_e_report_only() {
        let port = serve(|line| {
            if line.starts_with("GET /ro ") {
                "HTTP/1.1 200 OK\r\nContent-Security-Policy-Report-Only: default-src 'self'; frame-ancestors 'none'; base-uri 'none'\r\nContent-Length: 0\r\n\r\n".into()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into()
            }
        })
        .await;
        let r = run(HeadersReq {
            url: format!("http://127.0.0.1:{port}/"),
        })
        .await
        .unwrap();
        assert!(r.csp.is_none());
        assert_eq!(find(&r, "Content-Security-Policy").status, ERR);
        assert!(r.cookies.is_empty() && r.cdn.is_empty());

        let r = run(HeadersReq {
            url: format!("http://127.0.0.1:{port}/ro"),
        })
        .await
        .unwrap();
        assert!(r.csp.as_ref().unwrap().report_only);
        assert_eq!(find(&r, "Content-Security-Policy").status, WARN);
        assert_eq!(find(&r, "Protezione dai frame").status, ERR);
    }

    /// The http:// probe: redirect to HTTPS, redirect that stays on HTTP, clear-text
    /// response, closed port.
    #[tokio::test]
    async fn http_porta_a_https() {
        let port = serve(|line| {
            if line.starts_with("GET /sicuro") {
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.com/sicuro\r\nContent-Length: 0\r\n\r\n".into()
            } else if line.starts_with("GET /altro") {
                "HTTP/1.1 302 Found\r\nLocation: /altrove\r\nContent-Length: 0\r\n\r\n".into()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into()
            }
        })
        .await;
        let c = client(true).unwrap();
        let url =
            |path: &str| reqwest::Url::parse(&format!("http://127.0.0.1:{port}{path}")).unwrap();
        let r = http_upgrade(&c, &url("/sicuro")).await;
        assert_eq!(r.status, OK);
        assert!(
            r.detail.contains("→ 301 → https://www.example.com/sicuro"),
            "{}",
            r.detail
        );
        let r = http_upgrade(&c, &url("/altro")).await;
        assert_eq!(r.status, WARN);
        assert!(r.detail.contains("resta su HTTP"));
        let r = http_upgrade(&c, &url("/")).await;
        assert_eq!(r.status, WARN);
        assert!(r.detail.contains("200 in chiaro"));
        // closed port: not a defect (with HSTS the browser does not use it)
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let u = reqwest::Url::parse(&format!("http://127.0.0.1:{closed}/")).unwrap();
        let r = http_upgrade(&c, &u).await;
        assert_eq!(r.status, INFO);
        assert_eq!(r.area, "Trasporto");
    }

    /// HTTPS with a self-signed certificate: the response arrives, but is marked unauthenticated
    /// and the reason the certificate was rejected is reported.
    #[tokio::test]
    async fn certificato_non_valido_segnalato() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
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
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // the first attempt (with verification) aborts the handshake: ignored here
                    let Ok(mut t) = acceptor.accept(s).await else {
                        return;
                    };
                    let mut buf = [0u8; 2048];
                    let _ = t.read(&mut buf).await;
                    let resp = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\nSet-Cookie: sid=SEGRETO; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n";
                    let _ = t.write_all(resp.as_bytes()).await;
                    let _ = t.shutdown().await;
                });
            }
        });
        let r = run(HeadersReq {
            url: format!("https://localhost:{port}/"),
        })
        .await
        .unwrap();
        assert_eq!(r.status_code, 200);
        assert!(!r.authenticated);
        assert_eq!(r.hops.len(), 1);
        assert_eq!(r.hops[0].transport, "https-invalid");
        assert!(!r.hops[0].tls_error.is_empty());
        let cert = find(&r, "Certificato");
        assert_eq!(cert.status, ERR);
        assert!(cert.detail.contains("destinazione"), "{}", cert.detail);
        // the headers are there and valid, but the UI shows them as unauthenticated
        assert_eq!(r.hops[0].hsts, Some(true));
        assert_eq!(find(&r, "HSTS").status, OK);
        assert_eq!(find(&r, "X-Content-Type-Options").status, OK);
        // over HTTPS a session without Secure is an error
        assert_eq!(find(&r, "sid").status, ERR);
        println!("motivo: {}", r.hops[0].tls_error);
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(normalize_url("").unwrap_err(), "URL required");
        assert_eq!(
            normalize_url("ftp://x").unwrap_err(),
            "Invalid URL: ftp://x"
        );
        let hop = |url: &str, transport: &str| Hop {
            url: url.into(),
            status: 200,
            transport: transport.into(),
            tls_error: String::new(),
            time_ms: 1,
            hsts: None,
            cookies: 0,
        };
        let c = Chain {
            hops: vec![hop("http://www.example.com/", "http")],
            cookies: vec![],
            status: reqwest::StatusCode::OK,
            headers: BTreeMap::new(),
            url: reqwest::Url::parse("http://www.example.com/").unwrap(),
        };
        let r = analyze_chain(c, None);
        let t = find(&r, "Transport");
        assert_eq!(
            (t.area, t.detail.as_str()),
            ("Transport", "Clear-text HTTP")
        );
        assert!(r.checks.iter().all(|c| c.detail != "assente"));
    }
}
