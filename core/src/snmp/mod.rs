//! Read-only SNMP: GET, WALK and tables with v1, v2c and v3 (USM with MD5/SHA/SHA-2 and
//! DES/AES-128), reading a whole device (`device`) and live counters (`monitor`).

pub mod ber;
pub mod client;
pub mod device;
#[cfg(test)]
pub mod fake;
pub mod mib;
pub mod monitor;
pub mod printer;
pub mod resources;
pub mod table;
pub mod usm;

use crate::http::analyze::{check, Check, ERR, INFO, OK, WARN};
use crate::ping::Stop;
use crate::{net, Result};
use client::{Level, Security, Session, V3Config, Value, VarBind, GET, GET_BULK, GET_NEXT};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const WALK_MAX: usize = 10_000;
pub const WALK_TIME: Duration = Duration::from_secs(60);

/// Holds community and passwords: `Debug` hides them (see below).
#[derive(Default, Deserialize)]
pub struct SnmpReq {
    pub host: String,
    #[serde(default)]
    pub oid: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    /// "get", "walk" or "table".
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub community: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub sec_level: Option<String>,
    #[serde(default)]
    pub auth_proto: Option<String>,
    #[serde(default)]
    pub auth_pass: Option<String>,
    #[serde(default)]
    pub priv_proto: Option<String>,
    #[serde(default)]
    pub priv_pass: Option<String>,
    /// UDP port of the agent (default 161).
    #[serde(default, deserialize_with = "crate::util::opt_u32")]
    pub port: Option<u32>,
}

/// Written by hand: community and passwords never appear, only whether they are set.
impl std::fmt::Debug for SnmpReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |v: &Option<String>| v.as_ref().map(|_| "(nascosto)");
        f.debug_struct("SnmpReq")
            .field("host", &self.host)
            .field("oid", &self.oid)
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("community", &hidden(&self.community))
            .field("user", &self.user)
            .field("sec_level", &self.sec_level)
            .field("auth_proto", &self.auth_proto)
            .field("auth_pass", &hidden(&self.auth_pass))
            .field("priv_proto", &self.priv_proto)
            .field("priv_pass", &hidden(&self.priv_pass))
            .field("port", &self.port)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct SnmpResult {
    pub output: String,
    pub host: String,
    pub oid: String,
    pub mode: String,
    pub count: usize,
    pub truncated: bool,
    pub stopped: bool,
    /// With `mode: "table"`: rows and columns. `None` if the values do not form a table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<table::Table>,
    /// The same table as CSV (`;` separator), for "Copy CSV".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csv: Option<String>,
    /// Security warnings about the reading (community, version, v3 level).
    pub checks: Vec<Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
}

fn error_status(code: i64) -> &'static str {
    match code {
        1 => crate::t!(
            "risposta troppo grande (tooBig)",
            "response too big (tooBig)"
        ),
        2 => crate::t!(
            "OID inesistente (noSuchName)",
            "OID does not exist (noSuchName)"
        ),
        3 => crate::t!("valore non valido (badValue)", "invalid value (badValue)"),
        5 => crate::t!(
            "errore generico dell'agente (genErr)",
            "generic agent error (genErr)"
        ),
        6 => crate::t!("accesso negato (noAccess)", "access denied (noAccess)"),
        16 => crate::t!(
            "utente non autorizzato a leggere questa parte della MIB (authorizationError)",
            "user not authorised to read this part of the MIB (authorizationError)"
        ),
        _ => crate::t!("errore dell'agente", "agent error"),
    }
}

fn security(req: &SnmpReq) -> Result<Security> {
    let version = req.version.as_deref().unwrap_or("2c").trim().to_lowercase();
    match version.as_str() {
        "1" | "2c" => {
            let community = req.community.as_deref().unwrap_or("public").to_string();
            if community.is_empty() {
                return Err(crate::t!("Community richiesta", "Community required").into());
            }
            Ok(Security::Community {
                v2c: version == "2c",
                community,
            })
        }
        "3" => {
            let user = req.user.as_deref().unwrap_or("").trim().to_string();
            if user.is_empty() {
                return Err(crate::t!("Utente SNMPv3 richiesto", "SNMPv3 user required").into());
            }
            let level = match req.sec_level.as_deref().unwrap_or("authPriv") {
                "noAuthNoPriv" => Level::NoAuthNoPriv,
                "authNoPriv" => Level::AuthNoPriv,
                "authPriv" => Level::AuthPriv,
                _ => {
                    return Err(crate::t!(
                        "Livello di sicurezza non valido",
                        "Invalid security level"
                    )
                    .into())
                }
            };
            let pw = |p: &Option<String>, what: &str| -> Result<String> {
                let v = p.clone().unwrap_or_default();
                if v.chars().count() < 8 {
                    return Err(crate::tf!(
                        "La password di {what} deve avere almeno 8 caratteri",
                        "The {what} password must be at least 8 characters"
                    ));
                }
                Ok(v)
            };
            let auth = if level == Level::NoAuthNoPriv {
                None
            } else {
                let a = usm::Auth::parse(req.auth_proto.as_deref().unwrap_or("SHA")).ok_or(
                    crate::t!(
                        "Protocollo di autenticazione non supportato",
                        "Authentication protocol not supported"
                    ),
                )?;
                Some((
                    a,
                    pw(
                        &req.auth_pass,
                        crate::t!("autenticazione", "authentication"),
                    )?,
                ))
            };
            let privacy = if level == Level::AuthPriv {
                let p = usm::Priv::parse(req.priv_proto.as_deref().unwrap_or("AES")).ok_or(
                    crate::t!(
                        "Cifratura non supportata: scegli AES (128 bit) o DES",
                        "Encryption not supported: choose AES (128 bit) or DES"
                    ),
                )?;
                Some((p, pw(&req.priv_pass, crate::t!("cifratura", "encryption"))?))
            } else {
                None
            };
            Ok(Security::V3(V3Config {
                user,
                level,
                auth,
                privacy,
            }))
        }
        _ => Err(crate::t!("Versione SNMP non valida", "Invalid SNMP version").into()),
    }
}

/// Communities that every scanner tries first.
const DEFAULT_COMMUNITIES: &[&str] = &[
    "public",
    "private",
    "community",
    "snmp",
    "admin",
    "default",
    "manager",
    "monitor",
    "read",
    "write",
    "secret",
    "test",
    "password",
    "guest",
];

fn area_sec() -> &'static str {
    crate::t!("Sicurezza", "Security")
}

/// Checks on how the device is being read: they depend only on the request
/// (version, community, v3 level and protocols), not on what the agent replies.
pub fn security_checks(sec: &Security) -> Vec<Check> {
    let mut out = Vec::new();
    match sec {
        Security::Community { v2c, community } => {
            let c = community.to_lowercase();
            if DEFAULT_COMMUNITIES.contains(&c.as_str()) {
                out.push(check(
                    area_sec(),
                    ERR,
                    crate::t!("Community predefinita", "Default community"),
                    crate::tf!(
                        "\"{community}\" è fra le prime community che chiunque prova: basta per \
                         leggere configurazione, interfacce e tabella degli indirizzi. Cambiala \
                         e limita gli indirizzi IP ammessi.",
                        "\"{community}\" is among the first communities anyone tries: it is enough \
                         to read the configuration, interfaces and address table. Change it \
                         and restrict the allowed IP addresses."
                    ),
                ));
            } else if community.chars().count() < 8 {
                out.push(check(
                    area_sec(),
                    WARN,
                    crate::t!("Community corta", "Short community"),
                    crate::t!(
                        "Meno di 8 caratteri: la community è l'unica protezione di v1 e v2c e una \
                         corta si trova per tentativi.",
                        "Fewer than 8 characters: the community is the only protection of v1 and v2c, \
                         and a short one can be found by guessing."
                    ),
                ));
            }
            out.push(check(
                area_sec(),
                WARN,
                crate::t!("Protocollo in chiaro", "Cleartext protocol"),
                crate::tf!(
                    "SNMP {} non cifra e non autentica: community e risposte si leggono sulla \
                     rete. Dove l'apparato lo permette usa v3 con autenticazione e cifratura.",
                    "SNMP {} neither encrypts nor authenticates: the community and responses can be read on the \
                     network. Where the device allows it, use v3 with authentication and encryption.",
                    if *v2c { "v2c" } else { "v1" }
                ),
            ));
            if !*v2c {
                out.push(check(
                    area_sec(),
                    INFO,
                    "SNMP v1",
                    crate::t!(
                        "Versione del 1988: niente contatori a 64 bit e una richiesta per ogni \
                         valore. Se l'apparato ha anche v2c o v3, v1 si può spegnere.",
                        "1988 version: no 64-bit counters and one request per \
                         value. If the device also has v2c or v3, v1 can be turned off."
                    ),
                ));
            }
        }
        Security::V3(cfg) => {
            match cfg.level {
                Level::NoAuthNoPriv => out.push(check(
                    area_sec(),
                    ERR,
                    crate::t!("v3 senza autenticazione", "v3 without authentication"),
                    crate::t!(
                        "Livello noAuthNoPriv: basta conoscere il nome dell'utente, senza password, \
                         e tutto passa in chiaro. Non protegge più di v2c.",
                        "noAuthNoPriv level: knowing the user name is enough, no password is needed, \
                         and everything travels in cleartext. It protects no more than v2c."
                    ),
                )),
                Level::AuthNoPriv => out.push(check(
                    area_sec(),
                    WARN,
                    crate::t!("v3 senza cifratura", "v3 without encryption"),
                    crate::t!(
                        "Livello authNoPriv: l'utente è autenticato, ma le risposte dell'apparato \
                         passano in chiaro sulla rete. Usa \"Autenticazione e cifratura\".",
                        "authNoPriv level: the user is authenticated, but the device's responses \
                         travel in cleartext on the network. Use \"Authentication and encryption\"."
                    ),
                )),
                Level::AuthPriv => {}
            }
            if let Some((a, _)) = &cfg.auth {
                match a {
                    usm::Auth::Md5 => out.push(check(
                        area_sec(),
                        WARN,
                        crate::t!("Autenticazione con MD5", "Authentication with MD5"),
                        crate::t!(
                            "HMAC-MD5 è l'algoritmo più debole fra quelli di SNMPv3: se l'apparato \
                             lo permette passa a SHA-256 o superiore.",
                            "HMAC-MD5 is the weakest algorithm in SNMPv3: if the device \
                             allows it, switch to SHA-256 or higher."
                        ),
                    )),
                    usm::Auth::Sha1 => out.push(check(
                        area_sec(),
                        INFO,
                        crate::t!("Autenticazione con SHA-1", "Authentication with SHA-1"),
                        crate::t!(
                            "HMAC-SHA-1 regge ancora, ma gli apparati recenti offrono SHA-256 o \
                             superiore (RFC 7860).",
                            "HMAC-SHA-1 still holds up, but recent devices offer SHA-256 or \
                             higher (RFC 7860)."
                        ),
                    )),
                    _ => {}
                }
            }
            if let Some((usm::Priv::Des, _)) = &cfg.privacy {
                out.push(check(
                    area_sec(),
                    WARN,
                    crate::t!("Cifratura con DES", "Encryption with DES"),
                    crate::t!(
                        "DES ha una chiave di 56 bit, oggi alla portata di una ricerca esaustiva: \
                         usa AES.",
                        "DES has a 56-bit key, nowadays within reach of an exhaustive search: \
                         use AES."
                    ),
                ));
            }
            if out.iter().all(|c| c.status == INFO) && cfg.level == Level::AuthPriv {
                out.push(check(
                    area_sec(),
                    OK,
                    crate::t!(
                        "SNMP v3 con autenticazione e cifratura",
                        "SNMP v3 with authentication and encryption"
                    ),
                    crate::t!(
                        "Utente autenticato e risposte cifrate.",
                        "Authenticated user and encrypted responses."
                    ),
                ));
            }
        }
    }
    out
}

pub(crate) fn timeout_msg(host: &str, v3: bool) -> String {
    if v3 {
        crate::tf!("Nessuna risposta da {host}: controlla UDP 161, l'IP del PC nelle ACL dell'agente e, per authPriv, password e protocollo di cifratura", "No response from {host}: check UDP 161, the PC's IP in the agent's ACLs and, for authPriv, the password and encryption protocol")
    } else {
        crate::tf!("Nessuna risposta da {host}: community errata, versione SNMP non abilitata, IP del PC non nelle ACL dell'agente oppure UDP 161 bloccata", "No response from {host}: wrong community, SNMP version not enabled, PC's IP not in the agent's ACLs or UDP 161 blocked")
    }
}

/// Session opened to the agent named in the request.
pub(crate) struct Conn {
    pub s: Session,
    pub host: String,
    pub ip: std::net::Ipv4Addr,
    pub v3: bool,
    pub checks: Vec<Check>,
}

impl Conn {
    /// A timeout becomes a sentence with the possible reasons; other errors are kept.
    pub fn explain(&self, e: String) -> String {
        if e == "TIMEOUT" {
            timeout_msg(&self.host, self.v3)
        } else {
            e
        }
    }
}

pub(crate) async fn connect(req: &SnmpReq) -> Result<Conn> {
    let host = net::clean_host(&req.host)?;
    let port = match req.port {
        None => 161,
        Some(p) if (1..=65_535).contains(&p) => p as u16,
        Some(_) => return Err(crate::t!("Porta: da 1 a 65535", "Port: 1 to 65535").into()),
    };
    let sec = security(req)?;
    let v3 = matches!(sec, Security::V3(_));
    let checks = security_checks(&sec);
    let ip = net::resolve_v4(&host).await?;
    let s = Session::new(SocketAddr::new(IpAddr::V4(ip), port), sec).await?;
    Ok(Conn {
        s,
        host,
        ip,
        v3,
        checks,
    })
}

/// Values read by a walk: `truncated` if it stopped at the limits, `stopped` if
/// the user stopped it (values already read are kept).
#[derive(Debug, Default)]
pub struct Walked {
    pub vbs: Vec<VarBind>,
    pub truncated: bool,
    pub stopped: bool,
}

/// WALK of a subtree (GETBULK with v2c/v3, GETNEXT with v1).
pub async fn walk(s: &mut Session, root: &[u32], stop: &Stop) -> Result<Walked> {
    let started = Instant::now();
    let mut out = Walked::default();
    let mut cur = root.to_vec();
    loop {
        let req = if s.is_v1() {
            s.request(GET_NEXT, 0, 0, std::slice::from_ref(&cur))
        } else {
            s.request(GET_BULK, 0, 25, std::slice::from_ref(&cur))
        };
        let Some(pdu) = stop.race(req).await else {
            out.stopped = true;
            return Ok(out);
        };
        let pdu = pdu?;
        if pdu.error_status == 2 && s.is_v1() {
            break; // v1: end of the MIB
        }
        if pdu.error_status != 0 {
            return Err(crate::tf!(
                "L'agente ha risposto con un errore: {}",
                "The agent replied with an error: {}",
                error_status(pdu.error_status)
            ));
        }
        let mut advanced = false;
        let mut done = false;
        for vb in pdu.varbinds {
            if vb.value == Value::EndOfMibView || !vb.oid.starts_with(root) {
                done = true;
                break;
            }
            if vb.oid <= cur {
                return Err(crate::t!(
                    "L'agente ha restituito OID non crescenti: walk interrotto",
                    "The agent returned non-increasing OIDs: walk aborted"
                )
                .into());
            }
            cur = vb.oid.clone();
            out.vbs.push(vb);
            advanced = true;
            if out.vbs.len() >= WALK_MAX || started.elapsed() > WALK_TIME {
                out.truncated = true;
                return Ok(out);
            }
        }
        if done || !advanced {
            break;
        }
    }
    // Like snmpwalk: if the subtree is empty, try a GET of the OID itself
    if out.vbs.is_empty() {
        let Some(pdu) = stop.race(s.request(GET, 0, 0, &[root.to_vec()])).await else {
            out.stopped = true;
            return Ok(out);
        };
        let pdu = pdu?;
        // with v1 a nonexistent OID is an error (noSuchName) with NULL values
        if pdu.error_status == 0 {
            out.vbs
                .extend(pdu.varbinds.into_iter().filter(|v| !v.value.is_exception()));
        }
    }
    Ok(out)
}

pub async fn run(req: SnmpReq, stop: &Stop) -> Result<SnmpResult> {
    let oid_text = req
        .oid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("1.3.6.1.2.1.1.1.0")
        .to_string();
    let oid = mib::parse_oid(&oid_text)
        .ok_or_else(|| crate::tf!("OID non valido: {oid_text}", "Invalid OID: {oid_text}"))?;
    let mode = req.mode.as_deref().unwrap_or("get").to_string();
    if !["get", "walk", "table"].contains(&mode.as_str()) {
        return Err(crate::t!("Modalità non valida", "Invalid mode").into());
    }
    let mut c = connect(&req).await?;
    // for a column requested as a table, the table containing it is read
    let root = if mode == "table" {
        table::root(&oid)
    } else {
        oid
    };

    let w = if mode == "get" {
        let pdu = match stop
            .race(c.s.request(GET, 0, 0, std::slice::from_ref(&root)))
            .await
        {
            Some(r) => r.map_err(|e| c.explain(e))?,
            None => return Err(crate::t!("Lettura fermata", "Read stopped").into()),
        };
        if pdu.error_status != 0 {
            return Err(crate::tf!(
                "L'agente ha risposto con un errore: {}",
                "The agent replied with an error: {}",
                error_status(pdu.error_status)
            ));
        }
        Walked {
            vbs: pdu.varbinds,
            ..Default::default()
        }
    } else {
        match walk(&mut c.s, &root, stop).await {
            Ok(w) => w,
            Err(e) => return Err(c.explain(e)),
        }
    };
    let mut output = w
        .vbs
        .iter()
        .map(|v| mib::line(&v.oid, &v.value))
        .collect::<Vec<_>>()
        .join("\n");
    if w.truncated {
        output.push_str(&crate::tf!(
            "\n… walk interrotto dopo {} valori",
            "\n… walk aborted after {} values",
            w.vbs.len()
        ));
    }
    if w.stopped {
        output.push_str(&crate::tf!(
            "\n… fermato dopo {} valori",
            "\n… stopped after {} values",
            w.vbs.len()
        ));
    }
    let table = (mode == "table")
        .then(|| table::build(&root, &w.vbs))
        .flatten();
    Ok(SnmpResult {
        output,
        host: c.host.clone(),
        oid: mib::dotted(&root),
        mode,
        count: w.vbs.len(),
        truncated: w.truncated,
        stopped: w.stopped,
        csv: table.as_ref().map(table::csv),
        table,
        checks: std::mem::take(&mut c.checks),
        engine_id: c.s.engine_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Community and passwords never appear in the debug text, also inside the requests
    /// that contain the SNMP one.
    #[test]
    fn debug_senza_segreti() {
        let r = SnmpReq {
            host: "srv01.corp.example".into(),
            community: Some("SEGRETO-C".into()),
            auth_pass: Some("SEGRETO-A".into()),
            priv_pass: Some("SEGRETO-P".into()),
            user: Some("monitor".into()),
            ..Default::default()
        };
        let d = format!("{r:?}");
        assert!(!d.contains("SEGRETO"), "{d}");
        assert!(d.contains("srv01.corp.example") && d.contains("monitor"));
        let dev = device::DeviceReq {
            snmp: r,
            ..Default::default()
        };
        assert!(!format!("{dev:?}").contains("SEGRETO"));
    }

    fn statuses(sec: &Security) -> Vec<(&'static str, String)> {
        security_checks(sec)
            .into_iter()
            .map(|c| (c.status, c.name))
            .collect()
    }

    fn v3cfg(level: Level, auth: Option<usm::Auth>, privacy: Option<usm::Priv>) -> Security {
        Security::V3(V3Config {
            user: "lettura".into(),
            level,
            auth: auth.map(|a| (a, "authpass123".into())),
            privacy: privacy.map(|p| (p, "privpass123".into())),
        })
    }

    #[test]
    fn controlli_di_sicurezza() {
        let comm = |v2c, c: &str| Security::Community {
            v2c,
            community: c.into(),
        };
        assert_eq!(
            statuses(&comm(true, "Public")),
            vec![
                (ERR, "Community predefinita".to_string()),
                (WARN, "Protocollo in chiaro".to_string())
            ]
        );
        assert_eq!(
            statuses(&comm(true, "x7Kq")),
            vec![
                (WARN, "Community corta".to_string()),
                (WARN, "Protocollo in chiaro".to_string())
            ]
        );
        assert_eq!(
            statuses(&comm(false, "una-community-lunga")),
            vec![
                (WARN, "Protocollo in chiaro".to_string()),
                (INFO, "SNMP v1".to_string())
            ]
        );
        // the community never appears in full unless it is one of the default ones
        assert!(security_checks(&comm(true, "x7Kq-segreta"))
            .iter()
            .all(|c| !c.detail.contains("x7Kq")));

        assert_eq!(
            statuses(&v3cfg(Level::NoAuthNoPriv, None, None)),
            vec![(ERR, "v3 senza autenticazione".to_string())]
        );
        assert_eq!(
            statuses(&v3cfg(Level::AuthNoPriv, Some(usm::Auth::Sha256), None)),
            vec![(WARN, "v3 senza cifratura".to_string())]
        );
        assert_eq!(
            statuses(&v3cfg(
                Level::AuthPriv,
                Some(usm::Auth::Md5),
                Some(usm::Priv::Des)
            )),
            vec![
                (WARN, "Autenticazione con MD5".to_string()),
                (WARN, "Cifratura con DES".to_string())
            ]
        );
        assert_eq!(
            statuses(&v3cfg(
                Level::AuthPriv,
                Some(usm::Auth::Sha1),
                Some(usm::Priv::Aes128)
            )),
            vec![
                (INFO, "Autenticazione con SHA-1".to_string()),
                (OK, "SNMP v3 con autenticazione e cifratura".to_string())
            ]
        );
        assert_eq!(
            statuses(&v3cfg(
                Level::AuthPriv,
                Some(usm::Auth::Sha512),
                Some(usm::Priv::Aes128)
            )),
            vec![(OK, "SNMP v3 con autenticazione e cifratura".to_string())]
        );
    }

    fn small_mib() -> fake::Mib {
        use fake::{at, text};
        let mut m = fake::Mib::new();
        m.insert(at("sysDescr", &[0]), text("Switch di prova"));
        m.insert(at("sysName", &[0]), text("sw-prova"));
        for i in 1..=60u32 {
            m.insert(at("ifDescr", &[i]), text(&format!("porta {i}")));
            m.insert(
                at("ifOperStatus", &[i]),
                ber::int(if i % 2 == 0 { 2 } else { 1 }),
            );
        }
        m
    }

    fn req(agent: &fake::Agent, ver: &str, mode: &str, oid: &str) -> SnmpReq {
        SnmpReq {
            host: "127.0.0.1".into(),
            oid: Some(oid.into()),
            version: Some(ver.into()),
            mode: Some(mode.into()),
            community: Some("prova-lettura".into()),
            port: Some(agent.addr.port() as u32),
            ..Default::default()
        }
    }

    /// GET, WALK and table against the fake agent, with v1 (GETNEXT) and v2c (GETBULK).
    #[tokio::test]
    async fn get_walk_e_tabella() {
        let a = fake::agent(small_mib(), "prova-lettura").await;
        let stop = Stop::new();
        for ver in ["1", "2c"] {
            let r = run(req(&a, ver, "get", "sysName.0"), &stop).await.unwrap();
            assert_eq!(r.output, "SNMPv2-MIB::sysName.0 = STRING: \"sw-prova\"");
            assert!(r.table.is_none() && !r.stopped);
            let r = run(req(&a, ver, "walk", "ifDescr"), &stop).await.unwrap();
            assert_eq!(r.count, 60, "v{ver}");
            assert!(r
                .output
                .ends_with("IF-MIB::ifDescr.60 = STRING: \"porta 60\""));
            // table by name, and the same requested from one of its columns
            for oid in ["ifTable", "IF-MIB::ifOperStatus"] {
                let r = run(req(&a, ver, "table", oid), &stop).await.unwrap();
                let t = r.table.unwrap();
                assert_eq!(r.oid, "1.3.6.1.2.1.2.2");
                assert_eq!(t.name, "IF-MIB::ifTable");
                assert_eq!(t.rows.len(), 60);
                assert_eq!(t.columns.len(), 2);
                assert_eq!(t.rows[1].cells, ["porta 2", "down"]);
                let csv = r.csv.unwrap();
                assert!(csv.starts_with("Indice;ifDescr;ifOperStatus\r\n1;porta 1;up\r\n"));
            }
        }
        // with v2c and GETBULK the table takes few requests: 120 values, 25 at a time
        let before = a.requests.load(std::sync::atomic::Ordering::SeqCst);
        run(req(&a, "2c", "table", "ifTable"), &stop).await.unwrap();
        let used = a.requests.load(std::sync::atomic::Ordering::SeqCst) - before;
        assert!(used <= 6, "{used} richieste");
        // the security checks accompany every response
        let r = run(req(&a, "2c", "get", "sysName.0"), &stop).await.unwrap();
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].name, "Protocollo in chiaro");
    }

    #[tokio::test]
    async fn errori_e_limiti() {
        let a = fake::agent(small_mib(), "prova-lettura").await;
        let stop = Stop::new();
        let mut r = req(&a, "2c", "get", "sysName.0");
        r.port = Some(70_000);
        assert_eq!(run(r, &stop).await.unwrap_err(), "Porta: da 1 a 65535");
        let e = run(req(&a, "2c", "set", "sysName.0"), &stop)
            .await
            .unwrap_err();
        assert_eq!(e, "Modalità non valida");
        let e = run(req(&a, "2c", "get", "nonEsiste.0"), &stop)
            .await
            .unwrap_err();
        assert!(e.starts_with("OID non valido"), "{e}");
        // OID that does not exist: with v2c a "No Such" value, with v1 the agent error
        let r = run(req(&a, "2c", "get", "sysContact.0"), &stop)
            .await
            .unwrap();
        assert!(r.output.contains("No Such Instance"), "{}", r.output);
        let e = run(req(&a, "1", "get", "sysContact.0"), &stop)
            .await
            .unwrap_err();
        assert!(e.contains("noSuchName"), "{e}");
        // empty branch read as a table: no table, no error
        let r = run(req(&a, "2c", "table", "lldpRemTable"), &stop)
            .await
            .unwrap();
        assert!(r.table.is_none() && r.count == 0);
        // stop arrived first: no request is sent
        let stopped = Stop::new();
        stopped.stop();
        let n = a.requests.load(std::sync::atomic::Ordering::SeqCst);
        let r = run(req(&a, "2c", "walk", "ifDescr"), &stopped)
            .await
            .unwrap();
        assert!(r.stopped && r.count == 0);
        assert_eq!(a.requests.load(std::sync::atomic::Ordering::SeqCst), n);
    }

    /// Wrong community: the agent stays silent and the error explains the possible reasons.
    #[tokio::test]
    async fn community_errata() {
        let a = fake::agent(small_mib(), "prova-lettura").await;
        let mut c = connect(&SnmpReq {
            community: Some("sbagliata".into()),
            ..req(&a, "2c", "get", "sysName.0")
        })
        .await
        .unwrap();
        c.s.timeout = Duration::from_millis(200);
        c.s.retries = 0;
        let e =
            c.s.request(GET, 0, 0, &[mib::oid_of("sysName")])
                .await
                .unwrap_err();
        assert!(c.explain(e).contains("community errata"));
    }

    /// Tests against a real agent: NTB_SNMP_TEST=port (Net-SNMP agent on 127.0.0.1)
    /// configured with the "public" community and the u_* test users.
    fn port() -> Option<u16> {
        std::env::var("NTB_SNMP_TEST").ok()?.parse().ok()
    }

    fn v3(user: &str, level: &str, auth: &str, privacy: &str) -> SnmpReq {
        SnmpReq {
            host: "127.0.0.1".into(),
            oid: Some("sysName.0".into()),
            version: Some("3".into()),
            mode: Some("get".into()),
            user: Some(user.into()),
            sec_level: Some(level.into()),
            auth_proto: Some(auth.into()),
            auth_pass: Some("authpass123".into()),
            priv_proto: Some(privacy.into()),
            priv_pass: Some("privpass123".into()),
            port: port().map(u32::from),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn agente_vero() {
        let Some(p) = port() else { return };
        let stop = Stop::new();
        let run = |r: SnmpReq| run(r, &stop);
        let base = |ver: &str, mode: &str, oid: &str| SnmpReq {
            host: "127.0.0.1".into(),
            oid: Some(oid.into()),
            version: Some(ver.into()),
            mode: Some(mode.into()),
            community: Some("public".into()),
            port: Some(p as u32),
            ..Default::default()
        };
        for ver in ["1", "2c"] {
            let r = run(base(ver, "get", "1.3.6.1.2.1.1.5.0")).await.unwrap();
            assert_eq!(
                r.output, "SNMPv2-MIB::sysName.0 = STRING: \"test-agent\"",
                "v{ver}"
            );
            let r = run(base(ver, "walk", "1.3.6.1.2.1.1")).await.unwrap();
            assert!(r.count >= 7, "v{ver} walk: {}", r.output);
            assert!(r
                .output
                .contains("SNMPv2-MIB::sysLocation.0 = STRING: \"Sala server\""));
            println!("walk v{ver}: {} valori", r.count);
        }
        // walk on a leaf: GET of the OID itself
        assert_eq!(
            run(base("2c", "walk", "sysContact.0")).await.unwrap().count,
            1
        );
        // large walk (interfaces) with GETBULK
        let r = run(base("2c", "walk", "1.3.6.1.2.1.2.2")).await.unwrap();
        println!("ifTable v2c: {} valori", r.count);
        // the same as a table
        let r = run(base("2c", "table", "ifTable")).await.unwrap();
        let t = r.table.unwrap();
        println!(
            "ifTable: {} righe, {} colonne",
            t.rows.len(),
            t.columns.len()
        );
        assert!(!t.rows.is_empty() && t.columns.iter().any(|c| c.name == "ifDescr"));
        // nonexistent OID
        let r = run(base("2c", "get", "1.3.6.1.2.1.1.99.0")).await.unwrap();
        assert!(r.output.contains("No Such Object"), "{}", r.output);
        // wrong community → timeout with explanation
        let mut bad = base("2c", "get", "sysName.0");
        bad.community = Some("sbagliata".into());
        assert!(run(bad).await.unwrap_err().contains("community errata"));

        // SNMPv3: all combinations
        for (u, lvl, a, x) in [
            ("u_none", "noAuthNoPriv", "SHA", "AES"),
            ("u_md5", "authNoPriv", "MD5", "AES"),
            ("u_md5des", "authPriv", "MD5", "DES"),
            ("u_shaaes", "authPriv", "SHA", "AES"),
            ("u_sha224", "authPriv", "SHA-224", "AES"),
            ("u_sha256aes", "authPriv", "SHA-256", "AES"),
            ("u_sha384", "authPriv", "SHA-384", "DES"),
            ("u_sha512aes", "authPriv", "SHA-512", "AES"),
        ] {
            let r = run(v3(u, lvl, a, x))
                .await
                .unwrap_or_else(|e| panic!("{u}: {e}"));
            assert_eq!(
                r.output, "SNMPv2-MIB::sysName.0 = STRING: \"test-agent\"",
                "{u}"
            );
            let mut w = v3(u, lvl, a, x);
            w.mode = Some("walk".into());
            w.oid = Some("1.3.6.1.2.1.1".into());
            let r = run(w).await.unwrap_or_else(|e| panic!("{u} walk: {e}"));
            assert!(r.count >= 7, "{u} walk {}", r.count);
            println!("{u}: ok, engine {}", r.engine_id.unwrap_or_default());
        }
        // v3 errors
        let e = run(v3("nessuno", "authPriv", "SHA", "AES"))
            .await
            .unwrap_err();
        assert!(e.contains("sconosciuto"), "{e}");
        let mut w = v3("u_shaaes", "authPriv", "SHA", "AES");
        w.auth_pass = Some("sbagliata1".into());
        let e = run(w).await.unwrap_err();
        assert!(e.contains("Autenticazione fallita"), "{e}");
        let mut w = v3("u_shaaes", "authPriv", "MD5", "AES");
        w.auth_pass = Some("authpass123".into());
        assert!(run(w).await.unwrap_err().contains("Autenticazione fallita"));
        let mut w = v3("u_shaaes", "authPriv", "SHA", "AES");
        w.priv_pass = Some("sbagliata1".into());
        let e = run(w).await.unwrap_err();
        println!("password di cifratura errata → {e}");
        let e = run(v3("u_md5", "authPriv", "MD5", "DES"))
            .await
            .unwrap_err();
        println!("livello superiore a quello dell'utente → {e}");
        let mut w = v3("u_shaaes", "authPriv", "SHA", "AES");
        w.auth_pass = Some("corta".into());
        assert!(run(w).await.unwrap_err().contains("almeno 8"));
    }

    /// English messages (and no Italian ones) for the checks, request errors and timeouts.
    #[test]
    fn messaggi_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let names: Vec<String> = security_checks(&Security::Community {
            v2c: true,
            community: "public".into(),
        })
        .into_iter()
        .map(|c| c.name)
        .collect();
        assert_eq!(names, ["Default community", "Cleartext protocol"]);
        assert!(security_checks(&Security::Community {
            v2c: false,
            community: "x".into()
        })
        .iter()
        .all(|c| c.area == "Security" && !c.detail.contains("community è")));
        let e = security(&SnmpReq {
            version: Some("3".into()),
            ..Default::default()
        })
        .err()
        .unwrap();
        assert_eq!(e, "SNMPv3 user required");
        assert!(timeout_msg("srv01", false).starts_with("No response from srv01"));
        assert!(!timeout_msg("srv01", true).contains("Nessuna"));
        assert_eq!(error_status(2), "OID does not exist (noSuchName)");
    }
}
