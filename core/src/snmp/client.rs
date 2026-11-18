//! Client SNMP v1, v2c e v3 (USM) su UDP.

use super::ber::{self, Reader, OCTET_STRING, SEQUENCE};
use super::usm::{self, Auth, Priv};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub const GET: u8 = 0xA0;
pub const GET_NEXT: u8 = 0xA1;
pub const RESPONSE: u8 = 0xA2;
pub const GET_BULK: u8 = 0xA5;
pub const REPORT: u8 = 0xA8;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Str(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    Ip([u8; 4]),
    Counter32(u64),
    Gauge32(u64),
    TimeTicks(u64),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Other(u8, Vec<u8>),
}

impl Value {
    pub fn is_exception(&self) -> bool {
        matches!(
            self,
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
        )
    }
}

#[derive(Debug, Clone)]
pub struct VarBind {
    pub oid: Vec<u32>,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct Pdu {
    pub tag: u8,
    pub request_id: i64,
    pub error_status: i64,
    pub error_index: i64,
    pub varbinds: Vec<VarBind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

#[derive(Debug, Clone)]
pub struct V3Config {
    pub user: String,
    pub level: Level,
    pub auth: Option<(Auth, String)>,
    pub privacy: Option<(Priv, String)>,
}

pub enum Security {
    Community { v2c: bool, community: String },
    V3(V3Config),
}

/// USM state after the agent's discovery.
struct Engine {
    id: Vec<u8>,
    boots: u32,
    time: u32,
    at: Instant,
    auth_key: Vec<u8>,
    priv_key: Vec<u8>,
    /// boots/time confirmed by an authenticated message (those from discovery are not)
    synced: bool,
}

pub struct Session {
    sock: UdpSocket,
    addr: SocketAddr,
    sec: Security,
    engine: Option<Engine>,
    next_id: i32,
    salt: u64,
    pub timeout: Duration,
    pub retries: u32,
}

pub fn encode_pdu(tag: u8, request_id: i32, a: i64, b: i64, oids: &[Vec<u32>]) -> Vec<u8> {
    let vbs: Vec<Vec<u8>> = oids
        .iter()
        .map(|o| ber::seq(&[ber::oid(o), ber::null()]))
        .collect();
    ber::tlv(
        tag,
        &[
            ber::int(request_id as i64),
            ber::int(a),
            ber::int(b),
            ber::seq(&vbs),
        ]
        .concat(),
    )
}

fn decode_value(tag: u8, c: &[u8]) -> Value {
    match tag {
        0x02 => Value::Int(ber::decode_int(c)),
        0x04 => Value::Str(c.to_vec()),
        0x05 => Value::Null,
        0x06 => Value::Oid(ber::decode_oid(c)),
        0x40 if c.len() == 4 => Value::Ip([c[0], c[1], c[2], c[3]]),
        0x41 => Value::Counter32(ber::decode_uint(c)),
        0x42 => Value::Gauge32(ber::decode_uint(c)),
        0x43 => Value::TimeTicks(ber::decode_uint(c)),
        0x44 => Value::Opaque(c.to_vec()),
        0x46 => Value::Counter64(ber::decode_uint(c)),
        0x80 => Value::NoSuchObject,
        0x81 => Value::NoSuchInstance,
        0x82 => Value::EndOfMibView,
        t => Value::Other(t, c.to_vec()),
    }
}

pub fn decode_pdu(r: &mut Reader) -> Result<Pdu, String> {
    let (tag, content, at) = r.tlv()?;
    if tag & 0xE0 != 0xA0 {
        return Err(crate::tf!(
            "PDU SNMP non valida (tag 0x{tag:02x})",
            "Invalid SNMP PDU (tag 0x{tag:02x})"
        ));
    }
    let mut p = Reader {
        buf: content,
        pos: 0,
        base: at,
    };
    let request_id = p.int()?;
    let error_status = p.int()?;
    let error_index = p.int()?;
    let mut list = p.enter(SEQUENCE)?;
    let mut varbinds = Vec::new();
    while !list.at_end() {
        let mut vb = list.enter(SEQUENCE)?;
        let (oid, _) = vb.expect(ber::OID)?;
        let (vt, vc, _) = vb.tlv()?;
        varbinds.push(VarBind {
            oid: ber::decode_oid(oid),
            value: decode_value(vt, vc),
        });
    }
    Ok(Pdu {
        tag,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}

/// Received SNMP message (v3), with the position of the authentication field.
struct V3Response {
    msg_id: i64,
    flags: u8,
    engine_id: Vec<u8>,
    boots: u32,
    time: u32,
    user: Vec<u8>,
    auth_params: Vec<u8>,
    auth_at: usize,
    priv_params: Vec<u8>,
    data: Vec<u8>,
    data_encrypted: bool,
}

fn parse_v3(buf: &[u8]) -> Result<V3Response, String> {
    let mut r = Reader::new(buf);
    let mut m = r.enter(SEQUENCE)?;
    if m.int()? != 3 {
        return Err(crate::t!("Risposta non SNMPv3", "Not an SNMPv3 response").into());
    }
    let mut g = m.enter(SEQUENCE)?;
    let msg_id = g.int()?;
    let _max = g.int()?;
    let flags = *g.octets()?.first().unwrap_or(&0);
    if g.int()? != 3 {
        return Err(crate::t!(
            "Modello di sicurezza diverso da USM",
            "Security model other than USM"
        )
        .into());
    }
    let (sp, sp_at) = m.expect(OCTET_STRING)?;
    let mut u = Reader {
        buf: sp,
        pos: 0,
        base: sp_at,
    }
    .enter(SEQUENCE)?;
    let engine_id = u.octets()?.to_vec();
    let boots = u.int()? as u32;
    let time = u.int()? as u32;
    let user = u.octets()?.to_vec();
    let (auth_params, auth_at) = u.expect(OCTET_STRING)?;
    let priv_params = u.octets()?.to_vec();
    let (tag, content, _) = m.tlv()?;
    let data_encrypted = tag == OCTET_STRING;
    let data = if data_encrypted {
        content.to_vec()
    } else {
        ber::tlv(tag, content)
    };
    Ok(V3Response {
        msg_id,
        flags,
        engine_id,
        boots,
        time,
        user,
        auth_params: auth_params.to_vec(),
        auth_at,
        priv_params,
        data,
        data_encrypted,
    })
}

/// Fields of an SNMPv3 message to build (a request, or a fake response in tests).
struct V3Out<'a> {
    msg_id: i32,
    flags: u8,
    engine_id: &'a [u8],
    boots: u32,
    time: u32,
    user: &'a [u8],
    priv_params: &'a [u8],
    /// ScopedPDU (SEQUENCE) or OCTET STRING holding the encrypted ScopedPDU
    data: Vec<u8>,
    /// Protocol and localised key used to sign the message
    auth: Option<(Auth, &'a [u8])>,
}

fn build_v3(o: V3Out) -> Vec<u8> {
    let mac_len = o.auth.map(|(a, _)| a.mac_len()).unwrap_or(0);
    let e = ber::octets(o.engine_id);
    let bo = ber::int(o.boots as i64);
    let ti = ber::int(o.time as i64);
    let us = ber::octets(o.user);
    let au = ber::octets(&vec![0u8; mac_len]);
    let pr = ber::octets(o.priv_params);
    let usm_content = [
        e.clone(),
        bo.clone(),
        ti.clone(),
        us.clone(),
        au.clone(),
        pr,
    ]
    .concat();
    let usm_seq = ber::tlv(SEQUENCE, &usm_content);
    let sec_param = ber::octets(&usm_seq);
    let ver = ber::int(3);
    let global = ber::seq(&[
        ber::int(o.msg_id as i64),
        ber::int(65_507),
        ber::octets(&[o.flags]),
        ber::int(3),
    ]);
    let body = [ver.clone(), global.clone(), sec_param.clone(), o.data].concat();
    let mut msg = ber::tlv(SEQUENCE, &body);
    if let Some((a, key)) = o.auth {
        let offset = (msg.len() - body.len())
            + ver.len()
            + global.len()
            + (sec_param.len() - usm_seq.len())
            + (usm_seq.len() - usm_content.len())
            + e.len()
            + bo.len()
            + ti.len()
            + us.len()
            + (au.len() - mac_len);
        let mac = a.mac(key, &msg);
        msg[offset..offset + mac_len].copy_from_slice(&mac);
    }
    msg
}

/// Constant-time comparison (HMAC).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What the response to a v3 request must satisfy.
struct Expect<'a> {
    msg_id: i32,
    request_id: i32,
    engine_id: &'a [u8],
    user: &'a [u8],
    auth: Option<(Auth, &'a [u8])>,
    privacy: Option<(Priv, &'a [u8])>,
    /// estimated boots and time of the agent, after the first authenticated message
    clock: Option<(u32, u32)>,
}

/// Verified v3 response: plaintext PDU and, if authenticated, the agent's boots/time.
struct Verified {
    pdu: Pdu,
    clock: Option<(u32, u32)>,
}

/// Verifies a v3 response (RFC 3414 §3.2) before using any of its fields.
/// With authentication required: auth flag, engine ID, user, HMAC length and value
/// and time window; with authPriv also the priv flag and the encrypted data. The only exception
/// is unprotected Reports (unknown user, bad signature...), which always become an
/// error and never data. The PDU must carry the request's request-id.
fn verify_v3(raw: &[u8], ex: &Expect) -> Result<Verified, String> {
    let resp = parse_v3(raw)?;
    if resp.msg_id != ex.msg_id as i64 {
        return Err(crate::t!(
            "msgID diverso da quello della richiesta",
            "msgID differs from the request's"
        )
        .into());
    }
    let authed = resp.flags & 0x01 != 0;
    let privd = resp.flags & 0x02 != 0;
    if privd && !authed {
        return Err(crate::t!(
            "Flag di sicurezza non validi (priv senza auth)",
            "Invalid security flags (priv without auth)"
        )
        .into());
    }
    let mut clock = None;
    match ex.auth {
        Some((a, key)) if authed => {
            if resp.engine_id != ex.engine_id {
                return Err(crate::t!(
                    "Engine ID diverso da quello dell'agente interrogato",
                    "Engine ID differs from the queried agent's"
                )
                .into());
            }
            if resp.user != ex.user {
                return Err(crate::t!(
                    "Utente diverso da quello della richiesta",
                    "User differs from the request's"
                )
                .into());
            }
            if resp.auth_params.len() != a.mac_len() {
                return Err(crate::t!(
                    "Lunghezza della firma non valida",
                    "Invalid signature length"
                )
                .into());
            }
            let mut copy = raw.to_vec();
            copy[resp.auth_at..resp.auth_at + resp.auth_params.len()].fill(0);
            if !ct_eq(&a.mac(key, &copy), &resp.auth_params) {
                return Err(crate::t!(
                    "La risposta dell'agente ha una firma non valida",
                    "The agent's response has an invalid signature"
                )
                .into());
            }
            if let Some((boots, time)) = ex.clock {
                if resp.boots == 0x7fff_ffff
                    || resp.boots < boots
                    || (resp.boots == boots && resp.time.saturating_add(150) < time)
                {
                    return Err(crate::t!(
                        "Risposta fuori dalla finestra temporale dell'agente",
                        "Response outside the agent's time window"
                    )
                    .into());
                }
            }
            clock = Some((resp.boots, resp.time));
        }
        Some(_) => {}
        None if authed => {
            return Err(crate::t!(
                "Livello di sicurezza della risposta diverso da quello richiesto",
                "Response security level differs from the requested one"
            )
            .into());
        }
        None => {}
    }
    let scoped = if resp.data_encrypted {
        if !privd {
            return Err(crate::t!(
                "Dati cifrati senza il flag priv",
                "Encrypted data without the priv flag"
            )
            .into());
        }
        let (p, key) = ex.privacy.ok_or(crate::t!(
            "Risposta cifrata inattesa",
            "Unexpected encrypted response"
        ))?;
        usm::decrypt(p, key, resp.boots, resp.time, &resp.priv_params, &resp.data)?
    } else if privd {
        return Err(crate::t!(
            "Flag priv senza dati cifrati",
            "Priv flag without encrypted data"
        )
        .into());
    } else {
        resp.data
    };
    let mut r = Reader::new(&scoped);
    let mut s = r.enter(SEQUENCE).map_err(|_| {
        crate::t!(
            "Decifratura fallita: password o protocollo di cifratura errati",
            "Decryption failed: wrong password or encryption protocol"
        )
        .to_string()
    })?;
    s.octets()?;
    s.octets()?;
    let pdu = decode_pdu(&mut s)?;
    if pdu.tag == REPORT {
        return Ok(Verified { pdu, clock });
    }
    let protected = ex.auth.is_none() || (authed && (ex.privacy.is_none() || privd));
    if !protected {
        return Err(crate::t!(
            "Risposta senza la protezione richiesta (autenticazione/cifratura)",
            "Response without the required protection (authentication/encryption)"
        )
        .into());
    }
    if pdu.tag != RESPONSE {
        return Err(format!("PDU inattesa (tag 0x{:02x})", pdu.tag));
    }
    if pdu.request_id != ex.request_id as i64 {
        return Err(crate::t!(
            "request-id diverso da quello della richiesta",
            "request-id differs from the request's"
        )
        .into());
    }
    Ok(Verified { pdu, clock })
}

/// USM counters in the agent's reports (1.3.6.1.6.3.15.1.1.x.0).
fn report_error(pdu: &Pdu) -> String {
    let code = pdu.varbinds.first().and_then(|v| {
        (v.oid.len() >= 10 && v.oid[..9] == [1, 3, 6, 1, 6, 3, 15, 1, 1]).then(|| v.oid[9])
    });
    match code {
        Some(1) => crate::t!(
            "L'agente non supporta il livello di sicurezza richiesto per questo utente",
            "The agent does not support the requested security level for this user"
        )
        .into(),
        Some(2) => crate::t!(
            "Orologio dell'agente fuori finestra temporale",
            "Agent clock outside the time window"
        )
        .into(),
        Some(3) => crate::t!(
            "Utente SNMPv3 sconosciuto all'agente",
            "SNMPv3 user unknown to the agent"
        )
        .into(),
        Some(4) => crate::t!("Engine ID sconosciuto", "Unknown engine ID").into(),
        Some(5) => crate::t!(
            "Autenticazione fallita: password o protocollo di autenticazione errati",
            "Authentication failed: wrong password or authentication protocol"
        )
        .into(),
        Some(6) => crate::t!(
            "Decifratura fallita: password o protocollo di cifratura errati",
            "Decryption failed: wrong password or encryption protocol"
        )
        .into(),
        _ => match pdu.varbinds.first() {
            Some(v) => crate::tf!(
                "L'agente ha risposto con un report ({})",
                "The agent replied with a report ({})",
                v.oid
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            ),
            None => crate::t!(
                "L'agente ha risposto con un report",
                "The agent replied with a report"
            )
            .into(),
        },
    }
}

impl Session {
    pub async fn new(addr: SocketAddr, sec: Security) -> Result<Session, String> {
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("Socket UDP: {e}"))?;
        // Connected socket: the system drops packets not coming from the agent's IP and port
        sock.connect(addr)
            .await
            .map_err(|e| format!("Socket UDP: {e}"))?;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1);
        Ok(Session {
            sock,
            addr,
            sec,
            engine: None,
            next_id: (seed as i32 & 0x3fff_ffff).max(1),
            salt: seed as u64,
            timeout: Duration::from_secs(3),
            retries: 1,
        })
    }

    pub fn is_v1(&self) -> bool {
        matches!(self.sec, Security::Community { v2c: false, .. })
    }

    fn new_id(&mut self) -> i32 {
        self.next_id = self.next_id.wrapping_add(1) & 0x3fff_ffff;
        self.next_id
    }

    /// Sends and waits for a response satisfying `accept`, with retries.
    async fn exchange(
        &self,
        msg: &[u8],
        accept: impl Fn(&[u8]) -> bool,
    ) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 65_535];
        let closed = |e: std::io::Error| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
            ) {
                crate::tf!(
                    "Porta UDP {} chiusa su {}: nessun agente SNMP in ascolto",
                    "UDP port {} closed on {}: no SNMP agent listening",
                    self.addr.port(),
                    self.addr.ip()
                )
            } else {
                crate::tf!("Ricezione fallita: {e}", "Receive failed: {e}")
            }
        };
        for _ in 0..=self.retries {
            self.sock.send(msg).await.map_err(closed)?;
            let deadline = Instant::now() + self.timeout;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match tokio::time::timeout(left, self.sock.recv(&mut buf)).await {
                    Ok(Ok(n)) if accept(&buf[..n]) => return Ok(buf[..n].to_vec()),
                    Ok(Ok(_)) => continue,
                    Ok(Err(e)) => return Err(closed(e)),
                    Err(_) => break,
                }
            }
        }
        Err("TIMEOUT".into())
    }

    /// Runs a request (GET, GETNEXT, GETBULK) and returns the response PDU.
    pub async fn request(
        &mut self,
        tag: u8,
        a: i64,
        b: i64,
        oids: &[Vec<u32>],
    ) -> Result<Pdu, String> {
        let id = self.new_id();
        let pdu = encode_pdu(tag, id, a, b, oids);
        match &self.sec {
            Security::Community { v2c, community } => {
                let msg = ber::seq(&[
                    ber::int(if *v2c { 1 } else { 0 }),
                    ber::octets(community.as_bytes()),
                    pdu,
                ]);
                let raw = self
                    .exchange(&msg, |r| {
                        let mut rd = Reader::new(r);
                        (|| -> Result<bool, String> {
                            let mut m = rd.enter(SEQUENCE)?;
                            m.int()?;
                            m.octets()?;
                            Ok(decode_pdu(&mut m)?.request_id == id as i64)
                        })()
                        .unwrap_or(false)
                    })
                    .await?;
                let mut rd = Reader::new(&raw);
                let mut m = rd.enter(SEQUENCE)?;
                m.int()?;
                m.octets()?;
                decode_pdu(&mut m)
            }
            Security::V3(_) => {
                if self.engine.is_none() {
                    self.discover().await?;
                }
                let mut resp = self.v3_send(&pdu, id).await?;
                if resp.tag == REPORT && report_error(&resp).starts_with("Orologio") {
                    // boots/time updated by v3_send (authenticated report): a second attempt
                    resp = self.v3_send(&pdu, id).await?;
                }
                if resp.tag == REPORT {
                    return Err(report_error(&resp));
                }
                Ok(resp)
            }
        }
    }

    /// Discovery: request without credentials, the agent replies with engine ID, boots and time.
    async fn discover(&mut self) -> Result<(), String> {
        let Security::V3(cfg) = &self.sec else {
            return Ok(());
        };
        let cfg = cfg.clone();
        let msg_id = self.new_id();
        let pdu = encode_pdu(GET, msg_id, 0, 0, &[]);
        let usm = ber::seq(&[
            ber::octets(b""),
            ber::int(0),
            ber::int(0),
            ber::octets(b""),
            ber::octets(b""),
            ber::octets(b""),
        ]);
        let msg = ber::seq(&[
            ber::int(3),
            ber::seq(&[
                ber::int(msg_id as i64),
                ber::int(65_507),
                ber::octets(&[0x04]),
                ber::int(3),
            ]),
            ber::octets(&usm),
            ber::seq(&[ber::octets(b""), ber::octets(b""), pdu]),
        ]);
        let raw = self
            .exchange(&msg, |r| {
                parse_v3(r)
                    .map(|p| p.msg_id == msg_id as i64)
                    .unwrap_or(false)
            })
            .await
            .map_err(|e| {
                if e == "TIMEOUT" {
                    "TIMEOUT".to_string()
                } else {
                    e
                }
            })?;
        let resp = parse_v3(&raw)?;
        if resp.engine_id.is_empty() {
            return Err(crate::t!(
                "L'agente non ha comunicato il proprio engine ID",
                "The agent did not provide its engine ID"
            )
            .into());
        }
        let (auth_key, priv_key) = match &cfg.auth {
            Some((a, pw)) => {
                let ak = a.localize(&a.password_to_key(pw.as_bytes()), &resp.engine_id);
                let pk = match &cfg.privacy {
                    Some((_, ppw)) => {
                        a.localize(&a.password_to_key(ppw.as_bytes()), &resp.engine_id)
                    }
                    None => vec![],
                };
                (ak, pk)
            }
            None => (vec![], vec![]),
        };
        self.engine = Some(Engine {
            id: resp.engine_id,
            boots: resp.boots,
            time: resp.time,
            at: Instant::now(),
            auth_key,
            priv_key,
            synced: false,
        });
        Ok(())
    }

    async fn v3_send(&mut self, pdu: &[u8], request_id: i32) -> Result<Pdu, String> {
        let Security::V3(cfg) = &self.sec else {
            unreachable!()
        };
        let cfg = cfg.clone();
        let msg_id = self.new_id();
        self.salt = self.salt.wrapping_add(1);
        let eng = self.engine.as_ref().ok_or(crate::t!(
            "Discovery non eseguita",
            "Discovery not performed"
        ))?;
        let elapsed = eng.at.elapsed().as_secs() as u32;
        let time = eng.time.saturating_add(elapsed);
        let auth = cfg
            .auth
            .as_ref()
            .map(|(a, _)| *a)
            .filter(|_| cfg.level != Level::NoAuthNoPriv);
        let privacy = cfg
            .privacy
            .as_ref()
            .map(|(p, _)| *p)
            .filter(|_| cfg.level == Level::AuthPriv);
        let flags =
            0x04 | if auth.is_some() { 0x01 } else { 0 } | if privacy.is_some() { 0x02 } else { 0 };

        let scoped = ber::seq(&[ber::octets(&eng.id), ber::octets(b""), pdu.to_vec()]);
        let (data, priv_params) = match privacy {
            Some(p) => {
                let (enc, salt) =
                    usm::encrypt(p, &eng.priv_key, eng.boots, time, self.salt, &scoped)?;
                (ber::octets(&enc), salt)
            }
            None => (scoped, vec![]),
        };
        let msg = build_v3(V3Out {
            msg_id,
            flags,
            engine_id: &eng.id,
            boots: eng.boots,
            time,
            user: cfg.user.as_bytes(),
            priv_params: &priv_params,
            data,
            auth: auth.map(|a| (a, eng.auth_key.as_slice())),
        });

        let ex = Expect {
            msg_id,
            request_id,
            engine_id: &eng.id,
            user: cfg.user.as_bytes(),
            auth: auth.map(|a| (a, eng.auth_key.as_slice())),
            privacy: privacy.map(|p| (p, eng.priv_key.as_slice())),
            clock: eng.synced.then_some((eng.boots, time)),
        };
        // Packets that fail verification are discarded and we keep waiting for
        // the real one; if it never arrives, the error gives the reason for the last discard.
        let rejected = std::sync::Mutex::new(None::<String>);
        let res = self
            .exchange(&msg, |r| {
                if !parse_v3(r).is_ok_and(|p| p.msg_id == msg_id as i64) {
                    return false;
                }
                match verify_v3(r, &ex) {
                    Ok(_) => true,
                    Err(e) => {
                        *rejected.lock().unwrap() = Some(e);
                        false
                    }
                }
            })
            .await;
        let raw = match (res, rejected.into_inner().unwrap()) {
            (Ok(raw), _) => raw,
            (Err(e), Some(why)) if e == "TIMEOUT" => {
                return Err(crate::tf!(
                    "Risposta dell'agente scartata: {why}",
                    "Agent response discarded: {why}"
                ))
            }
            (Err(e), _) => return Err(e),
        };
        let v = verify_v3(&raw, &ex)?;
        // Agent clock updated only by authenticated messages (RFC 3414 §3.2 point 7)
        if let (Some((boots, time)), Some(eng)) = (v.clock, self.engine.as_mut()) {
            eng.boots = boots;
            eng.time = time;
            eng.at = Instant::now();
            eng.synced = true;
        }
        Ok(v.pdu)
    }

    pub fn engine_id(&self) -> Option<String> {
        self.engine
            .as_ref()
            .map(|e| e.id.iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGINE: &[u8] = b"\x80\x00\x1f\x88\x80ntb-test";
    const USER: &[u8] = b"u_sha";

    fn keys() -> (Vec<u8>, Vec<u8>) {
        let a = Auth::Sha1;
        let ak = a.localize(&a.password_to_key(b"authpass123"), ENGINE);
        let pk = a.localize(&a.password_to_key(b"privpass123"), ENGINE);
        (ak, pk)
    }

    fn scoped(tag: u8, request_id: i32, text: &[u8]) -> Vec<u8> {
        let pdu = ber::tlv(
            tag,
            &[
                ber::int(request_id as i64),
                ber::int(0),
                ber::int(0),
                ber::seq(&[ber::seq(&[
                    ber::oid(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
                    ber::octets(text),
                ])]),
            ]
            .concat(),
        );
        ber::seq(&[ber::octets(ENGINE), ber::octets(b""), pdu])
    }

    /// authNoPriv response; `sign` = sign with the right key.
    fn reply(flags: u8, sign: bool, tag: u8, rid: i32, boots: u32, time: u32) -> Vec<u8> {
        let (ak, _) = keys();
        build_v3(V3Out {
            msg_id: 7,
            flags,
            engine_id: ENGINE,
            boots,
            time,
            user: USER,
            priv_params: b"",
            data: scoped(tag, rid, b"VERO"),
            auth: sign.then_some((Auth::Sha1, ak.as_slice())),
        })
    }

    fn expect<'a>(ak: &'a [u8], pk: Option<&'a [u8]>, clock: Option<(u32, u32)>) -> Expect<'a> {
        Expect {
            msg_id: 7,
            request_id: 42,
            engine_id: ENGINE,
            user: USER,
            auth: Some((Auth::Sha1, ak)),
            privacy: pk.map(|k| (Priv::Aes128, k)),
            clock,
        }
    }

    fn text(p: &Pdu) -> Vec<u8> {
        match &p.varbinds[0].value {
            Value::Str(s) => s.clone(),
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn v3_risposta_autenticata_valida() {
        let (ak, _) = keys();
        let v = verify_v3(
            &reply(0x01, true, RESPONSE, 42, 5, 1000),
            &expect(&ak, None, None),
        )
        .unwrap();
        assert_eq!(text(&v.pdu), b"VERO");
        assert_eq!(v.clock, Some((5, 1000)));
    }

    #[test]
    fn v3_senza_flag_auth_rifiutata() {
        // right msgID, auth flag missing and no signature: must be rejected with authNoPriv
        let (ak, _) = keys();
        let e = verify_v3(
            &reply(0x00, false, RESPONSE, 42, 5, 1000),
            &expect(&ak, None, None),
        )
        .err()
        .unwrap();
        assert!(e.contains("protezione richiesta"), "{e}");
        // an unprotected report is allowed, but without updating the clock (it becomes an error)
        let v = verify_v3(
            &reply(0x00, false, REPORT, 0, 99, 99),
            &expect(&ak, None, None),
        )
        .unwrap();
        assert_eq!(v.pdu.tag, REPORT);
        assert_eq!(v.clock, None);
    }

    #[test]
    fn v3_firma_e_campi_errati() {
        let (ak, _) = keys();
        let ex = expect(&ak, None, None);
        // tampered signature
        let mut m = reply(0x01, true, RESPONSE, 42, 5, 1000);
        let r = parse_v3(&m).unwrap();
        m[r.auth_at] ^= 0xff;
        assert!(verify_v3(&m, &ex)
            .err()
            .unwrap()
            .contains("firma non valida"));
        // auth flag with empty signature (wrong length)
        let e = verify_v3(&reply(0x01, false, RESPONSE, 42, 5, 1000), &ex)
            .err()
            .unwrap();
        assert!(e.contains("Lunghezza"), "{e}");
        // request-id diverso
        let e = verify_v3(&reply(0x01, true, RESPONSE, 43, 5, 1000), &ex)
            .err()
            .unwrap();
        assert!(e.contains("request-id"), "{e}");
        // engine ID diverso
        let other = Expect {
            engine_id: b"altro",
            ..expect(&ak, None, None)
        };
        let e = verify_v3(&reply(0x01, true, RESPONSE, 42, 5, 1000), &other)
            .err()
            .unwrap();
        assert!(e.contains("Engine ID"), "{e}");
        // different user
        let other = Expect {
            user: b"admin",
            ..expect(&ak, None, None)
        };
        let e = verify_v3(&reply(0x01, true, RESPONSE, 42, 5, 1000), &other)
            .err()
            .unwrap();
        assert!(e.contains("Utente"), "{e}");
        // different msgID
        let other = Expect {
            msg_id: 8,
            ..expect(&ak, None, None)
        };
        assert!(verify_v3(&reply(0x01, true, RESPONSE, 42, 5, 1000), &other).is_err());
        // priv without auth
        assert!(verify_v3(&reply(0x02, false, RESPONSE, 42, 5, 1000), &ex).is_err());
        // noAuthNoPriv requested, response declares auth
        let none = Expect {
            auth: None,
            ..expect(&ak, None, None)
        };
        assert!(verify_v3(&reply(0x01, true, RESPONSE, 42, 5, 1000), &none).is_err());
        assert!(verify_v3(&reply(0x00, false, RESPONSE, 42, 5, 1000), &none).is_ok());
    }

    #[test]
    fn v3_finestra_temporale() {
        let (ak, _) = keys();
        let ex = expect(&ak, None, Some((5, 1000)));
        let ok = |b, t| verify_v3(&reply(0x01, true, RESPONSE, 42, b, t), &ex).is_ok();
        assert!(!ok(4, 5000), "boots precedente");
        assert!(!ok(5, 800), "tempo indietro di oltre 150 s");
        assert!(ok(5, 900));
        assert!(ok(6, 1));
        assert!(!ok(0x7fff_ffff, 1));
    }

    #[test]
    fn v3_auth_priv() {
        let (ak, pk) = keys();
        let ex = expect(&ak, Some(&pk), None);
        // plaintext with authPriv: rejected even if signed
        let e = verify_v3(&reply(0x01, true, RESPONSE, 42, 5, 1000), &ex)
            .err()
            .unwrap();
        assert!(e.contains("protezione richiesta"), "{e}");
        // cifrata e firmata: accettata
        let (enc, salt) = usm::encrypt(
            Priv::Aes128,
            &pk,
            5,
            1000,
            1,
            &scoped(RESPONSE, 42, b"VERO"),
        )
        .unwrap();
        let m = build_v3(V3Out {
            msg_id: 7,
            flags: 0x03,
            engine_id: ENGINE,
            boots: 5,
            time: 1000,
            user: USER,
            priv_params: &salt,
            data: ber::octets(&enc),
            auth: Some((Auth::Sha1, ak.as_slice())),
        });
        assert_eq!(text(&verify_v3(&m, &ex).unwrap().pdu), b"VERO");
        // encrypted data without priv flag
        let m = build_v3(V3Out {
            msg_id: 7,
            flags: 0x01,
            engine_id: ENGINE,
            boots: 5,
            time: 1000,
            user: USER,
            priv_params: &salt,
            data: ber::octets(&enc),
            auth: Some((Auth::Sha1, ak.as_slice())),
        });
        assert!(verify_v3(&m, &ex).is_err());
        // authenticated plaintext report (out of window): allowed and updates the clock
        let v = verify_v3(&reply(0x01, true, REPORT, 0, 6, 10), &ex).unwrap();
        assert_eq!(v.clock, Some((6, 10)));
    }

    /// Fake UDP agent: before the real response, a signed response from
    /// another port and an unauthenticated one with the same msgID arrive. The real one wins.
    #[tokio::test]
    async fn v3_pacchetti_falsi_scartati() {
        let agent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = agent.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (ak, _) = keys();
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, peer) = agent.recv_from(&mut buf).await.unwrap();
                let req = parse_v3(&buf[..n]).unwrap();
                let mut rd = Reader::new(&req.data);
                let mut sc = rd.enter(SEQUENCE).unwrap();
                sc.octets().unwrap();
                sc.octets().unwrap();
                let rid = decode_pdu(&mut sc).unwrap().request_id as i32;
                let mid = req.msg_id as i32;
                if req.engine_id.is_empty() {
                    // discovery: unauthenticated report with engine ID, boots and time
                    let m = build_v3(V3Out {
                        msg_id: mid,
                        flags: 0,
                        engine_id: ENGINE,
                        boots: 5,
                        time: 1000,
                        user: b"",
                        priv_params: b"",
                        data: scoped(REPORT, rid, b""),
                        auth: None,
                    });
                    agent.send_to(&m, peer).await.unwrap();
                    continue;
                }
                let msg = |flags: u8, text: &[u8], sign: bool| {
                    build_v3(V3Out {
                        msg_id: mid,
                        flags,
                        engine_id: ENGINE,
                        boots: 5,
                        time: 1001,
                        user: USER,
                        priv_params: b"",
                        data: scoped(RESPONSE, rid, text),
                        auth: sign.then_some((Auth::Sha1, ak.as_slice())),
                    })
                };
                spoof
                    .send_to(&msg(0x01, b"ALTRA-PORTA", true), peer)
                    .await
                    .unwrap();
                agent
                    .send_to(&msg(0x00, b"FALSO", false), peer)
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                agent
                    .send_to(&msg(0x01, b"VERO", true), peer)
                    .await
                    .unwrap();
                break;
            }
        });
        let mut s = Session::new(
            addr,
            Security::V3(V3Config {
                user: "u_sha".into(),
                level: Level::AuthNoPriv,
                auth: Some((Auth::Sha1, "authpass123".into())),
                privacy: None,
            }),
        )
        .await
        .unwrap();
        let p = s
            .request(GET, 0, 0, &[vec![1, 3, 6, 1, 2, 1, 1, 5, 0]])
            .await
            .unwrap();
        assert_eq!(text(&p), b"VERO");
        assert!(s.engine.as_ref().unwrap().synced);
        task.await.unwrap();
    }

    /// Only fake packets: an error with the discard reason, not a result.
    #[tokio::test]
    async fn v3_solo_risposta_non_autenticata() {
        let agent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = agent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = agent.recv_from(&mut buf).await else {
                    return;
                };
                let req = parse_v3(&buf[..n]).unwrap();
                let mut rd = Reader::new(&req.data);
                let mut sc = rd.enter(SEQUENCE).unwrap();
                sc.octets().unwrap();
                sc.octets().unwrap();
                let rid = decode_pdu(&mut sc).unwrap().request_id as i32;
                let discovery = req.engine_id.is_empty();
                let m = build_v3(V3Out {
                    msg_id: req.msg_id as i32,
                    flags: 0,
                    engine_id: ENGINE,
                    boots: 5,
                    time: 1000,
                    user: if discovery { b"" } else { USER },
                    priv_params: b"",
                    data: scoped(if discovery { REPORT } else { RESPONSE }, rid, b"FALSO"),
                    auth: None,
                });
                agent.send_to(&m, peer).await.unwrap();
            }
        });
        let mut s = Session::new(
            addr,
            Security::V3(V3Config {
                user: "u_sha".into(),
                level: Level::AuthNoPriv,
                auth: Some((Auth::Sha1, "authpass123".into())),
                privacy: None,
            }),
        )
        .await
        .unwrap();
        s.timeout = Duration::from_millis(300);
        s.retries = 0;
        let e = s
            .request(GET, 0, 0, &[vec![1, 3, 6, 1, 2, 1, 1, 5, 0]])
            .await
            .unwrap_err();
        assert!(e.starts_with("Risposta dell'agente scartata"), "{e}");
        assert!(e.contains("protezione richiesta"), "{e}");
    }

    /// Connected socket: a closed port (ICMP port unreachable) gives a clear error.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn porta_udp_chiusa() {
        let addr = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let mut s = Session::new(
            addr,
            Security::Community {
                v2c: true,
                community: "public".into(),
            },
        )
        .await
        .unwrap();
        s.retries = 0;
        let e = s
            .request(GET, 0, 0, &[vec![1, 3, 6, 1, 2, 1, 1, 5, 0]])
            .await
            .unwrap_err();
        assert!(e.contains("chiusa"), "{e}");
    }
}
