//! Fake SNMP agent for tests: v1 and v2c on 127.0.0.1, with GET, GETNEXT and GETBULK
//! over a small in-memory MIB that the test can change while the agent runs.

use super::ber::{self, Reader, SEQUENCE};
use super::client::{decode_pdu, GET, GET_BULK, GET_NEXT, RESPONSE};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

/// OID → value already BER-encoded.
pub type Mib = BTreeMap<Vec<u32>, Vec<u8>>;

pub struct Agent {
    pub addr: SocketAddr,
    pub mib: Arc<Mutex<Mib>>,
    /// Requests received with the right community.
    pub requests: Arc<AtomicUsize>,
}

fn uint(tag: u8, v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let skip = b.iter().take_while(|x| **x == 0).count().min(7);
    let mut c = b[skip..].to_vec();
    if c[0] & 0x80 != 0 {
        c.insert(0, 0);
    }
    ber::tlv(tag, &c)
}

pub fn text(s: &str) -> Vec<u8> {
    ber::octets(s.as_bytes())
}
pub fn counter32(v: u64) -> Vec<u8> {
    uint(0x41, v)
}
pub fn gauge(v: u64) -> Vec<u8> {
    uint(0x42, v)
}
pub fn ticks(v: u64) -> Vec<u8> {
    uint(0x43, v)
}
pub fn counter64(v: u64) -> Vec<u8> {
    uint(0x46, v)
}
pub fn ip(a: [u8; 4]) -> Vec<u8> {
    ber::tlv(0x40, &a)
}

/// `<name>.<index>` → OID, with the built-in names.
pub fn at(name: &str, index: &[u32]) -> Vec<u32> {
    let mut o = super::mib::oid_of(name);
    o.extend_from_slice(index);
    o
}

fn respond(
    mib: &Mib,
    v2c: bool,
    tag: u8,
    a: i64,
    b: i64,
    oids: &[Vec<u32>],
) -> (i64, Vec<Vec<u8>>) {
    let vb = |o: &[u32], v: Vec<u8>| ber::seq(&[ber::oid(o), v]);
    // like a real agent: with v1 Counter64 does not exist
    let visible = |v: &Vec<u8>| v2c || v.first() != Some(&0x46);
    let next = |o: &[u32]| {
        mib.range::<[u32], _>((std::ops::Bound::Excluded(o), std::ops::Bound::Unbounded))
            .find(|(_, v)| visible(v))
    };
    let mut out = Vec::new();
    match tag {
        GET => {
            for o in oids {
                match mib.get(o).filter(|v| visible(v)) {
                    Some(v) => out.push(vb(o, v.clone())),
                    None if v2c => out.push(vb(o, ber::tlv(0x81, &[]))),
                    None => return (2, oids.iter().map(|o| vb(o, ber::null())).collect()),
                }
            }
        }
        GET_NEXT => {
            for o in oids {
                match next(o) {
                    Some((k, v)) => out.push(vb(k, v.clone())),
                    None if v2c => out.push(vb(o, ber::tlv(0x82, &[]))),
                    None => return (2, oids.iter().map(|o| vb(o, ber::null())).collect()),
                }
            }
        }
        GET_BULK => {
            let _non_repeaters = a;
            for o in oids {
                let mut cur = o.clone();
                for _ in 0..b.max(1) {
                    match next(&cur) {
                        Some((k, v)) => {
                            out.push(vb(k, v.clone()));
                            cur = k.clone();
                        }
                        None => {
                            out.push(vb(&cur, ber::tlv(0x82, &[])));
                            break;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    (0, out)
}

/// Starts the agent: answers only to the given community (stays silent for others).
pub async fn agent(mib: Mib, community: &str) -> Agent {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let mib = Arc::new(Mutex::new(mib));
    let requests = Arc::new(AtomicUsize::new(0));
    let (m, n, community) = (mib.clone(), requests.clone(), community.to_string());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((len, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let mut r = Reader::new(&buf[..len]);
            let Ok(mut msg) = r.enter(SEQUENCE) else {
                continue;
            };
            let (Ok(ver), Ok(comm)) = (msg.int(), msg.octets()) else {
                continue;
            };
            if comm != community.as_bytes() {
                continue;
            }
            let Ok(pdu) = decode_pdu(&mut msg) else {
                continue;
            };
            n.fetch_add(1, Ordering::SeqCst);
            let oids: Vec<Vec<u32>> = pdu.varbinds.iter().map(|v| v.oid.clone()).collect();
            let (status, vbs) = {
                let mib = m.lock().unwrap();
                respond(
                    &mib,
                    ver == 1,
                    pdu.tag,
                    pdu.error_status,
                    pdu.error_index,
                    &oids,
                )
            };
            let reply = ber::seq(&[
                ber::int(ver),
                ber::octets(comm),
                ber::tlv(
                    RESPONSE,
                    &[
                        ber::int(pdu.request_id),
                        ber::int(status),
                        ber::int(if status == 0 { 0 } else { 1 }),
                        ber::seq(&vbs),
                    ]
                    .concat(),
                ),
            ]);
            let _ = sock.send_to(&reply, from).await;
        }
    });
    Agent {
        addr,
        mib,
        requests,
    }
}
