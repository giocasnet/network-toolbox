//! Live interface counters: one reading every few seconds, speed from the difference
//! between two readings, errors and discards since the monitor started.

use super::client::{Session, Value};
use super::device::state;
use super::{connect, mib, walk, SnmpReq};
use crate::ping::Stop;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub const INTERVAL_S: u32 = 5;
pub const MIN_INTERVAL_S: u32 = 2;
pub const MAX_INTERVAL_S: u32 = 60;
/// Consecutive failed readings after which the monitor closes by itself.
const MAX_FAILS: u32 = 3;
const STOPPED: &str = "STOP";

#[derive(Debug, Default, Deserialize)]
pub struct MonitorReq {
    #[serde(flatten)]
    pub snmp: SnmpReq,
    /// Seconds between two readings (default 5).
    #[serde(default, deserialize_with = "crate::util::opt_u32")]
    pub interval_s: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PortCounters {
    pub in_octets: Option<u64>,
    pub out_octets: Option<u64>,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    pub admin: Option<u64>,
    pub oper: Option<u64>,
}

/// One reading of the counters of all interfaces.
#[derive(Debug, Clone, Default)]
pub struct Counters {
    /// Milliseconds since the monitor started.
    pub at_ms: u64,
    /// 64-bit byte counters (ifHCInOctets) instead of 32-bit ones.
    pub hc: bool,
    pub ports: BTreeMap<u32, PortCounters>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PortSample {
    pub index: u32,
    /// Bits per second since the last reading; `None` if the counter is missing or restarted.
    pub in_bps: Option<f64>,
    pub out_bps: Option<f64>,
    /// Errors and discards since the monitor started.
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    pub state: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MonitorMsg {
    Start {
        hc: bool,
        interval_s: u32,
        ports: usize,
    },
    Sample {
        t_ms: u64,
        ports: Vec<PortSample>,
    },
}

#[derive(Debug, Serialize)]
pub struct MonitorEnd {
    pub samples: usize,
    pub elapsed_s: f64,
    pub stopped: bool,
    /// Why the monitor closed by itself (the agent no longer answers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Difference between two readings of a counter. With 32 bits a lower value is a counter
/// wrap; with 64 bits it is a restarted counter (port or device restarted).
pub fn delta(prev: u64, cur: u64, bits64: bool) -> Option<u64> {
    if cur >= prev {
        Some(cur - prev)
    } else if bits64 {
        None
    } else {
        Some(cur + (1u64 << 32) - prev)
    }
}

/// Sample from the comparison with the previous reading (speed) and the first (errors).
pub fn sample(base: &Counters, prev: &Counters, cur: &Counters) -> Vec<PortSample> {
    let secs = cur.at_ms.saturating_sub(prev.at_ms) as f64 / 1000.0;
    let bps = |p: Option<u64>, c: Option<u64>| -> Option<f64> {
        let d = delta(p?, c?, cur.hc)?;
        (secs > 0.0).then(|| d as f64 * 8.0 / secs)
    };
    cur.ports
        .iter()
        .map(|(i, c)| {
            let p = prev.ports.get(i);
            let b = base.ports.get(i);
            // the error counters are always 32-bit
            let since =
                |f: fn(&PortCounters) -> u64| b.and_then(|b| delta(f(b), f(c), false)).unwrap_or(0);
            PortSample {
                index: *i,
                in_bps: bps(p.and_then(|p| p.in_octets), c.in_octets),
                out_bps: bps(p.and_then(|p| p.out_octets), c.out_octets),
                in_errors: since(|x| x.in_errors),
                out_errors: since(|x| x.out_errors),
                in_discards: since(|x| x.in_discards),
                out_discards: since(|x| x.out_discards),
                state: state(c.admin, c.oper),
            }
        })
        .collect()
}

/// Where the readings come from: the agent in the program, a fake sequence in tests.
#[allow(async_fn_in_trait)]
pub(crate) trait Source {
    async fn poll(&mut self, stop: &Stop) -> Result<Counters>;
}

struct Agent {
    s: Session,
    started: Instant,
    /// Decided at the first reading: `Some(true)` if the agent has 64-bit counters.
    hc: Option<bool>,
}

fn number(v: &Value) -> Option<u64> {
    match v {
        Value::Int(i) => u64::try_from(*i).ok(),
        Value::Counter32(n) | Value::Gauge32(n) | Value::Counter64(n) => Some(*n),
        _ => None,
    }
}

impl Agent {
    async fn column(&mut self, name: &str, stop: &Stop) -> Result<BTreeMap<u32, u64>> {
        let root = mib::oid_of(name);
        let w = walk(&mut self.s, &root, stop).await?;
        if w.stopped {
            return Err(STOPPED.into());
        }
        Ok(w.vbs
            .iter()
            .filter(|v| v.oid.len() == root.len() + 1)
            .filter_map(|v| Some((v.oid[root.len()], number(&v.value)?)))
            .collect())
    }
}

impl Source for Agent {
    async fn poll(&mut self, stop: &Stop) -> Result<Counters> {
        let mut inb = BTreeMap::new();
        if self.hc != Some(false) {
            inb = self.column("ifHCInOctets", stop).await?;
        }
        let hc = *self.hc.get_or_insert(!inb.is_empty());
        let outb = if hc {
            self.column("ifHCOutOctets", stop).await?
        } else {
            inb = self.column("ifInOctets", stop).await?;
            self.column("ifOutOctets", stop).await?
        };
        let at_ms = self.started.elapsed().as_millis() as u64;
        let ie = self.column("ifInErrors", stop).await?;
        let oe = self.column("ifOutErrors", stop).await?;
        let id = self.column("ifInDiscards", stop).await?;
        let od = self.column("ifOutDiscards", stop).await?;
        let admin = self.column("ifAdminStatus", stop).await?;
        let oper = self.column("ifOperStatus", stop).await?;
        let ports = oper
            .keys()
            .chain(inb.keys())
            .map(|i| {
                let get = |m: &BTreeMap<u32, u64>| m.get(i).copied();
                (
                    *i,
                    PortCounters {
                        in_octets: get(&inb),
                        out_octets: get(&outb),
                        in_errors: get(&ie).unwrap_or(0),
                        out_errors: get(&oe).unwrap_or(0),
                        in_discards: get(&id).unwrap_or(0),
                        out_discards: get(&od).unwrap_or(0),
                        admin: get(&admin),
                        oper: get(&oper),
                    },
                )
            })
            .collect();
        Ok(Counters { at_ms, hc, ports })
    }
}

pub(crate) async fn monitor_with<S: Source, F: FnMut(MonitorMsg)>(
    mut source: S,
    interval: Duration,
    stop: &Stop,
    mut emit: F,
) -> Result<MonitorEnd> {
    let started = Instant::now();
    let end = |samples, stopped, error| MonitorEnd {
        samples,
        elapsed_s: (started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        stopped,
        error,
    };
    // the first reading is the reference: if it fails the monitor does not start
    let base = match source.poll(stop).await {
        Ok(c) => c,
        Err(e) if e == STOPPED => return Ok(end(0, true, None)),
        Err(e) => return Err(e),
    };
    if base.ports.is_empty() {
        return Err(crate::t!(
            "L'agente non espone i contatori delle interfacce (IF-MIB)",
            "The agent does not expose the interface counters (IF-MIB)"
        )
        .into());
    }
    emit(MonitorMsg::Start {
        hc: base.hc,
        interval_s: interval.as_secs() as u32,
        ports: base.ports.len(),
    });
    let mut prev = base.clone();
    let (mut samples, mut fails) = (0usize, 0u32);
    loop {
        if stop.race(tokio::time::sleep(interval)).await.is_none() {
            return Ok(end(samples, true, None));
        }
        match source.poll(stop).await {
            Ok(cur) => {
                fails = 0;
                samples += 1;
                emit(MonitorMsg::Sample {
                    t_ms: cur.at_ms,
                    ports: sample(&base, &prev, &cur),
                });
                prev = cur;
            }
            Err(e) if e == STOPPED => return Ok(end(samples, true, None)),
            Err(e) => {
                fails += 1;
                if fails >= MAX_FAILS {
                    return Ok(end(samples, false, Some(e)));
                }
            }
        }
    }
}

pub async fn run<F: FnMut(MonitorMsg)>(
    req: MonitorReq,
    stop: &Stop,
    emit: F,
) -> Result<MonitorEnd> {
    let interval = match req.interval_s {
        None => INTERVAL_S,
        Some(s) if (MIN_INTERVAL_S..=MAX_INTERVAL_S).contains(&s) => s,
        Some(_) => {
            return Err(crate::tf!(
                "Intervallo: da {MIN_INTERVAL_S} a {MAX_INTERVAL_S} secondi",
                "Interval: {MIN_INTERVAL_S} to {MAX_INTERVAL_S} seconds"
            ))
        }
    };
    let c = connect(&req.snmp).await?;
    let (host, v3) = (c.host.clone(), c.v3);
    let explain = |e: String| {
        if e == "TIMEOUT" {
            super::timeout_msg(&host, v3)
        } else {
            e
        }
    };
    let agent = Agent {
        s: c.s,
        started: Instant::now(),
        hc: None,
    };
    let mut end = monitor_with(agent, Duration::from_secs(interval as u64), stop, emit)
        .await
        .map_err(explain)?;
    end.error = end.error.map(explain);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::super::ber;
    use super::super::fake::{self, at, counter32, counter64};
    use super::*;

    fn port(inb: u64, outb: u64, err: u64) -> PortCounters {
        PortCounters {
            in_octets: Some(inb),
            out_octets: Some(outb),
            in_errors: err,
            admin: Some(1),
            oper: Some(1),
            ..Default::default()
        }
    }

    fn counters(at_ms: u64, hc: bool, ports: &[(u32, PortCounters)]) -> Counters {
        Counters {
            at_ms,
            hc,
            ports: ports.iter().cloned().collect(),
        }
    }

    #[test]
    fn differenze() {
        assert_eq!(delta(10, 25, false), Some(15));
        assert_eq!(delta(10, 25, true), Some(15));
        // 32-bit counter wrap; with 64 bits a lower value is a restarted counter
        assert_eq!(delta(u32::MAX as u64 - 5, 10, false), Some(16));
        assert_eq!(delta(1000, 10, true), None);
    }

    #[test]
    fn campioni() {
        let base = counters(0, true, &[(1, port(1000, 0, 5)), (2, port(0, 0, 0))]);
        let prev = counters(5000, true, &[(1, port(2000, 0, 6)), (2, port(0, 0, 0))]);
        // port 1: 1.25 MB in 5 s = 2 Mb/s; 9 errors since the start. Port 3 just appeared.
        let cur = counters(
            10_000,
            true,
            &[
                (1, port(2000 + 1_250_000, 625_000, 14)),
                (
                    2,
                    PortCounters {
                        oper: Some(2),
                        admin: Some(1),
                        ..port(0, 0, 0)
                    },
                ),
                (3, port(77, 77, 3)),
            ],
        );
        let s = sample(&base, &prev, &cur);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].in_bps, Some(2_000_000.0));
        assert_eq!(s[0].out_bps, Some(1_000_000.0));
        assert_eq!((s[0].in_errors, s[0].state), (9, "up"));
        assert_eq!((s[1].in_bps, s[1].state), (Some(0.0), "down"));
        // without a previous reading there is no speed, and errors start from zero
        assert_eq!((s[2].in_bps, s[2].in_errors), (None, 0));

        // restarted 64-bit counter: no speed instead of a huge number
        let reset = counters(15_000, true, &[(1, port(10, 10, 14))]);
        assert_eq!(sample(&base, &cur, &reset)[0].in_bps, None);
        // with 32 bits the same jump is a counter wrap
        let a = counters(0, false, &[(1, port(u32::MAX as u64 - 624_999, 0, 0))]);
        let b = counters(5000, false, &[(1, port(0, 0, 0))]);
        assert_eq!(sample(&a, &a, &b)[0].in_bps, Some(1_000_000.0));
        // two readings at the same instant: no division by zero
        assert_eq!(sample(&base, &base, &base)[0].in_bps, None);
    }

    /// Fake source: one reading per element, then errors.
    struct Seq(Vec<Result<Counters>>);
    impl Source for Seq {
        async fn poll(&mut self, _: &Stop) -> Result<Counters> {
            if self.0.is_empty() {
                Err("TIMEOUT".into())
            } else {
                self.0.remove(0)
            }
        }
    }

    #[tokio::test]
    async fn monitor_finto() {
        let step = |n: u64| counters(n * 1000, true, &[(1, port(n * 125_000, 0, n))]);
        // three good readings, one failed in the middle (retry), then the agent disappears
        let seq = vec![Ok(step(0)), Ok(step(1)), Err("TIMEOUT".into()), Ok(step(3))];
        let mut msgs = Vec::new();
        let end = monitor_with(Seq(seq), Duration::from_millis(5), &Stop::new(), |m| {
            msgs.push(m)
        })
        .await
        .unwrap();
        assert_eq!((end.samples, end.stopped), (2, false));
        assert_eq!(end.error.as_deref(), Some("TIMEOUT"));
        assert!(matches!(
            msgs[0],
            MonitorMsg::Start {
                hc: true,
                ports: 1,
                ..
            }
        ));
        let MonitorMsg::Sample { t_ms, ports } = &msgs[1] else {
            panic!("{:?}", msgs[1])
        };
        assert_eq!(*t_ms, 1000);
        assert_eq!(ports[0].in_bps, Some(1_000_000.0));
        // after the skipped reading the speed is over the real duration (2 s), not the interval
        let MonitorMsg::Sample { ports, .. } = &msgs[2] else {
            panic!()
        };
        assert_eq!(
            (ports[0].in_bps, ports[0].in_errors),
            (Some(1_000_000.0), 3)
        );

        // first reading failed: the monitor does not start
        let e = monitor_with(Seq(vec![]), Duration::from_millis(5), &Stop::new(), |_| {})
            .await
            .unwrap_err();
        assert_eq!(e, "TIMEOUT");
        // no interfaces
        let e = monitor_with(
            Seq(vec![Ok(Counters::default())]),
            Duration::from_millis(5),
            &Stop::new(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(e.contains("IF-MIB"), "{e}");
    }

    fn mib(hc: bool) -> fake::Mib {
        let mut m = fake::Mib::new();
        for i in [1u32, 2] {
            m.insert(at("ifAdminStatus", &[i]), ber::int(1));
            m.insert(at("ifOperStatus", &[i]), ber::int(i as i64));
            m.insert(at("ifInOctets", &[i]), counter32(100));
            m.insert(at("ifOutOctets", &[i]), counter32(200));
            m.insert(at("ifInErrors", &[i]), counter32(7));
            if hc {
                m.insert(at("ifHCInOctets", &[i]), counter64(1 << 40));
                m.insert(at("ifHCOutOctets", &[i]), counter64(1 << 41));
            }
        }
        m
    }

    fn req(a: &fake::Agent) -> MonitorReq {
        MonitorReq {
            snmp: SnmpReq {
                host: "127.0.0.1".into(),
                version: Some("2c".into()),
                community: Some("prova-lettura".into()),
                port: Some(a.addr.port() as u32),
                ..Default::default()
            },
            interval_s: None,
        }
    }

    /// Real reading of the counters from the fake agent: 64-bit if present, otherwise 32-bit.
    #[tokio::test]
    async fn lettura_dei_contatori() {
        for hc in [true, false] {
            let a = fake::agent(mib(hc), "prova-lettura").await;
            let c = connect(&req(&a).snmp).await.unwrap();
            let mut ag = Agent {
                s: c.s,
                started: Instant::now(),
                hc: None,
            };
            let first = ag.poll(&Stop::new()).await.unwrap();
            assert_eq!(first.hc, hc);
            assert_eq!(first.ports.len(), 2);
            let p = &first.ports[&2];
            assert_eq!(p.in_octets, Some(if hc { 1 << 40 } else { 100 }));
            assert_eq!(p.out_octets, Some(if hc { 1 << 41 } else { 200 }));
            assert_eq!((p.in_errors, p.out_errors, p.oper), (7, 0, Some(2)));
            // the agent counts: at the next reading the bytes have grown
            a.mib
                .lock()
                .unwrap()
                .insert(at("ifInOctets", &[2]), counter32(100 + 2500));
            a.mib
                .lock()
                .unwrap()
                .insert(at("ifHCInOctets", &[2]), counter64((1 << 40) + 2500));
            let mut second = ag.poll(&Stop::new()).await.unwrap();
            second.at_ms = first.at_ms + 2000;
            let s = sample(&first, &first, &second);
            assert_eq!(s[1].in_bps, Some(10_000.0), "hc {hc}");
            assert_eq!(s[1].state, "down");
            // the choice between 64 and 32 bits is made once: the second reading costs one column less
            assert_eq!(ag.hc, Some(hc));
        }
    }

    #[tokio::test]
    async fn monitor_vero_e_stop() {
        let a = fake::agent(mib(true), "prova-lettura").await;
        let mut r = req(&a);
        r.interval_s = Some(1);
        assert_eq!(
            run(r, &Stop::new(), |_| {}).await.unwrap_err(),
            "Intervallo: da 2 a 60 secondi"
        );
        // stopped while waiting between two readings
        let stop = Stop::new();
        let s2 = stop.clone();
        let mut started = false;
        let end = run(req(&a), &stop, |m| {
            if matches!(m, MonitorMsg::Start { .. }) {
                started = true;
                s2.stop();
            }
        })
        .await
        .unwrap();
        assert!(started && end.stopped && end.samples == 0 && end.error.is_none());
        // silent agent: error with the possible reasons (shortening the session timeout by
        // hand is not needed: the stop already received avoids waiting)
        let stopped = Stop::new();
        stopped.stop();
        let end = run(req(&a), &stopped, |_| {}).await.unwrap();
        assert!(end.stopped && end.samples == 0);
    }

    #[tokio::test]
    async fn english_errors() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let e = monitor_with(
            Seq(vec![Ok(Counters::default())]),
            Duration::from_millis(5),
            &Stop::new(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(
            e,
            "The agent does not expose the interface counters (IF-MIB)"
        );
        assert!(!e.contains("L'agente"));
        let a = fake::agent(mib(true), "prova-lettura").await;
        let mut r = req(&a);
        r.interval_s = Some(1);
        let e = run(r, &Stop::new(), |_| {}).await.unwrap_err();
        assert_eq!(e, "Interval: 2 to 60 seconds");
    }
}
