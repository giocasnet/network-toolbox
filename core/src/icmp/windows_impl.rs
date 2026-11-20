//! Windows backend: IP Helper API.
//!
//! Two ways of sending an echo:
//! - `echo_blocking` (`IcmpSendEcho`): a call that waits for the reply, in a
//!   pool thread. It is the one used by ping, traceroute and the home screen: few
//!   probes, times measured with maximum precision.
//! - `echo_async` (`IcmpSendEcho2Ex`): for the scans. A single dedicated thread
//!   starts all the requests on one handle and receives the replies as APCs
//!   while waiting: no thread per probe. If the engine does not start or does not
//!   answer, the caller falls back to `echo_blocking`.

use super::{Echo, EchoOpts, Status, PAYLOAD};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpNetTable2, IcmpCloseHandle, IcmpCreateFile, IcmpParseReplies, IcmpSendEcho,
    IcmpSendEcho2Ex, SendARP, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION, MIB_IPNET_ROW2,
    MIB_IPNET_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    NlnsDelay, NlnsPermanent, NlnsProbe, NlnsReachable, NlnsStale, AF_INET,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThreadId, OpenThread, QueueUserAPC, SleepEx, INFINITE, THREAD_SET_CONTEXT,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

// IP_STATUS codes (ipexport.h)
const IP_SUCCESS: u32 = 0;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
const IP_PACKET_TOO_BIG: u32 = 11009;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;

fn status_of(code: u32) -> Status {
    match code {
        IP_SUCCESS => Status::Reply,
        IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => Status::TtlExpired,
        IP_PACKET_TOO_BIG => Status::TooBig,
        IP_REQ_TIMED_OUT => Status::Timeout,
        IP_DEST_NET_UNREACHABLE
        | IP_DEST_HOST_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE => Status::Unreachable,
        other => Status::Error(other),
    }
}

/// IP_FLAG_DF of `IP_OPTION_INFORMATION.Flags`: "Do not fragment".
const IP_FLAG_DF: u8 = 0x02;

/// Space for the reply to a request with `size` data bytes: ICMP_ECHO_REPLY +
/// data + 8 bytes for a possible ICMP error message + IO_STATUS_BLOCK (required
/// by asynchronous calls) + margin.
fn reply_len(size: usize) -> usize {
    size_of::<ICMP_ECHO_REPLY>() + size + 8 + size_of::<IO_STATUS_BLOCK>() + 64
}

/// Data of every echo request.
static DATA: [u8; PAYLOAD] = [b'a'; PAYLOAD];

/// Reply buffer, 8-byte aligned.
fn reply_buffer(size: usize) -> Vec<u64> {
    vec![0u64; reply_len(size).div_ceil(8)]
}

/// Parses the buffer filled by IcmpSendEcho / IcmpParseReplies.
/// `n` is the number of replies returned, `last_error` the error if `n` is zero,
/// `measured_ms` the time measured by the caller. With `kernel_rtt` the
/// measured time is kept within the millisecond given by Windows in the
/// reply: needed by the asynchronous engine, where some moments can pass between the
/// reply arriving and its delivery to the thread.
///
/// # Safety
/// `buf` must be the buffer passed to the ICMP call, at least `reply_len(size)` long.
unsafe fn parse_reply(
    buf: &[u64],
    n: u32,
    last_error: u32,
    measured_ms: f64,
    kernel_rtt: bool,
) -> Echo {
    let reply = &*(buf.as_ptr() as *const ICMP_ECHO_REPLY);
    let from = (reply.Address != 0).then(|| Ipv4Addr::from(reply.Address.to_ne_bytes()));
    // With an expired TTL some Windows versions return 0 but still fill
    // the reply with the router's address: in that case we use it.
    let code = if n > 0 || (from.is_some() && reply.Status != IP_SUCCESS) {
        reply.Status
    } else {
        last_error
    };
    let status = match status_of(code) {
        // no reply and no error code: it is not a reply
        Status::Reply if n == 0 => Status::Timeout,
        s => s,
    };
    let rtt_ms = if kernel_rtt && status == Status::Reply {
        let k = reply.RoundTripTime as f64;
        if measured_ms < k + 1.0 {
            measured_ms.max(k)
        } else {
            k + 0.5
        }
    } else {
        measured_ms
    };
    Echo {
        status,
        from: if status == Status::Timeout {
            None
        } else {
            from
        },
        rtt_ms,
        ttl: (status == Status::Reply).then_some(reply.Options.Ttl),
    }
}

fn error(code: u32) -> Echo {
    Echo {
        status: status_of(code),
        from: None,
        rtt_ms: 0.0,
        ttl: None,
    }
}

pub fn echo_blocking(dest: Ipv4Addr, o: EchoOpts, timeout_ms: u32) -> Echo {
    let mut buf = reply_buffer(o.size);
    let data = vec![b'a'; o.size];
    unsafe {
        let handle = IcmpCreateFile();
        if handle == INVALID_HANDLE_VALUE {
            return Echo {
                status: Status::Error(GetLastError()),
                from: None,
                rtt_ms: 0.0,
                ttl: None,
            };
        }
        let mut opts: IP_OPTION_INFORMATION = std::mem::zeroed();
        opts.Ttl = o.ttl;
        if o.dont_fragment {
            opts.Flags = IP_FLAG_DF;
        }

        let t0 = Instant::now();
        let n = IcmpSendEcho(
            handle,
            u32::from_ne_bytes(dest.octets()),
            data.as_ptr() as *const c_void,
            o.size as u16,
            &opts,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8) as u32,
            timeout_ms,
        );
        let rtt_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let last_error = if n == 0 { GetLastError() } else { 0 };
        IcmpCloseHandle(handle);
        parse_reply(&buf, n, last_error, rtt_ms, false)
    }
}

// ───────────────────────── asynchronous engine (scans) ─────────────────────────

struct Job {
    dest: Ipv4Addr,
    ttl: u8,
    timeout_ms: u32,
    reply: oneshot::Sender<Echo>,
}

/// A request in progress: lives from start to the `on_reply` call, always on the
/// engine thread.
struct Pending {
    buf: Vec<u64>,
    t0: Instant,
    reply: Option<oneshot::Sender<Echo>>,
}

struct Engine {
    jobs: Mutex<mpsc::Sender<Job>>,
    /// Handle of the engine thread (as an integer), to wake it; 0 if not
    /// available: in that case the thread checks the queue at intervals.
    thread: usize,
}

static ENGINE: OnceLock<Option<Engine>> = OnceLock::new();
/// The engine did not answer a request: it is no longer used until the app restarts.
static DISABLED: AtomicBool = AtomicBool::new(false);

fn engine() -> Option<&'static Engine> {
    if DISABLED.load(Ordering::Relaxed) {
        return None;
    }
    ENGINE.get_or_init(start_engine).as_ref()
}

fn start_engine() -> Option<Engine> {
    let (jobs, rx) = mpsc::channel::<Job>();
    let (ready, started) = mpsc::channel::<Option<usize>>();
    std::thread::Builder::new()
        .name("ntb-icmp".into())
        .spawn(move || engine_thread(rx, ready))
        .ok()?;
    let thread = started.recv_timeout(Duration::from_secs(2)).ok()??;
    Some(Engine {
        jobs: Mutex::new(jobs),
        thread,
    })
}

/// Empty APC: only serves to make `SleepEx` return when there is a new request.
unsafe extern "system" fn wake(_: usize) {}

/// Reply (or timeout) of a request: called by Windows as an APC on the engine
/// thread, while it is waiting.
unsafe extern "system" fn on_reply(
    ctx: *mut c_void,
    _status: *mut IO_STATUS_BLOCK,
    _reserved: u32,
) {
    if ctx.is_null() {
        return;
    }
    let mut p = Box::from_raw(ctx as *mut Pending);
    let elapsed = p.t0.elapsed().as_secs_f64() * 1000.0;
    let n = IcmpParseReplies(p.buf.as_mut_ptr() as *mut c_void, (p.buf.len() * 8) as u32);
    let last_error = if n == 0 { GetLastError() } else { 0 };
    let echo = parse_reply(&p.buf, n, last_error, elapsed, true);
    if let Some(reply) = p.reply.take() {
        // whoever was waiting may have given up ("Stop"): the reply is discarded
        let _ = reply.send(echo);
    }
}

/// Starts a request on the engine thread.
unsafe fn start(icmp: HANDLE, job: Job) {
    let mut opts: IP_OPTION_INFORMATION = std::mem::zeroed();
    opts.Ttl = job.ttl;
    let ctx = Box::into_raw(Box::new(Pending {
        buf: reply_buffer(PAYLOAD),
        t0: Instant::now(),
        reply: Some(job.reply),
    }));
    let buf = (*ctx).buf.as_mut_ptr() as *mut c_void;
    let len = ((*ctx).buf.len() * 8) as u32;
    (*ctx).t0 = Instant::now();
    let r = IcmpSendEcho2Ex(
        icmp,
        std::ptr::null_mut(),
        Some(on_reply),
        ctx as *const c_void,
        0,
        u32::from_ne_bytes(job.dest.octets()),
        DATA.as_ptr() as *const c_void,
        PAYLOAD as u16,
        &opts,
        buf,
        len,
        job.timeout_ms,
    );
    let err = GetLastError();
    if r == ERROR_IO_PENDING || (r == 0 && err == ERROR_IO_PENDING) {
        return; // in progress: the outcome arrives at `on_reply`
    }
    if r == 0 {
        // did not start: `on_reply` will not be called, the request ends here
        let mut p = Box::from_raw(ctx);
        if let Some(reply) = p.reply.take() {
            let _ = reply.send(error(err));
        }
    }
    // Any other value (not expected in asynchronous mode): it is not known whether `on_reply`
    // will arrive, so the request stays where it is. If it does not arrive, whoever is waiting
    // times out and the engine is disabled (`disable_async`).
}

fn engine_thread(rx: mpsc::Receiver<Job>, ready: mpsc::Sender<Option<usize>>) {
    unsafe {
        let icmp = IcmpCreateFile();
        if icmp == INVALID_HANDLE_VALUE {
            let _ = ready.send(None);
            return;
        }
        let me = OpenThread(THREAD_SET_CONTEXT, 0, GetCurrentThreadId());
        let _ = ready.send(Some(me as usize));
        let wait_ms = if me.is_null() { 10 } else { INFINITE };
        loop {
            loop {
                match rx.try_recv() {
                    Ok(job) => {
                        start(icmp, job);
                        // deliver the replies already arrived at once, so the measured
                        // times do not depend on how many requests remain to be started
                        SleepEx(0, 1);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        IcmpCloseHandle(icmp);
                        return;
                    }
                }
            }
            // "alertable" wait: returns on every reply (APC) and every wake-up
            SleepEx(wait_ms, 1);
        }
    }
}

/// Starts an echo on the asynchronous engine. `None` if the engine is not available: the
/// caller uses `echo_blocking`.
pub fn echo_async(dest: Ipv4Addr, ttl: u8, timeout_ms: u32) -> Option<oneshot::Receiver<Echo>> {
    let eng = engine()?;
    let (reply, rx) = oneshot::channel();
    eng.jobs
        .lock()
        .ok()?
        .send(Job {
            dest,
            ttl,
            timeout_ms,
            reply,
        })
        .ok()?;
    if eng.thread != 0 {
        unsafe {
            QueueUserAPC(Some(wake), eng.thread as HANDLE, 0);
        }
    }
    Some(rx)
}

/// The asynchronous engine is usable (it starts it, if needed).
pub fn async_available() -> bool {
    engine().is_some()
}

/// Disables the asynchronous engine: from here on the scans use blocking echoes.
pub fn disable_async() {
    DISABLED.store(true, Ordering::Relaxed);
}

// ───────────────────────── ARP ─────────────────────────

/// Windows neighbour table (the ARP cache): IPv4 → MAC of the hosts that
/// answered ARP. A single call for the whole network, without waiting: after a
/// ping Windows has already resolved the address, even if the host does not answer ping.
/// `None` if the table cannot be read.
pub fn neighbors() -> Option<HashMap<Ipv4Addr, [u8; 6]>> {
    unsafe {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        if GetIpNetTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return None;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table) as *const MIB_IPNET_ROW2,
            n,
        );
        let mut map = HashMap::with_capacity(n);
        for r in rows {
            // resolved: reachable, or cached and being re-verified
            let resolved = [
                NlnsReachable,
                NlnsStale,
                NlnsDelay,
                NlnsProbe,
                NlnsPermanent,
            ]
            .contains(&r.State);
            if r.Address.si_family != AF_INET || !resolved || r.PhysicalAddressLength != 6 {
                continue;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&r.PhysicalAddress[..6]);
            // no null, broadcast or multicast addresses
            if mac == [0u8; 6] || mac[0] & 1 != 0 {
                continue;
            }
            let ip = Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            map.insert(ip, mac);
        }
        FreeMibTable(table as *const c_void);
        Some(map)
    }
}

pub fn arp_blocking(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let mut mac = [0u32; 2];
    let mut len: u32 = 6;
    let r = unsafe {
        SendARP(
            u32::from_ne_bytes(ip.octets()),
            0,
            mac.as_mut_ptr() as *mut c_void,
            &mut len,
        )
    };
    if r != 0 || len < 6 {
        return None;
    }
    let b: [u8; 8] = unsafe { std::mem::transmute(mac) };
    Some([b[0], b[1], b[2], b[3], b[4], b[5]])
}
