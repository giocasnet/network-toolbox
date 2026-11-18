//! Probe TCP connections (port scan, TCP check of the scans, local network
//! services) with a distinct outcome: open, refused, no answer.
//!
//! Windows retries the SYN after a refusal (RST) and reports the port as closed only
//! after about a second. To avoid that cost, on Windows a first attempt is made
//! with a socket that does not retransmit the SYN (`SIO_TCP_INITIAL_RTO`): there the
//! refusal arrives at once. That attempt only counts for certain answers (open
//! or refused); if none arrives it retries with a normal socket and the
//! full timeout, so an open port that answers late (connection
//! held back by the antivirus, lost SYN) is found as before.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Maximum wait of the attempt without SYN retransmission.
const QUICK: Duration = Duration::from_millis(1000);

pub enum Conn {
    Open(TcpStream),
    /// Refused by the host (RST): the port is closed, the host is up.
    Refused,
    /// No answer within the timeout (`None`) or local error.
    Failed(Option<std::io::Error>),
}

#[cfg(any(windows, ntb_check_windows))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_impl {
    use std::ffi::c_void;
    use windows_sys::Win32::Networking::WinSock::{
        WSAIoctl, SIO_TCP_INITIAL_RTO, SOCKET, TCP_INITIAL_RTO_PARAMETERS,
    };

    // mstcpip.h: TCP_INITIAL_RTO_UNSPECIFIED_RTT ((USHORT) -1) leaves the RTT as is,
    // TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS ((UCHAR) -2) removes retransmissions.
    const UNSPECIFIED_RTT: u16 = 0xFFFF;
    const NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

    /// Sets "no SYN retransmission" on the socket. `false` if the system
    /// does not accept it: in that case the socket must not be used for the quick attempt.
    pub fn no_syn_retry(sock: SOCKET) -> bool {
        let params = TCP_INITIAL_RTO_PARAMETERS {
            Rtt: UNSPECIFIED_RTT,
            MaxSynRetransmissions: NO_SYN_RETRANSMISSIONS,
        };
        let mut returned = 0u32;
        let r = unsafe {
            WSAIoctl(
                sock,
                SIO_TCP_INITIAL_RTO,
                &params as *const TCP_INITIAL_RTO_PARAMETERS as *const c_void,
                std::mem::size_of::<TCP_INITIAL_RTO_PARAMETERS>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        r == 0
    }
}

/// Socket for the quick attempt: Windows only, and only if the option is accepted.
#[cfg(windows)]
fn quick_socket(addr: SocketAddr) -> Option<tokio::net::TcpSocket> {
    use std::os::windows::io::AsRawSocket;
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .ok()?;
    windows_impl::no_syn_retry(sock.as_raw_socket() as usize).then_some(sock)
}

#[cfg(not(windows))]
fn quick_socket(_addr: SocketAddr) -> Option<tokio::net::TcpSocket> {
    None
}

/// The attempt without SYN retransmission is available on this system.
pub fn quick_available() -> bool {
    quick_socket(SocketAddr::from(([127, 0, 0, 1], 9))).is_some()
}

fn refused(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionRefused
}

/// Tries to connect to `addr` within `timeout`.
pub async fn connect(addr: SocketAddr, timeout: Duration) -> Conn {
    if let Some(sock) = quick_socket(addr) {
        match tokio::time::timeout(QUICK.min(timeout), sock.connect(addr)).await {
            Ok(Ok(s)) => return Conn::Open(s),
            Ok(Err(e)) if refused(&e) => return Conn::Refused,
            // no certain answer: retry the normal way
            _ => {}
        }
    }
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => Conn::Open(s),
        Ok(Err(e)) if refused(&e) => Conn::Refused,
        Ok(Err(e)) => Conn::Failed(Some(e)),
        Err(_) => Conn::Failed(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn aperta_e_rifiutata() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        assert!(matches!(
            connect(addr, Duration::from_secs(5)).await,
            Conn::Open(_)
        ));
        drop(l);
        // port just freed: refusal
        assert!(matches!(
            connect(addr, Duration::from_secs(5)).await,
            Conn::Refused
        ));
    }
}
