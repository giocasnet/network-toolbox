//! Target validation, name resolution (system resolver, hence
//! with the domain's DNS suffixes: "srv01" works) and reverse DNS with timeout.

use crate::{t, tf, Result};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize)]
pub struct HostMeta {
    pub ip: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ptr: String,
}

/// Normalises and validates a host: strips spaces, scheme (http://) and path.
pub fn clean_host(raw: &str) -> Result<String> {
    let mut h = raw.trim();
    if let Some(i) = h.find("://") {
        h = &h[i + 3..];
    }
    let h = h.split('/').next().unwrap_or("").trim();
    if h.is_empty() {
        return Err(t!("Host richiesto", "Host required").into());
    }
    if h.parse::<IpAddr>().is_ok() {
        return Ok(h.to_string());
    }
    let ok = h.len() <= 253
        && !h.starts_with(['-', '.'])
        && !h.ends_with('-')
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if ok {
        Ok(h.to_string())
    } else {
        Err(tf!("Host non valido: {h}", "Invalid host: {h}"))
    }
}

/// Resolves a host to IPv4 with the system resolver.
pub async fn resolve_v4(host: &str) -> Result<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(t!(
            "Gli indirizzi IPv6 non sono ancora supportati: usa un indirizzo IPv4",
            "IPv6 addresses are not supported yet: use an IPv4 address"
        )
        .into());
    }
    let h = host.to_string();
    let job = tokio::task::spawn_blocking(move || {
        (h.as_str(), 0)
            .to_socket_addrs()
            .map(|a| a.collect::<Vec<_>>())
    });
    let addrs = match tokio::time::timeout(Duration::from_secs(6), job).await {
        Ok(Ok(Ok(a))) => a,
        Ok(_) => return Err(tf!("Impossibile risolvere {host}", "Cannot resolve {host}")),
        Err(_) => {
            return Err(tf!(
                "Timeout nella risoluzione di {host}",
                "Timeout resolving {host}"
            ))
        }
    };
    addrs
        .iter()
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| {
            tf!(
                "{host} ha solo indirizzi IPv6, non ancora supportati",
                "{host} has only IPv6 addresses, not supported yet"
            )
        })
}

/// Reverse DNS with timeout: direct PTR query to the PC's DNS servers (like `dig -x`).
/// Empty string if there is no PTR record or for IPv6 addresses.
pub async fn rdns(ip: IpAddr, timeout: Duration) -> String {
    match ip {
        IpAddr::V4(v4) => tokio::time::timeout(timeout, crate::dns::ptr(v4))
            .await
            .unwrap_or_default(),
        IpAddr::V6(_) => String::new(),
    }
}

/// Addresses worth asking for the NetBIOS name: private and link-local networks.
/// An Internet router does not answer on UDP 137, and waiting for it costs a second.
pub fn netbios_candidate(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

/// Name of an IPv4: PTR record, otherwise NetBIOS name (in upper case, as
/// Windows shows it). The two lookups start together: the PTR has precedence and,
/// if it arrives first, NetBIOS is not awaited. Empty string if neither
/// answers.
pub async fn name_of(ip: Ipv4Addr, timeout: Duration) -> String {
    let ptr = rdns(IpAddr::V4(ip), timeout);
    if !netbios_candidate(ip) {
        return ptr.await;
    }
    let nb = crate::netbios::name(ip, timeout.min(Duration::from_secs(1)));
    tokio::pin!(ptr, nb);
    tokio::select! {
        p = &mut ptr => {
            if p.is_empty() {
                nb.await.unwrap_or_default()
            } else {
                p
            }
        }
        n = &mut nb => {
            let p = ptr.await;
            if p.is_empty() {
                n.unwrap_or_default()
            } else {
                p
            }
        }
    }
}

/// Name and IP of a target, as shown in the results header.
pub async fn host_meta(host: &str, ip: Ipv4Addr) -> HostMeta {
    let ptr = name_of(ip, Duration::from_secs(2)).await;
    if host.parse::<IpAddr>().is_ok() {
        HostMeta {
            ip: ip.to_string(),
            name: ptr,
            ptr: String::new(),
        }
    } else {
        HostMeta {
            ip: ip.to_string(),
            name: host.to_string(),
            ptr,
        }
    }
}

/// Lookup of the name of the ping and traceroute target, started in parallel with the
/// first packet: the test does not wait for the name to start.
pub struct MetaLookup {
    host: String,
    ip: Ipv4Addr,
    /// The target was given as an IP: the name found is its only name.
    by_ip: bool,
    task: Option<tokio::task::JoinHandle<HostMeta>>,
    meta: Option<HostMeta>,
    emitted: bool,
}

impl MetaLookup {
    pub fn start(host: &str, ip: Ipv4Addr) -> Self {
        let h = host.to_string();
        MetaLookup {
            host: host.to_string(),
            ip,
            by_ip: host.parse::<IpAddr>().is_ok(),
            task: Some(tokio::spawn(async move { host_meta(&h, ip).await })),
            meta: None,
            emitted: false,
        }
    }

    /// Waits for the lookup to finish (at once, if it already has).
    pub async fn wait(&mut self) -> &HostMeta {
        if let Some(task) = self.task.as_mut() {
            // lookup did not complete: the IP and the given name remain
            let m = task.await.unwrap_or_else(|_| HostMeta {
                ip: self.ip.to_string(),
                name: if self.by_ip {
                    String::new()
                } else {
                    self.host.clone()
                },
                ptr: String::new(),
            });
            self.task = None;
            self.meta = Some(m);
        }
        self.meta.get_or_insert_with(HostMeta::default)
    }

    /// Name derived from the address (PTR or NetBIOS), empty if there is none.
    pub async fn reverse_name(&mut self) -> String {
        let by_ip = self.by_ip;
        let m = self.wait().await;
        if by_ip {
            m.name.clone()
        } else {
            m.ptr.clone()
        }
    }

    /// The data to send to the UI: once only, and only if the lookup has
    /// already finished (it does not wait for it).
    pub async fn ready(&mut self) -> Option<HostMeta> {
        let finished = self.meta.is_some() || self.task.as_ref().is_some_and(|t| t.is_finished());
        if self.emitted || !finished {
            return None;
        }
        self.emitted = true;
        Some(self.wait().await.clone())
    }

    /// Like `ready`, but waits for the lookup to finish. `None` if the data has already
    /// been sent.
    pub async fn finish(&mut self) -> Option<HostMeta> {
        if self.emitted {
            return None;
        }
        self.emitted = true;
        Some(self.wait().await.clone())
    }
}

impl Drop for MetaLookup {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulizia_host() {
        assert_eq!(clean_host(" srv01 ").unwrap(), "srv01");
        assert_eq!(
            clean_host("https://www.example.com/path").unwrap(),
            "www.example.com"
        );
        assert_eq!(clean_host("172.16.24.1").unwrap(), "172.16.24.1");
        assert!(clean_host("").is_err());
        assert!(clean_host("-f").is_err());
        assert!(clean_host("a b").is_err());
        assert!(clean_host("host;id").is_err());
    }

    #[test]
    fn netbios_solo_reti_private() {
        assert!(netbios_candidate(Ipv4Addr::new(10, 1, 24, 7)));
        assert!(netbios_candidate(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(netbios_candidate(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(netbios_candidate(Ipv4Addr::new(169, 254, 3, 4)));
        assert!(!netbios_candidate(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!netbios_candidate(Ipv4Addr::new(203, 0, 113, 9)));
    }

    /// A public address without PTR does not wait for the NetBIOS second.
    #[tokio::test]
    async fn nome_pubblico_senza_attesa_netbios() {
        let t0 = std::time::Instant::now();
        let _ = name_of(Ipv4Addr::new(203, 0, 113, 9), Duration::from_millis(600)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(900),
            "{:?}",
            t0.elapsed()
        );
    }

    /// The name lookup runs on its own: `ready` does not wait for it, `finish` does.
    #[tokio::test]
    async fn ricerca_del_nome_in_parallelo() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let mut m = MetaLookup::start("203.0.113.9", ip);
        let first = m.ready().await; // almost always not ready yet
        let last = m.finish().await;
        assert!(first.is_some() != last.is_some());
        assert_eq!(first.or(last).unwrap().ip, "203.0.113.9");
        assert!(m.ready().await.is_none() && m.finish().await.is_none());
        // target given by name: the name derived from the address is the PTR
        let mut m = MetaLookup::start("srv01", ip);
        assert_eq!(m.reverse_name().await, m.wait().await.ptr.clone());
        assert_eq!(m.wait().await.name, "srv01");
    }

    #[tokio::test]
    async fn risoluzione_ip_diretta() {
        assert_eq!(
            resolve_v4("192.0.2.31").await.unwrap(),
            Ipv4Addr::new(192, 0, 2, 31)
        );
        assert!(resolve_v4("::1").await.is_err());
    }

    #[tokio::test]
    async fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(clean_host("").unwrap_err(), "Host required");
        assert_eq!(clean_host("a b").unwrap_err(), "Invalid host: a b");
        let e = resolve_v4("::1").await.unwrap_err();
        assert!(
            e.contains("not supported yet") && !e.contains("supportati"),
            "{e}"
        );
    }
}
