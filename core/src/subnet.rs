//! IPv4 subnet calculator.

use crate::{t, tf, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize)]
pub struct SubnetReq {
    pub cidr: String,
}

#[derive(Debug, Serialize)]
pub struct SubnetResult {
    pub network: String,
    pub broadcast: String,
    pub netmask: String,
    pub wildcard: String,
    pub prefix: u8,
    pub total_hosts: u64,
    pub usable_hosts: u64,
    pub first_host: String,
    pub last_host: String,
    pub host_ip: String,
    pub is_private: bool,
    pub version: u8,
    pub cidr: String,
    pub subnets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_prefix: Option<u8>,
}

fn private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || (o[0] == 100 && (64..128).contains(&o[1]))
}

pub fn run(req: SubnetReq) -> Result<SubnetResult> {
    let cidr = req.cidr.trim();
    let (addr, prefix) = cidr.split_once('/').ok_or(t!(
        "Formato non valido. Usa: IP/prefisso (es: 192.0.2.0/24)",
        "Invalid format. Use: IP/prefix (e.g. 192.0.2.0/24)"
    ))?;
    let host_ip: Ipv4Addr = addr
        .trim()
        .parse()
        .map_err(|_| tf!("Indirizzo non valido: {addr}", "Invalid address: {addr}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| tf!("Prefisso non valido: {prefix}", "Invalid prefix: {prefix}"))?;
    let net = Ipv4Net::new(host_ip, prefix)
        .map_err(|_| {
            t!(
                "Il prefisso deve essere tra 0 e 32",
                "The prefix must be between 0 and 32"
            )
            .to_string()
        })?
        .trunc();

    let total = 1u64 << (32 - prefix as u32);
    let (first, last, usable) = if prefix >= 31 {
        (net.network(), net.broadcast(), total)
    } else {
        (
            Ipv4Addr::from(u32::from(net.network()) + 1),
            Ipv4Addr::from(u32::from(net.broadcast()) - 1),
            total - 2,
        )
    };
    let (subnets, sub_prefix) = if prefix < 30 {
        let sp = (prefix + 2).min(30);
        (
            net.subnets(sp)
                .map(|s| s.take(8).map(|n| n.to_string()).collect())
                .unwrap_or_default(),
            Some(sp),
        )
    } else {
        (vec![], None)
    };

    Ok(SubnetResult {
        network: net.network().to_string(),
        broadcast: net.broadcast().to_string(),
        netmask: net.netmask().to_string(),
        wildcard: net.hostmask().to_string(),
        prefix,
        total_hosts: total,
        usable_hosts: usable,
        first_host: first.to_string(),
        last_host: last.to_string(),
        host_ip: host_ip.to_string(),
        is_private: private(net.network()),
        version: 4,
        cidr: net.to_string(),
        subnets,
        sub_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn c(s: &str) -> SubnetResult {
        run(SubnetReq { cidr: s.into() }).unwrap()
    }

    #[test]
    fn calcoli() {
        let r = c("172.16.24.0/21");
        assert_eq!(
            (r.network.as_str(), r.broadcast.as_str()),
            ("172.16.24.0", "172.16.31.255")
        );
        assert_eq!(r.usable_hosts, 2046);
        assert_eq!(r.wildcard, "0.0.7.255");
        assert_eq!(r.subnets.len(), 4);
        assert_eq!(r.sub_prefix, Some(23));
        assert!(r.is_private);
        let r = c("192.0.2.130/24");
        assert_eq!(r.cidr, "192.0.2.0/24");
        assert_eq!(r.host_ip, "192.0.2.130");
        assert_eq!(
            (r.first_host.as_str(), r.last_host.as_str()),
            ("192.0.2.1", "192.0.2.254")
        );
        let r = c("10.0.0.1/31");
        assert_eq!(r.usable_hosts, 2);
        let r = c("8.8.8.8/32");
        assert_eq!((r.usable_hosts, r.is_private), (1, false));
        assert_eq!(c("0.0.0.0/0").total_hosts, 1 << 32);
        assert!(run(SubnetReq {
            cidr: "172.16.24.0".into()
        })
        .is_err());
        assert!(run(SubnetReq {
            cidr: "172.16.24.0/33".into()
        })
        .is_err());
    }

    #[test]
    fn english_messages() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let e = |s: &str| run(SubnetReq { cidr: s.into() }).unwrap_err();
        assert!(e("172.16.24.0").starts_with("Invalid format"));
        assert_eq!(e("x/24"), "Invalid address: x");
        assert_eq!(e("10.0.0.0/x"), "Invalid prefix: x");
        assert_eq!(e("10.0.0.0/33"), "The prefix must be between 0 and 32");
    }
}
