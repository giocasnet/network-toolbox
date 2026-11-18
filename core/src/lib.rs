//! NET::TOOLBOX — network logic shared by the desktop app.
//!
//! Every tool exposes a `run` function. Tools with text output (ping,
//! traceroute) emit events line by line through a closure, so the same code
//! serves both the live mode and the single-response mode.

pub mod blacklist;
pub mod clipboard;
pub mod dns;
pub mod email;
pub mod http;
pub mod i18n;
pub mod icmp;
pub mod lan;
pub mod myip;
pub mod neigh;
pub mod net;
pub mod netbios;
pub mod netpath;
pub mod ntp;
pub mod numconv;
pub mod online;
pub mod ping;
pub mod ports;
pub mod pwgen;
pub mod selftest;
pub mod smtp;
pub mod snmp;
pub mod subnet;
pub mod sweep;
pub mod tcp;
pub mod tls;
pub mod trace;
pub mod util;
pub mod uuid;
pub mod whois;
pub mod wifi;
pub mod wol;

use serde::Serialize;

/// Error shown directly to the user, already translated (see `i18n`).
pub type Result<T> = std::result::Result<T, String>;

/// Event of a streaming tool. Serialised as
/// `{"meta":{...}}`, `{"line":"..."}`, `{"done":true}`: the same NDJSON format
/// used by the server version, so the interface stays identical.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Event {
    Meta(net::HostMeta),
    Line(String),
    Done(bool),
}
