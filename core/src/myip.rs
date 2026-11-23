//! Public IP this PC uses to reach the Internet, and information about an IP (ipinfo.io).

use crate::Result;
use std::time::Duration;

pub async fn run() -> Result<serde_json::Value> {
    get("https://ipinfo.io/json").await
}

/// Country, region, city and provider of a public IP.
pub async fn ip_info(ip: std::net::Ipv4Addr) -> Result<serde_json::Value> {
    get(&format!("https://ipinfo.io/{ip}/json")).await
}

async fn get(url: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(concat!("NetworkToolbox/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| {
        crate::tf!(
            "ipinfo.io non raggiungibile: {e}",
            "ipinfo.io unreachable: {e}"
        )
    })?;
    if !resp.status().is_success() {
        return Err(crate::tf!(
            "ipinfo.io ha risposto HTTP {}",
            "ipinfo.io replied with HTTP {}",
            resp.status().as_u16()
        ));
    }
    // a few hundred bytes are expected: 64 KiB is plenty
    let body = crate::http::read_body(resp, 64 * 1024)
        .await
        .map_err(|e| match e {
            crate::http::BodyError::TooLarge => crate::t!(
                "Risposta di ipinfo.io troppo grande",
                "Response from ipinfo.io too large"
            )
            .to_string(),
            crate::http::BodyError::Interrupted => crate::t!(
                "Risposta di ipinfo.io interrotta",
                "Response from ipinfo.io interrupted"
            )
            .to_string(),
        })?;
    serde_json::from_slice(&body).map_err(|e| {
        crate::tf!(
            "Risposta di ipinfo.io non valida: {e}",
            "Invalid response from ipinfo.io: {e}"
        )
    })
}
