# Changelog

## 2.0.0 — 18 Nov 2026 — first public release
- Windows desktop app (Rust + Tauri 2) with network diagnostic tools: ping, traceroute, subnet
  scan, Wake-on-LAN, DNS, TCP ports, whois, blacklist, public IP, subnet calculator, HTTP headers,
  TLS certificates, email, NTP, SNMP v1/v2c/v3, SMTP server, Local network, Wi-Fi, password
  generator, number converter and UUID generator.
- Bilingual interface (Italian default, English selectable) and backend messages.
- **Licence files**: `LICENSE` (Apache 2.0), `NOTICE` and `THIRD-PARTY-LICENSES.md` (fonts, IEEE
  registry and the Rust crates with their licences).
- **Documentation**: `README.md` (and Italian `README.it.md`) with feature table, screenshots
  (`docs/screenshots/`), installation, notes on the unsigned binaries (SmartScreen/EDR) and
  responsible use; `SECURITY.md`, `CONTRIBUTING.md`.
- **CI**: `.github/workflows/ci.yml` (format, clippy, tests and UI smoke test on Windows).
