# Changelog

## 2.1.0 — 18 Nov 2026 — portable version
- **Portable version**: `build.ps1` also produces `release\NetworkToolbox-portable\` and
  `NetworkToolbox-<version>-portable.zip` (exe, `oui.txt`, `portable.txt`, licence files), to run
  from a USB stick without installing. While `portable.txt` is next to the exe, the WebView2 data
  (language, theme, SNMP profiles) is kept in a `data` folder beside it instead of
  `%LOCALAPPDATA%`; without the file, or if the folder cannot be created, the app behaves as the
  installed one.
- The main window is now created in code (`"create": false` in `tauri.conf.json`) so that the data
  folder can be chosen at start-up; no change for the installed version.

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
