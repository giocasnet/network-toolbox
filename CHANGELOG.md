# Changelog

## 2.3.0 — 23 Nov 2026 — Bonjour and UPnP in Local network
- **Local network, Bonjour tab**: browser for the services announced with mDNS / DNS-SD
  (printers, AirPlay, SMB, SSH, web interfaces...). It enumerates every service type, then reads
  host, port, TXT records and addresses of each instance. Results are grouped by host, with search,
  CSV and shortcuts to Ping, Ports and SNMP. It flags Telnet and FTP announcements and, as
  information, remote access and file sharing.
- **Local network, UPnP tab**: SSDP search on every IPv4 adapter, then the device description
  (manufacturer, model, services). A router with UPnP IGD enabled is flagged. The description is
  downloaded only if its URL points to the address that replied; nothing is ever sent to the
  devices and the router's port mappings are not read.
- Both tabs only send multicast questions, have a selectable listening time and a **Stop** button
  that keeps what has been found so far.
- No new dependency beyond `socket2` (already used by `tokio`).

## 2.2.0 — 20 Nov 2026 — Ping size and MTU, Email tabs
- **Ping**: selectable data size (presets 32, 64, 512, 1024, 1472, 1500, or any value from 0 to
  65500 bytes) and a "Do not fragment" (DF) option. A packet that does not fit the path is shown as
  `Frag needed and DF set`.
- **Find MTU** button: sends echoes with DF and a growing size and finds the largest packet the
  path carries (binary search; the usual 1500 is confirmed in three packets). The result is the
  path MTU and the largest data size for an unfragmented ping.
- **Email**: the two forms (domain records, message headers) are now two tabs.

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
