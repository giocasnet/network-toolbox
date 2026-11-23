# Changelog

## 2.4.0 — 23 Nov 2026 — security fixes
- **HTTP headers**: the `http://` probe that checks the redirect to HTTPS now asks only for
  `http://host/`. Before, it repeated the whole typed address in clear text, path and query
  included (signed links, reset tokens).
- **HTTP headers**: a redirect is no longer followed from a response obtained with an invalid
  certificate, nor from a public site towards a local or private address. The result shows the
  redirect that was not followed; an internal address can still be checked by entering it.
- **DNS, Email, Bonjour**: `hickory-proto` and `hickory-resolver` updated to 0.26.3. The DNS
  message parser of 0.24 could reserve memory out of proportion to a small response
  (RUSTSEC-2026-0491); the app parses the replies of the queried DNS server and the Bonjour
  datagrams with it. `url` updated to 2.5.9 (RUSTSEC-2026-0592).
- **CSV**: every "Copy CSV" (Neighbours, Bonjour, UPnP, SNMP, Wi-Fi) now marks with a leading `'`
  the text that a spreadsheet would read as a formula (`=`, `+`, `-`, `@`...): SSIDs, device names
  and SNMP values come from the network. Numbers stay numbers.
- **Bonjour and UPnP**: limits on queued datagrams, services, hosts, addresses and records per
  device; beyond them the result says it is partial. The follow-up questions of a Bonjour round are
  bounded. In UPnP the Stop button also interrupts the download of the descriptions.
- **Email (MTA-STS)** and **public IP**: the response is read with its size limit checked while it
  arrives, not after the whole download.
- **Password generator**: the protected copy opens the clipboard with the app window as owner,
  refuses the copy if the formats that keep it out of the clipboard history cannot be set, and
  reads the clipboard sequence number before closing it. Only the timer of the last copy clears
  the clipboard.
- SNMP requests no longer show the community and passwords in their debug form.

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
