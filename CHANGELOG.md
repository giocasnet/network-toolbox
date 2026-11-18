# Changelog

## 2.0.0 — 18 Nov 2026 — first public release preparation
- No functional change from 1.24.0: the major version marks the bilingual app (1.24.0) plus the
  repository prepared for publication.
- **Licence files**: `Apache-License-2.0.txt` renamed to `LICENSE` (so GitHub recognises it), new
  `NOTICE` and `THIRD-PARTY-LICENSES.md` (fonts, IEEE registry and the 333 Rust crates with their
  licences). `license`, `repository`, `homepage` and descriptions in the `Cargo.toml` files;
  `publish = false`.
- **README**: new introduction with description, feature table, screenshots (`docs/screenshots/`),
  installation, notes on the unsigned binaries (SmartScreen/EDR) and responsible use.
- **New files**: `SECURITY.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml` (format, clippy,
  tests and UI smoke test on Windows), `.gitattributes` (LF line endings).
- **Example data**: the private example networks in the tests and the mock now use `172.16.x.x` only.

## 1.24.0 — 18 Nov 2026 — English version
- **Language selector**: flag button in the top bar, next to the theme button. The app is
  bilingual, Italian (default) and English; the choice is remembered in `localStorage`
  (`ntb-lang`).
- **English UI and backend messages**: UI texts go through `__()` with the dictionaries in
  `ui/i18n/en-*.js`; backend messages (errors, checks, notes, event lines) follow the language
  through the `set_lang` command (`core/src/i18n.rs`, macros `t!`/`tf!`). Italian output is
  unchanged.
- **English code comments and documents**: `README.md` and `CHANGELOG.md` are now in English;
  the Italian README is kept as `README.it.md`.
- **Dark theme is the default**: the system preference (`prefers-color-scheme`) is no longer
  used to choose the theme.

## 1.23.0 — 18 Nov 2026
- **Password generator: Diceware mode removed** (tab, `diceware` and `diceware_estimate`
  commands, `diceware_it.txt` list, dice styles). The generator now only produces passwords;
  the GPL list is no longer distributed with the app.

## 1.22.0 — 17 Nov 2026
- **Local network: "Neighbours" tab** (this PC's ARP and NDP). At the top of the view a
  **Network scan / Neighbours (ARP and NDP)** selector; the menu stays at 21 entries. The
  reading is **passive**: the Windows neighbour table, without sending anything.
- **Devices**: IPv4 and IPv6 merged by MAC, one row per device with vendor (from
  `oui.txt`), adapter, addresses as labels, state (reachable, cached, static, unresolved) and
  the Gateway, IPv6 router and VM labels; the detail opens on click, with Ping, Ports, SNMP and
  Wake-on-LAN. Addresses without an answer are all grouped in a separate row. Search by MAC
  (also without separators), IP, vendor or adapter; **Copy CSV**.
- **Routers and prefixes**: the IPv6 routers advertising the network (MAC, vendor, lifetime,
  whether they match the IPv4 gateway) and the advertised prefixes.
- **Checks**, in order of severity: gateway in the table, MAC with many IPv4 addresses,
  unresolved addresses, no IPv6 router, several IPv6 routers with different MACs, multiple
  prefixes. From the second refresh, the **comparison with the previous reading** (kept in
  memory while the app stays open): same IP with a different MAC (error if it is the gateway),
  gateway changed, IPv6 router new or gone, new devices or devices no longer in the table.
- **Echo to ff02::1** on request (checkbox off): a single ICMPv6 packet for each active adapter
  with IPv6, then the table is read again; the result says how many entries are new. No IPv6
  ping, traceroute or scan.
- Windows code: `GetIpNetTable2(AF_UNSPEC)`, `GetIpForwardTable2` (routers and prefixes from
  the advertised routes), `GetIfEntry2` (adapter names), `Icmp6SendEcho2`. If the unified table
  cannot be read, it falls back to the already tested IPv4-only table and the result says so.
  The `collaudo_vicini` self-test prints the path used.
- Verified on the PC by Claude: fmt, clippy, 262 tests run (5 ignored), `cargo check`,
  smoke test with 134 screenshots, `collaudo_vicini` (unified table) and `collaudo_motore`.
  With the echo to ff02::1 `Icmp6SendEcho2` returns no direct replies, but the NDP table
  fills up (about a hundred extra entries on a network with many IPv6 nodes): it is the table,
  not the API response, that provides the neighbours. **Not tried by the user.**

## 1.21.0 — 17 Nov 2026
- **SNMP: Resources and Printer views** in the "Device" reading, second part of the module
  (the first is 1.20.0). Two new checkboxes in the form; the tabs appear only if the device
  has the data (HOST-RESOURCES-MIB, Printer-MIB), other devices do not change. Read-only, no
  SET.
- **Resources** (servers and devices with HOST-RESOURCES-MIB): processor load (per core and
  average), physical and virtual memory, disks and volumes with the percentage used and free
  space (allocation units × blocks; the serial number Windows writes in the volume name is
  removed), the ten processes using the most memory, processes and users, system boot. Checks:
  processor above 90%, physical memory above 95% (with the warning that some agents count the
  cache), disk to watch from 85% and almost full from 95%. CSV.
- **Printer** (Printer-MIB and hrPrinterTable): status, detected errors (paper, toner, door,
  jam), supplies with the bar and the colour taken from the colorant (or from the name),
  containers that fill up (waste toner), "unknown" and "at least one left" levels handled, paper
  trays with the level, active alerts with severity, page counter. Checks: supply below 15%
  (error below 5%), container full above 85%, empty tray, every alert and every error reported
  by the printer. Supplies CSV.
- The two boxes to the right of the summary change with the device: printer (status,
  supplies), server (CPU, memory), otherwise interfaces and boot.
- **Built-in names**: 178 objects (were 141). All the columns of `prtMarkerSuppliesTable`,
  `prtInputTable`, `prtMarkerTable`, `prtMarkerColorantTable` and `prtAlertTable`,
  `hrPrinterTable`, `hrSWRunTable`, `hrSWRunPerfTable`. Standard MIBs only.
- **Enumerated values with their name** also in the "Table" reading and in the WALK: supply
  type and class, units, colorant role, alert severity and code, print technology, tray type,
  printer status, process type and status; the −1, −2 and −3 supply levels.
- The number of reading steps shown during the analysis is now 6.
- `snmp_device` command: the request accepts `resources` and `printer`, the response has
  `resources` and `printer` (`null` if the device has no data).

## 1.20.0 — 16 Nov 2026
- **SNMP: table views instead of text only.** In the form a switch chooses between
  **Device** and **OIDs and tables**. Everything stays read-only (no SET).
- **Device**: a single reading of the device, with the result in tabs. Sections are chosen with
  four checkboxes; during the reading the button becomes "Stop".
  - **Checks**, in order of severity: default or short community, cleartext v1 and v2c,
    v3 without authentication or without encryption, MD5 and DES; ports with errors, active
    ports without a link, 64-bit counters; LLDP absent, neighbours without a management
    address; sections read only in part.
  - **System**: name, description, model, serial number and firmware (ENTITY-MIB, one row per
    unit of a stack), agent uptime, contact, location, services served, IP addresses with mask
    and interface.
  - **Interfaces**: one row per port with name, description, status, speed, errors and
    discards. **Live counters**: one reading every 5 seconds, inbound and outbound speed with
    the utilisation bar, new errors and discards next to the total. "Active" and "With errors"
    filters.
  - **Neighbours** (LLDP): local port, neighbour name and port, capabilities, management
    address, with the SNMP and Ping buttons.
  - **MAC and ARP**: MAC address, vendor, IP address (from the device's ARP table), port, VLAN
    and type; search and "No IP" and "Ports with several MACs" filters. On a device that is not
    a switch only the ARP table is shown.
- **OIDs and tables**: besides GET and WALK, the **Table** reading shows any SNMP table of
  rows and columns, with a filter. Every table view has **Copy CSV**.
- **Built-in names**: 141 objects from 10 standard MIBs (system, interfaces, IP, bridge, VLAN,
  host resources, printers, ENTITY, LLDP), with no MIB files to load. The OID field suggests
  names as you type; "Browse names" opens the full tree with the filter.
- **Profiles**: host, port, version, user and protocols are saved with one click. Community
  and passwords are never saved.
- Agent **port** in the form (default 161).
- Removed from the built-in names the five objects of a vendor's private MIB: only standard
  MIBs remain.
- Fixed: with SNMP v1 the walk of an empty branch returned a row with a NULL value.
- New commands: `snmp_device`, `snmp_monitor`, `snmp_monitor_stop`, `snmp_stop`,
  `snmp_names`. `snmp` accepts `mode: "table"` and also responds with `table`, `csv`,
  `checks` and `stopped`.

## 1.19.0 — 16 Nov 2026
- **Email: records are evaluated, not just shown.** The result of a domain check is in tabs:
  **Checks** (in order of severity), **SPF**, **DMARC and DKIM**, **MX and transport**. "Copy"
  takes all the tabs.
  - **SPF as a tree**: each `include` shows what it contains below it, with the addresses of
    `a` and `mx` resolved and the DNS lookups it costs. You can see where the **limit of 10**
    is exceeded (from there on the record is no longer valid), multiple `v=spf1` records,
    includes without a record or in a loop, `ptr`, unknown mechanisms, too many empty lookups,
    and how the record ends (`-all`, `~all`, `?all`, `+all`, nothing).
  - **IP to check** (new optional field): the SPF result for that address and the mechanism
    that decides, marked in the tree. Also valid for IPv6.
  - **DMARC** explained tag by tag: policy, subdomains, percentage, reports, alignment.
    Flagged: `p=none`, `sp=none`, `pct` below 100, missing `rua`, multiple records, reports
    to an external domain that has not authorised them. A subdomain without a record inherits
    the one of the parent domain.
  - **DKIM**: key type and length of every selector found (RSA below 2048 bits, revoked key,
    selector in test mode). New **DKIM selector** field: without it, the most common names are
    tried.
  - **MX**: priority, IPv4 and IPv6 addresses, reverse name; null MX, MX without addresses.
    Three row buttons open the server in **SMTP server**, **TLS certificates** (port 25 with
    STARTTLS) or **Blacklist**: they fill in the form, the user launches the test.
  - **MTA-STS**: if the record exists the policy is downloaded via HTTPS and read (mode,
    servers covered, lifetime); flagged: policy not downloadable, `testing`, MX not covered.
    **TLS-RPT** and BIMI read-only.
- **Headers of a message**, in tabs: **Checks**, **Path**, **Anti-spam**, **Headers**.
  - Path in time order, with protocol, TLS and **delay** of each step (flagged from 30 seconds
    up) and total time.
  - SPF, DKIM and DMARC with the domain they refer to and the **alignment** with the sender;
    they are still taken only from the first `Authentication-Results`.
  - Sender: From and Return-Path, Reply-To to another domain, display name showing an address
    different from the real one.
  - Anti-spam scores gathered in a tab; from the message's DKIM signature a button takes the
    domain and selector to the domain form.
- `emailheader` command: request with `selector` and `ip`; response `{domain_report}` or
  `{message}` instead of the previous fields.

## 1.18.0 — 16 Nov 2026
- **DNS: domain analysis**. In the form a switch chooses between "Server comparison"
  (the usual one) and "Domain analysis": you type the domain and the result comes in tabs,
  **Checks** (in order of severity), **Records**, **Delegation**, **DNSSEC**. "Copy" takes all
  the tabs.
  - **Records**: A, AAAA, NS, SOA, MX, TXT, CAA, HTTPS, DNSKEY, DS and TLSA of `_443._tcp`,
    with the TTL; at the bottom the types with no answer. Flagged: TTL below one minute,
    wildcards (`*.domain` that answers), CAA and AAAA missing.
  - **Delegation**: the name servers delegated by the parent zone (asked directly to its
    servers) compared with those the zone declares; each name server queried directly:
    answers or not (UDP, then TCP), is authoritative, SOA serial, time. Flagged: dead name
    servers, lame delegations, different serials, registry and zone differing, a single name
    server, all on the same network, recursion offered, SOA values.
  - **DNSSEC**: registry DS and zone keys (the DS digest is recomputed), deprecated
    algorithms, SHA-1-only DS, signature expiry, NSEC3. In addition, the same query to a public
    validating resolver (1.1.1.1, then 9.9.9.9), normal and with the CD bit: if the first fails
    and the second does not, validation is broken. The app does not verify the signatures
    itself.
  - **Zone transfer (AXFR)** only with the checkbox on: the first message is read to know
    whether it is allowed, the zone is not downloaded.
  - If outbound DNS is closed from the PC's network, direct queries do not arrive: the
    analysis says so ("not reachable from this PC") and continues with the PC's DNS, without
    flagging errors that are not the domain's.
  - A name that is not a zone (`www.example.com`) is brought back to the zone that contains it.
- **Server comparison**: new types HTTPS, SVCB, TLSA, DNSKEY, DS, NAPTR, SSHFP; below the
  outcome the response **flags** (AA authoritative, RA recursion available, AD validated with
  DNSSEC). The comparison queries start with the AD bit.
- New `dns_domain` command; the `dns` response also has `flags`. No new dependencies: DNSSEC
  records are read from the bytes (`core/src/dns/rdata.rs`).
- `collaudo_dns` (`NTB_DNS_TEST=domain`): says which sources answered and prints the checks.

## 1.17.0 — 16 Nov 2026
- **TLS certificates, enhanced**. The result is in tabs like HTTP headers: **Checks** (in
  order of severity), **Certificate**, **Chain** and, with the scan, **Protocols and ciphers**.
  "Copy" takes all the tabs.
  - **Full certificate**: subject and issuer in full, key (RSA with bits, ECDSA curve,
    Ed25519), signature algorithm, extended usages, validity, serial, SHA-256 and SHA-1
    fingerprints, OCSP, CRL and issuer (AIA) addresses, embedded SCTs, names covered also IPv6.
    Checks: trust, expiry, name covered by the alternative names, RSA key below 2048 bits,
    SHA-1/MD5 signature, validity over 398 days (information), usage without server
    authentication.
  - **Real chain**: from the server to the root as Windows builds it. You can see what the
    server sent, the **intermediate CA not sent** (which Windows fetches by itself and other
    clients do not), the root taken from the PC's store, the root sent needlessly, wrong order,
    unrelated certificates, expired or SHA-1-signed intermediates.
  - **Revocation and transparency read-only**: OCSP stapling present or not, OCSP and CRL
    addresses, number of SCTs. No requests to OCSP or CRL.
  - **SNI name separate** from the host: you connect to one address and ask for (and verify)
    another name. One extra connection, without SNI, says whether the server presents a
    different certificate to those who do not send the name.
  - **STARTTLS**: SMTP, IMAP, POP3 (STLS) and **RDP** (X.224 negotiation, also with NLA). The
    "Protocol" menu starts on "Automatic": 25 and 587 SMTP, 143 IMAP, 110 POP3, 3389 RDP, the
    rest direct TLS. No authentication: it only asks to switch to TLS.
  - **Accepted versions and ciphers** (checkbox off by default): TLS 1.3 with one handshake per
    suite, TLS 1.2, 1.1 and 1.0 with the compatibility probe, each time removing the ciphers
    already chosen by the server. Suites appear as they come, the button becomes "Stop".
    Flagged: TLS 1.0 and 1.1, 3DES and RC4, suites without forward secrecy, CBC. It is dozens
    of connections one after another, and no vulnerability testing.
- `ssl` command: request with `protocol`, `sni`, `scan`; events on Channel (`result`, then
  `scan`); response with `cert`, `chain_info`, `checks`, `ocsp_stapled`, `protocol`, `sni`,
  `scan`. New `ssl_stop` command. The previous fields remain (the SMTP test uses them).
- `collaudo_tls` also reports the chain and whether it was built by the system.

## 1.16.0 — 16 Nov 2026
- **HTTP headers becomes a security analysis**. The result is in tabs: **Checks**
  (all checks in order of severity: errors, warnings, information, passed), **Path**,
  **Cookies**, **CSP**, **Headers**. "Copy" takes all the tabs.
  - **Cookies**: for every `Set-Cookie` of all steps (also of redirects, previously lost) name,
    `Secure`, `HttpOnly`, `SameSite`, domain, lifetime and the step that sets it. Flagged:
    without `Secure` on HTTPS, `SameSite=None` without `Secure`, `__Host-`/`__Secure-` prefixes
    not respected, session readable by scripts, cookies over cleartext HTTP. **The cookie value
    is no longer shown**, not even in the headers table (`name=(hidden)`).
  - **Content-Security-Policy** broken down by directive: `'unsafe-inline'` and `'unsafe-eval'`
    in scripts (not with nonce, hash or `'strict-dynamic'`), `*`, `http:`, `https:`, `data:`
    sources, missing `object-src` and `base-uri`, Report-Only-only policy, multiple policies.
  - **HSTS**: duration (warning below 6 months), `includeSubDomains`, `preload` requirements,
    and HSTS missing on intermediate hosts of a redirect.
  - **Path**: time of each step, HSTS and cookies per step, redirects from HTTPS to HTTP.
    With an `https://` address on the standard port `http://` is also tried on the same host
    (one request, together with the others) to see whether it leads to HTTPS.
  - **Headers**: if the CSP has `frame-ancestors`, `X-Frame-Options` is no longer required;
    COOP/COEP/CORP; `X-XSS-Protection`, `Expect-CT` and `Public-Key-Pins` flagged as obsolete;
    missing `Referrer-Policy` is a warning, not an error.
  - **Server and CDN**: `Server` with the version, `X-Powered-By` and similar; recognition of
    Cloudflare (with datacentre and cache status), CloudFront, Akamai, Fastly, Azure Front Door.
- **GET is used instead of HEAD** (some servers answer HEAD without cookies or without CSP):
  only the headers are read, the body is not downloaded.
- `headers` command response: removed `security` and `security_notes`; added `checks`,
  `cookies`, `csp`, `cdn` and, in each step, `time_ms`, `hsts`, `cookies`.
- UI: tabs inside a result (`rtabs`/`rpane`), reusable by the other tools.

## 1.15.2 — 16 Nov 2026
- **Clean-up of references** (the author's private project): UI, documents and comments no
  longer name specific products or infrastructure; generic terms instead.
- **TCP ports**: the VoIP preset contains only the SIP ports (5060, 5061).
- **SNMP**: removed the two vendor-specific OID presets; the standard ones remain
  (description, uptime, name, location, interfaces, CPU load).
- **Wake-on-LAN**: the note on directed broadcast speaks of "router or firewall".
- `backup.ps1` (new): at every version it creates `..\nettoolbox-desktop-backup-<version>.zip`
  with working tree, `.git` and the version's `release\`, without `target\`.
- No changes in the backend.

## 1.15.1 — 12 Nov 2026
- First version developed with Claude Code directly on the PC: git repository (one commit per
  version with tag `vX.Y.Z`) instead of delta and full zips.
- **Self-test of the asynchronous ICMP engine's timeout**: with `$env:NTB_ICMP_SILENT = "<ip>"`
  (free address on the PC's network) `collaudo_motore` sends an echo that stays unanswered,
  with the scan echo and with the ping and traceroute one, and says whether the engine is still
  asynchronous right afterwards. Without the variable it reports it as not tried. Tried on the
  PC: no answer after ~500 ms (Windows closes the request by itself, like `ping -w 800`), engine
  still asynchronous.
- No change in how the app works.

## 1.15.0 — 12 Nov 2026
- **TLS certificates with legacy servers**: a server that closed the connection upon the
  ClientHello (error 10054 "An existing connection was forcibly closed") gave only "TLS
  handshake failed". Now, if the server **rejects** the handshake (reset, close, alert
  handshake_failure/protocol_version/insufficient_security, incompatible peer):
  1. second attempt on a new connection offering **TLS 1.2 only** (full handshake,
     full verification);
  2. if that is not enough, **compatibility probe**: ClientHello with TLS 1.0–1.2 and obsolete
     ciphers (CBC, RSA exchange, DHE, 3DES, RC4); ServerHello and certificate are read in
     cleartext, then the connection is closed without completing the handshake. Chain and name
     verified as usual; the result shows "Chain verified (handshake not completed)", "Cipher
     chosen by the server" and the "Compatibility" row with the reason.
  With modern servers the first attempt succeeds as before (no extra connection);
  timeouts, closed ports and non-TLS services do not trigger the fallbacks.
- TLS 1.0/1.1/SSLv3 protocol highlighted and "To check" strip when a fallback is needed.
- Verification messages: "The certificate does not cover the name", "Certificate expired" and
  "not yet valid" also with the detailed variants of rustls 0.23 (previously they appeared as
  `NotValidForNameContext { … }`).
- Self-test on the PC: `$env:NTB_TLS_TEST = "host:port"` +
  `cargo test -p ntb-core collaudo_tls -- --ignored --nocapture` tries the three attempts one
  by one.

## 1.14.0 — 11 Nov 2026
- New **Wi-Fi** tool ("Diagnostics" group, after Local network), with the Windows Native Wi-Fi
  API (`wlanapi.dll` loaded at runtime, no drivers or privileges):
  - **Current connection**: signal in dBm with indicator, network, BSSID and vendor of the AP,
    channel, band and width, standard (Wi-Fi 4–7), RX/TX speed, security and encryption, IP
    address, 802.11k/v/r and MLO announced by the AP.
  - **Nearby networks**: one row per access point with signal, SSID, BSSID, vendor (oui.txt;
    for locally administered BSSIDs that of the twin), channel, band, width (20–320 MHz),
    standard, security (Open, WEP, WPA, WPA2/WPA3 Personal and Enterprise, OWE), 802.11k/v/r,
    clients and channel load (BSS Load), MLO. Filters by band and for hidden networks, grouping
    by network, "Copy CSV", "Repeat every 10 s".
  - **Hidden networks**: name from the profile saved on the PC, name length if the AP
    transmits it, "same AP as …" from the BSSID.
  - **Channels**: chart for 2.4, 5 and 6 GHz (6 GHz limited to 5945–6425 MHz, as in Europe),
    DFS bands highlighted, least busy channel among 1, 6 and 11 and least busy 80 MHz group.
  - **Signal monitor**: sample every 0.5–5 s in streaming with "Start"/"Stop", chart of the
    last 3 minutes with the −67/−75 dBm thresholds, minimum, maximum and average, roaming (with
    the interruption reported by Windows), disconnections and threshold events, "Copy CSV".
  - States handled: no adapter, WlanSvc service stopped, Windows Server without the Wi-Fi
    feature, Wi-Fi off, location denied (Windows 11 24H2), scan not completed.
- Menu: entries slightly narrower to make room for the new one; below 787 px of height they
  narrow further, so the menu stays complete down to about 722 px (1366×768 laptop with a
  maximised window). Credits visible from 848 px.
- Backend: `wifi` module (parser of the HT/VHT/HE/EHT/RSN/BSS Load/Multi-Link Information
  Elements, portable and tested with hand-built beacons), commands `wifi_scan`, `wifi_monitor`,
  `wifi_monitor_stop`; self-test on the PC with `collaudo_wifi`.

## 1.13.0 — 11 Nov 2026
- Optimisation: ping without waiting for the name, names (PTR and NetBIOS) in parallel,
  traceroute in blocks of 8 hops, two-phase scans with the asynchronous ICMP engine
  (`IcmpSendEcho2Ex`) and ARP table (`GetIpNetTable2`), TCP ports in streaming with "Stop" and
  immediate refusals. (Entry reconstructed: the full 1.13.0 zip was not in Downloads.)

## 1.12.0 — 10 Nov 2026
- Subnet scan with real-time results (arrival order) and "Stop"; Local network with a single
  "Scan"/"Stop" button and immediate stop. (Entry reconstructed.)

## 1.11.0 — 10 Nov 2026
- **Stop** for ping and traceroute: while the test runs, the "Run ping" / "Run traceroute"
  button becomes "Stop", in the same place and with the same width; when the test ends it goes
  back as it was. The stop is immediate: it does not wait for the current packet's timeout or
  for the interval. A stopped ping shows the statistics of the packets that had an outcome
  ("Stopped after 3 packets out of 100."), traceroute the hops that arrived ("stopped before
  the end"); the result strip has the new "■ Stopped" state. Also valid without "Show lines as
  they arrive". Enter in a field during the test is equivalent to the button (stops).
- A test of the same tool started while another is running (for example "Ping" from a row of
  the scan, or a click on the gateway in the Home) stops the one in progress: one at a time.
- Ping: up to **100 packets** (previously 50). Unchanged: default 4, interval 100–2000 ms
  (1000), timeout 100–5000 ms (2000). Traceroute unchanged: max hops 1–64 (30).
- Backend: `ping::Stop` (switch on `tokio::sync::watch`), `ping::run` and `trace::run`
  return `true` if stopped; new commands `ping_stop` and `traceroute_stop`.
- `dev/`: `setup.sh` also installs `iputils-ping` (without it the new ping and traceroute tests
  do not exercise real ICMP); smoke test with simulated hosts "lento" and "muto" to try "Stop".

## 1.10.1 — 09 Nov 2026
- Home: removed the "Time and date" heading from the clock box; the time remains and the date
  below it (inner margins adjusted).

## 1.10.0 — 09 Nov 2026
- **Home screen redesigned**: world map in the background, network path PC → gateway
  → Internet at the top across the whole width (shorter box, latencies in "pills"), compact
  "Time and date" box at the bottom centre, resting on the luminous horizon and the grid.
  Semi-transparent boxes with an aqua-green border and glow. The map fills the free space
  between the two boxes and is never covered, whatever the window size.
- Light theme: same images, inverted via CSS (`--home-filter`), with the map blended into the
  background (`--home-blend`).
- Logo and credits removed from the Home: version, copyright and licence are three small lines
  at the bottom of the side menu, hidden when the window is lower than the full menu (less than
  857 px) or narrow (≤ 900 px).
- Images: `ui/home-map.webp` (72 KB) and `ui/home-ground.webp` (22 KB) derived from
  "Mappa mondiale.png" (1.6 MB), with the fake texts and the interface arc removed.
- `dev/`: smoke test at 1.10.0 with neutral examples (RFC 2606/5737), checks of the new Home at
  four window sizes; `snmpd.conf` with `sysLocation Sala server`.

## 1.9.0 — 09 Nov 2026
- Clean-up of internal references in the sources, tests and README (RFC 2606/5737 examples).
- Identifier `it.giocas.nettoolbox`; MSI upgrade code fixed in `tauri.conf.json`.
- Web mode and PWA removed from `ui/app.js`: the UI works only inside Tauri.

## 1.8.0 — 04 Nov 2026
- New **SMTP server** tool ("Protocols" group), modelled on MXToolbox: connection,
  banner, reverse DNS (PTR and forward A), valid hostname or generic provider name, matching
  banner and PTR, EHLO extensions, STARTTLS or implicit TLS (465) with version, cipher and
  certificate verified by the Windows store, AUTH mechanisms (warning if PLAIN/LOGIN are
  offered before TLS), maximum size, transaction time. Real-time session transcript with the
  time of each response.
- Options (all off by default): **open relay** (MAIL FROM and RCPT TO to the reserved domains
  example.com/example.net, then RSET: never DATA), **authentication** (PLAIN or LOGIN, password
  sent only over TLS with a verified certificate and masked in the transcript), **sending a
  test message** (sender, up to 10 recipients, subject, body; Date, Message-ID,
  X-Mailer, UTF-8 body in base64). Automatic encryption, mandatory STARTTLS, implicit TLS or
  none; customisable EHLO name (empty = PC name).
- Security: after STARTTLS, data received in cleartext aborts the session (CVE-2011-0411);
  line breaks and control characters rejected in addresses, subject, EHLO and credentials; the
  password does not go into `localStorage`.
- `tls.rs`: the TLS handshake is a reusable function on an already open connection.

## 1.7.0 — 04 Nov 2026
Security fixes after an external review of the 1.6.0 code.
- **Active Directory tool removed** (LDAP: access check, search, browsing, Kerberos) together
  with the `ldap3` dependency: no more password binds over cleartext LDAP or over LDAPS without
  certificate verification. The UUID generator still shows the LDAP filter on `objectGUID`
  (text to use with `Get-ADObject -LDAPFilter`).
- **SNMPv3**: with authentication required the response must have the auth flag, a valid HMAC
  (verified in constant time, before using any field), the same engine ID, user,
  msgID and request-id and be within the time window; with authPriv also the priv flag and the
  encrypted data. Previously a response without the auth flag was enough to skip verification.
  The agent's clock is updated only from authenticated messages. Unprotected Reports become
  just an error. Packets that fail verification are discarded and the wait for the real one
  continues; if it does not arrive, the error gives the reason.
- **SNMP (all versions)**: socket connected to the agent (only responses from the agent's IP
  **and port**); closed UDP port = immediate, clear error instead of waiting.
- **DNS**: random query ID (previously derived from the clock); socket connected to the
  server; a response is valid only with the same ID, QR=1, opcode QUERY and the same question,
  also via TCP after a truncated response (new query with a new ID). Valid for DNS, blacklist,
  email and PTR.
- **NTP**: socket connected to the server and check of the originate timestamp (it must be the
  request's transmit, with random low bits); server mode mandatory.
- **HTTP headers**: certificate verified with the Windows store. If it is not valid the request
  is repeated without verification and the result is marked "Invalid certificate:
  unauthenticated response", with the reason. Each step of the chain shows HTTPS/HTTP. Security
  headers count only with an effective value (HSTS max-age > 0 and only over HTTPS, `nosniff`,
  DENY/SAMEORIGIN, Referrer-Policy other than `unsafe-url`); those present but ineffective are
  in yellow with the reason.
- **Email headers**: SPF, DKIM and DMARC only from the first `Authentication-Results` (at the
  top, written by the last server that received the message); the lower ones may come from the
  sender and are not considered.
- **Blacklist**: "listed" only with 127.x.x.x codes; other addresses (a DNS that resolves any
  name) are reported as an unexpected response.

## 1.6.0 — 04 Nov 2026
- New **Number converter** tool ("Utilities" group): decimal, hexadecimal, binary and IPv4
  updated as you type in any of the fields. Width 8/16/32/64 bits with or without sign (two's
  complement, with a warning if the value is truncated) or free up to 1024 bits. Accepts `0x`,
  `0b`, trailing `h`, MAC and dump separators (`:` `-` `.` spaces `_`) and the thousands
  separator. Clickable bit grid, big and little endian bytes, byte-swapped value, ASCII,
  "Copy" without spaces.
- New **UUID generator** tool ("Utilities" group): random v4, time-ordered v7 (increasing even
  within the same millisecond), v5 from a name with DNS/URL/OID/X.500 or custom namespace (one
  UUID per line of names). 1–100 at a time; upper/lower case format, with or without hyphens,
  in braces or `urn:uuid:`, also applied to UUIDs already generated; "Copy" and "Copy all".
  Analysis of a UUID/GUID: version, variant, date and time (v1, v6, v7), node, bytes in
  Windows order and LDAP filter on `objectGUID`.

## 1.5.3 — 03 Nov 2026
- Home screen redesigned in three boxes: at the top the network path (smaller, closer icons,
  full names without "…"), in the middle a **24 h clock with seconds** and below the long date
  ("Tuesday 3 November 2026"), at the bottom the logo (smaller), version and credits.

## 1.5.2 — 02 Nov 2026
- App author (publisher): "GioCas" instead of the IT department's name (Programs and Features,
  installer, package metadata).

## 1.5.1 — 02 Nov 2026
- Home screen: above the logo (smaller) the network path **PC → gateway → Internet**
  with name and IP of this PC (icon for cable, Wi-Fi or VPN), DNS name and IP of the gateway,
  provider and public IP, and the latencies on the lines. Click: PC → Local network, gateway →
  Ping, Internet → Whois and location of the public IP.

## 1.5.0 — 02 Nov 2026
- New **Local network** tool ("Diagnostics" group): inventory of a network up to /21, by
  default that of this PC, with results arriving as they come and the "Stop" button.
  For each host: name (PTR, NetBIOS or sysName), adapter MAC and vendor (IEEE registry),
  model and description via SNMP v2c `public`, device type with icon (PC, server,
  printer, network device, phone, camera), virtual adapters (VM) and random MACs.
  "Services" option: 21 TCP ports with banners and TCP lookup of hosts that do not answer
  ping. Filter, sorting, host detail with the Ping, Ports, SNMP, Wake-on-LAN buttons;
  "Copy" exports the list in tabular format.
- Vendor list in the separate `oui.txt` file next to the exe (also copied by `build.ps1`).

## 1.4.0 — 02 Nov 2026
- New **Password generator** tool ("Utilities" group of the menu), entirely local:
  - Password: lowercase, uppercase, digits and symbols with a minimum per type (0–10),
    editable symbol set, length 4–64, quantity 1–10, exclusion of ambiguous characters,
    pronounceable mode. Uniform draw with the Windows cryptographic generator; exact entropy
    in the preview and strength (weak, medium, strong, extreme); "Regenerate" per single
    password.
  - Diceware: 3–10 words from Tarin Gamberini's Italian list (7776 words), dice and codes
    visible, separator of choice, initial capital, trailing digit.
  - "Copy" outside the Windows clipboard history (Win+V) and the cloud, with the clipboard
    cleared after 30 s and when the app closes.
  - Session history (last 20) in memory only.
- The diceware list is a separate file, `diceware_it.txt`, installed next to the exe (and
  copied by `build.ps1` to `release\`).

## 1.3.1 — 02 Nov 2026
- Top bar 40 px high (like the window buttons): icon and name on the left, without IP;
  on the right Theme, Home and the connection dot in a button with the same look.

## 1.3.0 — 02 Nov 2026
- Ping: interval (100–2000 ms) and timeout (100–5000 ms) configurable.
- Traceroute: max hops (1–64) and per-hop timeout (100–5000 ms) configurable.

## 1.2.2 — 02 Nov 2026
- "Route" icon also inside the app (bar and home screen).

## 1.2.1 — 02 Nov 2026
- Logo, name and IP moved to the top bar.

## 1.2.0 — 02 Nov 2026
- Frameless window: single bar with minimise/maximise/close.
- PC IP instead of the name; Windows icons back to "Route".

## 1.1.0 — 02 Nov 2026
- Home screen with version, copyright and Apache 2.0 licence.
- Top bar with theme, Home and Internet connection status (ping to 1.1.1.1 / 8.8.8.8).
- Ping and Traceroute as separate entries; ping up to 50 packets.
- No example text in the fields; AD search with empty filter = users only.
- More compact menu; scroll bars consistent with the theme.

## 1.0.0 — 30 Oct 2026
- LDAP / Active Directory: access check with server information, search, OU browsing;
  anonymous bind, with user and password, or with the current Windows account (Kerberos/SSPI);
  readable AD errors; decoded objectSid and objectGUID; base DN filled in from the domain.
- SNMP v1/v2c/v3 (own implementation): GET and WALK (GETBULK), MD5/SHA-1/SHA-2, DES/AES-128,
  symbolic names for the most common OIDs.
- Bundled fonts (works offline), CSP without external origins, version in the side bar.
- `build.ps1`: tests, MSI/NSIS installer, optional signing, SHA-256 hashes.

## 0.3.1
- Ports: "closed" (refused) and "filtered" (no answer) distinguished, with the reason (e.g. 10013).
- Connection timeout at 3 s (on Windows the refusal arrives after about 1 s).
- Subnet scan: TCP check of the 6 ports in parallel with 1.5 s.

## 0.3.0
- HTTP headers, TLS certificates, email (MX/SPF/DMARC/DKIM/MTA-STS/BIMI and header analysis), NTP.

## 0.2.1
- System DNS: fec0::/link-local excluded, IPv4 first, fallback between servers; PTR via DNS.
- Whois on the registrable domain; location and provider of public IPs.
- Blacklist: removed NiX Spam and WPBL.

## 0.2.0
- DNS with server comparison, blacklist, TCP ports with banners, whois, subnet, public IP.

## 0.1.1
- NetBIOS names when the PTR record is missing.

## 0.1.0
- Ping and traceroute line by line, subnet scan (ICMP, ARP, TCP), Wake-on-LAN.
