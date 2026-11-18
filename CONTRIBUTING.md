# Contributing

Thanks for your interest in Network Toolbox. Bug reports, ideas and pull requests are welcome.

## Before you start

- Read the architecture and the conventions in the technical sections of [`README.md`](README.md):
  they describe the structure, the rules that must not be broken and the lessons learned.
- Open an issue first for anything bigger than a small fix, so the approach can be discussed.
- The app targets **Windows** (Rust + Tauri 2). Network logic lives in `core/` and must stay
  independent of Tauri and testable.

## Development setup

```powershell
git clone https://github.com/giocasnet/network-toolbox.git
cd network-toolbox
cargo fmt --all
cargo clippy -q --all-targets -p ntb-core     # zero warnings
cargo test -p ntb-core
cargo check -p nettoolbox
python -E -P dev\ui-mock\ui_smoke.py           # UI with a simulated IPC (needs Playwright + Chromium)
```

Tests must not leave the PC: use fake servers on `127.0.0.1`. Do not add tests that depend on real
networks or on real hosts.

## Rules for changes

- **Languages**: the interface and the backend messages exist in Italian (default) and English.
  Every new user-visible text needs both: `t!("italiano", "english")` / `tf!(...)` in Rust,
  `__('italiano')` in `ui/app.js` plus an entry in `ui/i18n/en-*.js`. Never translate machine
  codes that the UI compares. Code comments are written in English.
- **Examples and test data** use reserved names and addresses only (RFC 2606 names such as
  `www.example.com`, RFC 5737 addresses `192.0.2.x`, `198.51.100.x`, `203.0.113.x`, or `172.16.x.x`
  for private networks). Never commit real host names, domains, company data or credentials.
- **Probing tools** (scans, SNMP, SMTP, TLS) must never run from tests against real targets.
- Keep the changes focused, update `CHANGELOG.md` and say what was verified.
- New dependencies: check the licence is compatible with Apache-2.0 and regenerate
  `THIRD-PARTY-LICENSES.md`.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
