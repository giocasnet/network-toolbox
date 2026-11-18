# Security policy

## Supported versions

Only the latest released version receives fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Report it privately with the
GitHub *Security advisories* feature of this repository (**Security → Report a vulnerability**).
Include the version, the steps to reproduce and, if possible, the impact you see. You will get an
answer as soon as the maintainer can read the report.

## Scope and design notes

- The app runs every test **from the user's PC** and has no server component and no telemetry.
- SNMP access is **read-only** (no SET requests); passwords and community strings are not saved in
  the profiles and are never written to logs or transcripts.
- Server certificates are verified; the only exception is a fallback that is always marked in the
  result as not authenticated. Passwords are sent (SMTP) only over a verified TLS session.
- The installers are **not code-signed**: verify the SHA-256 hashes published with each release.
- Dependencies are listed in [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md); reports about
  vulnerable dependencies are welcome.
