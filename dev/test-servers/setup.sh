#!/usr/bin/env bash
# Test environment in the Linux sandbox: libraries to build the Tauri shell and a Net-SNMP
# agent on 127.0.0.1:16100 (community public, v3 users u_*), for NTB_SNMP_TEST=16100.
# Since 1.7.0 (Active Directory removed) OpenLDAP is no longer needed.
# Background processes are killed between turns: if snmp::tests::agente_vero fails with
# "Porta UDP ... chiusa", run this script again.
# DNS, HTTP, TLS and NTP are tested with fake servers started by the tests themselves.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# iputils-ping: the Linux ICMP backend uses the ping command (without it the tests run idle)
if ! pkg-config --exists webkit2gtk-4.1 2>/dev/null || ! command -v snmpd >/dev/null \
   || ! command -v ping >/dev/null; then
  apt-get update -q >/dev/null
  apt-get install -y -q pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev \
    librsvg2-dev libayatana-appindicator3-dev libssl-dev snmpd snmp iputils-ping >/dev/null
fi
D=${NTB_SNMP_DIR:-/tmp/ntb-snmp}
HERE=$(cd "$(dirname "$0")" && pwd)
if ! pgrep -x snmpd >/dev/null; then
  rm -rf "$D" && mkdir -p "$D/persist"
  /usr/sbin/snmpd -C -c "$HERE/snmpd.conf" -p "$D/pid" -Lf "$D/log" --persistentDir="$D/persist"
  sleep 1
fi
snmpget -v3 -l authPriv -u u_shaaes -a SHA -A authpass123 -x AES -X privpass123 \
  127.0.0.1:16100 1.3.6.1.2.1.1.5.0 | sed 's/^/Net-SNMP ready: /'
