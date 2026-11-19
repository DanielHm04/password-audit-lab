#!/usr/bin/env python3
"""
triage.py -- "abuse, don't crack" advisory (pure core, no LLM, no deps).

Before burning the GPU on an NTDS dump, some hashes should never be cracked:
machine accounts and krbtgt are effectively 120-char random -- you *pass* them,
you don't crack them. Blank hashes are already a finding. This scanner labels
each line so the Operator (and Daniel) spend GPU time only where it can pay off.

It also surfaces reuse (identical NT hashes) and AES-only Kerberos tickets
(slow -- prefer an RC4 downgrade). Cracking still happens elsewhere; this just
keeps the ladder honest about what's worth attacking.
"""
import re
from collections import Counter
from pathlib import Path

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _rows(hashfile):
    for raw in Path(hashfile).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            yield line


def triage(hashfile):
    """Return {'crack': [...], 'abuse': [...], 'note': [...], 'summary': {...}}."""
    crack, abuse, note = [], [], []
    nt_counts = Counter()
    for line in _rows(hashfile):
        parts = line.split(":")
        user = parts[0] if len(parts) > 1 else ""
        low_user = user.split("\\")[-1].lower()
        nt = parts[3].lower() if len(parts) >= 4 and _HEX32.match(parts[3]) else (
             parts[1].lower() if len(parts) == 2 and _HEX32.match(parts[1]) else None)
        if nt:
            nt_counts[nt] += 1

        # krbtgt -> golden-ticket material, never crack
        if low_user == "krbtgt":
            abuse.append((user, "krbtgt -> golden-ticket material; NEVER crack, protect/rotate"))
            continue
        # machine accounts end with $ -> ~120-char random, pass-the-hash only
        if user.endswith("$"):
            abuse.append((user, "machine account; ~random 120-char -> PtH/S4U, do not crack"))
            continue
        # blank NT hash -> already a finding
        if nt == _EMPTY_NT:
            note.append((user, "BLANK password (empty NT hash) -- report as critical"))
            continue
        # AES-only Kerberos tickets -> slow; prefer RC4 downgrade
        if "$krb5tgs$18$" in line or "$krb5tgs$19$" in line or \
           "$krb5asrep$18$" in line or "$krb5asrep$19$" in line:
            note.append((user or "(ticket)", "AES Kerberos ticket -> slow to crack; request RC4 (etype 23) if possible"))
            crack.append(line)
            continue
        crack.append(line)

    reused = {h: c for h, c in nt_counts.items() if c > 1 and h != _EMPTY_NT}
    return {
        "crack": crack, "abuse": abuse, "note": note,
        "summary": {
            "total": sum(1 for _ in _rows(hashfile)),
            "crackable": len(crack), "abuse_only": len(abuse),
            "flagged": len(note), "reused_hashes": len(reused),
        },
        "reused": reused,
    }


def report_text(t):
    s = t["summary"]
    L = [f"[triage] {s['total']} line(s): {s['crackable']} worth cracking, "
         f"{s['abuse_only']} abuse-only (skip GPU), {s['flagged']} flagged, "
         f"{s['reused_hashes']} reused hash(es)."]
    for user, why in t["abuse"]:
        L.append(f"  ABUSE  {user:<24} {why}")
    for user, why in t["note"]:
        L.append(f"  NOTE   {user:<24} {why}")
    if t["reused"]:
        L.append(f"  REUSE  {len(t['reused'])} NT hash(es) shared by multiple accounts "
                 f"(password reuse -- crack once, applies to all).")
    return "\n".join(L)


def write_crackable(t, out):
    """Write only the crack-worthy lines (machine/krbtgt stripped) to `out`."""
    Path(out).write_text("\n".join(t["crack"]) + "\n", encoding="utf-8")
    return out
