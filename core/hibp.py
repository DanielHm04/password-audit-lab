#!/usr/bin/env python3
"""
hibp.py -- compare domain NT hashes directly against the Have I Been Pwned
NTLM corpus (~1B breached hashes). ZERO cracking: it's a set-membership scan,
so it flags known-breached passwords in seconds and works even on strong
passwords a GPU would never crack. The top move for a domain password audit.

The HIBP NTLM file is `UPPERHASH:count` sorted lines (from the official
haveibeenpwned-downloader, `-n` for NTLM). Fetch it with scripts/fetch-hibp.ps1.
Targets are small (one domain's hashes) and held in RAM; the huge HIBP file is
streamed once, never loaded whole.
"""
import re
from pathlib import Path

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"   # NT hash of the empty password


def load_targets(hashfile):
    """Parse NT hashes from an NTDS dump or user:hash file.
    Returns {nt_hash_lower: [usernames...]}. Recognizes:
      DOMAIN\\user:rid:lm:nt:::   (secretsdump)  -> NT is field index 3
      user:nt                     -> NT is the last field
      bare nt hash                -> no username
    """
    targets = {}
    for raw in Path(hashfile).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        nt, user = None, None
        if len(parts) >= 4 and _HEX32.match(parts[3]):        # secretsdump layout
            nt, user = parts[3].lower(), parts[0]
        elif len(parts) == 2 and _HEX32.match(parts[1]):      # user:nt
            nt, user = parts[1].lower(), parts[0]
        elif len(parts) == 1 and _HEX32.match(parts[0]):      # bare hash
            nt = parts[0].lower()
        if nt:
            targets.setdefault(nt, []).append(user)
    return targets


def scan(hibp_file, targets):
    """Stream the HIBP NTLM file; return {nt_hash: prevalence_count} for hits."""
    hits = {}
    want = set(targets)
    # utf-8-sig strips a leading BOM if the downloader wrote one (else no-op),
    # so the very first hash line isn't silently missed.
    with open(hibp_file, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            h, _sep, cnt = line.partition(":")
            hl = h.strip().lower()
            if hl in want:
                try:
                    hits[hl] = int(cnt.strip() or 0)
                except ValueError:
                    hits[hl] = 0
                if len(hits) == len(want):
                    break                 # found them all -> stop early
    return hits


def report_markdown(targets, hits, context=""):
    total_accounts = sum(len(u) for u in targets.values())
    unique_hashes = len(targets)
    breached_accounts = sum(len(targets[h]) for h in hits)
    empty_accounts = targets.get(_EMPTY_NT, [])
    pct = round(100 * breached_accounts / total_accounts) if total_accounts else 0
    L = ["# HIBP Breached-Password Findings (no cracking)", "",
         f"**Context:** {context or 'n/a'}", "",
         f"**Accounts using a known-breached password: {breached_accounts} / "
         f"{total_accounts} ({pct}%)**  across {unique_hashes} unique hashes.", ""]
    if empty_accounts:
        L += ["## Blank passwords (critical)", ""]
        L += [f"- **{u}**" for u in empty_accounts if u]
        L.append("")
    # rank breached by prevalence (most common breached pw first = weakest)
    ranked = sorted(hits.items(), key=lambda kv: -kv[1])
    if ranked:
        L += ["## Breached accounts (by breach prevalence)", ""]
        for h, cnt in ranked:
            if h == _EMPTY_NT:
                continue
            users = ", ".join(u for u in targets[h] if u) or "(no username)"
            L.append(f"- seen **{cnt:,}x** in breaches -> {len(targets[h])} account(s): {users}")
    else:
        L.append("_No accounts matched the HIBP corpus._")
    L += ["", "## Remediation", "",
          "- Force-reset every flagged account; these passwords are in public breach lists.",
          "- Enable a breached-password filter (Azure AD Password Protection or an on-prem"
          " banned-password list seeded from HIBP) so they can't be set again.", ""]
    return "\n".join(L)
