#!/usr/bin/env python3
"""
analysis.py -- password analysis for the CPTS report + the mask feedback loop.
Pure Python (no Ruby/pipal, no PACK). Consumed by cracklab.py `report` and `masks`.
"""
import re
from collections import Counter

def mask_of(pw):
    out = []
    for c in pw:
        if c.islower(): out.append("?l")
        elif c.isupper(): out.append("?u")
        elif c.isdigit(): out.append("?d")
        else: out.append("?s")
    return "".join(out)

def base_word(pw):
    core = re.sub(r"^[^A-Za-z]+", "", pw)          # strip leading non-alpha
    core = re.sub(r"[^A-Za-z]+$", "", core)        # strip trailing non-alpha
    return core.lower()

def analyze(plaintexts):
    n = len(plaintexts)
    if n == 0:
        return {"count": 0}
    lengths = Counter(len(p) for p in plaintexts)
    top = Counter(plaintexts).most_common(10)
    words = Counter(base_word(p) for p in plaintexts if base_word(p)).most_common(10)
    has_upper = sum(1 for p in plaintexts if any(c.isupper() for c in p))
    has_digit = sum(1 for p in plaintexts if any(c.isdigit() for c in p))
    has_special = sum(1 for p in plaintexts if any(not c.isalnum() for c in p))
    ge8 = sum(1 for p in plaintexts if len(p) >= 8)
    return {
        "count": n, "lengths": dict(sorted(lengths.items())),
        "top": top, "base_words": words,
        "pct_upper": round(100*has_upper/n), "pct_digit": round(100*has_digit/n),
        "pct_special": round(100*has_special/n), "pct_ge8": round(100*ge8/n),
    }

def masks_from_cracked(plaintexts, top_n=25):
    """statsgen/maskgen-lite: frequency-sorted .hcmask lines for the next run."""
    c = Counter(mask_of(p) for p in plaintexts)
    return c.most_common(top_n)

def reuse(pairs):
    """pairs: list of (user, plaintext). Returns reuse groups + weak-account flags."""
    by_pw = {}
    for user, pw in pairs:
        by_pw.setdefault(pw, []).append(user)
    reused = {pw: us for pw, us in by_pw.items() if len([u for u in us if u]) > 1}
    pw_eq_user = [(u, pw) for u, pw in pairs if u and pw and pw.lower() == u.split("\\")[-1].lower()]
    return {"reused": reused, "pw_equals_user": pw_eq_user}

def report_markdown(mode_name, total, pairs, context=""):
    plains = [pw for _u, pw in pairs]
    a = analyze(plains)
    cracked = len(plains)
    pct = round(100*cracked/total) if total else 0
    L = [f"# Password Cracking Appendix", "",
         f"**Hash type:** {mode_name}  |  **Context:** {context or 'n/a'}", "",
         f"**Cracked: {cracked} / {total} ({pct}%)**", ""]
    if cracked == 0:
        L.append("_No passwords recovered._")
        return "\n".join(L)
    L += ["## Complexity of cracked passwords",
          f"- Contains uppercase: {a['pct_upper']}%",
          f"- Contains a digit: {a['pct_digit']}%",
          f"- Contains a special char: {a['pct_special']}%",
          f"- Length >= 8: {a['pct_ge8']}%", "",
          "## Top passwords", ""]
    for pw, ct in a["top"]:
        L.append(f"- `{pw}` x{ct}")
    L += ["", "## Top base words", ""]
    for w, ct in a["base_words"]:
        L.append(f"- {w} x{ct}")
    L += ["", "## Length distribution", ""]
    for ln, ct in a["lengths"].items():
        L.append(f"- {ln} chars: {ct}")
    r = reuse(pairs)
    if any(u for u, _ in pairs):   # only if usernames present
        L += ["", "## Password reuse (finding)", ""]
        if r["reused"]:
            for pw, users in sorted(r["reused"].items(), key=lambda kv: -len(kv[1]))[:10]:
                L.append(f"- `{pw}` shared by {len(users)} accounts: {', '.join(u for u in users if u)}")
        else:
            L.append("- No shared passwords detected.")
        if r["pw_equals_user"]:
            L += ["", "## Password == username (critical)", ""]
            for u, pw in r["pw_equals_user"]:
                L.append(f"- **{u}** : `{pw}`")
    return "\n".join(L)
