#!/usr/bin/env python3
"""
rulegen.py -- the RuleGen strange-loop (governed self-modification).

Mines hashcat RULES from passwords CrackLab already cracked: reverse the mangling
(base word -> observed password), emit the equivalent hashcat rule, rank by
frequency. The result (rules/learned.rule) becomes a late Escalation-ladder rung,
so each Job rewrites the ruleset the next Job uses. This is the GEB feedback loop.

Governance (see docs/adr/0003):
  - cap N new rules per refresh (default 200)
  - only patterns seen >= MIN_FREQ times (default 2) -- never learn from one datum
  - every kept rule logged with its frequency + an example crack (audit trail)
  - engagement scopes learn into an isolated file, never the shared ruleset

Pure Python, no LLM, no PACK dependency.
"""
import json, re
from collections import Counter
from pathlib import Path

MAX_AFFIX = 12          # ignore absurdly long prefixes/suffixes (not a real rule)
DEFAULT_CAP = 200
DEFAULT_MIN_FREQ = 2

# hashcat single-char rule functions we emit; keep to the safe, portable subset
_CORE_RE = re.compile(r"^(?P<pre>[^A-Za-z]*)(?P<core>[A-Za-z]+)(?P<post>.*)$")


def derive_rule(pw):
    """Reverse a cracked password to the hashcat rule that makes it from its
    lowercased dictionary base word. Returns (rule_str, base_word) or (None, None)
    when the password isn't a clean base+affix shape we can encode."""
    if not pw or " " in pw:            # spaces are ambiguous in rule files -> skip
        return None, None
    m = _CORE_RE.match(pw)
    if not m:
        return None, None
    pre, core, post = m.group("pre"), m.group("core"), m.group("post")
    if len(pre) > MAX_AFFIX or len(post) > MAX_AFFIX:
        return None, None
    # any non-ascii or a second alpha run inside post -> too specific, skip
    if not core.isascii() or not pre.isascii() or not post.isascii():
        return None, None
    tokens = []
    # 1) case operation to turn the lowercase base word into `core`
    if core == core.lower():
        pass                            # base word already lowercase -> no op
    elif core == core.capitalize():
        tokens.append("c")              # capitalize first letter
    elif core == core.upper():
        tokens.append("u")              # uppercase everything
    else:
        return None, None               # mixed/weird case -> not a general rule
    # 2) prepend the prefix (reversed so the first char lands leftmost)
    for ch in reversed(pre):
        tokens.append("^" + ch)
    # 3) append the suffix in order
    for ch in post:
        tokens.append("$" + ch)
    if not tokens:                      # plain dictionary word -> no-op, not useful
        return None, None
    return " ".join(tokens), core.lower()


def mine(plaintexts, cap=DEFAULT_CAP, min_freq=DEFAULT_MIN_FREQ):
    """plaintexts -> ranked list of (rule, freq, example). Governed by cap/min_freq."""
    counter = Counter()
    example = {}
    for pw in plaintexts:
        rule, _base = derive_rule(pw)
        if not rule:
            continue
        counter[rule] += 1
        example.setdefault(rule, pw)
    kept = [(r, c, example[r]) for r, c in counter.most_common() if c >= min_freq]
    return kept[:cap]


def write_learned(plaintexts, rule_file, log_file=None, cap=DEFAULT_CAP,
                  min_freq=DEFAULT_MIN_FREQ, redact=False):
    """Refresh the learned ruleset from cracked plaintexts. Returns count written.
    redact=True (engagement) keeps rules but omits the example plaintext from the log."""
    kept = mine(plaintexts, cap, min_freq)
    rf = Path(rule_file)
    rf.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "# learned.rule -- auto-mined by rulegen.py from CrackLab's own cracks.",
        f"# {len(kept)} rules (freq >= {min_freq}, cap {cap}). Regenerated each Job.",
        "# Do NOT hand-edit; changes are overwritten. See docs/adr/0003.",
    ]
    body = [r for r, _c, _ex in kept]
    rf.write_text("\n".join(header + body) + "\n", encoding="utf-8")
    if log_file:
        lf = Path(log_file)
        lf.parent.mkdir(parents=True, exist_ok=True)
        with open(lf, "a", encoding="utf-8") as f:
            for r, c, ex in kept:
                f.write(json.dumps({
                    "rule": r, "freq": c,
                    "example": "[redacted]" if redact else ex,
                    "confidence": round(min(1.0, c / 10.0), 2),
                }) + "\n")
    return len(kept)


if __name__ == "__main__":
    import sys
    # tiny self-test / manual run: pipe plaintexts on stdin
    pts = [l.strip() for l in sys.stdin if l.strip()] if not sys.stdin.isatty() else \
          ["Summer2024!", "Summer2023!", "Winter2024!", "admin123", "Admin123",
           "!password", "!welcome", "COMPANY1", "COMPANY2"]
    for r, c, ex in mine(pts):
        print(f"{c:>3}  {r:<30}  ({ex})")
