#!/usr/bin/env python3
"""
forge.py -- deterministic Targeted-wordlist generator (Muscle, no LLM).

The Brain picks smart base words from free-form OSINT; THIS explodes them into a
candidate list with the human password patterns (case, leet, years, specials,
combos). Runs fully offline. Also has a dumb --osint-file tokenizer so the
Deterministic core can extract base words with no Brain at all.

Usage:
  python forge.py --terms shoreline,miller,dolphins --years 1974,2019-2026 --out ../wordlists/target.txt
  python forge.py --osint-file notes.txt --years 2000-2026 --out ../wordlists/target.txt
"""
import argparse, re, sys
from pathlib import Path

LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})
DEFAULT_SPECIALS = ["", "!", "@", "#", "$", "1", "123", "!@#", ".", "*"]
STOPWORDS = {
    "the","and","for","are","was","with","that","this","from","have","has","not",
    "you","your","our","their","its","a","an","of","to","in","on","at","is","it",
    "com","www","http","https","inc","llc","ltd","co",
}

def base_from_osint(text: str) -> list:
    """Dumb offline tokenizer: pull candidate base words from free text."""
    toks = re.split(r"[^A-Za-z0-9]+", text)
    out = []
    for t in toks:
        t = t.strip()
        if len(t) >= 3 and t.lower() not in STOPWORDS and not t.isdigit():
            out.append(t)
    # dedupe preserving order, case-insensitive
    seen, uniq = set(), []
    for t in out:
        if t.lower() not in seen:
            seen.add(t.lower()); uniq.append(t)
    return uniq

def parse_years(spec: str) -> list:
    years = set()
    if not spec:
        return []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            for y in range(int(a), int(b) + 1):
                years.add(str(y))
        elif part:
            years.add(part)
    return sorted(years)

def word_variants(word: str, leet: bool) -> list:
    w = word.strip()
    if not w:
        return []
    v = {w.lower(), w.capitalize(), w.upper()}
    if leet:
        v.add(w.lower().translate(LEET))
        v.add(w.capitalize().translate(LEET))
    return list(v)

def generate(base_words, years=None, specials=None, leet=True, combine=False,
             min_len=1, max_len=None):
    years = years or []
    specials = specials if specials is not None else DEFAULT_SPECIALS
    suffixes = [""] + years[:] + specials[:]
    # year+special and special+year combos (the classic Password2024! shape)
    for y in years:
        for s in specials:
            if s:
                suffixes.append(y + s)
    words = list(base_words)
    if combine:  # small pairwise combos -- keep bounded
        for i in range(len(base_words)):
            for j in range(len(base_words)):
                if i != j:
                    words.append(base_words[i] + base_words[j])
    out = []
    for w in words:
        for variant in word_variants(w, leet):
            for suf in suffixes:
                cand = variant + suf
                if len(cand) < min_len:
                    continue
                if max_len and len(cand) > max_len:
                    continue
                out.append(cand)
    # dedupe preserving order
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c); uniq.append(c)
    return uniq

def main():
    p = argparse.ArgumentParser(description="Deterministic targeted-wordlist forge")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--terms", help="comma-separated base words")
    src.add_argument("--osint-file", help="free-text file; base words auto-extracted")
    p.add_argument("--years", default="", help="e.g. 1974,2019-2026")
    p.add_argument("--specials", help="comma-separated; overrides defaults")
    p.add_argument("--no-leet", action="store_true")
    p.add_argument("--combine", action="store_true", help="add pairwise word combos")
    p.add_argument("--min-len", type=int, default=1)
    p.add_argument("--max-len", type=int, default=None)
    p.add_argument("--out", help="output file (default: stdout)")
    a = p.parse_args()

    if a.terms:
        base = [t.strip() for t in a.terms.split(",") if t.strip()]
    else:
        base = base_from_osint(Path(a.osint_file).read_text(encoding="utf-8", errors="ignore"))
    if not base:
        print("forge: no base words found", file=sys.stderr); sys.exit(1)

    specials = None
    if a.specials is not None:
        specials = [s for s in a.specials.split(",")]
    cands = generate(base, parse_years(a.years), specials, not a.no_leet,
                     a.combine, a.min_len, a.max_len)

    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text("\n".join(cands) + "\n", encoding="utf-8")
        print(f"forge: {len(cands)} candidates from {len(base)} base words -> {a.out}")
    else:
        print("\n".join(cands))

if __name__ == "__main__":
    main()
