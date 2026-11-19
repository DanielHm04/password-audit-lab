"""
Offline unit tests for the deterministic core.

These cover the pure, no-GPU logic: hash identification (provenance + content
prefix), NTDS triage (abuse vs crack), targeted wordlist forging, self-mined
rule derivation, password analysis, and the HIBP set-membership scan.

Run from the repo root:  python -m pytest -q
"""
import sys
from pathlib import Path

# make the `core` package importable regardless of where pytest is invoked
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import cracklab, triage, forge, rulegen, analysis, hibp


# ---------- identify ----------

def test_identify_provenance_wins(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("aad3b435b51404eeaad3b435b51404ee:" + "a" * 32 + "\n")
    res = cracklab.identify(str(f), provenance="secretsdump")
    assert res["mode"] == 1000
    assert res["basis"].startswith("provenance")
    assert res["confidence"] == "high"


def test_identify_prefix_sha512crypt(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("$6$abc$def\n")
    res = cracklab.identify(str(f))
    assert res["mode"] == 1800


def test_identify_prefix_bcrypt(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("$2b$12$abcdefghijklmnopqrstuv\n")
    res = cracklab.identify(str(f))
    assert res["mode"] == 3200


def test_identify_kerberoast_prefix(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("$krb5tgs$23$*user$DOMAIN$spn*$abcdef\n")
    res = cracklab.identify(str(f))
    assert res["mode"] == 13100


# ---------- triage ----------

def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_triage_machine_and_krbtgt_are_abuse_only(tmp_path):
    empty = triage._EMPTY_NT
    data = (
        "DC01$:1001:aad3b435b51404eeaad3b435b51404ee:" + "a" * 32 + ":::\n"
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:" + "b" * 32 + ":::\n"
        "alice:1103:aad3b435b51404eeaad3b435b51404ee:" + "c" * 32 + ":::\n"
    )
    t = triage.triage(_write(tmp_path, "ntds.txt", data))
    assert t["summary"]["abuse_only"] == 2
    assert t["summary"]["crackable"] == 1
    abusers = {u for u, _ in t["abuse"]}
    assert "DC01$" in abusers and "krbtgt" in abusers


def test_triage_blank_password_flagged(tmp_path):
    data = "guest:501:aad3b435b51404eeaad3b435b51404ee:" + triage._EMPTY_NT + ":::\n"
    t = triage.triage(_write(tmp_path, "n.txt", data))
    assert t["summary"]["flagged"] == 1
    assert any("BLANK" in why for _u, why in t["note"])


def test_triage_detects_reuse(tmp_path):
    shared = "d" * 32
    data = (
        "u1:1:x:" + shared + ":::\n"
        "u2:2:x:" + shared + ":::\n"
    )
    t = triage.triage(_write(tmp_path, "n.txt", data))
    assert t["summary"]["reused_hashes"] == 1


def test_write_crackable_strips_abuse(tmp_path):
    data = (
        "DC01$:1001:x:" + "a" * 32 + ":::\n"
        "alice:1103:x:" + "c" * 32 + ":::\n"
    )
    t = triage.triage(_write(tmp_path, "n.txt", data))
    out = tmp_path / "crackable.txt"
    triage.write_crackable(t, str(out))
    lines = [l for l in out.read_text().splitlines() if l]
    assert len(lines) == 1 and lines[0].startswith("alice")


# ---------- forge ----------

def test_forge_years_range_parsing():
    assert forge.parse_years("2019-2021,1999") == ["1999", "2019", "2020", "2021"]


def test_forge_osint_tokenizer_drops_stopwords_and_digits():
    words = forge.base_from_osint("The dolphins and 2020 shoreline from the LLC")
    assert "dolphins" in words and "shoreline" in words
    assert "the" not in [w.lower() for w in words]
    assert "2020" not in words


def test_forge_generate_applies_year_and_special_suffix():
    cands = forge.generate(["miller"], years=["2024"], specials=["", "!"], leet=False)
    assert "Miller2024!" in cands
    assert "miller" in cands
    # deterministic de-dup: no duplicates in output
    assert len(cands) == len(set(cands))


def test_forge_leet_variant():
    cands = forge.generate(["password"], years=[], specials=[""], leet=True)
    assert "p@$$w0rd" in cands


# ---------- rulegen ----------

def test_rulegen_derive_capitalize_and_suffix():
    rule, base = rulegen.derive_rule("Summer2024!")
    assert base == "summer"
    assert rule.startswith("c ")
    assert "$2" in rule and "$!" in rule


def test_rulegen_derive_prefix():
    rule, base = rulegen.derive_rule("!welcome")
    assert base == "welcome"
    assert "^!" in rule


def test_rulegen_rejects_spaces_and_plain_words():
    assert rulegen.derive_rule("two words") == (None, None)
    assert rulegen.derive_rule("plainword") == (None, None)  # no affix -> no rule


def test_rulegen_mine_respects_min_freq():
    pts = ["Summer2024!", "Winter2024!", "Spring2024!", "one2024!"]
    kept = rulegen.mine(pts, cap=200, min_freq=2)
    rules = {r for r, _c, _ex in kept}
    # "c $2 $0 $2 $4 $!" appears for all four -> kept; nothing appears once that survives
    assert all(c >= 2 for _r, c, _ex in kept)
    assert len(rules) >= 1


def test_rulegen_write_learned_header(tmp_path):
    rf = tmp_path / "learned.rule"
    n = rulegen.write_learned(["Summer2024!", "Winter2024!"], str(rf), min_freq=2)
    txt = rf.read_text()
    assert txt.startswith("# learned.rule")
    assert f"{n} rules" in txt


# ---------- analysis ----------

def test_analysis_mask_of():
    assert analysis.mask_of("Ab1!") == "?u?l?d?s"


def test_analysis_base_word():
    assert analysis.base_word("!Summer2024!") == "summer"


def test_analysis_percentages():
    a = analysis.analyze(["Summer2024!", "winter", "Spring2025"])
    assert a["count"] == 3
    assert a["pct_upper"] == 67  # 2 of 3 have an uppercase char
    assert 0 <= a["pct_special"] <= 100


def test_analysis_reuse_and_pw_equals_user():
    pairs = [("DOMAIN\\alice", "P@ss1"), ("bob", "P@ss1"), ("admin", "admin")]
    r = analysis.reuse(pairs)
    assert "P@ss1" in r["reused"]
    assert ("admin", "admin") in r["pw_equals_user"]


# ---------- hibp ----------

def test_hibp_load_targets_secretsdump_layout(tmp_path):
    nt = "e" * 32
    f = tmp_path / "n.txt"
    f.write_text("DOMAIN\\alice:1103:aad3:" + nt + ":::\n")
    targets = hibp.load_targets(str(f))
    assert nt in targets and targets[nt] == ["DOMAIN\\alice"]


def test_hibp_scan_membership(tmp_path):
    nt = "f" * 32
    corpus = tmp_path / "hibp.txt"
    corpus.write_text((nt.upper()) + ":42\nAAAA:1\n")
    hits = hibp.scan(str(corpus), {nt: ["alice"]})
    assert hits == {nt: 42}


def test_hibp_scan_no_match(tmp_path):
    corpus = tmp_path / "hibp.txt"
    corpus.write_text("BBBB:1\n")
    hits = hibp.scan(str(corpus), {"a" * 32: ["x"]})
    assert hits == {}


# ---------- classify_pattern (trophy labelling) ----------

def test_classify_pattern_word_year_special():
    assert cracklab.classify_pattern("Summer2024!") == "Word+Year+Special"


def test_classify_pattern_digits():
    assert cracklab.classify_pattern("admin123") == "Word+Digits"
