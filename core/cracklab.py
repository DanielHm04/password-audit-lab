#!/usr/bin/env python3
"""
cracklab.py -- the Deterministic core (Muscle, no LLM required).

Identifies a hash (provenance-first), forges/uses wordlists, climbs the governed
Escalation ladder within a wall-clock cap, and writes the Trophy log -- all
offline. The Brain (Claude Code / future API / Ollama) orchestrates this via the
skills, but every capability here also runs headless:

  python cracklab.py identify hashes/x.txt --provenance secretsdump
  python cracklab.py auto     hashes/x.txt --scope htb --provenance shadow --cap 1800
  python cracklab.py manual   hashes/x.txt --mode 1000 --wordlist ../wordlists/rockyou.txt --rules OneRuleToRuleThemAll.rule --scope htb
  python cracklab.py status
  python cracklab.py trophies --context ad

Governance: authorized scope required; 30-min default cap; brute-force never runs
unless --allow-bruteforce is explicitly passed.
"""
import argparse, json, os, subprocess, sys, time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # ...\CrackLab
HASHCAT_DIR = ROOT / "hashcat"
HASHCAT = HASHCAT_DIR / "hashcat.exe"
WORDLISTS = ROOT / "wordlists"
RULES_LOCAL = ROOT / "rules"
RULES_BUNDLED = HASHCAT_DIR / "rules"
LOOT = ROOT / "loot"
POTFILE = LOOT / "cracked.pot"
TROPHY = LOOT / "trophy.jsonl"
JOBS = LOOT / "jobs"
ROCKYOU = WORDLISTS / "rockyou.txt"
TOOLS = ROOT / "tools"                  # optional binaries: princeprocessor, kwprocessor
BENCH_CACHE = LOOT / "benchmarks.json"  # cached GPU H/s per mode (for keyspace ETA)
LEARNED_LOG = LOOT / "learned-rules.jsonl"

# runtime state (set per-job from CLI args)
CURRENT_POT = POTFILE       # per-engagement potfiles keep client data separate
CURRENT_LEARNED = RULES_LOCAL / "learned.rule"   # scope-isolated self-learned ruleset
USE_USERNAME = False        # input is user:hash -> map cracks back to accounts
TEMP_ABORT = 90             # hashcat aborts a rung if the GPU hits this temp (laptop guard)

VALID_SCOPES = ("htb", "cpts", "lab", "engagement")     # engagement may be "engagement:label"
SLOW_MODES = {1800, 3200, 500, 400, 1600, 7400, 1500, 3000, 22000, 2100, 5200, 13721}

# provenance -> hashcat mode (the reliable path; trusted over hash-shape guessing)
PROVENANCE = {
    "secretsdump": 1000, "ntds": 1000, "sam": 1000, "ntlm": 1000, "ntlmhash": 1000,
    "shadow": 1800, "linux": 1800, "sha512crypt": 1800,
    "md5crypt": 500, "shadow-md5": 500,
    "bcrypt": 3200,
    "responder": 5600, "netntlmv2": 5600, "ntlmv2": 5600,
    "netntlmv1": 5500, "ntlmv1": 5500,
    "kerberoast": 13100, "tgs": 13100, "getuserspns": 13100,
    "asrep": 18200, "asreproast": 18200, "getnpusers": 18200,
    "wpa": 22000, "wpa2": 22000, "handshake": 22000,
    "mysql": 300, "mssql": 1731, "postgres": 12,
    "keepass": 13400, "zip": 13600, "sshkey": 22921, "office": 9600,
}
# hash-content prefix -> mode (fallback when provenance not given)
PREFIX = [
    ("$6$", 1800), ("$5$", 7400), ("$1$", 500),
    ("$2a$", 3200), ("$2b$", 3200), ("$2y$", 3200),
    ("$y$", 3200),  # yescrypt approx -> flag for review
    ("$krb5tgs$23$", 13100), ("$krb5tgs$", 13100),
    ("$krb5asrep$23$", 18200), ("$krb5asrep$", 18200),
    ("$krb5pa$", 7500),
    ("$DCC2$", 2100), ("$sha1$", 200),
    ("$sshng$", 22911), ("$keepass$", 13400), ("$office$", 9600),
    ("$pdf$", 10700), ("$rar5$", 13000), ("$RAR3$", 12500),
    ("$7z$", 11600), ("$zip2$", 13600), ("$pkzip2$", 17200),
    ("$bitlocker$", 22100), ("$luks$", 14600), ("$ansible$", 16900),
    ("aad3b435b51404eeaad3b435b51404ee", 1000),  # empty-LM colon NTLM lines
]
# file extension -> (*2john tool in john/run, runner)  [perl .pl tools unavailable: no perl]
EXTRACTORS = {
    ".ssh": ("ssh2john.py", "py"), ".key": ("ssh2john.py", "py"),
    ".ppk": ("putty2john.py", "py"),
    ".kdbx": ("keepass2john.exe", "exe"),
    ".docx": ("office2john.py", "py"), ".xlsx": ("office2john.py", "py"),
    ".pptx": ("office2john.py", "py"), ".doc": ("office2john.py", "py"),
    ".rar": ("rar2john.exe", "exe"),
    ".vhd": ("bitlocker2john.exe", "exe"), ".bek": ("bitlocker2john.exe", "exe"),
}
MODE_NAMES = {
    0:"MD5",100:"SHA1",1000:"NTLM",1800:"sha512crypt",500:"md5crypt",3200:"bcrypt",
    5600:"NetNTLMv2",5500:"NetNTLMv1",13100:"Kerberos TGS-REP",18200:"Kerberos AS-REP",
    22000:"WPA-PBKDF2",7400:"sha256crypt",1700:"SHA-512",2100:"DCC2",300:"MySQL",
    13400:"KeePass",13600:"WinZip",9600:"Office 2013",
}
# hashcat mode -> john --format name (for routing / the john bridge)
MODE_TO_JOHN = {
    0:"raw-md5", 100:"raw-sha1", 1000:"nt", 1800:"sha512crypt", 500:"md5crypt",
    7400:"sha256crypt", 3200:"bcrypt", 5600:"netntlmv2", 5500:"netntlm",
    13100:"krb5tgs", 18200:"krb5asrep", 9600:"office", 9500:"office", 9400:"office",
    13400:"keepass", 22100:"BitLocker", 22921:"ssh", 13600:"zip", 11600:"7z",
    10700:"pdf", 12500:"rar3", 13000:"rar5", 300:"mysql-sha1", 22000:"wpapsk",
}

def die(msg, code=1):
    print(f"cracklab: {msg}", file=sys.stderr); sys.exit(code)

def now_iso():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def read_hash_lines(hashfile):
    p = Path(hashfile)
    if not p.exists():
        die(f"hash file not found: {hashfile}")
    lines = [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()]
    return [l for l in lines if l and not l.startswith("#")]

# ---------- identify ----------
def identify(hashfile, provenance=None):
    lines = read_hash_lines(hashfile)
    if not lines:
        die("hash file is empty")
    sample = lines[0]
    # 1) provenance wins
    if provenance:
        key = provenance.lower().strip()
        if key in PROVENANCE:
            m = PROVENANCE[key]
            return {"mode": m, "name": MODE_NAMES.get(m, str(m)),
                    "basis": f"provenance:{key}", "confidence": "high", "candidates": [m]}
    # 2) content prefix
    for pref, m in PREFIX:
        if sample.startswith(pref) or (":" in sample and sample.split(":")[-1].startswith(pref)):
            return {"mode": m, "name": MODE_NAMES.get(m, str(m)),
                    "basis": f"prefix:{pref}", "confidence": "high", "candidates": [m]}
    # 3) name-that-hash ranked shortlist
    try:
        from name_that_hash import runner
        token = sample.split(":")[-1] if ":" in sample else sample
        data = json.loads(runner.api_return_hashes_as_json([token]))
        cands = []
        for _h, opts in data.items():
            for o in opts:
                hc = o.get("hashcat")
                if hc is not None and hc not in cands:
                    cands.append(hc)
        if cands:
            m = cands[0]
            return {"mode": m, "name": MODE_NAMES.get(m, str(m)),
                    "basis": "name-that-hash", "confidence": "low (ambiguous - give --provenance)",
                    "candidates": cands[:6]}
    except Exception as e:
        pass
    die("could not identify hash; pass --mode or --provenance")

# ---------- extract (the *2john front-door) ----------
JOHN_RUN = ROOT / "john" / "run"

def hc_identify(token):
    """hashcat 7 native --identify -> candidate modes (deterministic cross-check)."""
    try:
        out = subprocess.run([str(HASHCAT), token, "--identify", "--quiet"],
                             cwd=str(HASHCAT_DIR), capture_output=True, text=True, timeout=60)
        modes = []
        for l in out.stdout.splitlines():
            head = l.strip().split("|")[0].strip()
            if head.isdigit():
                modes.append(int(head))
        return modes
    except Exception:
        return []

def extract(infile, out=None):
    p = Path(infile)
    if not p.exists():
        die(f"file not found: {infile}")
    if p.name in ("shadow", "passwd"):
        die("for Linux creds: john\\run\\unshadow.exe passwd shadow > out.hash, then `identify`.")
    ext = p.suffix.lower()
    if ext in EXTRACTORS:
        tool, kind = EXTRACTORS[ext]
    else:
        # content sniff: SSH/PEM private keys usually have no extension
        head = p.read_text(encoding="utf-8", errors="ignore")[:120] if p.stat().st_size < 1_000_000 else ""
        if "PRIVATE KEY" in head:
            tool, kind = "ssh2john.py", "py"
        else:
            die(f"no extractor for '{ext or 'no-ext'}'. Supported: {sorted(EXTRACTORS)} "
                f"+ SSH keys by content (zip/pdf/7z need perl, which isn't installed).")
    toolpath = JOHN_RUN / tool
    if not toolpath.exists():
        die(f"extractor missing: {toolpath}")
    cmd = ([sys.executable, str(toolpath)] if kind == "py" else [str(toolpath)]) + [str(p.resolve())]
    res = subprocess.run(cmd, cwd=str(JOHN_RUN), capture_output=True, text=True)
    raw_lines = [l for l in res.stdout.splitlines() if l.strip()]
    # *2john prefixes the artifact name ("<file>:$tag$...") -- strip so the hash is hashcat-ready
    cleaned = [ln.split(":", 1)[1] if (":" in ln and ln.split(":", 1)[1].startswith("$")) else ln
               for ln in raw_lines]
    line = chr(10).join(cleaned)
    if not line:
        die(f"{tool} produced no hash. The bundled John is the 2019 build and can't parse some "
            f"modern formats (e.g. new OpenSSH keys). Extract on Kali with current John:\n"
            f"    {tool.replace('.py','').replace('.exe','')} <file> > out.hash\n"
            f"then: scp out.hash here and run `identify`.\n(raw: {res.stderr.strip()[:160]})")
    out = out or str(ROOT / "hashes" / (p.stem + ".hash"))
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(line + "\n", encoding="utf-8")
    info = identify(out)
    return {"hashfile": out, "tool": tool, **info}

# ---------- scope gate ----------
def scope_gate(scope):
    if not scope:
        die("SCOPE GATE: refused. Pass --scope htb|cpts|lab|engagement[:label] "
            "to declare the target is authorized.")
    base = scope.split(":")[0].lower()
    if base not in VALID_SCOPES:
        die(f"SCOPE GATE: '{scope}' is not a valid scope {VALID_SCOPES}")
    return scope.lower()

# ---------- hashcat helpers ----------
def hc_base(mode):
    cmd = [str(HASHCAT), "-m", str(mode), "--backend-ignore-opencl", "-d", "1",
           "--potfile-path", str(CURRENT_POT)]
    if USE_USERNAME:
        cmd.append("--username")
    return cmd

def set_pot_for_scope(scope):
    """Engagement scopes get an isolated potfile so client creds never mix."""
    global CURRENT_POT
    if scope and scope.startswith("engagement"):
        label = scope.split(":", 1)[1] if ":" in scope else "default"
        CURRENT_POT = LOOT / f"pot-{label}.pot"
    else:
        CURRENT_POT = POTFILE
    return CURRENT_POT

def set_username(flag):
    global USE_USERNAME
    USE_USERNAME = bool(flag)

def set_temp_abort(v):
    global TEMP_ABORT
    if v: TEMP_ABORT = int(v)

def _show_lines(mode, hashfile, timeout=120):
    """Run hashcat --show and return ONLY real potfile-match lines.

    hashcat prints parse errors ("Token length exception", the multi-line
    "This error happens..." help, "No hashes loaded") to STDOUT even under
    --quiet. Counting those as cracks caused a false "already in potfile" skip
    and bogus Trophy rows on a malformed/example hash. Filter them out
    structurally: a genuine --show line is the original hash line + ":plain",
    never indented, never a hashcat status/help/error line.
    """
    try:
        out = subprocess.run(hc_base(mode) + [str(Path(hashfile).resolve()), "--show", "--quiet"],
                             cwd=str(HASHCAT_DIR), capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    # If nothing loaded, nothing could have been cracked -- hard guard.
    if "no hashes loaded" in (out.stderr or "").lower():
        return []
    good = []
    for raw in out.stdout.splitlines():
        if not raw.strip():
            continue
        if raw != raw.lstrip():          # indented -> hashcat help continuation
            continue
        low = raw.lower()
        if raw.startswith(("*", "Hashfile ", "Mixing ")):
            continue
        if "exception" in low or "no hashes loaded" in low:
            continue
        if ":" not in raw:               # a real crack line always has hash:plain
            continue
        good.append(raw.rstrip("\n"))
    return good

def hashcat_can_load(mode, hashfile):
    """False if hashcat cannot parse ANY line for this mode (malformed/wrong-type/example hash)."""
    try:
        out = subprocess.run(hc_base(mode) + [str(Path(hashfile).resolve()), "--show", "--quiet"],
                             cwd=str(HASHCAT_DIR), capture_output=True, text=True, timeout=60)
    except Exception:
        return True   # don't block on a probe failure; let the real run decide
    return "no hashes loaded" not in (out.stderr or "").lower()

def count_cracked(mode, hashfile):
    return len(_show_lines(mode, hashfile))

def get_cracked_pairs(mode, hashfile):
    return _show_lines(mode, hashfile)

def get_cracked_userpass(mode, hashfile, username=False):
    pairs = []
    for l in _show_lines(mode, hashfile):
        parts = l.split(":")
        plain = parts[-1]
        user = parts[0] if (username and len(parts) >= 2) else None
        pairs.append((user, plain))
    return pairs

def rule_path(name):
    if (RULES_LOCAL / name).exists():
        return RULES_LOCAL / name
    return RULES_BUNDLED / name

def onerule_name():
    """Prefer the 2023 refresh (deduped, re-ranked); fall back to the original."""
    return "OneRuleToRuleThemStill.rule" if (RULES_LOCAL / "OneRuleToRuleThemStill.rule").exists() \
           else "OneRuleToRuleThemAll.rule"

def fast_rule_name():
    """The cheap first-pass ruleset. best64 if present, else hashcat's bundled best66."""
    for n in ("best64.rule", "best66.rule"):
        if (RULES_LOCAL / n).exists() or (RULES_BUNDLED / n).exists():
            return n
    return "best64.rule"

def weakpass_path():
    """The optional 'medium' corpus. Present only after scripts/fetch-wordlists.ps1."""
    for p in sorted(WORDLISTS.glob("weakpass*")):
        if p.is_file() and p.suffix.lower() in ("", ".txt"):
            return p
    return None

def tool_exe(*names):
    """Find an optional bundled binary (princeprocessor / kwprocessor) if fetched."""
    for n in names:
        for p in TOOLS.rglob(n):
            if p.is_file():
                return p
    return None

def set_learned_for_scope(scope):
    """Engagement scopes learn into an isolated ruleset so client-specific structure
    never bleeds into the shared training ruleset."""
    global CURRENT_LEARNED
    if scope and scope.startswith("engagement"):
        label = scope.split(":", 1)[1] if ":" in scope else "default"
        CURRENT_LEARNED = RULES_LOCAL / f"learned-{label}.rule"
    else:
        CURRENT_LEARNED = RULES_LOCAL / "learned.rule"
    return CURRENT_LEARNED

def learned_ready():
    return CURRENT_LEARNED.exists() and CURRENT_LEARNED.stat().st_size > 0 and \
           any(not l.startswith("#") and l.strip()
               for l in CURRENT_LEARNED.read_text(encoding="utf-8", errors="ignore").splitlines())

def pot_plaintexts():
    """Every plaintext in the current scope's potfile (source for RuleGen)."""
    if not CURRENT_POT.exists():
        return []
    out = []
    for line in CURRENT_POT.read_text(encoding="utf-8", errors="ignore").splitlines():
        if ":" in line:
            out.append(line.split(":")[-1])
    return out

def refresh_learned(scope, redact):
    """RuleGen strange-loop: re-mine the learned ruleset from this scope's cracks."""
    try:
        set_learned_for_scope(scope)
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import rulegen
        plains = pot_plaintexts()
        if not plains:
            return 0
        engagement = scope.startswith("engagement")
        n = rulegen.write_learned(plains, CURRENT_LEARNED,
                                  log_file=None if engagement else LEARNED_LOG,
                                  redact=redact or engagement)
        if n:
            print(f"[learn] mined {n} rule(s) from {len(plains)} crack(s) -> {CURRENT_LEARNED.name}")
        return n
    except Exception as e:
        print(f"[learn] skipped ({e})")
        return 0

def build_username_wordlist(hashfile):
    """Deduped list of the account usernames, used as a straight -a 0 dictionary
    (+ rules). Catches password == username AND cross-user reuse (one account's
    name is another's password), and -- unlike -a 9 association -- it writes to the
    potfile so downstream --show accounting sees the cracks. Tiny keyspace.
    Returns the wordlist path, or None when there are no usernames."""
    if not USE_USERNAME:
        return None
    seen, users = set(), []
    for line in read_hash_lines(hashfile):
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user = parts[0].split("\\")[-1].strip()
        if user and user.lower() not in seen:
            seen.add(user.lower()); users.append(user)
    if not users:
        return None
    fp = LOOT / "_usernames.txt"
    fp.write_text("\n".join(users) + "\n", encoding="utf-8")
    return fp

# ---------- keyspace / ETA estimation ----------
def _parse_hs(text):
    """Pull the first 'NNN.N kH/s|MH/s|GH/s|H/s' speed out of hashcat -b output."""
    import re
    m = re.search(r"([\d.]+)\s*([kMGT]?)H/s", text)
    if not m:
        return None
    val = float(m.group(1)); unit = m.group(2)
    return val * {"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[unit]

def bench_speed(mode):
    """Benchmarked H/s for a mode, cached to loot/benchmarks.json (lazy, one-time)."""
    cache = {}
    if BENCH_CACHE.exists():
        try: cache = json.loads(BENCH_CACHE.read_text(encoding="utf-8"))
        except Exception: cache = {}
    if str(mode) in cache:
        return cache[str(mode)]
    try:
        out = subprocess.run([str(HASHCAT), "-b", "-m", str(mode), "--backend-ignore-opencl",
                              "-d", "1", "--quiet"], cwd=str(HASHCAT_DIR),
                             capture_output=True, text=True, timeout=180)
        hs = _parse_hs(out.stdout)
        if hs:
            cache[str(mode)] = hs
            BENCH_CACHE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        return hs
    except Exception:
        return None

def hc_keyspace(mode, attack):
    """hashcat --keyspace for a given attack; multiply by rule count for -r rungs."""
    try:
        argv = [str(HASHCAT), "-m", str(mode), "--backend-ignore-opencl", "-d", "1",
                "--quiet", "--keyspace"] + attack
        out = subprocess.run(argv, cwd=str(HASHCAT_DIR), capture_output=True, text=True, timeout=120)
        base = None
        for l in out.stdout.splitlines():
            if l.strip().isdigit():
                base = int(l.strip())
        if base is None:
            return None
        # --keyspace returns the wordlist count; rules apply on top -> multiply
        if "-r" in attack:
            rf = Path(attack[attack.index("-r") + 1])
            if rf.exists():
                rc = sum(1 for l in rf.read_text(encoding="utf-8", errors="ignore").splitlines()
                         if l.strip() and not l.startswith("#"))
                base *= max(rc, 1)
        return base
    except Exception:
        return None

def eta_seconds(mode, attack):
    ks = hc_keyspace(mode, attack)
    sp = bench_speed(mode)
    if not ks or not sp:
        return None
    return ks / sp

def fmt_eta(secs):
    if secs is None:
        return "eta unknown"
    if secs < 90:      return f"~{int(secs)}s"
    if secs < 5400:    return f"~{secs/60:.0f}m"
    if secs < 172800:  return f"~{secs/3600:.1f}h"
    return f"~{secs/86400:.1f}d"

def attack_temp_flags():
    return ["--hwmon-temp-abort", str(TEMP_ABORT)]

# ---------- ladder ----------
def build_ladder(mode, targeted, allow_bruteforce, assoc=None):
    slow = mode in SLOW_MODES
    onerule = str(rule_path(onerule_name()))
    have_targeted = bool(targeted and Path(targeted).exists())
    tgt = str(Path(targeted).resolve()) if have_targeted else None
    D = ["-a", "0", "-O", "-w", "3"]     # straight-dictionary prefix
    L = []

    # usernames as a dictionary + rules. Tiny keyspace, huge signal (password ==
    # username, User2024!, cross-user reuse). Runs even on slow modes.
    if assoc:
        L.append(("usernames+rules", ["-a", "0", "-O", "-w", "3", str(assoc),
                                      "-r", str(rule_path(fast_rule_name()))]))
    if have_targeted:
        L.append(("targeted-straight", D + [tgt]))
    L.append(("rockyou-straight", D + [str(ROCKYOU)]))

    if slow:
        # slow/salted (bcrypt, sha512crypt, DCC2, WPA...) -> only cheap rungs
        if have_targeted:
            L.append(("targeted+clem-small", D + [tgt, "-r", str(rule_path("clem9669_small.rule"))]))
        L.append(("rockyou+clem-small", D + [str(ROCKYOU), "-r", str(rule_path("clem9669_small.rule"))]))
        if learned_ready():
            L.append(("rockyou+learned", D + [str(ROCKYOU), "-r", str(CURRENT_LEARNED)]))
        return L

    # fast modes -> full ladder, cheap/high-yield first
    L.append(("rockyou+best64", D + [str(ROCKYOU), "-r", str(rule_path(fast_rule_name()))]))
    if learned_ready():
        L.append(("rockyou+learned", D + [str(ROCKYOU), "-r", str(CURRENT_LEARNED)]))
    L.append(("rockyou+OneRule", D + [str(ROCKYOU), "-r", onerule]))
    if have_targeted:
        L.append(("targeted+OneRule", D + [tgt, "-r", onerule]))
        if learned_ready():
            L.append(("targeted+learned", D + [tgt, "-r", str(CURRENT_LEARNED)]))
    wp = weakpass_path()
    if wp:
        L.append(("weakpass+OneRule", D + [str(wp), "-r", onerule]))
    L.append(("rockyou+clem-medium", D + [str(ROCKYOU), "-r", str(rule_path("clem9669_medium.rule"))]))
    # hybrid: the "Summer2024" / "Summer2024!" majority that plain rules miss
    L.append(("rockyou+hybrid-year", ["-a", "6", "-O", "-w", "3", str(ROCKYOU), "?d?d?d?d"]))
    L.append(("rockyou+hybrid-year-bang", ["-a", "6", "-O", "-w", "3", str(ROCKYOU), "?d?d?d?d?s"]))
    keywalks = WORDLISTS / "keywalks.txt"
    if keywalks.exists():
        L.append(("keywalks-straight", D + [str(keywalks)]))
    # PRINCE (chained-word / passphrase coverage): gated -- keyspace explodes
    pp = tool_exe("pp64.exe", "pp64.bin", "princeprocessor.exe")
    if pp and allow_bruteforce:
        L.append(("prince-rockyou", ["__PRINCE__", str(pp), str(ROCKYOU)]))
    if allow_bruteforce:
        L.append(("mask-1to8-all", ["-a", "3", "-O", "-w", "3", "-i", "?a?a?a?a?a?a?a?a"]))
    return L

def run_rung(name, attack, mode, hashfile, remaining, session):
    """Execute one ladder rung within `remaining` seconds. Returns elapsed seconds.
    Handles straight/rule/hybrid/mask rungs and the piped PRINCE generator rung."""
    hf = str(Path(hashfile).resolve())
    R = str(int(remaining))
    t0 = time.time()
    if attack and attack[0] == "__PRINCE__":              # pp64 <wordlist> | hashcat -a 0 (stdin)
        pp, wl = attack[1], attack[2]
        gen = subprocess.Popen([pp, wl], stdout=subprocess.PIPE, cwd=str(HASHCAT_DIR))
        argv = hc_base(mode) + [hf, "-a", "0", "-O", "-w", "3",
                "--runtime", R, "--session", f"{session}-{name}"] + attack_temp_flags()
        subprocess.run(argv, stdin=gen.stdout, cwd=str(HASHCAT_DIR))
        if gen.stdout: gen.stdout.close()
        gen.terminate()
        return time.time() - t0
    argv = hc_base(mode) + [hf] + attack + \
           ["--runtime", R, "--session", f"{session}-{name}"] + attack_temp_flags()
    subprocess.run(argv, cwd=str(HASHCAT_DIR))
    return time.time() - t0


def run_auto(hashfile, mode, mode_name, scope, cap, targeted, allow_bruteforce,
             context, redact, session):
    set_pot_for_scope(scope)
    set_learned_for_scope(scope)
    total = len(read_hash_lines(hashfile))
    if not hashcat_can_load(mode, hashfile):
        print(f"[!] hashcat cannot load any hash from {hashfile} as mode {mode} ({mode_name}).")
        print("    Likely causes: malformed/example hash, wrong mode, or a shadow line whose "
              "digest length is invalid.")
        print("    Nothing logged. Re-check the source line or run `route`/`identify` on it.")
        return
    already = count_cracked(mode, hashfile)
    print(f"[*] {mode_name} (mode {mode}) | {total} hash(es) | {already} already cracked "
          f"| scope={scope} | cap={cap}s | brute={'ON' if allow_bruteforce else 'off (gated)'}")
    if already >= total:
        print("[+] all hashes already in potfile -- nothing to do.")
        _finish(hashfile, mode, mode_name, scope, context, redact, "potfile", 0.0)
        return
    assoc = build_username_wordlist(hashfile)
    ladder = build_ladder(mode, targeted, allow_bruteforce, assoc)
    if not ladder:
        die("empty ladder (slow hash with no viable rungs) -- run manual with a chosen wordlist")
    elapsed = 0.0
    for name, attack in ladder:
        remaining = cap - elapsed
        if remaining <= 5:
            print(f"[!] cap reached ({cap}s) -- stopping before rung '{name}'."); break
        # keyspace ETA advisory (esp. for mask rungs) -- honest about coverage
        eta = None if attack and attack[0] == "__PRINCE__" else eta_seconds(mode, attack)
        note = ""
        if eta is not None:
            if attack[0] == "-a" and "3" in attack[:2] and eta > remaining:
                note = f"  [full keyspace {fmt_eta(eta)} > cap; runs incrementally, catches short pw]"
            else:
                note = f"  [full pass {fmt_eta(eta)}]"
        print(f"[>] rung: {name}  (<= {int(remaining)}s){note}")
        try:
            dt = run_rung(name, attack, mode, hashfile, remaining, session)
        except KeyboardInterrupt:
            print("[!] interrupted."); break
        elapsed += dt
        cracked = count_cracked(mode, hashfile)
        print(f"    -> {cracked}/{total} cracked (elapsed {int(elapsed)}s)")
        if cracked >= total:
            print("[+] ALL cracked.")
            _finish(hashfile, mode, mode_name, scope, context, redact, name, dt)
            return
    # cracked-feedback pass: reused/derived passwords elsewhere in the same dump
    cracked_now = count_cracked(mode, hashfile)
    if 0 < cracked_now < total and (cap - elapsed) > 5 and mode not in SLOW_MODES:
        plains = sorted({p.split(":")[-1] for p in get_cracked_pairs(mode, hashfile)})
        if plains:
            fb = LOOT / "_feedback.txt"
            fb.write_text("\n".join(plains) + "\n", encoding="utf-8")
            print(f"[>] rung: cracked-feedback ({len(plains)} plaintexts + OneRule)")
            argv = hc_base(mode) + [str(Path(hashfile).resolve()), "-a", "0", "-O", "-w", "3",
                   str(fb), "-r", str(rule_path(onerule_name())),
                   "--runtime", str(int(cap - elapsed)), "--session", f"{session}-feedback"] + attack_temp_flags()
            t0 = time.time(); subprocess.run(argv, cwd=str(HASHCAT_DIR)); elapsed += time.time() - t0
            c2 = count_cracked(mode, hashfile)
            print(f"    -> {c2}/{total} cracked (elapsed {int(elapsed)}s)")
            if c2 >= total:
                print("[+] ALL cracked (via feedback).")
                _finish(hashfile, mode, mode_name, scope, context, redact, "cracked-feedback", elapsed)
                return

    # partial / exhausted
    cracked = count_cracked(mode, hashfile)
    if cracked > 0:
        _finish(hashfile, mode, mode_name, scope, context, redact, "partial", elapsed)
    print(f"[=] done. {cracked}/{total} cracked. "
          f"{'Recommend: longer cap, bigger wordlist, or --allow-bruteforce.' if cracked<total else ''}")

def classify_pattern(pw):
    import re
    core = re.sub(r"[^A-Za-z0-9]+$", "", pw)          # strip trailing specials first
    had_special = core != pw
    label = "Word" if pw[:1].isalpha() else "Mixed"
    if re.search(r"(19|20)\d{2}$", core): label += "+Year"
    elif re.search(r"\d+$", core):        label += "+Digits"
    if had_special:                       label += "+Special"
    return label

def _finish(hashfile, mode, mode_name, scope, context, redact, winning_rung, secs):
    engagement = scope.startswith("engagement")
    redact = redact or engagement
    pairs = get_cracked_pairs(mode, hashfile)
    for pair in pairs:
        plain = pair.split(":")[-1]
        entry = {
            "ts": now_iso(), "mode": mode, "mode_name": mode_name,
            "context": context or "", "scope": scope,
            "winning_rung": winning_rung, "seconds": round(secs, 1),
            "pattern": classify_pattern(plain),
            "plaintext": "[redacted]" if redact else plain,
        }
        JOBS.mkdir(parents=True, exist_ok=True)
        with open(TROPHY, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    print(f"[T] logged {len(pairs)} trophy row(s) -> {TROPHY.name}"
          f"{' (redacted)' if redact else ''}")
    refresh_learned(scope, redact)     # strange-loop: wins rewrite the next run's ruleset

# ---------- john bridge (formats hashcat has no -m for: RIPEMD, exotic dynamic) ----------
JOHN_EXE = JOHN_RUN / "john.exe"

def john_pot_for_scope(scope):
    """Engagement scopes get an isolated john pot so client creds never mix."""
    if scope and scope.startswith("engagement"):
        label = scope.split(":", 1)[1] if ":" in scope else "default"
        return LOOT / f"john-{label}.pot"
    return JOHN_RUN / "john.pot"

def john_show(fmt, hashfile, potpath):
    """Parse `john --show` -> list of (user_or_None, plaintext)."""
    out = subprocess.run([str(JOHN_EXE), f"--format={fmt}", f"--pot={potpath}",
                          "--show", str(Path(hashfile).resolve())],
                         cwd=str(JOHN_RUN), capture_output=True, text=True)
    pairs = []
    for l in out.stdout.splitlines():
        if not l.strip() or "password hash" in l:   # skip blank + summary line
            continue
        if ":" in l:
            login, plain = l.split(":", 1)
            user = login if (login and login != "?") else None
            pairs.append((user, plain))
    return pairs

def _finish_john(hashfile, fmt, scope, context, redact, secs):
    """Write john cracks to the Trophy log (same memory surface as hashcat wins)."""
    engagement = scope.startswith("engagement")
    redact = redact or engagement
    potpath = john_pot_for_scope(scope)
    pairs = john_show(fmt, hashfile, potpath)
    mode_name = f"john:{fmt}"
    JOBS.mkdir(parents=True, exist_ok=True)
    for user, plain in pairs:
        entry = {
            "ts": now_iso(), "mode": mode_name, "mode_name": mode_name,
            "context": context or "", "scope": scope,
            "winning_rung": "john-manual", "seconds": round(secs, 1),
            "pattern": classify_pattern(plain),
            "plaintext": "[redacted]" if redact else plain,
        }
        if user:
            entry["user"] = "[redacted]" if redact else user
        with open(TROPHY, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    print(f"[T] logged {len(pairs)} trophy row(s) -> {TROPHY.name}"
          f"{' (redacted)' if redact else ''}")
    return len(pairs)

def run_johncrack(hashfile, scope, fmt, wordlist, rules, cap, fork, context, redact):
    """Governed John run: scope-gated, time-capped, Trophy-logged. Use for hashes
    hashcat has no mode for (RIPEMD-128/256/320, exotic dynamic formats)."""
    if not JOHN_EXE.exists():
        die(f"john not found at {JOHN_EXE}")
    hpath = Path(hashfile).resolve()
    if not hpath.exists():
        die(f"hash file not found: {hashfile}")
    wl = Path(wordlist).resolve()
    if not wl.exists():
        die(f"wordlist not found: {wl}")
    potpath = john_pot_for_scope(scope)
    total = len(read_hash_lines(hashfile))
    cmd = [str(JOHN_EXE), f"--format={fmt}", f"--pot={potpath}",
           f"--wordlist={wl}", f"--max-run-time={cap}"]
    if rules:
        cmd.append(f"--rules={rules}")   # NOTE: john rule SECTION name, not a hashcat .rule file
    if fork and fork > 1:
        cmd.append(f"--fork={fork}")
    cmd.append(str(hpath))
    print(f"[johncrack] {fmt} | {total} hash(es) | cap={cap}s"
          f"{' | rules=' + rules if rules else ''}"
          f"{' | fork=' + str(fork) if fork and fork > 1 else ''}")
    t0 = time.time()
    subprocess.run(cmd, cwd=str(JOHN_RUN))
    elapsed = time.time() - t0
    n = _finish_john(hashfile, fmt, scope, context, redact, elapsed)
    print(f"[=] {n}/{total} cracked via john ({int(elapsed)}s).")
    if n == 0:
        print("[i] no cracks. Next: bigger wordlist, add --rules Jumbo, "
              "or confirm --format with `john --list=formats`.")

# ---------- route: deterministic hashcat-vs-john decision ----------
def has_optimized_kernel(mode):
    """True if hashcat ships an optimized kernel for this mode (else pure-only = slow)."""
    d = HASHCAT_DIR / "OpenCL"
    if not d.exists():
        return None
    hits = list(d.glob(f"m{int(mode):05d}*optimized*.cl"))
    return len(hits) > 0

def route(hashfile, provenance=None):
    """Recommend hashcat or john from rig facts: optimized-kernel presence, hash count, mode."""
    lines = read_hash_lines(hashfile)
    n = len(lines)
    try:
        info = identify(hashfile, provenance)
        mode = info['mode']; basis = info['basis']
    except SystemExit:
        info = None; mode = None; basis = 'unidentified'
    opt = has_optimized_kernel(mode) if mode is not None else None
    jf = MODE_TO_JOHN.get(mode) if mode is not None else None
    reasons = []
    SMALL = 10
    if mode is None:
        engine = 'john'
        reasons.append('hashcat could not identify a mode; john auto-detects more formats')
    elif opt is False and n <= SMALL:
        engine = 'john'
        reasons.append(f'mode {mode} has NO optimized hashcat kernel (pure only)')
        reasons.append(f'only {n} hash(es): hashcat kernel-compile + self-test init loses to john CPU to first result')
    elif opt is False and n > SMALL:
        engine = 'hashcat'
        reasons.append(f'mode {mode} is pure-kernel-only but {n} hashes amortize init; GPU across salts wins')
    else:
        engine = 'hashcat'
        reasons.append(f'mode {mode} has an optimized GPU kernel; throughput dominates')
    name = MODE_NAMES.get(mode, str(mode)) if mode is not None else '?'
    print(f'[route] {name} (mode {mode}) | {n} hash(es) | basis={basis}')
    print(f'[route] optimized hashcat kernel: {opt}')
    print(f'[route] >>> RECOMMEND: {engine.upper()}')
    for r in reasons:
        print(f'          - {r}')
    hf = str(Path(hashfile).resolve())
    if engine == 'hashcat':
        md = mode if mode is not None else '<mode>'
        print(f'[route] run: python core/cracklab.py auto {hf} --scope htb --mode {md}')
        print(f'             (or manual ... --mode {md} --wordlist wordlists/rockyou.txt --rules OneRuleToRuleThemStill.rule)')
    else:
        fmt = jf or '<john-format>'
        note = '' if jf else '   # set --format via: john --list=formats'
        print(f'[route] run: python core/cracklab.py johncrack {hf} --scope htb --format {fmt} --wordlist wordlists/rockyou.txt{note}')
    return {'engine': engine, 'mode': mode, 'john_format': jf, 'n': n, 'optimized_kernel': opt}

# ---------- detach / status ----------
def spawn_detached(args_list, session):
    JOBS.mkdir(parents=True, exist_ok=True)
    logf = LOOT / f"{session}.log"
    rec = JOBS / f"{session}.json"
    log = open(logf, "w", encoding="utf-8")
    DETACHED = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    p = subprocess.Popen([sys.executable, str(Path(__file__).resolve())] + args_list,
                         stdout=log, stderr=subprocess.STDOUT, cwd=str(ROOT),
                         creationflags=DETACHED, close_fds=True)
    rec.write_text(json.dumps({"session": session, "pid": p.pid, "started": now_iso(),
                               "log": str(logf), "args": args_list}, indent=2), encoding="utf-8")
    print(f"[job] detached '{session}' pid={p.pid}. It survives SSH disconnect.")
    print(f"      log: {logf}")
    print(f"      check: python cracklab.py status")

def cmd_status():
    if not JOBS.exists() or not any(JOBS.glob("*.json")):
        print("no jobs recorded."); return
    for rec in sorted(JOBS.glob("*.json")):
        j = json.loads(rec.read_text(encoding="utf-8"))
        pid, sess = j.get("pid"), j.get("session")
        alive = False
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
            alive = str(pid) in out.stdout
        except Exception:
            pass
        tail = ""
        lp = Path(j.get("log", ""))
        if lp.exists():
            tail = lp.read_text(encoding="utf-8", errors="ignore").splitlines()[-1:] or [""]
            tail = tail[0]
        print(f"[{sess}] pid={pid} {'RUNNING' if alive else 'finished'} | {tail}")

def cmd_trophies(context=None):
    if not TROPHY.exists():
        print("no trophies yet."); return
    rows = [json.loads(l) for l in TROPHY.read_text(encoding="utf-8").splitlines() if l.strip()]
    if context:
        rows = [r for r in rows if r.get("context") == context]
    print(f"{len(rows)} trophy row(s){' for context=' + context if context else ''}:")
    from collections import Counter
    by_rung = Counter(r["winning_rung"] for r in rows)
    by_pat = Counter(r["pattern"] for r in rows)
    for r in rows[-15:]:
        print(f"  {r['ts']} m{r['mode']} {r['mode_name']:<16} rung={r['winning_rung']:<16} "
              f"pat={r['pattern']:<16} {r['plaintext']}")
    print("  --- winning rungs:", dict(by_rung))
    print("  --- patterns    :", dict(by_pat))

# ---------- CLI ----------
def main():
    # forge is delegated verbatim to forge.py -- bypass argparse so its --flags pass through
    if len(sys.argv) >= 2 and sys.argv[1] == "forge":
        forge_py = Path(__file__).resolve().parent / "forge.py"
        sys.exit(subprocess.call([sys.executable, str(forge_py)] + sys.argv[2:]))

    ap = argparse.ArgumentParser(prog="cracklab", description="Deterministic cracking core")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("identify"); pi.add_argument("hashfile"); pi.add_argument("--provenance")

    pe = sub.add_parser("extract"); pe.add_argument("infile"); pe.add_argument("--out")

    pf = sub.add_parser("forge")  # delegate to forge.py
    pf.add_argument("rest", nargs=argparse.REMAINDER)

    pa = sub.add_parser("auto")
    pa.add_argument("hashfile"); pa.add_argument("--scope", required=True)
    pa.add_argument("--provenance"); pa.add_argument("--mode", type=int)
    pa.add_argument("--cap", type=int, default=1800)
    pa.add_argument("--targeted"); pa.add_argument("--context")
    pa.add_argument("--allow-bruteforce", action="store_true")
    pa.add_argument("--redact", action="store_true")
    pa.add_argument("--username", action="store_true", help="input is user:hash")
    pa.add_argument("--session", default=None)
    pa.add_argument("--detach", action="store_true")
    pa.add_argument("--temp-abort", type=int, default=90, help="GPU temp (C) to abort a rung")

    pm = sub.add_parser("manual")
    pm.add_argument("hashfile"); pm.add_argument("--scope", required=True)
    pm.add_argument("--mode", type=int, required=True)
    pm.add_argument("--wordlist", required=True); pm.add_argument("--rules")
    pm.add_argument("--cap", type=int, default=1800); pm.add_argument("--context")
    pm.add_argument("--redact", action="store_true")
    pm.add_argument("--username", action="store_true", help="input is user:hash")
    pm.add_argument("--temp-abort", type=int, default=90, help="GPU temp (C) to abort")

    pj = sub.add_parser("johncrack",
        help="crack with John (formats hashcat has no -m for: RIPEMD, exotic dynamic)")
    pj.add_argument("hashfile"); pj.add_argument("--scope", required=True)
    pj.add_argument("--format", required=True, dest="jformat",
                    help="john format e.g. ripemd-128 (see: john --list=formats)")
    pj.add_argument("--wordlist", default=str(ROCKYOU))
    pj.add_argument("--rules", help="john rule SECTION (Single|Wordlist|Jumbo|KoreLogic), not a .rule file")
    pj.add_argument("--cap", type=int, default=1800)
    pj.add_argument("--fork", type=int, default=0, help="CPU fork count (physical cores)")
    pj.add_argument("--context"); pj.add_argument("--redact", action="store_true")

    prt = sub.add_parser("route",
        help="recommend hashcat vs john for a hash (deterministic, no cracking)")
    prt.add_argument("hashfile"); prt.add_argument("--provenance")

    sub.add_parser("status")
    pt = sub.add_parser("trophies"); pt.add_argument("--context")

    pes = sub.add_parser("estimate")   # ladder ETA before committing GPU-hours
    pes.add_argument("hashfile"); pes.add_argument("--mode", type=int, required=True)
    pes.add_argument("--targeted"); pes.add_argument("--allow-bruteforce", action="store_true")
    pes.add_argument("--username", action="store_true")

    pl = sub.add_parser("learn")       # (re)mine learned.rule from cracked plaintexts
    pl.add_argument("--scope", required=True); pl.add_argument("--redact", action="store_true")
    pl.add_argument("--show", action="store_true", help="print the mined rules")

    ph = sub.add_parser("hibp")        # compare NT hashes vs HIBP (no cracking)
    ph.add_argument("hashfile"); ph.add_argument("--scope"); ph.add_argument("--context")
    ph.add_argument("--file", help="HIBP NTLM file (default loot/hibp/pwned-ntlm.txt)")
    ph.add_argument("--out")

    ptr = sub.add_parser("triage")     # abuse-don't-crack scanner + crackable subset
    ptr.add_argument("hashfile"); ptr.add_argument("--out", help="write crack-worthy lines here")

    pr = sub.add_parser("report")
    pr.add_argument("hashfile"); pr.add_argument("--mode", type=int, required=True)
    pr.add_argument("--scope"); pr.add_argument("--context")
    pr.add_argument("--username", action="store_true"); pr.add_argument("--out")

    pk = sub.add_parser("masks")
    pk.add_argument("hashfile"); pk.add_argument("--mode", type=int, required=True)
    pk.add_argument("--scope"); pk.add_argument("--top", type=int, default=25); pk.add_argument("--out")
    pk.add_argument("--username", action="store_true", help="input is user:hash")

    a = ap.parse_args()

    if a.cmd == "identify":
        r = identify(a.hashfile, a.provenance)
        print(json.dumps(r, indent=2)); return

    if a.cmd == "extract":
        r = extract(a.infile, a.out)
        print(json.dumps(r, indent=2))
        print(f"\n[+] crack it: python core/cracklab.py auto {r['hashfile']} --scope htb --mode {r['mode']}")
        return

    if a.cmd == "forge":
        forge_py = Path(__file__).resolve().parent / "forge.py"
        sys.exit(subprocess.call([sys.executable, str(forge_py)] + a.rest))

    if a.cmd == "status":
        cmd_status(); return
    if a.cmd == "trophies":
        cmd_trophies(a.context); return

    if a.cmd == "report":
        import analysis
        if a.scope: set_pot_for_scope(scope_gate(a.scope))
        set_username(a.username)
        total = len(read_hash_lines(a.hashfile))
        pairs = get_cracked_userpass(a.mode, a.hashfile, a.username)
        md = analysis.report_markdown(MODE_NAMES.get(a.mode, str(a.mode)), total, pairs, a.context or "")
        out = a.out or str(LOOT / f"report-{datetime.now().strftime('%m%d-%H%M%S')}.md")
        Path(out).write_text(md, encoding="utf-8")
        print(md); print(f"\n[+] saved -> {out}")
        return

    if a.cmd == "masks":
        import analysis
        if a.scope: set_pot_for_scope(scope_gate(a.scope))
        set_username(a.username)
        plains = [pw for _u, pw in get_cracked_userpass(a.mode, a.hashfile, a.username)]
        if not plains:
            die("no cracked passwords in potfile yet -- crack something first")
        masks = analysis.masks_from_cracked(plains, a.top)
        out = a.out or str(WORDLISTS / "from-cracked.hcmask")
        Path(out).write_text("\n".join(m for m, _c in masks) + "\n", encoding="utf-8")
        for m, c in masks:
            print(f"{c:>5}  {m}")
        print(f"[+] {len(masks)} masks -> {out}")
        print(f"    next: hc -m {a.mode} <hashfile> -a 3 {out}")
        return

    if a.cmd == "triage":
        import triage as tri
        t = tri.triage(a.hashfile)
        print(tri.report_text(t))
        if a.out:
            tri.write_crackable(t, a.out)
            print(f"[+] {t['summary']['crackable']} crack-worthy line(s) -> {a.out} "
                  f"(machine/krbtgt stripped)")
        return

    if a.cmd == "hibp":
        import hibp
        if a.scope: set_pot_for_scope(scope_gate(a.scope))
        hfile = a.file or str(LOOT / "hibp" / "pwned-ntlm.txt")
        if not Path(hfile).exists():
            die(f"HIBP file not found: {hfile}\n"
                f"Fetch it once with: powershell -File scripts\\fetch-hibp.ps1")
        targets = hibp.load_targets(a.hashfile)
        if not targets:
            die("no NT hashes found in input (expects NTDS or user:nthash lines)")
        print(f"[hibp] {sum(len(u) for u in targets.values())} account(s), "
              f"{len(targets)} unique hash(es) -> scanning HIBP corpus...")
        hits = hibp.scan(hfile, targets)
        md = hibp.report_markdown(targets, hits, a.context or "")
        out = a.out or str(LOOT / f"hibp-{datetime.now().strftime('%m%d-%H%M%S')}.md")
        Path(out).write_text(md, encoding="utf-8")
        print(md); print(f"\n[+] saved -> {out}")
        return

    if a.cmd == "learn":
        scope = scope_gate(a.scope)
        set_pot_for_scope(scope)
        n = refresh_learned(scope, a.redact)
        if n == 0:
            print("[learn] nothing mined yet -- crack some passwords first.")
        elif a.show and CURRENT_LEARNED.exists():
            print(CURRENT_LEARNED.read_text(encoding="utf-8"))
        return

    if a.cmd == "estimate":
        set_username(a.username)
        set_learned_for_scope("lab")
        assoc = build_username_wordlist(a.hashfile) if a.username else None
        ladder = build_ladder(a.mode, a.targeted, a.allow_bruteforce, assoc)
        sp = bench_speed(a.mode)
        print(f"[estimate] mode {a.mode} ({MODE_NAMES.get(a.mode, a.mode)}) | "
              f"GPU {fmt_eta(1) if sp is None else f'{sp/1e9:.2f} GH/s' if sp>=1e9 else f'{sp/1e6:.1f} MH/s'}")
        for name, attack in ladder:
            if attack and attack[0] == "__PRINCE__":
                print(f"  {name:<26} PRINCE generator (unbounded -- time-boxed)")
                continue
            print(f"  {name:<26} full pass {fmt_eta(eta_seconds(a.mode, attack))}")
        print("  (rungs run cheapest-first within your --cap; slow rungs are trimmed for salted modes)")
        return

    if a.cmd == "auto":
        scope = scope_gate(a.scope)
        set_username(a.username)
        set_temp_abort(a.temp_abort)
        mode = a.mode
        if mode is None:
            info = identify(a.hashfile, a.provenance)
            mode = info["mode"]
            print(f"[id] {info['name']} (mode {mode}) via {info['basis']} [{info['confidence']}]")
        mode_name = MODE_NAMES.get(mode, str(mode))
        session = a.session or f"job-{datetime.now().strftime('%m%d-%H%M%S')}"
        if a.detach:
            fwd = ["auto", str(Path(a.hashfile).resolve()), "--scope", scope, "--mode", str(mode),
                   "--cap", str(a.cap), "--session", session, "--temp-abort", str(a.temp_abort)]
            if a.targeted: fwd += ["--targeted", str(Path(a.targeted).resolve())]
            if a.context: fwd += ["--context", a.context]
            if a.allow_bruteforce: fwd += ["--allow-bruteforce"]
            if a.redact: fwd += ["--redact"]
            if a.username: fwd += ["--username"]
            spawn_detached(fwd, session); return
        run_auto(a.hashfile, mode, mode_name, scope, a.cap, a.targeted,
                 a.allow_bruteforce, a.context, a.redact, session)
        return

    if a.cmd == "manual":
        scope = scope_gate(a.scope)
        set_username(a.username)
        set_temp_abort(a.temp_abort)
        set_pot_for_scope(scope)
        set_learned_for_scope(scope)
        mode_name = MODE_NAMES.get(a.mode, str(a.mode))
        total = len(read_hash_lines(a.hashfile))
        attack = ["-a", "0", "-O", "-w", "3", str(Path(a.wordlist).resolve())]
        if a.rules: attack += ["-r", str(rule_path(a.rules))]
        argv = hc_base(a.mode) + [str(Path(a.hashfile).resolve())] + attack + \
               ["--runtime", str(a.cap), "--session", f"manual-{datetime.now().strftime('%m%d-%H%M%S')}"] + attack_temp_flags()
        print(f"[manual] {mode_name} | {total} hash(es) | cap={a.cap}s")
        t0 = time.time()
        subprocess.run(argv, cwd=str(HASHCAT_DIR))
        elapsed = time.time() - t0
        cracked = count_cracked(a.mode, a.hashfile)
        print(f"[=] {cracked}/{total} cracked in {int(elapsed)}s.")
        if cracked > 0:
            _finish(a.hashfile, a.mode, mode_name, scope, a.context, a.redact, "manual", elapsed)
        return

    if a.cmd == "johncrack":
        scope = scope_gate(a.scope)
        set_pot_for_scope(scope)
        run_johncrack(a.hashfile, scope, a.jformat, a.wordlist, a.rules,
                      a.cap, a.fork, a.context, a.redact)
        return

    if a.cmd == "route":
        route(a.hashfile, a.provenance)
        return

if __name__ == "__main__":
    main()
