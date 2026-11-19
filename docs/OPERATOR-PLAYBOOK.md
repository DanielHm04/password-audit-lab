# CrackLab Operator Playbook

Load this before choosing Strategy. It's the researched, decision-first cheat sheet that sits
on top of `CLAUDE.md` (the contract) and `CONTEXT.md` (the language). Sources: web research
Aug 2026 (hashcat wiki/forums, In.security, TrustedSec, HackTricks, HTB/CPTS writeups, TCM).

## 0. Reflexes (learned from real sessions)
- **Execute, don't narrate.** Daniel can run commands himself. Adapt his command to the rig and RUN it. One discovery pass, not a staircase.
- **Scope comes first.** Work only on lab targets or engagements with written authorization; the core refuses to run without `--scope`.
- **Batch discovery**: locate binary + wordlist + mode in ONE command.
- **Lead with the result**: plaintext + which rung/tool won + time.
- **Known paths**: `./john/run/john.exe`, `wordlists/rockyou.txt` (14.3M).

## 1. Identify (provenance-first)
1. **Provenance beats every guesser.** secretsdump→1000, shadow `$6$`→1800, kerberoast `$krb5tgs$`→13100, etc. (`PROVENANCE`/`PREFIX` maps in core).
2. If unknown: `python core/cracklab.py identify <hf> --provenance <src>`. Core uses name-that-hash as the low-confidence fallback.
3. `hashid` is dead (unmaintained since 2015). If installing an identifier, prefer **haiti** (gives both john format AND hashcat `-m`).

## 2. hashcat vs john — DON'T GUESS, run `route`
`python core/cracklab.py route <hashfile> [--provenance <p>]` decides deterministically and prints the command. The rule it encodes (so you understand it):
- **No optimized hashcat kernel** for the mode (check: `hashcat/OpenCL/m<MODE>*optimized*.cl` missing) — true for **bcrypt(3200), Office(9600), KeePass(13400), BitLocker(22100), SSH(22921)** — AND **≤10 hashes** → **john**. hashcat's kernel-compile + self-test init loses to john's CPU to first result, and its pure-kernel fallback is slow. (This is the exact call I blew on Office and BitLocker.)
- **Optimized kernel exists** (MD5/SHA1/NTLM/sha512crypt) → **hashcat** (GPU throughput dominates).
- **Pure-only mode but many hashes (>10)** → **hashcat** — init amortizes, GPU parallelism across salts wins.
- **hashcat has NO `-m` at all** (RIPEMD-128/256/320, exotic `dynamic=...`) → **john** (only option).
- john also auto-detects format (no `--mode` step) and eats the `*2john` `filename:` prefix natively.
Engines: hashcat → `auto`/`manual`; john → `johncrack`.
  - `python core/cracklab.py johncrack <hf> --scope htb --format ripemd-128 [--rules Jumbo] [--fork <cores>]`
  - Scope-gated, time-capped, Trophy-logged — do NOT run raw `john.exe` anymore; the bridge keeps the learning loop intact.
  - `--rules` here is a john **section name** (Single|Wordlist|Jumbo|KoreLogic), not a hashcat `.rule` file.
  - Run john **single** mode first when you have usernames (mangles GECOS/username — highest ROI).

## 3. Fast-wins ladder (cheap → expensive) — what `auto` climbs
1. Straight dict, no rules (rockyou) — trivial/reused pw in seconds.
2. Dict + **OneRuleToRuleThemStill.rule** (already in `rules/`; highest crack-per-keyspace single file, ~63–70%).
3. Hybrid `?w+?d?d?d?d` / `?d?d?d?d+?w` (`-a 6/-a 7`) — `Word2024`, `Summer2025!`.
4. Frequency/runtime-ordered mask (`.hcmask`, `-a 3`) — productive 8-char: `?u?l?l?l?l?d?d?d`, `?u?l?l?l?l?l?d?s`.
5. Combinator / bigger wordlist + rules.
> Dict+rules recovers ~50–70% of real dumps for near-zero keyspace. Brute-force is LAST and gated (`--allow-bruteforce`, Daniel's explicit OK only).

## 4. AD workflow (post-secretsdump / NTDS)
1. **Triage, crack the subset** (`triage` command): strip machine accounts (`$`) and `krbtgt` — **abuse-not-crack** (PtH / golden ticket). Never GPU them.
2. Order: (1) blank NTLM `31d6cfe0d16ae931b73c59d7e0c089c0` = empty (instant); (2) `password==username`; (3) reused hashes across users (one crack unlocks many); (4) dictionary the rest, **privileged accounts first**.
3. NTLM (1000) is fast — dict+rules almost always worth it.

## 5. Kerberoast / AS-REP
- Modes: TGS-REP `-m 13100` (RC4), AS-REP `-m 18200`, AES `-m 19600/19700`. **Confirm mode first** — AES is ~10x slower; #1 wasted-hours mistake.
- Best combo: rockyou + OneRuleToRuleThem(Still/All). Service accounts skew `ServiceName2023!`, vendor defaults (old, human-set, rarely rotated).
- 15+ char random = uncrackable here → move on.

## 6. Targeted wordlists from OSINT (`forge`)
- Web target: `cewl -d 2 -m 5 http://target -w words.txt` (on Kali), fold into `forge --terms`.
- Company name + founding year + city + season. Mangle with hashcat rules (GPU-side). `Season+Year+!` corporate pattern → hybrid/combinator, not blind mask (~60% of policy-compliant users do Capital+word+number+symbol).

## 7. HTB reality + when to STOP
- rockyou hits constantly; keyboard walks (`qwerty`, `1qaz2wsx`), box-themed passwords, rockyou+`?d?d?d`. HTB authors seed the intended path — usually gettable in minutes.
- **Waste of time**: brute-forcing slow hashes (bcrypt/sha512crypt/KeePass) with masks. If it's slow and rockyou+rules misses → it's not the path, find another vector.
- Time-box: rockyou (~2min NTLM) → +OneRule (~15min) → targeted/CeWL → masks. Nothing on a *fast* hash after rules ⇒ plaintext is random ⇒ stop, pivot. Slow hash: one rockyou pass, then stop.

## 8. Perf flags (real vs placebo)
- `-O` optimized kernel: real speedup, caps len ~31 (fine for human pw). Core already passes `-O`.
- `-w 3` default; `-w 4` only if headless.
- `-S`: only helps slow/salted (bcrypt); placebo on NTLM/MD5.
- Keep `--hwmon-temp-abort` (laptop thermal guard; core does this per rung).

## 9. Feedback loop (GEB strange-loop)
- Potfile stays on (auto-skips cracked across jobs). Per-engagement pots keep client creds isolated.
- `--loopback` (john) / cracked-feedback rung (hashcat) re-feeds fresh cracks through rules.
- Wins → `learned.rule` (governed, ADR-0003) and the **Trophy log** (read before choosing Strategy). john wins now land in the Trophy log too via `johncrack`.

## 10. Reporting (CPTS appendix — `report`)
% cracked, top-N passwords, **reuse stats** (same hash across N accounts; admin↔user), `password==username` count, complex-but-weak (`Companyname1!`), blanks, crack-time as risk proxy. Recs: 14+ length policy, block breached (HIBP/`hibp` command), unique per-account, AES-only Kerberos, periodic audits. Engagement scope auto-redacts plaintext.

## Upgrades worth fetching
- **weakpass_4** wordlist (bigger high-hit second pass after rockyou).
- **Extreme_Breach_Masks** (sean-t-smith) — runtime-ordered `.hcmask` for the mask rung.
- **haiti** identifier (john + hashcat modes in one).
