# CrackLab

An AI-orchestrated password-cracking environment for authorized security work (HTB / CPTS / sanctioned engagements). Deterministic tools do the cracking; Claude Code, running in the terminal, decides how. Designed to be driven over SSH from Kali and to improve over time.

## Language

### The three layers

**Muscle**:
The deterministic, non-thinking tools that actually crack and generate: hashcat, John the Ripper, hashid, and the Python generators. Fast, dumb, reliable.
_Avoid_: engine, backend

**Brain**:
The pluggable intelligence layer that chooses strategy, forges candidates, and decides when to escalate or stop. Swappable across Backends; default is Claude Code on Daniel's subscription. Optional and enhancing — the Deterministic core runs without it.
_Avoid_: AI, the model, the agent (too vague — name the specific Backend instead)

**Backend**:
A concrete implementation of the Brain. Three planned: `claude-code` (default, online, no API cost), `api` (a future keyed LLM API), `ollama` (a local model, fully offline). Selected by config behind one adapter seam.
_Avoid_: provider, engine

**Deterministic core**:
The no-LLM orchestrator (Python) that can identify a hash, forge a wordlist, climb the Escalation ladder, and write the Trophy log entirely offline with zero Brain. The floor that always works.
_Avoid_: the script, the engine (reserve "Muscle" for the individual tools)

**Interface**:
What Daniel actually invokes: the skills, the agents, and the thin launcher. The surface between him and the Brain.
_Avoid_: UI, frontend

### Core nouns

**Strategy**:
The complete plan for one cracking attempt: hash mode, attack type, which wordlist, which rules, and the resource caps. Produced by the Brain, executed by the Muscle.
_Avoid_: config, settings, approach

**Targeted wordlist**:
A temporary, disposable list of candidate passwords generated from a specific target's OSINT (names, dates, company, locale). Distinct from a generic wordlist like rockyou.
_Avoid_: custom list, dictionary (reserve "dictionary" for the attack mode)

**Job**:
One cracking run against one hash file, always named so it can be paused and resumed (hashcat `--session`). Survives an SSH disconnect.
_Avoid_: run, task, session (say "hashcat session" for the flag specifically)

**Escalation ladder**:
The ordered sequence of Strategies the Brain climbs in automatic mode — cheapest/most-likely first, most expensive last — with a defined stop condition at each rung.
_Avoid_: pipeline, workflow

**Trophy log**:
The append-only record of what actually cracked and which Strategy cracked it. The tool's memory — read before choosing a Strategy so past wins inform future ones. This is the learning loop.
_Avoid_: history, results, database

**Learned ruleset**:
The hashcat rules CrackLab mines from its own cracked passwords (reverse the mangling, rank by frequency), regenerated every Job and added as a late Escalation-ladder rung. The Trophy log made actionable — wins rewrite the next run's plan. Governed and scope-isolated (see ADR-0003).
_Avoid_: custom rules, auto rules

**Keyspace estimate**:
The predicted time for a Strategy to exhaust its candidates (candidate count ÷ benchmarked GPU speed), computed before GPU time is committed. Turns "start it and see" into a decision.
_Avoid_: guess, ETA (say "keyspace estimate" canonically)

**Breached-password check**:
Testing captured hashes for *membership* in a known-breached corpus (Have I Been Pwned NTLM) — a reportable finding produced without any cracking. Distinct from a Job.
_Avoid_: audit (too broad), lookup

**Abuse-not-crack**:
The triage verdict for credential material that should be used directly — pass-the-hash / golden ticket, or a GPP / DPAPI / LAPS **decrypt** — rather than sent to the GPU. Decided before a Job, so GPU time is never spent on the uncrackable (machine accounts, krbtgt).
_Avoid_: skip, ignore

### Operation

**Operator**:
The single governed Claude session Daniel talks to over SSH. Not a named subagent — it is the main `claude` session, bound by `CrackLab/CLAUDE.md`. There is deliberately no swarm of agents.
_Avoid_: bot, assistant, agent swarm

**Provenance**:
Where a hash came from (secretsdump, `/etc/shadow`, Responder, GetUserSPNs, a file's prefix). The primary basis for identifying its mode — trusted over hash-shape guessing.
_Avoid_: source type, origin (use "provenance" canonically)

**Scope gate**:
The refusal check run before any Job: the hash must be tagged as an authorized target (HTB / CPTS / sanctioned engagement) or the Operator will not crack it.
_Avoid_: auth check, permission check

### Modes

**Automatic mode**:
The Brain climbs the Escalation ladder unattended, within resource caps, stopping at defined gates. Daniel is not watching.

**Manual mode**:
Daniel specifies or approves each Strategy before it runs. The Brain advises; he decides.
