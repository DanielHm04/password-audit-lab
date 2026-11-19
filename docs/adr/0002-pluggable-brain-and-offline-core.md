# Pluggable Brain backend + a Brain-less offline core

Refines ADR-0001. Two forward-looking requirements — "be able to add an LLM API later" and "run offline" — mean the intelligence must not be welded to Claude Code, and cracking must not depend on any LLM being reachable. We decided: (1) a **Deterministic core** (Python) can identify, forge, climb the ladder, and log **fully offline with no Brain at all** — the floor that always works; and (2) the Brain sits behind a **one-interface adapter seam** with three Backends — `claude-code` (default, online, zero API cost), `api` (a future keyed API), `ollama` (local, offline).

## Relationship to ADR-0001

Does not contradict it. 0001's point stands: no monolithic app that welds an LLM API into the cracking logic. Here the LLM stays a *separate, optional, swappable* layer; the new Python core is deterministic Muscle that can self-orchestrate the mechanical ladder — it contains no LLM.

## Consequences

- **v1 implements only the `claude-code` Backend and the Deterministic core.** `api` and `ollama` are a config flag + one small adapter file each — deferred, but the seam ships now so adding them later is not a refactor.
- Offline automatic mode works with zero internet (mechanical ladder). Offline *intelligence* requires the `ollama` Backend, installed later.
- Every capability (identify, forge, crack, log) must be callable **both** as a plain Python primitive (for the core) **and** describable to a Brain (for the skills). Skills orchestrate; they never own logic the core can't also run.
