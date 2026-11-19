# Claude Code is the Brain; no external LLM API

The tool needs intelligence (hash strategy, targeted wordlist generation, when to escalate/stop) but must run at zero marginal cost and stay maintainable long-term. We decided the "intelligence" is **Claude Code running as the `claude` CLI on the rig**, driven interactively over SSH — not an LLM embedded in a standalone application. Deterministic tools (hashcat, John, name-that-hash, `forge.py`) are thin "Muscle"; the reasoning lives in the Claude session ("Brain"); a small set of skills is the "Interface".

## Considered Options

- **Monolithic Python app that calls an LLM API** — rejected: costs metered API money per run, hides its reasoning inside code, rots fast, and effectively re-implements a worse hashcat wrapper.
- **A swarm of Claude subagents managing each other** — rejected: more files to keep in sync and more handoffs to break, directly against the "simple, updatable long-term" goal. Chose **one governed operator (CrackLab/CLAUDE.md) wielding three skills** instead.

## Consequences

- Zero API cost — runs on Daniel's existing Claude subscription.
- Every decision is readable and hand-overridable; nothing is buried in compiled logic.
- The Brain is **ephemeral**, so Jobs must run detached (hashcat `--session`) and survive SSH disconnect — the operator launches, records, and reconnects to check status.
- Updating the tool = editing markdown skills + small Python, not refactoring an app.
