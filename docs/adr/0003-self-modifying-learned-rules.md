# Self-modifying learned ruleset (RuleGen strange-loop) with a governance gate

CrackLab's Trophy log was memory the Brain *read*; the tool did not change its own
attack based on it. We decided to close the loop: after every Job, `rulegen.py`
reverse-engineers the mangling of each cracked password (base word → observed
password) into the equivalent hashcat rule, ranks by frequency, and writes
`rules/learned.rule`. That file is injected as a late Escalation-ladder rung, so
**each Job rewrites the ruleset the next Job uses** — the outputs of one level
become inputs at a higher level. This is the GEB feedback CrackLab was designed
around, made concrete.

## Why this needs an ADR

It is self-modification: the tool edits an artifact that changes its own future
behavior. That is powerful and, done naively, dangerous (runaway growth, drift,
overfitting to one lucky crack, and — for client work — leaking target-specific
password structure into a shared file). So the mechanism is deliberately
**governed**, and the governance is the decision worth recording.

## The governance gate

- **Never learn from a single datum.** A rule is kept only if its pattern recurs
  (`MIN_FREQ = 2`). One crack never rewrites the ruleset.
- **Bounded growth.** At most `CAP = 200` rules per refresh; the file is fully
  regenerated each Job, not appended — it cannot grow without bound or drift.
- **Auditable.** Every kept rule is logged to `loot/learned-rules.jsonl` with its
  frequency, an example crack, and a confidence score.
- **Scope isolation.** `htb/cpts/lab` (training data) learn into the shared
  `rules/learned.rule`. `engagement` scopes learn into an isolated
  `rules/learned-<label>.rule` used only within that engagement, and the audit log
  omits the example plaintext — client-specific structure never bleeds into the
  shared ruleset or the logs.
- **Deterministic, no Brain.** Rule derivation is pure Python (no LLM), so the
  loop runs headless and offline and is reproducible.

## Consequences

- The learned rung is cheap (≤200 rules) and slots in after `best64`/OneRule; it
  is *additive* — the fixed rulesets (OneRuleToRuleThemStill, clem9669) are never
  replaced, only supplemented. If mining yields nothing, the rung simply doesn't
  appear.
- First Job against a new kind of target has no learned rules yet; value compounds
  as the Trophy log grows. This is intended (the incompleteness/portfolio stance:
  the ruleset is never "finished").
- Failure modes designed against: runaway growth (cap + full regen), overfitting
  (min-freq ≥ 2), drift (fixed rulesets stay authoritative; learned is a small
  additive layer), and cross-client leakage (per-engagement isolation + redacted
  log).
