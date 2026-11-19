# Brain adapter seam

The **Brain** (intelligence) is swappable. The **Deterministic core** (`core/cracklab.py`)
never calls a Brain — it runs offline on its own. The Brain sits *on top*, adding the smart
parts: reading free-form OSINT into good base words, choosing/ordering strategy, reasoning
about ambiguous provenance. This file is the contract so a future backend is a drop-in, not a
refactor. (See ADR-0001, ADR-0002.)

## The three backends (`brain/brain.json`)

| Backend | Status | What it is | Needs |
|---------|--------|-----------|-------|
| `claude-code` | **active (v1)** | You, driving `claude` in the terminal | internet, your subscription (no API cost) |
| `api` | seam-ready | A keyed LLM API call | an API key in `ANTHROPIC_API_KEY`, `brain/adapter_api.py` |
| `ollama` | seam-ready | A local model, fully offline | Ollama + a pulled model, `brain/adapter_ollama.py` |

## The contract every Brain must satisfy

A Brain only ever produces **structured requests to the core** — it never cracks anything itself.
Its two jobs:

1. **`osint_to_basewords(free_text) -> list[str]`**
   Turn messy notes ("hospital box, admin's name is on the site, founded 2003") into smart base
   words (`["stmary","hospital","admin","2003","florida"]`). The core's `forge.py --terms ...`
   does the mechanical explosion.

2. **`choose_strategy(identify_result, trophy_history) -> dict`**
   Given the identified mode and past wins, return `{mode, targeted, cap, allow_bruteforce, order}`.
   In v1 this is *your judgment* reading `cracklab.py trophies`. A programmatic backend returns
   the same shape.

Everything else (identify, ladder execution, potfile, trophy log, detach) is the core's job and
is identical across backends.

## Adding a backend later (≈ one file)

1. In `brain/brain.json` set the backend's `enabled: true` and pick the active `backend`.
2. Create `brain/adapter_<name>.py` exposing the two functions above.
3. Nothing in `core/` changes. The skills call `forge` and `cracklab.py` exactly as now.

The rule that keeps this true (ADR-0002): **every capability works as a plain core primitive
first; the Brain only ever chooses inputs.** If you ever find logic living *only* in a skill that
the core can't run headless, move it into the core.
