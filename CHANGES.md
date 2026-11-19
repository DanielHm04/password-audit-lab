# Changes from my working copy for publication

The code behaviour is unchanged. Edits were limited to removing personal data and
adding the things a public repo needs.

- **Personal data removed.** SSH connection examples used my real login name and my
  lab's private IP addresses (in `README.md`, `scripts/Harden-And-Setup-Admin.ps1`,
  `kali/capture-cheatsheet.md`, `docs/MANUAL.html`). These are now placeholders:
  `user@RIG_IP`, `<user>`, `RIG_SUBNET_NAT` / `RIG_SUBNET_HOSTONLY` /
  `RIG_SUBNET_BRIDGED`. Fill in your own values.
- **README rewritten** for a hiring reader: architecture diagram, benchmark table,
  governance design, quick start, authorized-use notice, and what I learned. The old
  README is preserved in substance.
- **Added** `tests/` (offline pytest suite, 26 tests), `tests/`-enabling
  `core/__init__.py` (so the modules import as a package under pytest; the runtime
  bare imports in `cracklab.py` are unaffected), `.gitignore`, `LICENSE` (MIT),
  `SECURITY.md`, and this file.
- **No data shipped.** No hashes, potfiles, wordlists, loot, or job logs were ever
  in the source tree, and none were added.
