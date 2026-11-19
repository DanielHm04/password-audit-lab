# Security and responsible use

This is a password-auditing training tool. It is for use only against hashes you
are authorized to audit: your own lab targets, your own training material, the
CPTS exam, or an engagement covered by **written permission**.

## Do not commit sensitive data
The `.gitignore` is written to keep hashes, potfiles, cracked plaintext, loot,
wordlists, and the HIBP corpus out of the repository permanently. Do not override
it. If you fork this, verify `git status` shows none of those paths before you push.

## Reporting a problem
This repo ships code only, no live service and no data. If you find a bug in the
governance logic (for example a way the scope gate or the brute-force gate can be
bypassed), open an issue describing the case. Do not include real hashes or
cracked material in an issue.
