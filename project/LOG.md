# Work log

Newest first. Every session adds one entry: date, who, what was done, how it was verified, what is left.

## 2026-10-16 — Claude (Opus 5.5): pSIONIUM 1.0 built end to end, project folder created

**Done**
- Recovered the lost original code from VS Code history to the `legacy` branch and `~/Desktop/pSIONIUM_recovered`; wrote the pSIONIUM 3 plan.
- Built `psionium-core` (.psen v2, hybrid ML-KEM, ML-DSA signatures, Argon2id identities), the `psion` CLI and `psionium-scan` (code, dependencies, certificates, keys, TLS; CBOM).
- Spec `docs/psen-v2.md`, threat model, scanner guide, SECURITY.md, CHANGELOG, Apache-2.0 license.
- Test vectors, mutation tests (2.4 million mutations in a one-off run, none accepted), independent Go implementation that interoperates both ways.
- CI (Linux, macOS, Windows, MSRV, audit, interop), release workflow (musl, macOS, Windows, checksums, provenance on public repos), `install.sh`.
- Fixed: `-o -` creating a file named `-`; release failure on private repos; pluralized messages; README claim that all crypto comes from AWS-LC (Argon2id is RustCrypto); Windows line endings for vectors (`.gitattributes`).
- Rewrote the website's pSIONIUM pages without fabricated claims (not pushed).
- Created this `project/` folder.

**Verified**
- Full suite green on macOS and in a Linux (Alpine musl) container, including a fresh-clone copy; `cargo audit` clean.
- `install.sh` against a local release layout on macOS and clean Alpine (wget only); tampered archive refused.
- Website builds; both pSIONIUM pages checked at desktop and phone widths.
- Committed and pushed as `708fbc5` with the owner's approval. GitHub CI run 38938057560: lint, Linux, macOS, MSRV, audit, interop passed. Windows hung in `passphrase_protected_identities` (the passphrase prompt waits on the Windows console); run cancelled after 36 minutes to save billed minutes.
- Fixed locally, not committed: on Windows, prompt only when stdin or stderr is a terminal; `timeout-minutes` on every CI and release job. Local suite green.

**Left / next agent**
- With the owner's approval, commit and push the Windows fix and timeouts, then confirm the Windows job passes (the core and scanner tests never ran on Windows yet).
- Owner decisions: public repo, `v1.0.0` tag, website push, security mailbox, independent review (see `STATUS.md`).
- The `project/` folder was committed with the owner's approval (docs only, pushed with `[skip ci]` because the Windows fix was not yet approved).
