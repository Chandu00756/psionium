# Work log

Newest first. Every session adds one entry: date, who, what was done, how it was verified, what is left.

## 2026-10-16 — Claude (Opus 5.5): full platform design written

**Done**
- Answered the owner's question of what exists: the released CLI (local encrypt/decrypt/sign/scan) only. No interactive shell, accounts, transfer, web app, apps, licensing or admin yet.
- Checked the old CLI: the recovered `psionium_shell.py` (cmd prompt) and `psionium_desktop_shell.py` / `backend/psionium_terminal_shell.py` (Tkinter window, black background, bold green Courier, `pSIONIUM>` prompt, history; commands encode/decode/compress/decompress/api execute). A more colorful version, if it existed, was not in VS Code history.
- Read the 26 PVII documents (converted to text) and mapped every idea in `design/13-research-track.md`.
- Wrote `project/design/` 01–14 and rewrote `ROADMAP.md` into 8 stages linked to the design; updated `README.md`, `RULES.md`, `VISION.md`, `STATUS.md`, `DECISIONS.md`.
- Confirmed the GitHub repository is public; the owner installed v1.0.0 with `install.sh`.

**Verified**
- Every relative link in `project/` resolves (checked with a script); docs only, no code changed.

**Left / next agent**
- Ask the owner D11 (shell brand) if needed, then start Stage 2 (interactive shell) per `design/05-interactive-cli.md`.
- Owner items in `design/14-owner-decisions.md`.

## 2026-10-16 — Claude (Opus 5.5): v1.0.0 released

**Done**
- Fixed the Windows CI hang: `rpassword` reads the Windows console even with no one there, so the "no terminal" test waited forever. On Windows `psion` now prompts only when stdin or stderr is a terminal. Added `timeout-minutes` to every CI and release job. Commit `14bd645`.
- Let the release workflow run by hand to test all builds without publishing; only tags publish.
- Dated the changelog, tagged `v1.0.0` on `1aa8086`, release run 38944493682 published 5 archives and SHA256SUMS.

**Verified**
- CI run 38943173387 green on all jobs; Windows ran all 42 tests.
- Release assets: checksums match; `psion 1.0.0` on macOS arm64, macOS x86-64 (Rosetta), Linux arm64 and x86-64 (Alpine); Windows `.exe` is a valid PE32+ x86-64 binary; files encrypted and signed by the released macOS binary decrypt and verify with the released Linux binary; the released Linux binary decrypts a committed vector to the same bytes as macOS.

**Left / next agent**
- Owner decisions in `STATUS.md` (public repo, website, mailbox, review, the untracked `flutter/` folder).
- After the repo is public: run `install.sh` against the real release; the Windows binary has only been checked by CI tests and file type, not run by hand.
- Next roadmap stage: Scan GitHub Action and HTML report.

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
