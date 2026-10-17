# Where pSIONIUM stands

Last updated: 2026-10-16, after the **`v1.1.0` release** (commit `e7d1dcf`): the interactive shell and Scan Stage A are released. Stage 2 continues. Every agent updates this file at the end of its work (see `README.md`).

## Summary

pSIONIUM **v1.1.0** is released: https://github.com/Chandu00756/psionium/releases/tag/v1.1.0. It adds the interactive shell (`psion` with no command) and HTML/SARIF scan reports with baselines to the v1.0.0 command line (encrypt, sign, decrypt, scan). Users update by re-running the `install.sh` one-liner. The repository is **public** (confirmed 2026-10-16), and the owner installed it with the one-line `install.sh` on macOS.

The full platform the owner wants (accounts, secure transfer, web app, desktop/mobile apps, licensing, admin console, staff back office, Scan dashboard, SDKs) is **designed but not built**. The design is in [`design/`](design/README.md); the build order is in [`ROADMAP.md`](ROADMAP.md). The table "What exists today vs. what is planned" in `design/01-products-and-journeys.md` is the quick answer to "do we have X?".

## What exists and works

| Part | State | Evidence |
|---|---|---|
| `.psen` v2 format | Specified in `docs/psen-v2.md` (draft 2, proposed frozen for 1.0) | Committed test vectors in `crates/psionium-core/tests/vectors`; a second implementation in Go (`interop/go`) written from the spec alone interoperates both ways |
| `psionium-core` (Rust) | Encryption to many recipients (X25519 + ML-KEM-768, or ML-KEM-1024), ML-DSA signatures, Argon2id-protected identities, streaming AES-256-GCM chunks | 17 round-trip, 4 passphrase, 3 mutation, 2 vector tests; 2.4 million random file corruptions, none accepted |
| `psion` CLI | keygen, pubkey, encrypt, decrypt (`--signed-by`), inspect, passphrase, scan; `-` for stdin/stdout; atomic outputs | 8 end-to-end CLI tests |
| `psionium-scan` | Finds quantum-vulnerable crypto in code (40+ languages/formats), dependency manifests, certificates, keys, live TLS (X25519MLKEM768 check); text, Markdown, JSON, CycloneDX 1.6 CBOM; `--fail-on` for CI | 5 tests incl. live local TLS servers; real scans of TaskFlow |
| Interactive shell (v1.1.0) | `psion` / `psion shell`: Home, Encrypt, Decrypt, Keys, Scan, Console (`pSIONIUM>` prompt), Settings, Help + tutorial; palette; 4 themes + `NO_COLOR`; launch animation; `--plain`; `psion theme`; `--passphrase-file -`; `PSION_NO_PROMPT`. Guide: `docs/shell.md` | 29 snapshots (every screen at 80×24 and 200×60, overlays, per-theme styles), 17 shell unit tests, 2 new CLI tests; every journey driven in a real pseudo-terminal (see `LOG.md`) |
| Scan Stage A (v1.1.0) | `--format html` (self-contained report), `--format sarif` (2.1.0), baseline `.psionium-scan.toml` (accepted findings with reasons, `ignore` paths; `--baseline`, `--no-baseline`, `--write-baseline`), `--no-excerpts`, a `fingerprint` on every finding | 5 new scanner tests, 1 new CLI test; HTML checked in a browser (dark, light, 375 px wide, no overflow); full suite green (see `LOG.md`) |
| CI (`.github/workflows/ci.yml`) | lint, tests on Linux/macOS/Windows, MSRV 1.88, `cargo audit`, Go interop; every job has a timeout | Green on `14bd645` (run 38943173387): all 42 tests pass on Linux, macOS and Windows. An earlier Windows hang (the passphrase prompt waited on the console) is fixed |
| Release (`.github/workflows/release.yml`) | On a `v*` tag: builds Linux musl (x86-64, ARM64), macOS (arm64, x86-64), Windows; SHA256SUMS; provenance attestations when the repo is public. Can run by hand (`gh workflow run release.yml`) to test builds without publishing | v1.0.0 published by run 38944493682. Downloaded assets match SHA256SUMS; every binary prints `psion 1.0.0` (macOS arm64 native, x86-64 under Rosetta, Linux arm64 and x86-64 in Alpine); files made by the released macOS binary decrypt with the released Linux binary. No provenance attestations yet (private repo) |
| `install.sh` | Detects OS/CPU, downloads the release, checks SHA-256, installs to `~/.local/bin` (Windows Git Bash/MSYS2/Cygwin: `psion.exe` to `~/bin`, added 2026-10-16); curl or wget | Tested on macOS and a clean Alpine container against a local copy of the release layout; tampered archive refused |
| Docs | `README.md`, `docs/psen-v2.md`, `docs/threat-model.md`, `docs/scan.md`, `docs/production-readiness.md`, `SECURITY.md`, `CHANGELOG.md`, `LICENSE` (Apache-2.0) | — |

Totals at `1aa8086`: 42 Rust tests pass on Linux, macOS and Windows (1 ignored: the vector writer), Go interop passes, clippy clean with `-D warnings`, `cargo audit` clean (144 crates).

## Related work outside this repository

| Where | State |
|---|---|
| Website `~/P7Ultra/portalvii-website2` (repo `~/P7Ultra`) | pSIONIUM pages rewritten for the real product (`/pages/psionium`, `/pages/resources/psionium`); fake claims and fake-metric components removed; builds. **Not committed or pushed** (they link to the GitHub repo, so publish after it is public) |
| Website, other product pages | A separate session ("Remove unverified claims from other PORTAL VII pages") is cleaning HIPAA/PCI/SOC 2/uptime claims on Jupiter, SuperDesktop and enterprise-security pages |
| `legacy` branch of this repo | The original pSIONIUM code recovered from VS Code history (114 files). Reference only |
| `~/Desktop/pSIONIUM_recovered` | The same recovered files with every saved version and `RECOVERY_REPORT.md` |
| `~/Desktop/PVII` | The owner's original idea documents (charter, architecture, research proposal) |
| TaskFlow `~/Taskflow` (live at taskflow.portalvii.com) | Separate product; its stack (Go services, PostgreSQL, Redis, Next.js) is the planned base for the Vault cloud service |

## Waiting on the owner

All open owner decisions and actions are tracked in [`design/14-owner-decisions.md`](design/14-owner-decisions.md). The ones blocking work right now: push the rewritten website pages (D13), decide on the untracked `flutter/` and `.vscode/` folders (D12), confirm the security mailbox (A1), D11 (shell brand) was answered on 2026-10-16. The independent cryptographic review (D10/A5) is required before customers' irreplaceable data.

## Known gaps (not blocking 1.0 CLI, needed for the vision)

- No GitHub Action wrapper, Docker image or GitLab template for Scan yet (HTML report and SARIF exist). No custom rules in the baseline.
- No `cargo-fuzz` targets (mutation tests cover parsing today); no benchmarks published.
- SLH-DSA (long-term signatures) not implemented.
- No Vault service, apps, SDKs, key hierarchy, recovery or audit log yet.
