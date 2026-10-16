# Where pSIONIUM stands

Last updated: 2026-10-16, after commit `708fbc5` on `main`. Every agent updates this file at the end of its work (see `README.md`).

## Summary

pSIONIUM 1.0 (the `psion` command line: encrypt, sign, decrypt, scan) is **built and verified locally, pushed to GitHub, but not released**. Release needs the owner's decisions listed at the bottom. The cloud Vault, apps and SDK (see `VISION.md`) are not started.

## What exists and works

| Part | State | Evidence |
|---|---|---|
| `.psen` v2 format | Specified in `docs/psen-v2.md` (draft 2, proposed frozen for 1.0) | Committed test vectors in `crates/psionium-core/tests/vectors`; a second implementation in Go (`interop/go`) written from the spec alone interoperates both ways |
| `psionium-core` (Rust) | Encryption to many recipients (X25519 + ML-KEM-768, or ML-KEM-1024), ML-DSA signatures, Argon2id-protected identities, streaming AES-256-GCM chunks | 17 round-trip, 4 passphrase, 3 mutation, 2 vector tests; 2.4 million random file corruptions, none accepted |
| `psion` CLI | keygen, pubkey, encrypt, decrypt (`--signed-by`), inspect, passphrase, scan; `-` for stdin/stdout; atomic outputs | 8 end-to-end CLI tests |
| `psionium-scan` | Finds quantum-vulnerable crypto in code (40+ languages/formats), dependency manifests, certificates, keys, live TLS (X25519MLKEM768 check); text, Markdown, JSON, CycloneDX 1.6 CBOM; `--fail-on` for CI | 5 tests incl. live local TLS servers; real scans of TaskFlow |
| CI (`.github/workflows/ci.yml`) | lint, tests on Linux/macOS/Windows, MSRV 1.88, `cargo audit`, Go interop | First run on GitHub (run 38938057560, commit `708fbc5`): lint, Linux, macOS, MSRV, audit and interop passed. **Windows hung** in `passphrase_protected_identities`: on Windows `rpassword` reads the console, so the "no terminal" test waited forever. The run was cancelled after 36 minutes. A fix (prompt only when stdin or stderr is a terminal on Windows) and job timeouts are made locally, **not yet committed**; push them and confirm the Windows job passes, including the core and scanner tests it never reached |
| Release (`.github/workflows/release.yml`) | On a `v*` tag: builds Linux musl (x86-64, ARM64), macOS (arm64, x86-64), Windows; SHA256SUMS; provenance attestations when the repo is public | Never run yet (no tag). Linux ARM64 musl and macOS x86-64 builds verified locally |
| `install.sh` | Detects OS/CPU, downloads the release, checks SHA-256, installs to `~/.local/bin`; curl or wget | Tested on macOS and a clean Alpine container against a local copy of the release layout; tampered archive refused |
| Docs | `README.md`, `docs/psen-v2.md`, `docs/threat-model.md`, `docs/scan.md`, `docs/production-readiness.md`, `SECURITY.md`, `CHANGELOG.md`, `LICENSE` (Apache-2.0) | — |

Totals at `708fbc5`: 42 Rust tests pass (1 ignored: the vector writer), Go interop passes, clippy clean with `-D warnings`, `cargo audit` clean (144 crates).

## Related work outside this repository

| Where | State |
|---|---|
| Website `~/P7Ultra/portalvii-website2` (repo `~/P7Ultra`) | pSIONIUM pages rewritten for the real product (`/pages/psionium`, `/pages/resources/psionium`); fake claims and fake-metric components removed; builds. **Not committed or pushed** (they link to the GitHub repo, so publish after it is public) |
| Website, other product pages | A separate session ("Remove unverified claims from other PORTAL VII pages") is cleaning HIPAA/PCI/SOC 2/uptime claims on Jupiter, SuperDesktop and enterprise-security pages |
| `legacy` branch of this repo | The original pSIONIUM code recovered from VS Code history (114 files). Reference only |
| `~/Desktop/pSIONIUM_recovered` | The same recovered files with every saved version and `RECOVERY_REPORT.md` |
| `~/Desktop/PVII` | The owner's original idea documents (charter, architecture, research proposal) |
| TaskFlow `~/Taskflow` (live at taskflow.portalvii.com) | Separate product; its stack (Go services, PostgreSQL, Redis, Next.js) is the planned base for the Vault cloud service |

## Waiting on the owner (agents must not do these without explicit approval)

1. Make `github.com/Chandu00756/psionium` public (required for public downloads, `install.sh`, the website links, and provenance attestations). Alternative: a separate public release repository.
2. Date the `1.0.0` entry in `CHANGELOG.md` and push the `v1.0.0` tag to run the release workflow.
3. Commit and push the website pSIONIUM pages (after step 1).
4. Confirm `chandu@portalvii.com` receives mail (it is the private vulnerability address in `SECURITY.md`) and turn on GitHub private vulnerability reporting once public.
5. Commission an independent cryptographic review of the format and code. This cannot be self-certified; until it is done every release and page says so.

## Known gaps (not blocking 1.0 CLI, needed for the vision)

- No GitHub Action wrapper or hosted HTML report for Scan yet.
- No `cargo-fuzz` targets (mutation tests cover parsing today); no benchmarks published.
- SLH-DSA (long-term signatures) not implemented.
- No Vault service, apps, SDKs, key hierarchy, recovery or audit log yet.
