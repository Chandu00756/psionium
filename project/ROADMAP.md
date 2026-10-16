# Roadmap

Ordered by what to do next. No dates: finish a stage's "done when" before starting the next stage's main work (independent pieces may overlap). Mark items `[x]` when done and verified, and add a line to `LOG.md`.

## Stage 1 — Release pSIONIUM 1.0 (current)

- [x] `.psen` v2 format, spec, test vectors, Go interop implementation
- [x] `psion` CLI with signatures, passphrases, scan
- [x] CI and release workflows, `install.sh`, security docs
- [x] CI green on all jobs, including Windows (run 38943173387)
- [x] Release v1.0.0 published (private repository) and its assets verified on macOS and Linux
- [ ] Owner decisions in `STATUS.md` → "Waiting on the owner" (public repo, website, mailbox)
- [ ] After the repo is public: run `install.sh` against the real release on macOS and Linux, and verify `gh attestation` on the next release
- [ ] Website pSIONIUM pages live with working download links

**Done when:** anyone can install `psion` with one command, the release has checksums and provenance, and portalvii.com describes it truthfully.

## Stage 2 — Make Scan the front door

- [ ] GitHub Action (`psionium/scan-action`) that runs `psion scan`, uploads the CBOM, comments a summary on pull requests, fails on `--fail-on`
- [ ] Self-contained HTML report format (`--format html`) a non-engineer can read
- [ ] More languages/ecosystems as users ask (lock files for versions, Java keystores, cloud KMS inventories)
- [ ] A "quantum readiness" landing page and guide on portalvii.com with a sample report
- [ ] Collect feedback from the first outside users; list 10 design-partner companies

**Done when:** outside teams run Scan in CI and some of them ask for help migrating.

## Stage 3 — Harden the core

- [ ] Independent cryptographic review of the format and implementation; fix findings; publish the report
- [ ] `cargo-fuzz` targets for header parsing, identity files and keys; run continuously
- [ ] Benchmarks published (throughput, memory, header sizes)
- [ ] SLH-DSA option for long-term signatures (archives, releases)
- [ ] Re-wrap tooling: add/remove recipients and rotate suites without re-encrypting payloads
- [ ] Sign pSIONIUM's own releases with ML-DSA/SLH-DSA in addition to GitHub provenance

**Done when:** the review is published with no open critical findings.

## Stage 4 — Vault

- [ ] Architecture decision record for the service (reuse TaskFlow's Go services, PostgreSQL, Redis, Next.js console, sign-up, organizations, roles, audit, email)
- [ ] Organization key hierarchy, sharing with people and teams, rotation, k-of-n recovery
- [ ] Zero-knowledge API: stores ciphertext and wrapped keys only
- [ ] Tamper-evident audit log (hash chain with daily anchors)
- [ ] Hardware-backed device keys (Secure Enclave, TPM, StrongBox, passkeys)
- [ ] Desktop and mobile app: revive the Flutter "dock" app from the `legacy` branch on `psionium-core` via flutter_rust_bridge
- [ ] TaskFlow attachments encrypted with pSIONIUM in production

**Done when:** design partners use Vault weekly and TaskFlow runs on it.

## Stage 5 — SDK and business

- [ ] Field-level encryption SDKs: Rust, Go, TypeScript (WebAssembly), Python
- [ ] BYOK with AWS KMS, Google Cloud KMS, HSMs
- [ ] Compliance evidence pack mapped to NIST and CNSA 2.0
- [ ] Billing and plans (see `VISION.md`); SOC 2 readiness
- [ ] First paying customers

## Stage 6 — Expand (driven by customer demand)

- Post-quantum proxy for legacy apps (basis: `network_resilience` on the `legacy` branch)
- Anomaly alerts on key usage (basis: `ai_threat_detection` on the `legacy` branch)
- Threshold / MPC key custody
- Research track: DIBLE, FHE experiments — off the product path until published and reviewed
