# Production readiness

pSIONIUM goes live when every item below is checked. Each item names how it is verified.

## Cryptography and format

- [x] Only standardized algorithms from production libraries: ML-KEM (FIPS 203), ML-DSA (FIPS 204), X25519, AES-256-GCM, HKDF-SHA-384, HMAC-SHA-384 and SHA-384 from AWS-LC; Argon2id (RFC 9106) from RustCrypto's `argon2` for passphrases. *Verified: dependency review of `Cargo.lock`; `cargo audit` clean.*
- [x] `.psen` v2 specification complete: a second implementation written in Go from `docs/psen-v2.md` alone (`interop/go`) decrypts every committed vector and interoperates with `psion` in both directions, for both suites, signed and unsigned, at every chunk boundary. A flags byte reserves room for extensions; unknown flags are rejected. *Verified: `interop/go` tests, parser tests.*
- [x] Sender authentication with ML-DSA signatures over the whole ciphertext; ML-DSA keys derived from the same seed agree between AWS-LC and CIRCL. *Verified: sign/verify, tampering, stripping and wrong-signer tests in Rust and Go.*
- [x] Secret keys at rest protected by a passphrase by default. *Verified: CLI tests.*
- [x] Published test vectors that every future version must keep decrypting. *Verified: `crates/psionium-core/tests/vectors`, in CI and in the Go implementation.*
- [x] Mutation testing: random corruptions of valid files never panic and never decrypt. *Verified: 6,000 per CI run; 2.4 million in a one-off campaign over three seeds with no failure.*
- [x] Secrets wiped from memory after use where pSIONIUM holds them (`zeroize`); no `unsafe` code in pSIONIUM crates. *Verified: `#![forbid(unsafe_code)]` in every crate.*

## Product

- [x] `psion` CLI: keygen, pubkey, encrypt, decrypt, sign-aware decrypt, inspect, passphrase management, recipients files, standard input and output (`-`).
- [x] pSIONIUM Scan: finds quantum-vulnerable cryptography in source code, dependencies, certificates and keys, and checks TLS endpoints for post-quantum key exchange; exports a CycloneDX CBOM and a readable report. *Verified: fixture and live TLS tests; real scans.*
- [x] Clear error messages for every failure a user can cause. *Verified: CLI tests.*
- [x] Documentation: install, quick start, command reference, format specification, scanner guide, threat model.

## Engineering

- [ ] Continuous integration on Linux, macOS and Windows: format, lint, tests, MSRV, dependency audit, Go interoperability. *Workflow written; locally verified on macOS (arm64) and Linux (Alpine musl, arm64). Checked when the first run on GitHub is green, including Windows.*
- [ ] Release builds for macOS (Apple silicon, Intel), Linux (x86-64, ARM64, static) and Windows, with SHA-256 checksums and, on a public repository, build provenance attestations. *Workflow written; macOS Intel cross-build and Linux ARM64 musl build verified locally. Checked when the v1.0.0 workflow succeeds.*
- [x] Versioning and changelog; `psion --version` reports the build.
- [x] Security policy (`SECURITY.md`) with a private reporting address.

## Going live

- [ ] Release v1.0.0 published on GitHub with binaries. *Needs: a public repository (or a public release repository), the changelog dated, and the `v1.0.0` tag.*
- [x] Install instructions verified on a clean machine. *Verified: `install.sh` against a local copy of the release layout on macOS (curl) and on a clean Alpine container with only busybox `wget`, including a tampered archive (refused, nothing installed) and a missing version; the latest-release lookup against GitHub with both curl and wget. Re-check against the real v1.0.0 release.*
- [ ] pSIONIUM pages on portalvii.com updated with real features, downloads and no unverified claims.

## Outside this repository (required before handling customers' irreplaceable data)

- [ ] Independent cryptographic review of the format and implementation. This cannot be self-certified; until it is done, releases say so.
