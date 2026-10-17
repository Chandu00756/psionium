# Changelog

## Unreleased

### psion scan

- `--format html`: a self-contained report (no scripts or network requests) with a summary, NIST deadlines, a chart of algorithms, and what to do about each finding.
- `--format sarif`: SARIF 2.1.0 for GitHub code scanning; accepted findings carry suppressions.
- Baselines: `.psionium-scan.toml` lists accepted findings (each with a reason) and paths to `ignore`; `--fail-on` then fails only on new findings. Read automatically from the current folder, or with `--baseline FILE`; `--no-baseline` skips it; `--write-baseline FILE` accepts what is found and keeps reasons already written.
- `--no-excerpts`: reports never quote source code.
- Every finding has a `fingerprint` (in JSON and SARIF) that survives edits elsewhere in the file.

## 1.0.0 (2026-10-16)

First release of pSIONIUM 3.

### psion command line

- `keygen`: identities with an encryption key pair and a signing key, in the `pq-hybrid-768` (default) or `cnsa-1024` suite; passphrase protected by default.
- `encrypt` / `decrypt`: files and streams to one or more recipients (`-r`, `-R` lists), optional signing with `--sign-with`, sender checks with `--signed-by` / `--signed-by-file`; outputs are written atomically so failures leave nothing behind.
- `inspect`: suite, chunk size, recipients and signer of a file without decrypting it.
- `pubkey`, `passphrase`: show public keys, and add, change or remove a passphrase.
- `scan`: quantum-readiness scanner for code, dependencies, certificates, keys and TLS endpoints, with text, Markdown, JSON and CycloneDX 1.6 CBOM output and `--fail-on` for CI.
- `-` as a file name means standard input or output.

### Distribution

- Binaries for Linux (x86-64, ARM64; static, for any distribution), macOS (Apple silicon, Intel) and Windows, with `SHA256SUMS`.
- `install.sh` installs the right binary for macOS and Linux after checking its checksum.

### Format

- `.psen` v2 (`docs/psen-v2.md`): X25519 + ML-KEM-768 or ML-KEM-1024 key wrapping, AES-256-GCM chunked payload, HMAC-SHA-384 header, optional ML-DSA-65/87 signature, flags byte for extensions.
- Committed test vectors that every later 1.x release must decrypt.
- A second implementation in Go, written from the specification, interoperates with `psion` in both directions.
