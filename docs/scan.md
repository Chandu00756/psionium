# pSIONIUM Scan

`psion scan` shows where your software still depends on cryptography that a quantum computer breaks, so you can plan the move to post-quantum algorithms before NIST deprecates RSA and elliptic curves (after 2030) and disallows them (after 2035).

```bash
psion scan                                  # the current folder
psion scan ./service ./infra                # several folders
psion scan --tls api.example.com            # a live server only
psion scan . --tls api.example.com:8443 --format markdown -o quantum-readiness.md
```

## What it looks at

| Where | What it finds |
|---|---|
| Source code and configuration (40+ languages and formats) | RSA, ECDSA, ECDH, named curves, Ed25519, X25519, Diffie-Hellman, DSA; MD5, SHA-1, DES/3DES, RC4, TLS 1.0/1.1; ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS/LMS and hybrid groups such as X25519MLKEM768 |
| Dependency manifests (`package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`) | Crypto libraries, classified as quantum-vulnerable, to review, or post-quantum |
| Certificates (PEM and DER) | Key algorithm and size, signature algorithm, expiry; certificates still valid after 2030 are called out |
| Keys | SSH public keys (with RSA size), PEM and OpenSSH private keys. Private keys are reported by type and location only; their contents never appear in a report |
| TLS endpoints (`--tls`) | Whether the server accepts the X25519MLKEM768 post-quantum hybrid key exchange, its TLS version, cipher suite, preferred group, certificate, and whether the chain is publicly trusted |

The scan respects `.gitignore`, skips lock files (their integrity hashes are not crypto usage), binary files, files over 4 MB, and vendored dependencies (`node_modules`, `vendor`, virtualenvs, `target`) unless you pass `--include-dependencies`.

## Reading the results

| Category | Meaning | What to do |
|---|---|---|
| Quantum-vulnerable | Broken by a large quantum computer | Plan migration: ML-KEM (or X25519MLKEM768 hybrid) for key exchange, ML-DSA for signatures. Prioritize data that must stay secret for years, since it can be recorded now and decrypted later |
| Weak | Weak even without quantum computers | Replace now |
| Review | A general crypto library or a 128-bit key | Check how it is used |
| Already post-quantum | ML-KEM, ML-DSA, SLH-DSA or a hybrid group | Keep it |

Code findings come from patterns, so a mention in a comment or a string counts too; every finding shows the file and line so you can judge it.

## Formats

- `text` (default): a summary grouped by category and algorithm.
- `markdown`: a report to share or attach to a ticket.
- `json`: every finding with category, algorithm, primitive, NIST quantum security level, location, line and rule.
- `cbom`: a CycloneDX 1.6 cryptography bill of materials (ECMA-424) with one component per algorithm and its evidence, plus TLS protocol and certificate components.

## In CI

```bash
psion scan --fail-on quantum-vulnerable --format markdown -o quantum-readiness.md
```

The command exits with status 2 when findings of the chosen kind exist (`quantum-vulnerable`, or `weak`, which includes quantum-vulnerable), 1 on errors, and 0 otherwise.
