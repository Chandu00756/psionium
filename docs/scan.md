# pSIONIUM Scan

`psion scan` shows where your software still depends on cryptography that a quantum computer breaks, so you can plan the move to post-quantum algorithms before NIST deprecates RSA and elliptic curves (after 2030) and disallows them (after 2035).

```bash
psion scan                                  # the current folder
psion scan ./service ./infra                # several folders
psion scan --tls api.example.com            # a live server only
psion scan . --tls api.example.com:8443 --format markdown -o quantum-readiness.md
psion scan --format html -o quantum-readiness.html   # a report for managers and auditors
```

## What it looks at

| Where | What it finds |
|---|---|
| Source code and configuration (40+ languages and formats) | RSA, ECDSA, ECDH, named curves, Ed25519, X25519, Diffie-Hellman, DSA; MD5, SHA-1, DES/3DES, RC4, TLS 1.0/1.1; ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS/LMS and hybrid groups such as X25519MLKEM768 |
| Dependency manifests (`package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`) | Crypto libraries, classified as quantum-vulnerable, to review, or post-quantum |
| Certificates (PEM and DER) | Key algorithm and size, signature algorithm, expiry; certificates still valid after 2030 are called out |
| Keys | SSH public keys (with RSA size), PEM and OpenSSH private keys. Private keys are reported by type and location only; their contents never appear in a report |
| TLS endpoints (`--tls`) | Whether the server accepts the X25519MLKEM768 post-quantum hybrid key exchange, its TLS version, cipher suite, preferred group, certificate, and whether the chain is publicly trusted |

The scan respects `.gitignore`, skips lock files (their integrity hashes are not crypto usage), binary files, files over 4 MB, the baseline file, paths listed under `ignore` in the baseline, and vendored dependencies (`node_modules`, `vendor`, virtualenvs, `target`) unless you pass `--include-dependencies`.

## Reading the results

| Category | Meaning | What to do |
|---|---|---|
| Quantum-vulnerable | Broken by a large quantum computer | Plan migration: ML-KEM (or X25519MLKEM768 hybrid) for key exchange, ML-DSA for signatures. Prioritize data that must stay secret for years, since it can be recorded now and decrypted later |
| Weak | Weak even without quantum computers | Replace now |
| Review | A general crypto library or a 128-bit key | Check how it is used |
| Already post-quantum | ML-KEM, ML-DSA, SLH-DSA or a hybrid group | Keep it |

Code findings come from patterns, so a mention in a comment or a string counts too; every finding shows the file and line so you can judge it. With `--no-excerpts`, code findings name the rule instead of quoting the line, so no source code appears in any report.

Every finding has a `fingerprint`: 32 hex characters from the rule, the file and the matched line's text, but not the line number, so it stays the same when code above it changes. If the same line appears twice in one file, the second copy gets its own fingerprint.

## Formats

- `text` (default): a summary grouped by category and algorithm.
- `markdown`: a report to share or attach to a ticket.
- `html`: one self-contained file (no scripts, no network requests, light and dark themes) with a summary, the NIST deadlines, a chart of algorithms, every finding with what to do about it, and TLS results. It opens offline and prints well.
- `json`: every finding with category, algorithm, primitive, NIST quantum security level, location, line, rule and fingerprint; accepted findings are under `accepted` with their reasons.
- `sarif`: SARIF 2.1.0 for GitHub code scanning and similar tools. Weak findings are errors, quantum-vulnerable ones warnings, review items notes; post-quantum findings and TLS endpoints (which have no file) are left out. Accepted findings carry a suppression with the baseline's reason.
- `cbom`: a CycloneDX 1.6 cryptography bill of materials (ECMA-424) with one component per algorithm and its evidence, plus TLS protocol and certificate components. Accepted findings stay in it, because it is an inventory.

## In CI

```bash
psion scan --fail-on quantum-vulnerable --format markdown -o quantum-readiness.md
```

The command exits with status 2 when findings of the chosen kind exist (`quantum-vulnerable`, or `weak`, which includes quantum-vulnerable), 1 on errors, and 0 otherwise. Findings accepted in the baseline never count.

To show findings in GitHub's Security tab:

```yaml
- run: psion scan --format sarif -o psionium.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: psionium.sarif
```

Paths in SARIF are relative to the current folder when you scan relative paths (run it from the repository root), or resolved against a `file://` base when you scan absolute ones.

## Baselines: fail only on new findings

An existing project usually has findings it cannot fix at once. Record them in a baseline, give each a reason, and commit it; CI then fails only when something new appears.

```bash
psion scan --write-baseline .psionium-scan.toml   # accept everything found today
$EDITOR .psionium-scan.toml                        # replace each placeholder reason
psion scan --fail-on quantum-vulnerable            # reads .psionium-scan.toml automatically
```

```toml
ignore = ["docs/", "**/testdata/**"]

[[accepted]]
location = "src/auth.go:12"
algorithm = "RSA"
rule = "rsa-api"
fingerprint = "abd89e3c761de5cdbdcd596fc4baf8d5"
reason = "Legacy signing for partner API; migration in SEC-12"
```

- `psion scan` reads `.psionium-scan.toml` from the current folder when it exists; `--baseline FILE` reads another file and `--no-baseline` reads none. The command says on standard error which baseline it used.
- Only `fingerprint` decides what is accepted; `location`, `algorithm` and `rule` are there for people. Every entry needs a non-empty `reason`, and unknown keys are rejected so typos do not pass silently.
- `ignore` takes `.gitignore`-style patterns relative to each scanned folder; those paths are not read at all.
- Accepted findings are listed separately in every report and never count toward `--fail-on`. Entries that no longer match anything (the code was fixed, or the line changed) are reported, and `--write-baseline` again drops them while keeping the reasons and `ignore` patterns you wrote.
