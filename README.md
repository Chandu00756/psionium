# pSIONIUM

Post-quantum protection for the data you keep. `psion` encrypts and signs files with NIST's post-quantum algorithms, and `psion scan` finds the cryptography in your systems that quantum computers will break.

- **Encrypt** to one or more people with hybrid X25519 + ML-KEM-768 (FIPS 203), or ML-KEM-1024 for CNSA 2.0. AES-256-GCM in authenticated chunks streams files of any size in a few MB of memory.
- **Sign** with ML-DSA (FIPS 204) so recipients can prove who sent a file.
- **Protect keys** with a passphrase (Argon2id) by default.
- **Scan** source code, dependencies, certificates, SSH keys and live TLS servers for RSA, elliptic curves, Diffie-Hellman and DSA, and export a CycloneDX 1.6 CBOM.

All cryptographic primitives come from [AWS-LC](https://github.com/aws/aws-lc) via `aws-lc-rs`, except Argon2id passphrase hashing, which comes from RustCrypto's [`argon2`](https://crates.io/crates/argon2). pSIONIUM's own crates contain no `unsafe` code.

> **Status:** the format and code have not yet had an independent cryptographic review. Until they have, don't rely on pSIONIUM alone for data you cannot afford to lose. See [SECURITY.md](SECURITY.md) and [the threat model](docs/threat-model.md).

## Install

On macOS (Apple silicon or Intel) and Linux (x86-64 or ARM64, any distribution):

```bash
curl -fsSL https://raw.githubusercontent.com/Chandu00756/psionium/main/install.sh | sh
```

The script downloads the release for your machine, checks it against the release's `SHA256SUMS`, and installs `psion` to `~/.local/bin` (set `PSION_INSTALL_DIR` to change it, `PSION_VERSION=v1.0.0` to pin a version). It needs only `curl` or `wget`.

On Windows, or to install by hand, download the archive for your platform from the [releases page](https://github.com/Chandu00756/psionium/releases), check it with `sha256sum --check --ignore-missing SHA256SUMS`, and put `psion` on your `PATH`. On macOS, a binary downloaded with a web browser is quarantined; run `xattr -d com.apple.quarantine psion` once to allow it.

To build from source with Rust 1.88 or later:

```bash
cargo install --locked --git https://github.com/Chandu00756/psionium psion
```

## Quick start

```bash
# Create your identity (asks for a passphrase) and share the printed public key.
psion keygen -o ~/.psion/me.key

# Encrypt to a colleague, signed as you.
psion encrypt -r psionpk:… --sign-with ~/.psion/me.key quarterly.xlsx      # writes quarterly.xlsx.psen

# Decrypt, and insist it came from them.
psion decrypt -i ~/.psion/me.key --signed-by psionvk:… quarterly.xlsx.psen

# Find quantum-vulnerable cryptography in a project and on a server.
psion scan ./my-app --tls api.example.com
```

## Commands

| Command | What it does |
|---|---|
| `psion keygen [-o FILE] [--suite pq-hybrid-768\|cnsa-1024]` | New identity: decryption and signing keys. Prints the public key (`psionpk:`). Passphrase protected unless `--no-passphrase`. |
| `psion pubkey -i FILE [--verify-key]` | Prints the public key, or the verifying key (`psionvk:`) others use to check your signatures. |
| `psion encrypt -r KEY… [-R FILE] [--sign-with IDENTITY] [-o OUT] [INPUT]` | Encrypts to every recipient. Reads standard input and writes standard output when no files are given. |
| `psion decrypt -i IDENTITY [--signed-by KEY…] [-o OUT] [INPUT]` | Decrypts and reports the signature. With `--signed-by`, unsigned files and other signers are refused. |
| `psion inspect FILE` | Shows a file's suite, chunk size, recipients and signer without decrypting. |
| `psion passphrase -i IDENTITY [--remove]` | Adds, changes or removes an identity's passphrase. |
| `psion scan [PATH…] [--tls HOST[:PORT]…] [--format text\|markdown\|json\|cbom] [--fail-on quantum-vulnerable\|weak]` | Quantum-readiness scan. Exit status 2 with `--fail-on` when matching findings exist. |

For scripts, `--passphrase-file FILE` reads a passphrase from the first line of a file instead of prompting, and `-` as a file name means standard input or output.

Decrypting to standard output streams plaintext as it is authenticated, chunk by chunk; the command fails at the end if the file is truncated or its signature is missing or wrong. When writing to a file, `psion` keeps the output only if everything checks out.

## Documentation

- [Project folder](project/README.md): vision, current status, roadmap and working rules; start here if you are picking up the project
- [The `.psen` v2 format](docs/psen-v2.md), with an independent [Go implementation](interop/go) that CI checks against `psion` in both directions
- [pSIONIUM Scan](docs/scan.md)
- [Threat model](docs/threat-model.md)
- [Production readiness checklist](docs/production-readiness.md)
- [Security policy](SECURITY.md) and [changelog](CHANGELOG.md)

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo build -p psion && (cd interop/go && PSION=../../target/debug/psion go test ./...)
```

The suite covers round trips at every chunk boundary for both suites, several recipients, signatures and required signers, passphrase protection, committed test vectors, thousands of random file corruptions (`PSIONIUM_MUTATIONS=200000` for a longer run), the scanner against a fixture project and live local TLS servers, the command line end to end, and interoperability with a second implementation written from the specification.

The `legacy` branch holds the original pSIONIUM code recovered from VS Code's local history on 2026-10-16; it is reference only.

## License

Apache-2.0. See [LICENSE](LICENSE).
