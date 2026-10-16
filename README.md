# pSIONIUM

Post-quantum protection for the data companies keep: files, secrets and application fields.

pSIONIUM 3 is being rebuilt from scratch on NIST-standard algorithms (ML-KEM, ML-DSA, SLH-DSA, AES-256). The product plan is in the PORTAL VII workspace.

## What works today

- **`psionium-core`** (Rust library): the [`.psen` v2 format](docs/psen-v2.md). Files are encrypted to one or more recipients with X25519 + ML-KEM-768 (or ML-KEM-1024 for CNSA 2.0) and AES-256-GCM in authenticated 64 KiB chunks. Built on AWS-LC (`aws-lc-rs`); no `unsafe` code.
- **`psion`** (command line): create identities, encrypt, decrypt and inspect files.

Measured on an Apple Silicon Mac: a 256 MB file encrypts or decrypts in about 0.2 s with 3.3 MB of memory; the size overhead is 16 bytes per 64 KiB plus a header of about 1.4 KB per recipient.

## Build and try

```bash
cargo build --release
./target/release/psion keygen -o me.key          # prints your public key (psionpk:…)
./target/release/psion encrypt -r psionpk:… report.pdf
./target/release/psion decrypt -i me.key report.pdf.psen
./target/release/psion inspect report.pdf.psen
```

Use `--suite cnsa-1024` with `keygen` for ML-KEM-1024 keys. `-R team.txt` encrypts to every public key listed in a file. Decryption writes to a temporary file and keeps it only when the whole file authenticates.

## Tests

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The tests cover round trips at every chunk boundary for both suites, several recipients, wrong keys, header and payload tampering, chunk reordering, truncation and extension, corrupted secret keys, and the command line end to end.

## Not yet done

- An independent review of the format and implementation. Until then, don't rely on it alone for irreplaceable data.
- Published test vectors, fuzzing, passphrase-protected identity files and hardware-backed keys.
- Sender signatures (ML-DSA) and the Scan, Vault and SDK products from the plan.

## Branches

- `main`: pSIONIUM 3 (new work starts here).
- `legacy`: the original pSIONIUM code (Python backend, Rust 2.0 workspace, Flutter app), recovered from VS Code's local history on 2026-10-16 after the original repository was lost. Reference only; nothing in it is production-ready.

## Ground rules

- No home-made cryptography on the encryption path; standard algorithms from production libraries only.
- Hybrid key exchange by default (X25519 + ML-KEM-768); a CNSA 2.0 suite for customers who need it.
- Every encrypted object records its algorithm suite so keys can be re-wrapped as standards change.
- Never commit credentials.
