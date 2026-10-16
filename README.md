# pSIONIUM

Post-quantum protection for the data companies keep: files, secrets and application fields.

pSIONIUM 3 is being rebuilt from scratch on NIST-standard algorithms (ML-KEM, ML-DSA, SLH-DSA, AES-256). The product plan is in the PORTAL VII workspace.

## Branches

- `main`: pSIONIUM 3 (new work starts here).
- `legacy`: the original pSIONIUM code (Python backend, Rust 2.0 workspace, Flutter app), recovered from VS Code's local history on 2026-10-16 after the original repository was lost. Reference only; nothing in it is production-ready.

## Ground rules

- No home-made cryptography on the encryption path; standard algorithms from production libraries only.
- Hybrid key exchange by default (X25519 + ML-KEM-768); a CNSA 2.0 suite for customers who need it.
- Every encrypted object records its algorithm suite so keys can be re-wrapped as standards change.
- Never commit credentials.
