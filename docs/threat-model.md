# Threat model

## What pSIONIUM protects

| Asset | Protection |
|---|---|
| File contents | AES-256-GCM under a fresh 256-bit key per file. Only listed recipients can recover the key. |
| File keys in transit and storage | Wrapped for each recipient with X25519 + ML-KEM-768 (or ML-KEM-1024). Recording a file today and breaking classical cryptography later with a quantum computer does not reveal it. |
| Integrity | Every byte is authenticated: the header by HMAC-SHA-384, the payload by per-chunk AES-GCM tags with chunk numbers and a final-chunk flag, signed files by ML-DSA. Changing, reordering, truncating or extending a file is detected. |
| Sender identity | Optional ML-DSA signature over the whole file. `psion decrypt --signed-by` refuses files that are unsigned or signed by anyone else. |
| Secret keys at rest | Identity files are passphrase-protected by default (Argon2id, 64 MiB, then AES-256-GCM) and created readable only by their owner. |

## Attackers considered

- **Network and storage attackers** who can read, record, modify, drop or reorder files, including ones with a future quantum computer. They learn file sizes, the suite, recipient key identifiers and the signer's verifying key, and nothing else.
- **Recipients acting maliciously.** A recipient knows the file key. They can read the file (by design), re-encrypt it, and remove or replace the sender's signature. They cannot forge another sender's signature, so readers who require a specific signer detect this.
- **Someone who steals an identity file.** Without the passphrase they must guess it against Argon2id. Weak passphrases remain guessable; `psion` requires at least 8 characters, and longer ones are better.
- **Crafted input.** Malformed files, keys and identity files are rejected without panics (tested with thousands of random mutations). Hostile passphrase parameters are rejected before any memory is allocated.

## Not protected

- A compromised machine where the identity is unlocked, or the plaintext before encryption and after decryption.
- Metadata: file size (to within 16 bytes per chunk), timing, who the recipients are by key identifier.
- Deniability: a signed file proves who signed it to anyone holding the verifying key.
- Forward secrecy for stored files: whoever later obtains a recipient's secret key can decrypt files sent to it. Rotate identities if a key may have leaked.
- Side channels in the host environment. Constant-time behaviour relies on AWS-LC.

## Assumptions

- AWS-LC's ML-KEM, ML-DSA, X25519, AES-GCM, HKDF, HMAC and SHA-384 and RustCrypto's Argon2id are correct, and the operating system's random number generator is sound.
- At least one of X25519 and ML-KEM-768 remains secure (hybrid suite), or ML-KEM-1024 does (CNSA suite).
- Users check verifying keys through a trusted channel before relying on `--signed-by`.

## Review status

The format is specified in `docs/psen-v2.md`. It has not yet been independently reviewed; that review is a release requirement for regulated customers.
