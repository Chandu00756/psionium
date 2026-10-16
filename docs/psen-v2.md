# The `.psen` v2 file format

Status: draft 1 (2026-10-16). Implemented by `crates/psionium-core`.

`.psen` v2 encrypts one file (or stream) to one or more recipients with post-quantum key establishment. It uses only standardized primitives:

| Purpose | Suite 0x0001 `pq-hybrid-768` (default) | Suite 0x0002 `cnsa-1024` |
|---|---|---|
| Key establishment | X25519 + ML-KEM-768 (FIPS 203), hybrid | ML-KEM-1024 (FIPS 203) |
| Key derivation | HKDF-SHA-384 (RFC 5869) | HKDF-SHA-384 |
| Key wrapping and data | AES-256-GCM (SP 800-38D) | AES-256-GCM |
| Header authentication | HMAC-SHA-384 | HMAC-SHA-384 |
| Key identifiers | SHA-384, truncated to 16 bytes | SHA-384, truncated to 16 bytes |

The hybrid suite stays secure if either X25519 or ML-KEM-768 is broken. The `cnsa-1024` suite uses only algorithms in NSA's CNSA 2.0 suite.

All integers are big-endian. `‖` is concatenation. `HKDF(salt, ikm, info, L)` is HKDF-SHA-384 extract-then-expand producing `L` bytes.

## Keys

A recipient key pair belongs to exactly one suite.

| Suite | Public key bytes `pk` | Secret key bytes `sk` |
|---|---|---|
| 0x0001 | `x25519_pk (32) ‖ mlkem768_ek (1184)` | `x25519_sk (32) ‖ mlkem768_dk (2400)` |
| 0x0002 | `mlkem1024_ek (1568)` | `mlkem1024_dk (3168)` |

Text encodings use unpadded base64url:

- Public key: `psionpk:` ‖ base64url(`suite (2) ‖ pk`)
- Secret key: `psionsk:` ‖ base64url(`suite (2) ‖ sk`)

Key identifier: `key_id = SHA-384(suite ‖ pk)[0..16]`.

An identity file is UTF-8 text. Lines starting with `#` are comments; the first line starting with `psionsk:` is the secret key. Implementations create identity files readable only by their owner.

## File layout

```
header   magic "PSEN" (4) ‖ version 0x02 (1) ‖ suite (2) ‖ chunk_log2 (1) ‖ salt (16) ‖ n (1)
         n × stanza
         header_mac (48)
payload  one or more encrypted chunks
```

- `chunk_log2` is between 12 and 24; the default is 16 (64 KiB chunks).
- `salt` is 16 random bytes, fresh for every file.
- `n` is the number of recipients, from 1 to 64.

The first 25 bytes (magic through `n`) are the header prefix, `prefix`.

### Recipient stanza

```
key_id (16) ‖ kem_ct ‖ wrapped_file_key (48)
```

| Suite | `kem_ct` | Size |
|---|---|---|
| 0x0001 | `eph_x25519_pk (32) ‖ mlkem768_ct (1088)` | 1120 |
| 0x0002 | `mlkem1024_ct (1568)` | 1568 |

## Encryption

1. Generate a random 32-byte `file_key` and a random 16-byte `salt`.
2. For each recipient with public key `pk`:
   - Suite 0x0001: generate an ephemeral X25519 key pair `(e_sk, e_pk)`. Compute `ss_x = X25519(e_sk, x25519_pk)` and `(ct_m, ss_m) = ML-KEM-768.Encaps(mlkem768_ek)`. Set `kem_ct = e_pk ‖ ct_m` and `ikm = ss_m ‖ ss_x`. The info string binds the transcript: `info = "psionium/v2/kek" ‖ suite ‖ key_id ‖ kem_ct ‖ x25519_pk`.
   - Suite 0x0002: `(ct_m, ss_m) = ML-KEM-1024.Encaps(mlkem1024_ek)`, `kem_ct = ct_m`, `ikm = ss_m`, `info = "psionium/v2/kek" ‖ suite ‖ key_id ‖ kem_ct`.
   - `kek = HKDF(salt, ikm, info, 32)`.
   - `wrapped_file_key = AES-256-GCM-Seal(kek, nonce = 0^12, aad = prefix ‖ key_id, file_key)`. Each `kek` is used once, so the fixed nonce is safe.
3. `mac_key = HKDF(salt, file_key, "psionium/v2/header-mac", 48)` and `header_mac = HMAC-SHA-384(mac_key, all header bytes before header_mac)`.
4. `payload_key = HKDF(salt, file_key, "psionium/v2/payload", 32)`.
5. Split the plaintext into chunks of `2^chunk_log2` bytes. The last chunk is the final chunk; it may be full, and it is empty only when the whole plaintext is empty. Chunk `i` (from 0) is `AES-256-GCM-Seal(payload_key, nonce_i, aad = empty, chunk_i)` where `nonce_i = i as 11 bytes ‖ final_flag (1)` and `final_flag` is 0x01 for the final chunk and 0x00 otherwise.

## Decryption

1. Parse the header; reject an unknown magic, version or suite, a `chunk_log2` outside 12–24, or `n` outside 1–64.
2. For every stanza whose `key_id` matches the identity, derive `kek` as above (decapsulating instead of encapsulating) and open `wrapped_file_key`. If no stanza opens, the identity is not a recipient.
3. Derive `mac_key` and verify `header_mac` in constant time before reading the payload.
4. Read encrypted chunks of `2^chunk_log2 + 16` bytes. A chunk is final if it is shorter than that or if no data follows it. Open each chunk with its nonce. Fail if a chunk does not open, if data follows the final chunk, or if the stream ends before a final chunk.

Plaintext from chunks that opened is authentic, but the file as a whole is only authentic once the final chunk opens. Tools that write to disk write to a temporary file and keep it only when decryption completes.

## Security notes

- Recipient `key_id`s are visible in the header, so files reveal which public keys they were encrypted to.
- The format does not authenticate the sender. A future version adds an optional ML-DSA signature (FIPS 204).
- Changing recipients or algorithms means re-wrapping `file_key` and rewriting the header; the payload stays the same, but `header_mac` must be recomputed.
