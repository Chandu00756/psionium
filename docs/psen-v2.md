# The `.psen` v2 file format

Status: draft 2 (2026-10-16), proposed for freezing at pSIONIUM 1.0. Implemented by `crates/psionium-core` and, independently from this document alone, by `interop/go`; CI checks that each reads the other's files and that both read the committed test vectors.

`.psen` v2 encrypts one file (or stream) to one or more recipients with post-quantum key establishment, and can sign it so recipients know who sent it. It uses only standardized primitives:

| Purpose | Suite 0x0001 `pq-hybrid-768` (default) | Suite 0x0002 `cnsa-1024` |
|---|---|---|
| Key establishment | X25519 + ML-KEM-768 (FIPS 203), hybrid | ML-KEM-1024 (FIPS 203) |
| Sender signatures | ML-DSA-65 (FIPS 204) | ML-DSA-87 (FIPS 204) |
| Key derivation | HKDF-SHA-384 (RFC 5869) | HKDF-SHA-384 |
| Key wrapping and data | AES-256-GCM (SP 800-38D) | AES-256-GCM |
| Header authentication | HMAC-SHA-384 | HMAC-SHA-384 |
| Transcript hash, key identifiers | SHA-384 | SHA-384 |

The hybrid suite stays secure if either X25519 or ML-KEM-768 is broken. The `cnsa-1024` suite uses only algorithms in NSA's CNSA 2.0 suite.

All integers are big-endian. `‖` is concatenation. `HKDF(salt, ikm, info, L)` is HKDF-SHA-384 extract-then-expand producing `L` bytes. Labels are ASCII without a terminator.

## Keys

An identity has a decryption key pair and, normally, a signing key pair, all in one suite.

| Suite | Public key `pk` | Secret key `sk` | Verifying key `vk` | Signing key |
|---|---|---|---|---|
| 0x0001 | `x25519_pk (32) ‖ mlkem768_ek (1184)` | `x25519_sk (32) ‖ mlkem768_dk (2400)` | ML-DSA-65 public key (1952) | ML-DSA-65 seed (32) |
| 0x0002 | `mlkem1024_ek (1568)` | `mlkem1024_dk (3168)` | ML-DSA-87 public key (2592) | ML-DSA-87 seed (32) |

`mlkem*_dk` is the FIPS 203 decapsulation key, which embeds `ek` and `SHA3-256(ek)`; implementations recover `ek` from it and check the hash.

Text encodings use unpadded base64url, each prefixed by the suite (2 bytes):

| Prefix | Contents | Secret |
|---|---|---|
| `psionpk:` | suite ‖ `pk` | no |
| `psionvk:` | suite ‖ `vk` | no |
| `psionsk:` | suite ‖ `sk` | yes |
| `psionss:` | suite ‖ ML-DSA seed | yes |
| `psionpe:` | passphrase-protected secret lines (below) | yes |

Key identifier: `key_id = SHA-384(suite ‖ pk)[0..16]`, and likewise for verifying keys.

### Identity files

UTF-8 text. Lines starting with `#` are comments; implementations write the public and verifying keys as `# public key: psionpk:…` and `# verify key: psionvk:…` comments. The first `psionsk:` line is the decryption key and the first `psionss:` line, if any, the signing key. Implementations create identity files readable only by their owner.

A passphrase-protected identity replaces the secret lines with one `psionpe:` line:

```
version 0x01 (1) ‖ m_cost KiB (4) ‖ t_cost (4) ‖ p_cost (1) ‖ salt (16) ‖ nonce (12) ‖ ciphertext ‖ tag (16)
key        = Argon2id (RFC 9106, version 0x13)(passphrase, salt, m_cost, t_cost, p_cost, 32 bytes)
ciphertext = AES-256-GCM-Seal(key, nonce, aad = the 38 bytes before the ciphertext, secret lines joined with "\n")
```

The defaults are 64 MiB, 3 passes and 1 lane. Readers reject parameters above 1 GiB, 16 passes or 16 lanes before deriving, so a crafted file cannot exhaust memory.

## File layout

```
header    magic "PSEN" (4) ‖ version 0x02 (1) ‖ suite (2) ‖ chunk_log2 (1) ‖ flags (1) ‖ salt (16) ‖ n (1)
          n × stanza
          vk (signed files only)
          header_mac (48)
payload   one or more encrypted chunks
trailer   signature (signed files only: 3309 bytes for 0x0001, 4627 bytes for 0x0002)
```

- `chunk_log2` is between 12 and 24; the default is 16 (64 KiB chunks).
- `flags`: bit 0 set means the file is signed. Readers reject any other bit.
- `salt` is 16 random bytes, fresh for every file.
- `n` is the number of recipients, from 1 to 64.

The first 26 bytes (magic through `n`) are the header prefix, `prefix`.

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
   - Suite 0x0001: generate an ephemeral X25519 key pair `(e_sk, e_pk)`. Compute `ss_x = X25519(e_sk, x25519_pk)` and `(ct_m, ss_m) = ML-KEM-768.Encaps(mlkem768_ek)`. Set `kem_ct = e_pk ‖ ct_m`, `ikm = ss_m ‖ ss_x` and `info = "psionium/v2/kek" ‖ suite ‖ key_id ‖ kem_ct ‖ x25519_pk`, which binds the transcript.
   - Suite 0x0002: `(ct_m, ss_m) = ML-KEM-1024.Encaps(mlkem1024_ek)`, `kem_ct = ct_m`, `ikm = ss_m`, `info = "psionium/v2/kek" ‖ suite ‖ key_id ‖ kem_ct`.
   - `kek = HKDF(salt, ikm, info, 32)`.
   - `wrapped_file_key = AES-256-GCM-Seal(kek, nonce = 0^12, aad = prefix ‖ key_id, file_key)`. Each `kek` is used once, so the fixed nonce is safe.
3. For a signed file, append the sender's verifying key `vk`.
4. `mac_key = HKDF(salt, file_key, "psionium/v2/header-mac", 48)` and `header_mac = HMAC-SHA-384(mac_key, all header bytes before header_mac)`.
5. `payload_key = HKDF(salt, file_key, "psionium/v2/payload", 32)`.
6. Split the plaintext into chunks of `2^chunk_log2` bytes. The last chunk is the final chunk; it may be full, and it is empty only when the whole plaintext is empty. Chunk `i` (from 0) is `AES-256-GCM-Seal(payload_key, nonce_i, aad = empty, chunk_i)` where `nonce_i = i as 11 bytes ‖ final_flag (1)` and `final_flag` is 0x01 for the final chunk and 0x00 otherwise.
7. For a signed file, `signature = ML-DSA.Sign(signing_key, "psionium/v2/signature" ‖ SHA-384(header ‖ payload))` with an empty context string, where `header` includes `header_mac`.

## Decryption

1. Parse the header; reject an unknown magic, version, suite or flag, a `chunk_log2` outside 12–24, or `n` outside 1–64.
2. For every stanza whose `key_id` matches the identity, derive `kek` as above (decapsulating instead of encapsulating) and open `wrapped_file_key`. If no stanza opens, the identity is not a recipient.
3. Derive `mac_key` and verify `header_mac` in constant time before reading the payload.
4. Read encrypted chunks of `2^chunk_log2 + 16` bytes; for a signed file, the last signature-length bytes of the input are the trailer, not payload. A chunk is final if it is shorter than a full block or if no payload follows it. Open each chunk with its nonce. Fail if a chunk does not open or if the payload ends before a final chunk.
5. For a signed file, check that the trailer has the signature's exact length and verify it with `vk` over the header and payload.

Plaintext from chunks that opened is authentic, but the file as a whole is only authentic, and its signature only checked, once the whole input is read. Tools that write to disk write to a temporary file and keep it only when decryption completes.

## Security notes

- A valid signature proves that the holder of `vk` produced exactly this file for exactly these recipients. Whether `vk` belongs to the expected sender is for the reader to check: tools take the expected verifying keys from the user and refuse other or missing signatures.
- Any recipient knows `file_key`, so a recipient can remove a signature (clearing the flag and recomputing `header_mac`) or replace it with their own. Readers that require a particular sender detect both.
- Recipient `key_id`s and the signer's `vk` are visible in the header, so files reveal which keys they involve.
- Changing recipients means re-wrapping `file_key` and rewriting the header; the payload stays the same, but `header_mac` and any signature must be recomputed.
