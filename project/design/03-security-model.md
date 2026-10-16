# 03 · Security model

This is the contract every component must keep. If a feature cannot be built inside it, the feature changes, not the model.

## Goals

1. **Zero knowledge.** PORTAL VII's servers store ciphertext, public keys and wrapped (encrypted) private keys only. A full server breach reveals metadata, never content.
2. **Post-quantum by default.** Every key exchange and signature uses the `.psen` suites: X25519 + ML-KEM-768 with ML-DSA-65 (default), ML-KEM-1024 with ML-DSA-87 (CNSA mode). Symmetric: AES-256-GCM, HKDF-SHA-384, Argon2id.
3. **No key copying by hand.** People find each other by email or handle; keys travel through the Key Directory, and the UI makes key changes visible.
4. **Nobody gets locked out silently.** Every account has at least one recovery path, chosen and confirmed at sign-up.
5. **Honest metadata.** We say exactly what the server can see.

## Key hierarchy (per user)

```
 Identity keys  (psion identity: X25519 + ML-KEM decryption keys, ML-DSA signing key)
     └── encrypted under ── Account Key (AK, random 256-bit, one per user)
                                 ├── wrapped for each approved Device Key  (one per device/browser)
                                 ├── wrapped for the Recovery Kit key      (from the 128-bit recovery code, Argon2id)
                                 └── wrapped for the Org Escrow key        (only if org policy enables admin recovery)
```

- **Identity keys** are what other people encrypt to and verify against. One identity per user (not per device), so a sender encrypts once per recipient. Rotating identity keys is supported (new version in the Directory; old versions kept to open old files).
- **Device keys** are hybrid KEM key pairs generated on the device and stored in the OS keychain (macOS Keychain, Windows DPAPI/Credential Manager, Android Keystore, iOS Keychain with Secure Enclave–protected access control, Linux Secret Service). Biometric unlock where available. Browsers: the device key is kept in IndexedDB, encrypted under a non-extractable WebCrypto AES key; org policy can forbid persistent browser devices (unlock per session instead).
- **Account Key** never exists in plaintext anywhere but a client's memory.
- **Password / passkey** authenticate the session; they do **not** derive encryption keys. So a password reset never destroys data, and a stolen password alone cannot decrypt anything (it still needs an approved device or the Recovery Kit).

## Devices

- **Add a device:** sign in (passkey/password + MFA, or SSO) → the new device shows a QR code / 6-word code → an existing device scans or confirms it → the two devices run an authenticated hybrid KEM handshake and the existing device wraps AK for the new device key. Alternative: enter the Recovery Kit code. Org option: k-of-n admin approval (escrow).
- **Remove a device:** from settings or the admin console. Its wrapped AK is deleted and its sessions revoked. If the device is suspected compromised, the user (or policy) rotates AK and identity keys.
- The device list shows name, platform, last seen, approved by whom.

## Recovery

| Path | Who holds it | Default |
|---|---|---|
| Another approved device | User | Always |
| Recovery Kit (printable code + QR) | User, offline | Required at sign-up for individuals |
| Org escrow (k-of-n admins, Shamir-split escrow key, or customer KMS/HSM) | Organization | Off; org policy can require it |

Without any path, data is unrecoverable; the product states this in sign-up, in settings, and in docs.

## Key Directory and transparency

- The Directory maps each verified account (email, handle) to its current `psionpk:` and `psionvk:` plus history.
- Every change is appended to a **transparency log** (Merkle tree, root signed with the directory's ML-DSA key, roots published hourly and mirrored to a public Git repository). Clients verify inclusion and consistency proofs for keys they use.
- Clients remember the keys they have seen (trust on first use) and show **"Ravi's keys changed"** banners when a key changes, until the user reviews it.
- **Verified contacts:** two people compare a safety code (QR or 60-digit number) once; the contact is marked verified. Orgs can mark all members' keys as verified through domain verification + SSO.
- Senders always see whether a recipient is verified, unverified, or new.

## Transfers (summary; full design in 04)

- Files are encrypted on the sender's device with the recipient identities as `.psen` recipients and signed with the sender's ML-DSA key. Metadata that is sensitive (file names, subject, message) is encrypted in the same envelope.
- Guest links use a fresh 256-bit link key carried only in the URL fragment (`#…`), optionally combined with a passcode (Argon2id) and email one-time code. Needs a format extension (symmetric recipient stanza) specified in a new `docs/psen-v3.md` (to be written in Stage 3) before use.
- Receivers verify the signature against the sender's Directory verify key before showing **Signed by sender**.

## Managed decryption (enterprise only, opt-in)

Some regulated companies must archive, scan (DLP/antivirus) or e-discover company files. For orgs that enable it:
- An **org key** (held in the customer's KMS/HSM, never by PORTAL VII) is added as an extra recipient on transfers inside or from that org.
- A **managed decryption worker** runs in the customer's environment, decrypts for archiving/scanning, and logs every access to the audit log.
- Users see a permanent notice: **"Your organization can access files sent with your work account."**
- This is the only exception to zero knowledge, and it is the customer's, not PORTAL VII's.

## What the server can see

| Visible to PORTAL VII | Not visible |
|---|---|
| Accounts, emails, org membership, devices (names, platforms), IP addresses, timestamps | File contents |
| Who sent a transfer to whom, file count, ciphertext sizes, expiry, delivery and open events | File names, subjects, messages, folder names (encrypted) |
| Public keys, verify keys, wrapped key blobs | Private keys, Account Keys, link keys, passcodes, recovery codes |
| Plan, billing, usage counters | Anything inside a vault |

Retention: request logs 30 days, audit logs per org policy (default 1 year), deleted transfers purged within 24 hours (objects and wrapped keys).

## Transport and platform

- TLS 1.3 everywhere; prefer the X25519MLKEM768 hybrid group (Go 1.24+ supports it by default; check with `psion scan --tls`). HSTS, no TLS 1.0/1.1.
- Web: strict Content-Security-Policy, Subresource Integrity, no third-party scripts in the app or link origins, separate origin for guest links, cookies `HttpOnly; Secure; SameSite=Lax`, CSRF tokens on state changes.
- Sessions: short-lived access tokens + rotating refresh tokens; CLI/apps use the OAuth 2.0 device authorization flow and store tokens in the OS keychain.
- MFA: passkeys (WebAuthn) preferred, TOTP supported, SMS not offered for admins. Org policy can require passkeys.
- API keys: shown once, stored as hashes, scoped, revocable, with last-used tracking.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Server breach / malicious insider | Zero knowledge; wrapped keys only; staff access audited and limited to metadata |
| Key substitution by the server (man in the middle) | Transparency log, client-side key change warnings, verified contacts, org key pinning |
| Stolen laptop / phone | Keys in OS keychain behind device unlock/biometrics; remote device removal; AK rotation |
| Stolen password | Cannot decrypt without an approved device or Recovery Kit; MFA required |
| Phishing for the Recovery Kit | The product never asks for it except during recovery on the user's own device; education in UI |
| Malicious script on the link page | Separate origin, SRI-pinned minimal bundle, CSP, no third-party code |
| Quantum adversary recording traffic or storage | Hybrid ML-KEM everywhere (files and transport) |
| Abuse (malware or illegal content via guest links) | Cannot scan ciphertext; mitigated by account verification, rate limits, link limits, abuse reporting and takedown, sender identity shown to receivers |
| Downgrade or format confusion | Suite fields authenticated; unknown versions/flags rejected; test vectors |

## Things that need an outside review before launch

- `.psen` v3 additions (transfer metadata envelope, symmetric link stanza), device-linking handshake, recovery kit derivation, transparency log, license signing (08).
- Review gate: no paying customer data on the platform before the independent review of these is complete and findings fixed (`12-quality-security-ops.md`).
