# Decisions

Newest first. Each entry: the decision, why, and what would make us revisit it.

## 2026-10-16 — Independent Go implementation as a CI gate
A second implementation written only from `docs/psen-v2.md` (Go standard library ML-KEM/X25519/HKDF/AES-GCM, CIRCL for ML-DSA and expanded ML-KEM keys) must read psion's files and write files psion reads. **Why:** proves the spec is complete and that AWS-LC agrees with independent implementations, short of an external audit. **Revisit:** never remove; extend when the format grows.

## 2026-10-16 — Release attestations only on a public repository
The release workflow skips build provenance when the repo is private. **Why:** GitHub Free/Pro/Team only offer artifact attestations on public repositories; a private release would otherwise fail. **Revisit:** if the account moves to GitHub Enterprise Cloud.

## 2026-10-16 — `-` means standard input/output in the CLI
**Why:** `-o -` created a file literally named `-`; every common tool treats `-` as stdio.

## 2026-10-16 — Open source under Apache-2.0
Core, format and scanner are open source. **Why:** in cryptography, open code earns trust and adoption; the paid value is the service, apps, policy and compliance. **Revisit:** only for future proprietary service code, never for the core.

## 2026-10-16 — Scan first, core in parallel, Vault after
**Why:** Scan is the cheapest way to reach customers and shows them the problem; the core had to exist before Vault. **Revisit:** if design partners pull hard for Vault earlier.

## 2026-10-16 — `.psen` v2 design
One random 256-bit file key per file; one stanza per recipient; hybrid X25519 + ML-KEM-768 (or ML-KEM-1024 for CNSA) with HKDF-SHA-384 over the full transcript; AES-256-GCM 64 KiB chunks with counter + final flag; HMAC-SHA-384 header; optional ML-DSA signature over SHA-384(header ‖ payload); a flags byte for extensions. Modeled on age and HPKE. **Why:** standard primitives, streaming, crypto agility via the suite field. **Revisit:** only through a new format version and spec review.

## 2026-10-16 — Expanded ML-KEM decapsulation keys in identity files
Identity files store the FIPS 203 expanded decapsulation key, from which the encapsulation key is recovered and hash-checked. **Why:** aws-lc-rs's raw import cannot re-derive the public key. **Note:** Go's standard library only imports seed-form keys, which is why the Go interop uses CIRCL for decapsulation.

## 2026-10-16 — Standard algorithms only; research off the encryption path
DIBLE, chaos-based entropy and other research ideas from the original pSIONIUM are not used for encryption. **Why:** a security product lives or dies by its first review; unreviewed constructions would sink it. **Revisit:** after a research idea is published and independently reviewed.

## 2026-10-16 — Rebuild as pSIONIUM 3 instead of restoring the lost code
The original repository was lost; 114 files were recovered to the `legacy` branch as reference. **Why:** the recovered code relied on prototype libraries (liboqs Kyber) and had placeholder cryptography; a clean, standards-based core was safer and faster.

## 2026-10-16 — Remove unverifiable claims from portalvii.com
"ISO 27001 certified", "GDPR, HIPAA, PCI DSS", uptime and usage numbers are removed until audited or measured. **Why:** false compliance claims are a legal and trust risk, especially for a security product.
