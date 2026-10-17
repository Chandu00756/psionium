# Decisions

Newest first. Each entry: the decision, why, and what would make us revisit it.

## 2026-10-16 — How the shell is built
- **The shell runs `psion` itself.** Guided screens and the `pSIONIUM>` prompt run the same binary as a child process with captured output, so the shell and scripting mode cannot disagree and output never corrupts the full screen. Scans run in-process on a thread for live progress.
- **Passphrases go through a pipe.** `--passphrase-file -` reads one line from standard input; the shell writes the passphrase there, never to a file, an argument or the environment, and clears the field. Children get `PSION_NO_PROMPT=1`, so a command typed at the prompt fails with a clear message instead of grabbing the terminal; `psion --plain` runs commands in-process for people who want to type passphrases.
- **`:` opens a Console screen** rather than a one-line overlay: its bottom line is the `pSIONIUM>` prompt and its body keeps the output, like the original terminal. `design/05` is annotated.
- **Settings live in `config.toml`** under `$PSION_CONFIG_DIR`, `%APPDATA%\psion`, `$XDG_CONFIG_HOME/psion` or `~/.config/psion`; identities created in the shell go to `~/.psion` (0700), which the README already uses.
- **`psion` with no command opens the shell only in a terminal**; otherwise the usage error (exit 2) is unchanged, so scripts behave as before.
**Why:** one source of truth for behaviour, no secrets on disk, and no change for existing scripts. **Revisit:** when the account features need a long-lived API client in the shell (Stage 3), which may move work in-process.

## 2026-10-16 — D11: shell and app brand (owner)
Keep the pSIONIUM name and the PORTAL VII pyramid; the default `portal` theme uses violet/pink accents, and the `classic` theme keeps the original green-on-black terminal. **Why:** owner approved the recommendation in `design/14`. **Revisit:** a rebrand of PORTAL VII.

## 2026-10-16 — Scan baselines and fingerprints
Findings get a `fingerprint`: the first 128 bits of SHA-256 over a version label, the rule, the path relative to the scanned folder and the trimmed matched line (or the finding's detail for keys, certificates and dependencies), never the line number, and never secret key bytes. A second identical match in the same file gets a fingerprint derived from the first and its occurrence number. The baseline (`.psionium-scan.toml`, TOML as `design/10` says) matches on fingerprints only, requires a reason for each entry, rejects unknown keys, and is read automatically from the current folder. Accepted findings leave the counts and `--fail-on` but stay in the CBOM (an inventory) and appear in SARIF as suppressions. SARIF leaves out TLS endpoints (code scanning needs a file) and post-quantum findings (inventory, not problems). **Why:** CI must fail only on new findings without breaking on unrelated edits, and typos in a security allowlist must not pass silently. **Revisit:** if users need line-insensitive matching across file renames, or custom rules land in the same file.

## 2026-10-16 — Platform design adopted (owner request)
The owner asked for the full business platform to be designed end to end before more building: interactive shell, accounts, secure transfer, web and apps, licensing, admin, back office. The design is `project/design/` (01–14). **Why:** so any agent builds the same thing in the same order. **Revisit:** through the change process in `design/README.md`.

## 2026-10-16 — Open core with service-enforced licensing
The core, format and local CLI stay free and open source; paid features are those that need the service or a signed license file (self-hosted), enforced server-side. **Why:** licensing code inside open-source software can be removed, and keeping the core open builds trust. Details: `design/08-licensing.md`.

## 2026-10-16 — Accounts and a Key Directory replace manual key exchange
People find each other by email/handle; public keys come from a Directory with a transparency log and client-side key-change warnings; device keys and an Account Key let one identity work on many devices; recovery by another device, Recovery Kit, or org escrow. **Why:** copying keys by hand does not work for a business product. Details: `design/03-security-model.md`.

## 2026-10-16 — Guest links carry the key in the URL fragment
Recipients without accounts open files in the browser; the decryption key is in the `#fragment`, never sent to the server, optionally combined with a passcode and email one-time code. **Why:** "send like WhatsApp" to anyone, without breaking zero knowledge. Needs `.psen` v3 and review.

## 2026-10-16 — Managed decryption only as an opt-in enterprise exception
Org-held keys in the customer's own KMS/HSM and a customer-hosted worker; users are told. **Why:** some regulated customers must archive or scan files; PORTAL VII still never holds plaintext.

## 2026-10-16 — Cloud reuses TaskFlow's stack
Go services, PostgreSQL, Redis, Next.js, Docker Compose on Oracle Cloud first; crypto only in the Rust core (WASM/FFI to clients). **Why:** proven in production by the same owner; less to learn and operate.

## 2026-10-16 — The interactive shell lives in the same `psion` binary
`psion` alone opens the full-screen shell; `psion <command>` stays the scripting interface, unchanged. The original pSIONIUM terminal look (black, bold green, `pSIONIUM>` prompt) is kept as the `classic` theme. **Why:** one tool to install, and scripts never break.

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
