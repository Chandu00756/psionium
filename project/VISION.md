# pSIONIUM vision

## In one sentence

pSIONIUM is how a company makes the data it keeps safe from quantum computers: it shows where the company is exposed, protects files, secrets and fields with post-quantum cryptography, and proves it to auditors.

## The problem

Almost everything stored today is protected, directly or indirectly, by RSA or elliptic-curve cryptography. A large quantum computer breaks both. Connections (TLS) are already moving to post-quantum on their own, because browsers and clouds upgraded them. **Stored data is the gap.** Contracts, health records, legal files, backups and secrets that are copied today can be decrypted later ("harvest now, decrypt later"), and much of that data has to stay secret for decades. Regulators and governments (NIST, NSA's CNSA 2.0, the EU) have set the direction: RSA and ECC are deprecated and then disallowed, and organizations must inventory and migrate their cryptography.

Large vendors serve large enterprises and defense. Mid-size regulated companies (health, finance, legal, government supply chains) and the developers who build their software have nothing simple, affordable and trustworthy.

## The end outcome

pSIONIUM becomes the post-quantum data protection platform for those companies, built on one open, reviewed cryptographic core. People never copy keys by hand: they have accounts, find each other by email, and send files the way they send messages, while everything stays end-to-end encrypted, signed and post-quantum. The full design is in [`design/`](design/README.md). The products:

0. **pSIONIUM Transfer (free tier + paid; the everyday product).** Send files to people by email or handle, or to anyone with a secure link; they receive them in an inbox, see that they really came from you, and open them in one click, in the browser, or automatically into a folder. Request files from clients. Track delivery, revoke, set expiry. Works in the web app, desktop and mobile apps (share sheet, right-click), and the interactive `psion` shell. Design: `design/04-secure-transfer.md`.
1. **pSIONIUM Scan (free; brings customers in).** Finds every place a company depends on quantum-vulnerable cryptography: source code, dependencies, certificates, keys, live servers, and eventually cloud accounts and running systems. Produces a cryptography bill of materials (CBOM) and a plain-language migration plan an auditor understands. Runs in a terminal, in CI (GitHub Action), and as a hosted report.
2. **pSIONIUM Vault (paid; the core business).** Protects files, folders and secrets with post-quantum encryption and signatures:
   - the `.psen` format and `psion` command line (exists today),
   - desktop and mobile apps (reviving the recovered Flutter "dock" app on the Rust core),
   - team and organization sharing, a key hierarchy, rotation, k-of-n recovery so nobody is ever locked out,
   - hardware-backed device keys (Secure Enclave, TPM, StrongBox, passkeys),
   - a tamper-evident audit log (hash chain with anchors),
   - a zero-knowledge cloud service: it stores only ciphertext and wrapped keys, never plaintext.
3. **pSIONIUM SDK (usage-based).** Field-level encryption and tokenization for Go, TypeScript, Python and Rust, so developers protect PII, health and payment data inside their own apps, with bring-your-own-key from AWS KMS, Google Cloud KMS or an HSM. TaskFlow is the first integration (encrypted attachments and custom fields).

Around all products: accounts with passkeys, MFA and SSO; organizations with an admin console, policies and audit logs; licensing with plans, seats and signed licenses; and PORTAL VII's own back office for sales, billing, support and partners (`design/07`, `design/08`, `design/09`). The open-source `psion` CLI, with a beautiful interactive shell (`design/05`), stays free for local encryption and scanning.

Once that core is proven and customers ask for it: a post-quantum proxy for legacy applications, anomaly alerts on key usage, compliance evidence packs mapped to NIST and CNSA 2.0, threshold (MPC) key custody, and research tracks (DIBLE, FHE) that only reach products after publication and review.

### What success looks like

- A security reviewer can read the specification, the threat model and an independent audit, and find nothing to object to.
- A company can go from "we don't know our exposure" to "our sensitive data is quantum-safe and here is the evidence" quickly and without a cryptography team.
- Developers adopt the open-source core and scanner because they are the easiest correct choice; companies pay for the service, apps, policy, recovery and compliance on top.
- PORTAL VII's own products (TaskFlow first) run on pSIONIUM.

## Principles that never change

These keep pSIONIUM credible. Breaking one is a bug, whatever the feature.

- **Standard cryptography only on the encryption path.** NIST algorithms (ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-2/SHA-3) from production libraries (AWS-LC). No home-made algorithms. Research ideas live in a separate track until published and reviewed.
- **Hybrid by default.** Key exchange combines X25519 with ML-KEM, so data stays safe if either is broken. A CNSA 2.0 mode uses only CNSA algorithms.
- **Crypto agility.** Every file and key records its algorithm suite, so algorithms can be rotated by re-wrapping keys, not re-encrypting data.
- **Zero knowledge.** Encryption happens on the user's device. Services never see plaintext or file keys.
- **Nobody gets locked out.** Recovery is designed in (k-of-n admins, escrow options), never bolted on.
- **Evidence over claims.** Open specification, committed test vectors, independent implementations, fuzzing, external audits, a public security policy. No "certified" or "compliant" badge until an audit says so, on the website or anywhere else.
- **Open core.** `psionium-core`, the format and the scanner engine are open source (Apache-2.0). Paid value is the service, apps, policy and compliance.

## Who it is for

- Companies of roughly 50 to 2,000 people in health, finance, legal and government supply chains that keep sensitive records for years and will be asked about quantum readiness by customers and auditors.
- Developers who need field-level encryption without becoming cryptographers.
- Managed service providers who look after many such companies.

## Business model (starting hypotheses to test, not decisions)

| Plan | For | Includes |
|---|---|---|
| Scan | Anyone | CLI, GitHub Action, CBOM, report. Free. |
| Team | Small teams | Vault, apps, sharing, audit log. Per user. |
| Business | Regulated companies | Plus SSO, BYOK, recovery policies, evidence pack. Per user. |
| Developer | App builders | SDK and field encryption. Usage-based with a free tier. |
| Enterprise | Large and public sector | On-premises, HSM, CNSA mode, support terms. Contract. |

The original planning document, with market research, competitors and sources, is the "pSIONIUM 3 Plan" artifact: https://claude.ai/artifact/YG728QHRuaWFDMSsbxRyuq (private to the owner).
