# pSIONIUM design

This folder is the complete design of the pSIONIUM platform: every product, screen, service, flow and business process the owner expects, from today's command line to the full commercial platform. **Nothing here is built unless `../STATUS.md` says so.** Agents build from these documents; they do not invent a different design.

Status of these documents: **Approved direction (owner request, 2026-10-16).** Details can change, but only through the change process below.

## Read in this order

| # | Document | What it decides |
|---|---|---|
| 01 | [Products and journeys](01-products-and-journeys.md) | The product family, who uses it, end-to-end journeys, and what exists today vs. planned |
| 02 | [Architecture](02-architecture.md) | Components, services, tech stack, repositories, data model, environments |
| 03 | [Security model](03-security-model.md) | Identities, keys, devices, recovery, key directory, what the server can and cannot see |
| 04 | [Secure transfer](04-secure-transfer.md) | Sending and receiving files between people, links for guests, delivery modes (stay encrypted, auto-decrypt, open in browser) |
| 05 | [Interactive CLI](05-interactive-cli.md) | The full-screen `psion` shell: look, screens, commands, login, licensing, scripting mode |
| 06 | [Website and apps](06-website-and-apps.md) | Marketing site, docs, download, web app, desktop and mobile apps |
| 07 | [Accounts, organizations, admin](07-accounts-orgs-admin.md) | Sign-up, sign-in, MFA, SSO, organizations, roles, customer admin console, policies |
| 08 | [Licensing](08-licensing.md) | Plans, entitlements, seats, license files, activation, enforcement |
| 09 | [Business operations](09-business-operations.md) | PORTAL VII's own back office: staff console, sales, marketing, billing, support, partners |
| 10 | [Scan product](10-scan-product.md) | How Scan works today and its path to a hosted readiness dashboard |
| 11 | [API and SDKs](11-api-and-sdks.md) | Public API, webhooks, field-level encryption SDKs, BYOK |
| 12 | [Quality, security and operations](12-quality-security-ops.md) | Testing, CI/CD, environments, monitoring, incidents, backups, audits, compliance program |
| 13 | [Research track](13-research-track.md) | Every idea from the original PVII documents and where it lives (product, research, or out of scope) |
| 14 | [Owner decisions and actions](14-owner-decisions.md) | What only the owner can decide or do (domains, accounts, pricing, legal, auditors) |

The build order is in [`../ROADMAP.md`](../ROADMAP.md); each roadmap item points back to the section here that defines it.

## Glossary

| Term | Meaning |
|---|---|
| **psion** | The command-line program. `psion <command>` is scripting mode; `psion` alone opens the interactive shell |
| **`.psen`** | The encrypted file format (`docs/psen-v2.md`) |
| **Identity** | A person's key set: decryption key pair + signing key pair. Today a file (`me.key`); on the platform, held by the user's devices |
| **Public key `psionpk:`** | Lets others encrypt to a person. Published in the Key Directory |
| **Verify key `psionvk:`** | Lets others check a person's signatures. Published in the Key Directory |
| **Device key** | A key pair created on and kept by one device (in the OS keychain or secure hardware when available). Unlocks the user's identity on that device |
| **Key Directory** | The service that maps an account (email/handle) to its current public and verify keys, with an append-only transparency log so key changes are visible |
| **Transfer** | One send action: one or more files, sealed for one or more recipients, with options (expiry, delivery mode) |
| **Guest link** | A transfer for someone without an account; the decryption secret travels in the link's `#fragment`, which the server never receives |
| **Delivery mode** | What happens when a transfer arrives: keep encrypted, auto-decrypt on the recipient's devices, open in the browser, or (enterprise only) managed decryption |
| **Organization (org)** | A customer company: members, teams, policies, licenses, billing |
| **Entitlement** | A feature or limit a plan grants (seats, storage, SSO, retention…) |
| **License** | A signed statement of an org's plan and entitlements, verified by apps and self-hosted servers |
| **Staff console** | PORTAL VII's internal back office (customers, licenses, billing, support) |
| **Zero knowledge** | The service stores only ciphertext and wrapped keys; it cannot read user content |

## How to change the design

1. Propose the change to the owner with the reason.
2. If approved, edit the document here and add an entry to `../DECISIONS.md` (date, decision, why).
3. Then build. Code that contradicts these documents without a recorded decision is a bug.

## Rules that apply to every design here

- Cryptography only through `psionium-core` (Rust) and its bindings. No service or app implements its own encryption.
- Zero knowledge is the default everywhere. Any feature that lets a server see plaintext (managed decryption) is opt-in per organization, labeled in the UI, and documented in the security model.
- Every user-facing claim (security, compliance, uptime, numbers) must be true and evidenced. See `12-quality-security-ops.md`.
- Every feature works in three places unless a document says otherwise: the web app, the apps (desktop/mobile), and the CLI.
