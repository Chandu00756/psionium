# 01 · Products and journeys

## What exists today vs. what is planned

| Capability | Today | Planned (where it is designed) |
|---|---|---|
| Encrypt / decrypt / sign files | **Yes**: `psion encrypt/decrypt`, scripting-style CLI, keys exchanged by hand | Same engine, wrapped in accounts and transfer so nobody copies keys by hand (04, 05) |
| Interactive, colorful CLI | **Yes, local screens (2026-10-16)**: `psion` opens the full-screen shell (Home, Encrypt, Decrypt, Keys, Scan, Console, Settings, Help, tutorial). Account screens wait for Stage 3 | Full-screen `psion` shell (05) |
| Quantum-readiness Scan | **Yes, CLI only**: `psion scan` (text, Markdown, JSON, CBOM) | GitHub Action, HTML report, hosted dashboard with monitoring (10) |
| Website | **Partly**: product pages on portalvii.com rewritten (not yet pushed); no pricing, download page, docs site, sign-up | Marketing site, docs, download, pricing, trust center (06) |
| Accounts, sign-in, organizations | **No** | Accounts, MFA, passkeys, SSO, orgs, roles (07) |
| Secure file transfer ("send like WhatsApp") | **No** | Send to people by email/handle or guest link; inbox; delivery modes (04) |
| Web app, desktop app, mobile app | **No** (old Flutter "dock" app and Rust web UI survive on `legacy` as reference) | Web app, Flutter desktop/mobile apps, share extensions (06) |
| Licensing, plans, billing | **No** | Plans, entitlements, signed licenses, Stripe billing (08, 09) |
| Customer admin console | **No** | Org admin: users, policies, devices, audit, licenses (07) |
| PORTAL VII staff console | **No** | Customers, licenses, billing, sales, support, partners (09) |
| SDK / public API | **No** (Rust crate `psionium-core` and the Go interop package exist) | REST API, webhooks, SDKs for TS/Python/Go/Rust, field encryption, BYOK (11) |

## The product family

pSIONIUM is one platform with one cryptographic core and several ways in.

| Product | Who it is for | What they get | Paid? |
|---|---|---|---|
| **psion (open source)** | Developers, security people | Local encrypt/decrypt/sign and Scan in the terminal, scripting mode and interactive shell | Free forever (Apache-2.0) |
| **pSIONIUM Transfer** | Anyone who sends sensitive files | Send files to people like a messaging app; they receive, verify and open them; guest links; inbox; history | Free tier with limits, paid plans |
| **pSIONIUM Vault** | Teams and companies | Shared encrypted spaces (folders) for teams, long-term storage, recovery, retention, policies | Paid |
| **pSIONIUM Scan** | Engineering and security teams, auditors | CLI and CI scanning (free); hosted dashboard, monitoring, auditor reports (paid) | Free + paid |
| **pSIONIUM for Business** | Organizations | Admin console, SSO/SCIM, policies, audit export, licenses, priority support | Paid per seat |
| **pSIONIUM SDK & API** | App builders | Field-level encryption, transfer API, webhooks, BYOK | Usage-based |
| **pSIONIUM Enterprise** | Large and regulated customers | Self-hosted or dedicated deployment, HSM/KMS, CNSA mode, managed decryption, contracts | Contract |

## Personas

| Persona | Needs | Main surfaces |
|---|---|---|
| **Sender** (employee, lawyer, doctor, accountant) | Send a confidential file as easily as WhatsApp, know it arrived, know only the right person can open it | Web app, desktop/mobile app (share sheet), CLI |
| **Receiver with an account** | Get files in an inbox, trust who sent them, open them in one click or have them decrypted automatically | Web app, apps, CLI |
| **Guest receiver** (client, patient, outside party) | Open a file from a link without installing anything | Browser only |
| **Org admin** (IT/security) | Add people, enforce policies, see audit logs, manage seats and devices, recover accounts | Admin console |
| **Developer** | Encrypt data inside their app, automate transfers, scan code in CI | SDK, API, CLI, GitHub Action |
| **Auditor / compliance lead** | Evidence of cryptographic inventory and migration, access logs | Scan reports, audit export, trust center |
| **PORTAL VII staff** (sales, support, finance, admin) | Sell, onboard, license, bill, support customers, run marketing | Staff console, CRM, support desk |

## End-to-end journeys

Each journey is the acceptance test for the features it touches. Agents must keep these working end to end.

### J1 · First run (individual)
1. Visitor reads portalvii.com/psionium → clicks **Get started**.
2. Signs up with email (or Google/Microsoft, or passkey) → verifies email → sets up MFA (passkey or authenticator app).
3. The browser (or app) creates the user's identity and first device key **on the device**; the server receives only public keys and the wrapped private keys (03).
4. The user saves a **Recovery Kit** (printable PDF with a recovery code and QR). The app checks it was saved by asking for 4 characters of it.
5. Lands on the **Inbox**, with a 3-step tour: send a file, install the app/CLI, invite a colleague.

### J2 · Send a file to a colleague who has an account
1. Sender drags `contract.pdf` into the web app (or right-clicks → **Send with pSIONIUM**, or `psion send contract.pdf --to ravi@firm.com`).
2. Types the recipient's email → the app fetches the recipient's keys from the Key Directory and shows their **verified** status (03).
3. Chooses options: message, expiry, require signature check (on by default), allow download vs. view-only, delivery mode suggestion.
4. Clicks **Send**. The file is encrypted and signed **on the sender's device**, uploaded in chunks, and the recipient is notified (email + push + inbox).
5. Receiver opens the notification → the inbox shows the file, sender, and a green **Signed by sender · not modified** badge → **Open** (decrypted locally), **Save encrypted**, or it is already in their auto-decrypt folder (04).
6. Sender sees **Delivered** and **Opened** status (if the org's policy allows read receipts) and can revoke before it is opened.

### J3 · Send to someone without an account (guest link)
1. Sender chooses **Create link** (or types an email that has no account → app offers "send as secure link").
2. Optional: require a passcode (sent separately, e.g. by SMS), set expiry and maximum downloads, require the guest to verify their email with a one-time code.
3. The app encrypts the file with a fresh key, uploads ciphertext, and produces `https://<app-domain>/r/<id>#<key>`; the part after `#` never reaches the server.
4. Guest opens the link → the browser downloads ciphertext and decrypts it locally (WASM) → preview or download. The guest is invited (not forced) to create an account to reply securely.
5. Sender sees each open/download in the transfer's activity log.

### J4 · Receive automatically (auto-decrypt)
1. Receiver installs the desktop app (or runs `psion inbox --watch` on a server) and chooses an **auto-decrypt folder** per sender, team or all.
2. New transfers download and decrypt into that folder as they arrive; originals stay encrypted in the inbox until retention ends.
3. Policy can forbid auto-decrypt for some data classes or require it to land only on managed devices.

### J5 · Organization onboarding (Business plan)
1. A company starts a 14-day trial from the pricing page or a sales demo; the first user becomes org owner.
2. Owner verifies the company domain (DNS TXT), invites people (or connects SSO + SCIM), and sets policies: MFA required, external sharing allowed or not, link expiry max, allowed delivery modes, retention, recovery (admin escrow on/off).
3. Owner buys seats (Stripe) or sales issues an invoice; the license updates instantly in all apps.
4. Admins see members, devices, transfers metadata, audit log; export to SIEM.

### J6 · Lost device / forgotten passphrase
1. User signs in on a new device → approves it from an existing device (scan QR or confirm code), **or** enters the Recovery Kit code, **or** (org policy) asks admins to approve recovery (k-of-n).
2. Without any of these, encrypted data cannot be recovered; the app says so plainly at sign-up and in J1 step 4.

### J7 · Developer integrates
1. Creates an API key in the dashboard (scoped, revocable) → installs SDK → encrypts fields or sends transfers programmatically; receives webhooks (`transfer.delivered`, `transfer.opened`).
2. Uses BYOK so the org's master keys live in its own AWS/GCP KMS or HSM.

### J8 · Scan to migration
1. Engineer runs `psion scan` or adds the GitHub Action → gets a CBOM and report.
2. Uploads to the Scan dashboard (or the Action does) → sees inventory across repos and domains, trends, and a migration plan; creates tasks (TaskFlow integration) and exports an auditor report.
3. Sales sees the account as a lead if they asked for help (with consent).

### J9 · PORTAL VII sells and supports
1. Lead comes from the website, Scan, or a partner → CRM → demo → trial → quote → contract → license issued from the staff console → onboarding checklist → support desk (TaskFlow) for tickets.
2. Finance sees subscriptions, invoices, renewals, churn risk; marketing sees funnel metrics.

## What makes it "extraordinary", not just functional

- Opening a file sent to you feels as simple as WhatsApp, but every file is post-quantum encrypted and signed end to end, and the UI proves it (verified sender badges, fingerprints, activity log).
- The interactive CLI is a showcase: fast, beautiful, keyboard-first, with the classic pSIONIUM terminal heritage (05).
- Nothing requires trusting PORTAL VII with plaintext, and the documentation shows exactly why.
- Scan turns an abstract quantum threat into a concrete to-do list a company can finish.
