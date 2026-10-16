# Roadmap

The complete build plan from today's CLI to the full pSIONIUM platform. Ordered by what to do next; **no dates**. Each item names the design section that defines it (`design/NN-…`). Finish a stage's **Done when** before starting the next stage's main work (independent items may overlap). Mark items `[x]` only when built and verified, and add a line to `LOG.md`. Items marked **(owner)** need a decision or action from `design/14-owner-decisions.md` first.

## Stage 1 — pSIONIUM 1.0 CLI released ✅ (finishing)

- [x] `.psen` v2 format, spec, test vectors, Go interop implementation
- [x] `psion` CLI with signatures, passphrases, scan
- [x] CI and release workflows, `install.sh`, security docs
- [x] CI green on all jobs, including Windows (run 38943173387)
- [x] Release v1.0.0 published and assets verified on macOS and Linux
- [x] `install.sh` works against the real release (owner installed on macOS from GitHub, 2026-10-16)
- [ ] Website pSIONIUM pages pushed and live **(owner: D13)**
- [ ] Repository hygiene: decide `flutter/` and `.vscode/` **(owner: D12)**; confirm security mailbox **(owner: A1)**

**Done when:** anyone can install `psion` with one command and portalvii.com describes it truthfully.

## Stage 2 — The pSIONIUM shell and Scan front door (local only, no accounts)

Interactive CLI (`design/05-interactive-cli.md`):
- [ ] TUI framework in `crates/psion`: themes (classic, portal, high-contrast, light), launch animation, layout, command palette, classic `pSIONIUM>` prompt with history and completion
- [ ] Screens that work offline: Home, Encrypt/Decrypt (guided), Keys (local identity), Scan (live progress, findings browser, export), Settings, Help with tutorial
- [ ] Heritage utilities: `encode`/`decode`, `compress`/`decompress`
- [ ] `psion doctor`, `psion completions`, `psion update` (signature-checked self-update)
- [ ] Snapshot tests per screen and theme at 80×24 and 200×60; scripting-mode compatibility tests unchanged
Scan (`design/10-scan-product.md` Stage A):
- [ ] `--format html` report; SARIF output; baseline file; `--no-excerpts`
- [ ] GitHub Action `psionium/scan-action@v1`, Docker image, GitLab template
Core hardening (`design/12-quality-security-ops.md`):
- [ ] `cargo-fuzz` targets; benchmarks published; SLH-DSA option for long-term signatures

**Done when:** `psion` with no arguments opens the shell, a new user completes the tutorial unaided, and the Scan Action is in the GitHub Marketplace.

## Stage 3 — Platform foundation (accounts, keys, licensing, website)

Owner decisions first: domains (D2), hosting (D5), MFA (D8), brand (D11).
- [ ] `psionium-cloud` repo: Go services skeleton, gateway, PostgreSQL schemas, Redis, object storage, Docker Compose, CI, staging environment (`design/02-architecture.md`)
- [ ] `.psen` v3 spec: manifest stanza, symmetric link stanza, transfer binding; vectors; Go interop; review scope (`design/04`, `design/03`)
- [ ] `psionium-wasm` and `psionium-ffi` bindings with cross-language tests (`design/02`, `design/11`)
- [ ] Identity service: sign-up, email verification, passwords (Argon2id), passkeys, TOTP, sessions, OAuth device flow (`design/07`)
- [ ] Device keys, Account Key wrapping, device approval, Recovery Kit (`design/03`)
- [ ] Key Directory with transparency log, key-change warnings, contact verification (`design/03`)
- [ ] Orgs, members, roles, teams, domain verification (`design/07`)
- [ ] Licensing service: plans, entitlements, signed licenses (ML-DSA + Ed25519), enforcement middleware (`design/08`)
- [ ] Notify service (email via Brevo with TaskFlow's throttle/daily-limit logic, in-app, push later) (`design/07`)
- [ ] Web app shell: sign-up/sign-in, onboarding with Recovery Kit, settings, devices (`design/06`)
- [ ] CLI: `login`, `logout`, `whoami`, `devices`, `recovery`, `license` (`design/05`)
- [ ] Staff console MVP: customers, licenses, trials, staff auth and audit (`design/09`)
- [ ] Website: Transfer, Business, Pricing (draft), Download, Docs (getting started, CLI reference), Trust center (`design/06`)

**Done when:** a person can sign up on the web, approve the CLI as a device, see their license, and recover access with the Recovery Kit on a new device.

## Stage 4 — Secure Transfer MVP

- [ ] Transfer service: create, chunked resumable upload, complete, inbox/sent, revoke, expiry, activity log (`design/04`)
- [ ] Send and receive between accounts in the web app and CLI (`send`, `inbox`, `open`, `sent`, `revoke`) with verified-sender badges
- [ ] Guest links and request-files links on the separate `send.` origin with WASM decryption, passcode and email OTP
- [ ] Delivery modes: keep encrypted, open in browser, CLI `inbox --watch --auto-decrypt`
- [ ] Notifications (email, in-app), webhooks for transfer events
- [ ] Shell screens: Send, Inbox, Sent, Contacts (`design/05`)
- [ ] Abuse reporting and link takedown in the staff console (`design/09`)
- [ ] **Independent review** of v3, device linking, recovery, transparency log, licensing **(owner: D10, A5)** — gate for GA

**Done when:** journeys J1, J2, J3 (and J4 via CLI) in `design/01` pass end to end, and the review has no open critical findings.

## Stage 5 — Apps

- [ ] `psionium-apps` (Flutter + Rust core): macOS, Windows, Linux desktop with tray, share/right-click send, auto-decrypt folders, notifications (`design/06`)
- [ ] iOS and Android with share extensions, push, biometric unlock **(owner: A3)**
- [ ] Vaults (shared encrypted spaces) in service, web, apps, CLI (`design/04`)
- [ ] Signed installers, notarization, store listings, auto-update

**Done when:** J2–J4 work from a phone share sheet and a desktop right-click, matching the web and CLI.

## Stage 6 — Business launch

Owner decisions first: prices (D3), company/Stripe (D4), CRM (D6), legal (A4).
- [ ] Billing: Stripe Checkout, Customer Portal, webhooks → licensing; trials; dunning (`design/08`, `design/09`)
- [ ] Customer admin console: members, teams, devices, policies, audit log + export/SIEM, recovery approvals, billing (`design/07`)
- [ ] SSO (SAML, OIDC), SCIM, enforced MFA/passkeys, data classes (`design/07`)
- [ ] Scan dashboard: projects, endpoints monitoring, inventory, migration plan, alerts, auditor reports (`design/10` Stage B)
- [ ] Staff console complete: billing, metrics, partners, support tools (`design/09`)
- [ ] Support desk in TaskFlow, onboarding checklist, knowledge base (`design/09`)
- [ ] Penetration test; SOC 2 readiness started (`design/12`)
- [ ] Website: final pricing, legal pages, contact sales → CRM, guides (`design/06`)

**Done when:** a company can go from trial to paid, onboard 50 users with SSO, and PORTAL VII can sell, bill and support it without engineering help (J5, J9).

## Stage 7 — Developers and enterprise

- [ ] Public API docs, API keys, generated clients, sandbox (`design/11`)
- [ ] SDKs: TypeScript (WASM), Python (PyO3), Go (from `interop/go`), Rust client (`design/11`)
- [ ] Field-level encryption and BYOK (AWS KMS, GCP KMS, Azure Key Vault, PKCS#11) (`design/11`)
- [ ] Self-hosted / dedicated deployment with license files (`design/08`)
- [ ] Managed decryption worker (enterprise, opt-in) **(owner: D7)** (`design/03`, `design/04`)
- [ ] CNSA mode end to end; data residency regions **(owner: D14)**
- [ ] Integrations: Outlook/Gmail add-ins, Slack/Teams, TaskFlow encrypted attachments (`design/04`)

**Done when:** J7 works in three languages and an enterprise customer runs a dedicated instance with their own KMS.

## Stage 8 — Expand (driven by paying customers)

- [ ] Anomaly alerts on account and key usage (never content) (`design/13`)
- [ ] Post-quantum proxy for legacy apps (basis: `network_resilience` on the `legacy` branch)
- [ ] Threshold / MPC key custody; legal hold and e-discovery exports
- [ ] Internationalization of web and apps
- [ ] Research track items when published and reviewed (`design/13`)
