# 06 · Website and apps

## 1. Public website (marketing, docs, trust)

Lives in the existing PORTAL VII site (`~/P7Ultra/portalvii-website2/packages/frontend`, Next.js 14, Tailwind, framer-motion, deployed with Vercel). Keep the site's theme (black, violet/pink, PORTAL VII mark).

| Page | Path (proposal) | Contents | Status |
|---|---|---|---|
| Product home | `/pages/psionium` | Hero, install command, terminal demo, products, suites, file anatomy, evidence, honest review note | **Rewritten, not pushed** |
| How it works | `/pages/resources/psionium` | Encryption steps, checks, keys, threat model summary, scan categories | **Rewritten, not pushed** |
| Transfer | `/psionium/transfer` | "Send like a message, protected for decades": flows, guest links, delivery modes, screenshots | Planned |
| Scan | `/psionium/scan` | Free scanner, GitHub Action, dashboard, sample report, "2030 deadline" guide | Planned |
| Business | `/psionium/business` | Admin console, SSO/SCIM, policies, audit, recovery, deployment options | Planned |
| Developers | `/psionium/developers` | SDKs, API, BYOK, code samples | Planned |
| Pricing | `/psionium/pricing` | Plans table from 08, FAQ, "Contact sales", trial | Planned |
| Download | `/psionium/download` | Detects OS; CLI install command; desktop/mobile app links; checksums and signature instructions; release notes | Planned |
| Docs | `/psionium/docs/*` | Getting started, CLI reference (generated from `psion --help`), guides (send, receive, scan, admin), API reference (from OpenAPI), security whitepaper, `.psen` spec, threat model, FAQ | Planned |
| Trust center | `/psionium/trust` | Security architecture, review reports, subprocessors, data locations, status page link, vulnerability disclosure, compliance status (true claims only) | Planned |
| Guides / blog | `/psionium/guides/*` | Quantum-readiness explainers, migration guides, CNSA 2.0 timeline (sources cited) | Planned |
| Contact sales / demo | `/psionium/contact` | Form → CRM (09) with spam protection | Planned |
| Legal | `/legal/*` | Terms, privacy, DPA, acceptable use, SLA (enterprise), cookie policy | Planned (owner + lawyer, 14) |
| Status | `status.psionium.portalvii.com` | Uptime and incidents (hosted status page) | Planned |

SEO: per-page metadata, Open Graph images, sitemap (exists), structured data for SoftwareApplication. Analytics: privacy-friendly (Plausible or self-hosted), no ad trackers.

## 2. Web app (`app.psionium.portalvii.com`)

Next.js app with the WASM core. Navigation: **Inbox · Send · Sent · Requests · Vaults · Contacts · Scan · Settings**, plus **Admin** and **Billing** for org admins.

| Screen | Contents |
|---|---|
| Sign up / sign in | Email, Google/Microsoft, passkey, SSO (org domain detection), MFA, device approval, recovery |
| Onboarding | Create keys (progress UI), Recovery Kit download + confirmation, install apps/CLI, invite colleagues, tour |
| Inbox | List with verified badges, filters (sender, unread, expiring), detail drawer (files, message, activity), open/preview (PDF, images, text, Office via local rendering where possible), save |
| Send | Drop zone, recipients with key status, options, upload progress, success screen with link copy |
| Sent | States per recipient, revoke, extend, resend, activity |
| Requests | Create and manage request-files links, see uploads |
| Vaults | Folder browser, upload/download, versions, members, retention |
| Contacts | People/teams, verify (QR / safety code), key history |
| Scan | Projects/repos, endpoints monitored, findings over time, migration plan, reports (10) |
| Settings | Profile, security (MFA, passkeys, sessions), devices, keys (fingerprint, rotation), recovery, notifications, delivery modes, API keys (if permitted), appearance |
| Admin (org) | See 07 |
| Billing | Plan, seats, invoices, payment method (Stripe Customer Portal), license file download (self-hosted) |
| Guest link page (separate origin) | Sender + badge, files, passcode/OTP prompt, decrypt progress, preview/download, "Create an account to reply" |
| Request upload page | Requester name and message, drop zone, required fields, encrypt + upload progress, receipt |

Design system: shared with the marketing site (colors, type, components) but denser; dark and light themes; WCAG 2.2 AA; works on phones.

## 3. Desktop and mobile apps (Flutter)

Revive the recovered **dock** app (`legacy` branch: home, encrypt/decrypt, file management, key management, security settings, billing, workflow automation, threat management, command execution screens) on the new Rust core through `flutter_rust_bridge`.

| Platform | Specifics |
|---|---|
| macOS, Windows, Linux | Menu-bar/tray icon with unread count; Finder/Explorer "Send with pSIONIUM"; drag onto the dock icon to send; auto-decrypt folders; background sync for vaults; system notifications; keys in OS keychain; signed and notarized installers; auto-update with signature check |
| iOS, Android | Share extension ("Send with pSIONIUM" from any app, like WhatsApp), push notifications, biometric unlock, open-in from Files, document scanner to send scans securely; App Store / Play Store listings |

Screens mirror the web app: Inbox, Send, Sent, Requests, Vaults, Contacts, Scan (view), Settings, Admin (view-only on mobile).

The old "threat management", "workflow automation" and "command execution" screens become: **Activity** (security events for your account), **Automations** (rules like "auto-decrypt from legal team into ~/Legal"), and the embedded interactive shell on desktop.

## 4. Browser extension (later)

Adds "Send with pSIONIUM" to Gmail/Outlook web compose, and detects pSIONIUM links to open them in the app.

## Acceptance for the website and apps

- Lighthouse ≥ 90 on marketing pages; web app usable on a mid-range phone.
- Every journey in 01 works on web, desktop and mobile with the same results as the CLI.
- No page claims anything not listed as true in `../STATUS.md` or the trust center.
