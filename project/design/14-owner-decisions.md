# 14 · Owner decisions and actions

Things only the owner (or PORTAL VII as a company) can decide or do. Agents must not decide these; they ask, using the recommendation as the suggested answer, and record the answer in `../DECISIONS.md`. Status column: **Open** until answered.

## Decisions

| # | Decision | Recommendation | Needed before | Status |
|---|---|---|---|---|
| D1 | Make `Chandu00756/psionium` public (or create a public `portalvii/psionium` org repo and move it) | Move to a `portalvii` GitHub organization and keep it public, so the brand owns the project | Website push; any outside users | Repo appears public already (install from GitHub worked on 2026-10-16); org move open |
| D2 | Domains for the platform | `app.`, `api.`, `send.`, `staff.`, `status.` under `psionium.portalvii.com`; consider buying `psionium.com` for marketing | Stage 3 | Open |
| D3 | Prices and plan limits (08, 04) | Start with the proposed table; validate with design partners | Billing launch | Open |
| D4 | Company and payments: legal entity, Stripe account, tax registrations, bank | Stripe under the PORTAL VII entity | Billing launch | Open |
| D5 | Hosting for the cloud | Start on Oracle Cloud (like TaskFlow) + Oracle Object Storage; Cloudflare in front | Stage 3 | Open |
| D6 | CRM: HubSpot Free vs. building on TaskFlow | HubSpot Free first (fast), TaskFlow for support | Sales start | Open |
| D7 | Managed decryption offering (enterprise exception to zero knowledge) | Offer only in Enterprise, customer-hosted worker, clearly labeled | Stage 7 | Open |
| D8 | SMS as an MFA option for non-admins | No SMS; passkeys + TOTP only | Stage 3 | Open |
| D9 | Free plan limits and whether guest links need a verified sender | Verified email required to send guest links | Stage 4 | Open |
| D10 | Independent review vendor and budget | Request quotes from 2–3 cryptography review firms; scope: `.psen` v2/v3, device linking, recovery, transparency log, licensing | Before Transfer GA | Open |
| D11 | Brand for the interactive CLI and apps (keep "pSIONIUM", icon, colors) | Keep pSIONIUM + PORTAL VII pyramid; violet/pink + classic green theme | Stage 2 | **Answered 2026-10-16: approved as recommended** |
| D12 | What the untracked `flutter/` (Flutter SDK clone) and `.vscode/` in the repo are for | Keep the Flutter SDK outside the repo; add `.vscode/` to `.gitignore` or remove | Next commit touching the repo root | Open |
| D13 | Website: approve and push the rewritten pSIONIUM pages; decide the Vercel root-directory fix from the claims-cleanup session | Push after D1 | Now | Open |
| D14 | Data residency regions offered | US first; EU when the first EU customer asks | Business plan | Open |

## Actions only the owner can take

| # | Action | Why |
|---|---|---|
| A1 | Confirm `chandu@portalvii.com` receives mail; enable GitHub private vulnerability reporting | Security contact in `SECURITY.md` |
| A2 | Register domains/DNS records (D2) | Platform URLs |
| A3 | Create Stripe account, Apple Developer account ($99/yr), Google Play developer account, Windows code-signing certificate, macOS notarization | Billing and app distribution |
| A4 | Engage a lawyer for Terms, Privacy, DPA, AUP | Legal pages before paid launch |
| A5 | Commission the independent cryptographic review (D10) | Required before customers' irreplaceable data |
| A6 | Approve each outward-facing step: repo visibility, releases, website deploys, DNS, emails to customers | Owner's standing rules |
| A7 | Recruit 5–10 design partners | Product feedback and first revenue |
| A8 | Back up: Time Machine or equivalent on the development Mac; GitHub org with 2FA for all members | The original code was lost once |

## How agents use this file

- Before starting a roadmap item, check whether it depends on an open decision here. If it does, ask the owner that one question and wait.
- After the owner answers, update the Status column, add the decision to `../DECISIONS.md`, and continue.
