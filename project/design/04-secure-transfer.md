# 04 · Secure transfer

The heart of the business product: send files to people as easily as a messaging app, with post-quantum end-to-end encryption, sender verification and control after sending.

## Concepts

| Concept | Description |
|---|---|
| **Transfer** | One send: 1–1,000 files (or a folder), one or more recipients, an optional message, options. Has an id, status and activity log |
| **Recipient** | An account (email/handle), a team, or a guest (link or email without an account) |
| **Inbox** | Everything sent to you, newest first, with sender, verification badge, size, expiry, state |
| **Sent** | Everything you sent, with per-recipient state (sent → delivered → opened, or expired/revoked) |
| **Delivery mode** | What happens on arrival, chosen by the receiver (within org policy) |
| **Activity log** | Per transfer: created, uploaded, delivered, opened/downloaded (who, when, which device, IP country), revoked, expired |

## Send flow (all clients)

1. **Pick files.** Drag and drop, file picker, OS share sheet ("Send with pSIONIUM"), right-click in Finder/Explorer, or `psion send <files>`.
2. **Pick recipients.** Type email, handle, team or contact name; autocomplete from contacts and the org directory. Each chip shows: verified ✓ / unverified / new / no account (→ guest).
3. **Options** (defaults from org policy):
   - Message (encrypted).
   - Expiry: 1 hour … 1 year, or never (if allowed). Default 7 days.
   - Download limit (guests).
   - Require passcode (guests) and/or email one-time code.
   - Allow download vs. view only (view-only is a UI restriction, not cryptographic; documented as such).
   - Notify me when opened.
   - Sign (always on; cannot be turned off for accounts).
4. **Seal.** The client fetches recipient keys from the Directory (verifying transparency proofs), encrypts each file with a fresh file key to all recipient identities (plus the sender's own identity, so it appears readable in Sent), encrypts the manifest (names, sizes, message) in the same envelope, signs, and streams chunks.
5. **Upload.** Resumable chunked upload with progress, pause/resume, and retry. Large files (up to 50 GB on paid plans) never sit in memory.
6. **Notify.** The server marks the transfer delivered to each recipient's inbox, sends push/email ("Chandu sent you 2 files"; no file names in email), and fires webhooks.
7. **Track.** Sender sees state changes live; can revoke (deletes wrapped keys and objects for recipients who have not downloaded), extend expiry, or resend.

## Receive flow

1. Notification (push, email, in-app, CLI `psion inbox`).
2. Inbox entry shows sender with **verification badge**: ✓ *Signed by Chandu (verified contact)* · *Signed, keys new* · ⚠ *Sender keys changed, review*.
3. Actions: **Open** (decrypt in the app/browser, preview common types), **Save decrypted**, **Save encrypted (.psen)**, **Forward** (re-seal to new recipients without downloading plaintext to disk when possible), **Reply securely**, **Report**.
4. Receipt events recorded per device.

## Delivery modes (receiver's choice, limited by org policy)

| Mode | What happens | Where it works |
|---|---|---|
| **Keep encrypted** (default for orgs that require it) | Stays as `.psen` in the inbox and on download; opened on demand | All clients |
| **Auto-decrypt on my devices** | Desktop app / `psion inbox --watch` downloads and decrypts into a chosen folder automatically, per sender, team or all | Desktop apps, CLI (servers), mobile (on open) |
| **Open in browser** | Web app or guest page decrypts locally with WASM; preview or save | Browsers |
| **Managed decryption** (enterprise, opt-in) | Copies decrypted by the customer's own worker for archive/DLP | Customer environment (03) |

Each mode is visible in the transfer's activity log, so senders and admins can see how files were handled.

## Guest links (recipients without an account)

- Created by choosing **Create link** or sending to an email with no account.
- URL: `https://send.psionium.portalvii.com/r/<id>#<link-key>`. The fragment never reaches the server.
- Optional protections, combinable: passcode (sent through another channel), email one-time code to a named guest, expiry, download limit, single-device.
- The guest page: minimal, fast, works on phones; shows sender name and verified badge, file list, **Download** / **Preview**; invites the guest to create an account to reply securely (never forced).
- Guests can **reply** with files through a one-time "request files" link the sender can also create directly (**Request files** flow: send someone a link to upload files to you, encrypted to your keys).

## Request files (inbound)

A user or org creates a **request link** ("Upload your documents for the loan application"). Anyone with the link uploads files that are encrypted in their browser to the requester's keys (or a team's). Useful for clients, patients, applicants. Options: required fields, expiry, max files/size, notify on upload.

## Teams and shared inboxes

- Send to a team (e.g. `legal@firm`): sealed to every current team member's identity; new members can be granted access to past transfers by a member re-wrapping file keys (client side).
- Shared inboxes for functions (support@, intake@) with assignment and status.

## Vaults (shared encrypted spaces)

- A vault is a persistent shared folder for a team or project, synced by the desktop app, browsable in the web app.
- Each vault has its own key, wrapped for each member's identity; adding/removing members re-wraps keys (removal rotates the vault key for future files).
- Versioning, retention policies, legal hold (enterprise), activity log.

## Limits per plan (initial proposal; owner approves in 14)

| | Free | Pro | Team | Business | Enterprise |
|---|---|---|---|---|---|
| Max transfer size | 2 GB | 20 GB | 50 GB | 50 GB | Custom |
| Storage | 5 GB | 200 GB | 1 TB pooled | 5 TB pooled | Custom |
| Max expiry | 7 days | 1 year | 1 year | Custom | Custom |
| Guest links / month | 20 | Unlimited | Unlimited | Unlimited | Unlimited |
| Request-file links | 1 | 10 | Unlimited | Unlimited | Unlimited |
| Vaults | – | 3 | Unlimited | Unlimited | Unlimited |
| Read receipts, revocation | ✓ | ✓ | ✓ | ✓ | ✓ |

## Integrations (later stages)

Outlook and Gmail add-ins (attach as pSIONIUM link), Slack/Teams (send link with preview of sender only), Zapier/webhooks, TaskFlow (encrypted ticket attachments), SFTP/automation via CLI and API.

## Format work required

- `.psen` v3 (spec first, then implementation, interop, vectors, review):
  - encrypted manifest stanza (file names, sizes, message, transfer id binding),
  - symmetric recipient stanza for guest links (link key ⊕ optional passcode/OTP factor via HKDF),
  - transfer id and recipient list binding inside the signature to prevent replay into another transfer.
- v2 files must still decrypt forever.

## Acceptance tests (must pass before release)

- J2, J3, J4 from 01 end to end on web, desktop, mobile and CLI.
- A 10 GB file uploads and downloads with constant memory, resumes after network loss.
- Revoked transfer cannot be downloaded by recipients who had not downloaded it.
- Tampering with any stored object or wrapped key makes opening fail with a clear message.
- Key change of a recipient between composing and sending shows a warning.
- Guest page works with JavaScript-only WASM on current Chrome, Safari (incl. iOS), Firefox, Edge.
