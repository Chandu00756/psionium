# 02 · Architecture

## Principles

- **One crypto core.** `psionium-core` (Rust) does all cryptography. Everything else calls it: the CLI natively, the web app through WebAssembly, the Flutter apps through `flutter_rust_bridge`, SDKs through WASM/FFI/PyO3. Servers never encrypt or decrypt user content (except the opt-in managed decryption service, 04).
- **Reuse TaskFlow's proven stack** for the cloud: Go services, PostgreSQL, Redis, Next.js, Docker Compose on the existing Oracle Cloud host first, with the same deploy, email, monitoring (Prometheus/Grafana) and backup patterns. Move to Kubernetes only when load requires it.
- **Thin, boring services.** A handful of Go services with clear ownership, REST + JSON, OpenAPI documented, one PostgreSQL database with schemas per service.

## System diagram

```
 Clients (plaintext and private keys never leave these)
 ┌──────────────┐ ┌──────────────┐ ┌───────────────┐ ┌──────────────┐ ┌──────────────┐
 │ psion CLI    │ │ Web app      │ │ Desktop/mobile│ │ Browser link │ │ SDKs         │
 │ (Rust)       │ │ (Next.js +   │ │ (Flutter +    │ │ receiver     │ │ (TS/Py/Go/   │
 │              │ │  WASM core)  │ │  Rust core)   │ │ (WASM core)  │ │  Rust)       │
 └──────┬───────┘ └──────┬───────┘ └──────┬────────┘ └──────┬───────┘ └──────┬───────┘
        └────────────────┴──────── HTTPS (TLS 1.3, X25519MLKEM768 preferred) ─┘
                                        │
                              ┌─────────▼─────────┐
                              │ API gateway (Go)  │  auth, rate limits, request ids, CORS
                              └─────────┬─────────┘
   ┌───────────┬───────────┬────────────┼────────────┬────────────┬────────────┬───────────┐
   ▼           ▼           ▼            ▼            ▼            ▼            ▼           ▼
 identity   directory   transfer      vault         org        licensing     scan       notify
 (accounts, (keys +     (transfers,   (shared       (orgs,     (plans,       (reports,  (email,
 sessions,  transparency upload       spaces,       teams,     entitlements, CBOMs,     push,
 MFA, SSO,  log)        sessions,     folders)      policies,  licenses,     TLS        in-app,
 devices)               links)                      audit)     billing)      monitor)   webhooks)
   └───────────┴───────────┴────────────┴────────────┴────────────┴────────────┴───────────┘
                │                    │                     │
          PostgreSQL 16         Object storage        Redis 7 (sessions, rate limits,
          (schemas per          (S3-compatible:       queues, pub/sub for inbox updates)
           service)              ciphertext only)

 Internal: staff console (Next.js) ──► admin API (separate auth, VPN/IP-allowlisted, audited)
 Optional enterprise: managed-decryption worker in the customer's environment (04)
```

## Components

| Component | Tech | Responsibility | Repo |
|---|---|---|---|
| `psionium-core` | Rust | Formats (.psen v2, future v3 for transfers/vaults), keys, signatures, key wrapping, recovery codes, license verification | `psionium` (exists) |
| `psionium-wasm` | Rust → WASM (wasm-bindgen) | Core for browsers and Node | `psionium` |
| `psionium-ffi` | Rust (C ABI, uniffi) | Core for Flutter (flutter_rust_bridge), Swift/Kotlin, Go (cgo optional) | `psionium` |
| `psion` | Rust (clap + ratatui) | CLI: scripting mode + interactive shell (05) | `psionium` (exists, scripting mode only) |
| `psionium-scan` | Rust | Scanner engine (10) | `psionium` (exists) |
| Go interop package | Go | Second implementation of the format; becomes the base of the Go SDK | `psionium/interop/go` (exists) |
| Cloud services | Go 1.24+, chi or net/http, sqlc, pgx | identity, directory, transfer, vault, org, licensing, scan, notify, gateway, admin API | `psionium-cloud` (new) |
| Web app | Next.js (App Router), TypeScript, Tailwind, WASM core | Inbox, send, vaults, contacts, scan dashboard, settings, org admin, billing | `psionium-cloud/web` (new) |
| Staff console | Next.js | PORTAL VII back office (09) | `psionium-cloud/staff` (new) |
| Desktop + mobile apps | Flutter 3 + Rust core | macOS, Windows, Linux, iOS, Android; share extensions; auto-decrypt folders | `psionium-apps` (new; revive `dock` screens from `legacy`) |
| Marketing site + docs | Existing Next.js site (`~/P7Ultra/portalvii-website2`) + docs section | Product pages, pricing, download, docs, trust center, blog | `P7Ultra` (exists) |
| GitHub Action | TypeScript (or Docker) wrapping `psion scan` | CI scanning (10) | `psionium-scan-action` (new) |

## Environments and domains (proposal; owner confirms in 14)

| Environment | Purpose | Domains |
|---|---|---|
| Local | Docker Compose with seeded test data | `localhost` |
| Staging | Every merge to `main`; test Stripe; test email | `staging.psionium.portalvii.com` |
| Production | Customers | Web app `app.psionium.portalvii.com`, API `api.psionium.portalvii.com`, guest links `send.psionium.portalvii.com`, staff `staff.psionium.portalvii.com` (IP-allowlisted), marketing `portalvii.com/psionium`, docs `portalvii.com/psionium/docs` |

Guest links get their own origin so a compromised marketing page or app script cannot read the `#fragment` of a link page. The link page loads a minimal, versioned, Subresource-Integrity-pinned bundle.

## Data model (core tables)

Schemas group tables by owning service. Every table has `id` (UUIDv7), `created_at`, `updated_at`; tenant data carries `org_id` where applicable. Nothing here holds plaintext content or unwrapped private keys.

| Schema.table | Key columns |
|---|---|
| `identity.users` | email (verified), display_name, handle, status, mfa_required, last_seen |
| `identity.credentials` | user_id, type (password-hash Argon2id, passkey/WebAuthn, TOTP, SSO link), data |
| `identity.sessions` | user_id, device_id, created/expires, ip, user_agent, revoked |
| `identity.devices` | user_id, name, platform, device_public_key, approved_by, last_seen, revoked |
| `identity.wrapped_identity` | user_id, version, identity_ciphertext (identity private keys wrapped under the user's account key), wrapped_account_key per device / recovery / org escrow |
| `directory.keys` | user_id, version, psionpk, psionvk, fingerprint, valid_from, revoked_at |
| `directory.log` | append-only transparency log entries (user, key hash, prev hash, signature of the log key) |
| `transfer.transfers` | sender_id, org_id, subject (encrypted), status, expires_at, max_downloads, delivery_policy, revoked_at |
| `transfer.recipients` | transfer_id, user_id or guest (email hash), state (sent, delivered, opened, revoked), opened_at |
| `transfer.objects` | transfer_id, storage_key, size, chunk_count, sha384_of_ciphertext |
| `transfer.links` | transfer_id, token_hash, passcode_required, otp_email_hash, downloads_used |
| `vault.spaces` | org_id, name, members (via `vault.members`), key versions, retention |
| `vault.items` | space_id, path (encrypted), object key, version, size |
| `org.orgs` | name, verified_domains, plan_id, status, region |
| `org.members` | org_id, user_id, role, team ids, status |
| `org.policies` | org_id, policy JSON (versioned) |
| `org.audit_log` | org_id, actor, action, target, ip, metadata, hash, prev_hash (hash chain) |
| `licensing.plans` / `entitlements` / `licenses` / `seats` | plan definitions, per-org grants, signed license blobs, seat assignments |
| `billing.customers` / `subscriptions` / `invoices` | Stripe ids mirrored, status, amounts |
| `scan.projects` / `reports` / `findings` / `endpoints` | uploaded CBOMs, findings over time, monitored TLS endpoints |
| `notify.outbox` | queued emails/push/webhooks with retry (reuse TaskFlow's mail gate: throttle pause, daily limits) |
| `api.keys` | org_id, prefix, hash, scopes, last_used, revoked |
| `staff.users` / `staff.actions` | internal accounts and every action they take (audited) |

## Storage

- Ciphertext objects in S3-compatible storage (Oracle Object Storage to start; Cloudflare R2 or AWS S3 as alternatives). Uploads via pre-signed URLs, chunked and resumable (5–64 MiB parts), checked by size and SHA-384 of ciphertext.
- Per-object lifecycle rules enforce expiry and retention. Deleting a transfer deletes its objects and wrapped keys (crypto-shredding: without wrapped keys, ciphertext is useless).
- Region choice per org (later: EU, US) for data residency.

## APIs

- Public REST API under `/v1`, OpenAPI 3.1 spec in `psionium-cloud/api/openapi.yaml`, generated TS/Go clients. Auth: session cookies (web), OAuth 2.0 device flow tokens (CLI/apps), API keys (SDK). Detailed in 11.
- Real-time inbox updates via Server-Sent Events (web) and push (apps).
- Admin API separate from the public API, never exposed publicly.

## Observability

Structured JSON logs (no secrets, no file names in plaintext), Prometheus metrics, Grafana dashboards, uptime checks, error tracking (self-hosted Sentry or GlitchTip), alerting to email/Slack. Reuse TaskFlow's monitoring stack.

## Scale assumptions for the first version

Thousands of users, tens of thousands of transfers per day, files up to 50 GB (streamed, never fully in memory). One region. Single PostgreSQL with backups and a replica. Revisit when any of these is exceeded.
