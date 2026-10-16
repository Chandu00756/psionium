# 08 · Licensing

Everything sold is licensed: the cloud service, the apps, the CLI's account features, the SDK, and self-hosted deployments. The design keeps the open-source core credible while making paid features impossible to use without a valid license.

## The boundary: what is free, what is licensed

| Free forever (open source, Apache-2.0) | Licensed (paid plans, enforced by the service) |
|---|---|
| `psionium-core`, the `.psen` format, the Go implementation | Accounts beyond free limits, transfers, guest links, request links, vaults |
| `psion` local commands: keygen, encrypt, decrypt, sign, inspect, passphrase, scan, the interactive shell's local screens | Org features: admin console, SSO/SCIM, policies, audit export, recovery escrow |
| Scan CLI and GitHub Action (local reports) | Scan dashboard, monitoring, auditor reports |
| | SDK usage beyond the free tier, API keys, webhooks |
| | Self-hosted / dedicated deployments, managed decryption, CNSA mode support |

**Why:** licensing code inside open-source software can be removed by anyone, so licensed features are those that need PORTAL VII's service (or a license file verified by a self-hosted server). Enforcement happens on servers; clients only display entitlements. This keeps trust (open core) and revenue (service) separate and honest.

## Plans (initial proposal; owner approves prices in 14)

| Plan | For | Price idea | Includes |
|---|---|---|---|
| **Free** | Individuals | $0 | 1 user, transfer limits (04), 5 GB, 20 guest links/month, Scan CLI |
| **Pro** | Professionals | ~$8 / month | Higher limits, vaults (3), request links, custom expiry, priority email support |
| **Team** | Small teams (2–50) | ~$10 / user / month | Org, teams, shared inboxes, basic admin, audit log (90 days), pooled storage |
| **Business** | Regulated companies | ~$25 / user / month | SSO/SCIM, all policies, recovery escrow, data classes, audit export/SIEM, Scan dashboard, 1-year audit retention, SLA 99.9% (only once measured) |
| **Enterprise** | Large/public sector | Contract | Dedicated or self-hosted, HSM/KMS BYOK, managed decryption, CNSA mode, custom retention, legal hold, named support, security review package |
| **Developer** | App builders | Usage-based | SDK operations, API calls, storage; 10,000 operations/month free |
| **Scan Pro** | Engineering teams | Per repository / endpoint | Dashboard, monitoring, alerts, reports, integrations |

Discounts: annual billing (~2 months free), nonprofit/education, partners (09). Trials: 14 days of Business, no card required.

## Entitlements

Each plan is a set of entitlements; licenses carry entitlements, not plan names, so sales can grant custom bundles.

| Entitlement key | Type | Example |
|---|---|---|
| `seats` | integer | 25 |
| `storage_gb` | integer | 5000 |
| `transfer_max_gb` | integer | 50 |
| `guest_links_per_month` | integer or unlimited | -1 |
| `vaults` | integer | -1 |
| `sso`, `scim`, `policies.advanced`, `audit.export`, `recovery.escrow`, `data_classes`, `managed_decryption`, `cnsa_mode`, `byok`, `self_hosted` | boolean | true |
| `audit_retention_days` | integer | 365 |
| `scan.repos`, `scan.endpoints` | integer | 50, 20 |
| `api.ops_per_month` | integer | 1000000 |
| `support_tier` | enum | standard / priority / named |

## License objects

- Stored in `licensing.licenses`, one active per org (plus history).
- Serialized as canonical JSON:
  `{ "license_id", "org_id", "org_name", "entitlements": {…}, "seats", "issued_at", "not_before", "expires_at", "grace_days": 14, "deployment": "cloud" | "self_hosted", "instance_id" (self-hosted), "issuer": "PORTAL VII" }`
- Signed with PORTAL VII's **license signing key** (ML-DSA-65, plus Ed25519 for tooling that cannot verify ML-DSA yet; both must verify). Text form: `psionlic:<base64url(json)>.<base64url(signature)>`.
- The license public key ships in every client and server build and in the docs; key rotation supported by key id.
- The signing key lives in an HSM or offline machine; licenses are signed by the licensing service through a narrow signing API with audit (09).

## Activation and enforcement

| Where | How |
|---|---|
| Cloud service | Authoritative. Every request checks the org's current entitlements (cached in Redis, invalidated on change). Over-limit actions return `402`/`403` with a machine-readable reason |
| Web app, apps, CLI | Read entitlements from the API (and cache the signed license for offline display). Show upgrade prompts; never the source of truth |
| Self-hosted server | Requires a license file (`psionlic:`) at startup; verifies signature, expiry, instance id; counts seats locally; phones home weekly for renewal/revocation when allowed (air-gapped: manual renewal file); 14-day grace after expiry with banners, then read-only mode (no new transfers; existing files always openable) |
| SDK | API keys tied to the org; usage metered per operation; free tier limits; overage billed or blocked per contract |

**Never lock people out of their own data.** An expired or downgraded license blocks new paid actions, never opening existing files.

## Seats

- A seat is consumed by each active member (not guests). Suspended users free their seat after 30 days.
- Owners add seats self-service (prorated by Stripe) or through sales. Over-seat invites are blocked with a clear message.
- Staff console shows seat utilization for sales (upsell) and success (unused seats).

## Lifecycle events

trial started → trial ending (day 10, 13) → converted / expired → active → payment failed (retry schedule, 14-day grace, banners) → renewed / cancelled (data export window 30 days) → reactivated. Each event: email to billing admins, staff console entry, webhook.

## Acceptance

- A forged or edited license fails verification in all clients and servers (tests with mutated licenses).
- Downgrade from Business to Team disables SSO enforcement gracefully with owner warnings, never locks members out.
- A self-hosted instance with an expired license still opens every existing file.
