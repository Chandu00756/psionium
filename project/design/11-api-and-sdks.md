# 11 · API and SDKs

## Public REST API (`api.psionium.portalvii.com/v1`)

- OpenAPI 3.1 is the source of truth (`psionium-cloud/api/openapi.yaml`); docs, TypeScript and Go clients are generated from it.
- Auth: OAuth 2.0 (authorization code + PKCE for web/apps, device flow for CLI), API keys for servers (`Authorization: Bearer psk_live_…`), scoped (`transfers:write`, `transfers:read`, `directory:read`, `audit:read`, `scan:write`, `admin:*`).
- Conventions: JSON, UUIDv7 ids, cursor pagination, `Idempotency-Key` on POST, RFC 9457 problem details for errors, rate limits with `RateLimit-*` headers, versioned by path.

| Resource | Endpoints (summary) |
|---|---|
| Directory | `GET /directory/lookup?email=` (keys + transparency proof), `GET /directory/log/root`, `GET /directory/log/proof` |
| Transfers | `POST /transfers` (create, returns upload session), `PUT` parts via pre-signed URLs, `POST /transfers/{id}/complete`, `GET /transfers` (inbox/sent), `GET /transfers/{id}`, `POST /transfers/{id}/revoke`, `PATCH` expiry, `GET /transfers/{id}/activity` |
| Links & requests | `POST /links`, `POST /requests`, `GET /requests/{id}/uploads` |
| Vaults | `POST /vaults`, `GET /vaults/{id}/items`, items upload/download, members |
| Contacts | `GET/POST /contacts`, `POST /contacts/{id}/verify` |
| Devices & keys | `GET /devices`, `POST /devices/approve`, `DELETE /devices/{id}`, `POST /keys/rotate` |
| Orgs & admin | members, teams, policies, audit (`GET /audit`, streaming export), domains, SSO, SCIM 2.0 (`/scim/v2/*`) |
| Licensing | `GET /license` (signed license + entitlements), `GET /usage` |
| Scan | `POST /scan/reports` (CBOM + findings), `GET /scan/projects`, endpoints, alerts |
| Webhooks | `POST /webhooks` (subscribe), events: `transfer.created`, `transfer.delivered`, `transfer.opened`, `transfer.revoked`, `request.uploaded`, `member.added`, `policy.changed`, `scan.alert`, `license.changed`; signed with HMAC-SHA-384 and timestamp |

Every endpoint that touches content handles ciphertext only; encryption happens in the SDK on the caller's side.

## SDKs

All SDKs wrap `psionium-core`, so formats and crypto are identical everywhere.

| Language | Packaging | Notes |
|---|---|---|
| Rust | crates.io: `psionium-core`, `psionium-client` | Reference implementation |
| TypeScript / JavaScript | npm `@psionium/sdk` (WASM core + generated client) | Browser and Node; streaming via Web Streams |
| Python | PyPI `psionium` (PyO3 bindings + client) | Sync and async |
| Go | `github.com/Chandu00756/psionium/go` | Grows from `interop/go` (already a working format implementation) + generated client |
| Java/Kotlin, Swift, .NET | Later, via uniffi/FFI | On customer demand |

### SDK capabilities
1. **Files:** encrypt/decrypt/sign/verify `.psen` locally (same as the CLI).
2. **Transfers:** send/receive programmatically (`client.transfers.send(files, to=[…])`), watch an inbox.
3. **Field-level encryption:** `encrypt_field(value, context)` → compact token `psf1:…` (AES-256-GCM under a data key, data key wrapped by an org key), deterministic mode for searchable fields (documented trade-offs), key rotation by re-wrapping data keys.
4. **Envelope keys and BYOK:** org master keys in AWS KMS, Google Cloud KMS, Azure Key Vault, or PKCS#11 HSMs; the SDK asks the KMS to wrap/unwrap data keys; PORTAL VII never sees them.
5. **Tokenization (later):** format-preserving tokens for card numbers/IDs with a vault mapping, for PCI scope reduction (claims only after assessment).

## Developer experience

- Docs with copy-paste quick starts per language, sample apps (Next.js upload portal, Python batch sender, Go service with field encryption), Postman collection, sandbox environment with test data, API status, changelog.
- API keys managed in the web app; usage dashboard; webhook delivery logs with replay.

## Acceptance

- The same file encrypted by any SDK decrypts with the CLI and every other SDK (cross-language test matrix in CI, extending today's Go interop job).
- Generated clients are rebuilt and published automatically when the OpenAPI spec changes.
