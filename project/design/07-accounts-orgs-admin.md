# 07 · Accounts, organizations and the customer admin console

## Accounts

| Feature | Design |
|---|---|
| Sign-up | Email + password (Argon2id, breached-password check), or Google / Microsoft sign-in, or passkey-first. Email verification required before sending |
| Sign-in | Passkey, password + MFA, SSO (if the email domain belongs to an org with SSO enforced) |
| MFA | Passkeys (preferred), TOTP authenticator apps, recovery codes for MFA. SMS only for non-admin users if the owner approves (14) |
| Sessions | Listed in settings with device, location, last active; revoke one or all |
| Handles | Optional `@name` for sharing without email |
| Profile | Name, avatar, handle, verified email(s), language, time zone |
| Account deletion | Self-service; deletes keys, transfers, vault memberships after a 7-day grace period; org-owned accounts follow org policy |
| Data export | Download your transfers (encrypted or decrypted on device), contacts, settings |

Account security model (keys, devices, recovery) is in 03.

## Organizations

| Feature | Design |
|---|---|
| Creation | From a Team/Business trial, a purchase, or by PORTAL VII sales (staff console) |
| Domain verification | DNS TXT record; verified domains auto-join or auto-suggest users with that email domain |
| Members | Invite by email, bulk CSV, SCIM provisioning (Okta, Microsoft Entra ID, Google Workspace), JIT via SSO |
| Teams | Groups for sending (team inboxes) and for vault access |
| SSO | SAML 2.0 and OpenID Connect; enforce SSO for verified domains; break-glass owner account |
| Roles (RBAC) | **Owner** (everything, billing), **Admin** (members, policies, audit), **Billing admin**, **Auditor** (read-only audit and reports), **Member**, **Guest member** (external collaborator with limited rights). Custom roles on Enterprise |
| Multi-org | One account can belong to several orgs; a switcher in every client; personal space always separate |

## Policies (per org, versioned, audited)

| Area | Settings |
|---|---|
| Authentication | Require MFA; require passkeys; allowed sign-in methods; session length; allowed countries/IP ranges (Enterprise) |
| Devices | Allow browsers as persistent devices; require device approval by admin; max devices per user; require OS screen lock |
| Recovery | Admin escrow on/off; k-of-n approvers; recovery kit required |
| Sharing | External recipients allowed (all / approved domains / none); guest links allowed; max link expiry; passcode required for guest links; request links allowed |
| Delivery | Allowed delivery modes; auto-decrypt only on managed devices; view-only default |
| Retention | Default and maximum retention for transfers and vaults; legal hold (Enterprise) |
| Data classes | Labels (Public, Internal, Confidential, Restricted) with per-label rules (e.g. Restricted: no guest links, max 24 h expiry) |
| Managed decryption | Off by default; Enterprise only; requires customer KMS/HSM key (03) |
| API | Who may create API keys; allowed scopes |
| Scan | Repositories and domains that belong to the org; alert rules |

## Customer admin console (in the web app, `Admin`)

| Section | Contents |
|---|---|
| Overview | Seats used/available, active users, transfers this month, storage, policy health checks ("12 users without MFA"), license status |
| Members | Search, invite, roles, teams, status, last active, devices count, MFA status; suspend, remove, transfer ownership of data |
| Teams | Create, members, team inbox settings |
| Devices | All devices across the org; remove; require re-approval |
| Policies | All settings above with preview of impact before saving |
| Audit log | Every security-relevant event (sign-ins, device changes, policy changes, transfers created/opened/revoked metadata, admin actions), filters, CSV/JSON export, SIEM streaming (Splunk, Sentinel, Datadog via webhook/syslog), hash-chain integrity check |
| Recovery requests | Pending recovery approvals (k-of-n) |
| Domains & SSO | Verify domains, configure SAML/OIDC, SCIM tokens |
| Integrations | API keys, webhooks, Slack/Teams, TaskFlow |
| Scan | Org-wide readiness (10) |
| Billing & license | Plan, seats (add/remove), invoices, payment method, license file (self-hosted), renewal date |
| Support | Open a ticket (goes to PORTAL VII support desk), see ticket status |

## Notifications

In-app notification center, email, push (apps), and per-user preferences: new transfer, transfer opened, link expiring, key change of a contact, new device sign-in, policy change (admins), seat limit (admins), invoice (billing admins). Delivered through the notify service with TaskFlow's mail throttle and daily-limit controls.

## Acceptance

- An org of 50 can be onboarded with SSO + SCIM in under an hour following the docs.
- Every admin action appears in the audit log within 5 seconds, with actor, target and before/after values.
- Policies are enforced server-side; clients only reflect them.
