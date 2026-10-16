# 09 · Business operations (PORTAL VII back office)

How PORTAL VII itself runs pSIONIUM as a business: selling, licensing, billing, supporting, marketing and governing. Built as the **staff console** plus a few proven external tools.

## Staff console (`staff.psionium.portalvii.com`)

Internal Next.js app on the admin API. Access: PORTAL VII staff accounts only, passkey + IP allowlist/VPN, every action audited in `staff.actions`. Staff **never** see customer content (zero knowledge); they see metadata needed to operate.

| Section | What staff can do | Roles |
|---|---|---|
| Customers | Search orgs/users; view plan, seats, usage, health score, owner contacts, open tickets, invoices; notes; timeline of lifecycle events | Sales, Success, Support, Finance |
| Licenses | Issue, extend, upgrade/downgrade, add seats, grant custom entitlements, issue self-hosted license files, revoke; every change requires a reason and is signed via the licensing service | Sales ops, Admin |
| Trials | Extend trials, convert to paid, assign to a sales owner | Sales |
| Plans & pricing | Define plans, entitlements, prices (synced to Stripe Products/Prices), coupons, regional pricing | Admin, Finance |
| Billing | Subscriptions, invoices, refunds, credit notes, dunning status, tax settings (Stripe Tax), revenue reports (MRR, ARR, churn, expansion) | Finance |
| Support tools | Look up a user's account state, devices list, recent errors, transfer **metadata** (never content), resend verification emails, unlock rate limits; "view as" is not offered | Support |
| Abuse & trust | Abuse reports on guest links, take down links, suspend accounts, law-enforcement request log (transparency report) | Trust & safety, Admin |
| Partners | MSP/reseller accounts with sub-orgs, margins, deal registration | Partnerships |
| Content | Announcements (in-app banners), release notes, status incidents | Marketing, Eng |
| Feature flags | Gradual rollouts per org/plan | Eng |
| Metrics | Signups, activation (first transfer), WAU/MAU, transfers/day, storage, conversion, NPS | All |
| Staff admin | Staff accounts, roles, access reviews (quarterly) | Admin |

## Sales

- **Pipeline:** website forms, Scan dashboard upgrade requests, trials, partners → CRM. Start with HubSpot Free CRM or a TaskFlow "Sales" project if the owner prefers to stay in-house (decision in 14). Stages: Lead → Qualified → Demo → Trial → Proposal → Won/Lost.
- **Collateral:** pitch deck, security whitepaper, one-page datasheets per product, sample Scan report, ROI calculator (cost of a breach vs. plan price), customer references (when real).
- **Process:** demo script follows journeys J2, J3, J5, J8; trial success plan; quote → Stripe invoice or contract → license issued in the staff console → onboarding.
- **Design partners first:** 5–10 companies in health, legal, finance, gov supply chain, with discounted pricing for feedback and case studies.

## Marketing

- Website (06): product pages, pricing, docs, guides, trust center.
- Content: quantum-readiness guides, "2030/2035 deadline" checklists, Scan sample reports, comparisons (vs. WeTransfer/Dropbox Transfer/Proton Drive/Tresorit/Kiteworks), webinars.
- Free Scan as the lead magnet; GitHub presence (open-source core, Action in Marketplace).
- Newsletter and product updates via Brevo (already used by TaskFlow), with consent and unsubscribe.
- Events/communities: security meetups, PQC working groups, LinkedIn.
- Metrics: visitors → signups → activated → paying; per channel.

## Customer success and support

- **Support desk:** TaskFlow (PORTAL VII's own ITSM) with a pSIONIUM service catalog: Account access, Billing, Technical, Security report, Feature request. Customers open tickets from the admin console, email, or the website.
- **SLAs by plan:** Free: community/docs; Pro/Team: email, 2 business days; Business: 1 business day, 99.9% uptime target (published only after it is measured); Enterprise: named contact, 4-hour critical response, custom SLA.
- **Onboarding:** checklist for orgs (domain, SSO, policies, recovery, pilot group, rollout), office hours.
- **Health score:** seat usage, weekly active, transfers, failed payments, ticket volume → churn risk list for success.
- **Knowledge base:** in TaskFlow KB and docs site.

## Finance and billing

- **Stripe:** Products/Prices per plan, Checkout for self-serve, Customer Portal for card and invoices, Stripe Tax, invoices for enterprise (net 30), webhooks into the licensing service (`invoice.paid`, `customer.subscription.updated`, `invoice.payment_failed`).
- Revenue recognition and bookkeeping in the owner's accounting tool (decision in 14).
- Currency USD first; INR/EUR later.

## Partners (MSPs and resellers)

- Partner portal inside the staff console's partner role or a partner area in the web app: create and manage customer orgs, consolidated billing, margins, co-branded onboarding.
- Distribution through MSPs that already look after small regulated companies.

## Legal and compliance program

- Documents: Terms of Service, Privacy Policy, DPA (GDPR), Subprocessors list, Acceptable Use Policy, Cookie policy, SLA, Enterprise MSA; reviewed by a lawyer (14).
- Compliance roadmap (claims only when achieved): SOC 2 Type I → Type II (tooling: Vanta, as selected in the original vendor research), ISO 27001 later, HIPAA BAA readiness for health customers, GDPR/CCPA processes (data subject requests through support).
- Security program: independent cryptographic review (format, protocols), annual penetration test, bug bounty after launch, vulnerability disclosure policy (SECURITY.md).
- Transparency report: yearly count of legal requests and what could be provided (metadata only).

## Internal operations

- Company tooling: GitHub (code), TaskFlow (tickets, projects, KB), Brevo (email), Stripe (billing), Grafana (metrics), status page, password manager for staff, hardware keys for staff.
- On-call rotation and incident process (12).
- Quarterly access reviews of staff accounts and production access.

## Acceptance

- A sale can go from lead to active licensed org without any manual database change.
- Every license change, refund and suspension has an audit entry with staff identity and reason.
- Finance can produce MRR, churn and invoices without engineering help.
