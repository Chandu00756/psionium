# 12 · Quality, security and operations

## Testing (every repository)

| Layer | What | Where |
|---|---|---|
| Unit | Every module; crypto with known-answer tests | All repos |
| Format conformance | Committed vectors for every format version; cross-implementation matrix (Rust, Go, WASM, Python, TS) | `psionium` CI |
| Mutation / fuzzing | Random corruption tests (exist); `cargo-fuzz` targets for parsers, licenses, link payloads, API inputs; continuous fuzzing (OSS-Fuzz once public) | `psionium` |
| Integration | Services against real PostgreSQL/Redis/MinIO in Docker; contract tests from OpenAPI | `psionium-cloud` |
| End to end | Journeys J1–J9 (01) driven through the web app (Playwright), apps (Flutter integration tests), CLI (pseudo-terminal) | `psionium-cloud`, `psionium-apps` |
| Security | Dependency audit (`cargo audit`, `govulncheck`, `npm audit`), SAST (CodeQL/semgrep), secret scanning, container scanning, DAST on staging (OWASP ZAP) | CI |
| Performance | 10 GB transfer with constant memory; API p95 < 200 ms at target load; TUI open < 150 ms | Nightly |
| Accessibility | axe checks on web; keyboard-only runs; TUI themes/NO_COLOR snapshots | CI |
| Visual | Screenshot/snapshot tests for web pages and TUI screens | CI |

Rule (from `../RULES.md`): never report work done without the full suite green and the original issue verified.

## CI/CD

- GitHub Actions per repository with timeouts on every job (lesson from the Windows hang).
- `main` always releasable; feature branches + PRs once there is more than one contributor; required checks.
- Staging deploy on every merge; production deploy by tag with approval; database migrations forward-only and backward-compatible for one release.
- Releases: signed (GitHub provenance attestations + ML-DSA release signature + SHA256SUMS), changelog, docs updated in the same change.
- Apps: notarized macOS builds, signed Windows installers (code-signing certificate, 14), App Store / Play Store pipelines (fastlane).

## Environments and infrastructure

- Start: one production host (the Oracle Cloud server pattern used by TaskFlow) with Docker Compose, managed backups, plus object storage; staging on a smaller host.
- Then: two production hosts behind a load balancer, PostgreSQL primary + replica, object storage with versioning; later Kubernetes if needed.
- Infrastructure as code (Terraform for cloud resources; Compose/Helm for services) in `psionium-cloud/infra`.
- Secrets in a secrets manager (not `.env` files on servers long term); production access only through audited bastion with hardware keys.
- CDN/WAF in front of the web origins (Cloudflare), with post-quantum TLS to clients.

## Monitoring and incidents

- Metrics (Prometheus), dashboards (Grafana), logs (Loki or ELK), traces (OpenTelemetry), uptime checks, error tracking.
- SLOs: API availability 99.9% (target), transfer success rate 99.5%, p95 latency; error budgets reviewed monthly.
- On-call: paging for SLO burn and security alerts; runbooks in the repo; incident template; blameless post-mortems; customer communication through the status page and email for impacting incidents; security incidents follow a documented response plan with notification timelines (GDPR 72 h).

## Backups and disaster recovery

- PostgreSQL: continuous WAL archiving + daily snapshots, 30-day retention, encrypted; monthly restore test.
- Object storage: versioning + cross-region replication (Business/Enterprise regions).
- Wrapped keys are in the database, so a database restore restores access; object loss without replication means data loss: replicate.
- RPO 15 minutes, RTO 4 hours (targets; verified in drills before publishing).

## Security program

| Item | When |
|---|---|
| Independent cryptographic review of `.psen` v2 | Before handling customers' irreplaceable data (open item) |
| Review of v3 + device linking + recovery + transparency log + licensing | Before Transfer GA |
| Penetration test of web app, API, apps | Before Business plan GA, then yearly |
| Bug bounty (private, then public) | After first pentest |
| SOC 2 Type I → Type II | When the first Business customers require it |
| Threat model updates | Every new feature touching keys or data paths |
| Staff security | Hardware keys, least privilege, quarterly access reviews, security training |

## Claims policy

Public claims (website, sales decks, docs) must match evidence: no "certified", "compliant", uptime or user numbers until achieved and documented in the trust center. The original site's false claims (ISO 27001, GDPR/HIPAA/PCI, uptime) were removed for this reason.

## Definition of done (any feature)

1. Implements the design here (or the design was updated through the change process).
2. Tests at the right layers, all CI green, including other repos affected.
3. Docs and changelog updated; screenshots updated if UI changed.
4. Security review checklist done for anything touching keys, auth, or data paths.
5. `../STATUS.md`, `../ROADMAP.md`, `../LOG.md` updated.
