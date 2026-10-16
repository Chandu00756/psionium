# 10 · Scan product

## What exists today (and how to use it)

`psion scan` is built and released (v1.0.0). It has no UI beyond the terminal yet.

| Command | What it does |
|---|---|
| `psion scan ~/my-project` | Lists cryptography in code, dependencies, certificates and keys, grouped by risk |
| `psion scan --tls example.com` | Checks a live server: TLS version, cipher, certificate, and whether post-quantum X25519MLKEM768 is supported |
| `psion scan . --format markdown -o report.md` | Readable report to share |
| `psion scan . --format cbom -o crypto-bom.json` | CycloneDX 1.6 cryptography bill of materials for inventory tools |
| `psion scan . --format json` | Every finding for scripts |
| `psion scan . --fail-on quantum-vulnerable` | Exit status 2 if quantum-vulnerable crypto is found (for CI) |

Categories: **Quantum-vulnerable** (RSA, ECC, DH, DSA) · **Weak** (MD5, SHA-1, DES, RC4, old TLS) · **Review** · **Already post-quantum**. Details: `docs/scan.md`.

## Product path

### Stage A — Developer adoption (free)
- **HTML report** (`--format html`): single self-contained file with summary, charts, findings by category, fix guidance per algorithm, and the 2030/2035 dates; readable by managers and auditors.
- **GitHub Action** `psionium/scan-action@v1`: runs `psion scan` on pull requests, uploads CBOM and HTML as artifacts, posts a summary comment (new vulnerable findings in this PR), fails on policy; GitHub code scanning (SARIF) output so findings appear in the Security tab.
- **GitLab CI template** and a **Docker image** `ghcr.io/chandu00756/psion`.
- **Baseline file** (`.psionium-scan.toml`): accepted findings with reasons, so CI fails only on new ones; ignore paths; custom rules.
- More detectors over time: lock-file versions of crypto libraries, Java keystores, Windows cert stores, Kubernetes secrets/manifests, cloud KMS key specs (AWS/GCP/Azure APIs, read-only), SSH server configs, VPN configs.

### Stage B — Scan dashboard (paid, in the web app)
- **Projects:** repositories (uploaded by the Action or `psion scan --upload`), with findings over time and trend charts.
- **Endpoints:** domains and IPs monitored on a schedule (daily): TLS versions, PQ support, certificate algorithms and expiry; alerts on changes.
- **Inventory:** org-wide cryptographic inventory merged from CBOMs (ECMA-424), filterable by algorithm, owner, system.
- **Migration plan:** each quantum-vulnerable item gets a recommended replacement (ML-KEM/hybrid, ML-DSA, SLH-DSA), effort estimate, owner, status; export tasks to TaskFlow, Jira, GitHub Issues.
- **Policies & alerts:** "no new RSA in main", "certificates expiring after 2030 must be PQ-ready", notify by email/Slack/webhook.
- **Auditor reports:** PDF/HTML evidence pack: inventory, progress over time, policy status, mapped to NIST IR 8547 dates and CNSA 2.0 milestones (with sources).

### Stage C — Services
- Readiness assessment offered by PORTAL VII or partners (paid engagement) using the dashboard.
- Migration assistance: proxies and libraries (Stage 6 of the roadmap).

## Data and privacy

- The scanner never uploads source code; uploads contain findings (file path, line, short excerpt — excerpts can be disabled with `--no-excerpts`) and the CBOM.
- Private key contents are never reported (already true).
- Endpoint monitoring only for domains the org has verified ownership of (DNS TXT), or public sites with explicit acknowledgement.

## Acceptance

- The Action runs on a 100k-file repository in under 2 minutes on a standard runner.
- The HTML report renders without network access and passes accessibility checks.
- Dashboard trend numbers match the uploaded CBOMs exactly.
