# 13 · Research track and the original PVII ideas

The owner's original documents (`~/Desktop/PVII`, 26 documents from December 2024) contain many ideas. Nothing is lost: each idea is mapped below to where it lives now. Rule: research never enters the product's encryption path until it is published and independently reviewed (`../VISION.md`).

## Ideas that are now product features

| Original idea (document) | Where it lives now |
|---|---|
| Multi-factor authentication, RBAC, SSO (SAML/OAuth), password policies (Security Requirements, User Stories) | 07 Accounts, orgs, admin |
| Key management service: generation, rotation, hierarchy, HSM integration, audit of key operations (Encryption Service Development, Architecture) | 03 Security model, 11 BYOK/KMS/HSM |
| End-to-end encryption protocol, client-side encryption, key exchange (Sprint 1 plan) | 03, 04 |
| Field-level encryption service (Sprint 1 plan) | 11 SDK field-level encryption |
| Security token service, short-lived tokens, revocation (Sprint 1 plan) | 02/03 sessions, OAuth tokens, API keys |
| Audit logging with SIEM integration (Sprint 1 plan, Logging Nexus) | 07 audit log + SIEM export; hash chain instead of blockchain |
| Kyber + Dilithium hybrid cryptosystem (Architecture Refinement) | Done as ML-KEM + ML-DSA (FIPS 203/204) in `.psen` v2 |
| SPHINCS+ / XMSS hash-based signatures (Research Proposal, Logging Nexus) | SLH-DSA for long-term signatures (roadmap Stage 3) |
| User dashboard, notification center, analytics and reports, help section, responsive design (Scope, User Stories) | 06 web app, 07 notifications, 09 metrics, docs/help |
| Integration with external APIs (Scope) | 11 API, webhooks, 04 integrations |
| Microservices, API gateway, PostgreSQL, Redis, message queue, Docker/Kubernetes, Terraform, Prometheus/Grafana, ELK (Architecture, Tech Specs, Infrastructure) | 02 Architecture, 12 Operations (simplified to a few Go services first) |
| Compliance frameworks list: ISO 27001, NIST CSF, GDPR, CCPA, HIPAA, HITECH, PCI DSS, GLBA, SOX, SOC 2, FISMA, CIS (Compliance requirements) | 09 compliance program; claims only when achieved |
| Vendor research: Vanta recommended for compliance automation (Vendor Research) | 09 SOC 2 tooling |
| Risk assessment, testing strategy, code standards, development methodology (Week 1 docs) | 12 Quality; `../RULES.md` |
| Disaster recovery planning, education and training (Security Design) | 12 backups/DR, staff security |
| Mobile application (Scope) | 06 Flutter apps |
| Offline access (Scope) | Apps cache inbox/vault metadata; CLI works offline for local crypto |
| Multi-language support (Scope) | Web app and apps i18n (later stage) |
| AI-driven threat detection, anomaly detection, behavioral biometrics (Security Design, Auth Design) | Roadmap Stage 8: anomaly alerts on account/key usage (sign-in anomalies, unusual transfer volume). Never inspects content |
| Old pSIONIUM shell (encode/decode/compress) and dock app screens | 05 interactive CLI (heritage commands), 06 apps |
| Rust 2.0 network resilience, threat detection, offline update manager | Roadmap Stage 8 proxy; apps auto-update with signed updates |

## Research only (separate track, publish before any product use)

| Idea | Status and conditions |
|---|---|
| **DIBLE** (Device Identification Based Lattice Encryption, device-fingerprint keys) | Research. The prototype's "lattice" step was a placeholder; fingerprint-derived keys lock users out on hardware changes. Product uses hardware-backed device keys instead (03). May continue as a paper |
| Homomorphic encryption (FHE) for processing encrypted data | Research; candidate for privacy-preserving analytics later |
| Zero-knowledge proofs | Research; possible use in proving key ownership or compliance without revealing data |
| Quantum key distribution (BB84/E91), QRNG | Out of scope for software products; needs special hardware. Revisit only for specific enterprise/government requests |
| Chaos-theory and fractal-based encryption, AI-designed cryptographic algorithms | Not used: non-standard constructions fail security review. Research curiosity only |
| Blockchain / distributed ledger for logs | Replaced by hash-chained audit logs with published anchors (same tamper evidence, far simpler) |
| Edge computing security, in-house CDN | Not needed; use a CDN provider |
| MongoDB secondary store, Kafka, Istio, CQRS (Architecture Refinement) | Not needed at current scale; revisit with evidence |

## Speculative concepts (not buildable; kept for inspiration only)

The "Omniversal Authentication Nexus", "Hybrid Transcendence Authentication Nexus", "Transcendence Logging and Monitoring Nexus" and the large OpenAPI draft (Doc25) describe quantum entanglement identity, time crystals, consciousness and neural-interface authentication, multiverse transactions and teleportation. These cannot be built with existing technology and must not appear in product claims. Their practical intent (strong, continuous, phishing-resistant authentication; tamper-proof logs; zero-trust service communication) is covered by passkeys, device keys, hash-chained audit logs and mTLS in 02, 03 and 07.
