//! The scan report and its renderings: text, Markdown, JSON and a CycloneDX 1.6 CBOM. HTML and
//! SARIF are in their own modules.

use std::collections::BTreeMap;
use std::fmt::Write;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Value, json};

use crate::baseline::AcceptedFinding;
use crate::material::certificate_finding;
use crate::model::{Category, Finding, Primitive, Source, TlsResult};
use crate::util::{disambiguate, fingerprint, rfc3339};

/// Everything a scan found.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// The scanner's version.
    pub tool_version: String,
    /// When the scan started, RFC 3339 UTC.
    pub started: String,
    /// Paths that were scanned.
    pub roots: Vec<String>,
    /// Files read.
    pub files_scanned: usize,
    /// Files skipped as too large or unreadable.
    pub files_skipped: usize,
    /// Findings in files and from TLS endpoints.
    pub findings: Vec<Finding>,
    /// TLS endpoint results.
    pub tls: Vec<TlsResult>,
    /// Findings a baseline accepts. They are left out of `findings`, the counts and
    /// `--fail-on`, but stay in the CBOM, which is an inventory.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<AcceptedFinding>,
}

impl Report {
    pub(crate) fn new(started_unix: i64) -> Self {
        Report {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            started: rfc3339(started_unix),
            roots: Vec::new(),
            files_scanned: 0,
            files_skipped: 0,
            findings: Vec::new(),
            tls: Vec::new(),
            accepted: Vec::new(),
        }
    }

    /// Adds a TLS result, with findings for its key exchange and certificate.
    pub fn add_tls(&mut self, result: TlsResult) {
        if result.reachable {
            let (category, algorithm, detail) = if result.post_quantum_key_exchange {
                (
                    Category::QuantumSafe,
                    "X25519MLKEM768 (hybrid)".to_string(),
                    "accepts post-quantum hybrid key exchange".to_string(),
                )
            } else {
                (
                    Category::QuantumVulnerable,
                    result.preferred_group.clone().unwrap_or_else(|| "classical key exchange".into()),
                    "no post-quantum key exchange: recorded traffic can be decrypted later by a quantum computer".to_string(),
                )
            };
            self.findings.push(Finding {
                category,
                fingerprint: fingerprint("tls-key-exchange", &result.target, &algorithm),
                algorithm,
                primitive: Primitive::KeyAgree,
                nist_quantum_level: if result.post_quantum_key_exchange {
                    Some(3)
                } else {
                    Some(0)
                },
                source: Source::Tls,
                location: result.target.clone(),
                line: None,
                detail,
                rule: "tls-key-exchange".into(),
                root: 0,
            });
            if let Some(cert) = &result.certificate {
                self.findings
                    .push(certificate_finding(&result.target, None, cert, Source::Tls));
            }
            disambiguate(&mut self.findings);
        }
        self.tls.push(result);
    }

    /// Findings, then accepted findings.
    pub(crate) fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .chain(self.accepted.iter().map(|a| &a.finding))
    }

    /// Number of findings in each category.
    pub fn counts(&self) -> BTreeMap<Category, usize> {
        let mut counts = BTreeMap::new();
        for f in &self.findings {
            *counts.entry(f.category).or_insert(0) += 1;
        }
        counts
    }

    /// Findings grouped by category, then algorithm, in report order.
    pub(crate) fn grouped(&self) -> BTreeMap<Category, BTreeMap<String, Vec<&Finding>>> {
        let mut groups: BTreeMap<Category, BTreeMap<String, Vec<&Finding>>> = BTreeMap::new();
        for f in &self.findings {
            groups
                .entry(f.category)
                .or_default()
                .entry(f.algorithm.clone())
                .or_default()
                .push(f);
        }
        groups
    }

    /// A plain-text summary for the terminal.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "pSIONIUM Scan {}: {} scanned in {}",
            self.tool_version,
            count(self.files_scanned, "file", "files"),
            self.roots.join(", ")
        );
        if self.files_skipped > 0 {
            let _ = writeln!(
                out,
                "({} skipped: too large or unreadable)",
                count(self.files_skipped, "file", "files")
            );
        }
        let counts = self.counts();
        let _ = writeln!(
            out,
            "\nSummary: {} quantum-vulnerable, {} weak, {} to review, {} already post-quantum",
            counts.get(&Category::QuantumVulnerable).unwrap_or(&0),
            counts.get(&Category::Weak).unwrap_or(&0),
            counts.get(&Category::Review).unwrap_or(&0),
            counts.get(&Category::QuantumSafe).unwrap_or(&0)
        );
        for (category, algorithms) in self.grouped() {
            let _ = writeln!(out, "\n{}\n  {}", category.title(), category.advice());
            for (algorithm, items) in algorithms {
                let noun = if items.len() == 1 {
                    "finding"
                } else {
                    "findings"
                };
                let _ = writeln!(out, "  {:<34} {:>5} {noun}", algorithm, items.len());
                for f in items.iter().take(3) {
                    let _ = writeln!(out, "      {}  {}", location(f), f.detail);
                }
                if items.len() > 3 {
                    let _ = writeln!(out, "      … and {} more", items.len() - 3);
                }
            }
        }
        if !self.accepted.is_empty() {
            let _ = writeln!(
                out,
                "\nAccepted in the baseline (not counted above): {}",
                count(self.accepted.len(), "finding", "findings")
            );
        }
        if !self.tls.is_empty() {
            let _ = writeln!(out, "\nTLS endpoints");
            for t in &self.tls {
                let _ = writeln!(out, "  {}", tls_line(t));
            }
        }
        if self.findings.is_empty() && self.tls.is_empty() && self.accepted.is_empty() {
            let _ = writeln!(out, "\nNo cryptography found.");
        }
        let _ = writeln!(
            out,
            "\nUse --format html, markdown, json, sarif or cbom for the full list."
        );
        out
    }

    /// A Markdown report.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let counts = self.counts();
        let _ = writeln!(out, "# Quantum readiness report\n");
        let _ = writeln!(
            out,
            "Scanned {} in `{}` on {} with pSIONIUM Scan {}.\n",
            count(self.files_scanned, "file", "files"),
            self.roots.join("`, `"),
            self.started,
            self.tool_version
        );
        let _ = writeln!(out, "| Category | Findings | What to do |\n|---|---:|---|");
        for category in [
            Category::QuantumVulnerable,
            Category::Weak,
            Category::Review,
            Category::QuantumSafe,
        ] {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                category.title(),
                counts.get(&category).unwrap_or(&0),
                category.advice()
            );
        }
        for (category, algorithms) in self.grouped() {
            let _ = writeln!(out, "\n## {}\n", category.title());
            for (algorithm, items) in algorithms {
                let _ = writeln!(out, "### {} ({})\n", md(&algorithm), items.len());
                let _ = writeln!(out, "| Location | Detail |\n|---|---|");
                for f in items {
                    let _ = writeln!(out, "| `{}` | {} |", location(f), md(&f.detail));
                }
                out.push('\n');
            }
        }
        if !self.accepted.is_empty() {
            let _ = writeln!(
                out,
                "## Accepted in the baseline ({})\n\nNot counted above.\n",
                self.accepted.len()
            );
            let _ = writeln!(out, "| Location | Algorithm | Reason |\n|---|---|---|");
            for a in &self.accepted {
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {} |",
                    location(&a.finding),
                    md(&a.finding.algorithm),
                    md(&a.reason)
                );
            }
            out.push('\n');
        }
        if !self.tls.is_empty() {
            let _ = writeln!(out, "## TLS endpoints\n");
            for t in &self.tls {
                let _ = writeln!(out, "- {}", md(&tls_line(t)));
            }
        }
        out
    }

    /// The report as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }

    /// A CycloneDX 1.6 cryptography bill of materials (CBOM, ECMA-424).
    pub fn to_cbom(&self) -> String {
        let mut components: Vec<Value> = Vec::new();
        let mut algorithms: BTreeMap<(String, &'static str), Vec<&Finding>> = BTreeMap::new();
        for f in self
            .all_findings()
            .filter(|f| !matches!(f.source, Source::Certificate) && f.rule != "certificate")
        {
            algorithms
                .entry((f.algorithm.clone(), f.primitive.cyclonedx()))
                .or_default()
                .push(f);
        }
        for ((name, primitive), items) in &algorithms {
            let mut props = json!({ "primitive": primitive });
            if let Some(level) = items.iter().find_map(|f| f.nist_quantum_level) {
                props["nistQuantumSecurityLevel"] = json!(level);
            }
            let occurrences: Vec<Value> = items
                .iter()
                .map(|f| {
                    let mut o = json!({ "location": f.location });
                    if let Some(line) = f.line {
                        o["line"] = json!(line);
                    }
                    o["additionalContext"] = json!(f.detail);
                    o
                })
                .collect();
            components.push(json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto/algorithm/{}", slug(name)),
                "name": name,
                "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": props },
                "evidence": { "occurrences": occurrences },
                "properties": [{ "name": "psionium:category", "value": category_value(items[0].category) }],
            }));
        }
        let mut certs = 0;
        for t in &self.tls {
            if let Some(c) = &t.certificate {
                certs += 1;
                components.push(cert_component(certs, &t.target, c));
            }
            if t.reachable {
                components.push(json!({
                    "type": "cryptographic-asset",
                    "bom-ref": format!("crypto/protocol/tls/{}", slug(&t.target)),
                    "name": format!("TLS at {}", t.target),
                    "cryptoProperties": {
                        "assetType": "protocol",
                        "protocolProperties": {
                            "type": "tls",
                            "version": t.version.clone().unwrap_or_default().replace("TLS ", ""),
                            "cipherSuites": [{ "name": t.cipher_suite.clone().unwrap_or_default() }]
                        }
                    },
                    "properties": [
                        { "name": "psionium:postQuantumKeyExchange", "value": t.post_quantum_key_exchange.to_string() },
                        { "name": "psionium:preferredGroup", "value": t.preferred_group.clone().unwrap_or_default() }
                    ],
                }));
            }
        }
        for f in self
            .all_findings()
            .filter(|f| f.rule == "certificate" && f.source == Source::Certificate)
        {
            certs += 1;
            components.push(json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto/certificate/{certs}"),
                "name": format!("Certificate in {}", f.location),
                "cryptoProperties": { "assetType": "certificate" },
                "evidence": { "occurrences": [{ "location": f.location, "additionalContext": f.detail }] },
                "properties": [{ "name": "psionium:category", "value": category_value(f.category) }],
            }));
        }
        let bom = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": format!("urn:uuid:{}", uuid_v4()),
            "version": 1,
            "metadata": {
                "timestamp": self.started,
                "tools": { "components": [{ "type": "application", "name": "pSIONIUM Scan", "version": self.tool_version }] },
                "properties": [{ "name": "psionium:roots", "value": self.roots.join(", ") }],
            },
            "components": components,
        });
        serde_json::to_string_pretty(&bom).expect("cbom serializes")
    }
}

fn cert_component(n: usize, target: &str, c: &crate::model::CertificateInfo) -> Value {
    json!({
        "type": "cryptographic-asset",
        "bom-ref": format!("crypto/certificate/{n}"),
        "name": format!("Certificate for {target}"),
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": c.subject,
                "issuerName": c.issuer,
                "notValidBefore": format!("{}T00:00:00Z", c.not_before),
                "notValidAfter": format!("{}T00:00:00Z", c.not_after),
                "certificateFormat": "X.509"
            }
        },
        "properties": [
            { "name": "psionium:keyAlgorithm", "value": c.key_algorithm },
            { "name": "psionium:signatureAlgorithm", "value": c.signature_algorithm },
            { "name": "psionium:quantumSafe", "value": c.quantum_safe.to_string() }
        ],
    })
}

pub(crate) fn category_value(c: Category) -> &'static str {
    match c {
        Category::QuantumVulnerable => "quantum-vulnerable",
        Category::Weak => "weak",
        Category::Review => "review",
        Category::QuantumSafe => "quantum-safe",
    }
}

/// `n` with the singular or plural noun.
pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub(crate) fn location(f: &Finding) -> String {
    match f.line {
        Some(l) => format!("{}:{l}", f.location),
        None => f.location.clone(),
    }
}

pub(crate) fn tls_line(t: &TlsResult) -> String {
    if !t.reachable {
        return format!(
            "{}: could not check ({})",
            t.target,
            t.error.as_deref().unwrap_or("unknown error")
        );
    }
    let pq = if t.post_quantum_key_exchange {
        "post-quantum key exchange: yes"
    } else {
        "post-quantum key exchange: NO"
    };
    let mut s = format!(
        "{}: {pq}; {} {} via {}",
        t.target,
        t.version.as_deref().unwrap_or("?"),
        t.cipher_suite.as_deref().unwrap_or("?"),
        t.preferred_group.as_deref().unwrap_or("?")
    );
    if let Some(c) = &t.certificate {
        let bits = c.key_bits.map(|b| format!("-{b}")).unwrap_or_default();
        let _ = write!(
            s,
            "; certificate {}{} until {}",
            c.key_algorithm, bits, c.not_after
        );
    }
    match t.trusted {
        Some(true) => s.push_str(", trusted"),
        Some(false) => s.push_str(", NOT trusted by public roots"),
        None => {}
    }
    s
}

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn slug(s: &str) -> String {
    let raw: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    raw.split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    let _ = SystemRandom::new().fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
