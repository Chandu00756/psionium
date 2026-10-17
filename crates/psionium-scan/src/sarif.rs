//! SARIF 2.1.0 output, for GitHub code scanning and other static-analysis dashboards.
//!
//! Only findings in files are included: code scanning needs a file location, so TLS endpoint
//! results stay in the other formats. Post-quantum findings are inventory, not problems, and are
//! left out too. Findings a baseline accepts are included with an external suppression.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::guidance::guidance;
use crate::model::{Category, Finding, Source};
use crate::report::{Report, category_value};

const FINGERPRINT_KEY: &str = "psioniumFingerprint/v1";

impl Report {
    /// The report as a SARIF 2.1.0 log.
    pub fn to_sarif(&self) -> String {
        let included =
            |f: &&Finding| f.source != Source::Tls && f.category != Category::QuantumSafe;
        let mut rules: BTreeMap<&str, &Finding> = BTreeMap::new();
        for f in self.all_findings().filter(included) {
            rules.entry(f.rule.as_str()).or_insert(f);
        }
        let index: BTreeMap<&str, usize> = rules.keys().enumerate().map(|(i, r)| (*r, i)).collect();
        let rule_objects: Vec<Value> = rules.values().map(|f| rule(f)).collect();

        let mut base_ids = serde_json::Map::new();
        let mut results = Vec::new();
        let accepted = self
            .accepted
            .iter()
            .map(|a| (&a.finding, Some(a.reason.as_str())));
        for (f, reason) in self.findings.iter().map(|f| (f, None)).chain(accepted) {
            if !included(&f) {
                continue;
            }
            let (uri, base) = self.uri(f);
            let mut artifact = json!({ "uri": uri });
            if let Some((id, root_uri)) = base {
                artifact["uriBaseId"] = json!(id);
                base_ids.insert(id, json!({ "uri": root_uri }));
            }
            let mut physical = json!({ "artifactLocation": artifact });
            if let Some(line) = f.line {
                physical["region"] = json!({ "startLine": line });
            }
            let mut result = json!({
                "ruleId": f.rule,
                "ruleIndex": index[f.rule.as_str()],
                "level": level(f.category),
                "message": { "text": format!("{}: {}", f.algorithm, f.detail) },
                "locations": [{ "physicalLocation": physical }],
                "partialFingerprints": { FINGERPRINT_KEY: f.fingerprint },
                "properties": {
                    "category": category_value(f.category),
                    "algorithm": f.algorithm,
                    "primitive": f.primitive.cyclonedx(),
                },
            });
            if let Some(reason) = reason {
                result["suppressions"] = json!([{
                    "kind": "external",
                    "status": "accepted",
                    "justification": reason,
                }]);
            }
            results.push(result);
        }

        let mut run = json!({
            "tool": { "driver": {
                "name": "pSIONIUM Scan",
                "version": self.tool_version,
                "semanticVersion": self.tool_version,
                "informationUri": "https://github.com/Chandu00756/psionium/blob/main/docs/scan.md",
                "rules": rule_objects,
            }},
            "invocations": [{ "executionSuccessful": true, "startTimeUtc": self.started }],
            "results": results,
        });
        if !base_ids.is_empty() {
            run["originalUriBaseIds"] = Value::Object(base_ids);
        }
        let log = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [run],
        });
        serde_json::to_string_pretty(&log).expect("sarif serializes")
    }

    /// The finding's artifact URI, relative to the repository when the scanned path was
    /// relative, and the base id and URI to resolve it against when the path was absolute.
    fn uri(&self, f: &Finding) -> (String, Option<(String, String)>) {
        let root = self
            .roots
            .get(f.root)
            .map(|r| r.replace('\\', "/"))
            .unwrap_or_default();
        let root_is_file = f.location.replace('\\', "/") == root;
        if Path::new(&root).is_absolute() {
            if root_is_file {
                return (file_uri(&root), None);
            }
            let id = format!("SCANROOT{}", f.root);
            return (
                encode(&f.location),
                Some((id, format!("{}/", file_uri(root.trim_end_matches('/'))))),
            );
        }
        if root_is_file {
            return (encode(clean(&root)), None);
        }
        let prefix = clean(root.trim_end_matches('/'));
        let path = if prefix.is_empty() || prefix == "." {
            f.location.clone()
        } else {
            format!("{prefix}/{}", f.location)
        };
        (encode(&path), None)
    }
}

fn rule(f: &Finding) -> Value {
    let short = match f.rule.as_str() {
        "certificate" => "Certificate with a quantum-vulnerable key".to_string(),
        "private-key" => "Private key stored in the scanned files".to_string(),
        "public-key" => "Quantum-vulnerable public key".to_string(),
        _ => format!("{} ({})", f.algorithm, f.category.title().to_lowercase()),
    };
    let help = guidance(f);
    json!({
        "id": f.rule,
        "shortDescription": { "text": short },
        "fullDescription": { "text": f.category.advice() },
        "help": { "text": help, "markdown": help },
        "helpUri": "https://github.com/Chandu00756/psionium/blob/main/docs/scan.md",
        "defaultConfiguration": { "level": level(f.category) },
        "properties": {
            "tags": ["security", "cryptography", "post-quantum"],
            "precision": if f.rule.starts_with("dependency:") || f.source == Source::Code { "medium" } else { "high" },
            "security-severity": severity(f.category),
        },
    })
}

fn level(c: Category) -> &'static str {
    match c {
        Category::Weak => "error",
        Category::QuantumVulnerable => "warning",
        Category::Review | Category::QuantumSafe => "note",
    }
}

/// GitHub's severity scale: 7.0+ high, 4.0+ medium, 0.1+ low.
fn severity(c: Category) -> &'static str {
    match c {
        Category::Weak => "7.5",
        Category::QuantumVulnerable => "5.5",
        Category::Review | Category::QuantumSafe => "2.0",
    }
}

fn clean(path: &str) -> &str {
    let mut p = path;
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    p
}

fn file_uri(absolute: &str) -> String {
    if absolute.starts_with('/') {
        format!("file://{}", encode(absolute))
    } else {
        // A Windows path such as C:/work/app.
        format!("file:///{}", encode(absolute))
    }
}

/// Percent-encodes a path for a URI, keeping `/` and unreserved characters (and `:` for
/// Windows drive letters).
fn encode(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn encodes_paths() {
        assert_eq!(super::encode("src/my file.rs"), "src/my%20file.rs");
        assert_eq!(super::encode("a/é"), "a/%C3%A9");
        assert_eq!(super::file_uri("/srv/app"), "file:///srv/app");
        assert_eq!(super::file_uri("C:/work/app"), "file:///C:/work/app");
        assert_eq!(super::clean("././x"), "x");
    }
}
