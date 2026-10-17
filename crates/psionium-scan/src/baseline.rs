//! The baseline file (`.psionium-scan.toml`): findings a team has accepted, each with a reason,
//! and paths the scan skips. With a baseline, `--fail-on` fails only on new findings.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::{Category, Finding};
use crate::report::Report;

const HEADER: &str = "\
# pSIONIUM Scan baseline.
#
# `psion scan` reads .psionium-scan.toml from the current folder (or the file given with
# --baseline). Findings listed under [[accepted]] are reported separately and never fail
# --fail-on; anything new still does. `ignore` lists paths to skip, as .gitignore patterns
# relative to each scanned folder, for example \"docs/\" or \"**/testdata/**\".
#
# Give every accepted finding a real reason. To refresh the list after fixing findings, run
# `psion scan --write-baseline .psionium-scan.toml`; the reasons already written are kept.

";

/// A baseline: accepted findings and paths to skip.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// Paths to skip, as `.gitignore`-style patterns relative to each scanned folder.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Findings that are known and accepted.
    #[serde(default)]
    pub accepted: Vec<Accepted>,
}

/// One accepted finding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    /// Where the finding was, for people reading the file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    /// The algorithm, for people reading the file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub algorithm: String,
    /// The rule, for people reading the file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule: String,
    /// The finding's fingerprint; this alone decides what is accepted.
    pub fingerprint: String,
    /// Why it is accepted.
    pub reason: String,
}

/// A finding that the baseline accepts, with the reason.
#[derive(Clone, Debug, Serialize)]
pub struct AcceptedFinding {
    /// The finding.
    #[serde(flatten)]
    pub finding: Finding,
    /// The reason given in the baseline.
    pub reason: String,
}

impl Baseline {
    /// Parses and checks a baseline file.
    pub fn parse(text: &str) -> Result<Baseline, String> {
        let baseline: Baseline = toml::from_str(text).map_err(|e| e.to_string())?;
        for (i, a) in baseline.accepted.iter().enumerate() {
            let n = i + 1;
            if a.fingerprint.len() != 32
                || !a
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(format!(
                    "accepted finding {n}: fingerprint must be 32 lowercase hex characters, as psion scan prints them"
                ));
            }
            if a.reason.trim().is_empty() {
                return Err(format!(
                    "accepted finding {n} ({}): give a reason",
                    a.fingerprint
                ));
            }
        }
        Ok(baseline)
    }

    /// The baseline as TOML, with a comment explaining the file.
    pub fn to_toml(&self) -> String {
        let body = toml::to_string_pretty(self).expect("baseline serializes");
        format!("{HEADER}{body}")
    }

    /// A baseline that accepts every finding in `report` except post-quantum ones. Reasons and
    /// ignore patterns from `previous` are kept; its entries that no longer match anything are
    /// dropped. New entries get `reason`.
    pub fn accepting(report: &Report, previous: Option<&Baseline>, reason: &str) -> Baseline {
        let reasons: HashMap<&str, &str> = previous
            .map(|b| {
                b.accepted
                    .iter()
                    .map(|a| (a.fingerprint.as_str(), a.reason.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        let mut seen = HashSet::new();
        let mut findings: Vec<&Finding> = report
            .findings
            .iter()
            .chain(report.accepted.iter().map(|a| &a.finding))
            .filter(|f| f.category != Category::QuantumSafe)
            .filter(|f| seen.insert(f.fingerprint.clone()))
            .collect();
        // File order, so the baseline diffs cleanly in version control.
        findings
            .sort_by(|a, b| (&a.location, a.line, &a.rule).cmp(&(&b.location, b.line, &b.rule)));
        let accepted = findings
            .into_iter()
            .map(|f| Accepted {
                location: match f.line {
                    Some(l) => format!("{}:{l}", f.location),
                    None => f.location.clone(),
                },
                algorithm: f.algorithm.clone(),
                rule: f.rule.clone(),
                fingerprint: f.fingerprint.clone(),
                reason: reasons
                    .get(f.fingerprint.as_str())
                    .map_or(reason, |r| r)
                    .to_string(),
            })
            .collect();
        Baseline {
            ignore: previous.map(|b| b.ignore.clone()).unwrap_or_default(),
            accepted,
        }
    }
}

impl Report {
    /// Moves the findings that `baseline` accepts from `findings` to `accepted`. Returns the
    /// baseline entries that matched nothing (fixed, or moved by an edit to the matched line).
    pub fn apply_baseline<'a>(&mut self, baseline: &'a Baseline) -> Vec<&'a Accepted> {
        let by_fingerprint: HashMap<&str, &Accepted> = baseline
            .accepted
            .iter()
            .map(|a| (a.fingerprint.as_str(), a))
            .collect();
        let mut used = HashSet::new();
        let mut kept = Vec::with_capacity(self.findings.len());
        for f in self.findings.drain(..) {
            match by_fingerprint.get(f.fingerprint.as_str()) {
                Some(a) => {
                    used.insert(a.fingerprint.as_str());
                    self.accepted.push(AcceptedFinding {
                        finding: f,
                        reason: a.reason.clone(),
                    });
                }
                None => kept.push(f),
            }
        }
        self.findings = kept;
        for a in &self.accepted {
            used.insert(a.finding.fingerprint.as_str());
        }
        baseline
            .accepted
            .iter()
            .filter(|a| !used.contains(a.fingerprint.as_str()))
            .collect()
    }
}
