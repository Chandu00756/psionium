//! # psionium-scan
//!
//! Finds where software still depends on cryptography that quantum computers break (RSA,
//! elliptic curves, Diffie-Hellman, DSA), flags classically weak algorithms, and recognizes
//! post-quantum cryptography that is already in place. It reads source code, configuration,
//! dependency manifests, certificates and keys, and probes TLS endpoints for post-quantum key
//! exchange. Reports come as text, Markdown, JSON or a CycloneDX 1.6 CBOM.
//!
//! Private key material is reported by type and location only; it is never copied into a report.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod material;
mod model;
mod report;
mod rules;
mod scan;
mod tls;
mod util;

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use model::{Category, CertificateInfo, Finding, Primitive, Source, TlsResult};
pub use report::Report;
pub use rules::rule_count;
pub use scan::ScanOptions;
pub use tls::probe as probe_tls;

/// Scans files and folders. Missing paths are reported as errors.
pub fn scan_paths<P: AsRef<Path>>(paths: &[P], options: &ScanOptions) -> Result<Report, String> {
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut report = Report::new(started);
    let mut stats = scan::WalkStats::default();
    for path in paths {
        let path = path.as_ref();
        if !path.exists() {
            return Err(format!("{} does not exist", path.display()));
        }
        report.roots.push(path.display().to_string());
        scan::walk(path, options, &mut report.findings, &mut stats);
    }
    report.files_scanned = stats.scanned;
    report.files_skipped = stats.skipped;
    Ok(report)
}

/// Probes TLS endpoints and adds the results to a report.
pub fn scan_tls(report: &mut Report, targets: &[String], timeout: Duration) {
    for target in targets {
        report.add_tls(probe_tls(target, timeout, &[]));
    }
}

/// An empty report, for TLS-only scans.
pub fn empty_report() -> Report {
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Report::new(started)
}
