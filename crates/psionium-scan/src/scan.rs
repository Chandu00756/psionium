//! Walks files and applies the code, dependency and key-material rules.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use regex::Regex;

use crate::material;
use crate::model::{Finding, Source};
use crate::rules::{CODE_RULES, DEPENDENCY_RULES, is_code_file, is_lock_file};
use crate::util::fingerprint;

/// Options for [`crate::scan_paths`].
#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Also scan vendored and installed dependencies (`node_modules`, `vendor`, virtualenvs).
    pub include_dependencies: bool,
    /// Skip files larger than this many bytes.
    pub max_file_size: u64,
    /// Include the matching part of each line of code in findings. When false, code findings
    /// name the rule instead, so reports never contain source code.
    pub excerpts: bool,
    /// Paths to skip, as `.gitignore`-style patterns relative to each scanned folder (for
    /// example `docs/`, `**/testdata/**` or `*.pem`).
    pub ignore: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            include_dependencies: false,
            max_file_size: 4 * 1024 * 1024,
            excerpts: true,
            ignore: Vec::new(),
        }
    }
}

/// The baseline file's name; the scanner never reports on it.
pub const BASELINE_FILE: &str = ".psionium-scan.toml";

/// Builds the matcher for [`ScanOptions::ignore`] under one scanned path.
pub(crate) fn ignore_matcher(root: &Path, patterns: &[String]) -> Result<Gitignore, String> {
    let base = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    let mut builder = GitignoreBuilder::new(base);
    for pattern in patterns {
        builder
            .add_line(None, pattern)
            .map_err(|e| format!("ignore pattern \"{pattern}\": {e}"))?;
    }
    builder.build().map_err(|e| format!("ignore patterns: {e}"))
}

/// Counts of what the walk saw.
#[derive(Default)]
pub(crate) struct WalkStats {
    pub scanned: usize,
    pub skipped: usize,
}

const ALWAYS_SKIP: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".next",
    ".nuxt",
    ".gradle",
    ".terraform",
    "coverage",
];
const DEPENDENCY_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    ".venv",
    "venv",
    "site-packages",
    ".tox",
    "bower_components",
    "Pods",
];

pub(crate) fn walk(
    root: &Path,
    options: &ScanOptions,
    ignored: Gitignore,
    findings: &mut Vec<Finding>,
    stats: &mut WalkStats,
) {
    let include_deps = options.include_dependencies;
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false)
        .filter_entry(move |e| {
            let name = e.file_name().to_string_lossy();
            let is_dir = e.file_type().is_some_and(|t| t.is_dir());
            if e.depth() > 0 && ignored.matched(e.path(), is_dir).is_ignore() {
                return false;
            }
            !(is_dir
                && (ALWAYS_SKIP.contains(&name.as_ref())
                    || (!include_deps && DEPENDENCY_DIRS.contains(&name.as_ref()))))
        })
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if entry.file_name() == BASELINE_FILE {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if size > options.max_file_size {
            stats.skipped += 1;
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            stats.skipped += 1;
            continue;
        };
        stats.scanned += 1;
        let display = display_path(root, path);
        scan_file(&display, path, &bytes, options.excerpts, findings);
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    let rel = if root.is_file() {
        path
    } else {
        path.strip_prefix(root).unwrap_or(path)
    };
    let s = rel.to_string_lossy().replace('\\', "/");
    if s.is_empty() {
        path.to_string_lossy().into_owned()
    } else {
        s
    }
}

pub(crate) fn scan_file(
    display: &str,
    path: &Path,
    bytes: &[u8],
    excerpts: bool,
    findings: &mut Vec<Finding>,
) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let binary = bytes.iter().take(8192).any(|b| *b == 0);
    if binary {
        // DER-encoded certificates are binary.
        let lower = name.to_ascii_lowercase();
        if (lower.ends_with(".der") || lower.ends_with(".cer") || lower.ends_with(".crt"))
            && let Ok((_, cert)) = x509_parser::parse_x509_certificate(bytes)
        {
            let info = material::describe_certificate(&cert);
            findings.push(material::certificate_finding(
                display,
                None,
                &info,
                Source::Certificate,
            ));
        }
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    material::scan_text(display, &text, findings);
    dependencies(display, &name, &text, findings);
    if is_code_file(&name) && !is_lock_file(&name) {
        code(display, &text, excerpts, findings);
    }
}

fn code(display: &str, text: &str, excerpts: bool, findings: &mut Vec<Finding>) {
    for (i, line) in text.lines().enumerate() {
        if line.len() > 4000 {
            continue; // minified or generated
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for rule in CODE_RULES.iter() {
            let Some(m) = rule.pattern.find(line) else {
                continue;
            };
            if rule.unless.as_ref().is_some_and(|u| u.is_match(line))
                || !seen.insert(rule.algorithm)
            {
                continue;
            }
            findings.push(Finding {
                category: rule.category,
                algorithm: rule.algorithm.to_string(),
                primitive: rule.primitive,
                nist_quantum_level: rule.nist_level,
                source: Source::Code,
                location: display.to_string(),
                line: Some(i + 1),
                detail: if excerpts {
                    excerpt(line, m.start(), m.end())
                } else {
                    format!("matches the {} rule (excerpt hidden)", rule.id)
                },
                rule: rule.id.to_string(),
                fingerprint: fingerprint(rule.id, display, line),
                root: 0,
            });
        }
    }
}

/// The match with a little context, trimmed, at most about 120 characters.
fn excerpt(line: &str, start: usize, end: usize) -> String {
    let from = floor_char(line, start.saturating_sub(40));
    let to = ceil_char(line, (end + 40).min(line.len()));
    let mut s = line[from..to].trim().to_string();
    if from > 0 {
        s.insert(0, '…');
    }
    if to < line.len() {
        s.push('…');
    }
    s
}

fn floor_char(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

enum Manifest {
    PackageJson,
    Requirements,
    Pyproject,
    GoMod,
    CargoToml,
    Maven,
    Gradle,
}

fn manifest_kind(name: &str) -> Option<Manifest> {
    Some(match name {
        "package.json" => Manifest::PackageJson,
        "pyproject.toml" | "Pipfile" | "setup.cfg" => Manifest::Pyproject,
        "go.mod" => Manifest::GoMod,
        "Cargo.toml" => Manifest::CargoToml,
        "pom.xml" => Manifest::Maven,
        "build.gradle" | "build.gradle.kts" => Manifest::Gradle,
        n if n.starts_with("requirements") && n.ends_with(".txt") => Manifest::Requirements,
        _ => return None,
    })
}

static REQUIREMENT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([A-Za-z0-9_.\-]+)").expect("regex"));

fn dependencies(display: &str, name: &str, text: &str, findings: &mut Vec<Finding>) {
    let Some(kind) = manifest_kind(name) else {
        return;
    };
    let mut found: Vec<(String, usize)> = Vec::new();
    match kind {
        Manifest::PackageJson => {
            let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
                return;
            };
            for section in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ] {
                if let Some(map) = json.get(section).and_then(|v| v.as_object()) {
                    for key in map.keys() {
                        let line = text
                            .lines()
                            .position(|l| l.contains(&format!("\"{key}\"")))
                            .map_or(0, |p| p + 1);
                        found.push((key.clone(), line));
                    }
                }
            }
        }
        Manifest::Requirements => {
            for (i, l) in text.lines().enumerate() {
                let l = l.split('#').next().unwrap_or("");
                if let Some(c) = REQUIREMENT_NAME.captures(l) {
                    found.push((c[1].to_ascii_lowercase(), i + 1));
                }
            }
        }
        _ => {
            for rule in DEPENDENCY_RULES {
                let n = regex::escape(rule.name);
                let pattern = match kind {
                    Manifest::GoMod => format!(r"^\s*(?:require\s+)?{n}\s+v"),
                    Manifest::CargoToml => format!(r#"^\s*"?{n}"?\s*="#),
                    Manifest::Maven => format!(r"<artifactId>\s*{n}\s*</artifactId>"),
                    Manifest::Gradle => format!(r#"[:'"]{n}[:'"]"#),
                    _ => format!(r#"(?i)(?:^|["'\s])"?{n}"?\s*(?:[<>=!~\[;,'"]|$)"#),
                };
                let re = Regex::new(&pattern).expect("dependency pattern");
                if let Some(i) = text.lines().position(|l| re.is_match(l)) {
                    found.push((rule.name.to_string(), i + 1));
                }
            }
        }
    }
    let mut seen = HashSet::new();
    for (dep, line) in found {
        let Some(rule) = DEPENDENCY_RULES
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case(&dep))
        else {
            continue;
        };
        if !seen.insert(rule.name) {
            continue;
        }
        findings.push(Finding {
            category: rule.category,
            algorithm: rule.algorithm.to_string(),
            primitive: rule.primitive,
            nist_quantum_level: None,
            source: Source::Dependency,
            location: display.to_string(),
            line: (line > 0).then_some(line),
            detail: format!("depends on {}", rule.name),
            rule: format!("dependency:{}", rule.name),
            fingerprint: fingerprint(&format!("dependency:{}", rule.name), display, ""),
            root: 0,
        });
    }
}
