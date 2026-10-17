//! A self-contained HTML report: one file, no scripts, no network requests, readable by
//! managers and auditors, in light and dark themes.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::guidance::guidance;
use crate::model::{Category, Finding};
use crate::report::{Report, category_value, count, location, tls_line};

const CATEGORIES: [Category; 4] = [
    Category::QuantumVulnerable,
    Category::Weak,
    Category::Review,
    Category::QuantumSafe,
];

const STYLE: &str = r#"
:root{color-scheme:light dark;--bg:#fbfaf8;--panel:#fff;--text:#1d1b22;--muted:#5d5866;--line:#e4e0e8;
--qv:#b42318;--qv-bg:#fdecea;--weak:#a14a00;--weak-bg:#fdf0e1;--review:#3b5bab;--review-bg:#e9eefb;
--safe:#1f7a3a;--safe-bg:#e5f5ea;--accent:#6b3fd4}
@media (prefers-color-scheme:dark){:root{--bg:#121016;--panel:#1b1820;--text:#ece9f1;--muted:#a8a1b3;--line:#2e2a35;
--qv:#ff8a80;--qv-bg:#3a1714;--weak:#ffb870;--weak-bg:#38250f;--review:#9db4ff;--review-bg:#1b2440;
--safe:#7ddc98;--safe-bg:#12301c;--accent:#b79cff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
header .eyebrow{margin:0;color:var(--accent);font-weight:600;letter-spacing:.04em;text-transform:uppercase;font-size:12px}
h1{margin:4px 0 6px;font-size:30px;line-height:1.2}
h2{margin:40px 0 12px;font-size:21px}
h3{margin:0;font-size:16px}
.meta,.muted{color:var(--muted)}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;list-style:none;padding:0;margin:0}
.card{background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:10px;padding:14px 16px}
.card .num{display:block;font-size:32px;font-weight:700;color:var(--c);line-height:1.1}
.card .label{font-weight:600}
.card p{margin:6px 0 0;color:var(--muted);font-size:13px}
.qv{--c:var(--qv);--cbg:var(--qv-bg)}.weak{--c:var(--weak);--cbg:var(--weak-bg)}
.review{--c:var(--review);--cbg:var(--review-bg)}.safe{--c:var(--safe);--cbg:var(--safe-bg)}
.tag{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;color:var(--c);background:var(--cbg);white-space:nowrap}
.timeline{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;list-style:none;padding:0;margin:0}
.timeline li{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.timeline strong{display:block;font-size:20px}
.bars{list-style:none;padding:0;margin:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.bars li{display:grid;grid-template-columns:minmax(120px,240px) 1fr auto;gap:12px;align-items:center;padding:5px 0}
.bars .name{overflow-wrap:anywhere}
.bars .track{background:var(--line);border-radius:4px;height:12px}
.bars .bar{background:var(--c);border-radius:4px;height:12px;width:var(--w);min-width:3px}
.bars .n{font-variant-numeric:tabular-nums;min-width:3ch;text-align:right}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:10px 0}
summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
summary h3{display:inline}
.body{padding:0 16px 14px}
.fix{margin:0 0 10px;padding:10px 12px;border-radius:8px;background:var(--cbg)}
.table{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:7px 8px;border-top:1px solid var(--line)}
th{font-weight:600;color:var(--muted);border-top:0}
footer{margin-top:48px;color:var(--muted);font-size:13px}
a{color:var(--accent)}
@media (max-width:560px){.bars li{grid-template-columns:1fr auto}.bars .track{grid-column:1/-1;order:3}
.stack thead{position:absolute;left:-9999px}.stack tr{display:block;border-top:1px solid var(--line);padding:6px 0}
.stack td{display:block;border:0;padding:2px 0}}
@media print{details{break-inside:avoid}details:not([open]) .body{display:block}}
"#;

impl Report {
    /// A self-contained HTML report.
    pub fn to_html(&self) -> String {
        let mut out = String::with_capacity(16 * 1024 + self.findings.len() * 200);
        let counts = self.counts();
        let n = |c: Category| *counts.get(&c).unwrap_or(&0);
        let title = "Quantum readiness report";
        let _ = write!(
            out,
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <meta name=\"generator\" content=\"pSIONIUM Scan {v}\">\n\
             <title>{title}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<div class=\"wrap\">\n",
            v = esc(&self.tool_version)
        );

        // Header.
        let roots = self
            .roots
            .iter()
            .map(|r| format!("<code>{}</code>", esc(r)))
            .collect::<Vec<_>>()
            .join(", ");
        let scanned = if self.roots.is_empty() {
            "TLS endpoints only".to_string()
        } else {
            format!(
                "{} scanned in {roots}",
                count(self.files_scanned, "file", "files")
            )
        };
        let _ = write!(
            out,
            "<header>\n<p class=\"eyebrow\">pSIONIUM Scan {v}</p>\n<h1>{title}</h1>\n\
             <p class=\"meta\">{scanned} · {started}</p>\n</header>\n<main>\n",
            v = esc(&self.tool_version),
            started = esc(&self.started),
        );

        // Summary.
        let _ = write!(
            out,
            "<section aria-labelledby=\"summary\">\n<h2 id=\"summary\">Summary</h2>\n<ul class=\"cards\">\n"
        );
        for c in CATEGORIES {
            let _ = writeln!(
                out,
                "<li class=\"card {cls}\"><span class=\"num\">{num}</span>\
                 <span class=\"label\">{label}</span><p>{advice}</p></li>",
                cls = class(c),
                num = n(c),
                label = c.title(),
                advice = esc(c.advice()),
            );
        }
        out.push_str("</ul>\n");
        if !self.accepted.is_empty() {
            let _ = writeln!(
                out,
                "<p class=\"muted\">{} accepted in the baseline are not counted above; they are listed at the end.</p>",
                count(self.accepted.len(), "finding", "findings")
            );
        }
        if self.files_skipped > 0 {
            let _ = writeln!(
                out,
                "<p class=\"muted\">{} skipped: too large or unreadable.</p>",
                count(self.files_skipped, "file", "files")
            );
        }
        out.push_str("</section>\n");

        // Timeline.
        let year: i64 = self
            .started
            .get(..4)
            .and_then(|y| y.parse().ok())
            .unwrap_or(2026);
        let _ = write!(
            out,
            "<section aria-labelledby=\"timeline\">\n<h2 id=\"timeline\">Deadlines</h2>\n<ul class=\"timeline\">\n\
             <li><strong>After 2030</strong>NIST proposes to deprecate RSA, elliptic-curve, Diffie-Hellman and DSA keys at today's common sizes (NIST IR 8547, draft).{left30}</li>\n\
             <li><strong>After 2035</strong>NIST proposes to disallow them entirely (NIST IR 8547, draft).{left35}</li>\n\
             <li><strong>Now</strong>Data encrypted with them today can be recorded and decrypted later by a quantum computer. Protect long-lived secrets first.</li>\n\
             </ul>\n</section>\n",
            left30 = years_left(year, 2030),
            left35 = years_left(year, 2035),
        );

        // Chart of algorithms.
        let mut by_algorithm: BTreeMap<(Category, &str), usize> = BTreeMap::new();
        for f in &self.findings {
            *by_algorithm
                .entry((f.category, f.algorithm.as_str()))
                .or_insert(0) += 1;
        }
        let mut ranked: Vec<_> = by_algorithm.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        if let Some(max) = ranked.first().map(|r| r.1) {
            let shown = ranked.len().min(15);
            let _ = write!(
                out,
                "<section aria-labelledby=\"algorithms\">\n<h2 id=\"algorithms\">Algorithms found</h2>\n\
                 <p class=\"muted\">The {} most frequent, by number of findings.</p>\n<ol class=\"bars\">\n",
                count(shown, "algorithm", "algorithms")
            );
            for ((c, name), k) in ranked.iter().take(shown) {
                let pct = (*k as f64 / max as f64 * 100.0).max(1.0);
                let _ = writeln!(
                    out,
                    "<li class=\"{cls}\"><span class=\"name\">{name} <span class=\"tag\">{label}</span></span>\
                     <span class=\"track\" aria-hidden=\"true\"><span class=\"bar\" style=\"--w:{pct:.1}%;display:block\"></span></span>\
                     <span class=\"n\">{k}</span></li>",
                    cls = class(*c),
                    name = esc(name),
                    label = c.title(),
                );
            }
            out.push_str("</ol>\n</section>\n");
        }

        // Findings by category, then algorithm.
        for (c, algorithms) in self.grouped() {
            let total: usize = algorithms.values().map(Vec::len).sum();
            let id = category_value(c);
            let _ = write!(
                out,
                "<section aria-labelledby=\"{id}\" class=\"{cls}\">\n<h2 id=\"{id}\">{title} ({total})</h2>\n\
                 <p class=\"muted\">{advice}</p>\n",
                cls = class(c),
                title = c.title(),
                advice = esc(c.advice()),
            );
            let open = matches!(c, Category::QuantumVulnerable | Category::Weak);
            for (algorithm, items) in algorithms {
                findings_block(&mut out, &algorithm, &items, open);
            }
            out.push_str("</section>\n");
        }

        // TLS endpoints.
        if !self.tls.is_empty() {
            out.push_str(
                "<section aria-labelledby=\"tls\">\n<h2 id=\"tls\">TLS endpoints</h2>\n<div class=\"table\"><table>\n\
                 <thead><tr><th scope=\"col\">Endpoint</th><th scope=\"col\">Post-quantum key exchange</th><th scope=\"col\">Details</th></tr></thead>\n<tbody>\n",
            );
            for t in &self.tls {
                let pq = if !t.reachable {
                    "<span class=\"tag review\">Not checked</span>"
                } else if t.post_quantum_key_exchange {
                    "<span class=\"tag safe\">Yes</span>"
                } else {
                    "<span class=\"tag qv\">No</span>"
                };
                let _ = writeln!(
                    out,
                    "<tr><td><code>{}</code></td><td>{pq}</td><td>{}</td></tr>",
                    esc(&t.target),
                    esc(&tls_line(t)),
                );
            }
            out.push_str("</tbody></table></div>\n</section>\n");
        }

        // Accepted findings.
        if !self.accepted.is_empty() {
            let _ = write!(
                out,
                "<section aria-labelledby=\"accepted\">\n<h2 id=\"accepted\">Accepted in the baseline ({})</h2>\n\
                 <details><summary><h3>Show accepted findings</h3></summary><div class=\"body table\"><table>\n\
                 <thead><tr><th scope=\"col\">Location</th><th scope=\"col\">Algorithm</th><th scope=\"col\">Category</th><th scope=\"col\">Reason</th></tr></thead>\n<tbody>\n",
                self.accepted.len()
            );
            for a in &self.accepted {
                let f = &a.finding;
                let _ = writeln!(
                    out,
                    "<tr><td><code>{}</code></td><td>{}</td><td><span class=\"tag {}\">{}</span></td><td>{}</td></tr>",
                    esc(&location(f)),
                    esc(&f.algorithm),
                    class(f.category),
                    f.category.title(),
                    esc(&a.reason),
                );
            }
            out.push_str("</tbody></table></div></details>\n</section>\n");
        }

        if self.findings.is_empty() && self.tls.is_empty() && self.accepted.is_empty() {
            out.push_str("<p>No cryptography found.</p>\n");
        }

        out.push_str(
            "</main>\n<footer>\n<p>Generated by pSIONIUM Scan. Code findings come from patterns, so a mention in a comment \
             or string counts too; each finding shows its file and line so you can judge it. Private key contents are \
             never included in a report.</p>\n</footer>\n</div>\n</body>\n</html>\n",
        );
        out
    }
}

fn findings_block(out: &mut String, algorithm: &str, items: &[&Finding], open: bool) {
    let _ = write!(
        out,
        "<details{open}><summary><h3>{name}</h3><span class=\"muted\">{n}</span></summary>\n<div class=\"body\">\n\
         <p class=\"fix\"><strong>What to do:</strong> {fix}</p>\n<div class=\"table\"><table class=\"stack\">\n\
         <thead><tr><th scope=\"col\">Location</th><th scope=\"col\">Detail</th></tr></thead>\n<tbody>\n",
        open = if open { " open" } else { "" },
        name = esc(algorithm),
        n = count(items.len(), "finding", "findings"),
        fix = esc(guidance(items[0])),
    );
    for f in items {
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td>{}</td></tr>",
            esc(&location(f)),
            esc(&f.detail)
        );
    }
    out.push_str("</tbody></table></div>\n</div></details>\n");
}

fn class(c: Category) -> &'static str {
    match c {
        Category::QuantumVulnerable => "qv",
        Category::Weak => "weak",
        Category::Review => "review",
        Category::QuantumSafe => "safe",
    }
}

fn years_left(now: i64, deadline: i64) -> String {
    match deadline - now {
        n if n > 1 => format!(" About {n} years from this scan."),
        1 => " About a year from this scan.".to_string(),
        _ => String::new(),
    }
}

/// Escapes text for HTML element content and quoted attributes.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes() {
        assert_eq!(
            super::esc("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }
}
