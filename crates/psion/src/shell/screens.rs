//! The shell's screens: state, keys and drawing for Home, Encrypt, Decrypt, Keys, Scan,
//! Console, Settings and Help (with the tutorial).

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use zeroize::Zeroizing;

use psionium_scan::{Category, Report};

use super::app::{Action, App, Focus, Popup, Screen, Tone};
use super::complete;
use super::config::{self, Config};
use super::form::{Field, Form, Kind, Outcome};
use super::jobs::{Finished, Origin, ScanJob};
use super::theme::{THEMES, Theme};

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub(crate) fn spinner(app: &App) -> &'static str {
    SPINNER[app.tick % SPINNER.len()]
}

// ---------------------------------------------------------------------------------------------
// Identities

/// What an identity file says about itself, read from its comments (no passphrase needed).
#[derive(Clone, Debug)]
pub(crate) struct IdentityInfo {
    pub path: PathBuf,
    pub suite: String,
    pub protected: bool,
    pub public: Option<String>,
    pub verify: Option<String>,
    pub fingerprint: Option<String>,
    pub is_default: bool,
    pub error: Option<String>,
}

impl IdentityInfo {
    pub(crate) fn read(path: &Path) -> IdentityInfo {
        let mut info = IdentityInfo {
            path: path.to_path_buf(),
            suite: String::new(),
            protected: false,
            public: None,
            verify: None,
            fingerprint: None,
            is_default: false,
            error: None,
        };
        let contents = match fs::read_to_string(path) {
            Ok(c) => Zeroizing::new(c),
            Err(e) => {
                info.error = Some(format!("cannot read: {e}"));
                return info;
            }
        };
        info.protected = psionium_core::is_protected(&contents);
        for line in contents.lines() {
            let Some(rest) = line.strip_prefix('#').map(str::trim) else {
                continue;
            };
            if let Some(v) = rest.strip_prefix("suite:") {
                info.suite = v.split_whitespace().next().unwrap_or("").to_string();
            } else if let Some(v) = rest.strip_prefix("public key:") {
                info.public = Some(v.trim().to_string());
            } else if let Some(v) = rest.strip_prefix("verify key:") {
                info.verify = Some(v.trim().to_string());
            }
        }
        match info
            .public
            .as_deref()
            .map(psionium_core::PublicKey::from_str)
        {
            Some(Ok(pk)) => {
                info.fingerprint = Some(group_hex(&psionium_core::hex(&pk.key_id())));
                if info.suite.is_empty() {
                    info.suite = pk.suite().name().to_string();
                }
            }
            Some(Err(_)) => info.error = Some("its public key comment is not valid".into()),
            None if !info.protected => {
                info.error = Some("no public key comment; run psion pubkey to see it".into())
            }
            None => info.error = Some("no public key comment".into()),
        }
        info
    }
}

fn group_hex(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Default)]
pub(crate) struct KeysState {
    pub list: Vec<IdentityInfo>,
    pub selected: usize,
    pub pending: Option<PathBuf>,
    pub result: Option<Finished>,
}

impl KeysState {
    /// Lists `*.key` files in the keys folder and the default identity.
    pub(crate) fn load(&mut self, dir: Option<&Path>, default: Option<&Path>) {
        let mut paths: Vec<PathBuf> = dir
            .and_then(|d| fs::read_dir(d).ok())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "key") && p.is_file())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(d) = default
            && !paths.iter().any(|p| p == d)
        {
            paths.push(d.to_path_buf());
        }
        let mut list: Vec<IdentityInfo> = paths
            .iter()
            .map(|p| {
                let mut i = IdentityInfo::read(p);
                i.is_default = Some(p.as_path()) == default;
                i
            })
            .collect();
        list.sort_by(|a, b| b.is_default.cmp(&a.is_default).then(a.path.cmp(&b.path)));
        self.list = list;
        self.selected = self.selected.min(self.list.len().saturating_sub(1));
    }

    pub(crate) fn default_identity(&self) -> Option<&IdentityInfo> {
        self.list.iter().find(|i| i.is_default)
    }
}

pub(crate) fn new_identity_form(app: &App) -> Form {
    let taken = |n: &str| {
        app.keys
            .list
            .iter()
            .any(|i| i.path.file_name().is_some_and(|f| f == n))
    };
    let name = if !taken("me.key") {
        "me.key".to_string()
    } else {
        (2..)
            .map(|n| format!("me-{n}.key"))
            .find(|n| !taken(n))
            .unwrap_or_default()
    };
    let path = app
        .env
        .keys_dir
        .as_ref()
        .map(|d| app.tilde(&d.join(&name)))
        .unwrap_or(name);
    Form::new(vec![
        Field::new("path", "Save as", Kind::Path).value(path),
        Field::new(
            "suite",
            "Suite",
            Kind::Choice(&["pq-hybrid-768", "cnsa-1024"]),
        ),
        Field::new("protect", "Passphrase", Kind::Toggle).on(true),
        Field::new("pass", "New passphrase", Kind::Secret).placeholder("at least 8 characters"),
        Field::new("pass2", "Repeat it", Kind::Secret),
        Field::new("create", "Create identity", Kind::Button),
    ])
}

fn create_identity(app: &mut App) {
    let Some(Popup::NewIdentity(form)) = &app.popup else {
        return;
    };
    let path_text = form.text("path");
    let protect = form.get("protect").on;
    let pass = form.get("pass").value.clone();
    let suite = ["pq-hybrid-768", "cnsa-1024"][form.get("suite").choice];
    let path = app.expand(&path_text);
    let error = if path_text.is_empty() {
        Some("Choose where to save the identity")
    } else if path.exists() {
        Some("That file exists; choose another name")
    } else if protect && pass.chars().count() < psionium_core::MIN_PASSPHRASE_LEN {
        Some("The passphrase must be at least 8 characters")
    } else if protect && *pass != *form.get("pass2").value {
        Some("The passphrases do not match")
    } else {
        None
    };
    if let Some(e) = error {
        app.notify(e, Tone::Error);
        return;
    }
    if let Some(parent) = path.parent()
        && let Err(e) = create_private_dir(parent)
    {
        app.notify(
            format!("Could not create {}: {e}", parent.display()),
            Tone::Error,
        );
        return;
    }
    let mut args: Vec<String> = vec!["keygen".into(), "--suite".into(), suite.into(), "-o".into()];
    args.push(path.display().to_string());
    let stdin = if protect {
        args.extend(["--passphrase-file".into(), "-".into()]);
        Some(Zeroizing::new(format!("{}\n", *pass)))
    } else {
        args.push("--no-passphrase".into());
        None
    };
    app.popup = None;
    app.keys.pending = Some(path);
    let cwd = app.env.cwd.clone();
    let shown = format!(
        "psion keygen --suite {suite} -o {}",
        app.tilde(&app.expand(&path_text))
    );
    if app.spawn(Origin::Keygen, &cwd, args, stdin, Some(shown)) {
        app.notify("Creating the identity…", Tone::Info);
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

pub(crate) fn keygen_finished(app: &mut App, done: Finished) {
    let path = app.keys.pending.take();
    if done.success {
        if let Some(p) = &path
            && app.config.identity.is_none()
        {
            app.config.identity = Some(p.clone());
            let shown = app.tilde(p);
            set_identity_fields(app, &shown);
            app.save_config(&format!("Created {shown}, now your default identity"));
        } else {
            app.notify("Identity created", Tone::Ok);
        }
    } else {
        app.notify(last_line(&done.stderr), Tone::Error);
    }
    app.keys.result = (!done.success).then_some(done);
    app.reload_keys();
}

fn set_identity_fields(app: &mut App, shown: &str) {
    app.encrypt.get_mut("identity").value = Zeroizing::new(shown.to_string());
    app.decrypt.get_mut("identity").value = Zeroizing::new(shown.to_string());
}

fn last_line(s: &str) -> String {
    s.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("failed")
        .trim_start_matches("psion: error: ")
        .to_string()
}

// ---------------------------------------------------------------------------------------------
// Encrypt and decrypt

pub(crate) fn crypto_forms(config: &Config, home: Option<&Path>) -> (Form, Form) {
    let id = config
        .identity
        .as_ref()
        .map(|p| config::tilde(p, home))
        .unwrap_or_default();
    let encrypt = Form::new(vec![
        Field::new("file", "File", Kind::Path).placeholder("the file to encrypt"),
        Field::new("to", "Recipients", Kind::Text).placeholder("psionpk:… keys (empty: yourself)"),
        Field::new("to_file", "Recipients file", Kind::Path)
            .placeholder("optional: one key per line"),
        Field::new("sign", "Sign it", Kind::Toggle).on(true),
        Field::new("identity", "Your identity", Kind::Path)
            .value(id.clone())
            .placeholder("e.g. ~/.psion/me.key (create one in Keys)"),
        Field::new("pass", "Passphrase", Kind::Secret).placeholder("if your identity has one"),
        Field::new("out", "Save as", Kind::Path).placeholder("default: FILE.psen"),
        Field::new("go", "Encrypt", Kind::Button),
    ]);
    let decrypt = Form::new(vec![
        Field::new("file", "File", Kind::Path).placeholder("the .psen file"),
        Field::new("identity", "Your identity", Kind::Path)
            .value(id)
            .placeholder("e.g. ~/.psion/me.key"),
        Field::new("pass", "Passphrase", Kind::Secret).placeholder("if your identity has one"),
        Field::new("signer", "Require signer", Kind::Text)
            .placeholder("optional: the sender's psionvk:… key"),
        Field::new("out", "Save as", Kind::Path).placeholder("default: FILE without .psen"),
        Field::new("inspect", "Inspect", Kind::Button),
        Field::new("go", "Decrypt", Kind::Button),
    ]);
    (encrypt, decrypt)
}

/// Arguments for `psion encrypt` from the form, and the passphrase to feed it.
fn encrypt_args(
    app: &App,
    display: bool,
) -> Result<(Vec<String>, Option<Zeroizing<String>>), String> {
    let form = &app.encrypt;
    let file = form.text("file");
    let mut args = vec!["encrypt".to_string()];
    let keys: Vec<String> = form
        .text("to")
        .split([' ', ',', '\n'])
        .filter(|k| !k.is_empty())
        .map(str::to_string)
        .collect();
    let to_file = form.text("to_file");
    let identity = form.text("identity");
    let id_info = (!identity.is_empty()).then(|| IdentityInfo::read(&app.expand(&identity)));
    if keys.is_empty() && to_file.is_empty() {
        match id_info.as_ref().and_then(|i| i.public.clone()) {
            Some(pk) => args.extend(["-r".into(), pk]),
            None if display => args.extend(["-r".into(), "psionpk:…".into()]),
            None => {
                return Err(
                    "Add a recipient, or choose your identity to encrypt to yourself".into(),
                );
            }
        }
    }
    for k in keys {
        args.extend(["-r".into(), k]);
    }
    if !to_file.is_empty() {
        args.extend(["-R".into(), to_file]);
    }
    let mut stdin = None;
    if form.get("sign").on {
        if identity.is_empty() {
            if !display {
                return Err("Choose your identity to sign with, or turn signing off".into());
            }
        } else {
            args.extend(["--sign-with".into(), identity.clone()]);
            if id_info.as_ref().is_some_and(|i| i.protected) && !display {
                let pass = &form.get("pass").value;
                if pass.is_empty() {
                    return Err(format!("Enter the passphrase for {identity}"));
                }
                args.extend(["--passphrase-file".into(), "-".into()]);
                stdin = Some(Zeroizing::new(format!("{}\n", **pass)));
            }
        }
    }
    let out = form.text("out");
    if !out.is_empty() {
        args.extend(["-o".into(), out]);
    }
    if file.is_empty() {
        if !display {
            return Err("Choose the file to encrypt".into());
        }
        args.push("FILE".into());
    } else {
        args.push(file);
    }
    Ok((args, stdin))
}

fn decrypt_args(
    app: &App,
    display: bool,
    inspect: bool,
) -> Result<(Vec<String>, Option<Zeroizing<String>>), String> {
    let form = &app.decrypt;
    let file = form.text("file");
    if file.is_empty() && !display {
        return Err("Choose the .psen file".into());
    }
    let file = if file.is_empty() {
        "FILE.psen".to_string()
    } else {
        file
    };
    if inspect {
        return Ok((vec!["inspect".into(), file], None));
    }
    let identity = form.text("identity");
    if identity.is_empty() && !display {
        return Err("Choose your identity (create one in Keys)".into());
    }
    let mut args = vec![
        "decrypt".to_string(),
        "-i".into(),
        if identity.is_empty() {
            "IDENTITY".into()
        } else {
            identity.clone()
        },
    ];
    let mut stdin = None;
    if !display && IdentityInfo::read(&app.expand(&identity)).protected {
        let pass = &form.get("pass").value;
        if pass.is_empty() {
            return Err(format!("Enter the passphrase for {identity}"));
        }
        args.extend(["--passphrase-file".into(), "-".into()]);
        stdin = Some(Zeroizing::new(format!("{}\n", **pass)));
    }
    for s in form.text("signer").split_whitespace() {
        args.extend(["--signed-by".into(), s.to_string()]);
    }
    let out = form.text("out");
    if !out.is_empty() {
        args.extend(["-o".into(), out]);
    }
    args.push(file);
    Ok((args, stdin))
}

fn run_crypto(app: &mut App, origin: Origin) {
    let built = match origin {
        Origin::Encrypt => encrypt_args(app, false),
        Origin::Decrypt => decrypt_args(app, false, false),
        _ => decrypt_args(app, false, true),
    };
    let shown = match origin {
        Origin::Encrypt => encrypt_args(app, true),
        Origin::Decrypt => decrypt_args(app, true, false),
        _ => decrypt_args(app, true, true),
    }
    .ok()
    .map(|(a, _)| super::jobs::command_line(&a));
    match built {
        Ok((args, stdin)) => {
            let cwd = app.env.cwd.clone();
            if stdin.is_some() {
                let form = if origin == Origin::Encrypt {
                    &mut app.encrypt
                } else {
                    &mut app.decrypt
                };
                form.get_mut("pass").value = Zeroizing::new(String::new());
            }
            if app.spawn(origin, &cwd, args, stdin, shown) {
                app.crypto_running = Some(origin);
            }
        }
        Err(e) => app.notify(e, Tone::Error),
    }
}

// ---------------------------------------------------------------------------------------------
// Scan

pub(crate) struct Group {
    pub category: Category,
    pub algorithm: String,
    pub items: Vec<usize>,
}

pub(crate) struct ScanState {
    pub form: Form,
    pub progress: Arc<AtomicUsize>,
    pub started: Option<Instant>,
    pub report: Option<Report>,
    pub groups: Vec<Group>,
    pub selected: usize,
    pub scroll: u16,
    pub results: bool,
}

pub(crate) const EXPORTS: [(&str, &str); 5] = [
    ("html", "html"),
    ("markdown", "md"),
    ("json", "json"),
    ("sarif", "sarif"),
    ("cbom", "cdx.json"),
];

impl ScanState {
    pub(crate) fn new() -> ScanState {
        ScanState {
            form: Form::new(vec![
                Field::new("paths", "Folders", Kind::Path).value("."),
                Field::new("tls", "TLS servers", Kind::Text).placeholder("optional: host[:port] …"),
                Field::new("deps", "Include dependencies", Kind::Toggle),
                Field::new("go", "Scan", Kind::Button),
            ]),
            progress: Arc::new(AtomicUsize::new(0)),
            started: None,
            report: None,
            groups: Vec::new(),
            selected: 0,
            scroll: 0,
            results: false,
        }
    }

    pub(crate) fn typing(&self) -> bool {
        !self.results && self.started.is_none() && self.form.typing()
    }

    fn args(&self) -> Vec<String> {
        let mut args = vec!["scan".to_string()];
        args.extend(complete::split(&self.form.text("paths")).unwrap_or_default());
        for t in self.form.text("tls").split_whitespace() {
            args.extend(["--tls".into(), t.into()]);
        }
        if self.form.get("deps").on {
            args.push("--include-dependencies".into());
        }
        args
    }
}

fn start_scan(app: &mut App) {
    let paths: Vec<PathBuf> = match complete::split(&app.scan.form.text("paths")) {
        Ok(p) => p.iter().map(|p| app.expand(p)).collect(),
        Err(e) => return app.notify(e, Tone::Error),
    };
    let tls: Vec<String> = app
        .scan
        .form
        .text("tls")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if paths.is_empty() && tls.is_empty() {
        return app.notify("Give a folder or a TLS server to scan", Tone::Error);
    }
    if let Some(missing) = paths.iter().find(|p| !p.exists()) {
        return app.notify(
            format!("{} does not exist", app.tilde(missing)),
            Tone::Error,
        );
    }
    let Some(runner) = app.runner.clone() else {
        return app.notify("cannot scan here", Tone::Error);
    };
    app.scan.progress = Arc::new(AtomicUsize::new(0));
    app.scan.started = Some(Instant::now());
    app.busy += 1;
    let options = psionium_scan::ScanOptions {
        include_dependencies: app.scan.form.get("deps").on,
        ..psionium_scan::ScanOptions::default()
    };
    runner.scan(
        ScanJob {
            paths,
            tls,
            options,
        },
        app.scan.progress.clone(),
    );
}

pub(crate) fn scan_finished(app: &mut App, result: Result<Report, String>) {
    app.scan.started = None;
    match result {
        Ok(report) => {
            let mut groups: Vec<Group> = Vec::new();
            for (i, f) in report.findings.iter().enumerate() {
                match groups
                    .iter_mut()
                    .find(|g| g.category == f.category && g.algorithm == f.algorithm)
                {
                    Some(g) => g.items.push(i),
                    None => groups.push(Group {
                        category: f.category,
                        algorithm: f.algorithm.clone(),
                        items: vec![i],
                    }),
                }
            }
            groups.sort_by(|a, b| {
                a.category
                    .cmp(&b.category)
                    .then(b.items.len().cmp(&a.items.len()))
                    .then(a.algorithm.cmp(&b.algorithm))
            });
            let n = report.findings.len();
            app.scan.groups = groups;
            app.scan.report = Some(report);
            app.scan.selected = 0;
            app.scan.scroll = 0;
            app.scan.results = true;
            app.notify(
                format!(
                    "Scan finished: {} {}",
                    n,
                    if n == 1 { "finding" } else { "findings" }
                ),
                Tone::Ok,
            );
        }
        Err(e) => app.notify(e, Tone::Error),
    }
}

fn export(app: &mut App, format: usize) {
    let Some(report) = &app.scan.report else {
        return;
    };
    let (name, ext) = EXPORTS[format];
    let text = match name {
        "html" => report.to_html(),
        "markdown" => report.to_markdown(),
        "json" => report.to_json(),
        "sarif" => report.to_sarif(),
        _ => report.to_cbom(),
    };
    let path = (1..)
        .map(|n| {
            let stem = if n == 1 {
                "quantum-readiness".to_string()
            } else {
                format!("quantum-readiness-{n}")
            };
            app.env.cwd.join(format!("{stem}.{ext}"))
        })
        .find(|p| !p.exists())
        .unwrap_or_default();
    match crate::write_atomically(&path, false, |w| Ok(w.write_all(text.as_bytes())?)) {
        Ok(()) => app.notify(format!("Saved {}", app.tilde(&path)), Tone::Ok),
        Err(e) => app.notify(format!("Could not save: {e:#}"), Tone::Error),
    }
}

// ---------------------------------------------------------------------------------------------
// Console

pub(crate) struct Entry {
    pub command: String,
    pub output: String,
    pub ok: Option<bool>,
}

pub(crate) struct ConsoleState {
    pub entries: Vec<Entry>,
    pub input: String,
    pub history: Vec<String>,
    pub hist_pos: Option<usize>,
    pub scroll: u16,
    pub candidates: Vec<String>,
}

impl ConsoleState {
    pub(crate) fn new(history: Vec<String>) -> ConsoleState {
        ConsoleState {
            entries: Vec::new(),
            input: String::new(),
            history,
            hist_pos: None,
            scroll: 0,
            candidates: Vec::new(),
        }
    }

    pub(crate) fn running(&self) -> bool {
        self.entries.last().is_some_and(|e| e.ok.is_none())
    }

    pub(crate) fn finish(&mut self, done: Finished) {
        if let Some(e) = self.entries.iter_mut().rev().find(|e| e.ok.is_none()) {
            let mut out = done.stdout;
            if !done.stderr.is_empty() {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&done.stderr);
            }
            e.output = out;
            e.ok = Some(done.success);
        }
        self.scroll = 0;
    }

    pub(crate) fn paste(&mut self, text: &str) {
        self.input.push_str(text.lines().next().unwrap_or(""));
    }
}

fn console_key(app: &mut App, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let c = &mut app.console;
    if key.code != KeyCode::Tab {
        c.candidates.clear();
    }
    match key.code {
        KeyCode::Enter => submit(app),
        KeyCode::Char('l') if ctrl => c.entries.clear(),
        KeyCode::Char('u') if ctrl => c.input.clear(),
        KeyCode::Char(ch) if !ctrl => {
            c.input.push(ch);
            c.hist_pos = None;
        }
        KeyCode::Backspace => {
            c.input.pop();
        }
        KeyCode::Up if !c.history.is_empty() => {
            let i = c
                .hist_pos
                .map_or(c.history.len() - 1, |i| i.saturating_sub(1));
            c.hist_pos = Some(i);
            c.input = c.history[i].clone();
        }
        KeyCode::Down => match c.hist_pos {
            Some(i) if i + 1 < c.history.len() => {
                c.hist_pos = Some(i + 1);
                c.input = c.history[i + 1].clone();
            }
            Some(_) => {
                c.hist_pos = None;
                c.input.clear();
            }
            None => {}
        },
        KeyCode::Tab => {
            let (start, candidates) = complete::complete(&c.input, &app.env.cwd);
            match candidates.len() {
                0 => {}
                1 => {
                    c.input.truncate(start);
                    c.input.push_str(&candidates[0]);
                    if !candidates[0].ends_with('/') {
                        c.input.push(' ');
                    }
                }
                _ => {
                    let prefix = complete::common_prefix(&candidates);
                    if prefix.len() > c.input.len() - start {
                        c.input.truncate(start);
                        c.input.push_str(&prefix);
                    }
                    c.candidates = candidates;
                }
            }
        }
        KeyCode::PageUp => c.scroll = c.scroll.saturating_add(10),
        KeyCode::PageDown => c.scroll = c.scroll.saturating_sub(10),
        _ => return false,
    }
    true
}

fn submit(app: &mut App) {
    let line = app.console.input.trim().to_string();
    if line.is_empty() {
        return;
    }
    if app.console.running() {
        return app.notify("Wait for the running command to finish", Tone::Info);
    }
    app.console.input.clear();
    app.console.hist_pos = None;
    app.console.scroll = 0;
    if app.console.history.last() != Some(&line) {
        app.console.history.push(line.clone());
        let _ = config::save_history(app.env.config_dir.as_deref(), &app.console.history);
    }
    let reply = |app: &mut App, output: String, ok: bool| {
        app.console.entries.push(Entry {
            command: line.clone(),
            output,
            ok: Some(ok),
        });
    };
    let mut args = match complete::split(&line) {
        Ok(a) => a,
        Err(e) => return reply(app, e, false),
    };
    if args.first().is_some_and(|a| a == "psion") {
        args.remove(0);
    }
    let Some(first) = args.first().cloned() else {
        return;
    };
    match first.as_str() {
        "exit" | "quit" => app.quit = true,
        "clear" => app.console.entries.clear(),
        "pwd" => {
            let shown = app.tilde(&app.env.cwd);
            reply(app, shown, true)
        }
        "history" => {
            let h = app
                .console
                .history
                .iter()
                .rev()
                .take(20)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            reply(app, h, true)
        }
        "cd" => {
            let target = args.get(1).map_or_else(
                || app.env.home.clone().unwrap_or_else(|| app.env.cwd.clone()),
                |d| app.expand(d),
            );
            match target.canonicalize() {
                Ok(p) if p.is_dir() => {
                    let shown = app.tilde(&p);
                    app.env.cwd = p;
                    reply(app, shown, true)
                }
                _ => reply(
                    app,
                    format!("cd: {} is not a folder", args.get(1).map_or("~", |s| s)),
                    false,
                ),
            }
        }
        "help" if args.len() == 1 => {
            let mut out = String::from(
                "Commands (the same as psion <command> in a terminal; add --help to any of them):\n",
            );
            for (name, about) in complete::commands() {
                out.push_str(&format!("  {name:<12} {about}\n"));
            }
            out.push_str("\nShell commands:\n");
            for (name, about) in complete::BUILTINS {
                out.push_str(&format!("  {name:<12} {about}\n"));
            }
            out.push_str(
                "\nTab completes commands, flags and paths; ↑/↓ recall history; PgUp/PgDn scroll.",
            );
            reply(app, out, true)
        }
        _ => run_command(app, &line, args),
    }
}

fn run_command(app: &mut App, line: &str, args: Vec<String>) {
    use clap::Parser;
    let parsed = crate::Cli::try_parse_from(
        std::iter::once("psion".to_string()).chain(args.iter().cloned()),
    );
    let entry = |output: String, ok: Option<bool>| Entry {
        command: line.to_string(),
        output,
        ok,
    };
    let cli = match parsed {
        Ok(cli) => cli,
        Err(e) => {
            let ok = matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let text = e.render().to_string();
            app.console
                .entries
                .push(entry(text.trim_end().to_string(), Some(ok)));
            return;
        }
    };
    let refusal = match &cli.command {
        None | Some(crate::Command::Shell(_)) => Some("You are already in the shell.".to_string()),
        Some(crate::Command::Encrypt { input, .. } | crate::Command::Decrypt { input, .. })
            if input.as_deref().is_none_or(crate::is_dash) =>
        {
            Some("Name the input file: the shell has no standard input to read from.".to_string())
        }
        Some(crate::Command::Theme { name: Some(name) }) => {
            let name = name.clone();
            app.set_theme(&name);
            let ok = app.config.theme == name;
            app.console.entries.push(entry(
                if ok {
                    format!("Theme: {name}")
                } else {
                    format!("unknown theme \"{name}\" (use {})", THEMES.join(", "))
                },
                Some(ok),
            ));
            return;
        }
        _ => None,
    };
    if let Some(r) = refusal {
        app.console.entries.push(entry(r, Some(false)));
        return;
    }
    let cwd = app.env.cwd.clone();
    if app.spawn(Origin::Console, &cwd, args, None, None) {
        app.console.entries.push(entry(String::new(), None));
    }
}

// ---------------------------------------------------------------------------------------------
// Help and the tutorial

pub(crate) const TUTORIAL: [(&str, &str); 5] = [
    (
        "Create a practice identity",
        "An identity holds your keys: one to decrypt what others send you and one to sign what you send. This practice one has no passphrase; your real one should.",
    ),
    (
        "Write a sample file",
        "Any file works. The tutorial writes a short text file next to the practice identity.",
    ),
    (
        "Encrypt it to yourself and sign it",
        "Encryption uses X25519 + ML-KEM-768, so it stays safe against quantum computers. The ML-DSA signature proves who sent it.",
    ),
    (
        "Look inside without decrypting",
        "inspect shows the suite, the recipients' key ids and the signer, which anyone can see. The contents stay sealed.",
    ),
    (
        "Decrypt it and check the signature",
        "Only a listed recipient can decrypt, and psion checks every chunk and the signature before keeping the output.",
    ),
];

#[derive(Default)]
pub(crate) struct HelpState {
    pub tutorial: Option<Tutorial>,
    pub scroll: u16,
}

pub(crate) struct Tutorial {
    pub dir: Option<tempfile::TempDir>,
    pub step: usize,
    pub log: Vec<Entry>,
    pub public_key: Option<String>,
    pub running: bool,
    pub started: Instant,
}

impl HelpState {
    pub(crate) fn start(&mut self) {
        self.tutorial = Some(Tutorial {
            dir: tempfile::Builder::new()
                .prefix("psion-tutorial-")
                .tempdir()
                .ok(),
            step: 0,
            log: Vec::new(),
            public_key: None,
            running: false,
            started: Instant::now(),
        });
    }
}

/// The command for a tutorial step, as arguments after `psion`.
fn tutorial_args(step: usize, public_key: Option<&str>) -> Vec<String> {
    let pk = public_key.unwrap_or("psionpk:…").to_string();
    let v: Vec<&str> = match step {
        0 => vec!["keygen", "--no-passphrase", "-o", "practice.key"],
        2 => vec![
            "encrypt",
            "-r",
            &pk,
            "--sign-with",
            "practice.key",
            "hello.txt",
        ],
        3 => vec!["inspect", "hello.txt.psen"],
        4 => vec![
            "decrypt",
            "-i",
            "practice.key",
            "-o",
            "hello-decrypted.txt",
            "hello.txt.psen",
        ],
        _ => vec![],
    };
    v.into_iter().map(str::to_string).collect()
}

const SAMPLE: &str =
    "Hello from pSIONIUM. This file was encrypted with post-quantum cryptography.\n";

fn tutorial_command_line(step: usize, public_key: Option<&str>) -> String {
    if step == 1 {
        return "echo \"Hello from pSIONIUM…\" > hello.txt".into();
    }
    super::jobs::command_line(&tutorial_args(step, public_key))
}

fn tutorial_next(app: &mut App) {
    let Some(t) = &mut app.help.tutorial else {
        return;
    };
    if t.running || t.step >= TUTORIAL.len() {
        return;
    }
    let Some(dir) = t.dir.as_ref().map(|d| d.path().to_path_buf()) else {
        return app.notify("Could not create a folder for the tutorial", Tone::Error);
    };
    let step = t.step;
    if step == 1 {
        let ok = fs::write(dir.join("hello.txt"), SAMPLE).is_ok();
        t.log.push(Entry {
            command: tutorial_command_line(1, None),
            output: if ok {
                format!("Wrote hello.txt ({} bytes)", SAMPLE.len())
            } else {
                "Could not write hello.txt".into()
            },
            ok: Some(ok),
        });
        if ok {
            t.step += 1;
        }
        return;
    }
    let args = tutorial_args(step, t.public_key.as_deref());
    t.running = true;
    t.log.push(Entry {
        command: tutorial_command_line(step, t.public_key.as_deref()),
        output: String::new(),
        ok: None,
    });
    if !app.spawn(Origin::Tutorial(step), &dir, args, None, None)
        && let Some(t) = &mut app.help.tutorial
    {
        t.running = false;
        t.log.pop();
    }
}

pub(crate) fn tutorial_finished(app: &mut App, step: usize, done: Finished) {
    let Some(t) = &mut app.help.tutorial else {
        return;
    };
    t.running = false;
    let mut output = format!("{}{}", done.stdout, done.stderr)
        .trim_end()
        .to_string();
    let mut ok = done.success;
    if ok && step == 0 {
        t.public_key = done
            .stdout
            .lines()
            .find(|l| l.starts_with("psionpk:"))
            .map(str::to_string);
        ok = t.public_key.is_some();
    }
    if ok && step == 4 {
        let same = t
            .dir
            .as_ref()
            .and_then(|d| fs::read(d.path().join("hello-decrypted.txt")).ok())
            .is_some_and(|b| b == SAMPLE.as_bytes());
        output.push_str(if same {
            "\n✓ hello-decrypted.txt is identical to hello.txt"
        } else {
            "\n✗ the decrypted file differs"
        });
        ok = same;
    }
    if let Some(e) = t.log.iter_mut().rev().find(|e| e.ok.is_none()) {
        e.output = output;
        e.ok = Some(ok);
    }
    if ok {
        t.step += 1;
        if t.step == TUTORIAL.len() {
            let secs = t.started.elapsed().as_secs();
            app.notify(format!("Tutorial complete in {secs} s"), Tone::Ok);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Keys

pub(crate) fn screen_key(app: &mut App, key: KeyEvent) -> bool {
    match app.screen {
        Screen::Home => false,
        Screen::Encrypt | Screen::Decrypt => {
            let cwd = app.env.cwd.clone();
            let form = if app.screen == Screen::Encrypt {
                &mut app.encrypt
            } else {
                &mut app.decrypt
            };
            match form.on_key(key, &cwd) {
                Outcome::Pressed("go") if app.screen == Screen::Encrypt => {
                    run_crypto(app, Origin::Encrypt)
                }
                Outcome::Pressed("go") => run_crypto(app, Origin::Decrypt),
                Outcome::Pressed(_) => run_crypto(app, Origin::Inspect),
                Outcome::Handled => {}
                Outcome::Ignored => return false,
            }
            true
        }
        Screen::Keys => {
            let n = app.keys.list.len();
            match key.code {
                KeyCode::Up => app.keys.selected = app.keys.selected.saturating_sub(1),
                KeyCode::Down if n > 0 => app.keys.selected = (app.keys.selected + 1).min(n - 1),
                KeyCode::Char('n') => app.run(Action::NewIdentity),
                KeyCode::Char('r') => {
                    app.reload_keys();
                    app.notify("Reloaded", Tone::Info);
                }
                KeyCode::Char('m') if n > 0 => {
                    let path = app.keys.list[app.keys.selected].path.clone();
                    let shown = app.tilde(&path);
                    app.config.identity = Some(path);
                    set_identity_fields(app, &shown);
                    app.save_config(&format!("Default identity: {shown}"));
                    app.reload_keys();
                }
                KeyCode::Enter if n > 0 => {
                    let i = &app.keys.list[app.keys.selected];
                    let mut lines = vec![format!("File: {}", app.tilde(&i.path)), String::new()];
                    if let Some(pk) = &i.public {
                        lines.extend([
                            "Public key (others encrypt to you with it):".into(),
                            pk.clone(),
                            String::new(),
                        ]);
                    }
                    if let Some(vk) = &i.verify {
                        lines.extend([
                            "Verify key (others check your signatures with it):".into(),
                            vk.clone(),
                        ]);
                    }
                    app.popup = Some(Popup::Text {
                        title: "Identity".into(),
                        lines,
                    });
                }
                _ => return false,
            }
            true
        }
        Screen::Scan => {
            if app.scan.started.is_some() {
                return false;
            }
            if !app.scan.results {
                let cwd = app.env.cwd.clone();
                return match app.scan.form.on_key(key, &cwd) {
                    Outcome::Pressed(_) => {
                        start_scan(app);
                        true
                    }
                    Outcome::Handled => true,
                    Outcome::Ignored => false,
                };
            }
            let n = app.scan.groups.len();
            match key.code {
                KeyCode::Up => {
                    app.scan.selected = app.scan.selected.saturating_sub(1);
                    app.scan.scroll = 0;
                }
                KeyCode::Down if n > 0 => {
                    app.scan.selected = (app.scan.selected + 1).min(n - 1);
                    app.scan.scroll = 0;
                }
                KeyCode::PageDown | KeyCode::Char(' ') => {
                    app.scan.scroll = app.scan.scroll.saturating_add(8)
                }
                KeyCode::PageUp => app.scan.scroll = app.scan.scroll.saturating_sub(8),
                KeyCode::Char('n') => app.scan.results = false,
                KeyCode::Char('x') => app.popup = Some(Popup::Export { selected: 0 }),
                _ => return false,
            }
            true
        }
        Screen::Console => console_key(app, key),
        Screen::Settings => {
            match key.code {
                KeyCode::Up => app.settings_row = app.settings_row.saturating_sub(1),
                KeyCode::Down => app.settings_row = (app.settings_row + 1).min(2),
                KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter => {
                    match app.settings_row {
                        0 => {
                            let i = THEMES
                                .iter()
                                .position(|t| *t == app.theme.name)
                                .unwrap_or(0);
                            let next = if key.code == KeyCode::Left {
                                (i + THEMES.len() - 1) % THEMES.len()
                            } else {
                                (i + 1) % THEMES.len()
                            };
                            app.set_theme(THEMES[next]);
                        }
                        1 => app.run(Action::ToggleAnimation),
                        _ => app.go(Screen::Keys),
                    }
                }
                _ => return false,
            }
            true
        }
        Screen::Help => {
            if app.help.tutorial.is_some() {
                match key.code {
                    KeyCode::Enter => tutorial_next(app),
                    KeyCode::Esc => {
                        app.help.tutorial = None;
                        app.notify(
                            "Tutorial closed; its practice files were deleted",
                            Tone::Info,
                        );
                    }
                    _ => return false,
                }
                return true;
            }
            match key.code {
                KeyCode::PageDown | KeyCode::Down => {
                    app.help.scroll = app.help.scroll.saturating_add(3)
                }
                KeyCode::PageUp | KeyCode::Up => {
                    app.help.scroll = app.help.scroll.saturating_sub(3)
                }
                _ => return false,
            }
            true
        }
    }
}

pub(crate) fn popup_key(app: &mut App, key: KeyEvent) {
    let cwd = app.env.cwd.clone();
    match &mut app.popup {
        Some(Popup::Text { .. }) => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                app.popup = None;
            }
        }
        Some(Popup::NewIdentity(form)) => {
            if key.code == KeyCode::Esc {
                app.popup = None;
                return;
            }
            let outcome = form.on_key(key, &cwd);
            let protect = form.get("protect").on;
            form.get_mut("pass").hidden = !protect;
            form.get_mut("pass2").hidden = !protect;
            if outcome == Outcome::Pressed("create") {
                create_identity(app);
            }
        }
        Some(Popup::Export { selected }) => match key.code {
            KeyCode::Esc => app.popup = None,
            KeyCode::Up => *selected = selected.saturating_sub(1),
            KeyCode::Down => *selected = (*selected + 1).min(EXPORTS.len() - 1),
            KeyCode::Enter => {
                let s = *selected;
                app.popup = None;
                export(app, s);
            }
            _ => {}
        },
        None => {}
    }
}

// ---------------------------------------------------------------------------------------------
// What the bottom bar shows

/// The scripting command equivalent to what the screen would do now.
pub(crate) fn equivalent(app: &App) -> String {
    let line = |args: Vec<String>| super::jobs::command_line(&args);
    match app.screen {
        Screen::Home => "psion --help".into(),
        Screen::Help => match &app.help.tutorial {
            None => "psion --help".into(),
            Some(t) => {
                tutorial_command_line(t.step.min(TUTORIAL.len() - 1), t.public_key.as_deref())
            }
        },
        Screen::Encrypt => encrypt_args(app, true)
            .map(|(a, _)| line(a))
            .unwrap_or_default(),
        Screen::Decrypt => {
            let inspect = app
                .decrypt
                .fields
                .get(app.decrypt.focus)
                .is_some_and(|f| f.id == "inspect");
            decrypt_args(app, true, inspect)
                .map(|(a, _)| line(a))
                .unwrap_or_default()
        }
        Screen::Keys => match app.keys.list.get(app.keys.selected) {
            Some(i) => format!("psion pubkey -i {}", app.tilde(&i.path)),
            None => "psion keygen -o ~/.psion/me.key".into(),
        },
        Screen::Scan => line(app.scan.args()),
        Screen::Console => {
            let input = app.console.input.trim();
            if input.is_empty() {
                "psion <command>".into()
            } else {
                format!("psion {}", input.trim_start_matches("psion "))
            }
        }
        Screen::Settings => format!("psion theme {}", app.theme.name),
    }
}

/// Key hints for the bottom bar.
pub(crate) fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    if app.palette.is_some() {
        return vec![("↑↓", "choose"), ("Enter", "run"), ("Esc", "close")];
    }
    if let Some(p) = &app.popup {
        return match p {
            Popup::NewIdentity(_) => vec![
                ("Tab", "next"),
                ("Space", "change"),
                ("Enter", "create"),
                ("Esc", "cancel"),
            ],
            Popup::Export { .. } => vec![("↑↓", "format"), ("Enter", "save"), ("Esc", "cancel")],
            Popup::Text { .. } => vec![("Esc", "close")],
        };
    }
    if app.focus == Focus::Nav {
        return vec![
            ("↑↓", "screens"),
            ("Enter", "open"),
            ("1-8", "jump"),
            ("/", "palette"),
            (":", "prompt"),
            ("^Q", "quit"),
        ];
    }
    let mut h: Vec<(&str, &str)> = match app.screen {
        Screen::Home => vec![("/", "palette"), (":", "prompt"), ("?", "help")],
        Screen::Encrypt | Screen::Decrypt => vec![
            ("Tab", "next field"),
            ("→", "complete path"),
            ("Enter", "next / press"),
        ],
        Screen::Keys => vec![
            ("↑↓", "choose"),
            ("Enter", "show keys"),
            ("n", "new"),
            ("m", "make default"),
        ],
        Screen::Scan if app.scan.results => vec![
            ("↑↓", "algorithm"),
            ("PgDn", "scroll"),
            ("x", "export"),
            ("n", "new scan"),
        ],
        Screen::Scan => vec![("Tab", "next field"), ("Enter", "scan")],
        Screen::Console => vec![
            ("Enter", "run"),
            ("Tab", "complete"),
            ("↑↓", "history"),
            ("PgUp", "scroll"),
        ],
        Screen::Settings => vec![("↑↓", "choose"), ("←→", "change")],
        Screen::Help if app.help.tutorial.is_some() => {
            vec![("Enter", "next step"), ("Esc", "end tutorial")]
        }
        Screen::Help => vec![("t", "tutorial"), ("PgDn", "scroll")],
    };
    if !(app.screen == Screen::Help && app.help.tutorial.is_some()) {
        h.push(("Esc", "back"));
    }
    h.extend([("^K", "palette"), ("^Q", "quit")]);
    h
}

// ---------------------------------------------------------------------------------------------
// Drawing

pub(crate) fn draw(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Screen;
    match app.screen {
        Screen::Home => draw_home(f, area, app),
        Screen::Encrypt => draw_crypto(
            f,
            area,
            app,
            &app.encrypt,
            app.encrypt_result.as_ref(),
            app.crypto_running == Some(Origin::Encrypt),
            "Encrypt a file for one or more recipients. Signing proves it came from you.",
            focused,
        ),
        Screen::Decrypt => draw_crypto(
            f,
            area,
            app,
            &app.decrypt,
            app.decrypt_result.as_ref(),
            matches!(app.crypto_running, Some(Origin::Decrypt | Origin::Inspect)),
            "Decrypt a .psen file sent to you. Require a signer to refuse files from anyone else.",
            focused,
        ),
        Screen::Keys => draw_keys(f, area, app),
        Screen::Scan => draw_scan(f, area, app, focused),
        Screen::Console => draw_console(f, area, app),
        Screen::Settings => draw_settings(f, area, app, focused),
        Screen::Help => draw_help(f, area, app),
    }
}

fn kv<'a>(t: &Theme, label: &'a str, value: Vec<Span<'a>>) -> Line<'a> {
    let mut spans = vec![Span::styled(format!("{label:<10}"), t.muted())];
    spans.extend(value);
    Line::from(spans)
}

fn identity_summary<'a>(app: &App, i: Option<&IdentityInfo>) -> Vec<Span<'a>> {
    let t = &app.theme;
    match i {
        Some(i) => vec![
            Span::styled(app.tilde(&i.path), t.title()),
            Span::styled(
                if i.protected {
                    " · passphrase protected"
                } else {
                    " · no passphrase"
                },
                if i.protected { t.muted() } else { t.warn() },
            ),
        ],
        None => vec![Span::styled(
            "none yet: press k, then n, to create one",
            t.warn(),
        )],
    }
}

fn draw_home(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let mut lines = vec![
        Line::from(Span::styled("Welcome to pSIONIUM", t.accent())),
        Line::from(Span::styled(
            "Post-quantum encryption, signatures and quantum-readiness scans, on this computer.",
            t.muted(),
        )),
        Line::raw(""),
        kv(
            t,
            "Identity",
            identity_summary(app, app.keys.default_identity()),
        ),
    ];
    if let Some(i) = app.keys.default_identity() {
        let short: String = i
            .fingerprint
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(19)
            .collect();
        lines.push(kv(
            t,
            "",
            vec![Span::styled(
                format!("{} · key id {short}…", i.suite),
                t.muted(),
            )],
        ));
    }
    let scan = match &app.scan.report {
        Some(r) => {
            let c = r.counts();
            let n = |k| c.get(&k).copied().unwrap_or(0);
            vec![
                Span::styled(
                    format!("{} quantum-vulnerable", n(Category::QuantumVulnerable)),
                    t.danger(),
                ),
                Span::styled(format!(" · {} weak", n(Category::Weak)), t.warn()),
                Span::styled(
                    format!(
                        " · {} review · {} post-quantum",
                        n(Category::Review),
                        n(Category::QuantumSafe)
                    ),
                    t.muted(),
                ),
            ]
        }
        None => vec![Span::styled("not run yet: press q", t.muted())],
    };
    lines.push(kv(t, "Last scan", scan));
    lines.push(kv(
        t,
        "Account",
        vec![Span::styled(
            "not signed in (accounts are not available yet)",
            t.muted(),
        )],
    ));
    lines.push(kv(
        t,
        "Folder",
        vec![Span::styled(app.tilde(&app.env.cwd), t.title())],
    ));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("Quick actions", t.title())));
    let actions = [
        ("e", "Encrypt a file"),
        ("d", "Decrypt a file"),
        ("q", "Scan for quantum risk"),
        ("k", "Keys and identities"),
        ("t", "Take the tutorial"),
        (":", "pSIONIUM> prompt"),
        ("/", "Command palette"),
        ("?", "Help"),
    ];
    let two = area.width >= 54;
    let col = (area.width as usize / 2).saturating_sub(5).min(26);
    let mut row: Vec<Span> = Vec::new();
    for (i, (k, label)) in actions.iter().enumerate() {
        row.push(Span::styled(format!("  {k}  "), t.key()));
        row.push(Span::styled(format!("{label:<col$}"), t.title()));
        if !two || i % 2 == 1 {
            lines.push(Line::from(std::mem::take(&mut row)));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Tip: the bottom bar shows the psion command for each action.",
        t.muted(),
    )));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn result_lines<'a>(t: &Theme, r: &'a Finished) -> Vec<Line<'a>> {
    let mut lines = vec![Line::from(vec![
        Span::styled(
            if r.success { "✓ " } else { "✗ " },
            if r.success { t.ok() } else { t.danger() },
        ),
        Span::styled(r.command_line.clone(), t.muted()),
    ])];
    for l in r.stdout.lines().chain(r.stderr.lines()) {
        let style = if l.starts_with("psion: error") {
            t.danger()
        } else {
            t.title()
        };
        lines.push(Line::from(Span::styled(l.to_string(), style)));
    }
    lines
}

#[allow(clippy::too_many_arguments)]
fn draw_crypto(
    f: &mut Frame,
    area: Rect,
    app: &App,
    form: &Form,
    result: Option<&Finished>,
    running: bool,
    intro: &str,
    focused: bool,
) {
    let t = &app.theme;
    let [intro_area, form_area, result_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(form.height() + 1),
        Constraint::Min(0),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(Span::styled(intro.to_string(), t.muted())).wrap(Wrap { trim: true }),
        intro_area,
    );
    form.draw(f, form_area, t, focused, &app.env.cwd);
    let lines = if running {
        vec![Line::from(Span::styled(
            format!("{} working…", spinner(app)),
            t.accent(),
        ))]
    } else {
        result.map(|r| result_lines(t, r)).unwrap_or_default()
    };
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        result_area,
    );
}

fn draw_keys(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let mut lines = vec![
        Line::from(Span::styled(
            "Your identities. The public key lets people encrypt to you; the verify key lets them check your signatures.",
            t.muted(),
        )),
        Line::raw(""),
    ];
    if app.keys.list.is_empty() {
        lines.push(Line::from(Span::styled(
            "No identities yet in ~/.psion.",
            t.title(),
        )));
        lines.push(Line::from(vec![
            Span::styled("Press ", t.muted()),
            Span::styled("n", t.key()),
            Span::styled(" to create one. Keep its passphrase somewhere safe: without it, files sent to you cannot be opened.", t.muted()),
        ]));
    }
    for (idx, i) in app.keys.list.iter().enumerate() {
        let sel = idx == app.keys.selected && app.focus == Focus::Screen;
        let marker = if sel { "› " } else { "  " };
        let name_style = if sel { t.selected() } else { t.title() };
        let mut row = vec![
            Span::styled(marker, t.accent()),
            Span::styled(app.tilde(&i.path), name_style),
        ];
        if i.is_default {
            row.push(Span::styled("  default", t.ok()));
        }
        lines.push(Line::from(row));
        let mut detail = vec![Span::raw("    ")];
        if let Some(e) = &i.error {
            detail.push(Span::styled(e.clone(), t.warn()));
        } else {
            detail.push(Span::styled(
                format!(
                    "{} · {}",
                    i.suite,
                    if i.protected {
                        "passphrase protected"
                    } else {
                        "no passphrase"
                    }
                ),
                t.muted(),
            ));
        }
        lines.push(Line::from(detail));
        if let Some(fp) = &i.fingerprint {
            lines.push(Line::from(Span::styled(
                format!("    fingerprint {fp}"),
                t.muted(),
            )));
        }
        if let Some(pk) = &i.public {
            let width = area.width.saturating_sub(6) as usize;
            let short = if pk.chars().count() > width {
                format!("{}…", &pk[..width.saturating_sub(1).max(10).min(pk.len())])
            } else {
                pk.clone()
            };
            lines.push(Line::from(Span::styled(format!("    {short}"), t.muted())));
        }
    }
    if let Some(r) = &app.keys.result {
        lines.push(Line::raw(""));
        lines.extend(result_lines(t, r));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn category_tag(t: &Theme, c: Category) -> Span<'static> {
    match c {
        Category::QuantumVulnerable => Span::styled("VULN  ", t.danger()),
        Category::Weak => Span::styled("WEAK  ", t.warn()),
        Category::Review => Span::styled("REVIEW", t.accent()),
        Category::QuantumSafe => Span::styled("PQ OK ", t.ok()),
    }
}

fn draw_scan(f: &mut Frame, area: Rect, app: &App, focused: bool) {
    let t = &app.theme;
    let s = &app.scan;
    if let Some(started) = s.started {
        let lines = vec![
            Line::from(Span::styled(
                format!("{} Scanning…", spinner(app)),
                t.accent(),
            )),
            Line::from(Span::styled(
                format!(
                    "{} files read · {:.1} s",
                    s.progress.load(Ordering::Relaxed),
                    started.elapsed().as_secs_f32()
                ),
                t.muted(),
            )),
        ];
        f.render_widget(Paragraph::new(lines), area);
        return;
    }
    let (Some(report), true) = (&s.report, s.results) else {
        let [intro, form] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("Find cryptography that quantum computers will break: in code, dependencies, certificates, keys and live TLS servers.", t.muted())),
            ])
            .wrap(Wrap { trim: true }),
            intro,
        );
        s.form.draw(f, form, t, focused, &app.env.cwd);
        return;
    };
    let c = report.counts();
    let n = |k| c.get(&k).copied().unwrap_or(0);
    let [summary, body] = Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} quantum-vulnerable", n(Category::QuantumVulnerable)),
                t.danger(),
            ),
            Span::styled(format!(" · {} weak", n(Category::Weak)), t.warn()),
            Span::styled(format!(" · {} review", n(Category::Review)), t.accent()),
            Span::styled(
                format!(" · {} post-quantum", n(Category::QuantumSafe)),
                t.ok(),
            ),
            Span::styled(format!(" · {} files", report.files_scanned), t.muted()),
        ]))
        .wrap(Wrap { trim: true }),
        summary,
    );
    if s.groups.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled("No cryptography found.", t.title())),
            body,
        );
        return;
    }
    let list_w = (body.width / 2).clamp(24, 44);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Length(list_w), Constraint::Min(0)]).areas(body);
    let visible = list_area.height as usize;
    let first = s.selected.saturating_sub(visible.saturating_sub(1));
    let rows: Vec<Line> = s
        .groups
        .iter()
        .enumerate()
        .skip(first)
        .take(visible)
        .map(|(i, g)| {
            let sel = i == s.selected;
            let name_w = list_w.saturating_sub(14) as usize;
            let name: String = g.algorithm.chars().take(name_w).collect();
            Line::from(vec![
                Span::styled(if sel { "› " } else { "  " }, t.accent()),
                category_tag(t, g.category),
                Span::raw(" "),
                Span::styled(
                    format!("{name:<name_w$}"),
                    if sel { t.selected() } else { t.title() },
                ),
                Span::styled(format!("{:>4}", g.items.len()), t.muted()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(rows), list_area);
    let g = &s.groups[s.selected.min(s.groups.len() - 1)];
    let first_finding = &report.findings[g.items[0]];
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{} · {}", g.algorithm, g.category.title()),
            t.title(),
        )),
        Line::from(Span::styled(first_finding.guidance(), t.muted())),
        Line::raw(""),
    ];
    for &i in &g.items {
        let f = &report.findings[i];
        let at = match f.line {
            Some(l) => format!("{}:{l}", f.location),
            None => f.location.clone(),
        };
        lines.push(Line::from(Span::styled(at, t.accent())));
        lines.push(Line::from(Span::styled(
            format!("  {}", f.detail),
            t.title(),
        )));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((s.scroll, 0))
            .block(Block::new().padding(ratatui::widgets::Padding::left(2))),
        detail_area,
    );
}

/// Splits a line into pieces of at most `width` characters.
fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars.chunks(width).map(|c| c.iter().collect()).collect()
}

fn draw_console(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let c = &app.console;
    let width = area.width as usize;
    let prompt = "pSIONIUM> ";
    let mut lines: Vec<Line> = Vec::new();
    if c.entries.is_empty() {
        for l in [
            "Type a psion command without \"psion\", for example:",
            "  scan . --format markdown -o report.md",
            "help lists commands · Tab completes · exit leaves",
            "",
        ] {
            for w in wrap(l, width) {
                lines.push(Line::from(Span::styled(w, t.muted())));
            }
        }
    }
    for e in &c.entries {
        for (k, w) in wrap(&format!("{prompt}{}", e.command), width)
            .into_iter()
            .enumerate()
        {
            if k == 0 {
                let rest: String = w.chars().skip(prompt.len()).collect();
                lines.push(Line::from(vec![
                    Span::styled(prompt, t.accent2()),
                    Span::styled(rest, t.title()),
                ]));
            } else {
                lines.push(Line::from(Span::styled(w, t.title())));
            }
        }
        match e.ok {
            None => lines.push(Line::from(Span::styled(
                format!("{} running…", spinner(app)),
                t.accent(),
            ))),
            Some(ok) => {
                let style = if ok {
                    t.base().bg(ratatui::style::Color::Reset)
                } else {
                    t.danger()
                };
                for l in e.output.lines() {
                    for w in wrap(l, width) {
                        lines.push(Line::from(Span::styled(w, style)));
                    }
                }
            }
        }
    }
    let mut footer: Vec<Line> = Vec::new();
    if !c.candidates.is_empty() {
        let joined = c.candidates.join("  ");
        for w in wrap(&joined, width).into_iter().take(3) {
            footer.push(Line::from(Span::styled(w, t.muted())));
        }
    }
    let input = format!("{prompt}{}", c.input);
    let wrapped = wrap(&input, width.saturating_sub(1));
    let n = wrapped.len();
    for (k, w) in wrapped.into_iter().enumerate() {
        let mut spans = if k == 0 {
            let rest: String = w.chars().skip(prompt.len()).collect();
            vec![
                Span::styled(prompt, t.accent2()),
                Span::styled(rest, t.title()),
            ]
        } else {
            vec![Span::styled(w, t.title())]
        };
        if k + 1 == n && app.focus == Focus::Screen {
            spans.push(Span::styled("▏", t.accent()));
        }
        footer.push(Line::from(spans));
    }
    let footer_h = footer.len() as u16;
    let [log_area, input_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(footer_h)]).areas(area);
    let visible = log_area.height as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    let offset = max_scroll.saturating_sub(c.scroll as usize);
    let shown: Vec<Line> = lines.into_iter().skip(offset).take(visible).collect();
    f.render_widget(Paragraph::new(shown), log_area);
    f.render_widget(Paragraph::new(footer), input_area);
}

fn draw_settings(f: &mut Frame, area: Rect, app: &App, focused: bool) {
    let t = &app.theme;
    let row = |i: usize, label: &str, value: Vec<Span<'static>>| {
        let sel = focused && app.settings_row == i;
        let mut spans = vec![
            Span::styled(if sel { "› " } else { "  " }, t.accent()),
            Span::styled(
                format!("{label:<18}"),
                if sel { t.title() } else { t.muted() },
            ),
        ];
        spans.extend(value);
        Line::from(spans)
    };
    let themes: Vec<Span<'static>> = THEMES
        .iter()
        .enumerate()
        .flat_map(|(i, n)| {
            let style = if *n == t.name {
                t.selected()
            } else {
                t.muted()
            };
            [
                Span::raw(if i == 0 { "" } else { "  " }),
                Span::styled(n.to_string(), style),
            ]
        })
        .collect();
    let animation = if app.config.animation {
        "[x] on"
    } else {
        "[ ] off"
    };
    let identity = app
        .config
        .identity
        .as_ref()
        .map_or("none (choose one in Keys)".to_string(), |p| app.tilde(p));
    let mut lines = vec![
        row(0, "Theme", themes),
        row(
            1,
            "Launch animation",
            vec![Span::styled(animation, t.title())],
        ),
        row(
            2,
            "Default identity",
            vec![Span::styled(identity, t.title())],
        ),
        Line::raw(""),
    ];
    let saved = app
        .env
        .config_dir
        .as_ref()
        .map_or("not saved (no configuration folder)".to_string(), |d| {
            format!("Saved in {}", app.tilde(&d.join("config.toml")))
        });
    lines.push(Line::from(Span::styled(format!("  {saved}"), t.muted())));
    if t.mono {
        lines.push(Line::from(Span::styled(
            "  NO_COLOR is set, so colours are off.",
            t.muted(),
        )));
    }
    lines.push(Line::from(Span::styled(
        "  Start with --theme NAME, --no-animation or --plain to override these once.",
        t.muted(),
    )));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn draw_help(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    if let Some(tut) = &app.help.tutorial {
        let mut lines = vec![
            Line::from(Span::styled(
                "Tutorial: encrypt and decrypt a file in about a minute",
                t.accent(),
            )),
            Line::from(Span::styled(
                "Each step runs the real psion command in a temporary folder, deleted when the tutorial ends.",
                t.muted(),
            )),
            Line::raw(""),
        ];
        for (i, (title, about)) in TUTORIAL.iter().enumerate() {
            let (mark, style) = if i < tut.step {
                ("✓", t.ok())
            } else if i == tut.step {
                ("›", t.accent())
            } else {
                ("·", t.muted())
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {mark} {}. ", i + 1), style),
                Span::styled(
                    title.to_string(),
                    if i == tut.step { t.title() } else { t.muted() },
                ),
            ]));
            if i == tut.step {
                lines.push(Line::from(Span::styled(
                    format!("      {about}"),
                    t.muted(),
                )));
                lines.push(Line::from(vec![
                    Span::styled("      Press ", t.muted()),
                    Span::styled("Enter", t.key()),
                    Span::styled(" to run: ", t.muted()),
                    Span::styled(
                        tutorial_command_line(i, tut.public_key.as_deref()),
                        t.title(),
                    ),
                ]));
            }
        }
        if tut.step == TUTORIAL.len() {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "Done. You created keys, encrypted and signed a file, inspected it and decrypted it, all post-quantum. Next: create your own identity in Keys (with a passphrase).",
                t.ok(),
            )));
        }
        if let Some(e) = tut.log.last() {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("› ", t.accent2()),
                Span::styled(e.command.clone(), t.title()),
            ]));
            match e.ok {
                None => lines.push(Line::from(Span::styled(
                    format!("{} running…", spinner(app)),
                    t.accent(),
                ))),
                Some(ok) => {
                    for l in e.output.lines() {
                        lines.push(Line::from(Span::styled(
                            l.to_string(),
                            if ok { t.title() } else { t.danger() },
                        )));
                    }
                }
            }
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
        return;
    }
    let key = |k: &'static str, what: &'static str| {
        Line::from(vec![
            Span::styled(format!("  {k:<12}"), t.key()),
            Span::styled(what, t.title()),
        ])
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("New here? Press ", t.title()),
            Span::styled("t", t.key()),
            Span::styled(" for a one-minute tutorial.", t.title()),
        ]),
        Line::raw(""),
        Line::from(Span::styled("Keys everywhere", t.accent())),
        key("Ctrl+K  /", "command palette: type to find any action"),
        key(":", "the pSIONIUM> prompt (any psion command)"),
        key("1-8", "jump to a screen"),
        key("Tab ↑ ↓", "move between fields and rows"),
        key("Esc", "back to the screen list"),
        key("F1  ?", "this help"),
        key("Ctrl+Q", "quit"),
        Line::raw(""),
        Line::from(Span::styled("On the Home screen", t.accent())),
        key("e d q k t", "encrypt, decrypt, scan, keys, tutorial"),
        Line::raw(""),
        Line::from(Span::styled("What works today", t.accent())),
        Line::from(Span::styled(
            "  Everything here runs on this computer: identities, encryption, signatures, scans.",
            t.title(),
        )),
        Line::from(Span::styled(
            "  Accounts, sending files to people and the inbox are designed but not built yet.",
            t.muted(),
        )),
        Line::raw(""),
        Line::from(Span::styled("Scripting", t.accent())),
        Line::from(Span::styled(
            "  Every action shows its psion command in the bottom bar. psion <command> --help explains each one.",
            t.title(),
        )),
        Line::from(Span::styled(
            "  psion --plain gives a line-by-line pSIONIUM> prompt; NO_COLOR turns colours off.",
            t.title(),
        )),
        Line::raw(""),
        Line::from(Span::styled("Documentation", t.accent())),
        Line::from(Span::styled(
            "  https://github.com/Chandu00756/psionium (README, .psen format, threat model, scanner guide)",
            t.title(),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.help.scroll, 0)),
        area,
    );
}

/// Draws the open popup.
pub(crate) fn draw_popup(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let Some(popup) = &app.popup else { return };
    let (title, w, h) = match popup {
        Popup::Text { title, lines } => (title.clone(), 76, lines.len() as u16 + 6),
        Popup::NewIdentity(form) => ("New identity".to_string(), 70, form.height() + 5),
        Popup::Export { .. } => ("Save the report".to_string(), 46, EXPORTS.len() as u16 + 5),
    };
    let rect = centered(area, w, h);
    f.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.border(true))
        .style(t.base())
        .title(Span::styled(format!(" {title} "), t.accent()));
    let inner = block.inner(rect).inner(ratatui::layout::Margin::new(1, 1));
    f.render_widget(block, rect);
    match popup {
        Popup::Text { lines, .. } => {
            let l: Vec<Line> = lines
                .iter()
                .map(|s| Line::from(Span::styled(s.clone(), t.title())))
                .collect();
            f.render_widget(Paragraph::new(l).wrap(Wrap { trim: false }), inner);
        }
        Popup::NewIdentity(form) => form.draw(f, inner, t, true, &app.env.cwd),
        Popup::Export { selected } => {
            let mut l = vec![
                Line::from(Span::styled(
                    format!("Saved in {}", app.tilde(&app.env.cwd)),
                    t.muted(),
                )),
                Line::raw(""),
            ];
            for (i, (name, ext)) in EXPORTS.iter().enumerate() {
                let style = if i == *selected {
                    t.selected()
                } else {
                    t.title()
                };
                l.push(Line::from(vec![
                    Span::styled(if i == *selected { "› " } else { "  " }, t.accent()),
                    Span::styled(format!("{name:<10}"), style),
                    Span::styled(format!(" quantum-readiness.{ext}"), t.muted()),
                ]));
            }
            f.render_widget(Paragraph::new(l), inner);
        }
    }
}

/// A rectangle of at most `w`×`h` centred in `area`.
pub(crate) fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}
