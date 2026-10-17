//! The shell's state and key handling. Drawing is in `ui` and `screens`.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::config::{self, Config};
use super::jobs::{Event, Finished, Origin, Runner};
use super::screens::{
    self, ConsoleState, HelpState, KeysState, ScanState, crypto_forms, new_identity_form,
};
use super::theme::{self, Depth, Theme};

/// The screens, in navigation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Screen {
    Home,
    Encrypt,
    Decrypt,
    Keys,
    Scan,
    Console,
    Settings,
    Help,
}

impl Screen {
    pub(crate) const ALL: [Screen; 8] = [
        Screen::Home,
        Screen::Encrypt,
        Screen::Decrypt,
        Screen::Keys,
        Screen::Scan,
        Screen::Console,
        Screen::Settings,
        Screen::Help,
    ];

    pub(crate) fn title(self) -> &'static str {
        match self {
            Screen::Home => "Home",
            Screen::Encrypt => "Encrypt",
            Screen::Decrypt => "Decrypt",
            Screen::Keys => "Keys",
            Screen::Scan => "Scan",
            Screen::Console => "Console",
            Screen::Settings => "Settings",
            Screen::Help => "Help",
        }
    }

    pub(crate) fn index(self) -> usize {
        Screen::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

/// Which part of the window has the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Focus {
    Nav,
    Screen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Info,
    Ok,
    Error,
}

/// Something a palette entry or shortcut does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Go(Screen),
    Theme(&'static str),
    ToggleAnimation,
    Tutorial,
    NewIdentity,
    Quit,
}

pub(crate) struct Palette {
    pub query: String,
    pub selected: usize,
}

/// A window over the screen.
pub(crate) enum Popup {
    /// Read-only text, such as a full public key.
    Text { title: String, lines: Vec<String> },
    /// Create an identity.
    NewIdentity(super::form::Form),
    /// Pick a format to export the scan report.
    Export { selected: usize },
}

/// What the environment provides; tests pass fixed values.
pub(crate) struct Env {
    pub config_dir: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub keys_dir: Option<PathBuf>,
    pub cwd: PathBuf,
    pub version: String,
    pub depth: Depth,
    pub no_color: bool,
    pub exe: Option<PathBuf>,
}

pub(crate) struct App {
    pub env: Env,
    pub config: Config,
    pub theme: Theme,
    pub screen: Screen,
    pub focus: Focus,
    pub palette: Option<Palette>,
    pub popup: Option<Popup>,
    pub toast: Option<(String, Tone, Instant)>,
    pub runner: Option<Runner>,
    rx: Receiver<Event>,
    pub busy: usize,
    pub tick: usize,
    pub quit: bool,
    pub encrypt: super::form::Form,
    pub encrypt_result: Option<Finished>,
    pub decrypt: super::form::Form,
    pub decrypt_result: Option<Finished>,
    /// The encrypt, decrypt or inspect command in progress.
    pub crypto_running: Option<Origin>,
    pub keys: KeysState,
    pub scan: ScanState,
    pub console: ConsoleState,
    pub settings_row: usize,
    pub help: HelpState,
}

pub(crate) const TOAST_TIME: Duration = Duration::from_secs(4);

impl App {
    pub(crate) fn new(env: Env, config: Config, history: Vec<String>) -> App {
        let (tx, rx) = mpsc::channel();
        let runner = env.exe.clone().map(|exe| Runner { exe, tx });
        let theme = Theme::new(&config.theme, env.depth, env.no_color);
        let (encrypt, decrypt) = crypto_forms(&config, env.home.as_deref());
        let mut app = App {
            theme,
            screen: Screen::Home,
            focus: Focus::Nav,
            palette: None,
            popup: None,
            toast: None,
            runner,
            rx,
            busy: 0,
            tick: 0,
            quit: false,
            encrypt,
            encrypt_result: None,
            decrypt,
            decrypt_result: None,
            crypto_running: None,
            keys: KeysState::default(),
            scan: ScanState::new(),
            console: ConsoleState::new(history),
            settings_row: 0,
            help: HelpState::default(),
            config,
            env,
        };
        app.reload_keys();
        app
    }

    /// Rereads identities from the keys folder and the configured default.
    pub(crate) fn reload_keys(&mut self) {
        self.keys.load(
            self.env.keys_dir.as_deref(),
            self.config.identity.as_deref(),
        );
    }

    pub(crate) fn notify(&mut self, text: impl Into<String>, tone: Tone) {
        self.toast = Some((text.into(), tone, Instant::now()));
    }

    pub(crate) fn tilde(&self, path: &Path) -> String {
        config::tilde(path, self.env.home.as_deref())
    }

    pub(crate) fn expand(&self, path: &str) -> PathBuf {
        let p = config::expand(path, self.env.home.as_deref());
        if p.is_absolute() {
            p
        } else {
            self.env.cwd.join(p)
        }
    }

    /// Switches screens and gives it the keyboard.
    pub(crate) fn go(&mut self, screen: Screen) {
        self.screen = screen;
        self.focus = Focus::Screen;
        if screen == Screen::Keys {
            self.reload_keys();
        }
    }

    pub(crate) fn set_theme(&mut self, name: &str) {
        if !theme::is_theme(name) {
            self.notify(
                format!(
                    "unknown theme \"{name}\" (use {})",
                    theme::THEMES.join(", ")
                ),
                Tone::Error,
            );
            return;
        }
        self.config.theme = name.to_string();
        self.theme = Theme::new(name, self.env.depth, self.env.no_color);
        self.save_config(&format!("Theme: {name}"));
    }

    pub(crate) fn save_config(&mut self, done: &str) {
        match self.config.save_to(self.env.config_dir.as_deref()) {
            Ok(_) => self.notify(format!("{done} (saved)"), Tone::Ok),
            Err(e) => self.notify(format!("{done}, but not saved: {e:#}"), Tone::Error),
        }
    }

    pub(crate) fn run(&mut self, action: Action) {
        match action {
            Action::Go(s) => self.go(s),
            Action::Theme(name) => self.set_theme(name),
            Action::ToggleAnimation => {
                self.config.animation = !self.config.animation;
                let state = if self.config.animation { "on" } else { "off" };
                self.save_config(&format!("Launch animation {state}"));
            }
            Action::Tutorial => {
                self.go(Screen::Help);
                self.help.start();
            }
            Action::NewIdentity => {
                self.go(Screen::Keys);
                self.popup = Some(Popup::NewIdentity(new_identity_form(self)));
            }
            Action::Quit => self.quit = true,
        }
    }

    /// Every palette entry.
    pub(crate) fn actions() -> Vec<(String, Action)> {
        let mut out: Vec<(String, Action)> = Screen::ALL
            .iter()
            .map(|s| (format!("Go to {}", s.title()), Action::Go(*s)))
            .collect();
        out.push(("Encrypt a file".into(), Action::Go(Screen::Encrypt)));
        out.push(("Decrypt a file".into(), Action::Go(Screen::Decrypt)));
        out.push((
            "Scan for quantum-vulnerable cryptography".into(),
            Action::Go(Screen::Scan),
        ));
        out.push(("Create an identity".into(), Action::NewIdentity));
        out.push((
            "Open the pSIONIUM> prompt".into(),
            Action::Go(Screen::Console),
        ));
        out.push(("Take the tutorial".into(), Action::Tutorial));
        for name in theme::THEMES {
            out.push((format!("Theme: {name}"), Action::Theme(name)));
        }
        out.push((
            "Turn the launch animation on or off".into(),
            Action::ToggleAnimation,
        ));
        out.push(("Quit".into(), Action::Quit));
        out
    }

    /// Palette entries matching the query, best first.
    pub(crate) fn palette_matches(query: &str) -> Vec<(String, Action)> {
        let mut scored: Vec<(i64, String, Action)> = App::actions()
            .into_iter()
            .filter_map(|(label, a)| fuzzy(query, &label).map(|s| (s, label, a)))
            .collect();
        scored.sort_by_key(|a| std::cmp::Reverse(a.0));
        scored.into_iter().map(|(_, l, a)| (l, a)).collect()
    }

    /// Collects finished background work.
    pub(crate) fn update(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        if self
            .toast
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() > TOAST_TIME)
        {
            self.toast = None;
        }
        while let Ok(event) = self.rx.try_recv() {
            self.busy = self.busy.saturating_sub(1);
            match event {
                Event::Command(done) => self.finished(done),
                Event::Scan(result) => screens::scan_finished(self, result),
            }
        }
    }

    fn finished(&mut self, done: Finished) {
        if self.crypto_running == Some(done.origin) {
            self.crypto_running = None;
        }
        match done.origin {
            Origin::Console => self.console.finish(done),
            Origin::Encrypt => {
                if done.success {
                    self.notify("Encrypted", Tone::Ok);
                }
                self.encrypt_result = Some(done);
            }
            Origin::Decrypt | Origin::Inspect => {
                if done.success && done.origin == Origin::Decrypt {
                    self.notify("Decrypted", Tone::Ok);
                }
                self.decrypt_result = Some(done);
            }
            Origin::Keygen => screens::keygen_finished(self, done),
            Origin::Tutorial(step) => screens::tutorial_finished(self, step, done),
        }
    }

    /// Runs `psion args…` in the background.
    pub(crate) fn spawn(
        &mut self,
        origin: Origin,
        cwd: &Path,
        args: Vec<String>,
        stdin: Option<zeroize::Zeroizing<String>>,
        shown: Option<String>,
    ) -> bool {
        let Some(runner) = self.runner.clone() else {
            self.notify("cannot run commands here", Tone::Error);
            return false;
        };
        self.busy += 1;
        let home = self.env.home.clone();
        let args = args
            .into_iter()
            .map(|a| expand_arg(a, home.as_deref()))
            .collect();
        runner.psion(origin, cwd, args, stdin, shown);
        true
    }

    /// Handles a pasted string.
    pub(crate) fn on_paste(&mut self, text: &str) {
        if let Some(Popup::NewIdentity(form)) = &mut self.popup {
            form.paste(text);
            return;
        }
        if let Some(p) = &mut self.palette {
            p.query.push_str(text.lines().next().unwrap_or(""));
            return;
        }
        if self.focus != Focus::Screen {
            return;
        }
        match self.screen {
            Screen::Encrypt => self.encrypt.paste(text),
            Screen::Decrypt => self.decrypt.paste(text),
            Screen::Scan => self.scan.form.paste(text),
            Screen::Console => self.console.paste(text),
            _ => {}
        }
    }

    /// Handles a key press.
    pub(crate) fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')) {
            self.quit = true;
            return;
        }
        if self.popup.is_some() {
            screens::popup_key(self, key);
            return;
        }
        if self.palette.is_some() {
            self.palette_key(key);
            return;
        }
        if ctrl && key.code == KeyCode::Char('k') {
            self.palette = Some(Palette {
                query: String::new(),
                selected: 0,
            });
            return;
        }
        if key.code == KeyCode::F(1) {
            self.go(Screen::Help);
            return;
        }
        if self.focus == Focus::Screen {
            if screens::screen_key(self, key) {
                return;
            }
            if key.code == KeyCode::Esc {
                self.focus = Focus::Nav;
                return;
            }
        } else {
            match key.code {
                KeyCode::Up => {
                    let i = self.screen.index();
                    self.screen = Screen::ALL[(i + Screen::ALL.len() - 1) % Screen::ALL.len()];
                    return;
                }
                KeyCode::Down => {
                    let i = self.screen.index();
                    self.screen = Screen::ALL[(i + 1) % Screen::ALL.len()];
                    return;
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Tab => {
                    self.go(self.screen);
                    return;
                }
                KeyCode::Esc => {
                    self.notify("Press Ctrl+Q to quit", Tone::Info);
                    return;
                }
                _ => {}
            }
        }
        if self.typing() {
            return;
        }
        self.global_key(key);
    }

    /// Whether a text field has the keyboard, so letters are text, not shortcuts.
    pub(crate) fn typing(&self) -> bool {
        if self.focus != Focus::Screen {
            return false;
        }
        match self.screen {
            Screen::Encrypt => self.encrypt.typing(),
            Screen::Decrypt => self.decrypt.typing(),
            Screen::Scan => self.scan.typing(),
            Screen::Console => true,
            _ => false,
        }
    }

    fn global_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c @ '1'..='8') => {
                let i = c as usize - '1' as usize;
                self.go(Screen::ALL[i]);
            }
            KeyCode::Char('/') => {
                self.palette = Some(Palette {
                    query: String::new(),
                    selected: 0,
                })
            }
            KeyCode::Char(':') => self.go(Screen::Console),
            KeyCode::Char('?') => self.go(Screen::Help),
            KeyCode::Char('e') => self.go(Screen::Encrypt),
            KeyCode::Char('d') => self.go(Screen::Decrypt),
            KeyCode::Char('q') => self.go(Screen::Scan),
            KeyCode::Char('k') if self.screen == Screen::Home => self.go(Screen::Keys),
            KeyCode::Char('t') => self.run(Action::Tutorial),
            KeyCode::Char('s' | 'i') => self.notify(
                "Sending and the inbox need pSIONIUM accounts, which are not available yet",
                Tone::Info,
            ),
            _ => {}
        }
    }

    fn palette_key(&mut self, key: KeyEvent) {
        let Some(p) = &mut self.palette else { return };
        let matches = App::palette_matches(&p.query);
        match key.code {
            KeyCode::Esc => self.palette = None,
            KeyCode::Up => p.selected = p.selected.saturating_sub(1),
            KeyCode::Down => p.selected = (p.selected + 1).min(matches.len().saturating_sub(1)),
            KeyCode::Backspace => {
                p.query.pop();
                p.selected = 0;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                p.query.push(c);
                p.selected = 0;
            }
            KeyCode::Enter => {
                let chosen = matches.get(p.selected).map(|(_, a)| a.clone());
                self.palette = None;
                if let Some(a) = chosen {
                    self.run(a);
                }
            }
            _ => {}
        }
    }
}

/// Expands `~` at the start of an argument (or after `=` in `--flag=~/…`), as a shell would.
pub(crate) fn expand_arg(arg: String, home: Option<&Path>) -> String {
    let Some(home) = home else { return arg };
    let (flag, value) = match arg.split_once('=') {
        Some((f, v)) if f.starts_with("--") => (format!("{f}="), v.to_string()),
        _ => (String::new(), arg.clone()),
    };
    if value == "~" || value.starts_with("~/") || (cfg!(windows) && value.starts_with("~\\")) {
        format!("{flag}{}", config::expand(&value, Some(home)).display())
    } else {
        arg
    }
}

/// A fuzzy match score: every query character must appear in order (case-insensitive); runs
/// of adjacent characters and matches at word starts score higher. `None` if it does not match.
pub(crate) fn fuzzy(query: &str, text: &str) -> Option<i64> {
    let q: Vec<char> = query
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if q.is_empty() {
        return Some(0);
    }
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let mut score = 0i64;
    let mut qi = 0;
    let mut prev: Option<usize> = None;
    for (i, c) in t.iter().enumerate() {
        if qi < q.len() && *c == q[qi] {
            score += 1;
            if prev == Some(i.wrapping_sub(1)) {
                score += 5;
            }
            if i == 0 || !t[i - 1].is_alphanumeric() {
                score += 8;
            }
            prev = Some(i);
            qi += 1;
        }
    }
    (qi == q.len()).then_some(score - t.len() as i64 / 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_like_a_shell() {
        let ravi = Path::new("/home/ravi");
        let home = Some(ravi);
        // Path::join uses the platform's separator, as the shell does when it runs psion.
        assert_eq!(
            expand_arg("~/.psion/me.key".into(), home),
            ravi.join(".psion/me.key").display().to_string()
        );
        assert_eq!(
            expand_arg("--sign-with=~/k".into(), home),
            format!("--sign-with={}", ravi.join("k").display())
        );
        assert_eq!(expand_arg("a~/b".into(), home), "a~/b");
        assert_eq!(expand_arg("~ravi".into(), home), "~ravi");
    }

    #[test]
    fn fuzzy_matching() {
        assert!(fuzzy("enc", "Encrypt a file").is_some());
        assert!(fuzzy("xyz", "Encrypt a file").is_none());
        assert!(fuzzy("thc", "Theme: classic") > fuzzy("thc", "Take the tutorial: check"));
        assert_eq!(
            App::palette_matches("classic")[0].1,
            Action::Theme("classic")
        );
        assert_eq!(App::palette_matches("quit")[0].1, Action::Quit);
    }
}
