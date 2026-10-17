//! Snapshot tests: every screen at 80×24 and 200×60, the overlays, and each theme's styles.
//! Text snapshots are the same in every theme (checked below), so themes are compared by the
//! styles they use. Update with `INSTA_UPDATE=always cargo test -p psion` and review the diff.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::style::Color;

use super::app::{App, Env, Focus, Popup, Screen};
use super::config::Config;
use super::screens::{self, Entry, new_identity_form};
use super::theme::{Depth, THEMES, Theme};
use super::ui;

const IDENTITY: &str =
    include_str!("../../../psionium-core/tests/vectors/hybrid.identity.protected");

const SIZES: [(u16, u16); 2] = [(80, 24), (200, 60)];

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
}

/// A home folder with one passphrase-protected identity at `~/.psion/me.key`.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    std::fs::create_dir_all(home.join(".psion")).unwrap();
    std::fs::write(home.join(".psion/me.key"), IDENTITY).unwrap();
    Fixture { _dir: dir, home }
}

fn app(fx: Option<&Fixture>, theme: &str, no_color: bool) -> App {
    let home = fx.map_or_else(|| PathBuf::from("/home/ravi"), |f| f.home.clone());
    let config = Config {
        theme: theme.into(),
        animation: false,
        identity: fx.map(|f| f.home.join(".psion/me.key")),
    };
    let env = Env {
        config_dir: None,
        keys_dir: fx.map(|f| f.home.join(".psion")),
        cwd: home.join("work"),
        home: Some(home),
        version: "test".into(),
        depth: Depth::True,
        no_color,
        exe: None,
    };
    App::new(env, config, Vec::new())
}

fn render(app: &App, (w, h): (u16, u16)) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal.draw(|f| ui::draw(f, app)).unwrap();
    terminal
}

fn text(app: &App, size: (u16, u16)) -> String {
    render(app, size).backend().to_string()
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    }
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent {
        modifiers: KeyModifiers::CONTROL,
        ..key(KeyCode::Char(c))
    }
}

fn open(app: &mut App, screen: Screen) {
    app.screen = screen;
    app.focus = Focus::Screen;
}

/// A scan report from a small project, with paths relative to it.
fn scanned(app: &mut App) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("auth.go"),
        "k, _ := rsa.GenerateKey(rand.Reader, 2048)\nh := md5.Sum(x)\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("tls.go"),
        "groups := []CurveID{X25519MLKEM768}\n",
    )
    .unwrap();
    let mut report =
        psionium_scan::scan_paths(&[dir.path()], &psionium_scan::ScanOptions::default()).unwrap();
    report.started = "2026-10-16T00:00:00Z".into();
    report.roots = vec![".".into()];
    screens::scan_finished(app, Ok(report));
    app.toast = None;
}

#[test]
fn every_screen_at_both_sizes() {
    let fx = fixture();
    for screen in Screen::ALL {
        for size in SIZES {
            let mut a = app(Some(&fx), "portal", false);
            open(&mut a, screen);
            insta::assert_snapshot!(
                format!("{}_{}x{}", screen.title().to_lowercase(), size.0, size.1),
                text(&a, size)
            );
        }
    }
}

#[test]
fn first_run_without_identities() {
    let mut a = app(None, "portal", false);
    insta::assert_snapshot!("home_first_run", text(&a, (80, 24)));
    open(&mut a, Screen::Keys);
    insta::assert_snapshot!("keys_first_run", text(&a, (80, 24)));
}

#[test]
fn overlays_and_results() {
    let fx = fixture();
    let mut a = app(Some(&fx), "portal", false);

    a.on_key(ctrl('k'));
    for c in "them".chars() {
        a.on_key(key(KeyCode::Char(c)));
    }
    insta::assert_snapshot!("palette", text(&a, (80, 24)));
    a.on_key(key(KeyCode::Esc));

    open(&mut a, Screen::Keys);
    a.popup = Some(Popup::NewIdentity(new_identity_form(&a)));
    insta::assert_snapshot!("new_identity", text(&a, (80, 24)));
    a.popup = None;

    open(&mut a, Screen::Scan);
    scanned(&mut a);
    insta::assert_snapshot!("scan_results", text(&a, (80, 24)));
    a.on_key(key(KeyCode::Char('x')));
    insta::assert_snapshot!("scan_export", text(&a, (80, 24)));
    a.popup = None;

    open(&mut a, Screen::Console);
    a.console.entries.push(Entry {
        command: "inspect report.psen".into(),
        output: "format:      .psen v2\nsuite:       pq-hybrid-768".into(),
        ok: Some(true),
    });
    a.console.entries.push(Entry {
        command: "scan --bogus".into(),
        output: "error: unexpected argument '--bogus' found".into(),
        ok: Some(false),
    });
    a.console.input = "enc".into();
    a.on_key(key(KeyCode::Tab));
    insta::assert_snapshot!("console", text(&a, (80, 24)));

    open(&mut a, Screen::Help);
    a.help.start();
    insta::assert_snapshot!("tutorial", text(&a, (80, 24)));
}

#[test]
fn the_window_can_be_too_small() {
    let a = app(None, "portal", false);
    let t = text(&a, (50, 12));
    assert!(t.contains("needs a window of at least 60×16"));
}

#[test]
fn themes_change_colours_not_layout() {
    let fx = fixture();
    let mut styles = BTreeMap::new();
    for name in THEMES.iter().copied().chain(["no-color"]) {
        let mono = name == "no-color";
        for screen in Screen::ALL {
            for size in SIZES {
                let mut reference = app(Some(&fx), "portal", false);
                let mut themed = app(Some(&fx), if mono { "portal" } else { name }, mono);
                open(&mut reference, screen);
                open(&mut themed, screen);
                // Only the header's theme name may differ.
                let body = |a: &App| {
                    text(a, size)
                        .replace(&format!("psion theme {}", a.theme.name), "psion theme X")
                        .lines()
                        .skip(1)
                        .map(|l| l.trim_end_matches([' ', '"']))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                if mono && screen == Screen::Settings {
                    // Settings says why there are no colours.
                    assert!(body(&themed).contains("NO_COLOR is set"));
                } else {
                    assert_eq!(
                        body(&themed),
                        body(&reference),
                        "{name} changes the text of {screen:?} at {size:?}"
                    );
                }
                let header = text(&themed, size).lines().next().unwrap_or("").to_string();
                if size.0 >= 100 {
                    assert!(
                        header.contains(if mono { "portal" } else { name }),
                        "{header}"
                    );
                }
            }
        }
        let mut a = app(Some(&fx), if mono { "portal" } else { name }, mono);
        open(&mut a, Screen::Settings);
        let terminal = render(&a, (80, 24));
        let buffer = terminal.backend().buffer();
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        for cell in buffer.content() {
            *used
                .entry(format!(
                    "fg {:?} bg {:?} {:?}",
                    cell.fg, cell.bg, cell.modifier
                ))
                .or_insert(0) += 1;
        }
        if mono {
            assert!(
                buffer
                    .content()
                    .iter()
                    .all(|c| c.fg == Color::Reset && c.bg == Color::Reset),
                "NO_COLOR draws without colours"
            );
        }
        let summary: Vec<String> = used
            .into_iter()
            .map(|(k, n)| format!("{n:>5}  {k}"))
            .collect();
        styles.insert(name, summary.join("\n"));
    }
    for (name, summary) in styles {
        insta::assert_snapshot!(format!("styles_{name}"), summary);
    }
    let classic = Theme::new("classic", Depth::True, false);
    assert_eq!(classic.bg, Color::Rgb(0, 0, 0));
    assert!(classic.bold_text);
}

#[test]
fn keys_move_between_screens_and_fields() {
    let fx = fixture();
    let mut a = app(Some(&fx), "portal", false);
    assert_eq!((a.screen, a.focus), (Screen::Home, Focus::Nav));
    a.on_key(key(KeyCode::Down));
    assert_eq!(a.screen, Screen::Encrypt);
    a.on_key(key(KeyCode::Enter));
    assert_eq!(a.focus, Focus::Screen);
    for c in "e/q".chars() {
        a.on_key(key(KeyCode::Char(c)));
    }
    assert_eq!(
        a.encrypt.text("file"),
        "e/q",
        "letters in a field are text, not shortcuts"
    );
    a.on_key(key(KeyCode::Esc));
    assert_eq!(a.focus, Focus::Nav);
    a.on_key(key(KeyCode::Char('5')));
    assert_eq!((a.screen, a.focus), (Screen::Scan, Focus::Screen));
    a.on_key(key(KeyCode::Esc));
    a.on_key(key(KeyCode::Char(':')));
    assert_eq!(a.screen, Screen::Console);
    a.on_key(key(KeyCode::Esc));
    a.on_key(key(KeyCode::Char('/')));
    assert!(a.palette.is_some());
    for c in "quit".chars() {
        a.on_key(key(KeyCode::Char(c)));
    }
    a.on_key(key(KeyCode::Enter));
    assert!(a.quit);

    let mut a = app(Some(&fx), "portal", false);
    a.on_key(key(KeyCode::Char('s')));
    assert!(
        a.toast
            .as_ref()
            .is_some_and(|(t, _, _)| t.contains("accounts"))
    );
    a.on_key(ctrl('q'));
    assert!(a.quit);
}

#[test]
fn identities_are_read_without_a_passphrase() {
    let fx = fixture();
    let a = app(Some(&fx), "portal", false);
    let me = a.keys.default_identity().expect("default identity");
    assert!(me.protected && me.error.is_none());
    assert_eq!(me.suite, "pq-hybrid-768");
    assert!(
        me.public
            .as_deref()
            .is_some_and(|p| p.starts_with("psionpk:"))
    );
    assert_eq!(me.fingerprint.as_deref().map(str::len), Some(39));
    assert_eq!(
        screens::equivalent(&a),
        "psion --help",
        "the home screen points to the scripting help"
    );
    let path = Path::new(&me.path);
    assert!(path.ends_with(".psion/me.key"));
}
