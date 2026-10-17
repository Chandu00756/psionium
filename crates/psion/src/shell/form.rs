//! A keyboard form: text, secret, path, toggle and choice fields, and buttons.
//!
//! `Tab`/`↓` and `Shift+Tab`/`↑` move between fields, typing edits the focused text field,
//! `→` at the end of a path accepts the suggested completion, `Space` or `←`/`→` change toggles
//! and choices, and `Enter` presses a button (or moves on from a field).

use std::path::Path;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use zeroize::Zeroizing;

use super::theme::Theme;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Text,
    Path,
    Secret,
    Toggle,
    Choice(&'static [&'static str]),
    Button,
}

pub(crate) struct Field {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    pub value: Zeroizing<String>,
    pub on: bool,
    pub choice: usize,
    pub placeholder: String,
    pub hidden: bool,
}

impl Field {
    pub(crate) fn new(id: &'static str, label: &'static str, kind: Kind) -> Field {
        Field {
            id,
            label,
            kind,
            value: Zeroizing::new(String::new()),
            on: false,
            choice: 0,
            placeholder: String::new(),
            hidden: false,
        }
    }

    pub(crate) fn value(mut self, v: impl Into<String>) -> Field {
        self.value = Zeroizing::new(v.into());
        self
    }

    pub(crate) fn placeholder(mut self, p: impl Into<String>) -> Field {
        self.placeholder = p.into();
        self
    }

    pub(crate) fn on(mut self, on: bool) -> Field {
        self.on = on;
        self
    }

    fn is_text(&self) -> bool {
        matches!(self.kind, Kind::Text | Kind::Path | Kind::Secret)
    }
}

/// What a key press did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Not a form key.
    Ignored,
    /// The form handled it.
    Handled,
    /// A button was pressed.
    Pressed(&'static str),
}

pub(crate) struct Form {
    pub fields: Vec<Field>,
    pub focus: usize,
}

impl Form {
    pub(crate) fn new(fields: Vec<Field>) -> Form {
        Form { fields, focus: 0 }
    }

    pub(crate) fn get(&self, id: &str) -> &Field {
        self.fields
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("no field {id}"))
    }

    pub(crate) fn get_mut(&mut self, id: &str) -> &mut Field {
        self.fields
            .iter_mut()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("no field {id}"))
    }

    /// The trimmed text of a field.
    pub(crate) fn text(&self, id: &str) -> String {
        self.get(id).value.trim().to_string()
    }

    /// Whether the focused field takes typed characters.
    pub(crate) fn typing(&self) -> bool {
        self.fields.get(self.focus).is_some_and(Field::is_text)
    }

    fn step(&mut self, forward: bool) {
        let n = self.fields.len();
        for _ in 0..n {
            self.focus = if forward {
                (self.focus + 1) % n
            } else {
                (self.focus + n - 1) % n
            };
            if !self.fields[self.focus].hidden {
                return;
            }
        }
    }

    /// Handles a key; `cwd` is used for path suggestions.
    pub(crate) fn on_key(&mut self, key: KeyEvent, cwd: &Path) -> Outcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let Some(field) = self.fields.get_mut(self.focus) else {
            return Outcome::Ignored;
        };
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.step(true),
            KeyCode::BackTab | KeyCode::Up => self.step(false),
            KeyCode::Enter if field.kind == Kind::Button => return Outcome::Pressed(field.id),
            KeyCode::Enter => self.step(true),
            KeyCode::Char('u') if ctrl && field.is_text() => {
                field.value = Zeroizing::new(String::new())
            }
            KeyCode::Char(c) if field.is_text() && !ctrl => field.value.push(c),
            KeyCode::Backspace if field.is_text() => {
                field.value.pop();
            }
            KeyCode::Right if field.kind == Kind::Path => {
                if let Some(rest) = suggestion(&field.value, cwd) {
                    field.value.push_str(&rest);
                }
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right if field.kind == Kind::Toggle => {
                field.on = !field.on
            }
            KeyCode::Char(' ') | KeyCode::Right if matches!(field.kind, Kind::Choice(_)) => {
                if let Kind::Choice(opts) = field.kind {
                    field.choice = (field.choice + 1) % opts.len();
                }
            }
            KeyCode::Left if matches!(field.kind, Kind::Choice(_)) => {
                if let Kind::Choice(opts) = field.kind {
                    field.choice = (field.choice + opts.len() - 1) % opts.len();
                }
            }
            KeyCode::Char(' ') if field.kind == Kind::Button => return Outcome::Pressed(field.id),
            _ => return Outcome::Ignored,
        }
        Outcome::Handled
    }

    /// Adds pasted text to the focused text field (first line only).
    pub(crate) fn paste(&mut self, text: &str) {
        if let Some(field) = self.fields.get_mut(self.focus).filter(|f| f.is_text()) {
            field
                .value
                .push_str(text.lines().next().unwrap_or("").trim_end());
        }
    }

    /// Draws the form; `focused` is false when the screen does not have the keyboard.
    pub(crate) fn draw(&self, f: &mut Frame, area: Rect, t: &Theme, focused: bool, cwd: &Path) {
        let label_w = self
            .fields
            .iter()
            .map(|f| f.label.chars().count())
            .max()
            .unwrap_or(0)
            + 2;
        let mut lines = Vec::new();
        let mut buttons: Vec<Span> = Vec::new();
        for (i, field) in self.fields.iter().enumerate() {
            if field.hidden {
                continue;
            }
            let active = focused && i == self.focus;
            let marker = if active { "› " } else { "  " };
            if field.kind == Kind::Button {
                let style = if active { t.selected() } else { t.accent() };
                buttons.push(Span::styled(format!(" [ {} ] ", field.label), style));
                buttons.push(Span::raw(" "));
                continue;
            }
            let mut spans = vec![
                Span::styled(marker, t.accent()),
                Span::styled(
                    format!("{:<label_w$}", field.label),
                    if active { t.title() } else { t.muted() },
                ),
            ];
            match &field.kind {
                Kind::Text | Kind::Path | Kind::Secret => {
                    let shown = if field.kind == Kind::Secret {
                        "•".repeat(field.value.chars().count())
                    } else {
                        field.value.to_string()
                    };
                    if shown.is_empty() && !active {
                        spans.push(Span::styled(field.placeholder.clone(), t.muted()));
                    } else {
                        spans.push(Span::styled(shown, t.title()));
                        if active {
                            if field.kind == Kind::Path
                                && let Some(rest) = suggestion(&field.value, cwd)
                            {
                                spans.push(Span::styled(rest, t.muted()));
                            }
                            spans.push(Span::styled("▏", t.accent()));
                            if field.value.is_empty() && !field.placeholder.is_empty() {
                                spans.push(Span::styled(field.placeholder.clone(), t.muted()));
                            }
                        }
                    }
                }
                Kind::Toggle => spans.push(Span::styled(
                    if field.on { "[x] yes" } else { "[ ] no" },
                    if field.on { t.ok() } else { t.muted() },
                )),
                Kind::Choice(opts) => {
                    for (j, o) in opts.iter().enumerate() {
                        let style = if j == field.choice {
                            t.selected()
                        } else {
                            t.muted()
                        };
                        spans.push(Span::styled(format!(" {o} "), style));
                        spans.push(Span::raw(" "));
                    }
                }
                Kind::Button => {}
            }
            lines.push(Line::from(spans));
        }
        if !buttons.is_empty() {
            lines.push(Line::raw(""));
            let mut row = vec![Span::raw(" ".repeat(label_w + 2))];
            row.extend(buttons);
            lines.push(Line::from(row));
        }
        f.render_widget(Paragraph::new(lines), area);
    }

    /// Rows the form needs.
    pub(crate) fn height(&self) -> u16 {
        let visible = self
            .fields
            .iter()
            .filter(|f| !f.hidden && f.kind != Kind::Button)
            .count();
        let buttons = self
            .fields
            .iter()
            .any(|f| f.kind == Kind::Button && !f.hidden);
        (visible + if buttons { 2 } else { 0 }) as u16
    }
}

/// The rest of the single path that `typed` can complete to, if there is exactly one.
fn suggestion(typed: &str, cwd: &Path) -> Option<String> {
    if typed.is_empty() {
        return None;
    }
    let candidates = super::complete::paths(typed, cwd);
    let prefix = super::complete::common_prefix(&candidates);
    (prefix.len() > typed.len() && prefix.starts_with(typed))
        .then(|| prefix[typed.len()..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: ratatui::crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn edits_fields_and_presses_buttons() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("quarterly.xlsx"), "x").unwrap();
        let mut form = Form::new(vec![
            Field::new("file", "File", Kind::Path),
            Field::new("pass", "Passphrase", Kind::Secret),
            Field::new("sign", "Sign", Kind::Toggle).on(true),
            Field::new("suite", "Suite", Kind::Choice(&["a", "b"])),
            Field::new("go", "Go", Kind::Button),
        ]);
        for c in "quar".chars() {
            form.on_key(key(KeyCode::Char(c)), dir.path());
        }
        form.on_key(key(KeyCode::Right), dir.path());
        assert_eq!(form.text("file"), "quarterly.xlsx");
        form.on_key(key(KeyCode::Tab), dir.path());
        form.paste("hunter22\nignored");
        assert_eq!(*form.get("pass").value, "hunter22");
        form.on_key(key(KeyCode::Enter), dir.path());
        form.on_key(key(KeyCode::Char(' ')), dir.path());
        assert!(!form.get("sign").on);
        form.on_key(key(KeyCode::Down), dir.path());
        form.on_key(key(KeyCode::Left), dir.path());
        assert_eq!(form.get("suite").choice, 1);
        form.on_key(key(KeyCode::Down), dir.path());
        assert_eq!(
            form.on_key(key(KeyCode::Enter), dir.path()),
            Outcome::Pressed("go")
        );
        form.on_key(key(KeyCode::Down), dir.path());
        assert_eq!(form.focus, 0);
    }
}
