//! The window around the screens: header bar, screen list, bottom bar with key hints and the
//! equivalent `psion` command, toasts, and the command palette.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};

use super::app::{App, Focus, Screen, Tone};
use super::screens;

/// The smallest window the shell draws into.
pub(crate) const MIN_SIZE: (u16, u16) = (60, 16);

pub(crate) fn draw(f: &mut Frame, app: &App) {
    let t = &app.theme;
    let area = f.area();
    f.render_widget(Block::new().style(t.base()), area);
    if area.width < MIN_SIZE.0 || area.height < MIN_SIZE.1 {
        let msg = format!(
            "pSIONIUM needs a window of at least {}×{}; this one is {}×{}.",
            MIN_SIZE.0, MIN_SIZE.1, area.width, area.height
        );
        f.render_widget(
            Paragraph::new(msg)
                .style(t.base())
                .wrap(ratatui::widgets::Wrap { trim: true }),
            area,
        );
        return;
    }
    let [header, body, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(area);
    draw_header(f, header, app);
    let nav_w = if area.width >= 120 { 22 } else { 18 };
    let [nav, main] =
        Layout::horizontal([Constraint::Length(nav_w), Constraint::Min(0)]).areas(body);
    draw_nav(f, nav, app);

    let focused = app.focus == Focus::Screen;
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.border(focused))
        .title(Span::styled(
            format!(" {} ", app.screen.title()),
            t.accent(),
        ));
    let inner = block.inner(main).inner(ratatui::layout::Margin::new(1, 0));
    f.render_widget(block, main);
    screens::draw(f, inner, app);
    draw_bottom(f, bottom, app);
    screens::draw_popup(f, area, app);
    draw_palette(f, area, app);
    draw_toast(f, body, app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let sep = || Span::styled(" │ ", t.muted());
    let suite = app
        .keys
        .default_identity()
        .map(|i| i.suite.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pq-hybrid-768".into());
    let mut spans = vec![
        Span::styled(" ▲ ", t.accent2()),
        Span::styled("pSIONIUM", t.accent()),
        Span::styled(format!(" {}", app.env.version), t.muted()),
        sep(),
        Span::styled("local · not signed in", t.title()),
        sep(),
        Span::styled(suite, t.title()),
        sep(),
        Span::styled("offline", t.muted()),
    ];
    if app.busy > 0 {
        spans.push(sep());
        spans.push(Span::styled(
            format!("{} working", screens::spinner(app)),
            t.accent(),
        ));
    }
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let theme = format!("{} ", t.name);
    if used + theme.len() + 1 < area.width as usize {
        spans.push(Span::raw(
            " ".repeat(area.width as usize - used - theme.len()),
        ));
        spans.push(Span::styled(theme, t.muted()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(t.base()), area);
}

fn draw_nav(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let focused = app.focus == Focus::Nav;
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.border(focused));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let mut lines = Vec::new();
    for (i, s) in Screen::ALL.iter().enumerate() {
        let current = *s == app.screen;
        let marker = if current { "›" } else { " " };
        let style = if current && focused {
            t.selected()
        } else if current {
            t.accent()
        } else {
            t.title()
        };
        let width = inner.width as usize;
        let label = format!("{marker} {} {}", i + 1, s.title());
        lines.push(Line::from(Span::styled(format!("{label:<width$}"), style)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(" Send · Inbox", t.muted())));
    lines.push(Line::from(Span::styled(" need accounts", t.muted())));
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_bottom(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let [keys, equivalent] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    // Whole hints only: the ones that do not fit are left out, never cut.
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (k, what) in screens::hints(app) {
        let w = k.chars().count() + what.chars().count() + 3;
        if used + w > keys.width as usize {
            break;
        }
        used += w;
        spans.push(Span::styled(k, t.key()));
        spans.push(Span::styled(format!(" {what}  "), t.muted()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(t.base()), keys);
    let command = screens::equivalent(app);
    let width = equivalent.width as usize;
    let label = " Equivalent: ";
    let room = width.saturating_sub(label.len() + 1);
    let shown = if command.chars().count() > room {
        let cut: String = command.chars().take(room.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        command
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(label, t.muted()),
            Span::styled(shown, t.accent()),
        ]))
        .style(t.base()),
        equivalent,
    );
}

fn draw_toast(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let Some((text, tone, _)) = &app.toast else {
        return;
    };
    let (mark, style) = match tone {
        Tone::Ok => ("✓ ", t.ok()),
        Tone::Error => ("✗ ", t.danger()),
        Tone::Info => ("• ", t.accent()),
    };
    let max = area.width.saturating_sub(4).min(64) as usize;
    let mut text: String = text.chars().take(max.saturating_sub(6)).collect();
    if text.chars().count() < app.toast.as_ref().map_or(0, |(s, _, _)| s.chars().count()) {
        text.push('…');
    }
    let w = (text.chars().count() + 6) as u16;
    let rect = Rect::new(area.right().saturating_sub(w + 1), area.y + 1, w, 3);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(mark, style),
            Span::styled(text, t.title()),
        ]))
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(style)
                .style(t.base()),
        ),
        rect,
    );
}

fn draw_palette(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let Some(p) = &app.palette else { return };
    let matches = App::palette_matches(&p.query);
    let h = (matches.len().min(10) as u16 + 4).max(6);
    let rect = screens::centered(area, 60, h);
    let rect = Rect::new(
        rect.x,
        area.y + 3.min(area.height.saturating_sub(h)),
        rect.width,
        rect.height,
    );
    f.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.border(true))
        .style(t.base())
        .title(Span::styled(" Command palette ", t.accent()));
    let inner = block.inner(rect).inner(ratatui::layout::Margin::new(1, 0));
    f.render_widget(block, rect);
    let mut lines = vec![
        Line::from(vec![
            Span::styled("› ", t.accent()),
            Span::styled(p.query.clone(), t.title()),
            Span::styled("▏", t.accent()),
        ]),
        Line::raw(""),
    ];
    if matches.is_empty() {
        lines.push(Line::from(Span::styled("Nothing matches", t.muted())));
    }
    let first = p.selected.saturating_sub(9);
    for (i, (label, _)) in matches.iter().enumerate().skip(first).take(10) {
        let sel = i == p.selected;
        lines.push(Line::from(Span::styled(
            format!("{}{label}", if sel { "› " } else { "  " }),
            if sel { t.selected() } else { t.title() },
        )));
    }
    f.render_widget(Paragraph::new(lines), inner);
}
