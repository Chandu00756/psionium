//! The launch animation (at most 600 ms, skipped by any key): the PORTAL VII pyramid drawn in
//! block characters behind a scanline wipe, then the pSIONIUM wordmark in a violet-to-pink
//! gradient over a green shimmer.

use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{self, Event};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Widget};

use super::theme::{Depth, Theme};

pub(crate) const DURATION: Duration = Duration::from_millis(600);

/// The PORTAL VII pyramid.
pub(crate) const PYRAMID: [&str; 5] = [
    "      ▄      ",
    "     ▟█▙     ",
    "    ▟███▙    ",
    "   ▟█████▙   ",
    "  ▟███████▙  ",
];

/// "pSIONIUM" in half-block letters, three rows tall.
pub(crate) const WORDMARK: [&str; 3] = [
    "▄▄▄▄  ▄▀▀▀▀ ▀█▀ ▄▀▀▀▄ █▄  █ ▀█▀ █   █ █▄ ▄█",
    "█▄▄▄▀  ▀▀▀▄  █  █   █ █ ▀▄█  █  █   █ █ ▀ █",
    "█     ▄▄▄▄▀ ▄█▄ ▀▄▄▄▀ █   █ ▄█▄ ▀▄▄▄▀ █   █",
];

/// Plays the animation; returns early on any key.
pub(crate) fn play(terminal: &mut DefaultTerminal, theme: &Theme, depth: Depth) -> Result<()> {
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        let progress = (elapsed.as_secs_f32() / DURATION.as_secs_f32()).min(1.0);
        terminal.draw(|f| frame(f, theme, depth, progress))?;
        if progress >= 1.0 {
            // Hold the finished frame for a moment unless a key arrives.
            if event::poll(Duration::from_millis(120))? {
                let _ = event::read()?;
            }
            return Ok(());
        }
        if event::poll(Duration::from_millis(30))? && matches!(event::read()?, Event::Key(_)) {
            return Ok(());
        }
    }
}

/// One frame of the animation at `progress` (0 to 1).
pub(crate) fn frame(f: &mut Frame, theme: &Theme, depth: Depth, progress: f32) {
    let area = f.area();
    Block::new()
        .style(theme.base())
        .render(area, f.buffer_mut());
    let buf = f.buffer_mut();
    let height = PYRAMID.len() as u16 + 1 + WORDMARK.len() as u16 + 2;
    let top = area.y + area.height.saturating_sub(height) / 2;

    // Green shimmer: a sparse, deterministic field of characters that fades as the wordmark lands.
    let fade = 1.0 - ((progress - 0.5) * 2.0).clamp(0.0, 1.0);
    if fade > 0.0 && !theme.mono {
        let glyphs = ['0', '1', '·', ':', 'ψ', '░'];
        let tick = (progress * 20.0) as u32;
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                let h = hash(x as u32, y as u32, tick);
                if h % 23 == 0 {
                    let strength = (fade * 255.0) as u8;
                    buf[(x, y)]
                        .set_char(glyphs[(h / 23) as usize % glyphs.len()])
                        .set_style(Style::new().fg(theme.shimmer(strength, depth)).bg(theme.bg));
                }
            }
        }
    }

    // Pyramid, revealed top to bottom by a scanline.
    let reveal = (progress / 0.4).min(1.0);
    let rows = (reveal * PYRAMID.len() as f32).ceil() as usize;
    for (i, row) in PYRAMID.iter().enumerate().take(rows) {
        let style = if i + 1 == rows && reveal < 1.0 {
            theme.accent2()
        } else {
            theme.accent()
        };
        centered(buf, area, top + i as u16, row, |_| style.bg(theme.bg));
    }

    // Wordmark, wiped in left to right.
    let wipe = ((progress - 0.35) / 0.45).clamp(0.0, 1.0);
    let width = WORDMARK[0].chars().count();
    let shown = (wipe * width as f32).ceil() as usize;
    let wy = top + PYRAMID.len() as u16 + 1;
    for (i, row) in WORDMARK.iter().enumerate() {
        let visible: String = row
            .chars()
            .enumerate()
            .map(|(j, c)| if j < shown { c } else { ' ' })
            .collect();
        centered(buf, area, wy + i as u16, &visible, |j| {
            Style::new()
                .fg(theme.gradient(j, width, depth))
                .bg(theme.bg)
                .add_modifier(ratatui::style::Modifier::BOLD)
        });
    }
    if progress >= 0.8 {
        let tagline = "post-quantum protection for the data you keep";
        centered(buf, area, wy + WORDMARK.len() as u16 + 1, tagline, |_| {
            theme.muted().bg(theme.bg)
        });
    }
}

/// Writes `text` centred on row `y`, styling each column with `style(column)`.
fn centered(buf: &mut Buffer, area: Rect, y: u16, text: &str, style: impl Fn(usize) -> Style) {
    if y >= area.bottom() {
        return;
    }
    let width = text.chars().count() as u16;
    let x0 = area.x + area.width.saturating_sub(width) / 2;
    for (j, c) in text.chars().enumerate() {
        let x = x0 + j as u16;
        if x >= area.right() {
            break;
        }
        if c != ' ' {
            buf[(x, y)].set_char(c).set_style(style(j));
        }
    }
}

fn hash(x: u32, y: u32, t: u32) -> u32 {
    let mut h =
        x.wrapping_mul(374_761_393) ^ y.wrapping_mul(668_265_263) ^ t.wrapping_mul(2_246_822_519);
    h = (h ^ (h >> 13)).wrapping_mul(1_274_126_177);
    h ^ (h >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn the_wordmark_and_pyramid_are_drawn() {
        assert!(
            WORDMARK
                .iter()
                .all(|r| r.chars().count() == WORDMARK[0].chars().count())
        );
        let theme = Theme::new("portal", Depth::True, true);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|f| frame(f, &theme, Depth::True, 1.0))
            .unwrap();
        let text = terminal.backend().to_string();
        for row in PYRAMID.iter().chain(WORDMARK.iter()) {
            assert!(text.contains(row.trim()), "{row}");
        }
        assert!(text.contains("post-quantum protection"));
    }
}
