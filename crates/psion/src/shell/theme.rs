//! Shell themes: `portal` (default), `classic` (the original green-on-black pSIONIUM terminal),
//! `high-contrast` and `light`, adapted to the terminal's colour depth, or monochrome under
//! `NO_COLOR`. Nothing is shown by colour alone: markers and text carry the meaning too.

use ratatui::style::{Color, Modifier, Style};

/// The themes, in the order Settings cycles through them.
pub(crate) const THEMES: [&str; 4] = ["portal", "classic", "high-contrast", "light"];

/// How many colours the terminal shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Depth {
    True,
    Ansi256,
    Ansi16,
}

impl Depth {
    /// From `COLORTERM` and `TERM`.
    pub(crate) fn detect() -> Depth {
        let colorterm = std::env::var("COLORTERM").unwrap_or_default();
        if colorterm.contains("truecolor") || colorterm.contains("24bit") || cfg!(windows) {
            return Depth::True;
        }
        let term = std::env::var("TERM").unwrap_or_default();
        if term.contains("256") || std::env::var_os("TERM_PROGRAM").is_some() {
            Depth::Ansi256
        } else {
            Depth::Ansi16
        }
    }
}

/// Colours and styles for one theme.
#[derive(Clone, Debug)]
pub(crate) struct Theme {
    pub name: &'static str,
    pub mono: bool,
    pub bg: Color,
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    pub accent2: Color,
    pub ok: Color,
    pub warn: Color,
    pub danger: Color,
    pub border: Color,
    pub sel_bg: Color,
    pub sel_fg: Color,
    /// The classic theme draws all text bold, like the original terminal.
    pub bold_text: bool,
}

/// Whether `name` is a theme.
pub(crate) fn is_theme(name: &str) -> bool {
    THEMES.contains(&name)
}

impl Theme {
    /// A theme by name (unknown names give `portal`), for a colour depth, or monochrome.
    pub(crate) fn new(name: &str, depth: Depth, no_color: bool) -> Theme {
        let rgb = |r, g, b| adapt(Color::Rgb(r, g, b), depth);
        let mut t = match name {
            "classic" => Theme {
                name: "classic",
                mono: false,
                bg: rgb(0, 0, 0),
                fg: rgb(0, 230, 64),
                muted: rgb(0, 150, 45),
                accent: rgb(140, 255, 150),
                accent2: rgb(0, 255, 65),
                ok: rgb(140, 255, 150),
                warn: rgb(230, 230, 0),
                danger: rgb(255, 90, 90),
                border: rgb(0, 120, 35),
                sel_bg: rgb(0, 95, 28),
                sel_fg: rgb(210, 255, 210),
                bold_text: true,
            },
            "high-contrast" => Theme {
                name: "high-contrast",
                mono: false,
                bg: rgb(0, 0, 0),
                fg: rgb(255, 255, 255),
                muted: rgb(215, 215, 215),
                accent: rgb(255, 230, 0),
                accent2: rgb(0, 230, 255),
                ok: rgb(0, 255, 0),
                warn: rgb(255, 230, 0),
                danger: rgb(255, 100, 100),
                border: rgb(255, 255, 255),
                sel_bg: rgb(255, 230, 0),
                sel_fg: rgb(0, 0, 0),
                bold_text: false,
            },
            "light" => Theme {
                name: "light",
                mono: false,
                bg: rgb(250, 249, 247),
                fg: rgb(29, 27, 34),
                muted: rgb(88, 83, 97),
                accent: rgb(91, 33, 182),
                accent2: rgb(190, 24, 93),
                ok: rgb(21, 115, 55),
                warn: rgb(150, 90, 0),
                danger: rgb(180, 28, 28),
                border: rgb(200, 194, 210),
                sel_bg: rgb(233, 226, 252),
                sel_fg: rgb(29, 27, 34),
                bold_text: false,
            },
            _ => Theme {
                name: "portal",
                mono: false,
                bg: rgb(13, 11, 18),
                fg: rgb(236, 233, 241),
                muted: rgb(160, 152, 174),
                accent: rgb(167, 139, 250),
                accent2: rgb(244, 114, 182),
                ok: rgb(74, 222, 128),
                warn: rgb(251, 191, 36),
                danger: rgb(248, 113, 113),
                border: rgb(64, 56, 80),
                sel_bg: rgb(52, 40, 82),
                sel_fg: rgb(255, 255, 255),
                bold_text: false,
            },
        };
        if no_color {
            t.mono = true;
            for c in [
                &mut t.bg,
                &mut t.fg,
                &mut t.muted,
                &mut t.accent,
                &mut t.accent2,
                &mut t.ok,
                &mut t.warn,
                &mut t.danger,
                &mut t.border,
                &mut t.sel_bg,
                &mut t.sel_fg,
            ] {
                *c = Color::Reset;
            }
        }
        t
    }

    /// Normal text on the theme background.
    pub(crate) fn base(&self) -> Style {
        let s = Style::new().fg(self.fg).bg(self.bg);
        if self.bold_text {
            s.add_modifier(Modifier::BOLD)
        } else {
            s
        }
    }

    pub(crate) fn muted(&self) -> Style {
        Style::new().fg(self.muted)
    }

    pub(crate) fn accent(&self) -> Style {
        Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn accent2(&self) -> Style {
        Style::new().fg(self.accent2).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn title(&self) -> Style {
        Style::new().fg(self.fg).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn ok(&self) -> Style {
        Style::new().fg(self.ok).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn warn(&self) -> Style {
        Style::new().fg(self.warn).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn danger(&self) -> Style {
        Style::new().fg(self.danger).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn border(&self, focused: bool) -> Style {
        if focused {
            Style::new().fg(self.accent)
        } else {
            Style::new().fg(self.border)
        }
    }

    /// A selected row: reversed when there are no colours.
    pub(crate) fn selected(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::new()
                .fg(self.sel_fg)
                .bg(self.sel_bg)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// A key in a hint, such as `Enter`.
    pub(crate) fn key(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(self.accent2).add_modifier(Modifier::BOLD)
        }
    }

    /// The wordmark colour at position `i` of `n`: violet to pink in `portal`, the theme's
    /// accents elsewhere.
    pub(crate) fn gradient(&self, i: usize, n: usize, depth: Depth) -> Color {
        if self.mono {
            return Color::Reset;
        }
        if self.name != "portal" {
            return if i * 2 < n { self.accent } else { self.accent2 };
        }
        let t = if n <= 1 {
            0.0
        } else {
            i as f32 / (n - 1) as f32
        };
        let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
        adapt(
            Color::Rgb(lerp(139, 236), lerp(92, 72), lerp(246, 153)),
            depth,
        )
    }

    /// The green of the launch shimmer.
    pub(crate) fn shimmer(&self, strength: u8, depth: Depth) -> Color {
        if self.mono {
            return Color::Reset;
        }
        if self.name == "light" {
            return adapt(Color::Rgb(160, 210, 170), depth);
        }
        adapt(Color::Rgb(0, 60 + strength / 2, 20), depth)
    }
}

/// Maps a true colour to what the terminal can show.
pub(crate) fn adapt(c: Color, depth: Depth) -> Color {
    let Color::Rgb(r, g, b) = c else {
        return c;
    };
    match depth {
        Depth::True => c,
        Depth::Ansi256 => Color::Indexed(xterm256(r, g, b)),
        Depth::Ansi16 => ansi16(r, g, b),
    }
}

fn xterm256(r: u8, g: u8, b: u8) -> u8 {
    let level = |v: u8| -> u8 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            ((v as u16 - 35) / 40) as u8
        }
    };
    let (lr, lg, lb) = (level(r), level(g), level(b));
    let cube = 16 + 36 * lr + 6 * lg + lb;
    let value = |l: u8| if l == 0 { 0 } else { 55 + 40 * l as i32 };
    let cube_err = (value(lr) - r as i32).pow(2)
        + (value(lg) - g as i32).pow(2)
        + (value(lb) - b as i32).pow(2);
    let avg = (r as i32 + g as i32 + b as i32) / 3;
    let gray_step = if avg > 238 {
        23
    } else {
        ((avg - 3).max(0) / 10) as u8
    };
    let gv = 8 + 10 * gray_step as i32;
    let gray_err = (gv - r as i32).pow(2) + (gv - g as i32).pow(2) + (gv - b as i32).pow(2);
    if gray_err < cube_err {
        232 + gray_step
    } else {
        cube
    }
}

fn ansi16(r: u8, g: u8, b: u8) -> Color {
    const PALETTE: [(Color, (i32, i32, i32)); 16] = [
        (Color::Black, (0, 0, 0)),
        (Color::Red, (170, 0, 0)),
        (Color::Green, (0, 170, 0)),
        (Color::Yellow, (170, 85, 0)),
        (Color::Blue, (0, 0, 170)),
        (Color::Magenta, (170, 0, 170)),
        (Color::Cyan, (0, 170, 170)),
        (Color::Gray, (170, 170, 170)),
        (Color::DarkGray, (85, 85, 85)),
        (Color::LightRed, (255, 85, 85)),
        (Color::LightGreen, (85, 255, 85)),
        (Color::LightYellow, (255, 255, 85)),
        (Color::LightBlue, (85, 85, 255)),
        (Color::LightMagenta, (255, 85, 255)),
        (Color::LightCyan, (85, 255, 255)),
        (Color::White, (255, 255, 255)),
    ];
    let (r, g, b) = (r as i32, g as i32, b as i32);
    PALETTE
        .iter()
        .min_by_key(|(_, (pr, pg, pb))| (pr - r).pow(2) + (pg - g).pow(2) + (pb - b).pow(2))
        .map(|(c, _)| *c)
        .unwrap_or(Color::Reset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_adapt_to_the_terminal() {
        assert_eq!(xterm256(0, 0, 0), 16);
        assert_eq!(xterm256(255, 255, 255), 231);
        assert_eq!(xterm256(128, 128, 128), 244);
        assert_eq!(ansi16(0, 230, 64), Color::Green);
        assert_eq!(ansi16(250, 249, 247), Color::White);
        let classic = Theme::new("classic", Depth::Ansi16, false);
        assert_eq!(classic.bg, Color::Black);
        assert!(classic.bold_text);
        let mono = Theme::new("portal", Depth::True, true);
        assert!(mono.mono && mono.fg == Color::Reset && mono.accent == Color::Reset);
        assert_eq!(Theme::new("nonsense", Depth::True, false).name, "portal");
    }
}
