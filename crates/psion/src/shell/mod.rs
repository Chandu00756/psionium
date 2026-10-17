//! The interactive pSIONIUM shell (`design/05-interactive-cli.md`): `psion` with no command, or
//! `psion shell`. A full-screen terminal interface with screens for local work, a command
//! palette and the classic `pSIONIUM>` prompt; `--plain` gives the prompt line by line instead.
//! Every action has a scripting equivalent, shown in the bottom bar, and the shell runs the
//! same `psion` commands, so the two never disagree.

mod app;
mod complete;
mod config;
mod form;
mod jobs;
mod screens;
mod splash;
mod theme;
mod ui;

#[cfg(test)]
mod tests;

use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind,
};
use ratatui::crossterm::execute;

use crate::ShellArgs;
use app::{App, Env};
use config::Config;
use theme::{Depth, Theme};

/// Whether the shell can start: the full-screen shell needs a terminal; `--plain` works with
/// any input.
pub(crate) fn can_run(args: &ShellArgs) -> bool {
    args.plain || (io::stdin().is_terminal() && io::stdout().is_terminal())
}

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// `psion theme [NAME]`.
pub(crate) fn theme_command(name: Option<&str>) -> Result<()> {
    let dir = config::config_dir();
    let mut config = Config::load_from(dir.as_deref())?;
    match name {
        None => {
            println!("{}", config.theme);
            eprintln!("Themes: {}", theme::THEMES.join(", "));
        }
        Some(name) => {
            if !theme::is_theme(name) {
                bail!(
                    "unknown theme \"{name}\" (use {})",
                    theme::THEMES.join(", ")
                );
            }
            config.theme = name.to_string();
            let path = config.save_to(dir.as_deref())?;
            eprintln!("Theme set to {name} (saved in {})", path.display());
        }
    }
    Ok(())
}

/// Opens the shell.
pub(crate) fn run(args: ShellArgs) -> Result<()> {
    let config_dir = config::config_dir();
    let config = Config::load_from(config_dir.as_deref())?;
    let theme_name = args.theme.clone().unwrap_or_else(|| config.theme.clone());
    if !theme::is_theme(&theme_name) {
        bail!(
            "unknown theme \"{theme_name}\" (use {})",
            theme::THEMES.join(", ")
        );
    }
    if args.plain || std::env::var("TERM").is_ok_and(|t| t == "dumb") {
        return plain(config_dir.as_deref());
    }
    if !can_run(&args) {
        bail!("the shell needs a terminal; use psion <command>, or psion --plain");
    }
    let depth = Depth::detect();
    let env = Env {
        config_dir: config_dir.clone(),
        home: config::home_dir(),
        keys_dir: config::keys_dir(),
        cwd: std::env::current_dir().context("could not read the current folder")?,
        version: env!("CARGO_PKG_VERSION").to_string(),
        depth,
        no_color: no_color(),
        exe: std::env::current_exe().ok(),
    };
    let animate =
        config.animation && !args.no_animation && std::env::var_os("CI").is_none() && !env.no_color;
    let history = config::load_history(config_dir.as_deref());
    let mut app = App::new(env, config, history);
    app.theme = Theme::new(&theme_name, depth, app.env.no_color);

    let mut terminal = ratatui::try_init().context("could not start the full-screen shell")?;
    let _ = execute!(io::stdout(), EnableBracketedPaste);
    let result = (|| -> Result<()> {
        let size = terminal.size()?;
        if animate && size.width >= 50 && size.height >= 14 {
            splash::play(&mut terminal, &app.theme, depth)?;
        }
        event_loop(&mut terminal, &mut app)
    })();
    let _ = execute!(io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        app.update();
        terminal.draw(|f| ui::draw(f, app))?;
        if app.quit {
            return Ok(());
        }
        let wait = if app.busy > 0 || app.toast.is_some() {
            Duration::from_millis(80)
        } else {
            Duration::from_millis(500)
        };
        if event::poll(wait)? {
            match event::read()? {
                Event::Key(k) if k.kind != KeyEventKind::Release => app.on_key(k),
                Event::Paste(text) => app.on_paste(&text),
                _ => {}
            }
        }
    }
}

/// The line-by-line `pSIONIUM>` prompt. Commands run in this process, so passphrase prompts
/// work as they do in a terminal.
fn plain(config_dir: Option<&std::path::Path>) -> Result<()> {
    use clap::Parser;
    let color = !no_color() && io::stdout().is_terminal();
    let prompt = if color {
        "\x1b[1;32mpSIONIUM>\x1b[0m "
    } else {
        "pSIONIUM> "
    };
    let interactive = io::stdin().is_terminal();
    if interactive {
        println!(
            "pSIONIUM {} shell (plain). Type help for commands, exit to leave.",
            env!("CARGO_PKG_VERSION")
        );
    }
    let mut history = config::load_history(config_dir);
    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        if interactive {
            print!("{prompt}");
            io::stdout().flush()?;
        }
        line.clear();
        if stdin.lock().read_line(&mut line)? == 0 {
            if interactive {
                println!();
            }
            return Ok(());
        }
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if interactive && history.last().map(String::as_str) != Some(text) {
            history.push(text.to_string());
            let _ = config::save_history(config_dir, &history);
        }
        let mut args = match complete::split(text) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("psion: {e}");
                continue;
            }
        };
        if args.first().is_some_and(|a| a == "psion") {
            args.remove(0);
        }
        let home = config::home_dir();
        let args: Vec<String> = args
            .into_iter()
            .map(|a| app::expand_arg(a, home.as_deref()))
            .collect();
        match args.first().map(String::as_str) {
            None => continue,
            Some("exit" | "quit") => return Ok(()),
            Some("help") if args.len() == 1 => {
                println!("Commands (add --help to any of them):");
                for (name, about) in complete::commands() {
                    println!("  {name:<12} {about}");
                }
                println!("Shell commands: help, cd DIR, pwd, exit");
                continue;
            }
            Some("pwd") => {
                println!("{}", std::env::current_dir()?.display());
                continue;
            }
            Some("cd") => {
                let target = args
                    .get(1)
                    .map(|d| config::expand(d, config::home_dir().as_deref()))
                    .or_else(config::home_dir);
                if let Some(t) = target
                    && let Err(e) = std::env::set_current_dir(&t)
                {
                    eprintln!("cd: {}: {e}", t.display());
                }
                continue;
            }
            _ => {}
        }
        match crate::Cli::try_parse_from(std::iter::once("psion".to_string()).chain(args)) {
            Err(e) => {
                let _ = e.print();
            }
            Ok(cli) => match cli.command {
                None | Some(crate::Command::Shell(_)) => println!("You are already in the shell."),
                Some(command) => {
                    if let Err(e) = crate::run(command) {
                        eprintln!("psion: error: {e:#}");
                    }
                }
            },
        }
    }
}
