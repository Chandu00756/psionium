//! The classic prompt's command-line handling: splitting a line into arguments, and tab
//! completion of commands, flags and paths. Commands and flags come from the scripting
//! command definitions, so completion always matches `psion --help`.

use std::path::Path;

use clap::CommandFactory;

/// Commands the shell handles itself.
pub(crate) const BUILTINS: &[(&str, &str)] = &[
    ("help", "list commands"),
    ("clear", "clear the console"),
    ("cd", "change the shell's folder"),
    ("pwd", "show the shell's folder"),
    ("history", "show recent commands"),
    ("exit", "leave the shell"),
];

/// Scripting commands and their one-line descriptions, without `shell`.
pub(crate) fn commands() -> Vec<(String, String)> {
    crate::Cli::command()
        .get_subcommands()
        .filter(|c| c.get_name() != "shell" && c.get_name() != "help")
        .map(|c| {
            (
                c.get_name().to_string(),
                c.get_about().map(|a| a.to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

/// Splits a command line into arguments: whitespace separates, single and double quotes group,
/// and outside single quotes a backslash escapes the next character (except on Windows, where
/// backslashes are path separators).
pub(crate) fn split(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') if !cfg!(windows) => match chars.next() {
                Some(n) => current.push(n),
                None => return Err("the line ends with a backslash".into()),
            },
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_arg = true;
            }
            (None, '\\') if !cfg!(windows) => match chars.next() {
                Some(n) => {
                    current.push(n);
                    in_arg = true;
                }
                None => return Err("the line ends with a backslash".into()),
            },
            (None, c) if c.is_whitespace() => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            (None, c) => {
                current.push(c);
                in_arg = true;
            }
        }
    }
    if let Some(q) = quote {
        return Err(format!("a {q} quote is not closed"));
    }
    if in_arg {
        args.push(current);
    }
    Ok(args)
}

/// Completions for the word before the cursor (the end of `line`): the byte offset where that
/// word starts and the candidates that replace it, sorted.
pub(crate) fn complete(line: &str, cwd: &Path) -> (usize, Vec<String>) {
    let start = line.rfind(|c: char| c.is_whitespace()).map_or(0, |i| i + 1);
    let word = &line[start..];
    let before: Vec<&str> = line[..start].split_whitespace().collect();
    let first = before.first().map(|w| w.trim_start_matches("psion"));
    let position = if before.first() == Some(&"psion") {
        before.len() - 1
    } else {
        before.len()
    };
    let mut out: Vec<String> = if position == 0 {
        commands()
            .into_iter()
            .map(|(name, _)| name)
            .chain(BUILTINS.iter().map(|(n, _)| n.to_string()))
            .filter(|n| n.starts_with(word))
            .collect()
    } else if word.starts_with('-') {
        let name = if before.first() == Some(&"psion") {
            before.get(1).copied()
        } else {
            first
        };
        flags(name.unwrap_or_default())
            .into_iter()
            .filter(|f| f.starts_with(word))
            .collect()
    } else {
        paths(word, cwd)
    };
    out.sort();
    out.dedup();
    (start, out)
}

/// The longest common prefix of the candidates.
pub(crate) fn common_prefix(candidates: &[String]) -> String {
    let Some(first) = candidates.first() else {
        return String::new();
    };
    let mut len = first.len();
    for c in &candidates[1..] {
        len = len.min(
            first
                .char_indices()
                .zip(c.chars())
                .take_while(|((_, a), b)| a == b)
                .last()
                .map_or(0, |((i, a), _)| i + a.len_utf8()),
        );
    }
    first[..len].to_string()
}

fn flags(command: &str) -> Vec<String> {
    let cli = crate::Cli::command();
    let Some(sub) = cli.find_subcommand(command) else {
        return Vec::new();
    };
    let mut out: Vec<String> = sub
        .get_arguments()
        .filter(|a| !a.is_positional() && !a.is_hide_set())
        .flat_map(|a| {
            let mut names: Vec<String> = a
                .get_long_and_visible_aliases()
                .unwrap_or_default()
                .into_iter()
                .map(|l| format!("--{l}"))
                .collect();
            if let Some(s) = a.get_short() {
                names.push(format!("-{s}"));
            }
            names
        })
        .collect();
    out.push("--help".into());
    out
}

/// Files and folders that start with `word`, relative to `cwd`; folders end with `/`.
pub(crate) fn paths(word: &str, cwd: &Path) -> Vec<String> {
    let (dir_part, name_part) = match word.rfind(['/', std::path::MAIN_SEPARATOR]) {
        Some(i) => (&word[..=i], &word[i + 1..]),
        None => ("", word),
    };
    let expanded = super::config::expand(dir_part, super::config::home_dir().as_deref());
    let dir = if dir_part.is_empty() {
        cwd.to_path_buf()
    } else if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(name_part)
                || (name.starts_with('.') && !name_part.starts_with('.'))
            {
                return None;
            }
            let slash = if e.file_type().is_ok_and(|t| t.is_dir()) {
                "/"
            } else {
                ""
            };
            Some(format!("{dir_part}{}{slash}", quote(&name)))
        })
        .collect()
}

/// Quotes a name with spaces or quotes for the prompt.
fn quote(name: &str) -> String {
    if name.contains([' ', '\'', '"', '\\']) && !cfg!(windows) {
        name.chars()
            .flat_map(|c| {
                if matches!(c, ' ' | '\'' | '"' | '\\') {
                    vec!['\\', c]
                } else {
                    vec![c]
                }
            })
            .collect()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_a_shell() {
        assert_eq!(
            split("scan  . --tls a.com").unwrap(),
            ["scan", ".", "--tls", "a.com"]
        );
        assert_eq!(
            split(r#"inspect "my file.psen""#).unwrap(),
            ["inspect", "my file.psen"]
        );
        assert_eq!(split("inspect 'it''s'").unwrap(), ["inspect", "its"]);
        assert_eq!(split("a ''").unwrap(), ["a", ""]);
        assert!(split("inspect \"open").is_err());
        if !cfg!(windows) {
            assert_eq!(split(r"inspect my\ file").unwrap(), ["inspect", "my file"]);
        }
    }

    #[test]
    fn completes_commands_flags_and_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("reports")).unwrap();
        std::fs::write(dir.path().join("report.txt"), "x").unwrap();
        std::fs::write(dir.path().join(".hidden"), "x").unwrap();
        let cwd = dir.path();

        assert_eq!(complete("enc", cwd), (0, vec!["encrypt".to_string()]));
        let (_, all) = complete("", cwd);
        assert!(all.contains(&"scan".to_string()) && all.contains(&"exit".to_string()));
        assert!(!all.contains(&"shell".to_string()));
        let (at, f) = complete("scan --fo", cwd);
        assert_eq!((at, f), (5, vec!["--format".to_string()]));
        assert!(
            complete("psion decrypt --sig", cwd)
                .1
                .contains(&"--signed-by".to_string())
        );
        assert_eq!(
            complete("inspect rep", cwd).1,
            vec!["report.txt".to_string(), "reports/".to_string()]
        );
        assert!(
            complete("inspect ", cwd)
                .1
                .iter()
                .all(|p| !p.starts_with('.'))
        );
        assert_eq!(
            common_prefix(&["report.txt".into(), "reports/".into()]),
            "report"
        );
    }
}
