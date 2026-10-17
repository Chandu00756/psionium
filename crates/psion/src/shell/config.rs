//! Shell settings and prompt history, kept in the user's configuration folder:
//! `$PSION_CONFIG_DIR`, else `%APPDATA%\psion` on Windows, else `$XDG_CONFIG_HOME/psion`
//! or `~/.config/psion`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const HISTORY_LIMIT: usize = 500;

/// Saved shell settings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Config {
    /// portal, classic, high-contrast or light.
    pub theme: String,
    /// Play the launch animation.
    pub animation: bool,
    /// The identity the shell uses by default for signing and decrypting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            theme: "portal".into(),
            animation: true,
            identity: None,
        }
    }
}

/// Where settings and history live.
pub(crate) fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("PSION_CONFIG_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("psion"));
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir).join("psion"));
    }
    home_dir().map(|h| h.join(".config").join("psion"))
}

/// The user's home folder.
pub(crate) fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// Where identities are kept by convention (`~/.psion`).
pub(crate) fn keys_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".psion"))
}

/// Shows `~` for the home folder.
pub(crate) fn tilde(path: &Path, home: Option<&Path>) -> String {
    if let Some(rest) = home.and_then(|h| path.strip_prefix(h).ok()) {
        if rest.as_os_str().is_empty() {
            return "~".into();
        }
        return format!("~/{}", rest.display()).replace('\\', "/");
    }
    path.display().to_string()
}

/// Expands a leading `~/`.
pub(crate) fn expand(path: &str, home: Option<&Path>) -> PathBuf {
    match (path.strip_prefix("~/").or(path.strip_prefix("~\\")), home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ if path == "~" && home.is_some() => home.unwrap_or(Path::new("")).to_path_buf(),
        _ => PathBuf::from(path),
    }
}

impl Config {
    /// Loads the settings; a missing file gives the defaults.
    pub(crate) fn load_from(dir: Option<&Path>) -> Result<Config> {
        let Some(path) = dir.map(|d| d.join("config.toml")) else {
            return Ok(Config::default());
        };
        match fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text)
                .with_context(|| format!("{} is not valid; fix or delete it", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
        }
    }

    /// Saves the settings.
    pub(crate) fn save_to(&self, dir: Option<&Path>) -> Result<PathBuf> {
        let dir = dir.context("no configuration folder: set PSION_CONFIG_DIR or HOME")?;
        fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
        let path = dir.join("config.toml");
        let text = format!(
            "# pSIONIUM shell settings. Change them in the shell (Settings) or edit this file.\n{}",
            toml::to_string_pretty(self).expect("config serializes")
        );
        crate::write_atomically(&path, false, |w| Ok(w.write_all(text.as_bytes())?))?;
        Ok(path)
    }
}

/// Loads the prompt history, oldest first.
pub(crate) fn load_history(dir: Option<&Path>) -> Vec<String> {
    dir.and_then(|d| fs::read_to_string(d.join("history")).ok())
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Saves the most recent prompt history, readable only by the user.
pub(crate) fn save_history(dir: Option<&Path>, history: &[String]) -> Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    fs::create_dir_all(dir)?;
    let start = history.len().saturating_sub(HISTORY_LIMIT);
    let mut text = history[start..].join("\n");
    text.push('\n');
    crate::write_atomically(&dir.join("history"), true, |w| {
        Ok(w.write_all(text.as_bytes())?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Config::load_from(Some(dir.path())).unwrap(),
            Config::default()
        );
        let c = Config {
            theme: "classic".into(),
            animation: false,
            identity: Some(PathBuf::from("/keys/me.key")),
        };
        c.save_to(Some(dir.path())).unwrap();
        assert_eq!(Config::load_from(Some(dir.path())).unwrap(), c);
        fs::write(dir.path().join("config.toml"), "theme = 3\n").unwrap();
        assert!(Config::load_from(Some(dir.path())).is_err());

        save_history(
            Some(dir.path()),
            &["scan .".into(), "inspect a.psen".into()],
        )
        .unwrap();
        assert_eq!(
            load_history(Some(dir.path())),
            vec!["scan .", "inspect a.psen"]
        );
    }

    #[test]
    fn home_paths() {
        let home = Path::new("/home/ravi");
        assert_eq!(
            tilde(Path::new("/home/ravi/.psion/me.key"), Some(home)),
            "~/.psion/me.key"
        );
        assert_eq!(tilde(Path::new("/srv/x"), Some(home)), "/srv/x");
        assert_eq!(
            expand("~/.psion/me.key", Some(home)),
            home.join(".psion/me.key")
        );
        assert_eq!(expand("me.key", Some(home)), PathBuf::from("me.key"));
    }
}
