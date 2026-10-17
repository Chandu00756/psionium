//! Background work for the shell: `psion` commands run as child processes with captured output
//! (a passphrase, when needed, goes through a pipe, never a file or the environment), and scans
//! run on a thread with live progress. Results come back over a channel.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

/// Output kept from one command; more is cut.
const MAX_OUTPUT: usize = 256 * 1024;

/// Which part of the shell asked for the work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    Console,
    Encrypt,
    Decrypt,
    Inspect,
    Keygen,
    Tutorial(usize),
}

/// A finished command.
#[derive(Clone, Debug)]
pub(crate) struct Finished {
    pub origin: Origin,
    pub success: bool,
    /// What a person would type, without secrets.
    pub command_line: String,
    pub stdout: String,
    pub stderr: String,
}

/// Something background work reports.
pub(crate) enum Event {
    Command(Finished),
    Scan(Result<psionium_scan::Report, String>),
}

/// Starts background work.
#[derive(Clone)]
pub(crate) struct Runner {
    pub exe: PathBuf,
    pub tx: Sender<Event>,
}

/// A scan to run.
pub(crate) struct ScanJob {
    pub paths: Vec<PathBuf>,
    pub tls: Vec<String>,
    pub options: psionium_scan::ScanOptions,
}

impl Runner {
    /// Runs `psion args…` in `cwd`, feeding `stdin` (one line per passphrase) if given.
    pub(crate) fn psion(
        &self,
        origin: Origin,
        cwd: &Path,
        args: Vec<String>,
        stdin: Option<Zeroizing<String>>,
        shown: Option<String>,
    ) {
        let exe = self.exe.clone();
        let cwd = cwd.to_path_buf();
        let tx = self.tx.clone();
        let command_line = shown.unwrap_or_else(|| command_line(&args));
        thread::spawn(move || {
            let result = run(&exe, &cwd, &args, stdin);
            let finished = match result {
                Ok((success, stdout, stderr)) => Finished {
                    origin,
                    success,
                    command_line,
                    stdout,
                    stderr,
                },
                Err(e) => Finished {
                    origin,
                    success: false,
                    command_line,
                    stdout: String::new(),
                    stderr: format!("psion: error: could not run the command: {e}"),
                },
            };
            let _ = tx.send(Event::Command(finished));
        });
    }

    /// Scans on a thread; `progress` counts files as they are read.
    pub(crate) fn scan(&self, mut job: ScanJob, progress: Arc<AtomicUsize>) {
        let tx = self.tx.clone();
        job.options.progress = Some(progress);
        thread::spawn(move || {
            let result = if job.paths.is_empty() {
                Ok(psionium_scan::empty_report())
            } else {
                psionium_scan::scan_paths(&job.paths, &job.options)
            };
            let result = result.map(|mut report| {
                psionium_scan::scan_tls(&mut report, &job.tls, Duration::from_secs(10));
                report
            });
            let _ = tx.send(Event::Scan(result));
        });
    }
}

fn run(
    exe: &Path,
    cwd: &Path,
    args: &[String],
    stdin: Option<Zeroizing<String>>,
) -> std::io::Result<(bool, String, String)> {
    let mut child = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("PSION_NO_PROMPT", "1")
        .env("NO_COLOR", "1")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A command that fails early may close its end; the error shows in its output.
        let _ = pipe.write_all(text.as_bytes());
    }
    let out = child.wait_with_output()?;
    Ok((
        out.status.success(),
        printable(&out.stdout),
        printable(&out.stderr),
    ))
}

/// Output as text, or a note when it is binary.
fn printable(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.len() > MAX_OUTPUT => {
            let mut end = MAX_OUTPUT;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}\n… output cut at {} KiB", &s[..end], MAX_OUTPUT / 1024)
        }
        Ok(s) => s.to_string(),
        Err(_) => format!("({} bytes of binary output not shown)", bytes.len()),
    }
}

/// The arguments as a person would type them after `psion`, quoted where needed and with
/// long keys shortened.
pub(crate) fn command_line(args: &[String]) -> String {
    let mut out = String::from("psion");
    for a in args {
        out.push(' ');
        out.push_str(&display_arg(a));
    }
    out
}

fn display_arg(a: &str) -> String {
    let shown = if (a.starts_with("psionpk:") || a.starts_with("psionvk:")) && a.len() > 24 {
        format!("{}…", &a[..20])
    } else {
        a.to_string()
    };
    if shown.is_empty()
        || shown.contains(|c: char| c.is_whitespace() || "'\"\\$`|&;<>()*?".contains(c))
    {
        format!("'{}'", shown.replace('\'', r"'\''"))
    } else {
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_read_like_a_terminal() {
        let args: Vec<String> = [
            "encrypt",
            "-r",
            &format!("psionpk:{}", "A".repeat(60)),
            "my file.txt",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            command_line(&args),
            "psion encrypt -r psionpk:AAAAAAAAAAAA… 'my file.txt'"
        );
        assert_eq!(
            printable(&[0xff, 0x00]),
            "(2 bytes of binary output not shown)"
        );
    }
}
