//! `psion`: encrypt and decrypt files with pSIONIUM's post-quantum `.psen` v2 format.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use psionium_core::{
    EncryptOptions, Identity, MAX_CHUNK_LOG2, MIN_CHUNK_LOG2, PublicKey, Suite, hex,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "psion",
    version,
    about = "Post-quantum file encryption (pSIONIUM .psen v2)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new identity (a secret key and its public key)
    Keygen {
        /// Write the identity to this file (created readable only by you)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Algorithm suite: pq-hybrid-768 (default) or cnsa-1024
        #[arg(long, default_value = "pq-hybrid-768")]
        suite: String,
        /// Replace the output file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Print the public key of an identity
    Pubkey {
        /// Identity file
        #[arg(short, long)]
        identity: PathBuf,
    },
    /// Encrypt a file to one or more recipients
    Encrypt {
        /// Recipient public key (psionpk:…); repeat for several recipients
        #[arg(short = 'r', long = "recipient")]
        recipients: Vec<String>,
        /// File with one recipient public key per line; repeatable
        #[arg(short = 'R', long = "recipients-file")]
        recipient_files: Vec<PathBuf>,
        /// Output file [default: INPUT.psen, or standard output when reading standard input]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Chunk size as a power of two, 12 (4 KiB) to 24 (16 MiB)
        #[arg(long, default_value_t = 16)]
        chunk_size_log2: u8,
        /// Replace the output file if it exists
        #[arg(long)]
        force: bool,
        /// File to encrypt [default: standard input]
        input: Option<PathBuf>,
    },
    /// Decrypt a .psen file
    Decrypt {
        /// Identity file
        #[arg(short, long)]
        identity: PathBuf,
        /// Output file [default: INPUT without .psen, or standard output when reading standard input]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Replace the output file if it exists
        #[arg(long)]
        force: bool,
        /// File to decrypt [default: standard input]
        input: Option<PathBuf>,
    },
    /// Show a .psen file's suite, chunk size and recipients without decrypting it
    Inspect {
        /// File to inspect
        input: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("psion: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen {
            output,
            suite,
            force,
        } => keygen(output, &suite, force),
        Command::Pubkey { identity } => {
            println!("{}", load_identity(&identity)?.public_key());
            Ok(())
        }
        Command::Encrypt {
            recipients,
            recipient_files,
            output,
            chunk_size_log2,
            force,
            input,
        } => encrypt(
            &recipients,
            &recipient_files,
            output,
            chunk_size_log2,
            force,
            input,
        ),
        Command::Decrypt {
            identity,
            output,
            force,
            input,
        } => decrypt(&identity, output, force, input),
        Command::Inspect { input } => inspect(&input),
    }
}

fn keygen(output: Option<PathBuf>, suite: &str, force: bool) -> Result<()> {
    let suite = Suite::from_name(suite)
        .ok_or_else(|| anyhow!("unknown suite \"{suite}\" (use pq-hybrid-768 or cnsa-1024)"))?;
    let identity = Identity::generate(suite).context("could not generate keys")?;
    let contents = identity.to_file_contents(&utc_now())?;
    match output {
        Some(path) => {
            refuse_existing(&path, force)?;
            write_atomically(&path, true, |w| {
                w.write_all(contents.as_bytes())?;
                Ok(contents.len() as u64)
            })?;
            eprintln!("Created identity {} ({suite})", path.display());
            println!("{}", identity.public_key());
        }
        None => {
            io::stdout().write_all(contents.as_bytes())?;
            eprintln!("Public key: {}", identity.public_key());
        }
    }
    Ok(())
}

fn encrypt(
    keys: &[String],
    files: &[PathBuf],
    output: Option<PathBuf>,
    chunk_log2: u8,
    force: bool,
    input: Option<PathBuf>,
) -> Result<()> {
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_log2) {
        bail!("--chunk-size-log2 must be between {MIN_CHUNK_LOG2} and {MAX_CHUNK_LOG2}");
    }
    let mut recipients = Vec::new();
    for key in keys {
        recipients.push(
            key.parse::<PublicKey>()
                .with_context(|| format!("recipient \"{}\"", shorten(key)))?,
        );
    }
    for file in files {
        let text = fs::read_to_string(file)
            .with_context(|| format!("could not read {}", file.display()))?;
        for (n, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            recipients.push(
                line.parse::<PublicKey>()
                    .with_context(|| format!("{} line {n}", file.display()))?,
            );
        }
    }
    if recipients.is_empty() {
        bail!("no recipients: pass -r psionpk:… or -R FILE");
    }
    let options = EncryptOptions { chunk_log2 };
    let output = output.or_else(|| input.as_ref().map(|p| append_extension(p, "psen")));
    let reader = open_input(input.as_deref())?;
    match output {
        Some(path) => {
            refuse_existing(&path, force)?;
            write_atomically(&path, false, |w| {
                Ok(psionium_core::encrypt(&recipients, reader, w, &options)?)
            })?;
            eprintln!(
                "Encrypted to {} recipient(s): {}",
                recipients.len(),
                path.display()
            );
        }
        None => {
            let stdout = io::stdout();
            if stdout.is_terminal() {
                bail!(
                    "refusing to write encrypted data to the terminal; use -o FILE or redirect the output"
                );
            }
            psionium_core::encrypt(&recipients, reader, BufWriter::new(stdout.lock()), &options)?;
        }
    }
    Ok(())
}

fn decrypt(
    identity: &Path,
    output: Option<PathBuf>,
    force: bool,
    input: Option<PathBuf>,
) -> Result<()> {
    let identity = load_identity(identity)?;
    let output = match (output, &input) {
        (Some(o), _) => Some(o),
        (None, Some(path)) => Some(strip_extension(path, "psen").ok_or_else(|| {
            anyhow!(
                "{} does not end in .psen; choose an output with -o",
                path.display()
            )
        })?),
        (None, None) => None,
    };
    let reader = open_input(input.as_deref())?;
    match output {
        Some(path) => {
            refuse_existing(&path, force)?;
            // Plaintext reaches its final name only after the last chunk authenticates.
            write_atomically(&path, true, |w| {
                Ok(psionium_core::decrypt(&identity, reader, w)?)
            })?;
            eprintln!("Decrypted {}", path.display());
        }
        None => {
            psionium_core::decrypt(&identity, reader, BufWriter::new(io::stdout().lock()))?;
        }
    }
    Ok(())
}

fn inspect(input: &Path) -> Result<()> {
    let file = File::open(input).with_context(|| format!("could not open {}", input.display()))?;
    let size = file.metadata()?.len();
    let info = psionium_core::inspect(BufReader::new(file))?;
    let block = info.chunk_size as u64 + 16;
    let payload = size.saturating_sub(info.header_len as u64);
    let chunks = payload.div_ceil(block).max(1);
    println!("format:      .psen v2");
    println!("suite:       {} ({})", info.suite, info.suite.description());
    println!("chunk size:  {} bytes", info.chunk_size);
    println!("header:      {} bytes", info.header_len);
    println!(
        "plaintext:   about {} bytes",
        payload.saturating_sub(chunks * 16)
    );
    println!("recipients:  {}", info.recipients.len());
    for id in &info.recipients {
        println!("  {}", hex(id));
    }
    Ok(())
}

fn load_identity(path: &Path) -> Result<Identity> {
    let contents = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("could not read identity {}", path.display()))?,
    );
    Identity::from_file_contents(&contents)
        .with_context(|| format!("{} is not a valid identity", path.display()))
}

fn open_input(path: Option<&Path>) -> Result<Box<dyn Read>> {
    Ok(match path {
        Some(p) => Box::new(BufReader::new(
            File::open(p).with_context(|| format!("could not open {}", p.display()))?,
        )),
        None => Box::new(io::stdin().lock()),
    })
}

fn refuse_existing(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; use --force to replace it",
            path.display()
        );
    }
    Ok(())
}

/// Writes to a temporary file next to `path` and renames it into place only if `write` succeeds.
fn write_atomically(
    path: &Path,
    private: bool,
    write: impl FnOnce(&mut BufWriter<&File>) -> Result<u64>,
) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".psion-")
        .tempfile_in(dir)
        .with_context(|| format!("could not write in {}", dir.display()))?;
    if private {
        restrict_permissions(tmp.as_file())?;
    }
    {
        let mut w = BufWriter::new(tmp.as_file());
        write(&mut w)?;
        w.flush()?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("could not create {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_: &File) -> Result<()> {
    Ok(())
}

fn append_extension(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

fn strip_extension(path: &Path, ext: &str) -> Option<PathBuf> {
    (path.extension()? == ext).then(|| path.with_extension(""))
}

fn shorten(key: &str) -> String {
    if key.len() > 24 {
        format!("{}…", &key[..24])
    } else {
        key.to_string()
    }
}

fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
