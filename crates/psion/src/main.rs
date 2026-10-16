//! `psion`: encrypt, sign and decrypt files with pSIONIUM's post-quantum `.psen` v2 format.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use psionium_core::{
    Decrypted, EncryptOptions, Identity, KdfParams, MAX_CHUNK_LOG2, MIN_CHUNK_LOG2, PublicKey,
    Suite, VerifyingKey, hex, is_protected,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "psion",
    version,
    about = "Post-quantum file encryption and signing (pSIONIUM .psen v2)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone, Default)]
struct PassphraseSource {
    /// Read the identity's passphrase from the first line of this file instead of prompting
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new identity: a decryption key, a signing key and their public keys
    Keygen {
        /// Write the identity to this file (created readable only by you); `-` for standard output
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Algorithm suite: pq-hybrid-768 (default) or cnsa-1024
        #[arg(long, default_value = "pq-hybrid-768")]
        suite: String,
        /// Store the secret keys without a passphrase (for automation; protect the file yourself)
        #[arg(long, conflicts_with = "passphrase_file")]
        no_passphrase: bool,
        #[command(flatten)]
        passphrase: PassphraseSource,
        /// Replace the output file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Print an identity's public key (or, with --verify-key, its signature verifying key)
    Pubkey {
        /// Identity file
        #[arg(short, long)]
        identity: PathBuf,
        /// Print the verifying key (psionvk:…) that others use to check your signatures
        #[arg(long)]
        verify_key: bool,
        #[command(flatten)]
        passphrase: PassphraseSource,
    },
    /// Encrypt a file to one or more recipients, optionally signing it
    Encrypt {
        /// Recipient public key (psionpk:…); repeat for several recipients
        #[arg(short = 'r', long = "recipient")]
        recipients: Vec<String>,
        /// File with one recipient public key per line; repeatable
        #[arg(short = 'R', long = "recipients-file")]
        recipient_files: Vec<PathBuf>,
        /// Sign the file with this identity's signing key so recipients can check who sent it
        #[arg(short = 's', long = "sign-with", value_name = "IDENTITY")]
        sign_with: Option<PathBuf>,
        #[command(flatten)]
        passphrase: PassphraseSource,
        /// Output file, `-` for standard output [default: INPUT.psen, or standard output when reading standard input]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Chunk size as a power of two, 12 (4 KiB) to 24 (16 MiB)
        #[arg(long, default_value_t = 16)]
        chunk_size_log2: u8,
        /// Replace the output file if it exists
        #[arg(long)]
        force: bool,
        /// File to encrypt, `-` for standard input [default: standard input]
        input: Option<PathBuf>,
    },
    /// Decrypt a .psen file, checking its signature if it has one
    Decrypt {
        /// Identity file
        #[arg(short, long)]
        identity: PathBuf,
        #[command(flatten)]
        passphrase: PassphraseSource,
        /// Require a valid signature from this verifying key (psionvk:…); repeatable
        #[arg(long = "signed-by", value_name = "VERIFY_KEY")]
        signed_by: Vec<String>,
        /// Require a valid signature from one of the verifying keys listed in this file
        #[arg(long = "signed-by-file", value_name = "FILE")]
        signed_by_files: Vec<PathBuf>,
        /// Output file, `-` for standard output [default: INPUT without .psen, or standard output when reading standard input]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Replace the output file if it exists
        #[arg(long)]
        force: bool,
        /// File to decrypt, `-` for standard input [default: standard input]
        input: Option<PathBuf>,
    },
    /// Show a .psen file's suite, recipients and signer without decrypting it
    Inspect {
        /// File to inspect
        input: PathBuf,
    },
    /// Add, change or remove the passphrase on an identity file
    Passphrase {
        /// Identity file to update in place
        #[arg(short, long)]
        identity: PathBuf,
        #[command(flatten)]
        current: PassphraseSource,
        /// Read the new passphrase from the first line of this file instead of prompting
        #[arg(long, value_name = "FILE", conflicts_with = "remove")]
        new_passphrase_file: Option<PathBuf>,
        /// Remove the passphrase and store the secret keys unprotected
        #[arg(long)]
        remove: bool,
    },
    /// Find quantum-vulnerable cryptography in code, dependencies, certificates, keys and TLS endpoints
    Scan {
        /// Files or folders to scan [default: the current folder, unless only --tls is given]
        paths: Vec<PathBuf>,
        /// Also probe this TLS endpoint (host[:port], default port 443); repeatable
        #[arg(long = "tls", value_name = "HOST[:PORT]")]
        tls: Vec<String>,
        /// Report format: text, markdown, json or cbom (CycloneDX 1.6)
        #[arg(long, default_value = "text")]
        format: String,
        /// Write the report to this file instead of standard output
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Also scan vendored and installed dependencies (node_modules, vendor, virtualenvs)
        #[arg(long)]
        include_dependencies: bool,
        /// Exit with status 2 when findings of this kind exist: quantum-vulnerable, weak or never
        #[arg(long, default_value = "never")]
        fail_on: String,
        /// Seconds to wait for each TLS connection
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

/// Exit status when `psion scan --fail-on` finds what it was told to fail on.
const SCAN_FINDINGS_EXIT: u8 = 2;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("psion: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    if let Command::Scan {
        paths,
        tls,
        format,
        output,
        include_dependencies,
        fail_on,
        timeout,
    } = cli.command
    {
        return scan(
            paths,
            &tls,
            &format,
            output,
            include_dependencies,
            &fail_on,
            timeout,
        );
    }
    run_file_command(cli.command).map(|()| ExitCode::SUCCESS)
}

fn run_file_command(command: Command) -> Result<()> {
    match command {
        Command::Keygen {
            output,
            suite,
            no_passphrase,
            passphrase,
            force,
        } => keygen(dash(output), &suite, no_passphrase, &passphrase, force),
        Command::Pubkey {
            identity,
            verify_key,
            passphrase,
        } => pubkey(&identity, verify_key, &passphrase),
        Command::Encrypt {
            recipients,
            recipient_files,
            sign_with,
            passphrase,
            output,
            chunk_size_log2,
            force,
            input,
        } => encrypt(
            &recipients,
            &recipient_files,
            sign_with,
            &passphrase,
            output,
            chunk_size_log2,
            force,
            dash(input),
        ),
        Command::Decrypt {
            identity,
            passphrase,
            signed_by,
            signed_by_files,
            output,
            force,
            input,
        } => decrypt(
            &identity,
            &passphrase,
            &signed_by,
            &signed_by_files,
            output,
            force,
            dash(input),
        ),
        Command::Inspect { input } => inspect(&input),
        Command::Passphrase {
            identity,
            current,
            new_passphrase_file,
            remove,
        } => change_passphrase(&identity, &current, new_passphrase_file, remove),
        Command::Scan { .. } => unreachable!("handled in run"),
    }
}

fn scan(
    mut paths: Vec<PathBuf>,
    tls: &[String],
    format: &str,
    output: Option<PathBuf>,
    include_dependencies: bool,
    fail_on: &str,
    timeout: u64,
) -> Result<ExitCode> {
    let threshold = match fail_on {
        "never" => None,
        "quantum-vulnerable" => Some(&[psionium_scan::Category::QuantumVulnerable][..]),
        "weak" => Some(
            &[
                psionium_scan::Category::QuantumVulnerable,
                psionium_scan::Category::Weak,
            ][..],
        ),
        other => bail!("unknown --fail-on \"{other}\" (use quantum-vulnerable, weak or never)"),
    };
    if !["text", "markdown", "json", "cbom"].contains(&format) {
        bail!("unknown --format \"{format}\" (use text, markdown, json or cbom)");
    }
    if paths.is_empty() && tls.is_empty() {
        paths.push(PathBuf::from("."));
    }
    let options = psionium_scan::ScanOptions {
        include_dependencies,
        ..psionium_scan::ScanOptions::default()
    };
    let mut report = if paths.is_empty() {
        psionium_scan::empty_report()
    } else {
        psionium_scan::scan_paths(&paths, &options).map_err(|e| anyhow!(e))?
    };
    psionium_scan::scan_tls(
        &mut report,
        tls,
        std::time::Duration::from_secs(timeout.max(1)),
    );
    let rendered = match format {
        "markdown" => report.to_markdown(),
        "json" => report.to_json(),
        "cbom" => report.to_cbom(),
        _ => report.to_text(),
    };
    match output {
        Some(path) => {
            write_atomically(&path, false, |w| Ok(w.write_all(rendered.as_bytes())?))?;
            eprintln!("Wrote the {format} report to {}", path.display());
        }
        None => print!("{rendered}"),
    }
    if let Some(categories) = threshold {
        let hits = report
            .findings
            .iter()
            .filter(|f| categories.contains(&f.category))
            .count();
        if hits > 0 {
            let noun = if hits == 1 { "finding" } else { "findings" };
            eprintln!("psion: {hits} {noun} matched --fail-on {fail_on}");
            return Ok(ExitCode::from(SCAN_FINDINGS_EXIT));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn keygen(
    output: Option<PathBuf>,
    suite: &str,
    no_passphrase: bool,
    source: &PassphraseSource,
    force: bool,
) -> Result<()> {
    let suite = Suite::from_name(suite)
        .ok_or_else(|| anyhow!("unknown suite \"{suite}\" (use pq-hybrid-768 or cnsa-1024)"))?;
    if let Some(path) = &output {
        refuse_existing(path, force)?;
    }
    let passphrase = if no_passphrase {
        None
    } else {
        Some(new_passphrase(source.passphrase_file.as_deref())?)
    };
    let identity = Identity::generate(suite).context("could not generate keys")?;
    let plain = identity.to_file_contents(&utc_now())?;
    let contents = match &passphrase {
        Some(p) => psionium_core::protect(&plain, p.as_bytes(), KdfParams::default())?,
        None => plain,
    };
    match output {
        Some(path) => {
            write_atomically(&path, true, |w| {
                w.write_all(contents.as_bytes())?;
                Ok(())
            })?;
            eprintln!(
                "Created identity {} ({suite}, {})",
                path.display(),
                if passphrase.is_some() {
                    "passphrase protected"
                } else {
                    "no passphrase"
                }
            );
            if let Some(vk) = identity.verifying_key() {
                eprintln!("Verify key (share it so others can check your signatures):\n{vk}");
            }
            eprintln!("Public key (share it so others can encrypt to you):");
            println!("{}", identity.public_key());
        }
        None => {
            io::stdout().write_all(contents.as_bytes())?;
            eprintln!("Public key: {}", identity.public_key());
        }
    }
    Ok(())
}

fn pubkey(path: &Path, verify_key: bool, source: &PassphraseSource) -> Result<()> {
    let contents = read_identity_file(path)?;
    // A protected identity lists its public keys in comments; reading them needs no passphrase.
    if is_protected(&contents) {
        let wanted = if verify_key {
            "# verify key: "
        } else {
            "# public key: "
        };
        let line = contents
            .lines()
            .find_map(|l| l.trim().strip_prefix(wanted))
            .ok_or_else(|| {
                anyhow!(
                    "{} does not list its public keys; decrypt it with `psion passphrase --remove`",
                    path.display()
                )
            })?;
        if verify_key {
            println!(
                "{}",
                line.parse::<VerifyingKey>()
                    .context("the listed verify key is malformed")?
            );
        } else {
            println!(
                "{}",
                line.parse::<PublicKey>()
                    .context("the listed public key is malformed")?
            );
        }
        return Ok(());
    }
    let identity = parse_identity(path, &contents, source)?;
    if verify_key {
        let vk = identity
            .verifying_key()
            .ok_or_else(|| anyhow!("{} has no signing key", path.display()))?;
        println!("{vk}");
    } else {
        println!("{}", identity.public_key());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encrypt(
    keys: &[String],
    files: &[PathBuf],
    sign_with: Option<PathBuf>,
    source: &PassphraseSource,
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
        for (n, line) in key_lines(file)? {
            recipients.push(
                line.parse::<PublicKey>()
                    .with_context(|| format!("{} line {n}", file.display()))?,
            );
        }
    }
    if recipients.is_empty() {
        bail!("no recipients: pass -r psionpk:… or -R FILE");
    }
    let signer = match &sign_with {
        Some(path) => Some(load_identity(path, source)?),
        None => None,
    };
    let signing_key = match &signer {
        Some(id) => Some(
            id.signing_key()
                .ok_or_else(|| anyhow!("this identity has no signing key"))?,
        ),
        None => None,
    };
    let options = EncryptOptions { chunk_log2 };
    let seal = |reader: Box<dyn Read>, w: &mut dyn Write| -> Result<u64> {
        Ok(match signing_key {
            Some(key) => psionium_core::encrypt_signed(&recipients, key, reader, w, &options)?,
            None => psionium_core::encrypt(&recipients, reader, w, &options)?,
        })
    };
    let output = match output {
        Some(o) if is_dash(&o) => None,
        Some(o) => Some(o),
        None => input.as_ref().map(|p| append_extension(p, "psen")),
    };
    let reader = open_input(input.as_deref())?;
    match output {
        Some(path) => {
            refuse_existing(&path, force)?;
            write_atomically(&path, false, |w| seal(reader, w).map(drop))?;
            eprintln!(
                "Encrypted for {} {}{}: {}",
                recipients.len(),
                if recipients.len() == 1 {
                    "recipient"
                } else {
                    "recipients"
                },
                if signing_key.is_some() {
                    ", signed"
                } else {
                    ""
                },
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
            let mut w = BufWriter::new(stdout.lock());
            seal(reader, &mut w)?;
            w.flush()?;
        }
    }
    Ok(())
}

fn decrypt(
    identity: &Path,
    source: &PassphraseSource,
    signed_by: &[String],
    signed_by_files: &[PathBuf],
    output: Option<PathBuf>,
    force: bool,
    input: Option<PathBuf>,
) -> Result<()> {
    let mut expected = Vec::new();
    for key in signed_by {
        expected.push(
            key.parse::<VerifyingKey>()
                .with_context(|| format!("--signed-by \"{}\"", shorten(key)))?,
        );
    }
    for file in signed_by_files {
        for (n, line) in key_lines(file)? {
            expected.push(
                line.parse::<VerifyingKey>()
                    .with_context(|| format!("{} line {n}", file.display()))?,
            );
        }
    }
    let identity = load_identity(identity, source)?;
    let output = match (output, &input) {
        (Some(o), _) if is_dash(&o) => None,
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
    let result = match output {
        Some(path) => {
            refuse_existing(&path, force)?;
            let mut outcome = None;
            // Plaintext reaches its final name only after the whole file and its signature check out.
            write_atomically(&path, true, |w| {
                let d = psionium_core::decrypt(&identity, reader, w)?;
                check_signer(&d, &expected)?;
                outcome = Some(d);
                Ok(())
            })?;
            eprintln!("Decrypted {}", path.display());
            outcome.expect("set on success")
        }
        None => {
            let mut w = BufWriter::new(io::stdout().lock());
            let d = psionium_core::decrypt(&identity, reader, &mut w)?;
            w.flush()?;
            check_signer(&d, &expected)?;
            d
        }
    };
    match (&result.signer, expected.is_empty()) {
        (Some(s), true) => eprintln!(
            "Signature: valid, from verify key {} (use --signed-by to require a specific sender)",
            hex(&s.key_id())
        ),
        (Some(s), false) => eprintln!(
            "Signature: valid, from expected sender {}",
            hex(&s.key_id())
        ),
        (None, _) => eprintln!("Signature: none (the sender is not authenticated)"),
    }
    Ok(())
}

fn check_signer(d: &Decrypted, expected: &[VerifyingKey]) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    match &d.signer {
        None => bail!("the file is not signed, but --signed-by requires a signature"),
        Some(s) if expected.contains(s) => Ok(()),
        Some(s) => bail!(
            "the file is signed by {}, which is not one of the expected senders",
            hex(&s.key_id())
        ),
    }
}

fn inspect(input: &Path) -> Result<()> {
    let file = File::open(input).with_context(|| format!("could not open {}", input.display()))?;
    let size = file.metadata()?.len();
    let info = psionium_core::inspect(BufReader::new(file))?;
    let block = info.chunk_size as u64 + 16;
    let signature = if info.signer.is_some() {
        signature_len(info.suite)
    } else {
        0
    };
    let payload = size.saturating_sub(info.header_len as u64 + signature);
    let chunks = payload.div_ceil(block).max(1);
    println!("format:      .psen v2");
    println!("suite:       {} ({})", info.suite, info.suite.description());
    println!("chunk size:  {} bytes", info.chunk_size);
    println!("header:      {} bytes", info.header_len);
    println!(
        "plaintext:   about {} bytes",
        payload.saturating_sub(chunks * 16)
    );
    match &info.signer {
        Some(vk) => println!(
            "signed:      yes, by verify key {} (not checked; decrypt to check)",
            hex(&vk.key_id())
        ),
        None => println!("signed:      no"),
    }
    println!("recipients:  {}", info.recipients.len());
    for id in &info.recipients {
        println!("  {}", hex(id));
    }
    Ok(())
}

fn change_passphrase(
    path: &Path,
    current: &PassphraseSource,
    new_file: Option<PathBuf>,
    remove: bool,
) -> Result<()> {
    let contents = read_identity_file(path)?;
    let plain = if is_protected(&contents) {
        let pass = existing_passphrase(path, current.passphrase_file.as_deref())?;
        psionium_core::unprotect(&contents, pass.as_bytes())
            .with_context(|| format!("could not unlock {}", path.display()))?
    } else {
        Zeroizing::new(contents.to_string())
    };
    Identity::from_file_contents(&plain)
        .with_context(|| format!("{} is not a valid identity", path.display()))?;
    let updated = if remove {
        plain
    } else {
        let pass = new_passphrase(new_file.as_deref())?;
        psionium_core::protect(&plain, pass.as_bytes(), KdfParams::default())?
    };
    write_atomically(path, true, |w| {
        w.write_all(updated.as_bytes())?;
        Ok(())
    })?;
    eprintln!(
        "{} {}",
        if remove {
            "Removed the passphrase from"
        } else {
            "Set a new passphrase on"
        },
        path.display()
    );
    Ok(())
}

fn read_identity_file(path: &Path) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(fs::read_to_string(path).with_context(
        || format!("could not read identity {}", path.display()),
    )?))
}

fn load_identity(path: &Path, source: &PassphraseSource) -> Result<Identity> {
    let contents = read_identity_file(path)?;
    parse_identity(path, &contents, source)
}

fn parse_identity(path: &Path, contents: &str, source: &PassphraseSource) -> Result<Identity> {
    let plain = if is_protected(contents) {
        let pass = existing_passphrase(path, source.passphrase_file.as_deref())?;
        psionium_core::unprotect(contents, pass.as_bytes())
            .with_context(|| format!("could not unlock {}", path.display()))?
    } else {
        Zeroizing::new(contents.to_string())
    };
    Identity::from_file_contents(&plain)
        .with_context(|| format!("{} is not a valid identity", path.display()))
}

fn existing_passphrase(identity: &Path, file: Option<&Path>) -> Result<Zeroizing<String>> {
    match file {
        Some(f) => read_passphrase_file(f),
        None => prompt(&format!("Passphrase for {}: ", identity.display())),
    }
}

fn new_passphrase(file: Option<&Path>) -> Result<Zeroizing<String>> {
    let pass = match file {
        Some(f) => read_passphrase_file(f)?,
        None => {
            let first = prompt("New passphrase (at least 8 characters): ")?;
            let second = prompt("Repeat the passphrase: ")?;
            if *first != *second {
                bail!("the passphrases do not match");
            }
            first
        }
    };
    if pass.chars().count() < psionium_core::MIN_PASSPHRASE_LEN {
        bail!(
            "the passphrase must be at least {} characters",
            psionium_core::MIN_PASSPHRASE_LEN
        );
    }
    Ok(pass)
}

fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?,
    );
    let line = text.lines().next().unwrap_or("");
    Ok(Zeroizing::new(line.to_string()))
}

const NO_TERMINAL: &str = "cannot ask for a passphrase without a terminal; use --passphrase-file (or --no-passphrase for keygen)";

fn prompt(message: &str) -> Result<Zeroizing<String>> {
    // On Windows the prompt reads the console even when nobody is at it (a service or CI job),
    // and would wait forever; ask only when a person can answer.
    if cfg!(windows) && !io::stdin().is_terminal() && !io::stderr().is_terminal() {
        bail!(NO_TERMINAL);
    }
    rpassword::prompt_password(message)
        .map(Zeroizing::new)
        .map_err(|_| anyhow!(NO_TERMINAL))
}

/// Non-empty, non-comment lines of a key list file, with line numbers.
fn key_lines(file: &Path) -> Result<Vec<(usize, String)>> {
    let text =
        fs::read_to_string(file).with_context(|| format!("could not read {}", file.display()))?;
    Ok(text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim().to_string()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

fn signature_len(suite: Suite) -> u64 {
    match suite {
        Suite::PqHybrid768 => 3309,
        Suite::Cnsa1024 => 4627,
    }
}

/// `-` as a file name means standard input or output, as in most command-line tools.
fn is_dash(path: &Path) -> bool {
    path.as_os_str() == "-"
}

/// `None` for `-`, so the caller falls back to standard input or output.
fn dash(path: Option<PathBuf>) -> Option<PathBuf> {
    path.filter(|p| !is_dash(p))
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
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
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
    if key.chars().count() > 24 {
        format!("{}…", key.chars().take(24).collect::<String>())
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
