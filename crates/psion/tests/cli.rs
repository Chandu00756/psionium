use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

fn psion() -> Command {
    Command::cargo_bin("psion").unwrap()
}

fn keygen(dir: &Path, name: &str, suite: &str) -> String {
    let out = psion()
        .args(["keygen", "--no-passphrase", "--suite", suite, "-o"])
        .arg(dir.join(name))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).unwrap().trim().to_string()
}

#[test]
fn encrypt_and_decrypt_files_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let alice = keygen(dir.path(), "alice.key", "pq-hybrid-768");
    let bob = keygen(dir.path(), "bob.key", "pq-hybrid-768");
    assert!(alice.starts_with("psionpk:"));

    let plain = dir.path().join("report.txt");
    fs::write(&plain, b"Q3 numbers: confidential").unwrap();
    psion()
        .args(["encrypt", "-r", &alice, "-r", &bob])
        .arg(&plain)
        .assert()
        .success();
    let sealed = dir.path().join("report.txt.psen");
    assert!(sealed.exists());

    fs::remove_file(&plain).unwrap();
    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("bob.key"))
        .arg(&sealed)
        .assert()
        .success();
    assert_eq!(fs::read(&plain).unwrap(), b"Q3 numbers: confidential");

    psion()
        .arg("inspect")
        .arg(&sealed)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("pq-hybrid-768")
                .and(predicate::str::contains("recipients:  2")),
        );
}

#[test]
fn pubkey_matches_keygen_and_identity_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let pk = keygen(dir.path(), "id.key", "cnsa-1024");
    psion()
        .args(["pubkey", "-i"])
        .arg(dir.path().join("id.key"))
        .assert()
        .success()
        .stdout(format!("{pk}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join("id.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn stdin_to_stdout_with_a_recipients_file() {
    let dir = tempfile::tempdir().unwrap();
    let pk = keygen(dir.path(), "me.key", "pq-hybrid-768");
    let list = dir.path().join("team.txt");
    fs::write(&list, format!("# team keys\n\n{pk}\n")).unwrap();
    let sealed = psion()
        .args(["encrypt", "-R"])
        .arg(&list)
        .write_stdin("piped secret")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("me.key"))
        .write_stdin(sealed.clone())
        .assert()
        .success()
        .stdout("piped secret");

    // "-" names standard input and output explicitly, and never creates a file called "-".
    fs::write(dir.path().join("sealed.psen"), &sealed).unwrap();
    psion()
        .current_dir(dir.path())
        .args(["decrypt", "-i", "me.key", "-o", "-", "sealed.psen"])
        .assert()
        .success()
        .stdout("piped secret");
    assert!(!dir.path().join("sealed").exists());
    let resealed = psion()
        .current_dir(dir.path())
        .args(["encrypt", "-R", "team.txt", "-o", "-", "-"])
        .write_stdin("dash secret")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    psion()
        .current_dir(dir.path())
        .args(["decrypt", "-i", "me.key", "-"])
        .write_stdin(resealed)
        .assert()
        .success()
        .stdout("dash secret");
    assert!(!dir.path().join("-").exists());
}

#[test]
fn tampered_file_fails_and_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    let pk = keygen(dir.path(), "me.key", "pq-hybrid-768");
    let plain = dir.path().join("data.bin");
    fs::write(&plain, vec![7u8; 300_000]).unwrap();
    psion()
        .args(["encrypt", "-r", &pk])
        .arg(&plain)
        .assert()
        .success();
    let sealed = dir.path().join("data.bin.psen");
    let mut bytes = fs::read(&sealed).unwrap();
    let n = bytes.len();
    bytes[n - 20] ^= 1;
    fs::write(&sealed, bytes).unwrap();
    fs::remove_file(&plain).unwrap();

    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("me.key"))
        .arg(&sealed)
        .assert()
        .failure()
        .stderr(predicate::str::contains("corrupt"));
    assert!(!plain.exists(), "no partial plaintext may be left behind");
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".psion-"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files must be cleaned up");
}

#[test]
fn wrong_identity_and_existing_outputs_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pk = keygen(dir.path(), "a.key", "pq-hybrid-768");
    keygen(dir.path(), "b.key", "pq-hybrid-768");
    let plain = dir.path().join("note.txt");
    fs::write(&plain, b"hi").unwrap();
    psion()
        .args(["encrypt", "-r", &pk])
        .arg(&plain)
        .assert()
        .success();
    let sealed = dir.path().join("note.txt.psen");

    psion()
        .args(["encrypt", "-r", &pk])
        .arg(&plain)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("b.key"))
        .args(["-o"])
        .arg(dir.path().join("out.txt"))
        .arg(&sealed)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a recipient"));
    psion()
        .args(["keygen", "--no-passphrase", "-o"])
        .arg(dir.path().join("a.key"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    psion()
        .args(["encrypt", "-r", "psionpk:bogus"])
        .arg(&plain)
        .arg("--force")
        .assert()
        .failure();
}

fn verify_key(dir: &Path, name: &str) -> String {
    let out = psion()
        .args(["pubkey", "--verify-key", "-i"])
        .arg(dir.join(name))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).unwrap().trim().to_string()
}

#[test]
fn signed_files_are_checked_against_expected_senders() {
    let dir = tempfile::tempdir().unwrap();
    keygen(dir.path(), "alice.key", "pq-hybrid-768");
    let bob = keygen(dir.path(), "bob.key", "pq-hybrid-768");
    keygen(dir.path(), "mallory.key", "pq-hybrid-768");
    let alice_vk = verify_key(dir.path(), "alice.key");
    let mallory_vk = verify_key(dir.path(), "mallory.key");
    assert!(alice_vk.starts_with("psionvk:"));

    let plain = dir.path().join("contract.txt");
    fs::write(&plain, b"signed terms").unwrap();
    psion()
        .args(["encrypt", "-r", &bob, "--sign-with"])
        .arg(dir.path().join("alice.key"))
        .arg(&plain)
        .assert()
        .success();
    let sealed = dir.path().join("contract.txt.psen");
    psion()
        .arg("inspect")
        .arg(&sealed)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed:      yes"));

    // The right sender is accepted.
    let ok = dir.path().join("ok.txt");
    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("bob.key"))
        .args(["--signed-by", &alice_vk, "-o"])
        .arg(&ok)
        .arg(&sealed)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Signature: valid, from expected sender",
        ));
    assert_eq!(fs::read(&ok).unwrap(), b"signed terms");

    // A different expected sender is refused and nothing is written.
    let bad = dir.path().join("bad.txt");
    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("bob.key"))
        .args(["--signed-by", &mallory_vk, "-o"])
        .arg(&bad)
        .arg(&sealed)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not one of the expected senders"));
    assert!(!bad.exists());

    // An unsigned file is refused when a signature is required.
    let unsigned = dir.path().join("unsigned.txt");
    fs::write(&unsigned, b"x").unwrap();
    psion()
        .args(["encrypt", "-r", &bob])
        .arg(&unsigned)
        .assert()
        .success();
    psion()
        .args(["decrypt", "-i"])
        .arg(dir.path().join("bob.key"))
        .args(["--signed-by", &alice_vk, "-o"])
        .arg(dir.path().join("u.out"))
        .arg(dir.path().join("unsigned.txt.psen"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not signed"));
}

#[test]
fn passphrase_protected_identities() {
    let dir = tempfile::tempdir().unwrap();
    let pass = dir.path().join("pass.txt");
    fs::write(&pass, "correct horse battery\n").unwrap();
    let key = dir.path().join("me.key");
    let pk = String::from_utf8(
        psion()
            .args(["keygen", "-o"])
            .arg(&key)
            .arg("--passphrase-file")
            .arg(&pass)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();
    let contents = fs::read_to_string(&key).unwrap();
    assert!(contents.contains("psionpe:") && !contents.contains("psionsk:"));

    // The public key is readable without the passphrase.
    psion()
        .args(["pubkey", "-i"])
        .arg(&key)
        .assert()
        .success()
        .stdout(format!("{pk}\n"));

    let plain = dir.path().join("a.txt");
    fs::write(&plain, b"locked").unwrap();
    psion()
        .args(["encrypt", "-r", &pk])
        .arg(&plain)
        .assert()
        .success();
    fs::remove_file(&plain).unwrap();
    let sealed = dir.path().join("a.txt.psen");

    // Without a terminal and without --passphrase-file, decryption explains what to do.
    psion()
        .args(["decrypt", "-i"])
        .arg(&key)
        .arg(&sealed)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--passphrase-file"));

    // A wrong passphrase is refused.
    let wrong = dir.path().join("wrong.txt");
    fs::write(&wrong, "not the passphrase\n").unwrap();
    psion()
        .args(["decrypt", "-i"])
        .arg(&key)
        .arg("--passphrase-file")
        .arg(&wrong)
        .arg(&sealed)
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong passphrase"));

    psion()
        .args(["decrypt", "-i"])
        .arg(&key)
        .arg("--passphrase-file")
        .arg(&pass)
        .arg(&sealed)
        .assert()
        .success();
    assert_eq!(fs::read(&plain).unwrap(), b"locked");

    // Change the passphrase, then remove it.
    let new_pass = dir.path().join("new.txt");
    fs::write(&new_pass, "a brand new passphrase\n").unwrap();
    psion()
        .args(["passphrase", "-i"])
        .arg(&key)
        .arg("--passphrase-file")
        .arg(&pass)
        .arg("--new-passphrase-file")
        .arg(&new_pass)
        .assert()
        .success();
    psion()
        .args(["pubkey", "--verify-key", "-i"])
        .arg(&key)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("psionvk:"));
    psion()
        .args(["passphrase", "--remove", "-i"])
        .arg(&key)
        .arg("--passphrase-file")
        .arg(&new_pass)
        .assert()
        .success();
    assert!(fs::read_to_string(&key).unwrap().contains("psionsk:"));

    // keygen without a terminal needs a passphrase source.
    psion()
        .args(["keygen", "-o"])
        .arg(dir.path().join("x.key"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("--passphrase-file"));
    let short = dir.path().join("short.txt");
    fs::write(&short, "short\n").unwrap();
    psion()
        .args(["keygen", "-o"])
        .arg(dir.path().join("y.key"))
        .arg("--passphrase-file")
        .arg(&short)
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least 8"));
}

#[test]
fn scan_reports_and_fails_on_request() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join("src/keys.go"),
        "k, _ := rsa.GenerateKey(rand.Reader, 2048)\n",
    )
    .unwrap();
    fs::write(dir.path().join("src/pq.rs"), "let g = X25519MLKEM768;\n").unwrap();

    let out = psion()
        .arg("scan")
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["algorithm"] == "RSA" && f["location"] == "src/keys.go" && f["line"] == 1)
    );
    assert!(findings.iter().any(|f| f["category"] == "quantum-safe"));

    psion()
        .arg("scan")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Quantum-vulnerable"));
    psion()
        .arg("scan")
        .arg(dir.path())
        .args(["--fail-on", "quantum-vulnerable"])
        .assert()
        .code(2);
    psion()
        .arg("scan")
        .arg(dir.path().join("src/pq.rs"))
        .args(["--fail-on", "quantum-vulnerable"])
        .assert()
        .success();

    let cbom = dir.path().join("cbom.json");
    psion()
        .arg("scan")
        .arg(dir.path().join("src"))
        .args(["--format", "cbom", "-o"])
        .arg(&cbom)
        .assert()
        .success();
    let bom: serde_json::Value = serde_json::from_str(&fs::read_to_string(&cbom).unwrap()).unwrap();
    assert_eq!(bom["specVersion"], "1.6");

    psion()
        .arg("scan")
        .arg(dir.path())
        .args(["--format", "xml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown --format"));
    psion()
        .arg("scan")
        .arg(dir.path().join("missing"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn scan_baselines_and_report_formats() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("docs")).unwrap();
    fs::write(
        root.join("src/keys.go"),
        "k, _ := rsa.GenerateKey(rand.Reader, 2048)\nh := md5.Sum(b)\n",
    )
    .unwrap();
    fs::write(root.join("docs/notes.go"), "x := ecdsa.Sign(r, k, d)\n").unwrap();

    // HTML and SARIF reports, without code excerpts.
    let html = psion()
        .current_dir(root)
        .args(["scan", "--format", "html", "--no-excerpts"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let html = String::from_utf8(html).unwrap();
    assert!(html.starts_with("<!doctype html>") && !html.contains("GenerateKey"));
    let sarif = psion()
        .current_dir(root)
        .args(["scan", "--format", "sarif"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sarif: serde_json::Value = serde_json::from_slice(&sarif).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/keys.go"
            && r["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    }));

    // Accept everything known, then only new findings fail.
    psion()
        .current_dir(root)
        .args([
            "scan",
            "--write-baseline",
            ".psionium-scan.toml",
            "--fail-on",
            "weak",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("3 findings accepted"));
    let written = fs::read_to_string(root.join(".psionium-scan.toml")).unwrap();
    assert!(written.starts_with("# pSIONIUM Scan baseline."));
    assert!(written.contains("location = \"src/keys.go:1\""));
    psion()
        .current_dir(root)
        .args(["scan", "--fail-on", "weak"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using baseline .psionium-scan.toml",
        ));
    psion()
        .current_dir(root)
        .args(["scan", "--no-baseline", "--fail-on", "weak"])
        .assert()
        .code(2);

    // Ignoring docs/ leaves its entry stale; a new line still fails.
    fs::write(
        root.join(".psionium-scan.toml"),
        written.replace("ignore = []", "ignore = [\"docs/\"]"),
    )
    .unwrap();
    fs::write(
        root.join("src/keys.go"),
        "// moved\nk, _ := rsa.GenerateKey(rand.Reader, 2048)\nh := md5.Sum(b)\nk2, _ := rsa.GenerateKey(rand.Reader, 4096)\n",
    )
    .unwrap();
    psion()
        .current_dir(root)
        .args(["scan", "--fail-on", "quantum-vulnerable"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("src/keys.go:4"))
        .stdout(predicate::str::contains("src/keys.go:2").not())
        .stderr(predicate::str::contains(
            "1 entry in the baseline no longer matches",
        ))
        .stderr(predicate::str::contains("1 finding matched --fail-on"));

    // An explicit baseline elsewhere, and a broken one.
    let elsewhere = root.join("ci-baseline.toml");
    fs::rename(root.join(".psionium-scan.toml"), &elsewhere).unwrap();
    psion()
        .current_dir(root)
        .args(["scan", "--fail-on", "quantum-vulnerable", "--baseline"])
        .arg(&elsewhere)
        .assert()
        .code(2);
    fs::write(
        &elsewhere,
        "[[accepted]]\nfingerprint = \"xyz\"\nreason = \"r\"\n",
    )
    .unwrap();
    psion()
        .current_dir(root)
        .args(["scan", "--baseline"])
        .arg(&elsewhere)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is not a valid baseline"));
    psion()
        .current_dir(root)
        .args(["scan", "--baseline", "x.toml", "--no-baseline"])
        .assert()
        .failure();
}

#[test]
fn the_shell_and_its_scripting_hooks() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");

    // Without a terminal, psion with no command keeps asking for a command.
    psion()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("a command is required"));
    psion()
        .arg("shell")
        .assert()
        .failure()
        .stderr(predicate::str::contains("the shell needs a terminal"));
    psion()
        .args(["--theme", "neon", "--plain"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown theme"));

    // The plain prompt runs commands from standard input.
    psion()
        .env("PSION_CONFIG_DIR", &config)
        .current_dir(dir.path())
        .arg("--plain")
        .write_stdin("help\n# a comment\npsion inspect missing.psen\nshell\nexit\nscan .\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Commands (add --help"))
        .stdout(predicate::str::contains("already in the shell"))
        .stdout(predicate::str::contains("pSIONIUM Scan").not())
        .stderr(predicate::str::contains("could not open missing.psen"));

    // psion theme shows and saves the theme.
    psion()
        .env("PSION_CONFIG_DIR", &config)
        .args(["theme", "classic"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Theme set to classic"));
    psion()
        .env("PSION_CONFIG_DIR", &config)
        .arg("theme")
        .assert()
        .success()
        .stdout("classic\n");
    psion()
        .env("PSION_CONFIG_DIR", &config)
        .args(["theme", "neon"])
        .assert()
        .failure();
    assert!(
        fs::read_to_string(config.join("config.toml"))
            .unwrap()
            .contains("theme = \"classic\"")
    );
}

#[test]
fn passphrases_from_standard_input() {
    let dir = tempfile::tempdir().unwrap();
    let id = dir.path().join("me.key");
    let pk = String::from_utf8(
        psion()
            .args(["keygen", "--passphrase-file", "-", "-o"])
            .arg(&id)
            .write_stdin("correct horse battery\n")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    let plain = dir.path().join("notes.txt");
    fs::write(&plain, "quantum-safe notes").unwrap();

    psion()
        .args([
            "encrypt",
            "-r",
            pk.trim(),
            "--passphrase-file",
            "-",
            "--sign-with",
        ])
        .arg(&id)
        .arg(&plain)
        .write_stdin("correct horse battery\n")
        .assert()
        .success();
    let sealed = dir.path().join("notes.txt.psen");
    let out = dir.path().join("out.txt");
    psion()
        .args(["decrypt", "--passphrase-file", "-", "-i"])
        .arg(&id)
        .arg("-o")
        .arg(&out)
        .arg(&sealed)
        .write_stdin("correct horse battery\r\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Signature: valid"));
    assert_eq!(fs::read_to_string(&out).unwrap(), "quantum-safe notes");

    // The data and the passphrase cannot both come from standard input.
    psion()
        .args(["decrypt", "--passphrase-file", "-", "-i"])
        .arg(&id)
        .write_stdin("x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot carry both"));

    // A wrong passphrase from standard input fails cleanly.
    psion()
        .args(["decrypt", "--passphrase-file", "-", "--force", "-i"])
        .arg(&id)
        .arg("-o")
        .arg(&out)
        .arg(&sealed)
        .write_stdin("wrong passphrase\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not unlock"));

    // PSION_NO_PROMPT turns a passphrase prompt into an error.
    psion()
        .env("PSION_NO_PROMPT", "1")
        .args(["pubkey", "--verify-key", "-i"])
        .arg(&id)
        .assert()
        .success();
    psion()
        .env("PSION_NO_PROMPT", "1")
        .args(["decrypt", "--force", "-i"])
        .arg(&id)
        .arg("-o")
        .arg(&out)
        .arg(&sealed)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot ask for a passphrase"));
}
