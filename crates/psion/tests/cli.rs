use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

fn psion() -> Command {
    Command::cargo_bin("psion").unwrap()
}

fn keygen(dir: &Path, name: &str, suite: &str) -> String {
    let out = psion()
        .args(["keygen", "--suite", suite, "-o"])
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
        .write_stdin(sealed)
        .assert()
        .success()
        .stdout("piped secret");
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
        .args(["keygen", "-o"])
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
