use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use psionium_core::{Error, Identity, KdfParams, Suite, is_protected, protect, unprotect};

const FAST: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};

fn identity_file() -> (Identity, String) {
    let id = Identity::generate(Suite::default()).unwrap();
    let contents = id
        .to_file_contents("2026-10-16T00:00:00Z")
        .unwrap()
        .to_string();
    (id, contents)
}

#[test]
fn protect_then_unprotect_restores_the_identity() {
    let (id, plain) = identity_file();
    let locked = protect(&plain, b"correct horse battery", FAST).unwrap();
    assert!(is_protected(&locked));
    assert!(
        !locked.contains("psionsk:") && !locked.contains("psionss:"),
        "secrets must not appear in clear"
    );
    assert!(
        locked.contains("# public key: psionpk:"),
        "public keys stay readable"
    );
    let unlocked = unprotect(&locked, b"correct horse battery").unwrap();
    let back = Identity::from_file_contents(&unlocked).unwrap();
    assert_eq!(back.public_key(), id.public_key());
    assert_eq!(back.verifying_key(), id.verifying_key());
}

#[test]
fn default_parameters_work() {
    let (_, plain) = identity_file();
    let locked = protect(
        &plain,
        b"a reasonably long passphrase",
        KdfParams::default(),
    )
    .unwrap();
    assert!(unprotect(&locked, b"a reasonably long passphrase").is_ok());
}

#[test]
fn wrong_or_short_passphrases_are_refused() {
    let (_, plain) = identity_file();
    let locked = protect(&plain, b"correct horse battery", FAST).unwrap();
    assert!(matches!(
        unprotect(&locked, b"wrong horse battery"),
        Err(Error::Passphrase(_))
    ));
    assert!(matches!(
        protect(&plain, b"short", FAST),
        Err(Error::Passphrase(_))
    ));
    assert!(matches!(
        protect(&locked, b"correct horse battery", FAST),
        Err(Error::Passphrase(_))
    ));
    assert!(matches!(
        unprotect(&plain, b"correct horse battery"),
        Err(Error::Passphrase(_))
    ));
}

fn blob_of(locked: &str) -> Vec<u8> {
    let line = locked.lines().find(|l| l.starts_with("psionpe:")).unwrap();
    URL_SAFE_NO_PAD.decode(&line["psionpe:".len()..]).unwrap()
}

fn with_blob(locked: &str, blob: &[u8]) -> String {
    locked
        .lines()
        .map(|l| {
            if l.starts_with("psionpe:") {
                format!("psionpe:{}", URL_SAFE_NO_PAD.encode(blob))
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tampering_and_hostile_parameters_are_rejected() {
    let (_, plain) = identity_file();
    let locked = protect(&plain, b"correct horse battery", FAST).unwrap();
    let blob = blob_of(&locked);

    // Flipping a ciphertext byte or a parameter byte (bound as associated data) fails.
    for pos in [blob.len() - 1, 30, 20] {
        let mut b = blob.clone();
        b[pos] ^= 1;
        assert!(
            unprotect(&with_blob(&locked, &b), b"correct horse battery").is_err(),
            "byte {pos}"
        );
    }

    // A crafted file asking for 4 GiB of memory is refused before any work is done.
    let mut b = blob.clone();
    b[1..5].copy_from_slice(&(4u32 * 1024 * 1024).to_be_bytes());
    assert!(matches!(
        unprotect(&with_blob(&locked, &b), b"correct horse battery"),
        Err(Error::Unsupported(_))
    ));

    // So is an unknown version.
    let mut b = blob;
    b[0] = 9;
    assert!(matches!(
        unprotect(&with_blob(&locked, &b), b"correct horse battery"),
        Err(Error::Unsupported(_))
    ));
}
