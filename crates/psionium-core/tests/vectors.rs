//! Fixed test vectors. Files in `tests/vectors` were produced once and committed; every future
//! version must keep decrypting them exactly. Regenerate only when the format version changes:
//! `PSIONIUM_WRITE_VECTORS=1 cargo test -p psionium-core --test vectors -- --ignored`.

use std::fs;
use std::path::PathBuf;

use aws_lc_rs::digest;
use psionium_core::{
    EncryptOptions, Identity, KdfParams, PublicKey, Suite, decrypt, encrypt, encrypt_signed, hex,
    protect, unprotect,
};

const PASSPHRASE: &[u8] = b"pSIONIUM test vector passphrase";

struct Vector {
    file: &'static str,
    identity: &'static str,
    len: usize,
    chunk_log2: u8,
    extra_recipients: usize,
    signed: bool,
    sha384: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        file: "hybrid-empty.psen",
        identity: "hybrid.identity",
        len: 0,
        chunk_log2: 16,
        extra_recipients: 0,
        signed: false,
        sha384: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    Vector {
        file: "hybrid-small.psen",
        identity: "hybrid.identity",
        len: 1000,
        chunk_log2: 16,
        extra_recipients: 0,
        signed: false,
        sha384: "",
    },
    Vector {
        file: "hybrid-multichunk-3-recipients.psen",
        identity: "hybrid.identity",
        len: 3 * 4096 + 17,
        chunk_log2: 12,
        extra_recipients: 2,
        signed: false,
        sha384: "",
    },
    Vector {
        file: "hybrid-exact-chunks.psen",
        identity: "hybrid.identity",
        len: 2 * 4096,
        chunk_log2: 12,
        extra_recipients: 0,
        signed: false,
        sha384: "",
    },
    Vector {
        file: "hybrid-signed.psen",
        identity: "hybrid.identity",
        len: 5000,
        chunk_log2: 12,
        extra_recipients: 1,
        signed: true,
        sha384: "",
    },
    Vector {
        file: "cnsa-small.psen",
        identity: "cnsa.identity",
        len: 777,
        chunk_log2: 16,
        extra_recipients: 0,
        signed: false,
        sha384: "",
    },
    Vector {
        file: "cnsa-signed.psen",
        identity: "cnsa.identity",
        len: 9000,
        chunk_log2: 12,
        extra_recipients: 0,
        signed: true,
        sha384: "",
    },
];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

/// Deterministic plaintext: byte i is (i * 31 + 7) mod 251.
fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

fn sha384_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, data).as_ref())
}

fn load(name: &str) -> Identity {
    Identity::from_file_contents(&fs::read_to_string(dir().join(name)).unwrap()).unwrap()
}

#[test]
fn committed_vectors_still_decrypt() {
    let hybrid = load("hybrid.identity");
    let cnsa = load("cnsa.identity");
    for v in VECTORS {
        let identity = if v.identity == "cnsa.identity" {
            &cnsa
        } else {
            &hybrid
        };
        let file = fs::read(dir().join(v.file)).unwrap_or_else(|e| panic!("{}: {e}", v.file));
        let mut out = Vec::new();
        let result =
            decrypt(identity, &file[..], &mut out).unwrap_or_else(|e| panic!("{}: {e}", v.file));
        assert_eq!(out, plaintext(v.len), "{}", v.file);
        assert_eq!(result.signer.is_some(), v.signed, "{}", v.file);
        if v.signed {
            assert_eq!(
                result.signer.as_ref(),
                identity.verifying_key(),
                "{}",
                v.file
            );
        }
        if !v.sha384.is_empty() {
            assert_eq!(sha384_hex(&out), v.sha384, "{}", v.file);
        }
        let expected_hash = fs::read_to_string(dir().join(format!("{}.sha384", v.file))).unwrap();
        assert_eq!(
            sha384_hex(&file),
            expected_hash.trim(),
            "{} changed on disk",
            v.file
        );
    }
}

#[test]
fn committed_protected_identity_unlocks() {
    let locked = fs::read_to_string(dir().join("hybrid.identity.protected")).unwrap();
    let plain = unprotect(&locked, PASSPHRASE).unwrap();
    let id = Identity::from_file_contents(&plain).unwrap();
    assert_eq!(id.public_key(), load("hybrid.identity").public_key());
}

#[test]
#[ignore = "writes the committed vectors; run only when the format version changes"]
fn write_vectors() {
    if std::env::var_os("PSIONIUM_WRITE_VECTORS").is_none() {
        return;
    }
    let d = dir();
    fs::create_dir_all(&d).unwrap();
    let stamp = "2026-10-16T00:00:00Z";
    let hybrid = Identity::generate(Suite::PqHybrid768).unwrap();
    let cnsa = Identity::generate(Suite::Cnsa1024).unwrap();
    let hybrid_text = hybrid.to_file_contents(stamp).unwrap();
    fs::write(d.join("hybrid.identity"), hybrid_text.as_bytes()).unwrap();
    fs::write(
        d.join("cnsa.identity"),
        cnsa.to_file_contents(stamp).unwrap().as_bytes(),
    )
    .unwrap();
    let fast = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };
    fs::write(
        d.join("hybrid.identity.protected"),
        protect(&hybrid_text, PASSPHRASE, fast).unwrap().as_bytes(),
    )
    .unwrap();

    for v in VECTORS {
        let identity = if v.identity == "cnsa.identity" {
            &cnsa
        } else {
            &hybrid
        };
        let mut recipients: Vec<PublicKey> = vec![identity.public_key().clone()];
        for _ in 0..v.extra_recipients {
            recipients.insert(
                0,
                Identity::generate(identity.suite())
                    .unwrap()
                    .public_key()
                    .clone(),
            );
        }
        let opts = EncryptOptions {
            chunk_log2: v.chunk_log2,
        };
        let mut out = Vec::new();
        let data = plaintext(v.len);
        if v.signed {
            encrypt_signed(
                &recipients,
                identity.signing_key().unwrap(),
                &data[..],
                &mut out,
                &opts,
            )
            .unwrap();
        } else {
            encrypt(&recipients, &data[..], &mut out, &opts).unwrap();
        }
        fs::write(d.join(v.file), &out).unwrap();
        fs::write(
            d.join(format!("{}.sha384", v.file)),
            format!("{}\n", sha384_hex(&out)),
        )
        .unwrap();
    }
}
