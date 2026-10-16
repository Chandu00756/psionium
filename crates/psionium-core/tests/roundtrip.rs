use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use psionium_core::{
    EncryptOptions, Error, Identity, KEY_ID_LEN, MAX_RECIPIENTS, PublicKey, Suite, decrypt,
    encrypt, encrypted_len, inspect,
};

const SMALL: u8 = 12; // 4 KiB chunks keep multi-chunk tests fast
const CHUNK: usize = 1 << SMALL;

fn random(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    SystemRandom::new().fill(&mut v).unwrap();
    v
}

fn seal(recipients: &[&Identity], data: &[u8], chunk_log2: u8) -> Vec<u8> {
    let keys: Vec<PublicKey> = recipients.iter().map(|i| i.public_key().clone()).collect();
    let mut out = Vec::new();
    let n = encrypt(&keys, data, &mut out, &EncryptOptions { chunk_log2 }).unwrap();
    assert_eq!(n, data.len() as u64);
    out
}

fn open(identity: &Identity, file: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt(identity, file, &mut out)?;
    Ok(out)
}

#[test]
fn roundtrip_at_chunk_boundaries_for_every_suite() {
    for suite in Suite::ALL {
        let id = Identity::generate(suite).unwrap();
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 5] {
            let data = random(len);
            let file = seal(&[&id], &data, SMALL);
            assert_eq!(
                file.len() as u64,
                encrypted_len(suite, 1, SMALL, len as u64),
                "{suite} len {len}"
            );
            assert_eq!(open(&id, &file).unwrap(), data, "{suite} len {len}");
        }
    }
}

#[test]
fn default_options_stream_a_larger_file() {
    let id = Identity::generate(Suite::default()).unwrap();
    let data = random(1_000_003);
    let mut file = Vec::new();
    encrypt(
        &[id.public_key().clone()],
        &data[..],
        &mut file,
        &EncryptOptions::default(),
    )
    .unwrap();
    assert_eq!(open(&id, &file).unwrap(), data);
}

#[test]
fn every_recipient_can_decrypt_and_others_cannot() {
    let (a, b, c) = (
        Identity::generate(Suite::default()).unwrap(),
        Identity::generate(Suite::default()).unwrap(),
        Identity::generate(Suite::default()).unwrap(),
    );
    let outsider = Identity::generate(Suite::default()).unwrap();
    let data = random(3 * CHUNK);
    let file = seal(&[&a, &b, &c], &data, SMALL);
    for id in [&a, &b, &c] {
        assert_eq!(open(id, &file).unwrap(), data);
    }
    assert!(matches!(open(&outsider, &file), Err(Error::NotARecipient)));
    let other_suite = Identity::generate(Suite::Cnsa1024).unwrap();
    assert!(matches!(
        open(&other_suite, &file),
        Err(Error::NotARecipient)
    ));
}

#[test]
fn recipient_list_is_validated() {
    let a = Identity::generate(Suite::PqHybrid768).unwrap();
    let b = Identity::generate(Suite::Cnsa1024).unwrap();
    let mut out = Vec::new();
    let opts = EncryptOptions::default();
    assert!(matches!(
        encrypt(&[], &b"x"[..], &mut out, &opts),
        Err(Error::NoRecipients)
    ));
    let mixed = [a.public_key().clone(), b.public_key().clone()];
    assert!(matches!(
        encrypt(&mixed, &b"x"[..], &mut out, &opts),
        Err(Error::MixedSuites)
    ));
    let many = vec![a.public_key().clone(); MAX_RECIPIENTS + 1];
    assert!(matches!(
        encrypt(&many, &b"x"[..], &mut out, &opts),
        Err(Error::TooManyRecipients { .. })
    ));
    let bad_chunk = EncryptOptions { chunk_log2: 11 };
    assert!(matches!(
        encrypt(&[a.public_key().clone()], &b"x"[..], &mut out, &bad_chunk),
        Err(Error::ChunkSize)
    ));
}

#[test]
fn header_tampering_is_detected() {
    let id = Identity::generate(Suite::default()).unwrap();
    let data = random(CHUNK + 7);
    let file = seal(&[&id], &data, SMALL);
    let header_len = inspect(&file[..]).unwrap().header_len;

    // The MAC itself.
    let mut f = file.clone();
    f[header_len - 1] ^= 1;
    assert!(matches!(open(&id, &f), Err(Error::HeaderAuth)));

    // The salt and the wrapped key are bound into key unwrapping.
    for pos in [10, header_len - 50] {
        let mut f = file.clone();
        f[pos] ^= 1;
        assert!(open(&id, &f).is_err(), "flipping byte {pos} must fail");
    }

    // Signature and version.
    let mut f = file.clone();
    f[0] = b'X';
    assert!(matches!(open(&id, &f), Err(Error::Format(_))));
    let mut f = file.clone();
    f[4] = 3;
    assert!(matches!(open(&id, &f), Err(Error::Unsupported(_))));
}

#[test]
fn payload_tampering_truncation_and_extension_are_detected() {
    let id = Identity::generate(Suite::default()).unwrap();
    let data = random(3 * CHUNK + 100);
    let file = seal(&[&id], &data, SMALL);
    let header_len = inspect(&file[..]).unwrap().header_len;
    let block = CHUNK + 16;

    let mut f = file.clone();
    f[header_len + block + 3] ^= 0x80;
    assert!(matches!(open(&id, &f), Err(Error::ChunkAuth(1))));

    // Dropping the final chunk makes chunk 2 look final, which it was not sealed as.
    let f = &file[..header_len + 3 * block];
    assert!(matches!(open(&id, f), Err(Error::ChunkAuth(2))));

    // Cutting into the final chunk.
    let f = &file[..file.len() - 1];
    assert!(open(&id, f).is_err());

    // Data after the final chunk.
    let mut f = file.clone();
    f.push(0);
    assert!(open(&id, &f).is_err());

    // Swapping two chunks.
    let mut f = file.clone();
    let (a, b) = (header_len, header_len + block);
    let first: Vec<u8> = f[a..a + block].to_vec();
    f.copy_within(b..b + block, a);
    f[b..b + block].copy_from_slice(&first);
    assert!(matches!(open(&id, &f), Err(Error::ChunkAuth(0))));

    // Header only, no payload.
    assert!(matches!(
        open(&id, &file[..header_len]),
        Err(Error::Truncated)
    ));
}

#[test]
fn identical_plaintexts_encrypt_differently() {
    let id = Identity::generate(Suite::default()).unwrap();
    let a = seal(&[&id], b"same", SMALL);
    let b = seal(&[&id], b"same", SMALL);
    assert_ne!(a, b);
}

#[test]
fn keys_survive_text_encoding() {
    for suite in Suite::ALL {
        let id = Identity::generate(suite).unwrap();
        let secret = id.to_secret_string().unwrap();
        let restored = Identity::from_secret_str(&secret).unwrap();
        assert_eq!(restored.public_key(), id.public_key());

        let file = id.to_file_contents("2026-10-16T00:00:00Z").unwrap();
        let from_file = Identity::from_file_contents(&file).unwrap();
        assert_eq!(from_file.public_key(), id.public_key());

        let pk_text = id.public_key().to_string();
        assert!(pk_text.starts_with("psionpk:"));
        let pk: PublicKey = pk_text.parse().unwrap();
        assert_eq!(&pk, id.public_key());
        assert_eq!(pk.key_id().len(), KEY_ID_LEN);

        // A restored identity decrypts files made for the original.
        let sealed = seal(&[&id], b"persisted", SMALL);
        assert_eq!(open(&restored, &sealed).unwrap(), b"persisted");
    }
}

#[test]
fn malformed_keys_are_rejected() {
    assert!("psionsk:AAE".parse::<PublicKey>().is_err());
    assert!("psionpk:not base64!".parse::<PublicKey>().is_err());
    assert!("psionpk:AAE".parse::<PublicKey>().is_err());
    let good = Identity::generate(Suite::default())
        .unwrap()
        .public_key()
        .to_string();
    assert!(good[..good.len() - 10].parse::<PublicKey>().is_err());
    assert!(Identity::from_secret_str("psionsk:AAEAAA").is_err());
    assert!(Identity::from_file_contents("# no key here\n").is_err());
}

#[test]
fn corrupted_secret_key_is_detected() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let id = Identity::generate(Suite::default()).unwrap();
    let secret = id.to_secret_string().unwrap();
    let mut raw = URL_SAFE_NO_PAD
        .decode(secret.trim_start_matches("psionsk:"))
        .unwrap();
    // Byte 2 + 32 (X25519) + 1152 (dk_pke) + 10 lies inside the embedded ML-KEM public key.
    raw[2 + 32 + 1152 + 10] ^= 1;
    let corrupted = format!("psionsk:{}", URL_SAFE_NO_PAD.encode(raw));
    assert!(matches!(
        Identity::from_secret_str(&corrupted),
        Err(Error::Key(_))
    ));
}

#[test]
fn inspect_reports_header_without_keys() {
    let a = Identity::generate(Suite::Cnsa1024).unwrap();
    let b = Identity::generate(Suite::Cnsa1024).unwrap();
    let file = seal(&[&a, &b], b"hello", 14);
    let info = inspect(&file[..]).unwrap();
    assert_eq!(info.suite, Suite::Cnsa1024);
    assert_eq!(info.chunk_size, 1 << 14);
    assert_eq!(
        info.recipients,
        vec![a.public_key().key_id(), b.public_key().key_id()]
    );
    assert!(inspect(&b"PSEN"[..]).is_err());
}
