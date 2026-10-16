//! Passphrase protection for identity files: Argon2id (RFC 9106) derives a key that encrypts the
//! secret key lines with AES-256-GCM. Comment lines with the public keys stay readable.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const PROTECTED_PREFIX: &str = "psionpe:";
const BLOB_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// version (1) ‖ m_cost KiB (4) ‖ t_cost (4) ‖ p_cost (1) ‖ salt (16) ‖ nonce (12)
const HEADER_LEN: usize = 1 + 4 + 4 + 1 + SALT_LEN + NONCE_LEN;

/// Shortest passphrase accepted when protecting a key.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Passes over memory.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u8,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane: the first recommended option in RFC 9106 §4 scaled for
    /// interactive use, and above OWASP's minimum for Argon2id.
    fn default() -> Self {
        KdfParams {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

// Limits on parameters read from a file, so a crafted file cannot exhaust memory or time.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u8 = 16;

/// Whether identity file contents are passphrase protected.
pub fn is_protected(contents: &str) -> bool {
    contents
        .lines()
        .any(|l| l.trim().starts_with(PROTECTED_PREFIX))
}

/// Protects the secret lines (`psionsk:`, `psionss:`) of plain identity file contents with a
/// passphrase. Comment lines are kept as they are.
pub fn protect(contents: &str, passphrase: &[u8], params: KdfParams) -> Result<Zeroizing<String>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(Error::Passphrase(
            "passphrase must be at least 8 characters",
        ));
    }
    if is_protected(contents) {
        return Err(Error::Passphrase("the identity is already protected"));
    }
    check_params(params)?;
    let mut secret = Zeroizing::new(String::new());
    let mut out = Zeroizing::new(String::new());
    for line in contents.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            out.push_str(line);
            out.push('\n');
        } else {
            secret.push_str(t);
            secret.push('\n');
        }
    }
    if secret.is_empty() {
        return Err(Error::Key("the identity file has no secret key"));
    }

    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)?;
    let mut blob = Vec::with_capacity(HEADER_LEN + secret.len() + 16);
    blob.push(BLOB_VERSION);
    blob.extend_from_slice(&params.m_cost_kib.to_be_bytes());
    blob.extend_from_slice(&params.t_cost.to_be_bytes());
    blob.push(params.p_cost);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);

    let key = derive(passphrase, &salt, params)?;
    let mut body = Zeroizing::new(secret.as_bytes().to_vec());
    cipher(&key)?.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&blob[..HEADER_LEN]),
        &mut *body,
    )?;
    blob.extend_from_slice(&body);
    out.push_str(PROTECTED_PREFIX);
    out.push_str(&URL_SAFE_NO_PAD.encode(&blob));
    out.push('\n');
    Ok(out)
}

/// Removes passphrase protection, giving plain identity file contents.
pub fn unprotect(contents: &str, passphrase: &[u8]) -> Result<Zeroizing<String>> {
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(PROTECTED_PREFIX))
        .ok_or(Error::Passphrase(
            "the identity is not passphrase protected",
        ))?;
    let blob = URL_SAFE_NO_PAD
        .decode(&line[PROTECTED_PREFIX.len()..])
        .map_err(|_| Error::Key("protected identity is not valid base64url"))?;
    if blob.len() < HEADER_LEN + 16 {
        return Err(Error::Key("protected identity is too short"));
    }
    if blob[0] != BLOB_VERSION {
        return Err(Error::Unsupported("protected identity version"));
    }
    let params = KdfParams {
        m_cost_kib: u32::from_be_bytes(blob[1..5].try_into().expect("4 bytes")),
        t_cost: u32::from_be_bytes(blob[5..9].try_into().expect("4 bytes")),
        p_cost: blob[9],
    };
    check_params(params)?;
    let salt = &blob[10..10 + SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[10 + SALT_LEN..HEADER_LEN]);

    let key = derive(passphrase, salt, params)?;
    let mut body = Zeroizing::new(blob[HEADER_LEN..].to_vec());
    let plain = cipher(&key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&blob[..HEADER_LEN]),
            &mut body,
        )
        .map_err(|_| Error::Passphrase("wrong passphrase, or the identity file is corrupt"))?;
    let secret =
        std::str::from_utf8(plain).map_err(|_| Error::Key("protected identity is malformed"))?;

    let mut out = Zeroizing::new(String::new());
    for l in contents.lines() {
        if !l.trim().starts_with(PROTECTED_PREFIX) {
            out.push_str(l);
            out.push('\n');
        }
    }
    out.push_str(secret);
    Ok(out)
}

fn check_params(p: KdfParams) -> Result<()> {
    if p.m_cost_kib < 8 * u32::from(p.p_cost.max(1))
        || p.m_cost_kib > MAX_M_COST_KIB
        || p.t_cost == 0
        || p.t_cost > MAX_T_COST
        || p.p_cost == 0
        || p.p_cost > MAX_P_COST
    {
        return Err(Error::Unsupported("passphrase key-derivation parameters"));
    }
    Ok(())
}

fn derive(passphrase: &[u8], salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = argon2::Params::new(p.m_cost_kib, p.t_cost, u32::from(p.p_cost), Some(KEY_LEN))
        .map_err(|_| Error::Unsupported("passphrase key-derivation parameters"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

fn cipher(key: &[u8; KEY_LEN]) -> Result<LessSafeKey> {
    Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key)?))
}
