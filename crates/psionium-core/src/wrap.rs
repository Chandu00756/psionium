//! Per-recipient key encapsulation: derives the key-encryption key that wraps a file key.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement;
use aws_lc_rs::hkdf;
use aws_lc_rs::kem;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{Identity, KEY_ID_LEN, PublicKey};
use crate::suite::X25519_LEN;

pub(crate) const FILE_KEY_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const WRAPPED_LEN: usize = FILE_KEY_LEN + TAG_LEN;

const KEK_LABEL: &[u8] = b"psionium/v2/kek";

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA-384 extract-then-expand into `out`.
pub(crate) fn hkdf_sha384(salt: &[u8], ikm: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<()> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA384, salt).extract(ikm);
    prk.expand(info, Len(out.len()))?.fill(out)?;
    Ok(())
}

fn derive_kek(
    suite_id: u16,
    salt: &[u8],
    ikm: &[u8],
    key_id: &[u8; KEY_ID_LEN],
    kem_ct: &[u8],
    x25519_pk: Option<&[u8]>,
) -> Result<Zeroizing<[u8; FILE_KEY_LEN]>> {
    let suite = suite_id.to_be_bytes();
    let mut info: Vec<&[u8]> = vec![KEK_LABEL, &suite, key_id, kem_ct];
    if let Some(pk) = x25519_pk {
        info.push(pk);
    }
    let mut kek = Zeroizing::new([0u8; FILE_KEY_LEN]);
    hkdf_sha384(salt, ikm, &info, kek.as_mut())?;
    Ok(kek)
}

fn x25519(private: &agreement::PrivateKey, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    agreement::agree(
        private,
        agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
        Error::Crypto,
        |ss| Ok(Zeroizing::new(ss.to_vec())),
    )
}

/// Encapsulates to a recipient. Returns the stanza's KEM ciphertext and the key-encryption key.
pub(crate) fn encapsulate(
    recipient: &PublicKey,
    salt: &[u8],
    key_id: &[u8; KEY_ID_LEN],
) -> Result<(Vec<u8>, Zeroizing<[u8; FILE_KEY_LEN]>)> {
    let suite = recipient.suite();
    let ek = kem::EncapsulationKey::new(suite.kem(), recipient.mlkem_ek())
        .map_err(|_| Error::Key("ML-KEM public key is malformed"))?;
    let mut kem_ct = Vec::with_capacity(suite.kem_ct_len());
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));

    let ss_x = match recipient.x25519() {
        Some(peer) => {
            let eph = agreement::PrivateKey::generate(&agreement::X25519)?;
            kem_ct.extend_from_slice(eph.compute_public_key()?.as_ref());
            Some(x25519(&eph, peer)?)
        }
        None => None,
    };
    let (ct_m, ss_m) = ek.encapsulate()?;
    kem_ct.extend_from_slice(ct_m.as_ref());
    ikm.extend_from_slice(ss_m.as_ref());
    if let Some(ss_x) = &ss_x {
        ikm.extend_from_slice(ss_x);
    }

    let kek = derive_kek(suite.id(), salt, &ikm, key_id, &kem_ct, recipient.x25519())?;
    Ok((kem_ct, kek))
}

/// Decapsulates a stanza's KEM ciphertext with an identity, giving the key-encryption key.
pub(crate) fn decapsulate(
    identity: &Identity,
    kem_ct: &[u8],
    salt: &[u8],
    key_id: &[u8; KEY_ID_LEN],
) -> Result<Zeroizing<[u8; FILE_KEY_LEN]>> {
    let suite = identity.suite();
    if kem_ct.len() != suite.kem_ct_len() {
        return Err(Error::Format("recipient stanza has the wrong size"));
    }
    let (eph_pk, ct_m) = kem_ct.split_at(if suite.has_x25519() { X25519_LEN } else { 0 });
    let ss_m = identity.mlkem().decapsulate(kem::Ciphertext::from(ct_m))?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_m.as_ref());
    if let Some(private) = identity.x25519() {
        ikm.extend_from_slice(&x25519(private, eph_pk)?);
    }
    derive_kek(
        suite.id(),
        salt,
        &ikm,
        key_id,
        kem_ct,
        identity.public_key().x25519(),
    )
}

fn kek_cipher(kek: &[u8; FILE_KEY_LEN]) -> Result<LessSafeKey> {
    Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, kek)?))
}

/// Wraps the file key. Each key-encryption key is used once, so a fixed nonce is safe.
pub(crate) fn wrap_file_key(
    kek: &[u8; FILE_KEY_LEN],
    aad: &[u8],
    file_key: &[u8; FILE_KEY_LEN],
) -> Result<[u8; WRAPPED_LEN]> {
    let mut buf = Zeroizing::new(Vec::with_capacity(WRAPPED_LEN));
    buf.extend_from_slice(file_key);
    kek_cipher(kek)?.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
        Aad::from(aad),
        &mut *buf,
    )?;
    let mut out = [0u8; WRAPPED_LEN];
    out.copy_from_slice(&buf);
    Ok(out)
}

/// Opens a wrapped file key.
pub(crate) fn unwrap_file_key(
    kek: &[u8; FILE_KEY_LEN],
    aad: &[u8],
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; FILE_KEY_LEN]>> {
    let mut buf = Zeroizing::new(wrapped.to_vec());
    let plain = kek_cipher(kek)?.open_in_place(
        Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
        Aad::from(aad),
        &mut buf,
    )?;
    let mut key = Zeroizing::new([0u8; FILE_KEY_LEN]);
    key.copy_from_slice(plain);
    Ok(key)
}
