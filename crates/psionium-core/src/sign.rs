//! Sender signatures with ML-DSA (FIPS 204).

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{KEY_ID_LEN, hex, split_suite};
use crate::suite::Suite;

const VERIFY_PREFIX: &str = "psionvk:";
const SIGNING_PREFIX: &str = "psionss:";

/// Length of an ML-DSA seed, the stored form of a signing key.
pub const SEED_LEN: usize = 32;

/// A sender's public verifying key. Share it so recipients can check files you signed.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    suite: Suite,
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Builds a verifying key from its suite and raw ML-DSA public key bytes.
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != suite.mldsa_vk_len() {
            return Err(Error::Key(
                "verifying key has the wrong length for its suite",
            ));
        }
        Ok(VerifyingKey {
            suite,
            bytes: bytes.to_vec(),
        })
    }

    /// The key's algorithm suite.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The raw ML-DSA public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `SHA-384(suite ‖ verifying key)` truncated to 16 bytes, for display.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut ctx = digest::Context::new(&digest::SHA384);
        ctx.update(&self.suite.id().to_be_bytes());
        ctx.update(&self.bytes);
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&ctx.finish().as_ref()[..KEY_ID_LEN]);
        id
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        UnparsedPublicKey::new(self.suite.mldsa_verification(), &self.bytes)
            .verify(message, signature)
            .map_err(|_| Error::Signature)
    }
}

impl fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = Vec::with_capacity(2 + self.bytes.len());
        raw.extend_from_slice(&self.suite.id().to_be_bytes());
        raw.extend_from_slice(&self.bytes);
        write!(f, "{VERIFY_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("suite", &self.suite)
            .field("key_id", &hex(&self.key_id()))
            .finish()
    }
}

impl FromStr for VerifyingKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(VERIFY_PREFIX)
            .ok_or(Error::Key("verifying keys start with \"psionvk:\""))?;
        let raw = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Error::Key("verifying key is not valid base64url"))?;
        let (suite, bytes) = split_suite(&raw)?;
        VerifyingKey::from_bytes(suite, bytes)
    }
}

/// A sender's secret signing key.
pub struct SigningKey {
    suite: Suite,
    seed: Zeroizing<[u8; SEED_LEN]>,
    pair: PqdsaKeyPair,
    verifying: VerifyingKey,
}

impl SigningKey {
    /// Generates a new signing key for a suite.
    pub fn generate(suite: Suite) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        SystemRandom::new().fill(seed.as_mut())?;
        SigningKey::from_seed(suite, seed.as_ref())
    }

    /// Rebuilds a signing key from its 32-byte seed.
    pub fn from_seed(suite: Suite, seed: &[u8]) -> Result<Self> {
        if seed.len() != SEED_LEN {
            return Err(Error::Key("signing key seed must be 32 bytes"));
        }
        let pair = PqdsaKeyPair::from_seed(suite.mldsa_signing(), seed)
            .map_err(|_| Error::Key("signing key seed was rejected"))?;
        let verifying = VerifyingKey::from_bytes(suite, pair.public_key().as_ref())?;
        let mut stored = Zeroizing::new([0u8; SEED_LEN]);
        stored.copy_from_slice(seed);
        Ok(SigningKey {
            suite,
            seed: stored,
            pair,
            verifying,
        })
    }

    /// The key's algorithm suite.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The public key recipients use to check signatures.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// The signing key as text (`psionss:…`). Keep it secret.
    pub fn to_secret_string(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(2 + SEED_LEN));
        raw.extend_from_slice(&self.suite.id().to_be_bytes());
        raw.extend_from_slice(self.seed.as_ref());
        Zeroizing::new(format!("{SIGNING_PREFIX}{}", URL_SAFE_NO_PAD.encode(&*raw)))
    }

    /// Parses a signing key written by [`SigningKey::to_secret_string`].
    pub fn from_secret_str(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(SIGNING_PREFIX)
            .ok_or(Error::Key("signing keys start with \"psionss:\""))?;
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Error::Key("signing key is not valid base64url"))?,
        );
        let (suite, seed) = split_suite(&raw)?;
        SigningKey::from_seed(suite, seed)
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0u8; self.suite.mldsa_sig_len()];
        let n = self.pair.sign(message, &mut sig)?;
        sig.truncate(n);
        Ok(sig)
    }

    pub(crate) fn is_signing_prefix(line: &str) -> bool {
        line.starts_with(SIGNING_PREFIX)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying", &self.verifying)
            .finish_non_exhaustive()
    }
}
