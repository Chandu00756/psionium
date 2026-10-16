use std::fmt;

use aws_lc_rs::kem;
use aws_lc_rs::signature;

use crate::error::{Error, Result};

/// An algorithm suite. Every key pair and every file belongs to exactly one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Suite {
    /// X25519 + ML-KEM-768 hybrid, ML-DSA-65 signatures, AES-256-GCM, HKDF-SHA-384. The default.
    #[default]
    PqHybrid768,
    /// ML-KEM-1024, ML-DSA-87 signatures, AES-256-GCM, HKDF-SHA-384: algorithms from NSA's CNSA 2.0.
    Cnsa1024,
}

pub(crate) const X25519_LEN: usize = 32;

impl Suite {
    /// All suites, default first.
    pub const ALL: [Suite; 2] = [Suite::PqHybrid768, Suite::Cnsa1024];

    /// The suite's two-byte identifier in files and keys.
    pub const fn id(self) -> u16 {
        match self {
            Suite::PqHybrid768 => 0x0001,
            Suite::Cnsa1024 => 0x0002,
        }
    }

    /// Looks up a suite by its identifier.
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            0x0001 => Ok(Suite::PqHybrid768),
            0x0002 => Ok(Suite::Cnsa1024),
            _ => Err(Error::Unsupported("algorithm suite")),
        }
    }

    /// The suite's name, as used on the command line.
    pub const fn name(self) -> &'static str {
        match self {
            Suite::PqHybrid768 => "pq-hybrid-768",
            Suite::Cnsa1024 => "cnsa-1024",
        }
    }

    /// Looks up a suite by name.
    pub fn from_name(name: &str) -> Option<Self> {
        Suite::ALL.into_iter().find(|s| s.name() == name)
    }

    /// A one-line description of the suite's algorithms.
    pub const fn description(self) -> &'static str {
        match self {
            Suite::PqHybrid768 => "X25519 + ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF-SHA-384",
            Suite::Cnsa1024 => "ML-KEM-1024, ML-DSA-87, AES-256-GCM, HKDF-SHA-384 (CNSA 2.0)",
        }
    }

    pub(crate) fn kem(self) -> &'static kem::Algorithm {
        match self {
            Suite::PqHybrid768 => &kem::ML_KEM_768,
            Suite::Cnsa1024 => &kem::ML_KEM_1024,
        }
    }

    pub(crate) fn mldsa_signing(self) -> &'static signature::PqdsaSigningAlgorithm {
        match self {
            Suite::PqHybrid768 => &signature::ML_DSA_65_SIGNING,
            Suite::Cnsa1024 => &signature::ML_DSA_87_SIGNING,
        }
    }

    pub(crate) fn mldsa_verification(self) -> &'static signature::PqdsaVerificationAlgorithm {
        match self {
            Suite::PqHybrid768 => &signature::ML_DSA_65,
            Suite::Cnsa1024 => &signature::ML_DSA_87,
        }
    }

    /// Length of an ML-DSA public (verifying) key.
    pub(crate) const fn mldsa_vk_len(self) -> usize {
        match self {
            Suite::PqHybrid768 => 1952,
            Suite::Cnsa1024 => 2592,
        }
    }

    /// Length of an ML-DSA signature.
    pub(crate) const fn mldsa_sig_len(self) -> usize {
        match self {
            Suite::PqHybrid768 => 3309,
            Suite::Cnsa1024 => 4627,
        }
    }

    pub(crate) const fn has_x25519(self) -> bool {
        matches!(self, Suite::PqHybrid768)
    }

    pub(crate) const fn mlkem_ek_len(self) -> usize {
        match self {
            Suite::PqHybrid768 => 1184,
            Suite::Cnsa1024 => 1568,
        }
    }

    pub(crate) const fn mlkem_dk_len(self) -> usize {
        match self {
            Suite::PqHybrid768 => 2400,
            Suite::Cnsa1024 => 3168,
        }
    }

    pub(crate) const fn mlkem_ct_len(self) -> usize {
        match self {
            Suite::PqHybrid768 => 1088,
            Suite::Cnsa1024 => 1568,
        }
    }

    const fn x25519_len(self) -> usize {
        if self.has_x25519() { X25519_LEN } else { 0 }
    }

    /// Length of the public key bytes.
    pub(crate) const fn pk_len(self) -> usize {
        self.x25519_len() + self.mlkem_ek_len()
    }

    /// Length of the secret key bytes.
    pub(crate) const fn sk_len(self) -> usize {
        self.x25519_len() + self.mlkem_dk_len()
    }

    /// Length of a recipient stanza's KEM ciphertext.
    pub(crate) const fn kem_ct_len(self) -> usize {
        self.x25519_len() + self.mlkem_ct_len()
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
