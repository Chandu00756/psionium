//! # psionium-core
//!
//! Post-quantum file encryption in the `.psen` v2 format.
//!
//! Files are encrypted to one or more recipients. Each recipient's copy of the file key is
//! protected by ML-KEM (FIPS 203), by default combined with X25519 so the file stays safe if
//! either algorithm is broken. The payload is AES-256-GCM in authenticated chunks, so files of
//! any size stream in constant memory and truncation or reordering is detected. Files can be
//! signed with ML-DSA (FIPS 204) so recipients can check who sent them.
//! The format is specified in `docs/psen-v2.md`.
//!
//! ```
//! use psionium_core::{decrypt, encrypt, EncryptOptions, Identity, Suite};
//!
//! let alice = Identity::generate(Suite::default())?;
//! let mut sealed = Vec::new();
//! encrypt(&[alice.public_key().clone()], &b"quarterly results"[..], &mut sealed, &EncryptOptions::default())?;
//!
//! let mut opened = Vec::new();
//! decrypt(&alice, &sealed[..], &mut opened)?;
//! assert_eq!(opened, b"quarterly results");
//! # Ok::<(), psionium_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod format;
mod keys;
mod protect;
mod sign;
mod suite;
mod wrap;

pub use error::{Error, Result};
pub use format::{
    DEFAULT_CHUNK_LOG2, Decrypted, EncryptOptions, HeaderInfo, MAGIC, MAX_CHUNK_LOG2,
    MAX_RECIPIENTS, MIN_CHUNK_LOG2, VERSION, decrypt, encrypt, encrypt_signed, encrypted_len,
    inspect,
};
pub use keys::{Identity, KEY_ID_LEN, PublicKey, hex};
pub use protect::{KdfParams, MIN_PASSPHRASE_LEN, is_protected, protect, unprotect};
pub use sign::{SEED_LEN, SigningKey, VerifyingKey};
pub use suite::Suite;
