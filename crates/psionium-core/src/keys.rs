use std::fmt;
use std::str::FromStr;

use aws_lc_rs::agreement;
use aws_lc_rs::digest;
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::kem;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::sign::{SigningKey, VerifyingKey};
use crate::suite::{Suite, X25519_LEN};

const PUBLIC_PREFIX: &str = "psionpk:";
const SECRET_PREFIX: &str = "psionsk:";

/// Length of a recipient key identifier.
pub const KEY_ID_LEN: usize = 16;

/// A recipient's public key. Share it freely; files are encrypted to it.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    suite: Suite,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Builds a public key from its suite and raw bytes, checking that they are well formed.
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != suite.pk_len() {
            return Err(Error::Key("public key has the wrong length for its suite"));
        }
        let key = PublicKey {
            suite,
            bytes: bytes.to_vec(),
        };
        // Reject encapsulation keys that ML-KEM's input checks refuse.
        kem::EncapsulationKey::new(suite.kem(), key.mlkem_ek())
            .map_err(|_| Error::Key("ML-KEM public key is malformed"))?;
        Ok(key)
    }

    /// The key's algorithm suite.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The raw public key bytes (without the suite).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `SHA-384(suite ‖ public key)` truncated to 16 bytes; it names the key in file headers.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut ctx = digest::Context::new(&digest::SHA384);
        ctx.update(&self.suite.id().to_be_bytes());
        ctx.update(&self.bytes);
        let d = ctx.finish();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&d.as_ref()[..KEY_ID_LEN]);
        id
    }

    pub(crate) fn x25519(&self) -> Option<&[u8]> {
        self.suite.has_x25519().then(|| &self.bytes[..X25519_LEN])
    }

    pub(crate) fn mlkem_ek(&self) -> &[u8] {
        let start = if self.suite.has_x25519() {
            X25519_LEN
        } else {
            0
        };
        &self.bytes[start..]
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = Vec::with_capacity(2 + self.bytes.len());
        raw.extend_from_slice(&self.suite.id().to_be_bytes());
        raw.extend_from_slice(&self.bytes);
        write!(f, "{PUBLIC_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("suite", &self.suite)
            .field("key_id", &hex(&self.key_id()))
            .finish()
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(PUBLIC_PREFIX)
            .ok_or(Error::Key("public keys start with \"psionpk:\""))?;
        let raw = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Error::Key("public key is not valid base64url"))?;
        let (suite, bytes) = split_suite(&raw)?;
        PublicKey::from_bytes(suite, bytes)
    }
}

/// A secret identity: the private half of a key pair. Decrypts files sent to its public key.
pub struct Identity {
    suite: Suite,
    x25519: Option<agreement::PrivateKey>,
    mlkem: kem::DecapsulationKey,
    public: PublicKey,
    signing: Option<SigningKey>,
}

impl Identity {
    /// Generates a new identity for a suite, with an encryption key pair and a signing key.
    pub fn generate(suite: Suite) -> Result<Self> {
        let x25519 = if suite.has_x25519() {
            Some(agreement::PrivateKey::generate(&agreement::X25519)?)
        } else {
            None
        };
        let mlkem = kem::DecapsulationKey::generate(suite.kem())?;
        let ek = mlkem.encapsulation_key()?.key_bytes()?;
        let mut identity = Identity::assemble(suite, x25519, mlkem, ek.as_ref())?;
        identity.signing = Some(SigningKey::generate(suite)?);
        Ok(identity)
    }

    fn assemble(
        suite: Suite,
        x25519: Option<agreement::PrivateKey>,
        mlkem: kem::DecapsulationKey,
        mlkem_ek: &[u8],
    ) -> Result<Self> {
        let mut pk = Vec::with_capacity(suite.pk_len());
        if let Some(x) = &x25519 {
            pk.extend_from_slice(x.compute_public_key()?.as_ref());
        }
        pk.extend_from_slice(mlkem_ek);
        let public = PublicKey::from_bytes(suite, &pk)?;
        Ok(Identity {
            suite,
            x25519,
            mlkem,
            public,
            signing: None,
        })
    }

    /// The identity's suite.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The public key that files are encrypted to.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The signing key used to sign files sent from this identity, if it has one.
    pub fn signing_key(&self) -> Option<&SigningKey> {
        self.signing.as_ref()
    }

    /// The public key others use to check this identity's signatures, if it has a signing key.
    pub fn verifying_key(&self) -> Option<&VerifyingKey> {
        self.signing.as_ref().map(SigningKey::verifying_key)
    }

    /// The secret decryption key as text (`psionsk:…`). Keep it secret.
    pub fn to_secret_string(&self) -> Result<Zeroizing<String>> {
        let mut raw = Zeroizing::new(Vec::with_capacity(2 + self.suite.sk_len()));
        raw.extend_from_slice(&self.suite.id().to_be_bytes());
        if let Some(x) = &self.x25519 {
            let seed: Curve25519SeedBin<'static> =
                AsBigEndian::<Curve25519SeedBin<'static>>::as_be_bytes(x)?;
            raw.extend_from_slice(seed.as_ref());
        }
        raw.extend_from_slice(self.mlkem.key_bytes()?.as_ref());
        Ok(Zeroizing::new(format!(
            "{SECRET_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&*raw)
        )))
    }

    /// Parses a secret key written by [`Identity::to_secret_string`].
    pub fn from_secret_str(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(SECRET_PREFIX)
            .ok_or(Error::Key("secret keys start with \"psionsk:\""))?;
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Error::Key("secret key is not valid base64url"))?,
        );
        let (suite, sk) = split_suite(&raw)?;
        if sk.len() != suite.sk_len() {
            return Err(Error::Key("secret key has the wrong length for its suite"));
        }
        let (x_bytes, dk_bytes) = sk.split_at(if suite.has_x25519() { X25519_LEN } else { 0 });
        let x25519 = if suite.has_x25519() {
            Some(
                agreement::PrivateKey::from_private_key(&agreement::X25519, x_bytes)
                    .map_err(|_| Error::Key("X25519 secret key is malformed"))?,
            )
        } else {
            None
        };
        let ek = embedded_encapsulation_key(suite, dk_bytes)?;
        let mlkem = kem::DecapsulationKey::new(suite.kem(), dk_bytes)
            .map_err(|_| Error::Key("ML-KEM secret key is malformed"))?;
        Identity::assemble(suite, x25519, mlkem, ek)
    }

    /// The contents of an identity file: comments with the public keys, then the secret keys.
    pub fn to_file_contents(&self, created: &str) -> Result<Zeroizing<String>> {
        let secret = self.to_secret_string()?;
        let mut out = Zeroizing::new(format!(
            "# pSIONIUM identity. Keep this file secret: anyone with it can decrypt your files.\n\
             # created: {created}\n\
             # suite: {} ({})\n\
             # public key: {}\n",
            self.suite.name(),
            self.suite.description(),
            self.public,
        ));
        if let Some(signing) = &self.signing {
            out.push_str(&format!("# verify key: {}\n", signing.verifying_key()));
        }
        out.push_str(&secret);
        out.push('\n');
        if let Some(signing) = &self.signing {
            out.push_str(&signing.to_secret_string());
            out.push('\n');
        }
        Ok(out)
    }

    /// Reads an identity file: the first `psionsk:` line is the decryption key and the first
    /// `psionss:` line, if any, is the signing key.
    pub fn from_file_contents(contents: &str) -> Result<Self> {
        let mut lines = contents.lines().map(str::trim);
        let line = lines
            .clone()
            .find(|l| l.starts_with(SECRET_PREFIX))
            .ok_or(Error::Key(
                "no \"psionsk:\" line found in the identity file",
            ))?;
        let mut identity = Identity::from_secret_str(line)?;
        if let Some(sig_line) = lines.find(|l| SigningKey::is_signing_prefix(l)) {
            let signing = SigningKey::from_secret_str(sig_line)?;
            if signing.suite() != identity.suite {
                return Err(Error::Key(
                    "the signing key's suite differs from the identity's",
                ));
            }
            identity.signing = Some(signing);
        }
        Ok(identity)
    }

    pub(crate) fn x25519(&self) -> Option<&agreement::PrivateKey> {
        self.x25519.as_ref()
    }

    pub(crate) fn mlkem(&self) -> &kem::DecapsulationKey {
        &self.mlkem
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// An ML-KEM decapsulation key (FIPS 203, Algorithm 16) is `dk_pke ‖ ek ‖ H(ek) ‖ z`, where
/// `dk_pke` is 384·k bytes, `ek` is 384·k + 32 bytes and `H` is SHA3-256. Returns `ek` after
/// checking `H(ek)`, which also catches a corrupted secret key.
fn embedded_encapsulation_key(suite: Suite, dk: &[u8]) -> Result<&[u8]> {
    let dk_pke_len = suite.mlkem_ek_len() - 32;
    let ek_end = dk_pke_len + suite.mlkem_ek_len();
    if dk.len() != suite.mlkem_dk_len() || dk.len() != ek_end + 64 {
        return Err(Error::Key("ML-KEM secret key has the wrong length"));
    }
    let ek = &dk[dk_pke_len..ek_end];
    let hash = digest::digest(&digest::SHA3_256, ek);
    if hash.as_ref() != &dk[ek_end..ek_end + 32] {
        return Err(Error::Key(
            "ML-KEM secret key is corrupt (public key hash mismatch)",
        ));
    }
    Ok(ek)
}

pub(crate) fn split_suite(raw: &[u8]) -> Result<(Suite, &[u8])> {
    if raw.len() < 2 {
        return Err(Error::Key("key is too short"));
    }
    let suite = Suite::from_id(u16::from_be_bytes([raw[0], raw[1]]))?;
    Ok((suite, &raw[2..]))
}

/// Lowercase hex, for printing key identifiers.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
