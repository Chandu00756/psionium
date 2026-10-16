//! The `.psen` v2 container: header with recipient stanzas, then a chunked AES-256-GCM payload.
//! See `docs/psen-v2.md` for the specification.

use std::io::{self, Read, Write};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{Identity, KEY_ID_LEN, PublicKey};
use crate::suite::Suite;
use crate::wrap::{self, FILE_KEY_LEN, TAG_LEN, WRAPPED_LEN};

/// File signature.
pub const MAGIC: &[u8; 4] = b"PSEN";
/// Format version written by this crate.
pub const VERSION: u8 = 2;
/// The most recipients a file can have.
pub const MAX_RECIPIENTS: usize = 64;
/// Default chunk size, as a power of two (64 KiB).
pub const DEFAULT_CHUNK_LOG2: u8 = 16;
/// Smallest allowed chunk size, as a power of two (4 KiB).
pub const MIN_CHUNK_LOG2: u8 = 12;
/// Largest allowed chunk size, as a power of two (16 MiB).
pub const MAX_CHUNK_LOG2: u8 = 24;

const SALT_LEN: usize = 16;
const PREFIX_LEN: usize = 4 + 1 + 2 + 1 + SALT_LEN + 1;
const MAC_LEN: usize = 48;
const MAC_LABEL: &[u8] = b"psionium/v2/header-mac";
const PAYLOAD_LABEL: &[u8] = b"psionium/v2/payload";

/// Options for [`encrypt`].
#[derive(Clone, Debug)]
pub struct EncryptOptions {
    /// Plaintext chunk size as a power of two, from 12 (4 KiB) to 24 (16 MiB).
    pub chunk_log2: u8,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        EncryptOptions {
            chunk_log2: DEFAULT_CHUNK_LOG2,
        }
    }
}

/// What a file's header says, read without any key. Nothing here is authenticated.
#[derive(Clone, Debug)]
pub struct HeaderInfo {
    /// The file's algorithm suite.
    pub suite: Suite,
    /// Plaintext bytes per chunk.
    pub chunk_size: usize,
    /// Key identifiers of the recipients, in header order.
    pub recipients: Vec<[u8; KEY_ID_LEN]>,
    /// Header length in bytes; the payload follows.
    pub header_len: usize,
}

struct Stanza {
    key_id: [u8; KEY_ID_LEN],
    kem_ct: Vec<u8>,
    wrapped: Vec<u8>,
}

struct Header {
    suite: Suite,
    chunk_log2: u8,
    salt: [u8; SALT_LEN],
    stanzas: Vec<Stanza>,
    /// Every header byte before the MAC.
    authenticated: Vec<u8>,
    mac: [u8; MAC_LEN],
}

/// Encrypts `input` to `recipients`, writing a `.psen` v2 file to `output`.
/// Returns the number of plaintext bytes read.
pub fn encrypt<R: Read, W: Write>(
    recipients: &[PublicKey],
    mut input: R,
    mut output: W,
    options: &EncryptOptions,
) -> Result<u64> {
    let suite = check_recipients(recipients)?;
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&options.chunk_log2) {
        return Err(Error::ChunkSize);
    }
    let rng = SystemRandom::new();
    let mut file_key = Zeroizing::new([0u8; FILE_KEY_LEN]);
    rng.fill(file_key.as_mut())?;
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)?;

    let stanza_len = KEY_ID_LEN + suite.kem_ct_len() + WRAPPED_LEN;
    let mut header = Vec::with_capacity(PREFIX_LEN + recipients.len() * stanza_len + MAC_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&suite.id().to_be_bytes());
    header.push(options.chunk_log2);
    header.extend_from_slice(&salt);
    header.push(recipients.len() as u8);
    let prefix = header.clone();

    for recipient in recipients {
        let key_id = recipient.key_id();
        let (kem_ct, kek) = wrap::encapsulate(recipient, &salt, &key_id)?;
        let wrapped = wrap::wrap_file_key(&kek, &stanza_aad(&prefix, &key_id), &file_key)?;
        header.extend_from_slice(&key_id);
        header.extend_from_slice(&kem_ct);
        header.extend_from_slice(&wrapped);
    }
    let mac = hmac::sign(&mac_key(&salt, &file_key)?, &header);
    header.extend_from_slice(mac.as_ref());
    output.write_all(&header)?;

    let cipher = payload_cipher(&salt, &file_key)?;
    let chunk_size = 1usize << options.chunk_log2;
    let mut current = vec![0u8; chunk_size];
    let mut next = vec![0u8; chunk_size];
    let mut sealed = Vec::with_capacity(chunk_size + TAG_LEN);
    let mut counter = 0u64;
    let mut total = 0u64;
    let mut filled = read_full(&mut input, &mut current)?;
    loop {
        // A short chunk is final; a full chunk is final only if nothing follows it.
        let more = if filled == chunk_size {
            read_full(&mut input, &mut next)?
        } else {
            0
        };
        let last = more == 0;
        sealed.clear();
        sealed.extend_from_slice(&current[..filled]);
        cipher.seal_in_place_append_tag(chunk_nonce(counter, last), Aad::empty(), &mut sealed)?;
        output.write_all(&sealed)?;
        total += filled as u64;
        if last {
            break;
        }
        std::mem::swap(&mut current, &mut next);
        filled = more;
        counter += 1;
    }
    current.iter_mut().for_each(|b| *b = 0);
    next.iter_mut().for_each(|b| *b = 0);
    output.flush()?;
    Ok(total)
}

/// Decrypts a `.psen` v2 file from `input` with `identity`, writing the plaintext to `output`.
/// Returns the number of plaintext bytes written.
///
/// Plaintext is written chunk by chunk as each chunk authenticates. If an error is returned,
/// discard whatever was written: the file is only complete once its final chunk opens.
pub fn decrypt<R: Read, W: Write>(identity: &Identity, mut input: R, mut output: W) -> Result<u64> {
    let header = read_header(&mut input)?;
    if header.suite != identity.suite() {
        return Err(Error::NotARecipient);
    }
    let my_id = identity.public_key().key_id();
    let prefix = &header.authenticated[..PREFIX_LEN];
    let file_key = header
        .stanzas
        .iter()
        .filter(|s| s.key_id == my_id)
        .find_map(|s| {
            let kek = wrap::decapsulate(identity, &s.kem_ct, &header.salt, &s.key_id).ok()?;
            wrap::unwrap_file_key(&kek, &stanza_aad(prefix, &s.key_id), &s.wrapped).ok()
        })
        .ok_or(Error::NotARecipient)?;
    hmac::verify(
        &mac_key(&header.salt, &file_key)?,
        &header.authenticated,
        &header.mac,
    )
    .map_err(|_| Error::HeaderAuth)?;

    let cipher = payload_cipher(&header.salt, &file_key)?;
    let block = (1usize << header.chunk_log2) + TAG_LEN;
    let mut current = vec![0u8; block];
    let mut next = vec![0u8; block];
    let mut counter = 0u64;
    let mut total = 0u64;
    let mut filled = read_full(&mut input, &mut current)?;
    loop {
        if filled < TAG_LEN {
            return Err(Error::Truncated);
        }
        let more = if filled == block {
            read_full(&mut input, &mut next)?
        } else {
            0
        };
        let last = more == 0;
        let plain = cipher
            .open_in_place(
                chunk_nonce(counter, last),
                Aad::empty(),
                &mut current[..filled],
            )
            .map_err(|_| Error::ChunkAuth(counter))?;
        output.write_all(plain)?;
        total += plain.len() as u64;
        if last {
            break;
        }
        std::mem::swap(&mut current, &mut next);
        filled = more;
        counter += 1;
    }
    current.iter_mut().for_each(|b| *b = 0);
    next.iter_mut().for_each(|b| *b = 0);
    output.flush()?;
    Ok(total)
}

/// Reads a file's header without decrypting anything.
pub fn inspect<R: Read>(mut input: R) -> Result<HeaderInfo> {
    let header = read_header(&mut input)?;
    Ok(HeaderInfo {
        suite: header.suite,
        chunk_size: 1usize << header.chunk_log2,
        recipients: header.stanzas.iter().map(|s| s.key_id).collect(),
        header_len: header.authenticated.len() + MAC_LEN,
    })
}

/// Size of the `.psen` file produced for a plaintext of `plaintext_len` bytes.
pub fn encrypted_len(suite: Suite, recipients: usize, chunk_log2: u8, plaintext_len: u64) -> u64 {
    let chunk = 1u64 << chunk_log2;
    let chunks = if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk)
    };
    let header =
        PREFIX_LEN + recipients * (KEY_ID_LEN + suite.kem_ct_len() + WRAPPED_LEN) + MAC_LEN;
    header as u64 + plaintext_len + chunks * TAG_LEN as u64
}

fn check_recipients(recipients: &[PublicKey]) -> Result<Suite> {
    let first = recipients.first().ok_or(Error::NoRecipients)?;
    if recipients.len() > MAX_RECIPIENTS {
        return Err(Error::TooManyRecipients {
            max: MAX_RECIPIENTS,
        });
    }
    if recipients.iter().any(|r| r.suite() != first.suite()) {
        return Err(Error::MixedSuites);
    }
    Ok(first.suite())
}

fn read_header<R: Read>(input: &mut R) -> Result<Header> {
    let mut prefix = [0u8; PREFIX_LEN];
    read_exact_or(input, &mut prefix, Error::Format("the file is too short"))?;
    if &prefix[..4] != MAGIC {
        return Err(Error::Format("missing PSEN signature"));
    }
    if prefix[4] != VERSION {
        return Err(Error::Unsupported("format version"));
    }
    let suite = Suite::from_id(u16::from_be_bytes([prefix[5], prefix[6]]))?;
    let chunk_log2 = prefix[7];
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_log2) {
        return Err(Error::Format("chunk size out of range"));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&prefix[8..8 + SALT_LEN]);
    let count = prefix[PREFIX_LEN - 1] as usize;
    if count == 0 || count > MAX_RECIPIENTS {
        return Err(Error::Format("recipient count out of range"));
    }

    let stanza_len = KEY_ID_LEN + suite.kem_ct_len() + WRAPPED_LEN;
    let mut authenticated = Vec::with_capacity(PREFIX_LEN + count * stanza_len);
    authenticated.extend_from_slice(&prefix);
    let mut stanzas = Vec::with_capacity(count);
    let mut buf = vec![0u8; stanza_len];
    for _ in 0..count {
        read_exact_or(input, &mut buf, Error::Format("the header is incomplete"))?;
        authenticated.extend_from_slice(&buf);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&buf[..KEY_ID_LEN]);
        let kem_end = KEY_ID_LEN + suite.kem_ct_len();
        stanzas.push(Stanza {
            key_id,
            kem_ct: buf[KEY_ID_LEN..kem_end].to_vec(),
            wrapped: buf[kem_end..].to_vec(),
        });
    }
    let mut mac = [0u8; MAC_LEN];
    read_exact_or(input, &mut mac, Error::Format("the header is incomplete"))?;
    Ok(Header {
        suite,
        chunk_log2,
        salt,
        stanzas,
        authenticated,
        mac,
    })
}

fn stanza_aad(prefix: &[u8], key_id: &[u8; KEY_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + KEY_ID_LEN);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(key_id);
    aad
}

fn mac_key(salt: &[u8], file_key: &[u8; FILE_KEY_LEN]) -> Result<hmac::Key> {
    let mut key = Zeroizing::new([0u8; MAC_LEN]);
    wrap::hkdf_sha384(salt, file_key, &[MAC_LABEL], key.as_mut())?;
    Ok(hmac::Key::new(hmac::HMAC_SHA384, key.as_ref()))
}

fn payload_cipher(salt: &[u8], file_key: &[u8; FILE_KEY_LEN]) -> Result<LessSafeKey> {
    let mut key = Zeroizing::new([0u8; FILE_KEY_LEN]);
    wrap::hkdf_sha384(salt, file_key, &[PAYLOAD_LABEL], key.as_mut())?;
    Ok(LessSafeKey::new(UnboundKey::new(
        &AES_256_GCM,
        key.as_ref(),
    )?))
}

/// `counter` as 11 big-endian bytes, then 0x01 for the final chunk or 0x00 otherwise.
fn chunk_nonce(counter: u64, last: bool) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    Nonce::assume_unique_for_key(n)
}

/// Reads until `buf` is full or the input ends; returns the number of bytes read.
fn read_full<R: Read>(input: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn read_exact_or<R: Read>(input: &mut R, buf: &mut [u8], short: Error) -> Result<()> {
    match input.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(short),
        Err(e) => Err(Error::Io(e)),
    }
}
