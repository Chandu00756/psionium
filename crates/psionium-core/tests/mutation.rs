//! Random corruptions of valid files must never panic and never decrypt successfully.
//! Every byte of a `.psen` file is covered by the header MAC, key unwrapping, a chunk tag or the
//! signature, so any change at all has to be rejected.

use psionium_core::{EncryptOptions, Identity, Suite, decrypt, encrypt, encrypt_signed, inspect};

/// xorshift64*: deterministic, so a failure can be reproduced from the printed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Mutations per file and suite; raise with `PSIONIUM_MUTATIONS` for a longer campaign, and pick
/// fresh seeds with `PSIONIUM_MUTATION_SEED`.
fn iterations() -> usize {
    std::env::var("PSIONIUM_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500)
}

fn seed(base: u64) -> u64 {
    let extra = std::env::var("PSIONIUM_MUTATION_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    base ^ extra.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn mutate(rng: &mut Rng, file: &[u8]) -> Vec<u8> {
    let mut f = file.to_vec();
    match rng.below(6) {
        // Flip one bit.
        0 => {
            let i = rng.below(f.len());
            f[i] ^= 1 << rng.below(8);
        }
        // Replace one byte with a different value.
        1 => {
            let i = rng.below(f.len());
            f[i] = f[i].wrapping_add(1 + rng.below(255) as u8);
        }
        // Truncate.
        2 => f.truncate(rng.below(f.len())),
        // Insert bytes.
        3 => {
            let i = rng.below(f.len() + 1);
            let n = 1 + rng.below(32);
            let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            f.splice(i..i, bytes);
        }
        // Delete a range.
        4 => {
            let i = rng.below(f.len());
            let n = 1 + rng.below((f.len() - i).min(64));
            f.drain(i..i + n);
        }
        // Duplicate a range in place of another (chunk splicing).
        _ => {
            let a = rng.below(f.len());
            let b = rng.below(f.len());
            let n = 1 + rng.below((f.len() - a.max(b)).min(256));
            let src = f[a..a + n].to_vec();
            if f[b..b + n] == src[..] {
                f[b] ^= 0x80;
            } else {
                f[b..b + n].copy_from_slice(&src);
            }
        }
    }
    f
}

fn hammer(identity: &Identity, file: &[u8], iterations: usize, seed: u64) {
    let mut rng = Rng(seed);
    for i in 0..iterations {
        let bad = mutate(&mut rng, file);
        if bad == file {
            continue;
        }
        let mut out = Vec::new();
        let result = decrypt(identity, &bad[..], &mut out);
        assert!(
            result.is_err(),
            "mutation {i} (seed {seed:#x}) was accepted"
        );
        let _ = inspect(&bad[..]); // must not panic either
    }
}

fn sample(identity: &Identity, signed: bool) -> Vec<u8> {
    let data: Vec<u8> = (0..3 * 4096 + 123).map(|i| (i % 253) as u8).collect();
    let other = Identity::generate(identity.suite()).unwrap();
    let recipients = [other.public_key().clone(), identity.public_key().clone()];
    let opts = EncryptOptions { chunk_log2: 12 };
    let mut out = Vec::new();
    if signed {
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
    out
}

#[test]
fn random_corruptions_of_unsigned_files_are_rejected() {
    for (n, suite) in Suite::ALL.into_iter().enumerate() {
        let id = Identity::generate(suite).unwrap();
        hammer(
            &id,
            &sample(&id, false),
            iterations(),
            seed(0x5EED_0000 + n as u64),
        );
    }
}

#[test]
fn random_corruptions_of_signed_files_are_rejected() {
    for (n, suite) in Suite::ALL.into_iter().enumerate() {
        let id = Identity::generate(suite).unwrap();
        hammer(
            &id,
            &sample(&id, true),
            iterations(),
            seed(0x5EED_1000 + n as u64),
        );
    }
}

#[test]
fn garbage_input_never_panics() {
    let id = Identity::generate(Suite::default()).unwrap();
    let mut rng = Rng(0xDEAD_BEEF);
    for len in [0, 1, 4, 25, 26, 27, 100, 1000, 5000] {
        for _ in 0..50 {
            let mut junk: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if len >= 9 {
                junk[..4].copy_from_slice(b"PSEN");
                junk[4] = 2;
                junk[5] = 0;
                junk[6] = 1 + (rng.below(2) as u8);
                junk[7] = 12 + rng.below(13) as u8;
                junk[8] = rng.below(2) as u8;
            }
            let mut out = Vec::new();
            assert!(decrypt(&id, &junk[..], &mut out).is_err());
            let _ = inspect(&junk[..]);
        }
    }
}
