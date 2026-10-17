//! What to do about a finding, per algorithm, for the HTML report and SARIF rule help.

use crate::model::{Category, Finding, Primitive, Source};

/// One or two sentences on how to fix or migrate what `f` found.
pub(crate) fn guidance(f: &Finding) -> &'static str {
    let a = f.algorithm.to_ascii_uppercase();
    let has = |needle: &str| a.contains(needle);
    match f.category {
        Category::QuantumSafe => {
            "Post-quantum or hybrid cryptography. Keep it, and keep the library up to date."
        }
        Category::Review if has("AES-128") => {
            "AES-128 is fine today, but Grover's algorithm halves its strength against a quantum computer; prefer AES-256 for data that must stay secret for decades."
        }
        Category::Review => {
            "A general-purpose crypto library. Check which algorithms your code uses from it; those uses are listed separately when the scanner recognizes them."
        }
        Category::Weak if has("MD5") || has("SHA-1") => {
            "Replace with SHA-256, SHA-384 or SHA-3. For password hashing use Argon2id."
        }
        Category::Weak if has("DES") || has("RC4") => {
            "Replace with AES-256-GCM (or ChaCha20-Poly1305)."
        }
        Category::Weak if has("TLS") || has("SSL") => {
            "Allow only TLS 1.2 and 1.3, and prefer TLS 1.3 with the X25519MLKEM768 hybrid group."
        }
        Category::Weak => Category::Weak.advice(),
        Category::QuantumVulnerable => quantum_vulnerable(f, &has),
    }
}

fn quantum_vulnerable(f: &Finding, has: &dyn Fn(&str) -> bool) -> &'static str {
    if f.source == Source::PrivateKey {
        return "Move the key out of the scanned files into a secrets manager and rotate it; plan its replacement with ML-KEM (encryption) or ML-DSA (signatures).";
    }
    if f.source == Source::Tls && f.primitive == Primitive::KeyAgree {
        return "Enable the X25519MLKEM768 hybrid key exchange on this server (supported by OpenSSL 3.5+, BoringSSL, AWS-LC and Go 1.24+), so recorded traffic cannot be decrypted later.";
    }
    if f.rule == "certificate" {
        return "Certificates are replaced at renewal: keep lifetimes short, and follow your certificate authority's plans for ML-DSA. Certificates still valid after 2030 come first.";
    }
    if has("JWT") || has("JOSE") {
        return "Tokens signed with RS*, ES* or EdDSA are quantum-vulnerable; HMAC-signed tokens (HS256 and up) are not. Keep token lifetimes short and move to ML-DSA as your JOSE library adopts it.";
    }
    if has("SSH") {
        return "Turn on OpenSSH's post-quantum key exchange (mlkem768x25519-sha256 from OpenSSH 9.9, sntrup761x25519-sha512 from 9.0). Host and user keys stay classical for now.";
    }
    match f.primitive {
        Primitive::KeyAgree | Primitive::Kem => {
            "Use ML-KEM-768 (FIPS 203) for key exchange, ideally as the X25519MLKEM768 hybrid so it stays secure if either algorithm fails."
        }
        Primitive::Pke => {
            "For encryption and key transport, use ML-KEM-768 (FIPS 203), hybrid with X25519 where possible. For RSA signatures, use ML-DSA-65 (FIPS 204), or SLH-DSA (FIPS 205) for signatures that must verify for decades."
        }
        Primitive::Signature => {
            "Use ML-DSA-65 (FIPS 204) for signatures, or SLH-DSA (FIPS 205) where signatures must stay valid for decades."
        }
        _ => Category::QuantumVulnerable.advice(),
    }
}
