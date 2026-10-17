//! Certificates, public keys and private keys stored in files. Private key material is
//! reported by type only; its contents are never copied into a report.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::model::{Category, CertificateInfo, Finding, Primitive, Source};
use crate::util::{date, fingerprint};

/// Looks for PEM blocks and SSH public keys in a text file.
pub(crate) fn scan_text(path: &str, text: &str, findings: &mut Vec<Finding>) {
    for block in pem_blocks(text) {
        match block.label.as_str() {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                if let Some(der) = decode(&block.body)
                    && let Ok((_, cert)) = parse_x509_certificate(&der)
                {
                    let info = describe_certificate(&cert);
                    findings.push(certificate_finding(
                        path,
                        Some(block.line),
                        &info,
                        Source::Certificate,
                    ));
                }
            }
            "RSA PRIVATE KEY" => {
                findings.push(private_key(path, block.line, "RSA", Primitive::Pke))
            }
            "EC PRIVATE KEY" => findings.push(private_key(
                path,
                block.line,
                "ECDSA / ECDH",
                Primitive::Signature,
            )),
            "DSA PRIVATE KEY" => {
                findings.push(private_key(path, block.line, "DSA", Primitive::Signature))
            }
            "OPENSSH PRIVATE KEY" => {
                let alg = decode(&block.body)
                    .and_then(|d| openssh_key_type(&d))
                    .unwrap_or_else(|| "unknown".into());
                findings.push(private_key(
                    path,
                    block.line,
                    &ssh_algorithm(&alg),
                    Primitive::Signature,
                ));
            }
            "PRIVATE KEY" => {
                let alg = decode(&block.body)
                    .and_then(|d| pkcs8_algorithm(&d))
                    .unwrap_or_else(|| "unknown".into());
                let (name, primitive) = oid_algorithm(&alg);
                findings.push(private_key(path, block.line, name, primitive));
            }
            "ENCRYPTED PRIVATE KEY" => findings.push(private_key(
                path,
                block.line,
                "encrypted (algorithm hidden)",
                Primitive::Other,
            )),
            "RSA PUBLIC KEY" => findings.push(public_key(path, block.line, "RSA", None)),
            "PUBLIC KEY" => {
                let (name, bits) = decode(&block.body)
                    .and_then(|d| {
                        SubjectPublicKeyInfo::from_der(&d)
                            .ok()
                            .map(|(_, spki)| key_description(&spki))
                    })
                    .unwrap_or_else(|| ("unknown".into(), None));
                findings.push(public_key(path, block.line, &name, bits));
            }
            _ => {}
        }
    }
    for (i, line) in text.lines().enumerate() {
        if let Some((alg, bits)) = ssh_public_key(line) {
            findings.push(public_key(path, i + 1, &alg, bits));
        }
    }
}

/// Describes a parsed certificate.
pub(crate) fn describe_certificate(cert: &X509Certificate<'_>) -> CertificateInfo {
    let (key_algorithm, key_bits) = key_description(cert.public_key());
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let (sig_name, _) = oid_algorithm(&sig_oid);
    CertificateInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        quantum_safe: is_pq_name(&key_algorithm),
        key_algorithm,
        key_bits,
        signature_algorithm: sig_name.to_string(),
        not_before: date(cert.validity().not_before.timestamp()),
        not_after: date(cert.validity().not_after.timestamp()),
    }
}

/// Turns a certificate into a finding, noting validity past the 2030 deprecation date.
pub(crate) fn certificate_finding(
    location: &str,
    line: Option<usize>,
    info: &CertificateInfo,
    source: Source,
) -> Finding {
    let size = info.key_bits.map(|b| format!("-{b}")).unwrap_or_default();
    let mut detail = format!(
        "{}{} key, signed with {}, valid until {}; subject {}",
        info.key_algorithm, size, info.signature_algorithm, info.not_after, info.subject
    );
    if !info.quantum_safe && info.not_after.as_str() >= "2031-01-01" {
        detail.push_str(" (still valid after NIST deprecates this algorithm in 2030)");
    }
    Finding {
        category: if info.quantum_safe {
            Category::QuantumSafe
        } else {
            Category::QuantumVulnerable
        },
        algorithm: info.key_algorithm.clone(),
        primitive: Primitive::Signature,
        nist_quantum_level: if info.quantum_safe { None } else { Some(0) },
        source,
        location: location.to_string(),
        line,
        fingerprint: fingerprint("certificate", location, &detail),
        detail,
        rule: "certificate".into(),
        root: 0,
    }
}

fn private_key(path: &str, line: usize, algorithm: &str, primitive: Primitive) -> Finding {
    let pq = is_pq_name(algorithm);
    let detail = format!(
        "{algorithm} private key stored in the scanned files; move it to a secrets manager and rotate it"
    );
    Finding {
        category: if pq {
            Category::QuantumSafe
        } else {
            Category::QuantumVulnerable
        },
        algorithm: algorithm.to_string(),
        primitive,
        nist_quantum_level: if pq { None } else { Some(0) },
        source: Source::PrivateKey,
        location: path.to_string(),
        line: Some(line),
        fingerprint: fingerprint("private-key", path, &detail),
        detail,
        rule: "private-key".into(),
        root: 0,
    }
}

fn public_key(path: &str, line: usize, algorithm: &str, bits: Option<usize>) -> Finding {
    let pq = is_pq_name(algorithm);
    let detail = match bits {
        Some(b) => format!("{algorithm}-{b} public key"),
        None => format!("{algorithm} public key"),
    };
    Finding {
        category: if pq {
            Category::QuantumSafe
        } else {
            Category::QuantumVulnerable
        },
        algorithm: algorithm.to_string(),
        primitive: Primitive::Signature,
        nist_quantum_level: if pq { None } else { Some(0) },
        source: Source::PublicKey,
        location: path.to_string(),
        line: Some(line),
        fingerprint: fingerprint("public-key", path, &detail),
        detail,
        rule: "public-key".into(),
        root: 0,
    }
}

fn is_pq_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.contains("ML-DSA") || n.contains("ML-KEM") || n.contains("SLH-DSA")
}

struct PemBlock {
    label: String,
    body: String,
    line: usize,
}

fn pem_blocks(text: &str) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<PemBlock> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            current = Some(PemBlock {
                label: label.to_string(),
                body: String::new(),
                line: i + 1,
            });
        } else if line.starts_with("-----END ") {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
        } else if let Some(b) = current.as_mut()
            && !line.contains(':')
        {
            b.body.push_str(line);
        }
    }
    blocks
}

fn decode(body: &str) -> Option<Vec<u8>> {
    STANDARD.decode(body.trim()).ok()
}

/// Name and size of a SubjectPublicKeyInfo's key.
fn key_description(spki: &SubjectPublicKeyInfo<'_>) -> (String, Option<usize>) {
    let oid = spki.algorithm.algorithm.to_id_string();
    if oid == "1.2.840.10045.2.1" {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|o| curve_name(&o.to_id_string()))
            .unwrap_or("unknown curve");
        // The curve name already says the size.
        return (format!("ECDSA {curve}"), None);
    }
    let (name, _) = oid_algorithm(&oid);
    let bits = match spki.parsed() {
        Ok(PublicKey::RSA(_)) | Ok(PublicKey::DSA(_)) => spki.parsed().ok().map(|k| k.key_size()),
        _ => None,
    };
    (name.to_string(), bits)
}

fn curve_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.10" => "secp256k1",
        "1.2.840.10045.3.1.1" => "P-192",
        "1.3.132.0.33" => "P-224",
        _ => "unknown curve",
    }
}

/// Algorithm name and primitive for a public key or signature algorithm OID.
fn oid_algorithm(oid: &str) -> (&'static str, Primitive) {
    use Primitive::*;
    match oid {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => ("RSA", Pke),
        "1.2.840.113549.1.1.5" => ("RSA with SHA-1", Signature),
        "1.2.840.113549.1.1.11" => ("RSA with SHA-256", Signature),
        "1.2.840.113549.1.1.12" => ("RSA with SHA-384", Signature),
        "1.2.840.113549.1.1.13" => ("RSA with SHA-512", Signature),
        "1.2.840.10045.2.1" => ("ECDSA", Signature),
        "1.2.840.10045.4.1" => ("ECDSA with SHA-1", Signature),
        "1.2.840.10045.4.3.2" => ("ECDSA with SHA-256", Signature),
        "1.2.840.10045.4.3.3" => ("ECDSA with SHA-384", Signature),
        "1.2.840.10045.4.3.4" => ("ECDSA with SHA-512", Signature),
        "1.2.840.10040.4.1" => ("DSA", Signature),
        "1.3.101.110" => ("X25519", KeyAgree),
        "1.3.101.111" => ("X448", KeyAgree),
        "1.3.101.112" => ("Ed25519", Signature),
        "1.3.101.113" => ("Ed448", Signature),
        "2.16.840.1.101.3.4.3.17" => ("ML-DSA-44", Signature),
        "2.16.840.1.101.3.4.3.18" => ("ML-DSA-65", Signature),
        "2.16.840.1.101.3.4.3.19" => ("ML-DSA-87", Signature),
        "2.16.840.1.101.3.4.4.1" => ("ML-KEM-512", Kem),
        "2.16.840.1.101.3.4.4.2" => ("ML-KEM-768", Kem),
        "2.16.840.1.101.3.4.4.3" => ("ML-KEM-1024", Kem),
        o if o.starts_with("2.16.840.1.101.3.4.3.") => ("SLH-DSA", Signature),
        _ => ("unknown", Other),
    }
}

/// Reads the algorithm OID of a PKCS#8 PrivateKeyInfo without touching the key itself.
fn pkcs8_algorithm(der: &[u8]) -> Option<String> {
    // PrivateKeyInfo ::= SEQUENCE { version INTEGER, privateKeyAlgorithm AlgorithmIdentifier, ... }
    let (_, body) = der_tlv(der, 0x30)?;
    let (rest, _) = der_tlv(body, 0x02)?;
    let (_, alg) = der_tlv(rest, 0x30)?;
    let (_, oid) = der_tlv(alg, 0x06)?;
    Some(oid_to_string(oid))
}

/// Returns (bytes after the element, element contents) if `input` starts with `tag`.
fn der_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((&rest[len..], &rest[..len]))
}

fn oid_to_string(bytes: &[u8]) -> String {
    let mut ids = Vec::new();
    let mut v = 0u64;
    for b in bytes {
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            ids.push(v);
            v = 0;
        }
    }
    let mut parts = Vec::with_capacity(ids.len() + 1);
    if let Some((&first, rest)) = ids.split_first() {
        // The first sub-identifier encodes the first two arcs.
        if first < 80 {
            parts.extend([first / 40, first % 40]);
        } else {
            parts.extend([2, first - 80]);
        }
        parts.extend_from_slice(rest);
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The key type string from an `openssh-key-v1` private key container (public section only).
fn openssh_key_type(data: &[u8]) -> Option<String> {
    let rest = data.strip_prefix(b"openssh-key-v1\0")?;
    let (_, rest) = ssh_string(rest)?; // cipher
    let (_, rest) = ssh_string(rest)?; // kdf name
    let (_, rest) = ssh_string(rest)?; // kdf options
    let rest = rest.get(4..)?; // number of keys
    let (public, _) = ssh_string(rest)?;
    let (kind, _) = ssh_string(public)?;
    String::from_utf8(kind.to_vec()).ok()
}

fn ssh_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let body = input.get(4..4 + len)?;
    Some((body, &input[4 + len..]))
}

fn ssh_algorithm(kind: &str) -> String {
    match kind {
        "ssh-rsa" => "RSA".into(),
        "ssh-dss" => "DSA".into(),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => "Ed25519".into(),
        k if k.starts_with("ecdsa-sha2-") || k.starts_with("sk-ecdsa-sha2-") => "ECDSA".into(),
        other => other.to_string(),
    }
}

/// An SSH public key line (`authorized_keys`, `*.pub`, `known_hosts`): algorithm and RSA size.
fn ssh_public_key(line: &str) -> Option<(String, Option<usize>)> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    // known_hosts lines start with the host pattern; authorized_keys may start with options.
    let (kind, blob) = loop {
        let token = parts.next()?;
        if token.starts_with("ssh-") || token.starts_with("ecdsa-sha2-") || token.starts_with("sk-")
        {
            break (token, parts.next()?);
        }
    };
    let data = STANDARD.decode(blob).ok()?;
    let (embedded, rest) = ssh_string(&data)?;
    if embedded != kind.as_bytes() {
        return None;
    }
    let bits = if kind == "ssh-rsa" {
        let (_e, rest) = ssh_string(rest)?;
        let (n, _) = ssh_string(rest)?;
        let n = n.iter().skip_while(|b| **b == 0).count();
        Some(n * 8)
    } else {
        None
    };
    Some((ssh_algorithm(kind), bits))
}
