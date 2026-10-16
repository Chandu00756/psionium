use serde::Serialize;

/// How a finding bears on quantum readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Public-key cryptography that a quantum computer breaks (RSA, elliptic curves, DH, DSA).
    QuantumVulnerable,
    /// Classically weak cryptography that should be replaced regardless of quantum risk.
    Weak,
    /// Worth reviewing, such as a general crypto library or a 128-bit key.
    Review,
    /// Post-quantum cryptography already in place.
    QuantumSafe,
}

impl Category {
    /// A heading for reports.
    pub fn title(self) -> &'static str {
        match self {
            Category::QuantumVulnerable => "Quantum-vulnerable",
            Category::Weak => "Weak classical cryptography",
            Category::Review => "Review",
            Category::QuantumSafe => "Already post-quantum",
        }
    }

    /// One sentence on what to do.
    pub fn advice(self) -> &'static str {
        match self {
            Category::QuantumVulnerable => {
                "Broken by a large quantum computer. Plan migration to ML-KEM (key exchange) and ML-DSA (signatures); NIST deprecates these after 2030 and disallows them after 2035."
            }
            Category::Weak => {
                "Weak even today. Replace now: SHA-256 or better for hashing, AES-256-GCM for encryption, TLS 1.2+."
            }
            Category::Review => "Not a problem on its own; check how it is used.",
            Category::QuantumSafe => "Post-quantum or hybrid cryptography. Keep it.",
        }
    }
}

/// What kind of thing a finding was found in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// A line of source code or configuration.
    Code,
    /// A dependency in a package manifest.
    Dependency,
    /// An X.509 certificate.
    Certificate,
    /// A public key (for example an SSH key).
    PublicKey,
    /// Private key material stored in the scanned files.
    PrivateKey,
    /// A live TLS endpoint.
    Tls,
}

/// The cryptographic primitive, as CycloneDX names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    /// Public-key encryption (RSA).
    Pke,
    /// Digital signatures.
    Signature,
    /// Key agreement (ECDH, DH, X25519).
    KeyAgree,
    /// Key encapsulation (ML-KEM).
    Kem,
    /// Hash function.
    Hash,
    /// Block cipher.
    BlockCipher,
    /// Stream cipher.
    StreamCipher,
    /// Authenticated encryption.
    Ae,
    /// Protocol or anything else.
    Other,
}

impl Primitive {
    /// The CycloneDX 1.6 `primitive` value.
    pub fn cyclonedx(self) -> &'static str {
        match self {
            Primitive::Pke => "pke",
            Primitive::Signature => "signature",
            Primitive::KeyAgree => "key-agree",
            Primitive::Kem => "kem",
            Primitive::Hash => "hash",
            Primitive::BlockCipher => "block-cipher",
            Primitive::StreamCipher => "stream-cipher",
            Primitive::Ae => "ae",
            Primitive::Other => "other",
        }
    }
}

/// One thing the scan found.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    /// How it bears on quantum readiness.
    pub category: Category,
    /// The algorithm or library, such as `RSA`, `ECDSA` or `ML-KEM`.
    pub algorithm: String,
    /// The primitive it provides.
    pub primitive: Primitive,
    /// NIST post-quantum security category (0 means broken by a quantum computer), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist_quantum_level: Option<u8>,
    /// Where it was found.
    pub source: Source,
    /// File path or `host:port`.
    pub location: String,
    /// 1-based line number for code findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// What matched or what was found, never secret material.
    pub detail: String,
    /// The rule that produced the finding.
    pub rule: String,
}

/// The result of probing one TLS endpoint.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TlsResult {
    /// `host:port` as given.
    pub target: String,
    /// Whether any handshake succeeded.
    pub reachable: bool,
    /// Why the endpoint could not be checked, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether the server accepts the X25519MLKEM768 hybrid post-quantum key exchange.
    pub post_quantum_key_exchange: bool,
    /// Negotiated TLS version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Negotiated cipher suite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// Key exchange group chosen when classical groups are also offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_group: Option<String>,
    /// The server's leaf certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateInfo>,
    /// Whether the certificate chain is trusted by the Mozilla root store for this host name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

/// What a certificate says about its keys and lifetime.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CertificateInfo {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Public key algorithm, such as `RSA` or `ECDSA P-256`.
    pub key_algorithm: String,
    /// Public key size in bits, when meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<usize>,
    /// Signature algorithm of the certificate.
    pub signature_algorithm: String,
    /// Start of validity, as `YYYY-MM-DD`.
    pub not_before: String,
    /// End of validity, as `YYYY-MM-DD`.
    pub not_after: String,
    /// Whether the key resists quantum attack.
    pub quantum_safe: bool,
}
