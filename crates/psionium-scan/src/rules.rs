//! Patterns for cryptography in source code and configuration, and known crypto libraries in
//! dependency manifests.

use std::sync::LazyLock;

use regex::Regex;

use crate::model::{Category, Primitive};

/// A pattern that marks cryptographic usage on a line of code.
pub(crate) struct CodeRule {
    pub id: &'static str,
    pub algorithm: &'static str,
    pub category: Category,
    pub primitive: Primitive,
    pub nist_level: Option<u8>,
    pub pattern: Regex,
    /// A line that also matches this is not reported by the rule (for example hybrid
    /// post-quantum group names that contain "X25519").
    pub unless: Option<Regex>,
}

fn rule(
    id: &'static str,
    algorithm: &'static str,
    category: Category,
    primitive: Primitive,
    nist_level: Option<u8>,
    pattern: &str,
    unless: Option<&str>,
) -> CodeRule {
    CodeRule {
        id,
        algorithm,
        category,
        primitive,
        nist_level,
        pattern: Regex::new(pattern).unwrap_or_else(|e| panic!("rule {id}: {e}")),
        unless: unless.map(|u| Regex::new(u).unwrap_or_else(|e| panic!("rule {id}: {e}"))),
    }
}

const PQ_HYBRID: &str = r"(?i)mlkem|ml-kem|ml_kem|kyber";

/// Rules for source code and configuration files, most specific first.
pub(crate) static CODE_RULES: LazyLock<Vec<CodeRule>> = LazyLock::new(|| {
    use Category::*;
    use Primitive::*;
    vec![
        // Post-quantum algorithms already in use.
        rule(
            "pq-hybrid-tls",
            "X25519MLKEM768 (hybrid)",
            QuantumSafe,
            Kem,
            Some(3),
            r"\b(?:X25519MLKEM768|X25519Kyber768\w*|SecP256r1MLKEM768|SECP256R1MLKEM768|x25519_mlkem768)\b",
            None,
        ),
        rule(
            "ml-kem",
            "ML-KEM",
            QuantumSafe,
            Kem,
            Some(3),
            r"(?i)\b(?:ml[-_]?kem\w*|kyber\w*)",
            Some(r"(?i)x25519mlkem|x25519kyber"),
        ),
        rule(
            "ml-dsa",
            "ML-DSA",
            QuantumSafe,
            Signature,
            Some(3),
            r"(?i)\b(?:ml[-_]?dsa\w*|dilithium\w*)",
            None,
        ),
        rule(
            "slh-dsa",
            "SLH-DSA",
            QuantumSafe,
            Signature,
            Some(1),
            r"(?i)\b(?:slh[-_]?dsa\w*|sphincs\+?\w*)\b",
            None,
        ),
        rule(
            "fn-dsa",
            "FN-DSA (Falcon)",
            QuantumSafe,
            Signature,
            Some(1),
            r"(?i)\b(?:fn[-_]?dsa|falcon[-_]?(?:512|1024))\b",
            None,
        ),
        rule(
            "stateful-hash-sig",
            "XMSS / LMS",
            QuantumSafe,
            Signature,
            Some(1),
            r"\b(?:XMSS\w*|LMS_SHA256\w*|LMS_SHAKE\w*)\b",
            None,
        ),
        // Quantum-vulnerable public-key cryptography.
        rule(
            "rsa",
            "RSA",
            QuantumVulnerable,
            Pke,
            Some(0),
            r"\bRSA(?:[A-Z_/][A-Za-z0-9_/]*)?\b|\bRsa(?:PrivateKey|PublicKey|KeyPair|Cryptography|Pkcs1v15\w*|Oaep\w*)\b",
            None,
        ),
        rule(
            "rsa-api",
            "RSA",
            QuantumVulnerable,
            Pke,
            Some(0),
            r#"\brsa\.(?:GenerateKey|GenerateMultiPrimeKey|EncryptPKCS1v15|EncryptOAEP|DecryptPKCS1v15|DecryptOAEP|SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS|generate_private_key|newkeys|PrivateKey|PublicKey)\b|generateKeyPair(?:Sync)?\(\s*['"]rsa|\b(?:genrsa|ssh-rsa)\b|-t\s+rsa\b|\brsa:\d{3,4}\b"#,
            None,
        ),
        rule(
            "ecdsa",
            "ECDSA",
            QuantumVulnerable,
            Signature,
            Some(0),
            r#"\bECDSA\w*|\bEcdsa\w*|\becdsa\.(?:GenerateKey|Sign|SignASN1|Verify|VerifyASN1)\b|\becdsa-sha2-nistp\d+\b|\bES(?:256|384|512)\b"#,
            None,
        ),
        rule(
            "ecdh",
            "ECDH",
            QuantumVulnerable,
            KeyAgree,
            Some(0),
            r"\bECDHE?\w*|\bEcdh\w*|\becdh\b",
            None,
        ),
        rule(
            "ec-curves",
            "Elliptic curve (NIST P / secp)",
            QuantumVulnerable,
            Signature,
            Some(0),
            r#"\bsecp(?:192|224|256|384|521)[rk]1\b|\bprime256v1\b|\bnistp(?:256|384|521)\b|\belliptic\.P(?:224|256|384|521)\(|\bNIST[ _]?P-?(?:256|384|521)\b|\bec\.generate_private_key\b|generateKeyPair(?:Sync)?\(\s*['"]ec['"]|getInstance\(\s*"EC"|\bssl_ecdh_curve\b"#,
            None,
        ),
        rule(
            "eddsa",
            "EdDSA (Ed25519 / Ed448)",
            QuantumVulnerable,
            Signature,
            Some(0),
            r"\b(?:Ed25519|ed25519|ED25519|Ed448|ed448)\w*",
            None,
        ),
        rule(
            "x25519",
            "X25519 / X448 (ECDH)",
            QuantumVulnerable,
            KeyAgree,
            Some(0),
            r"\b(?:X25519|x25519|X448|x448|Curve25519|curve25519)\w*",
            Some(PQ_HYBRID),
        ),
        rule(
            "dh",
            "Diffie-Hellman",
            QuantumVulnerable,
            KeyAgree,
            Some(0),
            r#"\b(?:DiffieHellman\w*|createDiffieHellman\w*|DH_generate_key|dhparam|ffdhe\d+)\b|getInstance\(\s*"DH"|\bdh\.GenerateKey\b"#,
            None,
        ),
        rule(
            "dsa",
            "DSA",
            QuantumVulnerable,
            Signature,
            Some(0),
            r#"\bDSA\b|getInstance\(\s*"DSA"|\bdsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\b|\bssh-dss\b"#,
            Some(r"(?i)(?:ml|slh|fn)[-_]?dsa"),
        ),
        // Weak classical cryptography.
        rule(
            "md5",
            "MD5",
            Category::Weak,
            Hash,
            None,
            r#"\bMD5\b|\bmd5\b|\bMd5\b|createHash\(\s*['"]md5"#,
            None,
        ),
        rule(
            "sha1",
            "SHA-1",
            Category::Weak,
            Hash,
            None,
            r#"\bSHA-?1\b|\bsha1\b|\bSha1\b|createHash\(\s*['"]sha1"#,
            None,
        ),
        rule(
            "des",
            "DES / 3DES",
            Category::Weak,
            BlockCipher,
            None,
            r"\b(?:DES|3DES|TripleDES|DESede|DES_ede3\w*|des-ede3\w*|des_ede3\w*)\b",
            None,
        ),
        rule(
            "rc4",
            "RC4",
            Category::Weak,
            StreamCipher,
            None,
            r"\b(?:RC4|ARC4|arcfour)\b",
            None,
        ),
        rule(
            "old-tls",
            "TLS 1.0 / 1.1 / SSL",
            Category::Weak,
            Other,
            None,
            r"\bTLSv1(?:\.[01])?(?:[^.\d]|$)|\bSSLv[23]\b|\bVersionTLS1[01]\b|\bTLS1_[01]_VERSION\b",
            None,
        ),
        // Worth reviewing.
        rule(
            "aes-128",
            "AES-128",
            Category::Review,
            BlockCipher,
            Some(1),
            r"(?i)\baes[-_]?128\w*",
            None,
        ),
    ]
});

/// A library in a package manifest that provides or implies cryptography.
pub(crate) struct DependencyRule {
    pub name: &'static str,
    pub algorithm: &'static str,
    pub category: Category,
    pub primitive: Primitive,
}

const fn dep(
    name: &'static str,
    algorithm: &'static str,
    category: Category,
    primitive: Primitive,
) -> DependencyRule {
    DependencyRule {
        name,
        algorithm,
        category,
        primitive,
    }
}

/// Crypto libraries by package name, across npm, PyPI, Go, crates.io and Maven.
pub(crate) const DEPENDENCY_RULES: &[DependencyRule] = {
    use Category::*;
    use Primitive::*;
    &[
        // npm
        dep("node-rsa", "RSA", QuantumVulnerable, Pke),
        dep("jsrsasign", "RSA / ECDSA", QuantumVulnerable, Signature),
        dep("elliptic", "Elliptic curves", QuantumVulnerable, Signature),
        dep(
            "tweetnacl",
            "Curve25519 / Ed25519",
            QuantumVulnerable,
            KeyAgree,
        ),
        dep(
            "@noble/curves",
            "Elliptic curves",
            QuantumVulnerable,
            Signature,
        ),
        dep("@noble/ed25519", "Ed25519", QuantumVulnerable, Signature),
        dep(
            "@noble/secp256k1",
            "secp256k1",
            QuantumVulnerable,
            Signature,
        ),
        dep(
            "@noble/post-quantum",
            "ML-KEM / ML-DSA / SLH-DSA",
            QuantumSafe,
            Kem,
        ),
        dep("node-forge", "RSA and general crypto", Review, Other),
        dep(
            "jsonwebtoken",
            "JWT (RSA / ECDSA / HMAC)",
            Review,
            Signature,
        ),
        dep("jose", "JOSE (RSA / ECDSA / EdDSA)", Review, Signature),
        dep(
            "crypto-js",
            "Legacy algorithms (MD5, SHA-1, DES)",
            Category::Weak,
            Other,
        ),
        dep("openpgp", "OpenPGP (RSA / ECC)", QuantumVulnerable, Pke),
        // PyPI
        dep("rsa", "RSA", QuantumVulnerable, Pke),
        dep("ecdsa", "ECDSA", QuantumVulnerable, Signature),
        dep("pycryptodome", "RSA, ECC and general crypto", Review, Other),
        dep(
            "pycryptodomex",
            "RSA, ECC and general crypto",
            Review,
            Other,
        ),
        dep(
            "cryptography",
            "General crypto (RSA, ECC, ML-KEM in recent versions)",
            Review,
            Other,
        ),
        dep("pyjwt", "JWT (RSA / ECDSA / HMAC)", Review, Signature),
        dep("python-jose", "JOSE (RSA / ECDSA)", Review, Signature),
        dep(
            "paramiko",
            "SSH (RSA / ECDSA / Ed25519)",
            QuantumVulnerable,
            Signature,
        ),
        dep(
            "pynacl",
            "Curve25519 / Ed25519",
            QuantumVulnerable,
            KeyAgree,
        ),
        dep("liboqs-python", "Open Quantum Safe", QuantumSafe, Kem),
        dep("oqs", "Open Quantum Safe", QuantumSafe, Kem),
        dep("pqcrypto", "Post-quantum algorithms", QuantumSafe, Kem),
        dep("kyber-py", "ML-KEM", QuantumSafe, Kem),
        // Go
        dep(
            "golang.org/x/crypto",
            "General crypto (SSH, Curve25519, ...)",
            Review,
            Other,
        ),
        dep(
            "github.com/golang-jwt/jwt",
            "JWT (RSA / ECDSA / HMAC)",
            Review,
            Signature,
        ),
        dep(
            "github.com/golang-jwt/jwt/v4",
            "JWT (RSA / ECDSA / HMAC)",
            Review,
            Signature,
        ),
        dep(
            "github.com/golang-jwt/jwt/v5",
            "JWT (RSA / ECDSA / HMAC)",
            Review,
            Signature,
        ),
        dep(
            "github.com/cloudflare/circl",
            "Post-quantum and classical (ML-KEM, ML-DSA)",
            QuantumSafe,
            Kem,
        ),
        dep("filippo.io/mlkem768", "ML-KEM-768", QuantumSafe, Kem),
        // crates.io
        dep("rsa", "RSA", QuantumVulnerable, Pke),
        dep("p256", "ECDSA / ECDH P-256", QuantumVulnerable, Signature),
        dep("p384", "ECDSA / ECDH P-384", QuantumVulnerable, Signature),
        dep("k256", "secp256k1", QuantumVulnerable, Signature),
        dep("ed25519-dalek", "Ed25519", QuantumVulnerable, Signature),
        dep("x25519-dalek", "X25519", QuantumVulnerable, KeyAgree),
        dep("ring", "General crypto (RSA, ECDSA, X25519)", Review, Other),
        dep("ml-kem", "ML-KEM", QuantumSafe, Kem),
        dep("ml-dsa", "ML-DSA", QuantumSafe, Signature),
        dep("pqcrypto-kyber", "Kyber", QuantumSafe, Kem),
        dep("pqcrypto-mlkem", "ML-KEM", QuantumSafe, Kem),
        dep("pqcrypto-dilithium", "Dilithium", QuantumSafe, Signature),
        dep(
            "aws-lc-rs",
            "General crypto with ML-KEM and ML-DSA",
            QuantumSafe,
            Kem,
        ),
        // Maven
        dep(
            "bcprov-jdk18on",
            "Bouncy Castle (classical and post-quantum)",
            Review,
            Other,
        ),
        dep(
            "bcprov-jdk15on",
            "Bouncy Castle (classical and post-quantum)",
            Review,
            Other,
        ),
        dep("jjwt", "JWT (RSA / ECDSA / HMAC)", Review, Signature),
        dep(
            "nimbus-jose-jwt",
            "JOSE (RSA / ECDSA / EdDSA)",
            Review,
            Signature,
        ),
    ]
};

/// Files whose contents are hashes and versions, not code: lock files are skipped by the code
/// rules (they are full of SHA-1 and SHA-512 integrity strings).
pub(crate) fn is_lock_file(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "go.sum"
            | "poetry.lock"
            | "Pipfile.lock"
            | "composer.lock"
            | "Gemfile.lock"
    ) || name.ends_with(".min.js")
        || name.ends_with(".map")
}

/// File extensions the code rules apply to.
pub(crate) fn is_code_file(name: &str) -> bool {
    const EXT: &[&str] = &[
        "rs",
        "go",
        "py",
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "jsx",
        "java",
        "kt",
        "kts",
        "scala",
        "groovy",
        "cs",
        "fs",
        "vb",
        "c",
        "h",
        "cc",
        "cpp",
        "cxx",
        "hpp",
        "hh",
        "m",
        "mm",
        "swift",
        "rb",
        "php",
        "pl",
        "pm",
        "sh",
        "bash",
        "zsh",
        "ps1",
        "lua",
        "dart",
        "ex",
        "exs",
        "erl",
        "hs",
        "clj",
        "r",
        "sql",
        "yaml",
        "yml",
        "toml",
        "ini",
        "conf",
        "cfg",
        "cnf",
        "properties",
        "tf",
        "hcl",
        "json",
        "xml",
        "gradle",
        "env",
        "service",
        "nginx",
    ];
    const NAMES: &[&str] = &[
        "Dockerfile",
        "Makefile",
        "Caddyfile",
        "nginx.conf",
        "sshd_config",
        "ssh_config",
        "Jenkinsfile",
    ];
    if NAMES.contains(&name) {
        return true;
    }
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| EXT.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Number of code and dependency rules, for display.
pub fn rule_count() -> usize {
    CODE_RULES.len() + DEPENDENCY_RULES.len()
}
