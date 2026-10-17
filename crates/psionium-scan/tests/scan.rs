use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use psionium_scan::{
    Baseline, Category, Finding, ScanOptions, Source, empty_report, probe_tls, scan_paths,
};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn write(root: &Path, rel: &str, contents: impl AsRef<[u8]>) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, contents).unwrap();
}

fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn fixture(root: &Path) {
    write(
        root,
        "src/auth.go",
        "package auth\n\nimport (\"crypto/rsa\"; \"crypto/ecdsa\")\n\nfunc keys() {\n\tk, _ := rsa.GenerateKey(rand.Reader, 2048)\n\tsig, _ := ecdsa.SignASN1(rand.Reader, priv, digest)\n\th := md5.Sum(data)\n}\n",
    );
    write(
        root,
        "app/crypto.py",
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\nkey = rsa.generate_private_key(public_exponent=65537, key_size=3072)\ncurve = ec.SECP256R1()\nh = hashlib.sha1(b'x')\n",
    );
    write(
        root,
        "pq/kem.rs",
        "use aws_lc_rs::kem::ML_KEM_768;\nlet groups = vec![kx_group::X25519MLKEM768];\nlet sig = ML_DSA_65_SIGNING;\n",
    );
    write(
        root,
        "web/notes.ts",
        "// A conversation about universal design and versatile anchors.\nconst algs = ['ML-DSA-65', 'SLH-DSA'];\nconst ed = 'Ed25519';\nconst tls = { minVersion: 'TLSv1.2' };\nconst old = { minVersion: 'TLSv1.1' };\n",
    );
    write(
        root,
        "package.json",
        r#"{ "dependencies": { "node-rsa": "^1.1.1", "@noble/post-quantum": "^0.2.0", "react": "18.3.1" }, "devDependencies": { "jsonwebtoken": "^9.0.0" } }"#,
    );
    write(
        root,
        "requirements.txt",
        "cryptography>=42\nrsa==4.9  # signing\noqs\nrequests\n",
    );
    write(
        root,
        "go.mod",
        "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/cloudflare/circl v1.3.7\n\tgolang.org/x/crypto v0.21.0\n)\n",
    );
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"x\"\n\n[dependencies]\np256 = \"0.13\"\nml-kem = \"0.2\"\nserde = \"1\"\n",
    );
    // Lock files are full of hashes and must not be flagged.
    write(
        root,
        "package-lock.json",
        r#"{ "integrity": "sha1-abc sha512-def", "rsa": "x" }"#,
    );
    // Vendored dependencies and ignored files are skipped by default.
    write(
        root,
        "node_modules/lib/index.js",
        "const k = RSA.generate();\n",
    );
    write(root, ".gitignore", "ignored.js\n");
    write(root, "ignored.js", "const k = RSA.generate();\n");
    // Binary files are not read as text.
    write(root, "blob.bin", b"\0\0RSA ECDSA\0");

    // A certificate (ECDSA P-256) and its PKCS#8 private key.
    let ck = rcgen::generate_simple_self_signed(vec!["example.test".to_string()]).unwrap();
    write(root, "certs/server.pem", ck.cert.pem());
    write(root, "certs/server.key", ck.signing_key.serialize_pem());
    // An Ed25519 certificate in DER form.
    let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ed_cert = rcgen::CertificateParams::new(vec!["ed.test".to_string()])
        .unwrap()
        .self_signed(&ed)
        .unwrap();
    write(root, "certs/ed.der", ed_cert.der().as_ref());

    // An RSA-2048 SSH public key and an OpenSSH private key container.
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-rsa");
    ssh_string(&mut blob, &[1, 0, 1]);
    let mut n = vec![0u8];
    n.extend(std::iter::repeat_n(0xC3, 256));
    ssh_string(&mut blob, &n);
    write(
        root,
        "deploy/authorized_keys",
        format!(
            "# admins\nssh-rsa {} admin@example.test\n",
            STANDARD.encode(&blob)
        ),
    );
    let mut container = b"openssh-key-v1\0".to_vec();
    ssh_string(&mut container, b"none");
    ssh_string(&mut container, b"none");
    ssh_string(&mut container, b"");
    container.extend_from_slice(&1u32.to_be_bytes());
    let mut public = Vec::new();
    ssh_string(&mut public, b"ssh-ed25519");
    ssh_string(&mut public, &[7u8; 32]);
    ssh_string(&mut container, &public);
    let body = STANDARD.encode(&container);
    write(
        root,
        "deploy/id_ed25519",
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"),
    );
}

fn find<'a>(findings: &'a [Finding], location: &str, algorithm: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.location == location && f.algorithm == algorithm)
        .collect()
}

#[test]
fn finds_vulnerable_weak_and_post_quantum_cryptography() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let report = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    let f = &report.findings;

    // Code.
    let rsa_go = find(f, "src/auth.go", "RSA");
    assert!(
        rsa_go
            .iter()
            .any(|x| x.line == Some(6) && x.category == Category::QuantumVulnerable),
        "{rsa_go:?}"
    );
    assert!(!find(f, "src/auth.go", "ECDSA").is_empty());
    assert!(
        find(f, "src/auth.go", "MD5")
            .iter()
            .all(|x| x.category == Category::Weak)
            && !find(f, "src/auth.go", "MD5").is_empty()
    );
    assert!(
        find(f, "app/crypto.py", "RSA")
            .iter()
            .any(|x| x.line == Some(2))
    );
    assert!(!find(f, "app/crypto.py", "SHA-1").is_empty());
    assert!(
        find(f, "pq/kem.rs", "ML-KEM")
            .iter()
            .any(|x| x.category == Category::QuantumSafe && x.line == Some(1))
    );
    assert!(!find(f, "pq/kem.rs", "X25519MLKEM768 (hybrid)").is_empty());
    assert!(
        find(f, "pq/kem.rs", "X25519 / X448 (ECDH)").is_empty(),
        "the hybrid group is not classical X25519"
    );
    assert!(!find(f, "pq/kem.rs", "ML-DSA").is_empty());

    // No false positives from ordinary words or post-quantum names.
    assert!(find(f, "web/notes.ts", "RSA").is_empty());
    assert!(
        find(f, "web/notes.ts", "DSA").is_empty(),
        "ML-DSA and SLH-DSA are not DSA"
    );
    assert!(!find(f, "web/notes.ts", "ML-DSA").is_empty());
    assert!(!find(f, "web/notes.ts", "EdDSA (Ed25519 / Ed448)").is_empty());
    let old_tls = find(f, "web/notes.ts", "TLS 1.0 / 1.1 / SSL");
    assert_eq!(
        old_tls.len(),
        1,
        "TLSv1.2 is fine, TLSv1.1 is not: {old_tls:?}"
    );
    assert_eq!(old_tls[0].line, Some(5));

    // Dependencies.
    assert!(
        find(f, "package.json", "RSA")
            .iter()
            .any(|x| x.source == Source::Dependency)
    );
    assert!(
        find(f, "package.json", "ML-KEM / ML-DSA / SLH-DSA")
            .iter()
            .any(|x| x.category == Category::QuantumSafe)
    );
    assert!(!find(f, "package.json", "JWT (RSA / ECDSA / HMAC)").is_empty());
    assert!(
        find(f, "requirements.txt", "RSA")
            .iter()
            .any(|x| x.line == Some(2))
    );
    assert!(!find(f, "requirements.txt", "Open Quantum Safe").is_empty());
    assert!(!find(f, "go.mod", "Post-quantum and classical (ML-KEM, ML-DSA)").is_empty());
    assert!(!find(f, "Cargo.toml", "ECDSA / ECDH P-256").is_empty());
    assert!(!find(f, "Cargo.toml", "ML-KEM").is_empty());

    // Lock files, vendored code, ignored and binary files.
    assert!(f.iter().all(|x| x.location != "package-lock.json"));
    assert!(f.iter().all(|x| !x.location.starts_with("node_modules")));
    assert!(
        f.iter()
            .all(|x| x.location != "ignored.js" && x.location != "blob.bin")
    );

    // Certificates and keys.
    let cert = f
        .iter()
        .find(|x| x.location == "certs/server.pem" && x.source == Source::Certificate)
        .expect("PEM certificate");
    assert_eq!(cert.algorithm, "ECDSA P-256");
    assert!(
        f.iter()
            .any(|x| x.location == "certs/ed.der" && x.algorithm == "Ed25519")
    );
    let key = f
        .iter()
        .find(|x| x.location == "certs/server.key")
        .expect("PKCS#8 private key");
    assert_eq!(key.source, Source::PrivateKey);
    assert_eq!(key.algorithm, "ECDSA");
    let ssh = f
        .iter()
        .find(|x| x.location == "deploy/authorized_keys")
        .expect("SSH key");
    assert_eq!(ssh.detail, "RSA-2048 public key");
    let openssh = f
        .iter()
        .find(|x| x.location == "deploy/id_ed25519")
        .expect("OpenSSH private key");
    assert_eq!(openssh.algorithm, "Ed25519");

    // Private key contents never appear in any report format.
    let secret = fs::read_to_string(dir.path().join("certs/server.key")).unwrap();
    let secret_line = secret.lines().nth(1).unwrap();
    for rendered in [
        report.to_text(),
        report.to_markdown(),
        report.to_json(),
        report.to_cbom(),
    ] {
        assert!(
            !rendered.contains(secret_line),
            "private key material leaked into a report"
        );
    }
}

#[test]
fn dependency_folders_can_be_included() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let report = scan_paths(
        &[dir.path()],
        &ScanOptions {
            include_dependencies: true,
            ..ScanOptions::default()
        },
    )
    .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.location == "node_modules/lib/index.js")
    );
}

#[test]
fn reports_render_in_every_format() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let report = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();

    let text = report.to_text();
    assert!(
        text.contains("Summary:")
            && text.contains("Quantum-vulnerable")
            && text.contains("Already post-quantum")
    );

    let md = report.to_markdown();
    assert!(
        md.starts_with("# Quantum readiness report")
            && md.contains("| Category | Findings | What to do |")
    );

    let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
    assert!(json["findings"].as_array().unwrap().len() >= 20);
    assert_eq!(
        json["files_scanned"].as_u64().unwrap() as usize,
        report.files_scanned
    );

    let cbom: serde_json::Value = serde_json::from_str(&report.to_cbom()).unwrap();
    assert_eq!(cbom["bomFormat"], "CycloneDX");
    assert_eq!(cbom["specVersion"], "1.6");
    assert!(
        cbom["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:")
    );
    let components = cbom["components"].as_array().unwrap();
    let rsa = components
        .iter()
        .find(|c| {
            c["name"] == "RSA" && c["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"
        })
        .expect("RSA component");
    assert_eq!(rsa["cryptoProperties"]["assetType"], "algorithm");
    assert_eq!(
        rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
        0
    );
    assert!(
        !rsa["evidence"]["occurrences"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let mlkem = components
        .iter()
        .find(|c| {
            c["name"] == "ML-KEM"
                && c["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
        })
        .expect("ML-KEM component");
    assert_eq!(
        mlkem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
        3
    );
    assert!(
        components
            .iter()
            .all(|c| c["type"] == "cryptographic-asset")
    );
}

#[test]
fn missing_paths_are_errors() {
    assert!(scan_paths(&["/definitely/not/here"], &ScanOptions::default()).is_err());
}

/// A local TLS 1.3 server offering only `groups`, answering `connections` handshakes.
fn tls_server(
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    connections: usize,
) -> (u16, CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(CryptoProvider {
        kx_groups: groups,
        ..aws_lc_rs::default_provider()
    });
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().take(connections) {
            let Ok(mut tcp) = stream else { continue };
            let Ok(mut conn) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            while conn.is_handshaking() {
                if conn.complete_io(&mut tcp).is_err() {
                    break;
                }
            }
            let _ = conn.complete_io(&mut tcp);
        }
    });
    (port, cert)
}

#[test]
fn tls_probe_detects_post_quantum_support() {
    let (pq_port, pq_cert) = tls_server(
        vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
        ],
        2,
    );
    let r = probe_tls(&format!("localhost:{pq_port}"), Duration::from_secs(5), &[]);
    assert!(r.reachable, "{:?}", r.error);
    assert!(r.post_quantum_key_exchange);
    assert_eq!(r.version.as_deref(), Some("TLS 1.3"));
    assert_eq!(r.preferred_group.as_deref(), Some("X25519MLKEM768"));
    assert_eq!(
        r.trusted,
        Some(false),
        "a self-signed certificate is not publicly trusted"
    );
    assert_eq!(r.certificate.as_ref().unwrap().key_algorithm, "ECDSA P-256");

    let (classic_port, _) = tls_server(vec![aws_lc_rs::kx_group::X25519], 2);
    let r = probe_tls(
        &format!("localhost:{classic_port}"),
        Duration::from_secs(5),
        &[],
    );
    assert!(r.reachable, "{:?}", r.error);
    assert!(!r.post_quantum_key_exchange);
    assert_eq!(r.preferred_group.as_deref(), Some("X25519"));

    // Trust is reported against the given roots.
    let (port, cert) = tls_server(vec![aws_lc_rs::kx_group::X25519MLKEM768], 2);
    let r = probe_tls(
        &format!("localhost:{port}"),
        Duration::from_secs(5),
        &[cert],
    );
    assert_eq!(r.trusted, Some(true));
    drop(pq_cert);

    // Findings come out of TLS results.
    let mut report = empty_report();
    report.add_tls(probe_tls(
        &format!("localhost:{classic_port}"),
        Duration::from_secs(5),
        &[],
    ));
    assert!(report.tls.len() == 1);
    let unreachable = probe_tls("127.0.0.1:1", Duration::from_secs(2), &[]);
    assert!(!unreachable.reachable && unreachable.error.is_some());
}

#[test]
fn fingerprints_survive_edits_and_tell_duplicates_apart() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let before = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    let mut all: Vec<&str> = before
        .findings
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    assert!(all.iter().all(|fp| {
        fp.len() == 32
            && fp
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }));
    let total = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), total, "fingerprints are unique");

    // Lines moving down keep their fingerprints; an identical copy of a line gets a new one.
    let auth = dir.path().join("src/auth.go");
    let text = fs::read_to_string(&auth).unwrap();
    fs::write(
        &auth,
        format!("// moved\n// down\n{text}\th2 := md5.Sum(data)\n\th := md5.Sum(data)\n"),
    )
    .unwrap();
    let after = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    let in_auth = |r: &psionium_scan::Report| -> Vec<(String, usize)> {
        r.findings
            .iter()
            .filter(|f| f.location == "src/auth.go")
            .map(|f| (f.fingerprint.clone(), f.line.unwrap()))
            .collect()
    };
    let (old, new) = (in_auth(&before), in_auth(&after));
    for (fp, line) in &old {
        assert!(
            new.contains(&(fp.clone(), line + 2)),
            "{fp} moved with its line"
        );
    }
    assert_eq!(new.len(), old.len() + 2);
    let md5: Vec<_> = after
        .findings
        .iter()
        .filter(|f| f.location == "src/auth.go" && f.algorithm == "MD5")
        .map(|f| f.fingerprint.clone())
        .collect();
    assert_eq!(md5.len(), 3);
    assert!(
        md5[0] != md5[2],
        "a duplicate line gets its own fingerprint"
    );
}

#[test]
fn excerpts_can_be_left_out() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let with = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    let without = scan_paths(
        &[dir.path()],
        &ScanOptions {
            excerpts: false,
            ..ScanOptions::default()
        },
    )
    .unwrap();
    for format in [
        without.to_json(),
        without.to_markdown(),
        without.to_html(),
        without.to_sarif(),
        without.to_cbom(),
        without.to_text(),
    ] {
        assert!(!format.contains("GenerateKey") && !format.contains("SignASN1"));
    }
    assert!(with.to_json().contains("GenerateKey"));
    let fps = |r: &psionium_scan::Report| {
        let mut v: Vec<String> = r.findings.iter().map(|f| f.fingerprint.clone()).collect();
        v.sort();
        v
    };
    assert_eq!(
        fps(&with),
        fps(&without),
        "fingerprints do not depend on excerpts"
    );
}

#[test]
fn ignore_patterns_skip_paths() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let report = scan_paths(
        &[dir.path()],
        &ScanOptions {
            ignore: vec!["app/".into(), "*.pem".into(), "deploy/**".into()],
            ..ScanOptions::default()
        },
    )
    .unwrap();
    let f = &report.findings;
    assert!(f.iter().all(|f| !f.location.starts_with("app/")
        && !f.location.ends_with(".pem")
        && !f.location.starts_with("deploy/")));
    assert!(!find(f, "src/auth.go", "RSA").is_empty());
    assert!(
        f.iter().any(|f| f.location == "certs/server.key"),
        "only .pem files were ignored"
    );

    assert!(
        scan_paths(
            &[dir.path()],
            &ScanOptions {
                ignore: vec!["src/{a,b".into()],
                ..ScanOptions::default()
            },
        )
        .is_err()
    );
}

#[test]
fn baselines_accept_known_findings_and_keep_reasons() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    // The baseline file itself is never scanned, though it names algorithms.
    fs::write(
        dir.path().join(psionium_scan::BASELINE_FILE),
        "# RSA ECDSA md5\n",
    )
    .unwrap();
    let first = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    assert!(
        first
            .findings
            .iter()
            .all(|f| f.location != psionium_scan::BASELINE_FILE)
    );
    let baseline = Baseline::accepting(&first, None, "known");
    assert!(
        baseline
            .accepted
            .iter()
            .all(|a| a.reason == "known" && !a.location.is_empty())
    );
    let parsed = Baseline::parse(&baseline.to_toml()).unwrap();
    assert_eq!(parsed, baseline);

    // Everything known is accepted; only post-quantum findings remain.
    let mut again = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    assert!(again.apply_baseline(&parsed).is_empty());
    assert!(
        again
            .findings
            .iter()
            .all(|f| f.category == Category::QuantumSafe)
    );
    assert_eq!(again.accepted.len(), baseline.accepted.len());
    assert_eq!(again.counts().get(&Category::QuantumVulnerable), None);
    assert!(again.to_text().contains("Accepted in the baseline"));
    let cbom: serde_json::Value = serde_json::from_str(&again.to_cbom()).unwrap();
    assert!(
        cbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "RSA"),
        "the CBOM still lists accepted cryptography"
    );

    // A new finding is not accepted; a fixed one leaves a stale entry.
    write(
        dir.path(),
        "src/auth.go",
        "package auth\nfunc keys() {\n\tk, _ := rsa.GenerateKey(rand.Reader, 4096)\n}\n",
    );
    let mut edited = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    let stale = edited.apply_baseline(&parsed);
    assert!(!stale.is_empty());
    let new: Vec<_> = edited
        .findings
        .iter()
        .filter(|f| f.category != Category::QuantumSafe)
        .collect();
    assert_eq!(new.len(), 1);
    assert_eq!((new[0].algorithm.as_str(), new[0].line), ("RSA", Some(3)));

    // Rewriting keeps reasons, drops stale entries and adds new ones.
    let mut custom = parsed.clone();
    custom.ignore = vec!["docs/".into()];
    let kept = custom
        .accepted
        .iter_mut()
        .find(|a| a.location.starts_with("app/crypto.py"))
        .unwrap();
    kept.reason = "Python service retires in Q2".into();
    let kept_fp = kept.fingerprint.clone();
    let mut edited = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    edited.apply_baseline(&custom);
    let rewritten = Baseline::accepting(&edited, Some(&custom), "new");
    assert_eq!(rewritten.ignore, vec!["docs/".to_string()]);
    let reason = |fp: &str| {
        rewritten
            .accepted
            .iter()
            .find(|a| a.fingerprint == fp)
            .map(|a| a.reason.clone())
    };
    assert_eq!(
        reason(&kept_fp).as_deref(),
        Some("Python service retires in Q2")
    );
    assert_eq!(reason(&new[0].fingerprint).as_deref(), Some("new"));
    assert_eq!(
        rewritten.accepted.len(),
        baseline.accepted.len() - stale.len() + 1
    );

    // Bad baselines are rejected with a reason.
    for bad in [
        "ignroe = []\n",
        "[[accepted]]\nfingerprint = \"abc\"\nreason = \"x\"\n",
        "[[accepted]]\nfingerprint = \"0123456789abcdef0123456789abcdef\"\nreason = \" \"\n",
        "[[accepted]]\nreason = \"x\"\n",
    ] {
        assert!(Baseline::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(Baseline::parse("").unwrap(), Baseline::default());
}

#[test]
fn html_and_sarif_reports() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    write(
        dir.path(),
        // Characters that need escaping, all allowed in Windows file names too.
        "src/a&b c'.go",
        "k, _ := rsa.GenerateKey(rand.Reader, 2048) // <script>\n",
    );
    let mut report = scan_paths(&[dir.path()], &ScanOptions::default()).unwrap();
    let mut accept = Baseline::accepting(&report, None, "reviewed <ok>");
    accept.accepted.retain(|a| a.location.starts_with("app/"));
    report.apply_baseline(&accept);

    let html = report.to_html();
    assert!(html.starts_with("<!doctype html>") && html.ends_with("</html>\n"));
    assert!(!html.contains("<script") && !html.contains(" src=") && !html.contains("<link"));
    assert!(html.contains("src/a&amp;b c&#39;.go") && html.contains("reviewed &lt;ok&gt;"));
    assert!(html.contains("What to do:") && html.contains("ML-DSA-65 (FIPS 204)"));
    assert!(html.contains("Accepted in the baseline"));

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for r in results {
        let rule = &rules[r["ruleIndex"].as_u64().unwrap() as usize];
        assert_eq!(rule["id"], r["ruleId"]);
        assert_ne!(r["properties"]["category"], "quantum-safe");
        assert_eq!(
            r["partialFingerprints"]["psioniumFingerprint/v1"]
                .as_str()
                .unwrap()
                .len(),
            32
        );
        let location = &r["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(
            location["uriBaseId"], "SCANROOT0",
            "absolute roots use a base id"
        );
        assert!(!location["uri"].as_str().unwrap().starts_with('/'));
    }
    assert!(
        run["originalUriBaseIds"]["SCANROOT0"]["uri"]
            .as_str()
            .unwrap()
            .starts_with("file:///")
    );
    let weak = results
        .iter()
        .find(|r| r["properties"]["algorithm"] == "MD5")
        .unwrap();
    assert_eq!(weak["level"], "error");
    assert!(results.iter().any(
        |r| r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "src/a%26b%20c%27.go"
    ));
    let suppressed: Vec<_> = results
        .iter()
        .filter(|r| r.get("suppressions").is_some())
        .collect();
    assert_eq!(suppressed.len(), report.accepted.len());
    assert_eq!(
        suppressed[0]["suppressions"][0]["justification"],
        "reviewed <ok>"
    );
}
