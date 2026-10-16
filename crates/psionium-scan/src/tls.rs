//! Probes a TLS endpoint: does it accept post-quantum hybrid key exchange, and what certificate
//! and parameters does it use?

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use x509_parser::prelude::parse_x509_certificate;

use crate::material::describe_certificate;
use crate::model::TlsResult;

/// Records whether the chain validates, but lets the handshake finish either way so private or
/// expired certificates can still be inspected. The connection carries no application data.
#[derive(Debug)]
struct Recorder {
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    trusted: Mutex<Option<bool>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ok = self
            .webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            .is_ok();
        *self.trusted.lock().expect("lock") = Some(ok);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Handshake {
    version: String,
    cipher_suite: String,
    group: String,
    certificate: Option<Vec<u8>>,
    trusted: Option<bool>,
}

fn handshake(
    host: &str,
    port: u16,
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    timeout: Duration,
    roots: &Arc<RootCertStore>,
) -> Result<Handshake, String> {
    let provider = Arc::new(CryptoProvider {
        kx_groups: groups,
        ..aws_lc_rs::default_provider()
    });
    let webpki = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|e| e.to_string())?;
    let recorder = Arc::new(Recorder {
        webpki,
        provider: provider.clone(),
        trusted: Mutex::new(None),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("\"{host}\" is not a valid host name"))?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;

    // Try every resolved address: a name often has IPv6 and IPv4 addresses and not all answer.
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("cannot resolve {host}"));
    }
    let mut last_error = None;
    let mut tcp = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let mut tcp = tcp.ok_or_else(|| {
        format!(
            "cannot connect to {host}:{port}: {}",
            last_error.map(|e| e.to_string()).unwrap_or_default()
        )
    })?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).map_err(|e| e.to_string())?;
    }
    let result = Handshake {
        version: conn
            .protocol_version()
            .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
            .unwrap_or_default(),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_default(),
        group: conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()))
            .unwrap_or_default(),
        certificate: conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.to_vec()),
        trusted: *recorder.trusted.lock().expect("lock"),
    };
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
    let _ = tcp.flush();
    let mut sink = [0u8; 1];
    let _ = tcp.read(&mut sink);
    Ok(result)
}

/// Splits `host[:port]`, defaulting to port 443. IPv6 literals go in brackets: `[::1]:8443`.
pub(crate) fn split_target(target: &str) -> Result<(String, u16), String> {
    let t = target
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/');
    if let Some(rest) = t.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("missing ']' in IPv6 address")?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("invalid port in {target}"))?,
            None => 443,
        };
        return Ok((host.to_string(), port));
    }
    match t.rsplit_once(':') {
        Some((host, port)) => Ok((
            host.to_string(),
            port.parse()
                .map_err(|_| format!("invalid port in {target}"))?,
        )),
        None => Ok((t.to_string(), 443)),
    }
}

/// Probes `target` (`host[:port]`), with `extra_roots` trusted in addition to the Mozilla roots.
pub fn probe(
    target: &str,
    timeout: Duration,
    extra_roots: &[CertificateDer<'static>],
) -> TlsResult {
    let mut result = TlsResult {
        target: target.to_string(),
        ..TlsResult::default()
    };
    let (host, port) = match split_target(target) {
        Ok(hp) => hp,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };
    let mut store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra_roots {
        let _ = store.add(cert.clone());
    }
    let roots = Arc::new(store);

    // Offering only the hybrid group is a definitive test: the handshake succeeds only if the
    // server supports it.
    let pq = handshake(
        &host,
        port,
        vec![aws_lc_rs::kx_group::X25519MLKEM768],
        timeout,
        &roots,
    );
    result.post_quantum_key_exchange = pq.is_ok();
    // Then offer everything, post-quantum first, to see what the server prefers and its certificate.
    let groups = vec![
        aws_lc_rs::kx_group::X25519MLKEM768,
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::SECP384R1,
    ];
    let full = handshake(&host, port, groups, timeout, &roots);
    let best = match (full, pq) {
        (Ok(h), _) => h,
        (Err(_), Ok(h)) => h,
        (Err(e), Err(_)) => {
            result.error = Some(e);
            return result;
        }
    };
    result.reachable = true;
    result.version = Some(best.version);
    result.cipher_suite = Some(best.cipher_suite);
    result.preferred_group = Some(best.group);
    result.trusted = best.trusted;
    result.certificate = best.certificate.as_deref().and_then(|der| {
        parse_x509_certificate(der)
            .ok()
            .map(|(_, c)| describe_certificate(&c))
    });
    result
}

#[cfg(test)]
mod tests {
    use super::split_target;

    #[test]
    fn targets() {
        assert_eq!(
            split_target("example.com").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_target("https://example.com/").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_target("example.com:8443").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(split_target("[::1]:9000").unwrap(), ("::1".into(), 9000));
        assert!(split_target("example.com:http").is_err());
    }
}
