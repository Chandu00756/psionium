use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tokio_tungstenite::tungstenite::Message;
use std::sync::Arc;
use log::info;
use anyhow::{Result, anyhow};
use futures::{SinkExt, StreamExt};
use pqcrypto_kyber::kyber1024::{keypair as kyber_keypair, encapsulate, decapsulate, PublicKey, SecretKey};
use pqcrypto_kyber::kyber1024::Ciphertext as KyberCiphertext;
use pqcrypto_kyber::kyber1024::SharedSecret as KyberSharedSecret;
use dashmap::DashMap;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use generic_array::GenericArray;
use rand::Rng;
use hkdf::Hkdf;
use sha2::Sha512;
use blake3;

pub struct SecureChannel {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    aes_key: [u8; 32],
    routing_table: Arc<DashMap<String, Vec<String>>>,
}

impl SecureChannel {
    pub async fn new(signing_key: SigningKey, verifying_key: VerifyingKey, addr: &str) -> Result<Self> {
        let (ws_stream, _) = connect_async(format!("wss://{}", addr)).await
            .map_err(|e| anyhow!("Failed to connect to WebSocket: {}", e))?;

        let (kyber_pub_initiator, kyber_sec_initiator): (PublicKey, SecretKey) = kyber_keypair();
        let (kyber_pub_responder, kyber_sec_responder): (PublicKey, SecretKey) = kyber_keypair();

        let (ciphertext, shared_secret_initiator): (KyberCiphertext, KyberSharedSecret) = encapsulate(&kyber_pub_responder);
        let shared_secret_responder: KyberSharedSecret = decapsulate(&ciphertext, &kyber_sec_responder);

        if shared_secret_initiator.as_bytes() != shared_secret_responder.as_bytes() {
            return Err(anyhow!("Shared secret mismatch in Kyber key exchange"));
        }

        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let aes_key = derive_aes_key(shared_secret_initiator.as_bytes(), &salt)?;

        let routing_table = Arc::new(DashMap::new());
        routing_table.insert(
            addr.to_string(),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string(), "10.0.0.3".to_string()],
        );

        info!("Secure channel initialized with Kyber1024 and AES-256-GCM to {}", addr);
        Ok(SecureChannel {
            signing_key,
            verifying_key,
            ws_stream,
            aes_key,
            routing_table,
        })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.aes_key)
            .map_err(|_| anyhow!("Invalid AES key length"))?;
        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|_| anyhow!("Encryption failed"))?;

        let signature = self.signing_key.sign(&encrypted);

        let message = [
            nonce_bytes.as_slice(),
            encrypted.as_slice(),
            signature.to_bytes().as_slice(),
        ]
        .concat();

        let routes = self.routing_table
            .get("localhost:8080")
            .ok_or_else(|| anyhow!("No routes available"))?;
        let route_idx = (blake3::hash(data).as_bytes()[0] % routes.len() as u8) as usize;
        info!("Sending data via route: {}", routes[route_idx]);

        self.ws_stream
            .send(Message::Binary(message))
            .await
            .map_err(|e| anyhow!("WebSocket send failed: {}", e))?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        while let Some(msg) = self.ws_stream.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if data.len() < 12 + 16 + 64 {
                        return Err(anyhow!("Received data too short for nonce, ciphertext, and signature"));
                    }

                    let (nonce_bytes, rest) = data.split_at(12);
                    let (encrypted, sig_bytes) = rest.split_at(rest.len() - 64);
                    let signature = Signature::from_bytes(
                        sig_bytes.try_into().map_err(|_| anyhow!("Invalid signature length"))?,
                    );

                    self.verifying_key
                        .verify(encrypted, &signature)
                        .map_err(|_| anyhow!("Signature verification failed"))?;

                    let nonce = GenericArray::from_slice(nonce_bytes);
                    let cipher = Aes256Gcm::new_from_slice(&self.aes_key)
                        .map_err(|_| anyhow!("Invalid AES key length"))?;
                    let decrypted = cipher
                        .decrypt(nonce, encrypted)
                        .map_err(|_| anyhow!("Decryption failed"))?;

                    info!("Successfully received and decrypted data");
                    return Ok(decrypted);
                }
                Ok(_) => continue,
                Err(e) => return Err(anyhow!("WebSocket error: {}", e)),
            }
        }
        Err(anyhow!("WebSocket stream closed unexpectedly"))
    }
}

fn derive_aes_key(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), shared_secret);
    let mut aes_key = [u8; 32];
    hkdf.expand(b"SecureChannel AES-256 Key", &mut aes_key)
        .map_err(|_| anyhow!("HKDF key derivation failed"))?;
    Ok(aes_key)
}