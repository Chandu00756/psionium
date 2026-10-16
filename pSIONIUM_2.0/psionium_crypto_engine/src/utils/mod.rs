use thiserror::Error;

#[derive(Error, Debug)]
pub enum PsioniumError {
    #[error("Crypto initialization failed: {0}")]
    CryptoInit(String),
    #[error("Key generation failed: {0}")]
    KeyGen(String),
    #[error("Key loading failed: {0}")]
    KeyLoad(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Symmetric crypto error: {0}")]
    SymmetricCrypto(String),
    #[error("Enclave initialization failed: {0}")]
    EnclaveInit(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub fn generate_entropy(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut entropy = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut entropy);
    entropy
}