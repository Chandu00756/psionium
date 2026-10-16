pub mod crypto;
pub mod enclave;
pub mod utils;

#[cfg(test)]
mod tests;

// Ensure types are Send and Sync for thread safety
unsafe impl Send for crypto::PsioniumCrypto {}
unsafe impl Sync for crypto::PsioniumCrypto {}
unsafe impl Send for enclave::PsioniumEnclave {}
unsafe impl Sync for enclave::PsioniumEnclave {}