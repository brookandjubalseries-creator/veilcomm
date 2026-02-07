//! Error types for VeilComm Core

use thiserror::Error;

/// Core error type for VeilComm cryptographic operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("Ratchet state corrupted: {0}")]
    RatchetCorrupted(String),

    #[error("No one-time prekeys available")]
    NoOneTimePrekeys,

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Post-quantum key encapsulation failed")]
    PqEncapsulation,

    #[error("Post-quantum key decapsulation failed")]
    PqDecapsulation,

    #[error("Maximum skip exceeded: {0} messages skipped")]
    MaxSkipExceeded(u32),

    #[error("Duplicate message detected")]
    DuplicateMessage,
}

/// Result type for VeilComm Core operations
pub type Result<T> = std::result::Result<T, Error>;
