//! Storage error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Core crypto error: {0}")]
    Core(#[from] veilcomm_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
