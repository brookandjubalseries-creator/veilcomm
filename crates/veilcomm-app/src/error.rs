//! Application error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Not initialized - run 'veilcomm init' first")]
    NotInitialized,

    #[error("Already initialized")]
    AlreadyInitialized,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] veilcomm_core::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] veilcomm_storage::Error),

    #[error("Network error: {0}")]
    Network(#[from] veilcomm_network::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
