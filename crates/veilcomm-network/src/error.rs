//! Network error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("DHT error: {0}")]
    Dht(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Handshake error: {0}")]
    Handshake(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, Error>;
