//! Transport layer for VeilComm
//!
//! Provides QUIC-based transport with TLS 1.3 and optional Tor transport
//! via TCP+TLS through a SOCKS5 proxy.

pub mod quic;
pub mod tor;

use std::fmt;
use std::net::SocketAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use quic::{QuicConfig, QuicTransport};
pub use tor::{TorConfig, TorTransport};

use crate::error::Result;

/// Address of a peer - either a direct IP or a Tor onion address
#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum PeerAddress {
    /// Direct IP:port connection (QUIC/UDP)
    Direct(SocketAddr),
    /// Tor onion address (e.g. "xxxxx.onion:port") routed via TCP+TLS through SOCKS5
    Onion(String),
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddress::Direct(addr) => write!(f, "{}", addr),
            PeerAddress::Onion(addr) => write!(f, "{}", addr),
        }
    }
}

impl From<SocketAddr> for PeerAddress {
    fn from(addr: SocketAddr) -> Self {
        PeerAddress::Direct(addr)
    }
}

/// A bidirectional transport stream for sending and receiving data
#[async_trait]
pub trait TransportStream: Send + Sync {
    /// Send data over the stream
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    /// Receive data from the stream
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

/// Abstract transport layer trait
#[async_trait]
pub trait Transport: Send + Sync {
    /// Open a bidirectional connection/stream to a peer
    async fn connect(&self, addr: &PeerAddress) -> Result<Box<dyn TransportStream>>;
    /// Send data and receive a response (request-response pattern)
    async fn send_and_recv(&self, addr: &PeerAddress, data: &[u8]) -> Result<Vec<u8>>;
    /// Send data without expecting a response
    async fn send_oneshot(&self, addr: &PeerAddress, data: &[u8]) -> Result<()>;
}
