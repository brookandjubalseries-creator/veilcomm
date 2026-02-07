//! VeilComm Network - P2P networking, DHT, and transport
//!
//! This crate provides:
//! - QUIC transport layer with TLS 1.3
//! - TCP+TLS transport via Tor SOCKS5 proxy for onion routing
//! - Kademlia DHT for peer discovery
//! - Wire protocol for peer messaging
//! - Connection management with handshake authentication
//! - NAT traversal via STUN
//! - Network service coordinating all components

pub mod dht;
pub mod error;
pub mod mesh;
pub mod nat;
pub mod peer;
pub mod protocol;
pub mod service;
pub mod transport;

pub use error::{Error, Result};
pub use service::{NetworkEvent, NetworkService, NetworkServiceConfig};
pub use transport::{PeerAddress, TorConfig};
