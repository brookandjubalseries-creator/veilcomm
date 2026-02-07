//! Transport layer for VeilComm
//!
//! Provides QUIC-based transport with TLS 1.3.

pub mod quic;

pub use quic::{QuicConfig, QuicTransport};
