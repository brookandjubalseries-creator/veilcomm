//! VeilComm Core - Cryptographic primitives and protocol implementation
//!
//! This crate provides the core security primitives for VeilComm:
//! - Identity key management (Ed25519 + X25519)
//! - X3DH key exchange with post-quantum extensions
//! - Double Ratchet for perfect forward secrecy
//! - ChaCha20-Poly1305 AEAD encryption

pub mod crypto;
pub mod error;
pub mod protocol;
pub mod steganography;

pub use error::{Error, Result};
