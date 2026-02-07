//! Cryptographic primitives for VeilComm
//!
//! This module provides:
//! - `keys`: Identity and ephemeral key management
//! - `x3dh`: Extended Triple Diffie-Hellman key exchange
//! - `ratchet`: Double Ratchet protocol for forward secrecy
//! - `aead`: Authenticated encryption (ChaCha20-Poly1305)
//! - `kdf`: Key derivation functions
//! - `pq`: Post-quantum cryptographic primitives (Kyber)

pub mod aead;
pub mod kdf;
pub mod keys;
pub mod pq;
pub mod ratchet;
pub mod x3dh;

pub use aead::{decrypt, encrypt};
pub use kdf::{derive_key, hkdf_expand, hkdf_extract};
pub use keys::{IdentityKeyPair, KeyBundle, OneTimePreKey, PreKeyBundle, SignedPreKey};
pub use pq::{combine_secrets, KyberCiphertext, KyberKeyPair, KyberPublicKey, PqSharedSecret};
pub use ratchet::{DoubleRatchet, MessageHeader, RatchetState};
pub use x3dh::{X3dhInitiator, X3dhResponder};
