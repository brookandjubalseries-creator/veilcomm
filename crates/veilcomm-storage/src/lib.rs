//! VeilComm Storage - Encrypted database and key management
//!
//! Provides secure storage for:
//! - Identity keys
//! - Pre-keys
//! - Session state
//! - Message history

pub mod database;
pub mod error;
pub mod keystore;

pub use database::Database;
pub use error::{Error, Result};
pub use keystore::KeyStore;
