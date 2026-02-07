//! VeilComm Application - High-level application logic
//!
//! Coordinates crypto, storage, and networking components.

pub mod client;
pub mod error;

pub use client::VeilCommClient;
pub use error::{Error, Result};
