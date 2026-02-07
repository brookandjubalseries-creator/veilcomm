//! Protocol definitions for VeilComm
//!
//! Defines message types, session management, and protocol state machines.

pub mod message;
pub mod session;

pub use message::{ChatMessage, MessageContent, MessageType};
pub use session::{Session, SessionState};
