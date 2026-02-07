//! Protocol definitions for VeilComm
//!
//! Defines message types, session management, group protocol, and state machines.

pub mod group;
pub mod message;
pub mod session;

pub use group::{GroupAction, GroupInfo, GroupMember, GroupRole};
pub use message::{ChatMessage, MessageContent, MessageType};
pub use session::{Session, SessionState};
