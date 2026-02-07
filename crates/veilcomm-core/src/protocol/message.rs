//! Message types for VeilComm protocol

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of message content
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageType {
    /// Regular text message
    Text,
    /// File transfer initiation
    FileOffer,
    /// File transfer acceptance
    FileAccept,
    /// File chunk
    FileChunk,
    /// File transfer complete
    FileComplete,
    /// Typing indicator
    Typing,
    /// Read receipt
    ReadReceipt,
    /// Key ratchet notification
    KeyRatchet,
    /// Session close
    SessionClose,
    /// Sender key distribution for group chat
    SenderKeyDistribution,
    /// Group management action (create, add/remove member, etc.)
    GroupManagement,
}

/// Message content payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageContent {
    /// Type of message
    pub message_type: MessageType,
    /// Actual content (interpretation depends on message_type)
    pub body: Vec<u8>,
    /// Optional metadata (JSON-encoded)
    pub metadata: Option<String>,
}

impl MessageContent {
    /// Create a text message
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            message_type: MessageType::Text,
            body: text.into().into_bytes(),
            metadata: None,
        }
    }

    /// Create a typing indicator
    pub fn typing() -> Self {
        Self {
            message_type: MessageType::Typing,
            body: Vec::new(),
            metadata: None,
        }
    }

    /// Create a read receipt
    pub fn read_receipt(message_id: &str) -> Self {
        Self {
            message_type: MessageType::ReadReceipt,
            body: message_id.as_bytes().to_vec(),
            metadata: None,
        }
    }

    /// Get text content if this is a text message
    pub fn as_text(&self) -> Option<String> {
        if self.message_type == MessageType::Text {
            String::from_utf8(self.body.clone()).ok()
        } else {
            None
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| e.to_string())
    }
}

/// A complete chat message with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique message ID
    pub id: String,
    /// Sender's identity fingerprint
    pub sender: String,
    /// Recipient's identity fingerprint
    pub recipient: String,
    /// Message content
    pub content: MessageContent,
    /// Timestamp when message was created
    pub timestamp: DateTime<Utc>,
    /// Whether this message has been read
    pub read: bool,
}

impl ChatMessage {
    /// Create a new chat message
    pub fn new(
        sender: impl Into<String>,
        recipient: impl Into<String>,
        content: MessageContent,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender: sender.into(),
            recipient: recipient.into(),
            content,
            timestamp: Utc::now(),
            read: false,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_message() {
        let content = MessageContent::text("Hello, world!");
        assert_eq!(content.message_type, MessageType::Text);
        assert_eq!(content.as_text(), Some("Hello, world!".to_string()));
    }

    #[test]
    fn test_message_serialization() {
        let content = MessageContent::text("Test message");
        let bytes = content.to_bytes();
        let deserialized = MessageContent::from_bytes(&bytes).unwrap();

        assert_eq!(content.message_type, deserialized.message_type);
        assert_eq!(content.body, deserialized.body);
    }

    #[test]
    fn test_chat_message() {
        let msg = ChatMessage::new(
            "alice_fingerprint",
            "bob_fingerprint",
            MessageContent::text("Hello Bob!"),
        );

        assert_eq!(msg.sender, "alice_fingerprint");
        assert_eq!(msg.recipient, "bob_fingerprint");
        assert!(!msg.read);
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage::new("alice", "bob", MessageContent::text("Test"));
        let bytes = msg.to_bytes();
        let deserialized = ChatMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.id, deserialized.id);
        assert_eq!(msg.sender, deserialized.sender);
        assert_eq!(msg.recipient, deserialized.recipient);
    }
}
