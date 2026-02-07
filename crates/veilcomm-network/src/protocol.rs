//! Wire protocol for VeilComm P2P messaging
//!
//! Defines all message types exchanged between peers over QUIC connections.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::dht::NodeId;

/// Wire message envelope exchanged between peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMessage {
    /// Identity handshake (sent after QUIC connection)
    Handshake {
        /// Sender's node ID (BLAKE2s of identity public key)
        node_id: NodeId,
        /// Ed25519 public key bytes for verification
        identity_public_key: Vec<u8>,
        /// Signature over the challenge (node_id + peer addr + nonce)
        signature: Vec<u8>,
        /// Random nonce used in the challenge
        nonce: Vec<u8>,
        /// Listening address the sender wants to advertise
        listen_addr: SocketAddr,
    },

    /// Handshake acknowledgment
    HandshakeAck {
        node_id: NodeId,
        identity_public_key: Vec<u8>,
        signature: Vec<u8>,
        /// Random nonce used in the challenge
        nonce: Vec<u8>,
        listen_addr: SocketAddr,
    },

    /// Encrypted application message
    EncryptedMessage {
        /// Unique message identifier
        message_id: String,
        /// Sender's identity fingerprint
        sender_id: String,
        /// Recipient's identity fingerprint
        recipient_id: String,
        /// Encrypted payload (X3DH initial message or Double Ratchet ciphertext)
        payload: Vec<u8>,
    },

    /// Acknowledgment for a received message
    MessageAck {
        /// ID of the acknowledged message
        message_id: String,
    },

    /// Request a pre-key bundle for a peer
    RequestPreKeyBundle {
        /// Fingerprint of the peer whose bundle we want
        target_fingerprint: String,
    },

    /// Response with a pre-key bundle
    PreKeyBundleResponse {
        /// Fingerprint of the peer
        fingerprint: String,
        /// Serialized PreKeyBundle
        bundle_data: Vec<u8>,
    },

    /// Kademlia FIND_NODE request
    FindNode {
        /// Target node ID to find
        target: NodeId,
    },

    /// Kademlia FIND_NODE response
    FindNodeResponse {
        /// Closest known nodes to the target
        nodes: Vec<NodeEntry>,
    },

    /// Store a record in the DHT
    StoreRecord {
        /// Key for the record
        key: NodeId,
        /// Serialized record data
        value: Vec<u8>,
        /// Type of record (e.g. "prekey_bundle", "offline_message", "node_addr")
        record_type: String,
    },

    /// Acknowledgment for a stored record
    StoreRecordAck {
        key: NodeId,
        success: bool,
    },

    /// Request a record from the DHT
    GetRecord {
        key: NodeId,
    },

    /// Response with DHT records
    GetRecordResponse {
        key: NodeId,
        /// Serialized records (empty if not found)
        values: Vec<Vec<u8>>,
    },

    /// Keep-alive ping
    Ping {
        nonce: u64,
    },

    /// Keep-alive pong
    Pong {
        nonce: u64,
    },

    /// Error response
    Error {
        code: u32,
        message: String,
    },
}

/// A node entry for DHT responses
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeEntry {
    pub id: NodeId,
    pub addr: SocketAddr,
}

impl WireMessage {
    /// Serialize to bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| e.to_string())
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_pong_roundtrip() {
        let msg = WireMessage::Ping { nonce: 42 };
        let bytes = msg.to_bytes().unwrap();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        if let WireMessage::Ping { nonce } = decoded {
            assert_eq!(nonce, 42);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_encrypted_message_roundtrip() {
        let msg = WireMessage::EncryptedMessage {
            message_id: "msg-001".to_string(),
            sender_id: "abc123".to_string(),
            recipient_id: "def456".to_string(),
            payload: vec![1, 2, 3, 4],
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        if let WireMessage::EncryptedMessage { message_id, sender_id, recipient_id, payload } = decoded {
            assert_eq!(message_id, "msg-001");
            assert_eq!(sender_id, "abc123");
            assert_eq!(recipient_id, "def456");
            assert_eq!(payload, vec![1, 2, 3, 4]);
        } else {
            panic!("Wrong variant");
        }
    }
}
