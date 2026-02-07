//! Session management for VeilComm
//!
//! Handles encrypted session state between two peers.

use serde::{Deserialize, Serialize};

use crate::crypto::keys::IdentityPublicKey;
use crate::crypto::ratchet::{DoubleRatchet, ExportedRatchetState, RatchetMessage};
use crate::crypto::x3dh::X3dhInitialMessage;
use crate::error::{Error, Result};
use crate::protocol::message::{ChatMessage, MessageContent};

/// Session state enum
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established
    Pending,
    /// Session is active and ready for messaging
    Active,
    /// Session has been closed
    Closed,
    /// Session encountered an error
    Error(String),
}

/// An encrypted session with a peer
pub struct Session {
    /// Our identity fingerprint
    pub our_fingerprint: String,
    /// Peer's identity fingerprint
    pub peer_fingerprint: String,
    /// Peer's identity public key
    pub peer_identity: IdentityPublicKey,
    /// Current session state
    pub state: SessionState,
    /// Double Ratchet instance
    ratchet: DoubleRatchet,
    /// X3DH initial message (if we're the initiator)
    pub initial_message: Option<X3dhInitialMessage>,
}

impl Session {
    /// Create a new session as the initiator (Alice)
    pub fn new_initiator(
        our_fingerprint: String,
        peer_fingerprint: String,
        peer_identity: IdentityPublicKey,
        ratchet: DoubleRatchet,
        initial_message: X3dhInitialMessage,
    ) -> Self {
        Self {
            our_fingerprint,
            peer_fingerprint,
            peer_identity,
            state: SessionState::Active,
            ratchet,
            initial_message: Some(initial_message),
        }
    }

    /// Create a new session as the responder (Bob)
    pub fn new_responder(
        our_fingerprint: String,
        peer_fingerprint: String,
        peer_identity: IdentityPublicKey,
        ratchet: DoubleRatchet,
    ) -> Self {
        Self {
            our_fingerprint,
            peer_fingerprint,
            peer_identity,
            state: SessionState::Active,
            ratchet,
            initial_message: None,
        }
    }

    /// Restore a session from exported state
    pub fn restore(
        our_fingerprint: String,
        peer_fingerprint: String,
        peer_identity: IdentityPublicKey,
        exported_state: ExportedRatchetState,
        associated_data: Vec<u8>,
    ) -> Self {
        Self {
            our_fingerprint,
            peer_fingerprint,
            peer_identity,
            state: SessionState::Active,
            ratchet: DoubleRatchet::from_state(exported_state, associated_data),
            initial_message: None,
        }
    }

    /// Encrypt a message for the peer
    pub fn encrypt(&mut self, content: MessageContent) -> Result<EncryptedMessage> {
        if self.state != SessionState::Active {
            return Err(Error::SessionNotFound(format!(
                "Session is not active: {:?}",
                self.state
            )));
        }

        let chat_message = ChatMessage::new(
            self.our_fingerprint.clone(),
            self.peer_fingerprint.clone(),
            content,
        );

        let plaintext = chat_message.to_bytes();
        let ratchet_message = self.ratchet.encrypt(&plaintext)?;

        Ok(EncryptedMessage {
            message_id: chat_message.id.clone(),
            ratchet_message,
            initial_message: if self.ratchet.send_count() == 1 {
                self.initial_message.clone()
            } else {
                None
            },
        })
    }

    /// Decrypt a message from the peer
    pub fn decrypt(&mut self, encrypted: &EncryptedMessage) -> Result<ChatMessage> {
        if self.state != SessionState::Active {
            return Err(Error::SessionNotFound(format!(
                "Session is not active: {:?}",
                self.state
            )));
        }

        let plaintext = self.ratchet.decrypt(&encrypted.ratchet_message)?;
        let chat_message = ChatMessage::from_bytes(&plaintext)
            .map_err(|e| Error::Deserialization(e))?;

        Ok(chat_message)
    }

    /// Export session state for persistence
    pub fn export(&self) -> ExportedSession {
        ExportedSession {
            our_fingerprint: self.our_fingerprint.clone(),
            peer_fingerprint: self.peer_fingerprint.clone(),
            peer_identity: self.peer_identity.clone(),
            state: self.state.clone(),
            ratchet_state: self.ratchet.export_state(),
        }
    }

    /// Close the session
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Check if the session is active
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Get the number of messages sent
    pub fn messages_sent(&self) -> u32 {
        self.ratchet.send_count()
    }

    /// Get the number of messages received
    pub fn messages_received(&self) -> u32 {
        self.ratchet.recv_count()
    }
}

/// Encrypted message ready for transport
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Message ID
    pub message_id: String,
    /// Double Ratchet encrypted message
    pub ratchet_message: RatchetMessage,
    /// X3DH initial message (only for first message)
    pub initial_message: Option<X3dhInitialMessage>,
}

impl EncryptedMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Deserialization(e.to_string()))
    }
}

/// Exported session state for persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportedSession {
    pub our_fingerprint: String,
    pub peer_fingerprint: String,
    pub peer_identity: IdentityPublicKey,
    pub state: SessionState,
    pub ratchet_state: ExportedRatchetState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{IdentityKeyPair, OneTimePreKey, SignedPreKey};
    use crate::crypto::x3dh::{X3dhInitiator, X3dhResponder};
    use x25519_dalek::StaticSecret as X25519SecretKey;

    fn create_session_pair() -> (Session, Session) {
        // Setup identities
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        let alice_fingerprint = alice_identity.public_key().fingerprint();
        let bob_fingerprint = bob_identity.public_key().fingerprint();

        // Bob's pre-keys
        let bob_spk = SignedPreKey::generate(1, &bob_identity);
        let bob_otpks: Vec<_> = (0..10).map(|i| OneTimePreKey::generate(i)).collect();

        // X3DH
        let alice_x3dh = X3dhInitiator::new(alice_identity.clone());
        let mut bob_x3dh = X3dhResponder::new(bob_identity.clone(), bob_spk.clone(), bob_otpks);

        let bob_bundle = bob_x3dh.get_prekey_bundle(Some(0));
        let (alice_secret, initial_msg) = alice_x3dh.agree(&bob_bundle).unwrap();
        let bob_secret = bob_x3dh.agree(&initial_msg).unwrap();

        // Create ratchets
        let alice_ratchet = DoubleRatchet::init_alice(
            alice_secret.as_bytes(),
            &bob_bundle.signed_prekey.public,
            alice_secret.associated_data.clone(),
        );

        let bob_ratchet = DoubleRatchet::init_bob(
            bob_secret.as_bytes(),
            X25519SecretKey::from(bob_spk.secret_bytes()),
            bob_secret.associated_data.clone(),
        );

        // Create sessions
        let alice_session = Session::new_initiator(
            alice_fingerprint.clone(),
            bob_fingerprint.clone(),
            bob_identity.public_key(),
            alice_ratchet,
            initial_msg,
        );

        let bob_session = Session::new_responder(
            bob_fingerprint,
            alice_fingerprint,
            alice_identity.public_key(),
            bob_ratchet,
        );

        (alice_session, bob_session)
    }

    #[test]
    fn test_session_creation() {
        let (alice, bob) = create_session_pair();

        assert!(alice.is_active());
        assert!(bob.is_active());
        assert!(alice.initial_message.is_some());
        assert!(bob.initial_message.is_none());
    }

    #[test]
    fn test_session_encrypt_decrypt() {
        let (mut alice, mut bob) = create_session_pair();

        let content = MessageContent::text("Hello Bob!");
        let encrypted = alice.encrypt(content).unwrap();

        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.content.as_text(), Some("Hello Bob!".to_string()));
    }

    #[test]
    fn test_session_bidirectional() {
        let (mut alice, mut bob) = create_session_pair();

        // Alice -> Bob
        let enc1 = alice.encrypt(MessageContent::text("Hi Bob")).unwrap();
        let dec1 = bob.decrypt(&enc1).unwrap();
        assert_eq!(dec1.content.as_text(), Some("Hi Bob".to_string()));

        // Bob -> Alice
        let enc2 = bob.encrypt(MessageContent::text("Hi Alice")).unwrap();
        let dec2 = alice.decrypt(&enc2).unwrap();
        assert_eq!(dec2.content.as_text(), Some("Hi Alice".to_string()));
    }

    #[test]
    fn test_session_close() {
        let (mut alice, _) = create_session_pair();

        alice.close();
        assert!(!alice.is_active());
        assert_eq!(alice.state, SessionState::Closed);

        // Should fail to encrypt after close
        let result = alice.encrypt(MessageContent::text("Test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let (mut alice, mut bob) = create_session_pair();

        let encrypted = alice.encrypt(MessageContent::text("Test")).unwrap();
        let bytes = encrypted.to_bytes();
        let deserialized = EncryptedMessage::from_bytes(&bytes).unwrap();

        // Should still decrypt correctly
        let decrypted = bob.decrypt(&deserialized).unwrap();
        assert_eq!(decrypted.content.as_text(), Some("Test".to_string()));
    }

    #[test]
    fn test_message_counts() {
        let (mut alice, mut bob) = create_session_pair();

        assert_eq!(alice.messages_sent(), 0);
        assert_eq!(bob.messages_received(), 0);

        let enc = alice.encrypt(MessageContent::text("1")).unwrap();
        assert_eq!(alice.messages_sent(), 1);

        bob.decrypt(&enc).unwrap();
        assert_eq!(bob.messages_received(), 1);
    }
}
