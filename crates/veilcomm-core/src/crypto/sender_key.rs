//! Sender Key protocol for group messaging
//!
//! Implements Signal-style Sender Keys where each group member maintains
//! a symmetric chain key that is forward-ratcheted on each message.
//! Messages are authenticated with Ed25519 signatures.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::aead;
use crate::crypto::kdf::kdf_ck;
use crate::error::{Error, Result};

/// Our own sender key for a group (we encrypt with this)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SenderKey {
    #[zeroize(skip)]
    group_id: String,
    chain_key: [u8; 32],
    #[zeroize(skip)]
    signing_key: SigningKey,
    chain_index: u32,
}

/// Distribution message to share our sender key with a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    pub group_id: String,
    pub sender_fingerprint: String,
    pub chain_key: [u8; 32],
    pub signing_public_key: Vec<u8>,
    pub chain_index: u32,
}

/// A received sender key from another group member (we decrypt with this)
pub struct ReceivedSenderKey {
    pub sender_fingerprint: String,
    chain_key: [u8; 32],
    verifying_key: VerifyingKey,
    chain_index: u32,
    /// Skipped message keys for out-of-order delivery
    skipped_keys: HashMap<u32, [u8; 32]>,
}

/// An encrypted group message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderKeyMessage {
    pub group_id: String,
    pub sender_fingerprint: String,
    pub chain_index: u32,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Maximum number of skipped message keys to store
const MAX_SKIP: u32 = 256;

impl SenderKey {
    /// Generate a new sender key for a group
    pub fn generate(group_id: String) -> Self {
        let chain_key: [u8; 32] = rand::random();
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        Self {
            group_id,
            chain_key,
            signing_key,
            chain_index: 0,
        }
    }

    /// Encrypt a message and advance the chain
    pub fn encrypt(&mut self, sender_fingerprint: &str, plaintext: &[u8]) -> Result<SenderKeyMessage> {
        // Derive message key from chain key
        let (new_chain_key, message_key) = kdf_ck(&self.chain_key);
        let current_index = self.chain_index;

        // Encrypt with ChaCha20-Poly1305
        let ad = format!("{}||{}", self.group_id, current_index);
        let ciphertext = aead::encrypt(&message_key, plaintext, ad.as_bytes())?;

        // Sign (group_id || chain_index || ciphertext)
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(self.group_id.as_bytes());
        sign_data.extend_from_slice(&current_index.to_le_bytes());
        sign_data.extend_from_slice(&ciphertext);
        let signature = self.signing_key.sign(&sign_data);

        // Advance chain
        self.chain_key = new_chain_key;
        self.chain_index += 1;

        Ok(SenderKeyMessage {
            group_id: self.group_id.clone(),
            sender_fingerprint: sender_fingerprint.to_string(),
            chain_index: current_index,
            ciphertext,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Create a distribution message for sharing our key with a peer
    pub fn distribution(&self, sender_fingerprint: &str) -> SenderKeyDistribution {
        SenderKeyDistribution {
            group_id: self.group_id.clone(),
            sender_fingerprint: sender_fingerprint.to_string(),
            chain_key: self.chain_key,
            signing_public_key: self.signing_key.verifying_key().as_bytes().to_vec(),
            chain_index: self.chain_index,
        }
    }

    /// Get the group ID
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// Get the current chain index
    pub fn chain_index(&self) -> u32 {
        self.chain_index
    }
}

impl ReceivedSenderKey {
    /// Create from a distribution message
    pub fn from_distribution(dist: &SenderKeyDistribution) -> Result<Self> {
        if dist.signing_public_key.len() != 32 {
            return Err(Error::InvalidKeyLength {
                expected: 32,
                actual: dist.signing_public_key.len(),
            });
        }

        let key_bytes: [u8; 32] = dist.signing_public_key.as_slice().try_into()
            .map_err(|_| Error::InvalidKeyLength { expected: 32, actual: dist.signing_public_key.len() })?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Error::KeyGeneration(format!("Invalid verifying key: {}", e)))?;

        Ok(Self {
            sender_fingerprint: dist.sender_fingerprint.clone(),
            chain_key: dist.chain_key,
            verifying_key,
            chain_index: dist.chain_index,
            skipped_keys: HashMap::new(),
        })
    }

    /// Decrypt a sender key message
    pub fn decrypt(&mut self, message: &SenderKeyMessage) -> Result<Vec<u8>> {
        // Verify signature
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(message.group_id.as_bytes());
        sign_data.extend_from_slice(&message.chain_index.to_le_bytes());
        sign_data.extend_from_slice(&message.ciphertext);

        if message.signature.len() != 64 {
            return Err(Error::SignatureVerification);
        }
        let sig_bytes: [u8; 64] = message.signature.as_slice().try_into()
            .map_err(|_| Error::SignatureVerification)?;
        let signature = Signature::from_bytes(&sig_bytes);

        self.verifying_key.verify(&sign_data, &signature)
            .map_err(|_| Error::SignatureVerification)?;

        // Handle message ordering
        let ad = format!("{}||{}", message.group_id, message.chain_index);

        if message.chain_index < self.chain_index {
            // Try skipped keys
            if let Some(mk) = self.skipped_keys.remove(&message.chain_index) {
                return aead::decrypt(&mk, &message.ciphertext, ad.as_bytes());
            }
            return Err(Error::DuplicateMessage);
        }

        // Skip ahead if needed
        if message.chain_index > self.chain_index {
            let skip_count = message.chain_index - self.chain_index;
            if skip_count > MAX_SKIP {
                return Err(Error::MaxSkipExceeded(skip_count));
            }

            // Store skipped message keys
            let mut ck = self.chain_key;
            for idx in self.chain_index..message.chain_index {
                let (new_ck, mk) = kdf_ck(&ck);
                self.skipped_keys.insert(idx, mk);
                ck = new_ck;
            }
            self.chain_key = ck;
            self.chain_index = message.chain_index;
        }

        // Derive message key for this index
        let (new_chain_key, message_key) = kdf_ck(&self.chain_key);
        self.chain_key = new_chain_key;
        self.chain_index += 1;

        aead::decrypt(&message_key, &message.ciphertext, ad.as_bytes())
    }

    /// Get the sender fingerprint
    pub fn sender_fingerprint(&self) -> &str {
        &self.sender_fingerprint
    }

    /// Export state for persistence
    pub fn export_state(&self) -> ReceivedSenderKeyState {
        ReceivedSenderKeyState {
            sender_fingerprint: self.sender_fingerprint.clone(),
            chain_key: self.chain_key,
            signing_public_key: self.verifying_key.as_bytes().to_vec(),
            chain_index: self.chain_index,
            skipped_keys: self.skipped_keys.clone(),
        }
    }

    /// Restore from persisted state
    pub fn from_state(state: &ReceivedSenderKeyState) -> Result<Self> {
        if state.signing_public_key.len() != 32 {
            return Err(Error::InvalidKeyLength {
                expected: 32,
                actual: state.signing_public_key.len(),
            });
        }

        let key_bytes: [u8; 32] = state.signing_public_key.as_slice().try_into()
            .map_err(|_| Error::InvalidKeyLength { expected: 32, actual: state.signing_public_key.len() })?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Error::KeyGeneration(format!("Invalid verifying key: {}", e)))?;

        Ok(Self {
            sender_fingerprint: state.sender_fingerprint.clone(),
            chain_key: state.chain_key,
            verifying_key,
            chain_index: state.chain_index,
            skipped_keys: state.skipped_keys.clone(),
        })
    }
}

impl Drop for ReceivedSenderKey {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

/// Serializable state for persisting a received sender key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedSenderKeyState {
    pub sender_fingerprint: String,
    pub chain_key: [u8; 32],
    pub signing_public_key: Vec<u8>,
    pub chain_index: u32,
    pub skipped_keys: HashMap<u32, [u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_key_encrypt_decrypt() {
        let mut sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice");

        let mut receiver = ReceivedSenderKey::from_distribution(&dist).unwrap();

        let plaintext = b"Hello group!";
        let msg = sender.encrypt("alice", plaintext).unwrap();

        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chain_ratchet() {
        let mut sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice");

        let mut receiver = ReceivedSenderKey::from_distribution(&dist).unwrap();

        // Send multiple messages
        for i in 0..10 {
            let msg = sender.encrypt("alice", format!("msg {}", i).as_bytes()).unwrap();
            assert_eq!(msg.chain_index, i);
            let decrypted = receiver.decrypt(&msg).unwrap();
            assert_eq!(decrypted, format!("msg {}", i).as_bytes());
        }
    }

    #[test]
    fn test_out_of_order_delivery() {
        let mut sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice");

        let mut receiver = ReceivedSenderKey::from_distribution(&dist).unwrap();

        // Send 5 messages
        let mut messages = Vec::new();
        for i in 0..5 {
            let msg = sender.encrypt("alice", format!("msg {}", i).as_bytes()).unwrap();
            messages.push(msg);
        }

        // Deliver out of order: 0, 2, 1, 4, 3
        let order = [0, 2, 1, 4, 3];
        for &idx in &order {
            let decrypted = receiver.decrypt(&messages[idx]).unwrap();
            assert_eq!(decrypted, format!("msg {}", idx).as_bytes());
        }
    }

    #[test]
    fn test_signature_verification() {
        let mut sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice");

        let mut receiver = ReceivedSenderKey::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt("alice", b"hello").unwrap();

        // Tamper with the signature
        msg.signature[0] ^= 0xff;

        let result = receiver.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_distribution_roundtrip() {
        let sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice_fp");

        assert_eq!(dist.group_id, "group-001");
        assert_eq!(dist.sender_fingerprint, "alice_fp");
        assert_eq!(dist.chain_index, 0);
        assert_eq!(dist.signing_public_key.len(), 32);

        // Serialize and deserialize
        let bytes = bincode::serialize(&dist).unwrap();
        let restored: SenderKeyDistribution = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.group_id, dist.group_id);
        assert_eq!(restored.chain_key, dist.chain_key);

        // Can create receiver from it
        let receiver = ReceivedSenderKey::from_distribution(&restored).unwrap();
        assert_eq!(receiver.sender_fingerprint(), "alice_fp");
    }

    #[test]
    fn test_duplicate_message_rejected() {
        let mut sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice");

        let mut receiver = ReceivedSenderKey::from_distribution(&dist).unwrap();

        let msg = sender.encrypt("alice", b"hello").unwrap();

        // First decrypt succeeds
        receiver.decrypt(&msg).unwrap();

        // Second decrypt fails (duplicate)
        let result = receiver.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_export_restore() {
        let mut sender = SenderKey::generate("group-001".to_string());
        let dist = sender.distribution("alice");

        let mut receiver = ReceivedSenderKey::from_distribution(&dist).unwrap();

        // Process some messages
        for i in 0..5 {
            let msg = sender.encrypt("alice", format!("msg {}", i).as_bytes()).unwrap();
            receiver.decrypt(&msg).unwrap();
        }

        // Export and restore
        let state = receiver.export_state();
        let bytes = bincode::serialize(&state).unwrap();
        let restored_state: ReceivedSenderKeyState = bincode::deserialize(&bytes).unwrap();
        let mut restored = ReceivedSenderKey::from_state(&restored_state).unwrap();

        // Should be able to decrypt new messages
        let msg = sender.encrypt("alice", b"after restore").unwrap();
        let decrypted = restored.decrypt(&msg).unwrap();
        assert_eq!(decrypted, b"after restore");
    }
}
