//! Extended Triple Diffie-Hellman (X3DH) Key Exchange
//!
//! Implements the X3DH key agreement protocol for establishing shared secrets
//! between two parties. This provides:
//! - Mutual authentication
//! - Forward secrecy
//! - Cryptographic deniability
//!
//! The protocol uses X25519 for Diffie-Hellman operations.

use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::kdf::{concat_keys, derive_key};
use super::keys::{
    EphemeralKeyPair, IdentityKeyPair, IdentityPublicKey, OneTimePreKey, PreKeyBundle, SignedPreKey,
};
use super::pq::{combine_secrets, KyberCiphertext};
use crate::error::{Error, Result};

/// Size of the shared secret in bytes
pub const SHARED_SECRET_SIZE: usize = 32;

/// X3DH protocol info string
const X3DH_INFO: &[u8] = b"X3DH_SharedSecret";

/// Result of X3DH key agreement
#[derive(ZeroizeOnDrop)]
pub struct X3dhSharedSecret {
    /// The shared secret key
    secret: [u8; SHARED_SECRET_SIZE],
    /// Associated data for the session (identities concatenated)
    #[zeroize(skip)]
    pub associated_data: Vec<u8>,
}

impl X3dhSharedSecret {
    /// Get the shared secret bytes
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.secret
    }
}

/// Initial message sent from initiator to responder
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct X3dhInitialMessage {
    /// Initiator's identity public key
    pub identity_key: IdentityPublicKey,
    /// Ephemeral public key used in this exchange
    #[serde(with = "x25519_public_key_serde")]
    pub ephemeral_key: X25519PublicKey,
    /// ID of the signed pre-key used
    pub signed_prekey_id: u32,
    /// ID of the one-time pre-key used (if any)
    pub one_time_prekey_id: Option<u32>,
    /// Kyber-1024 ciphertext for post-quantum KEM
    pub kyber_ciphertext: KyberCiphertext,
}

/// X3DH initiator (Alice) - the party starting the conversation
pub struct X3dhInitiator {
    identity: IdentityKeyPair,
}

impl X3dhInitiator {
    /// Create a new X3DH initiator
    pub fn new(identity: IdentityKeyPair) -> Self {
        Self { identity }
    }

    /// Perform hybrid PQXDH key agreement with a peer's pre-key bundle
    ///
    /// Combines classical X3DH (X25519) with post-quantum KEM (Kyber-1024).
    /// Returns the shared secret and the initial message to send to the peer.
    pub fn agree(&self, peer_bundle: &PreKeyBundle) -> Result<(X3dhSharedSecret, X3dhInitialMessage)> {
        // Verify the signed pre-key
        peer_bundle.verify()?;

        // Generate ephemeral key pair
        let ephemeral = EphemeralKeyPair::generate();

        // Perform DH operations
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = self
            .identity
            .dh_secret()
            .diffie_hellman(&peer_bundle.signed_prekey.public);

        // DH2 = DH(EK_A, IK_B)
        let dh2 = ephemeral
            .secret()
            .diffie_hellman(peer_bundle.identity.dh_public());

        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ephemeral
            .secret()
            .diffie_hellman(&peer_bundle.signed_prekey.public);

        // Combine DH outputs
        let mut dh_outputs = concat_keys(&[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()]);

        // DH4 = DH(EK_A, OPK_B) if one-time pre-key is available
        let one_time_prekey_id = if let Some(ref otpk) = peer_bundle.one_time_prekey {
            let dh4 = ephemeral.secret().diffie_hellman(&otpk.public);
            dh_outputs.extend_from_slice(dh4.as_bytes());
            Some(otpk.id)
        } else {
            None
        };

        // Derive classical shared secret using HKDF
        let classical_bytes = derive_key(&dh_outputs, X3DH_INFO, SHARED_SECRET_SIZE)?;
        let mut classical_secret = [0u8; SHARED_SECRET_SIZE];
        classical_secret.copy_from_slice(&classical_bytes);

        // Post-quantum KEM: encapsulate against peer's Kyber public key
        let (pq_secret, kyber_ciphertext) = peer_bundle.identity.kyber_public().encapsulate();

        // Combine classical and post-quantum secrets
        let hybrid_secret = combine_secrets(&classical_secret, &pq_secret);

        // Create associated data: AD = IK_A || IK_B
        let associated_data = concat_keys(&[
            self.identity.public_key().dh_public().as_bytes(),
            peer_bundle.identity.dh_public().as_bytes(),
        ]);

        // Zeroize intermediate values
        dh_outputs.zeroize();
        classical_secret.zeroize();

        let shared_secret = X3dhSharedSecret {
            secret: hybrid_secret,
            associated_data,
        };

        let initial_message = X3dhInitialMessage {
            identity_key: self.identity.public_key(),
            ephemeral_key: ephemeral.public_key(),
            signed_prekey_id: peer_bundle.signed_prekey.id,
            one_time_prekey_id,
            kyber_ciphertext,
        };

        Ok((shared_secret, initial_message))
    }
}

/// X3DH responder (Bob) - the party receiving the initial message
pub struct X3dhResponder {
    identity: IdentityKeyPair,
    signed_prekey: SignedPreKey,
    one_time_prekeys: Vec<OneTimePreKey>,
}

impl X3dhResponder {
    /// Create a new X3DH responder
    pub fn new(
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekeys: Vec<OneTimePreKey>,
    ) -> Self {
        Self {
            identity,
            signed_prekey,
            one_time_prekeys,
        }
    }

    /// Process an initial message and derive the hybrid shared secret
    ///
    /// Combines classical X3DH with post-quantum Kyber decapsulation.
    /// If a one-time pre-key was used, it is consumed and cannot be reused.
    pub fn agree(&mut self, initial_message: &X3dhInitialMessage) -> Result<X3dhSharedSecret> {
        // Verify the signed pre-key ID matches
        if initial_message.signed_prekey_id != self.signed_prekey.id {
            return Err(Error::SessionNotFound(format!(
                "Signed pre-key {} not found",
                initial_message.signed_prekey_id
            )));
        }

        // Perform DH operations (mirrored from initiator)
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = self
            .signed_prekey
            .secret()
            .diffie_hellman(initial_message.identity_key.dh_public());

        // DH2 = DH(IK_B, EK_A)
        let dh2 = self
            .identity
            .dh_secret()
            .diffie_hellman(&initial_message.ephemeral_key);

        // DH3 = DH(SPK_B, EK_A)
        let dh3 = self
            .signed_prekey
            .secret()
            .diffie_hellman(&initial_message.ephemeral_key);

        // Combine DH outputs
        let mut dh_outputs = concat_keys(&[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()]);

        // DH4 = DH(OPK_B, EK_A) if one-time pre-key was used
        if let Some(otpk_id) = initial_message.one_time_prekey_id {
            let otpk_idx = self
                .one_time_prekeys
                .iter()
                .position(|k| k.id == otpk_id)
                .ok_or_else(|| Error::NoOneTimePrekeys)?;

            // Remove and consume the one-time pre-key
            let otpk = self.one_time_prekeys.remove(otpk_idx);
            let dh4 = otpk.secret().diffie_hellman(&initial_message.ephemeral_key);
            dh_outputs.extend_from_slice(dh4.as_bytes());
        }

        // Derive classical shared secret using HKDF
        let classical_bytes = derive_key(&dh_outputs, X3DH_INFO, SHARED_SECRET_SIZE)?;
        let mut classical_secret = [0u8; SHARED_SECRET_SIZE];
        classical_secret.copy_from_slice(&classical_bytes);

        // Post-quantum KEM: decapsulate using our Kyber secret key
        let pq_secret = self
            .identity
            .kyber_keypair()
            .decapsulate(&initial_message.kyber_ciphertext)?;

        // Combine classical and post-quantum secrets
        let hybrid_secret = combine_secrets(&classical_secret, &pq_secret);

        // Create associated data: AD = IK_A || IK_B
        let associated_data = concat_keys(&[
            initial_message.identity_key.dh_public().as_bytes(),
            self.identity.public_key().dh_public().as_bytes(),
        ]);

        // Zeroize intermediate values
        dh_outputs.zeroize();
        classical_secret.zeroize();

        Ok(X3dhSharedSecret {
            secret: hybrid_secret,
            associated_data,
        })
    }

    /// Get a pre-key bundle for publishing
    pub fn get_prekey_bundle(&self, one_time_prekey_idx: Option<usize>) -> PreKeyBundle {
        let one_time_prekey = one_time_prekey_idx
            .and_then(|idx| self.one_time_prekeys.get(idx))
            .map(|k| k.public_key());

        PreKeyBundle {
            identity: self.identity.public_key(),
            signed_prekey: self.signed_prekey.public_key(),
            one_time_prekey,
        }
    }

    /// Number of remaining one-time pre-keys
    pub fn remaining_one_time_prekeys(&self) -> usize {
        self.one_time_prekeys.len()
    }
}

// Serde helper for X25519PublicKey
mod x25519_public_key_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(PublicKey::from(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_responder() -> X3dhResponder {
        let identity = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(1, &identity);
        let one_time_prekeys: Vec<_> = (0..10).map(|i| OneTimePreKey::generate(i)).collect();

        X3dhResponder::new(identity, signed_prekey, one_time_prekeys)
    }

    #[test]
    fn test_x3dh_with_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let alice = X3dhInitiator::new(alice_identity);

        let mut bob = setup_responder();
        let bob_bundle = bob.get_prekey_bundle(Some(0));

        // Alice initiates
        let (alice_secret, initial_msg) = alice.agree(&bob_bundle).unwrap();

        // Bob responds
        let bob_secret = bob.agree(&initial_msg).unwrap();

        // Shared secrets should match
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
        assert_eq!(alice_secret.associated_data, bob_secret.associated_data);

        // One-time pre-key should be consumed
        assert_eq!(bob.remaining_one_time_prekeys(), 9);
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let alice = X3dhInitiator::new(alice_identity);

        let mut bob = setup_responder();
        let bob_bundle = bob.get_prekey_bundle(None);

        // Alice initiates without one-time pre-key
        let (alice_secret, initial_msg) = alice.agree(&bob_bundle).unwrap();

        // Bob responds
        let bob_secret = bob.agree(&initial_msg).unwrap();

        // Shared secrets should match
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());

        // No one-time pre-key consumed
        assert_eq!(bob.remaining_one_time_prekeys(), 10);
    }

    #[test]
    fn test_x3dh_different_initiators_different_secrets() {
        let alice1 = X3dhInitiator::new(IdentityKeyPair::generate());
        let alice2 = X3dhInitiator::new(IdentityKeyPair::generate());

        let bob = setup_responder();
        let bob_bundle1 = bob.get_prekey_bundle(Some(0));
        let bob_bundle2 = bob.get_prekey_bundle(Some(1));

        let (secret1, _) = alice1.agree(&bob_bundle1).unwrap();
        let (secret2, _) = alice2.agree(&bob_bundle2).unwrap();

        // Different initiators should produce different secrets
        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_x3dh_initial_message_serialization() {
        let alice = X3dhInitiator::new(IdentityKeyPair::generate());
        let bob = setup_responder();
        let bob_bundle = bob.get_prekey_bundle(Some(0));

        let (_, initial_msg) = alice.agree(&bob_bundle).unwrap();

        // Serialize and deserialize
        let serialized = bincode::serialize(&initial_msg).unwrap();
        let deserialized: X3dhInitialMessage = bincode::deserialize(&serialized).unwrap();

        assert_eq!(
            initial_msg.identity_key.fingerprint(),
            deserialized.identity_key.fingerprint()
        );
        assert_eq!(initial_msg.signed_prekey_id, deserialized.signed_prekey_id);
        assert_eq!(
            initial_msg.one_time_prekey_id,
            deserialized.one_time_prekey_id
        );
    }

    #[test]
    fn test_x3dh_wrong_signed_prekey_fails() {
        let alice = X3dhInitiator::new(IdentityKeyPair::generate());
        let mut bob = setup_responder();
        let bob_bundle = bob.get_prekey_bundle(Some(0));

        let (_, mut initial_msg) = alice.agree(&bob_bundle).unwrap();

        // Tamper with signed pre-key ID
        initial_msg.signed_prekey_id = 999;

        // Bob should reject
        assert!(bob.agree(&initial_msg).is_err());
    }

    #[test]
    fn test_prekey_bundle_verification() {
        let bob = setup_responder();
        let bundle = bob.get_prekey_bundle(Some(0));

        // Valid bundle should verify
        assert!(bundle.verify().is_ok());
    }
}
