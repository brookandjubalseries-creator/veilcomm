//! Post-Quantum Cryptographic Primitives
//!
//! Implements Kyber-1024 key encapsulation mechanism (KEM) for post-quantum
//! security. This is used in combination with X25519 for hybrid key exchange.
//!
//! Kyber is a lattice-based KEM that is a finalist in the NIST post-quantum
//! cryptography standardization process.

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Size of Kyber-1024 public key
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1568;
/// Size of Kyber-1024 secret key
pub const KYBER_SECRET_KEY_SIZE: usize = 3168;
/// Size of Kyber-1024 ciphertext
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;
/// Size of Kyber-1024 shared secret
pub const KYBER_SHARED_SECRET_SIZE: usize = 32;

/// Kyber-1024 key pair
pub struct KyberKeyPair {
    /// Public key for encapsulation
    public_key: kyber1024::PublicKey,
    /// Secret key for decapsulation
    secret_key: kyber1024::SecretKey,
}

impl Clone for KyberKeyPair {
    fn clone(&self) -> Self {
        Self {
            public_key: kyber1024::PublicKey::from_bytes(self.public_key.as_bytes())
                .expect("Cloning valid public key should not fail"),
            secret_key: kyber1024::SecretKey::from_bytes(self.secret_key.as_bytes())
                .expect("Cloning valid secret key should not fail"),
        }
    }
}

impl Drop for KyberKeyPair {
    fn drop(&mut self) {
        // Zeroize the secret key bytes by extracting, zeroizing, and
        // replacing with a zeroized key. We overwrite the secret key
        // field with a key constructed from zeroed bytes.
        let mut secret_bytes = self.secret_key.as_bytes().to_vec();
        secret_bytes.zeroize();
        // Overwrite the secret key in-place by creating a new one from zeroed bytes
        let zeroed = vec![0u8; KYBER_SECRET_KEY_SIZE];
        if let Ok(zeroed_key) = kyber1024::SecretKey::from_bytes(&zeroed) {
            self.secret_key = zeroed_key;
        }
    }
}

impl KyberKeyPair {
    /// Generate a new Kyber-1024 key pair
    pub fn generate() -> Self {
        let (public_key, secret_key) = kyber1024::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Result<Self> {
        let public_key = kyber1024::PublicKey::from_bytes(public_bytes)
            .map_err(|_| Error::InvalidKeyLength {
                expected: KYBER_PUBLIC_KEY_SIZE,
                actual: public_bytes.len(),
            })?;

        let secret_key = kyber1024::SecretKey::from_bytes(secret_bytes)
            .map_err(|_| Error::InvalidKeyLength {
                expected: KYBER_SECRET_KEY_SIZE,
                actual: secret_bytes.len(),
            })?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> KyberPublicKey {
        KyberPublicKey {
            inner: self.public_key.clone(),
        }
    }

    /// Decapsulate a ciphertext to obtain the shared secret
    pub fn decapsulate(&self, ciphertext: &KyberCiphertext) -> Result<PqSharedSecret> {
        let shared_secret = kyber1024::decapsulate(&ciphertext.inner, &self.secret_key);
        let mut secret = [0u8; KYBER_SHARED_SECRET_SIZE];
        secret.copy_from_slice(shared_secret.as_bytes());
        Ok(PqSharedSecret { secret })
    }

    /// Export public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Export secret key bytes
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_bytes().to_vec()
    }
}

/// Kyber-1024 public key
#[derive(Clone)]
pub struct KyberPublicKey {
    inner: kyber1024::PublicKey,
}

impl std::fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KyberPublicKey")
            .field("size", &self.to_bytes().len())
            .finish()
    }
}

impl KyberPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = kyber1024::PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidKeyLength {
            expected: KYBER_PUBLIC_KEY_SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self { inner })
    }

    /// Encapsulate to create a shared secret and ciphertext
    pub fn encapsulate(&self) -> (PqSharedSecret, KyberCiphertext) {
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&self.inner);
        let mut secret = [0u8; KYBER_SHARED_SECRET_SIZE];
        secret.copy_from_slice(shared_secret.as_bytes());
        (
            PqSharedSecret { secret },
            KyberCiphertext { inner: ciphertext },
        )
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl Serialize for KyberPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KyberPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Kyber-1024 ciphertext
#[derive(Clone)]
pub struct KyberCiphertext {
    inner: kyber1024::Ciphertext,
}

impl std::fmt::Debug for KyberCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KyberCiphertext")
            .field("size", &self.to_bytes().len())
            .finish()
    }
}

impl KyberCiphertext {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner =
            kyber1024::Ciphertext::from_bytes(bytes).map_err(|_| Error::InvalidKeyLength {
                expected: KYBER_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            })?;
        Ok(Self { inner })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl Serialize for KyberCiphertext {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KyberCiphertext {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Post-quantum shared secret
#[derive(Clone, ZeroizeOnDrop)]
pub struct PqSharedSecret {
    secret: [u8; KYBER_SHARED_SECRET_SIZE],
}

impl PqSharedSecret {
    /// Get the shared secret bytes
    pub fn as_bytes(&self) -> &[u8; KYBER_SHARED_SECRET_SIZE] {
        &self.secret
    }
}

/// Combine classical (X25519) and post-quantum (Kyber) shared secrets
///
/// Uses a simple concatenation and hash for domain separation.
/// The result provides security as long as either primitive is secure.
pub fn combine_secrets(
    classical_secret: &[u8; 32],
    pq_secret: &PqSharedSecret,
) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};

    let mut hasher = Blake2s256::new();
    hasher.update(b"VeilComm_HybridKEM_v1");
    hasher.update(classical_secret);
    hasher.update(pq_secret.as_bytes());

    let mut combined = [0u8; 32];
    combined.copy_from_slice(&hasher.finalize());
    combined
}

/// Hybrid key encapsulation result
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridKemCiphertext {
    /// Kyber ciphertext
    pub kyber_ciphertext: KyberCiphertext,
    /// Any additional data (e.g., X25519 ephemeral public key)
    pub additional_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_keypair_generation() {
        let keypair = KyberKeyPair::generate();
        let public = keypair.public_key();

        // Check sizes
        assert_eq!(public.to_bytes().len(), KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key_bytes().len(), KYBER_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_kyber_encapsulation() {
        let alice = KyberKeyPair::generate();
        let (secret1, ciphertext) = alice.public_key().encapsulate();
        let secret2 = alice.decapsulate(&ciphertext).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let alice = KyberKeyPair::generate();
        let bob = KyberKeyPair::generate();

        let (secret1, ciphertext1) = alice.public_key().encapsulate();
        let (secret2, ciphertext2) = bob.public_key().encapsulate();

        // Different keypairs should produce different secrets
        assert_ne!(secret1.as_bytes(), secret2.as_bytes());

        // Ciphertexts should also be different
        assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());
    }

    #[test]
    fn test_kyber_serialization() {
        let keypair = KyberKeyPair::generate();
        let public = keypair.public_key();

        let serialized = bincode::serialize(&public).unwrap();
        let deserialized: KyberPublicKey = bincode::deserialize(&serialized).unwrap();

        // Should produce same encapsulation
        let (secret1, ct1) = public.encapsulate();
        let dec1 = keypair.decapsulate(&ct1).unwrap();

        // Deserialized key should work
        let (secret2, ct2) = deserialized.encapsulate();
        let dec2 = keypair.decapsulate(&ct2).unwrap();

        // Both should be decapsulatable
        assert_eq!(secret1.as_bytes(), dec1.as_bytes());
        assert_eq!(secret2.as_bytes(), dec2.as_bytes());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let keypair = KyberKeyPair::generate();
        let (_, ciphertext) = keypair.public_key().encapsulate();

        let serialized = bincode::serialize(&ciphertext).unwrap();
        let deserialized: KyberCiphertext = bincode::deserialize(&serialized).unwrap();

        // Should be able to decapsulate
        let secret1 = keypair.decapsulate(&ciphertext).unwrap();
        let secret2 = keypair.decapsulate(&deserialized).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_combine_secrets() {
        let classical = [1u8; 32];
        let keypair = KyberKeyPair::generate();
        let (pq_secret, _) = keypair.public_key().encapsulate();

        let combined1 = combine_secrets(&classical, &pq_secret);
        let combined2 = combine_secrets(&classical, &pq_secret);

        // Same inputs should produce same output
        assert_eq!(combined1, combined2);

        // Different classical secret should produce different output
        let different_classical = [2u8; 32];
        let combined3 = combine_secrets(&different_classical, &pq_secret);
        assert_ne!(combined1, combined3);
    }

    #[test]
    fn test_keypair_from_bytes() {
        let keypair1 = KyberKeyPair::generate();
        let public_bytes = keypair1.public_key_bytes();
        let secret_bytes = keypair1.secret_key_bytes();

        let keypair2 = KyberKeyPair::from_bytes(&public_bytes, &secret_bytes).unwrap();

        // Both should be able to decapsulate the same ciphertext
        let (_, ciphertext) = keypair1.public_key().encapsulate();
        let secret1 = keypair1.decapsulate(&ciphertext).unwrap();
        let secret2 = keypair2.decapsulate(&ciphertext).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_invalid_key_bytes() {
        let result = KyberPublicKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());

        let result = KyberCiphertext::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }
}
