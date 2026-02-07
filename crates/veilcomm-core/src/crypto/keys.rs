//! Identity and ephemeral key management
//!
//! Implements the key hierarchy for VeilComm:
//! - Identity Key: Long-term Ed25519 signing key + X25519 DH key
//! - Signed Pre-Key: Medium-term X25519 key signed by identity
//! - One-Time Pre-Keys: Ephemeral X25519 keys for initial key exchange

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::pq::{KyberKeyPair, KyberPublicKey};
use crate::error::{Error, Result};

/// Size of Ed25519 public key in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of Ed25519 secret key in bytes
pub const ED25519_SECRET_KEY_SIZE: usize = 32;
/// Size of X25519 public key in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of X25519 secret key in bytes
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// Long-term identity key pair
///
/// Contains signing (Ed25519), DH (X25519), and post-quantum (Kyber-1024) key pairs.
/// Implements manual `Drop` to ensure all secret key material is zeroized,
/// including the Ed25519 signing key and Kyber secret key.
#[derive(Clone)]
pub struct IdentityKeyPair {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// X25519 secret key for DH operations
    dh_secret: X25519SecretKey,
    /// Kyber-1024 key pair for post-quantum KEM (has its own Drop for zeroization)
    kyber_keypair: KyberKeyPair,
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        // Zeroize the X25519 DH secret key (it implements Zeroize via ZeroizeOnDrop wrapper,
        // but we explicitly zeroize here since we're doing manual Drop)
        self.dh_secret.zeroize();

        // Zeroize the Ed25519 signing key bytes manually since SigningKey
        // doesn't implement the Zeroize trait
        let mut signing_bytes = self.signing_key.to_bytes();
        signing_bytes.zeroize();
        // Overwrite the signing key with a zeroed key
        self.signing_key = SigningKey::from_bytes(&[0u8; 32]);

        // KyberKeyPair has its own Drop impl that handles zeroization,
        // so it will be zeroized when it is dropped after this Drop completes.
    }
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let dh_secret = X25519SecretKey::random_from_rng(&mut OsRng);
        let kyber_keypair = KyberKeyPair::generate();

        Self {
            signing_key,
            dh_secret,
            kyber_keypair,
        }
    }

    /// Create identity key pair from raw bytes
    pub fn from_bytes(
        signing_bytes: &[u8],
        dh_bytes: &[u8],
        kyber_public_bytes: &[u8],
        kyber_secret_bytes: &[u8],
    ) -> Result<Self> {
        if signing_bytes.len() != ED25519_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: ED25519_SECRET_KEY_SIZE,
                actual: signing_bytes.len(),
            });
        }
        if dh_bytes.len() != X25519_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: X25519_SECRET_KEY_SIZE,
                actual: dh_bytes.len(),
            });
        }

        let signing_bytes_arr: [u8; 32] = signing_bytes.try_into().unwrap();
        let dh_bytes_arr: [u8; 32] = dh_bytes.try_into().unwrap();

        let signing_key = SigningKey::from_bytes(&signing_bytes_arr);
        let dh_secret = X25519SecretKey::from(dh_bytes_arr);
        let kyber_keypair = KyberKeyPair::from_bytes(kyber_public_bytes, kyber_secret_bytes)?;

        Ok(Self {
            signing_key,
            dh_secret,
            kyber_keypair,
        })
    }

    /// Get the public identity key bundle
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            verifying_key: self.signing_key.verifying_key(),
            dh_public: X25519PublicKey::from(&self.dh_secret),
            kyber_public: self.kyber_keypair.public_key(),
        }
    }

    /// Sign a message with the identity key
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Get the X25519 secret key for DH operations
    pub fn dh_secret(&self) -> &X25519SecretKey {
        &self.dh_secret
    }

    /// Get the Kyber key pair for post-quantum KEM
    pub fn kyber_keypair(&self) -> &KyberKeyPair {
        &self.kyber_keypair
    }

    /// Export signing key bytes (for secure storage)
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Export DH secret key bytes (for secure storage)
    pub fn dh_secret_bytes(&self) -> [u8; 32] {
        self.dh_secret.to_bytes()
    }

    /// Export Kyber public key bytes (for secure storage)
    pub fn kyber_public_key_bytes(&self) -> Vec<u8> {
        self.kyber_keypair.public_key_bytes()
    }

    /// Export Kyber secret key bytes (for secure storage)
    pub fn kyber_secret_key_bytes(&self) -> Vec<u8> {
        self.kyber_keypair.secret_key_bytes()
    }
}

/// Public portion of an identity key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPublicKey {
    /// Ed25519 verifying key
    #[serde(with = "verifying_key_serde")]
    verifying_key: VerifyingKey,
    /// X25519 public key for DH
    #[serde(with = "x25519_public_key_serde")]
    dh_public: X25519PublicKey,
    /// Kyber-1024 public key for post-quantum KEM
    kyber_public: KyberPublicKey,
}

impl PartialEq for IdentityPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.verifying_key == other.verifying_key
            && self.dh_public.as_bytes() == other.dh_public.as_bytes()
            && self.kyber_public.to_bytes() == other.kyber_public.to_bytes()
    }
}

impl Eq for IdentityPublicKey {}

impl IdentityPublicKey {
    /// Verify a signature against this identity
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|_| Error::SignatureVerification)
    }

    /// Get the X25519 public key for DH
    pub fn dh_public(&self) -> &X25519PublicKey {
        &self.dh_public
    }

    /// Get the Ed25519 verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the Kyber-1024 public key
    pub fn kyber_public(&self) -> &KyberPublicKey {
        &self.kyber_public
    }

    /// Generate a fingerprint for identity verification
    pub fn fingerprint(&self) -> String {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(self.verifying_key.as_bytes());
        hasher.update(self.dh_public.as_bytes());
        hasher.update(self.kyber_public.to_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..16])
    }

    /// Create from raw bytes
    pub fn from_bytes(
        verifying_bytes: &[u8],
        dh_bytes: &[u8],
        kyber_public_bytes: &[u8],
    ) -> Result<Self> {
        if verifying_bytes.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_SIZE,
                actual: verifying_bytes.len(),
            });
        }
        if dh_bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                actual: dh_bytes.len(),
            });
        }

        let verifying_bytes_arr: [u8; 32] = verifying_bytes.try_into().unwrap();
        let dh_bytes_arr: [u8; 32] = dh_bytes.try_into().unwrap();

        let verifying_key = VerifyingKey::from_bytes(&verifying_bytes_arr)
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;
        let dh_public = X25519PublicKey::from(dh_bytes_arr);
        let kyber_public = KyberPublicKey::from_bytes(kyber_public_bytes)?;

        Ok(Self {
            verifying_key,
            dh_public,
            kyber_public,
        })
    }

    /// Export verifying key bytes
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Export DH public key bytes
    pub fn dh_public_bytes(&self) -> [u8; 32] {
        self.dh_public.to_bytes()
    }

    /// Export Kyber public key bytes
    pub fn kyber_public_bytes(&self) -> Vec<u8> {
        self.kyber_public.to_bytes()
    }
}

/// A signed pre-key for X3DH
///
/// Rotated periodically (e.g., weekly) and signed by the identity key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SignedPreKey {
    /// Unique identifier for this pre-key
    #[zeroize(skip)]
    pub id: u32,
    /// X25519 secret key
    secret: X25519SecretKey,
    /// Signature over the public key
    #[zeroize(skip)]
    signature: Signature,
    /// Timestamp when this key was created
    #[zeroize(skip)]
    pub created_at: i64,
}

impl SignedPreKey {
    /// Generate a new signed pre-key
    pub fn generate(id: u32, identity: &IdentityKeyPair) -> Self {
        let secret = X25519SecretKey::random_from_rng(&mut OsRng);
        let public = X25519PublicKey::from(&secret);

        // Sign the public key
        let signature = identity.sign(public.as_bytes());

        Self {
            id,
            secret,
            signature,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Create from raw components
    pub fn from_bytes(
        id: u32,
        secret_bytes: &[u8],
        signature_bytes: &[u8],
        created_at: i64,
    ) -> Result<Self> {
        if secret_bytes.len() != X25519_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: X25519_SECRET_KEY_SIZE,
                actual: secret_bytes.len(),
            });
        }

        let secret_arr: [u8; 32] = secret_bytes.try_into().unwrap();
        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| Error::InvalidKeyLength {
                expected: 64,
                actual: signature_bytes.len(),
            })?;

        Ok(Self {
            id,
            secret: X25519SecretKey::from(secret_arr),
            signature: Signature::from_bytes(&sig_arr),
            created_at,
        })
    }

    /// Get the public pre-key
    pub fn public_key(&self) -> SignedPreKeyPublic {
        SignedPreKeyPublic {
            id: self.id,
            public: X25519PublicKey::from(&self.secret),
            signature: self.signature,
        }
    }

    /// Get the secret key for DH
    pub fn secret(&self) -> &X25519SecretKey {
        &self.secret
    }

    /// Export secret key bytes
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Export signature bytes
    pub fn signature_bytes(&self) -> [u8; 64] {
        self.signature.to_bytes()
    }
}

/// Public portion of a signed pre-key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPreKeyPublic {
    pub id: u32,
    #[serde(with = "x25519_public_key_serde")]
    pub public: X25519PublicKey,
    #[serde(with = "signature_serde")]
    pub signature: Signature,
}

impl SignedPreKeyPublic {
    /// Verify the signature using the identity's verifying key
    pub fn verify(&self, identity: &IdentityPublicKey) -> Result<()> {
        identity.verify(self.public.as_bytes(), &self.signature)
    }
}

/// A one-time pre-key for X3DH
///
/// Consumed on first use for additional forward secrecy.
#[derive(Clone, ZeroizeOnDrop)]
pub struct OneTimePreKey {
    #[zeroize(skip)]
    pub id: u32,
    secret: X25519SecretKey,
}

impl OneTimePreKey {
    /// Generate a new one-time pre-key
    pub fn generate(id: u32) -> Self {
        Self {
            id,
            secret: X25519SecretKey::random_from_rng(&mut OsRng),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(id: u32, secret_bytes: &[u8]) -> Result<Self> {
        if secret_bytes.len() != X25519_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: X25519_SECRET_KEY_SIZE,
                actual: secret_bytes.len(),
            });
        }

        let secret_arr: [u8; 32] = secret_bytes.try_into().unwrap();
        Ok(Self {
            id,
            secret: X25519SecretKey::from(secret_arr),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> OneTimePreKeyPublic {
        OneTimePreKeyPublic {
            id: self.id,
            public: X25519PublicKey::from(&self.secret),
        }
    }

    /// Get the secret key for DH
    pub fn secret(&self) -> &X25519SecretKey {
        &self.secret
    }

    /// Export secret key bytes
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

/// Public portion of a one-time pre-key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneTimePreKeyPublic {
    pub id: u32,
    #[serde(with = "x25519_public_key_serde")]
    pub public: X25519PublicKey,
}

/// An ephemeral key pair for a single message exchange
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    secret: X25519SecretKey,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        Self {
            secret: X25519SecretKey::random_from_rng(&mut OsRng),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.secret)
    }

    /// Get the secret key
    pub fn secret(&self) -> &X25519SecretKey {
        &self.secret
    }
}

/// Complete key bundle for publishing to peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity: IdentityPublicKey,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekeys: Vec<OneTimePreKeyPublic>,
}

impl KeyBundle {
    /// Verify the signed pre-key signature
    pub fn verify(&self) -> Result<()> {
        self.signed_prekey.verify(&self.identity)
    }
}

/// Pre-key bundle for X3DH (what initiator receives)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity: IdentityPublicKey,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekey: Option<OneTimePreKeyPublic>,
}

impl PreKeyBundle {
    /// Verify the signed pre-key signature
    pub fn verify(&self) -> Result<()> {
        self.signed_prekey.verify(&self.identity)
    }
}

// Serde helpers for ed25519-dalek types
mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        sig.to_bytes().to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let arr: [u8; 64] = bytes.try_into().map_err(|_| {
            serde::de::Error::custom("Invalid signature length")
        })?;
        Ok(Signature::from_bytes(&arr))
    }
}

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

    #[test]
    fn test_identity_generation() {
        let identity = IdentityKeyPair::generate();
        let public = identity.public_key();

        // Test signing and verification
        let message = b"test message";
        let signature = identity.sign(message);
        assert!(public.verify(message, &signature).is_ok());

        // Test wrong message fails verification
        assert!(public.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_identity_serialization() {
        let identity = IdentityKeyPair::generate();
        let public = identity.public_key();

        let serialized = bincode::serialize(&public).unwrap();
        let deserialized: IdentityPublicKey = bincode::deserialize(&serialized).unwrap();

        assert_eq!(public.fingerprint(), deserialized.fingerprint());
    }

    #[test]
    fn test_signed_prekey() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &identity);
        let spk_public = spk.public_key();

        // Verification should succeed with correct identity
        assert!(spk_public.verify(&identity.public_key()).is_ok());

        // Verification should fail with wrong identity
        let other_identity = IdentityKeyPair::generate();
        assert!(spk_public.verify(&other_identity.public_key()).is_err());
    }

    #[test]
    fn test_key_bundle() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &identity);
        let otpks: Vec<_> = (0..10).map(|i| OneTimePreKey::generate(i)).collect();

        let bundle = KeyBundle {
            identity: identity.public_key(),
            signed_prekey: spk.public_key(),
            one_time_prekeys: otpks.iter().map(|k| k.public_key()).collect(),
        };

        assert!(bundle.verify().is_ok());
        assert_eq!(bundle.one_time_prekeys.len(), 10);
    }

    #[test]
    fn test_fingerprint_consistency() {
        let identity = IdentityKeyPair::generate();
        let public = identity.public_key();

        let fp1 = public.fingerprint();
        let fp2 = public.fingerprint();

        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32); // 16 bytes as hex
    }
}
