//! Secure key storage with Argon2 password derivation
//!
//! Stores identity keys, pre-keys, and session keys encrypted at rest.

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Size of the encryption key
const KEY_SIZE: usize = 32;
/// Size of the nonce
const NONCE_SIZE: usize = 12;
/// Size of the salt
const SALT_SIZE: usize = 16;

/// Create an Argon2 instance with secure parameters:
/// Algorithm: Argon2id, Version: 0x13, Memory: 64 MiB, Iterations: 3, Parallelism: 4
fn argon2_instance<'a>() -> Argon2<'a> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
    )
}

/// Encrypted key store
#[derive(Serialize, Deserialize)]
pub struct KeyStore {
    /// Salt for password-based key derivation
    salt: [u8; SALT_SIZE],
    /// Argon2 password hash for verification
    password_hash: String,
    /// Encrypted identity key (signing key bytes)
    encrypted_signing_key: Vec<u8>,
    /// Encrypted DH secret key
    encrypted_dh_key: Vec<u8>,
    /// Encrypted Kyber-1024 public key
    encrypted_kyber_public_key: Vec<u8>,
    /// Encrypted Kyber-1024 secret key
    encrypted_kyber_secret_key: Vec<u8>,
    /// Encrypted signed pre-key
    encrypted_signed_prekey: Option<EncryptedPreKey>,
    /// Encrypted one-time pre-keys
    encrypted_one_time_prekeys: Vec<EncryptedPreKey>,
    /// Next one-time pre-key ID
    next_otpk_id: u32,
    /// Next signed pre-key ID
    next_spk_id: u32,
}

/// Encrypted pre-key
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedPreKey {
    pub id: u32,
    pub encrypted_secret: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub created_at: i64,
}

impl KeyStore {
    /// Create a new key store with a password
    ///
    /// Generates a new identity key pair and encrypts it with the password.
    pub fn create(password: &str) -> Result<(Self, veilcomm_core::crypto::IdentityKeyPair)> {
        // Generate salt
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        // Hash password for verification
        let salt_string = SaltString::encode_b64(&salt)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;
        let argon2 = argon2_instance();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?
            .to_string();

        // Derive encryption key from password
        let encryption_key = derive_encryption_key(password, &salt)?;

        // Generate identity key pair
        let identity = veilcomm_core::crypto::IdentityKeyPair::generate();

        // Encrypt the keys
        let encrypted_signing_key =
            encrypt_data(&encryption_key, &identity.signing_key_bytes())?;
        let encrypted_dh_key = encrypt_data(&encryption_key, &identity.dh_secret_bytes())?;
        let encrypted_kyber_public_key =
            encrypt_data(&encryption_key, &identity.kyber_public_key_bytes())?;
        let encrypted_kyber_secret_key =
            encrypt_data(&encryption_key, &identity.kyber_secret_key_bytes())?;

        let store = Self {
            salt,
            password_hash,
            encrypted_signing_key,
            encrypted_dh_key,
            encrypted_kyber_public_key,
            encrypted_kyber_secret_key,
            encrypted_signed_prekey: None,
            encrypted_one_time_prekeys: Vec::new(),
            next_otpk_id: 0,
            next_spk_id: 1,
        };

        Ok((store, identity))
    }

    /// Open an existing key store with a password
    pub fn open(&self, password: &str) -> Result<veilcomm_core::crypto::IdentityKeyPair> {
        // Verify password
        self.verify_password(password)?;

        // Derive encryption key
        let encryption_key = derive_encryption_key(password, &self.salt)?;

        // Decrypt keys
        let signing_key_bytes = decrypt_data(&encryption_key, &self.encrypted_signing_key)?;
        let dh_key_bytes = decrypt_data(&encryption_key, &self.encrypted_dh_key)?;
        let kyber_public_bytes = decrypt_data(&encryption_key, &self.encrypted_kyber_public_key)?;
        let kyber_secret_bytes = decrypt_data(&encryption_key, &self.encrypted_kyber_secret_key)?;

        // Reconstruct identity
        let identity = veilcomm_core::crypto::IdentityKeyPair::from_bytes(
            &signing_key_bytes,
            &dh_key_bytes,
            &kyber_public_bytes,
            &kyber_secret_bytes,
        )?;

        Ok(identity)
    }

    /// Verify password without decrypting keys
    pub fn verify_password(&self, password: &str) -> Result<()> {
        let parsed_hash = PasswordHash::new(&self.password_hash)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;

        argon2_instance()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| Error::InvalidPassword)
    }

    /// Generate and store a new signed pre-key
    pub fn generate_signed_prekey(
        &mut self,
        password: &str,
        identity: &veilcomm_core::crypto::IdentityKeyPair,
    ) -> Result<veilcomm_core::crypto::SignedPreKey> {
        self.verify_password(password)?;
        let encryption_key = derive_encryption_key(password, &self.salt)?;

        let spk = veilcomm_core::crypto::SignedPreKey::generate(self.next_spk_id, identity);
        self.next_spk_id += 1;

        let encrypted_secret = encrypt_data(&encryption_key, &spk.secret_bytes())?;

        self.encrypted_signed_prekey = Some(EncryptedPreKey {
            id: spk.id,
            encrypted_secret,
            signature: Some(spk.signature_bytes().to_vec()),
            created_at: spk.created_at,
        });

        Ok(spk)
    }

    /// Get the current signed pre-key
    pub fn get_signed_prekey(
        &self,
        password: &str,
    ) -> Result<Option<veilcomm_core::crypto::SignedPreKey>> {
        self.verify_password(password)?;
        let encryption_key = derive_encryption_key(password, &self.salt)?;

        if let Some(ref encrypted) = self.encrypted_signed_prekey {
            let secret_bytes = decrypt_data(&encryption_key, &encrypted.encrypted_secret)?;
            let signature = encrypted
                .signature
                .as_ref()
                .ok_or_else(|| Error::KeyNotFound("Missing signature".to_string()))?;

            let spk = veilcomm_core::crypto::SignedPreKey::from_bytes(
                encrypted.id,
                &secret_bytes,
                signature,
                encrypted.created_at,
            )?;

            Ok(Some(spk))
        } else {
            Ok(None)
        }
    }

    /// Generate new one-time pre-keys
    pub fn generate_one_time_prekeys(
        &mut self,
        password: &str,
        count: u32,
    ) -> Result<Vec<veilcomm_core::crypto::OneTimePreKey>> {
        self.verify_password(password)?;
        let encryption_key = derive_encryption_key(password, &self.salt)?;

        let mut otpks = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let otpk = veilcomm_core::crypto::OneTimePreKey::generate(self.next_otpk_id);
            self.next_otpk_id += 1;

            let encrypted_secret = encrypt_data(&encryption_key, &otpk.secret_bytes())?;

            self.encrypted_one_time_prekeys.push(EncryptedPreKey {
                id: otpk.id,
                encrypted_secret,
                signature: None,
                created_at: chrono::Utc::now().timestamp(),
            });

            otpks.push(otpk);
        }

        Ok(otpks)
    }

    /// Get a one-time pre-key by ID (removes it from storage)
    pub fn consume_one_time_prekey(
        &mut self,
        password: &str,
        id: u32,
    ) -> Result<veilcomm_core::crypto::OneTimePreKey> {
        self.verify_password(password)?;
        let encryption_key = derive_encryption_key(password, &self.salt)?;

        let idx = self
            .encrypted_one_time_prekeys
            .iter()
            .position(|k| k.id == id)
            .ok_or_else(|| Error::KeyNotFound(format!("One-time pre-key {}", id)))?;

        let encrypted = self.encrypted_one_time_prekeys.remove(idx);
        let secret_bytes = decrypt_data(&encryption_key, &encrypted.encrypted_secret)?;

        let otpk = veilcomm_core::crypto::OneTimePreKey::from_bytes(id, &secret_bytes)?;
        Ok(otpk)
    }

    /// Number of available one-time pre-keys
    pub fn one_time_prekey_count(&self) -> usize {
        self.encrypted_one_time_prekeys.len()
    }

    /// Serialize the key store to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Deserialize a key store from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Change the password
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        // Verify old password
        self.verify_password(old_password)?;

        // Decrypt with old password
        let old_key = derive_encryption_key(old_password, &self.salt)?;
        let signing_key_bytes = decrypt_data(&old_key, &self.encrypted_signing_key)?;
        let dh_key_bytes = decrypt_data(&old_key, &self.encrypted_dh_key)?;
        let kyber_public_bytes = decrypt_data(&old_key, &self.encrypted_kyber_public_key)?;
        let kyber_secret_bytes = decrypt_data(&old_key, &self.encrypted_kyber_secret_key)?;

        // Generate new salt and hash
        let mut new_salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut new_salt);

        let salt_string = SaltString::encode_b64(&new_salt)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;
        let argon2 = argon2_instance();
        let new_hash = argon2
            .hash_password(new_password.as_bytes(), &salt_string)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?
            .to_string();

        // Derive new encryption key
        let new_key = derive_encryption_key(new_password, &new_salt)?;

        // Re-encrypt identity keys
        let new_encrypted_signing = encrypt_data(&new_key, &signing_key_bytes)?;
        let new_encrypted_dh = encrypt_data(&new_key, &dh_key_bytes)?;
        let new_encrypted_kyber_public = encrypt_data(&new_key, &kyber_public_bytes)?;
        let new_encrypted_kyber_secret = encrypt_data(&new_key, &kyber_secret_bytes)?;

        // Re-encrypt pre-keys
        let new_signed_prekey = if let Some(ref old_spk) = self.encrypted_signed_prekey {
            let secret = decrypt_data(&old_key, &old_spk.encrypted_secret)?;
            Some(EncryptedPreKey {
                id: old_spk.id,
                encrypted_secret: encrypt_data(&new_key, &secret)?,
                signature: old_spk.signature.clone(),
                created_at: old_spk.created_at,
            })
        } else {
            None
        };

        let mut new_otpks = Vec::with_capacity(self.encrypted_one_time_prekeys.len());
        for old_otpk in &self.encrypted_one_time_prekeys {
            let secret = decrypt_data(&old_key, &old_otpk.encrypted_secret)?;
            new_otpks.push(EncryptedPreKey {
                id: old_otpk.id,
                encrypted_secret: encrypt_data(&new_key, &secret)?,
                signature: None,
                created_at: old_otpk.created_at,
            });
        }

        // Update state
        self.salt = new_salt;
        self.password_hash = new_hash;
        self.encrypted_signing_key = new_encrypted_signing;
        self.encrypted_dh_key = new_encrypted_dh;
        self.encrypted_kyber_public_key = new_encrypted_kyber_public;
        self.encrypted_kyber_secret_key = new_encrypted_kyber_secret;
        self.encrypted_signed_prekey = new_signed_prekey;
        self.encrypted_one_time_prekeys = new_otpks;

        Ok(())
    }
}

/// Derive an encryption key from password using Argon2
fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut key = [0u8; KEY_SIZE];
    argon2_instance()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    Ok(key)
}

/// Encrypt data with ChaCha20-Poly1305
fn encrypt_data(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Encryption(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;

    // Prepend nonce
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with ChaCha20-Poly1305
fn decrypt_data(key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(Error::Decryption("Ciphertext too short".to_string()));
    }

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let encrypted = &ciphertext[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| Error::Decryption("Decryption failed".to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_create_and_open() {
        let password = "test_password_123";

        let (store, identity1) = KeyStore::create(password).unwrap();
        let identity2 = store.open(password).unwrap();

        // Fingerprints should match
        assert_eq!(
            identity1.public_key().fingerprint(),
            identity2.public_key().fingerprint()
        );
    }

    #[test]
    fn test_wrong_password() {
        let (store, _) = KeyStore::create("correct_password").unwrap();

        let result = store.open("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_prekey_storage() {
        let password = "test_password";
        let (mut store, identity) = KeyStore::create(password).unwrap();

        let spk = store.generate_signed_prekey(password, &identity).unwrap();
        let retrieved = store.get_signed_prekey(password).unwrap().unwrap();

        assert_eq!(spk.id, retrieved.id);
    }

    #[test]
    fn test_one_time_prekey_storage() {
        let password = "test_password";
        let (mut store, _) = KeyStore::create(password).unwrap();

        let otpks = store.generate_one_time_prekeys(password, 10).unwrap();
        assert_eq!(otpks.len(), 10);
        assert_eq!(store.one_time_prekey_count(), 10);

        // Consume one
        let consumed = store.consume_one_time_prekey(password, otpks[5].id).unwrap();
        assert_eq!(consumed.id, otpks[5].id);
        assert_eq!(store.one_time_prekey_count(), 9);
    }

    #[test]
    fn test_keystore_serialization() {
        let password = "test_password";
        let (store1, identity1) = KeyStore::create(password).unwrap();

        let bytes = store1.to_bytes().unwrap();
        let store2 = KeyStore::from_bytes(&bytes).unwrap();

        let identity2 = store2.open(password).unwrap();
        assert_eq!(
            identity1.public_key().fingerprint(),
            identity2.public_key().fingerprint()
        );
    }

    #[test]
    fn test_change_password() {
        let old_password = "old_password";
        let new_password = "new_password";

        let (mut store, identity1) = KeyStore::create(old_password).unwrap();
        store.generate_signed_prekey(old_password, &identity1).unwrap();
        store.generate_one_time_prekeys(old_password, 5).unwrap();

        store.change_password(old_password, new_password).unwrap();

        // Old password should fail
        assert!(store.open(old_password).is_err());

        // New password should work
        let identity2 = store.open(new_password).unwrap();
        assert_eq!(
            identity1.public_key().fingerprint(),
            identity2.public_key().fingerprint()
        );

        // Pre-keys should still work
        assert!(store.get_signed_prekey(new_password).unwrap().is_some());
        assert_eq!(store.one_time_prekey_count(), 5);
    }
}
