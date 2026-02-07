//! Secure key storage with Argon2 password derivation
//!
//! Supports two formats:
//! - V1 (`KeyStore`): Single vault with password hash verification (fast unlock)
//! - V2 (`DuressKeyStore`): Dual-vault with trial decryption for duress password support
//!
//! The V2 format provides plausible deniability: both vaults are indistinguishable,
//! and there is no stored password hash. An adversary cannot determine which vault
//! is the "real" one vs the decoy.

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
/// Magic bytes identifying V2 (duress) format: "VK02"
const DURESS_MAGIC: [u8; 4] = [0x56, 0x4B, 0x30, 0x32];
/// Size of the database token
const DB_TOKEN_SIZE: usize = 32;

/// Create an Argon2 instance with secure parameters:
/// Algorithm: Argon2id, Version: 0x13, Memory: 64 MiB, Iterations: 3, Parallelism: 4
fn argon2_instance<'a>() -> Argon2<'a> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
    )
}

// ══════════════════════════════════════════════════════════════════
// V1 KeyStore (original format, backward compatible)
// ══════════════════════════════════════════════════════════════════

/// Encrypted key store (V1 format)
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

/// Encrypted pre-key (V1 format)
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedPreKey {
    pub id: u32,
    pub encrypted_secret: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub created_at: i64,
}

impl KeyStore {
    /// Create a new key store with a password
    pub fn create(password: &str) -> Result<(Self, veilcomm_core::crypto::IdentityKeyPair)> {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        let salt_string = SaltString::encode_b64(&salt)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;
        let argon2 = argon2_instance();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?
            .to_string();

        let encryption_key = derive_encryption_key(password, &salt)?;
        let identity = veilcomm_core::crypto::IdentityKeyPair::generate();

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
        self.verify_password(password)?;
        let encryption_key = derive_encryption_key(password, &self.salt)?;

        let signing_key_bytes = decrypt_data(&encryption_key, &self.encrypted_signing_key)?;
        let dh_key_bytes = decrypt_data(&encryption_key, &self.encrypted_dh_key)?;
        let kyber_public_bytes = decrypt_data(&encryption_key, &self.encrypted_kyber_public_key)?;
        let kyber_secret_bytes = decrypt_data(&encryption_key, &self.encrypted_kyber_secret_key)?;

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
        self.verify_password(old_password)?;

        let old_key = derive_encryption_key(old_password, &self.salt)?;
        let signing_key_bytes = decrypt_data(&old_key, &self.encrypted_signing_key)?;
        let dh_key_bytes = decrypt_data(&old_key, &self.encrypted_dh_key)?;
        let kyber_public_bytes = decrypt_data(&old_key, &self.encrypted_kyber_public_key)?;
        let kyber_secret_bytes = decrypt_data(&old_key, &self.encrypted_kyber_secret_key)?;

        let mut new_salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut new_salt);

        let salt_string = SaltString::encode_b64(&new_salt)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?;
        let argon2 = argon2_instance();
        let new_hash = argon2
            .hash_password(new_password.as_bytes(), &salt_string)
            .map_err(|e| Error::KeyDerivation(e.to_string()))?
            .to_string();

        let new_key = derive_encryption_key(new_password, &new_salt)?;

        let new_encrypted_signing = encrypt_data(&new_key, &signing_key_bytes)?;
        let new_encrypted_dh = encrypt_data(&new_key, &dh_key_bytes)?;
        let new_encrypted_kyber_public = encrypt_data(&new_key, &kyber_public_bytes)?;
        let new_encrypted_kyber_secret = encrypt_data(&new_key, &kyber_secret_bytes)?;

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

    /// Extract identity key bytes for V2 migration (requires password)
    fn extract_key_bytes(&self, password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.verify_password(password)?;
        let key = derive_encryption_key(password, &self.salt)?;
        Ok((
            decrypt_data(&key, &self.encrypted_signing_key)?,
            decrypt_data(&key, &self.encrypted_dh_key)?,
            decrypt_data(&key, &self.encrypted_kyber_public_key)?,
            decrypt_data(&key, &self.encrypted_kyber_secret_key)?,
        ))
    }

    /// Extract pre-key data for V2 migration
    fn extract_prekeys(&self, password: &str) -> Result<(Option<PreKeyEntry>, Vec<PreKeyEntry>)> {
        let key = derive_encryption_key(password, &self.salt)?;

        let spk = if let Some(ref encrypted) = self.encrypted_signed_prekey {
            let secret = decrypt_data(&key, &encrypted.encrypted_secret)?;
            Some(PreKeyEntry {
                id: encrypted.id,
                secret_bytes: secret,
                signature: encrypted.signature.clone(),
                created_at: encrypted.created_at,
            })
        } else {
            None
        };

        let mut otpks = Vec::with_capacity(self.encrypted_one_time_prekeys.len());
        for epk in &self.encrypted_one_time_prekeys {
            let secret = decrypt_data(&key, &epk.encrypted_secret)?;
            otpks.push(PreKeyEntry {
                id: epk.id,
                secret_bytes: secret,
                signature: None,
                created_at: epk.created_at,
            });
        }

        Ok((spk, otpks))
    }
}

// ══════════════════════════════════════════════════════════════════
// V2 DuressKeyStore (dual-vault with trial decryption)
// ══════════════════════════════════════════════════════════════════

/// Result of opening a keystore (V2)
pub struct OpenResult {
    pub identity: veilcomm_core::crypto::IdentityKeyPair,
    /// Token used to derive the database filename (unique per vault)
    pub db_token: [u8; DB_TOKEN_SIZE],
}

/// Encrypted vault slot
#[derive(Serialize, Deserialize, Clone)]
struct EncryptedSlot {
    salt: [u8; SALT_SIZE],
    ciphertext: Vec<u8>,
}

/// Plaintext vault payload (encrypted at rest inside EncryptedSlot)
#[derive(Serialize, Deserialize, Clone)]
struct VaultPayload {
    signing_key_bytes: Vec<u8>,
    dh_key_bytes: Vec<u8>,
    kyber_public_key_bytes: Vec<u8>,
    kyber_secret_key_bytes: Vec<u8>,
    signed_prekey: Option<PreKeyEntry>,
    one_time_prekeys: Vec<PreKeyEntry>,
    next_otpk_id: u32,
    next_spk_id: u32,
    /// Token to derive separate database filename per vault
    db_token: [u8; DB_TOKEN_SIZE],
}

/// Pre-key entry (plaintext within encrypted vault)
#[derive(Clone, Serialize, Deserialize)]
struct PreKeyEntry {
    id: u32,
    secret_bytes: Vec<u8>,
    signature: Option<Vec<u8>>,
    created_at: i64,
}

/// V2 key store with duress password support
///
/// Two indistinguishable encrypted vaults. Trial decryption determines which
/// vault a password opens. No password hash is stored, providing deniability.
#[derive(Serialize, Deserialize)]
pub struct DuressKeyStore {
    slot_a: EncryptedSlot,
    slot_b: EncryptedSlot,
    /// Cached active slot index after successful open (not serialized)
    #[serde(skip)]
    active_slot: Option<u8>,
}

impl DuressKeyStore {
    /// Create a new duress keystore by migrating from a V1 keystore
    ///
    /// The real vault inherits the V1 identity. A new decoy identity is generated
    /// for the duress vault. Returns the duress vault's OpenResult so the caller
    /// can initialize the decoy database.
    pub fn from_v1(
        v1: &KeyStore,
        real_password: &str,
        duress_password: &str,
    ) -> Result<(Self, OpenResult)> {
        // Extract real identity data from V1
        let (sign_bytes, dh_bytes, kyber_pub, kyber_sec) =
            v1.extract_key_bytes(real_password)?;
        let (real_spk, real_otpks) = v1.extract_prekeys(real_password)?;

        // Generate db_token for real vault
        let mut real_db_token = [0u8; DB_TOKEN_SIZE];
        rand::thread_rng().fill_bytes(&mut real_db_token);

        let real_payload = VaultPayload {
            signing_key_bytes: sign_bytes,
            dh_key_bytes: dh_bytes,
            kyber_public_key_bytes: kyber_pub,
            kyber_secret_key_bytes: kyber_sec,
            signed_prekey: real_spk,
            one_time_prekeys: real_otpks,
            next_otpk_id: v1.next_otpk_id,
            next_spk_id: v1.next_spk_id,
            db_token: real_db_token,
        };

        // Generate duress identity
        let duress_identity = veilcomm_core::crypto::IdentityKeyPair::generate();
        let mut duress_db_token = [0u8; DB_TOKEN_SIZE];
        rand::thread_rng().fill_bytes(&mut duress_db_token);

        let duress_payload = VaultPayload {
            signing_key_bytes: duress_identity.signing_key_bytes().to_vec(),
            dh_key_bytes: duress_identity.dh_secret_bytes().to_vec(),
            kyber_public_key_bytes: duress_identity.kyber_public_key_bytes().to_vec(),
            kyber_secret_key_bytes: duress_identity.kyber_secret_key_bytes().to_vec(),
            signed_prekey: None,
            one_time_prekeys: Vec::new(),
            next_otpk_id: 0,
            next_spk_id: 1,
            db_token: duress_db_token,
        };

        // Encrypt both slots
        let slot_a = encrypt_vault(&real_payload, real_password)?;
        let slot_b = encrypt_vault(&duress_payload, duress_password)?;

        let store = Self {
            slot_a,
            slot_b,
            active_slot: None,
        };

        let duress_result = OpenResult {
            identity: duress_identity,
            db_token: duress_db_token,
        };

        Ok((store, duress_result))
    }

    /// Open the keystore with a password (trial decryption)
    ///
    /// Tries slot A first, then slot B. Returns the identity and db_token
    /// for whichever vault the password unlocks.
    pub fn open(&mut self, password: &str) -> Result<OpenResult> {
        // Try slot A
        if let Ok(payload) = decrypt_vault(&self.slot_a, password) {
            self.active_slot = Some(0);
            let identity = veilcomm_core::crypto::IdentityKeyPair::from_bytes(
                &payload.signing_key_bytes,
                &payload.dh_key_bytes,
                &payload.kyber_public_key_bytes,
                &payload.kyber_secret_key_bytes,
            )?;
            return Ok(OpenResult {
                identity,
                db_token: payload.db_token,
            });
        }

        // Try slot B
        if let Ok(payload) = decrypt_vault(&self.slot_b, password) {
            self.active_slot = Some(1);
            let identity = veilcomm_core::crypto::IdentityKeyPair::from_bytes(
                &payload.signing_key_bytes,
                &payload.dh_key_bytes,
                &payload.kyber_public_key_bytes,
                &payload.kyber_secret_key_bytes,
            )?;
            return Ok(OpenResult {
                identity,
                db_token: payload.db_token,
            });
        }

        Err(Error::InvalidPassword)
    }

    /// Get the database token for the active vault
    pub fn db_token(&self, password: &str) -> Result<[u8; DB_TOKEN_SIZE]> {
        let payload = self.decrypt_active(password)?;
        Ok(payload.db_token)
    }

    /// Generate and store a new signed pre-key in the active vault
    pub fn generate_signed_prekey(
        &mut self,
        password: &str,
        identity: &veilcomm_core::crypto::IdentityKeyPair,
    ) -> Result<veilcomm_core::crypto::SignedPreKey> {
        let mut payload = self.decrypt_active(password)?;

        let spk = veilcomm_core::crypto::SignedPreKey::generate(payload.next_spk_id, identity);
        payload.next_spk_id += 1;

        payload.signed_prekey = Some(PreKeyEntry {
            id: spk.id,
            secret_bytes: spk.secret_bytes().to_vec(),
            signature: Some(spk.signature_bytes().to_vec()),
            created_at: spk.created_at,
        });

        self.encrypt_active(password, &payload)?;
        Ok(spk)
    }

    /// Get the current signed pre-key from the active vault
    pub fn get_signed_prekey(
        &self,
        password: &str,
    ) -> Result<Option<veilcomm_core::crypto::SignedPreKey>> {
        let payload = self.decrypt_active(password)?;

        if let Some(ref entry) = payload.signed_prekey {
            let signature = entry
                .signature
                .as_ref()
                .ok_or_else(|| Error::KeyNotFound("Missing signature".to_string()))?;

            let spk = veilcomm_core::crypto::SignedPreKey::from_bytes(
                entry.id,
                &entry.secret_bytes,
                signature,
                entry.created_at,
            )?;
            Ok(Some(spk))
        } else {
            Ok(None)
        }
    }

    /// Generate new one-time pre-keys in the active vault
    pub fn generate_one_time_prekeys(
        &mut self,
        password: &str,
        count: u32,
    ) -> Result<Vec<veilcomm_core::crypto::OneTimePreKey>> {
        let mut payload = self.decrypt_active(password)?;
        let mut otpks = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let otpk = veilcomm_core::crypto::OneTimePreKey::generate(payload.next_otpk_id);
            payload.next_otpk_id += 1;

            payload.one_time_prekeys.push(PreKeyEntry {
                id: otpk.id,
                secret_bytes: otpk.secret_bytes().to_vec(),
                signature: None,
                created_at: chrono::Utc::now().timestamp(),
            });

            otpks.push(otpk);
        }

        self.encrypt_active(password, &payload)?;
        Ok(otpks)
    }

    /// Consume a one-time pre-key by ID from the active vault
    pub fn consume_one_time_prekey(
        &mut self,
        password: &str,
        id: u32,
    ) -> Result<veilcomm_core::crypto::OneTimePreKey> {
        let mut payload = self.decrypt_active(password)?;

        let idx = payload
            .one_time_prekeys
            .iter()
            .position(|k| k.id == id)
            .ok_or_else(|| Error::KeyNotFound(format!("One-time pre-key {}", id)))?;

        let entry = payload.one_time_prekeys.remove(idx);
        self.encrypt_active(password, &payload)?;

        let otpk = veilcomm_core::crypto::OneTimePreKey::from_bytes(id, &entry.secret_bytes)?;
        Ok(otpk)
    }

    /// Number of one-time pre-keys in the active vault
    pub fn one_time_prekey_count(&self, password: &str) -> Result<usize> {
        let payload = self.decrypt_active(password)?;
        Ok(payload.one_time_prekeys.len())
    }

    /// Serialize with magic prefix
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let payload = bincode::serialize(self).map_err(|e| Error::Serialization(e.to_string()))?;
        let mut data = Vec::with_capacity(DURESS_MAGIC.len() + payload.len());
        data.extend_from_slice(&DURESS_MAGIC);
        data.extend_from_slice(&payload);
        Ok(data)
    }

    /// Deserialize (without magic prefix - caller strips it)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Decrypt the active vault payload
    fn decrypt_active(&self, password: &str) -> Result<VaultPayload> {
        let slot = match self.active_slot {
            Some(0) => &self.slot_a,
            Some(1) => &self.slot_b,
            _ => {
                // No cached slot, try both
                if let Ok(p) = decrypt_vault(&self.slot_a, password) {
                    return Ok(p);
                }
                return decrypt_vault(&self.slot_b, password)
                    .map_err(|_| Error::InvalidPassword);
            }
        };
        decrypt_vault(slot, password).map_err(|_| Error::InvalidPassword)
    }

    /// Re-encrypt the active vault with updated payload
    fn encrypt_active(&mut self, password: &str, payload: &VaultPayload) -> Result<()> {
        let slot_idx = self.active_slot.ok_or(Error::InvalidPassword)?;
        let new_slot = encrypt_vault(payload, password)?;
        match slot_idx {
            0 => self.slot_a = new_slot,
            1 => self.slot_b = new_slot,
            _ => return Err(Error::InvalidPassword),
        }
        Ok(())
    }
}

/// Encrypt a vault payload into an EncryptedSlot
fn encrypt_vault(payload: &VaultPayload, password: &str) -> Result<EncryptedSlot> {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_encryption_key(password, &salt)?;
    let plaintext = bincode::serialize(payload)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    let ciphertext = encrypt_data(&key, &plaintext)?;

    Ok(EncryptedSlot { salt, ciphertext })
}

/// Try to decrypt a vault slot with a password
fn decrypt_vault(slot: &EncryptedSlot, password: &str) -> Result<VaultPayload> {
    let key = derive_encryption_key(password, &slot.salt)?;
    let plaintext = decrypt_data(&key, &slot.ciphertext)?;
    bincode::deserialize(&plaintext).map_err(|e| Error::Serialization(e.to_string()))
}

// ══════════════════════════════════════════════════════════════════
// Format detection and loading
// ══════════════════════════════════════════════════════════════════

/// Detected keystore format
pub enum KeyStoreVersion {
    V1(KeyStore),
    V2(DuressKeyStore),
}

/// Load a keystore from bytes, auto-detecting the format
pub fn load_keystore(bytes: &[u8]) -> Result<KeyStoreVersion> {
    if bytes.len() >= DURESS_MAGIC.len() && bytes[..DURESS_MAGIC.len()] == DURESS_MAGIC {
        let dks = DuressKeyStore::from_bytes(&bytes[DURESS_MAGIC.len()..])?;
        Ok(KeyStoreVersion::V2(dks))
    } else {
        let ks = KeyStore::from_bytes(bytes)?;
        Ok(KeyStoreVersion::V1(ks))
    }
}

/// Derive a database filename from a db_token
pub fn db_filename_from_token(token: &[u8; DB_TOKEN_SIZE]) -> String {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"VeilComm_DB_v1_");
    hasher.update(token);
    let hash = hasher.finalize();
    format!("{}.db", hex::encode(&hash[..8]))
}

// ══════════════════════════════════════════════════════════════════
// Shared crypto helpers
// ══════════════════════════════════════════════════════════════════

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

    // ─── V1 KeyStore Tests ──────────────────────────────────

    #[test]
    fn test_keystore_create_and_open() {
        let password = "test_password_123";

        let (store, identity1) = KeyStore::create(password).unwrap();
        let identity2 = store.open(password).unwrap();

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

        assert!(store.open(old_password).is_err());

        let identity2 = store.open(new_password).unwrap();
        assert_eq!(
            identity1.public_key().fingerprint(),
            identity2.public_key().fingerprint()
        );

        assert!(store.get_signed_prekey(new_password).unwrap().is_some());
        assert_eq!(store.one_time_prekey_count(), 5);
    }

    // ─── V2 DuressKeyStore Tests ────────────────────────────

    #[test]
    fn test_duress_migration_and_open() {
        let real_pw = "real_password";
        let duress_pw = "duress_password";

        // Create V1 keystore
        let (v1_store, real_identity) = KeyStore::create(real_pw).unwrap();

        // Migrate to V2
        let (mut dks, duress_result) =
            DuressKeyStore::from_v1(&v1_store, real_pw, duress_pw).unwrap();

        // Real password should open real vault
        let real_result = dks.open(real_pw).unwrap();
        assert_eq!(
            real_result.identity.public_key().fingerprint(),
            real_identity.public_key().fingerprint(),
        );

        // Duress password should open duress vault (different identity)
        let mut dks2 = DuressKeyStore::from_bytes(
            &dks.to_bytes().unwrap()[DURESS_MAGIC.len()..],
        ).unwrap();
        let duress_result2 = dks2.open(duress_pw).unwrap();
        assert_eq!(
            duress_result2.identity.public_key().fingerprint(),
            duress_result.identity.public_key().fingerprint(),
        );

        // Different identities
        assert_ne!(
            real_result.identity.public_key().fingerprint(),
            duress_result2.identity.public_key().fingerprint(),
        );

        // Different db tokens
        assert_ne!(real_result.db_token, duress_result2.db_token);
    }

    #[test]
    fn test_duress_wrong_password() {
        let (v1_store, _) = KeyStore::create("real_pw").unwrap();
        let (mut dks, _) =
            DuressKeyStore::from_v1(&v1_store, "real_pw", "duress_pw").unwrap();

        assert!(dks.open("wrong_password").is_err());
    }

    #[test]
    fn test_duress_serialization_roundtrip() {
        let (v1_store, _) = KeyStore::create("real_pw").unwrap();
        let (dks, _) =
            DuressKeyStore::from_v1(&v1_store, "real_pw", "duress_pw").unwrap();

        let bytes = dks.to_bytes().unwrap();

        // Should be detected as V2
        match load_keystore(&bytes).unwrap() {
            KeyStoreVersion::V2(mut loaded) => {
                let result = loaded.open("real_pw").unwrap();
                assert!(!result.identity.public_key().fingerprint().is_empty());
            }
            _ => panic!("Expected V2 format"),
        }
    }

    #[test]
    fn test_v1_format_detection() {
        let (v1_store, _) = KeyStore::create("test_pw").unwrap();
        let bytes = v1_store.to_bytes().unwrap();

        match load_keystore(&bytes).unwrap() {
            KeyStoreVersion::V1(store) => {
                assert!(store.open("test_pw").is_ok());
            }
            _ => panic!("Expected V1 format"),
        }
    }

    #[test]
    fn test_duress_prekey_operations() {
        let (v1_store, real_identity) = KeyStore::create("real_pw").unwrap();
        let (mut dks, _) =
            DuressKeyStore::from_v1(&v1_store, "real_pw", "duress_pw").unwrap();

        // Open real vault
        let result = dks.open("real_pw").unwrap();

        // Generate signed pre-key
        let spk = dks.generate_signed_prekey("real_pw", &result.identity).unwrap();
        let retrieved = dks.get_signed_prekey("real_pw").unwrap().unwrap();
        assert_eq!(spk.id, retrieved.id);

        // Generate OTKs
        let otpks = dks.generate_one_time_prekeys("real_pw", 5).unwrap();
        assert_eq!(otpks.len(), 5);
        assert_eq!(dks.one_time_prekey_count("real_pw").unwrap(), 5);

        // Consume
        let consumed = dks.consume_one_time_prekey("real_pw", otpks[2].id).unwrap();
        assert_eq!(consumed.id, otpks[2].id);
        assert_eq!(dks.one_time_prekey_count("real_pw").unwrap(), 4);
    }

    #[test]
    fn test_db_filename_from_token() {
        let token_a = [1u8; DB_TOKEN_SIZE];
        let token_b = [2u8; DB_TOKEN_SIZE];

        let name_a = db_filename_from_token(&token_a);
        let name_b = db_filename_from_token(&token_b);

        // Different tokens produce different filenames
        assert_ne!(name_a, name_b);

        // Deterministic
        assert_eq!(name_a, db_filename_from_token(&token_a));

        // Ends with .db
        assert!(name_a.ends_with(".db"));
    }
}
