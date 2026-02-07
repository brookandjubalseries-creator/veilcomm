//! Authenticated Encryption with Associated Data (AEAD)
//!
//! Implements ChaCha20-Poly1305 for message encryption.
//! Provides both encryption and decryption with additional authenticated data.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Size of the encryption key in bytes
pub const KEY_SIZE: usize = 32;
/// Size of the nonce in bytes
pub const NONCE_SIZE: usize = 12;
/// Size of the authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// Encrypt a message using ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Message to encrypt
/// * `associated_data` - Additional data to authenticate (not encrypted)
///
/// # Returns
/// Ciphertext with prepended nonce: nonce || ciphertext || tag
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Encryption(e.to_string()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|e| Error::Encryption(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Encrypt a message with a specific nonce (for deterministic encryption in tests)
///
/// # Safety
/// Only use this for testing! Nonce reuse breaks security.
#[cfg(test)]
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Encryption(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|e| Error::Encryption(e.to_string()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a message using ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `ciphertext` - Nonce || ciphertext || tag
/// * `associated_data` - Additional data to verify
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(Error::Decryption(
            "Ciphertext too short".to_string(),
        ));
    }

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Decryption(e.to_string()))?;

    // Extract nonce and actual ciphertext
    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let encrypted = &ciphertext[NONCE_SIZE..];

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload {
            msg: encrypted,
            aad: associated_data,
        })
        .map_err(|_| Error::Decryption("Authentication failed".to_string()))?;

    Ok(plaintext)
}

/// Encrypt a message with header encryption
///
/// Uses two keys: one for header, one for message body.
/// This provides additional privacy for message metadata.
pub fn encrypt_with_header(
    header_key: &[u8; 32],
    message_key: &[u8; 32],
    header: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Encrypt header
    let encrypted_header = encrypt(header_key, header, b"")?;

    // Encrypt message with header as AAD
    let encrypted_message = encrypt(message_key, plaintext, &encrypted_header)?;

    Ok((encrypted_header, encrypted_message))
}

/// Decrypt a message with header encryption
pub fn decrypt_with_header(
    header_key: &[u8; 32],
    message_key: &[u8; 32],
    encrypted_header: &[u8],
    encrypted_message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Decrypt header
    let header = decrypt(header_key, encrypted_header, b"")?;

    // Decrypt message with header as AAD
    let plaintext = decrypt(message_key, encrypted_message, encrypted_header)?;

    Ok((header, plaintext))
}

/// Securely erase a key from memory
pub fn zeroize_key(key: &mut [u8; 32]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello, VeilComm!";
        let aad = b"associated data";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let plaintext = b"Hello, VeilComm!";
        let aad = b"associated data";

        let ciphertext = encrypt(&key1, plaintext, aad).unwrap();
        let result = decrypt(&key2, &ciphertext, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0u8; 32];
        let plaintext = b"Hello, VeilComm!";

        let ciphertext = encrypt(&key, plaintext, b"correct aad").unwrap();
        let result = decrypt(&key, &ciphertext, b"wrong aad");

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; 32];
        let plaintext = b"Hello, VeilComm!";
        let aad = b"associated data";

        let mut ciphertext = encrypt(&key, plaintext, aad).unwrap();

        // Tamper with ciphertext
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let result = decrypt(&key, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message() {
        let key = [0u8; 32];
        let plaintext = b"";
        let aad = b"associated data";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_header() {
        let header_key = [1u8; 32];
        let message_key = [2u8; 32];
        let header = b"message header";
        let plaintext = b"message body";

        let (enc_header, enc_message) =
            encrypt_with_header(&header_key, &message_key, header, plaintext).unwrap();

        let (dec_header, dec_plaintext) =
            decrypt_with_header(&header_key, &message_key, &enc_header, &enc_message).unwrap();

        assert_eq!(header.as_slice(), dec_header.as_slice());
        assert_eq!(plaintext.as_slice(), dec_plaintext.as_slice());
    }

    #[test]
    fn test_ciphertext_structure() {
        let key = [0u8; 32];
        let plaintext = b"Hello!";
        let aad = b"";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();

        // Should be: nonce (12) + ciphertext (6) + tag (16)
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }
}
