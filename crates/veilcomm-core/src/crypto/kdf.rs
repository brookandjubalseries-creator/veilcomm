//! Key Derivation Functions
//!
//! Provides HKDF-based key derivation using BLAKE2b for the Double Ratchet
//! and X3DH protocols.

use blake2::{Blake2b512, Digest};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::error::{Error, Result};

/// Domain separation string for VeilComm
const INFO_PREFIX: &[u8] = b"VeilComm_v1_";

/// Size of the root key and chain key in bytes
pub const KEY_SIZE: usize = 32;

/// Derive a key using HKDF with BLAKE2b
pub fn derive_key(input_key_material: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    // Use SHA-256 for HKDF as it's well-tested with this construction
    let hkdf = Hkdf::<Sha256>::new(None, input_key_material);
    let mut output = vec![0u8; output_len];

    // Prepend domain separation
    let mut full_info = INFO_PREFIX.to_vec();
    full_info.extend_from_slice(info);

    hkdf.expand(&full_info, &mut output)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    Ok(output)
}

/// HKDF-Extract: Extract pseudorandom key from input
pub fn hkdf_extract(salt: Option<&[u8]>, input_key_material: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(salt, input_key_material);
    let mut prk = [0u8; 32];
    // Extract returns the PRK directly, we need to expand to get output
    hkdf.expand(b"", &mut prk).expect("32 bytes is valid");
    prk
}

/// HKDF-Expand: Expand pseudorandom key to desired length
pub fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|e| Error::KeyDerivation(e.to_string()))?;

    let mut output = vec![0u8; output_len];

    let mut full_info = INFO_PREFIX.to_vec();
    full_info.extend_from_slice(info);

    hkdf.expand(&full_info, &mut output)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    Ok(output)
}

/// KDF for the Double Ratchet root chain
///
/// Takes the current root key and DH output, returns new root key and chain key
pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);

    let mut new_root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];

    hkdf.expand(b"VeilComm_v1_root", &mut new_root_key)
        .expect("32 bytes is valid");
    hkdf.expand(b"VeilComm_v1_chain", &mut chain_key)
        .expect("32 bytes is valid");

    (new_root_key, chain_key)
}

/// KDF for the Double Ratchet message chain
///
/// Takes the current chain key, returns new chain key and message key
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Use BLAKE2b for fast chain key derivation
    let mut hasher = Blake2b512::new();
    hasher.update(chain_key);
    hasher.update(&[0x01]); // Message key constant
    let hash = hasher.finalize();
    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&hash[..32]);

    let mut hasher = Blake2b512::new();
    hasher.update(chain_key);
    hasher.update(&[0x02]); // Chain key constant
    let hash = hasher.finalize();
    let mut new_chain_key = [0u8; 32];
    new_chain_key.copy_from_slice(&hash[..32]);

    (new_chain_key, message_key)
}

/// Concatenate multiple byte slices for use in KDF
pub fn concat_keys(keys: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = keys.iter().map(|k| k.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for key in keys {
        result.extend_from_slice(key);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let ikm = b"input key material";
        let info = b"test info";

        let key1 = derive_key(ikm, info, 32).unwrap();
        let key2 = derive_key(ikm, info, 32).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_info() {
        let ikm = b"input key material";

        let key1 = derive_key(ikm, b"info1", 32).unwrap();
        let key2 = derive_key(ikm, b"info2", 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_kdf_rk() {
        let root_key = [0u8; 32];
        let dh_output = [1u8; 32];

        let (new_root, chain) = kdf_rk(&root_key, &dh_output);

        // Keys should be different
        assert_ne!(new_root, chain);
        assert_ne!(new_root, root_key);
        assert_ne!(chain, dh_output);
    }

    #[test]
    fn test_kdf_ck() {
        let chain_key = [0u8; 32];

        let (new_chain, message) = kdf_ck(&chain_key);

        // Keys should be different
        assert_ne!(new_chain, message);
        assert_ne!(new_chain, chain_key);
    }

    #[test]
    fn test_kdf_ck_chain() {
        // Test that chaining produces different keys
        let mut chain_key = [0u8; 32];
        let mut message_keys = Vec::new();

        for _ in 0..10 {
            let (new_chain, message) = kdf_ck(&chain_key);
            message_keys.push(message);
            chain_key = new_chain;
        }

        // All message keys should be unique
        for (i, key) in message_keys.iter().enumerate() {
            for (j, other) in message_keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key, other);
                }
            }
        }
    }
}
