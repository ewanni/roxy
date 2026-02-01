//! Shared cryptographic utilities for ROXY protocol
//!
//! Provides HKDF-based key derivation, ChaCha20-Poly1305 AEAD encryption/decryption,
//! and nonce generation for use by both client and server implementations.

use anyhow::anyhow;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::Aead;
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

use crate::protocol::HKDF_INFO_PREFIX;

// ============================================================================
// CRYPTOGRAPHIC CONSTANTS
// ============================================================================

/// ChaCha20-Poly1305 key size (256 bits)
pub const KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Session ID size for UUID (128 bits)
pub const SESSION_ID_SIZE: usize = 16;

/// SCRAM salt/nonce size (256 bits)
pub const SCRAM_NONCE_SIZE: usize = 32;

/// Authentication tag size for ChaCha20-Poly1305 (128 bits)
pub const AUTH_TAG_SIZE: usize = 16;

/// Derives a session key from shared secrets using HKDF-SHA256.
///
/// This function implements deterministic session key derivation matching both
/// client and server implementations. Uses HKDF (RFC 5869) with SHA-256 for
/// cryptographically secure key generation.
///
/// # Arguments
/// * `salt` - IKM salt (typically client_nonce || server_nonce concatenated)
/// * `ikm` - Input key material (typically salted_password from SCRAM authentication)
/// * `session_id` - 16-byte UUID for domain separation and uniqueness
///
/// # Returns
/// * `Ok([u8; KEY_SIZE])` - 32-byte session key suitable for ChaCha20-Poly1305
/// * `Err` - HKDF expansion failed (should never occur with valid inputs)
///
/// # Example
/// ```rust,no_run
/// use roxy::crypto::{derive_session_key, SESSION_ID_SIZE, KEY_SIZE};
///
/// let salt = [1u8; 32];
/// let ikm = [2u8; 32];
/// let session_id = [3u8; SESSION_ID_SIZE];
///
/// let key = derive_session_key(&salt, &ikm, &session_id).unwrap();
/// assert_eq!(key.len(), KEY_SIZE);
/// ```
pub fn derive_session_key(
    salt: &[u8],
    ikm: &[u8],
    session_id: &[u8; SESSION_ID_SIZE],
) -> anyhow::Result<[u8; KEY_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);

    // Use session_id as part of the info string for domain separation
    let info = format!("{} {}", HKDF_INFO_PREFIX, uuid::Uuid::from_bytes(*session_id));

    let mut session_key = [0u8; KEY_SIZE];
    hkdf.expand(info.as_bytes(), &mut session_key)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;

    debug!("Session key derived successfully");
    Ok(session_key)
}

/// Encrypts plaintext using ChaCha20-Poly1305 AEAD.
///
/// Uses authenticated encryption with associated data (AEAD) to ensure both
/// confidentiality and integrity. The authentication tag is automatically appended.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique for each encryption with same key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Associated Authenticated Data (optional, authenticated but not encrypted)
///
/// # Returns
/// * `Ok(Vec<u8>)` - Ciphertext with authentication tag appended (plaintext_len + 16 bytes)
/// * `Err` - Encryption failed (extremely rare with valid key/nonce)
///
/// # Security
/// **CRITICAL**: Never reuse the same nonce with the same key. Use [`NonceGenerator`]
/// to ensure nonce uniqueness.
///
/// # Example
/// ```rust,no_run
/// use roxy::crypto::{encrypt_data, KEY_SIZE, NONCE_SIZE};
///
/// let key = [0u8; KEY_SIZE];
/// let nonce = [1u8; NONCE_SIZE];
/// let plaintext = b"Secret message";
///
/// let ciphertext = encrypt_data(&key, &nonce, plaintext, None).unwrap();
/// assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag
/// ```
pub fn encrypt_data(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    let ciphertext = if let Some(aad_data) = aad {
        cipher
            .encrypt(nonce_obj, chacha20poly1305::aead::Payload { msg: plaintext, aad: aad_data })
            .map_err(|e| anyhow!("Encryption failed: {}", e))?
    } else {
        cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?
    };

    Ok(ciphertext)
}

/// Decrypt ciphertext using ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - KEY_SIZE-byte encryption key
/// * `nonce` - NONCE_SIZE-byte nonce used during encryption
/// * `ciphertext` - Encrypted data with authentication tag
/// * `aad` - Associated Authenticated Data (must match what was used during encryption)
///
/// # Returns
/// Decrypted plaintext or error if authentication fails
pub fn decrypt_data(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    let plaintext = if let Some(aad_data) = aad {
        cipher
            .decrypt(nonce_obj, chacha20poly1305::aead::Payload { msg: ciphertext, aad: aad_data })
            .map_err(|_| anyhow!("Decryption failed or tag verification failed"))?
    } else {
        cipher
            .decrypt(nonce_obj, ciphertext)
            .map_err(|_| anyhow!("Decryption failed or tag verification failed"))?
    };

    Ok(plaintext)
}

/// Counter-based nonce generator with domain separation
///
/// Ensures nonce uniqueness by combining a monotonically increasing counter
/// with stream_id for differentiation across logical streams.
pub struct NonceGenerator {
    counter: AtomicU64,
    session_id: [u8; SESSION_ID_SIZE],
}

impl NonceGenerator {
    /// Create a new nonce generator for a session
    pub fn new(session_id: [u8; SESSION_ID_SIZE]) -> Self {
        Self {
            counter: AtomicU64::new(0),
            session_id,
        }
    }

    /// Generate a unique nonce for a data frame
    ///
    /// Layout (NONCE_SIZE bytes total):
    /// - Bytes 0-7: Counter (big-endian u64)
    /// - Bytes 8-11: Stream ID (big-endian u32)
    pub fn generate(&self, stream_id: u32) -> [u8; NONCE_SIZE] {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&count.to_be_bytes());
        nonce[8..12].copy_from_slice(&stream_id.to_be_bytes());

        // Mix in session_id via XOR for domain separation
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte ^= self.session_id[i % SESSION_ID_SIZE];
        }

        nonce
    }

    /// Validate received nonce freshness (basic check)
    ///
    /// This performs a simple check that the nonce counter hasn't wrapped
    /// or gone too far backwards (which might indicate replay).
    pub fn validate_freshness(&self, nonce: &[u8; NONCE_SIZE]) -> bool {
        // Extract counter from nonce
        let mut count_bytes: [u8; 8] = nonce[0..8].try_into().unwrap_or([0u8; 8]);
        // XOR out session_id to recover original counter
        for (i, byte) in count_bytes.iter_mut().enumerate() {
            *byte ^= self.session_id[i % SESSION_ID_SIZE];
        }
        let received_count = u64::from_be_bytes(count_bytes);
        let current = self.counter.load(Ordering::SeqCst);

        // Allow some drift for out-of-order delivery, but not too much
        const MAX_DRIFT: u64 = 1000; // Allow 1000 messages out of order

        // Should be reasonably recent
        received_count >= current.saturating_sub(MAX_DRIFT) && received_count <= current + MAX_DRIFT
    }

    /// Get current counter value (for testing)
    #[cfg(test)]
    fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_key() {
        let salt = [1u8; SCRAM_NONCE_SIZE];
        let ikm = [2u8; KEY_SIZE];
        let session_id = [3u8; SESSION_ID_SIZE];

        let key1 = derive_session_key(&salt, &ikm, &session_id).unwrap();
        let key2 = derive_session_key(&salt, &ikm, &session_id).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1, key2);
        // Key should be KEY_SIZE bytes
        assert_eq!(key1.len(), KEY_SIZE);
    }

    #[test]
    fn test_derive_session_key_different_inputs() {
        let salt1 = [1u8; SCRAM_NONCE_SIZE];
        let salt2 = [2u8; SCRAM_NONCE_SIZE];
        let ikm = [3u8; KEY_SIZE];
        let session_id = [4u8; SESSION_ID_SIZE];

        let key1 = derive_session_key(&salt1, &ikm, &session_id).unwrap();
        let key2 = derive_session_key(&salt2, &ikm, &session_id).unwrap();

        // Different inputs should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [5u8; KEY_SIZE];
        let nonce = [6u8; NONCE_SIZE];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt_data(&key, &nonce, plaintext, None).unwrap();
        let decrypted = decrypt_data(&key, &nonce, &ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = [5u8; KEY_SIZE];
        let nonce = [6u8; NONCE_SIZE];
        let plaintext = b"Secret message";
        let aad = b"Stream 1";

        let ciphertext = encrypt_data(&key, &nonce, plaintext, Some(aad)).unwrap();
        let decrypted = decrypt_data(&key, &nonce, &ciphertext, Some(aad)).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_aad_mismatch() {
        let key = [5u8; KEY_SIZE];
        let nonce = [6u8; NONCE_SIZE];
        let plaintext = b"Secret message";
        let aad1 = b"Stream 1";
        let aad2 = b"Stream 2";

        let ciphertext = encrypt_data(&key, &nonce, plaintext, Some(aad1)).unwrap();
        // Should fail if AAD doesn't match
        let result = decrypt_data(&key, &nonce, &ciphertext, Some(aad2));

        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_generator_uniqueness() {
        let session_id = [7u8; SESSION_ID_SIZE];
        let gen = NonceGenerator::new(session_id);

        let nonce1 = gen.generate(1);
        let nonce2 = gen.generate(1);
        let nonce3 = gen.generate(2);

        // Each nonce should be unique
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce1, nonce3);
        assert_ne!(nonce2, nonce3);
    }

    #[test]
    fn test_nonce_generator_counter_increments() {
        let session_id = [8u8; SESSION_ID_SIZE];
        let gen = NonceGenerator::new(session_id);

        let nonce1 = gen.generate(1);
        let nonce2 = gen.generate(1);

        // Extract counters: they should differ
        let _count1 = u64::from_be_bytes(nonce1[0..8].try_into().unwrap());
        let _count2 = u64::from_be_bytes(nonce2[0..8].try_into().unwrap());

        // Counters should be different (after XOR with session_id they might look similar)
        // but they should have been incremented
        assert!(gen.current_counter() >= 2);
    }

    #[test]
    fn test_nonce_generator_stream_id_variation() {
        let session_id = [9u8; SESSION_ID_SIZE];
        let gen = NonceGenerator::new(session_id);

        let nonce_stream1 = gen.generate(1);
        let nonce_stream2 = gen.generate(2);

        // Stream IDs are encoded differently, so nonces differ
        assert_ne!(nonce_stream1, nonce_stream2);
    }

    #[test]
    fn test_nonce_validation_freshness() {
        let session_id = [10u8; SESSION_ID_SIZE];
        let gen = NonceGenerator::new(session_id);

        // Generate and validate a nonce we just created
        let nonce = gen.generate(1);
        assert!(gen.validate_freshness(&nonce));
    }
}
