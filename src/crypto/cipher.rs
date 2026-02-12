use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, Key, XNonce, Tag
};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::memory::guard::SecureBuffer;
use crate::crypto::random::SecureRandom;

// Constants
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24; // 192-bit nonce for XChaCha20
pub const TAG_SIZE: usize = 16;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
    KeyDerivationFailed,
    KeyPrecomputationFailed,
    InternalError,
}

/// Derive a subkey from a master key using HKDF-SHA256.
/// This ensures key separation (master key never used directly for multiple things).
pub fn derive_subkey(
    master_key: &[u8],
    info: &[u8]
) -> Result<SecureBuffer, CryptoError> {
    if master_key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize);
    }

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = SecureBuffer::new(KEY_SIZE)
        .ok_or(CryptoError::InternalError)?;

    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(okm)
}

/// Encrypt data using XChaCha20-Poly1305.
/// Returns (Ciphertext, Nonce, Tag).
/// XChaCha20 is used because its 192-bit nonce allows for safe random generation
/// across millions of records without collision risk, unlike AES-GCM's 96-bit nonce.
pub fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8]
) -> Result<(SecureBuffer, [u8; NONCE_SIZE], [u8; TAG_SIZE]), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize);
    }

    // 1. Initialize cipher
    let key_ref = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key_ref);

    // 2. Generate random nonce (Unique per operation, safe for XChaCha20)
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    SecureRandom::fill(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // 3. Prepare buffer
    let mut buffer = SecureBuffer::from_slice(plaintext)
        .ok_or(CryptoError::InternalError)?;

    // 4. Encrypt in place
    let tag = cipher.encrypt_in_place_detached(nonce, aad, &mut buffer)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((buffer, nonce_bytes, tag.into()))
}

/// Decrypt data using XChaCha20-Poly1305.
pub fn decrypt(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    tag: &[u8; TAG_SIZE],
    ciphertext: &[u8],
    aad: &[u8]
) -> Result<SecureBuffer, CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize);
    }

    let key_ref = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key_ref);
    let nonce_ref = XNonce::from_slice(nonce);
    let tag_ref = Tag::from_slice(tag);

    let mut buffer = SecureBuffer::from_slice(ciphertext)
        .ok_or(CryptoError::InternalError)?;

    cipher.decrypt_in_place_detached(nonce_ref, aad, &mut buffer, tag_ref)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(buffer)
}
