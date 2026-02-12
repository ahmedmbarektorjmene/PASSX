use bip39::{Mnemonic, Language};
use crate::memory::guard::SecureBuffer;
use crate::crypto::kdf::{self, SALT_LEN, KdfError};

/// Generate a new 24-word BIP39 mnemonic (256 bits of entropy).
/// Returns the mnemonic phrase and the salt used for key derivation.
pub fn generate_recovery_phrase() -> (String, [u8; SALT_LEN]) {
    // Generate secure random mnemonic (24 words = 256 bits entropy)
    let mnemonic = Mnemonic::generate_in(Language::English, 24).expect("RNG failed");
    let phrase = mnemonic.to_string();
    
    // Generate a fresh salt specifically for recovery key derivation
    let salt = kdf::generate_salt();
    
    (phrase, salt)
}

/// Derive the vault encryption key from a BIP39 mnemonic using hardened Argon2id.
pub fn derive_key_from_phrase(phrase: &str, salt: &[u8]) -> Result<SecureBuffer, KdfError> {
    // Validate mnemonic integrity (checksum)
    if Mnemonic::parse_in_normalized(Language::English, phrase).is_err() {
        return Err(KdfError::DerivationFailed); // Invalid checksum or words
    }

    // Derive key using same strong parameters as master password
    kdf::derive_key(phrase.as_bytes(), salt, kdf::Argon2ParamsVersion::V1_2024)
}
