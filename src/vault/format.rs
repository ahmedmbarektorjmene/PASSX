use std::path::Path;
use std::fs::File;
use std::io::{self, Read, Write};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::crypto::{
    cipher::{self, NONCE_SIZE, TAG_SIZE}, 
    kdf::{self, SALT_LEN, Argon2ParamsVersion}
};
use crate::vault::entry::{AccountEntry, TotpEntry};
use crate::memory::guard::SecureBuffer;
use crate::tpm::sealing;

const MAGIC: &[u8; 6] = b"passx^";

// ─── VERSIONING & MIGRATION GUIDE ───
// To add a new version/migration:
// 1. Increment FORMAT_VERSION constant.
// 2. Rename the current `Vault` struct to `VaultV{current_version}` (e.g., VaultV1).
// 3. Define the new `Vault` struct with the desired changes.
// 4. Implement `From<VaultOld> for VaultNew` or a migration function.
// 5. Update `load_vault` to check for older version numbers, deserialize into the old struct,
//    and convert it to the new `Vault` struct before returning.
const FORMAT_VERSION: u32 = 1; // Stable V1

/// Defines how the Master Key is protected.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VaultMode {
    /// Master Key is generated randomly and sealed to the TPM. 
    /// Can only be opened on this specific device.
    DeviceBound = 1,
    /// Master Key is generated randomly and encrypted with a password-derived key.
    /// Can be opened on any device with the correct password.
    Portable = 2,
}

impl Default for VaultMode {
    fn default() -> Self {
        VaultMode::DeviceBound
    }
}

impl VaultMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(VaultMode::DeviceBound),
            2 => Some(VaultMode::Portable),
            _ => None,
        }
    }
}

/// Vault structure wrapped in an AEAD envelope.
#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub format_version: u32,
    pub mode: VaultMode,
    pub sequence_number: u64, // Monotonic counter for rollback protection
    pub last_updated: DateTime<Utc>,
    pub accounts: Vec<AccountEntry>,
    pub totps: Vec<TotpEntry>,
    pub generator_settings: GeneratorSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GeneratorSettings {
    pub length: i32,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
}

impl Default for GeneratorSettings {
    fn default() -> Self {
        Self {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        }
    }
}

#[derive(Debug)]
pub enum VaultError {
    IoError(io::Error),
    CryptoError(cipher::CryptoError),
    SerializationError(bincode::Error),
    TpmError(sealing::TpmError),
    InvalidMagic,
    UnsupportedVersion,
    InvalidFormat,
    RollbackDetected,
    InvalidMode(u8),
    MissingPassword,
    WrongPassword,
}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self { VaultError::IoError(e) }
}

impl From<cipher::CryptoError> for VaultError {
    fn from(e: cipher::CryptoError) -> Self { VaultError::CryptoError(e) }
}

impl From<bincode::Error> for VaultError {
    fn from(e: bincode::Error) -> Self { VaultError::SerializationError(e) }
}

impl From<sealing::TpmError> for VaultError {
    fn from(e: sealing::TpmError) -> Self { VaultError::TpmError(e) }
}

/// Save the vault to a file.
/// 
/// - `master_key`: The raw 32-byte encryption key for the vault.
/// - `password`: Required ONLY if mode is Portable. Used to wrap the master_key.
pub fn save_vault<P: AsRef<Path>>(
    path: P, 
    vault: &Vault, 
    master_key: &SecureBuffer, 
    mode: VaultMode,
    password: Option<&[u8]>
) -> Result<(), VaultError> {
    
    // 1. Prepare Header Data
    let salt = kdf::generate_salt();
    let kdf_version = Argon2ParamsVersion::V1_2024 as u8;

    // 2. Wrap the Master Key based on Mode
    let (wrapped_key_blob, wrapper_nonce) = match mode {
        VaultMode::DeviceBound => {
            let pass = password.ok_or(VaultError::MissingPassword)?;
            // Derive KEK (Key Encryption Key) from Password
            let kek = kdf::derive_key(pass, &salt, Argon2ParamsVersion::V1_2024)
                .map_err(|_| VaultError::CryptoError(cipher::CryptoError::KeyPrecomputationFailed))?;
            
            // Encrypt Master Key with KEK
            // Use "PASSX_DEVICE_BOUND_MASTER_KEY" as AAD to distinguish from Portable
            let aad = b"PASSX_DEVICE_BOUND_MASTER_KEY";
            let (ciphertext, nonce, tag) = cipher::encrypt(&kek, &master_key[..], aad)?;
            
            // Allow minimal allocation: Ciphertext + Tag
            let mut key_blob = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
            key_blob.extend_from_slice(&ciphertext);
            key_blob.extend_from_slice(&tag);
            
            // Seal the ENCRYPTED Master Key to TPM
            // We need to wrap it in SecureBuffer to pass to seal_key, though it's already encrypted.
            // But seal_key expects SecureBuffer.
            let key_blob_secure = SecureBuffer::from_slice(&key_blob).ok_or(VaultError::CryptoError(cipher::CryptoError::KeyPrecomputationFailed))?; // Reuse error
            let sealed_blob = sealing::seal_key(&key_blob_secure)?;

            // We use the nonce generated during KEK encryption
            (sealed_blob, nonce) 
        },
        VaultMode::Portable => {
            let pass = password.ok_or(VaultError::MissingPassword)?;
            // Derive KEK (Key Encryption Key) from Password
            let kek = kdf::derive_key(pass, &salt, Argon2ParamsVersion::V1_2024)
                .map_err(|_| VaultError::CryptoError(cipher::CryptoError::KeyPrecomputationFailed))?; // Map error properly
            
            // Encrypt Master Key with KEK
            // Use empty AAD for the wrapper or bind it? 
            // Let's bind it to "PASSX_PORTABLE_MASTER_KEY"
            let aad = b"PASSX_PORTABLE_MASTER_KEY";
            let (ciphertext, nonce, tag) = cipher::encrypt(&kek, &master_key[..], aad)?;
            
            // Allow minimal allocation: Ciphertext + Tag
            let mut blob = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
            blob.extend_from_slice(&ciphertext);
            blob.extend_from_slice(&tag);
            
            (blob, nonce)
        }
    };

    // 3. Encrypt Vault Content
    // Derive vault-specific subkey from Master Key to encrypt the actual data
    let content_subkey = cipher::derive_subkey(&master_key[..], b"passx_VAULT_CONTENT")?;
    
    let serialized_data = bincode::serialize(vault)?;

    // AAD for Content
    // Binds the ciphertext to the header metadata
    let mut aad = Vec::new();
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.push(mode as u8);
    aad.push(kdf_version);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&vault.sequence_number.to_le_bytes());

    let (content_ciphertext, content_nonce, content_tag) = cipher::encrypt(&content_subkey, &serialized_data, &aad)?;

    // 4. Write to File
    // Format:
    // Magic (6)
    // Version (4)
    // Mode (1)
    // KDF Ver (1)
    // Salt (32)
    // Wrapper Nonce (24) - Needed for Portable
    // Wrapped Key Len (4)
    // Wrapped Key (N)
    // Seq Num (8)
    // Content Nonce (24)
    // Content Tag (16) --- Wait, encrypt returns Tag separately? usually appended.
    // My cipher::encrypt returns (ciphertext, nonce, tag).
    // So: Content Ciphertext (M)
    // Content Tag (16)

    let mut file = File::create(path)?;
    file.write_all(MAGIC)?;
    file.write_all(&FORMAT_VERSION.to_le_bytes())?;
    file.write_all(&[mode as u8])?;
    file.write_all(&[kdf_version])?;
    file.write_all(&salt)?;
    file.write_all(&wrapper_nonce)?;
    
    let wrapped_key_len = wrapped_key_blob.len() as u32;
    file.write_all(&wrapped_key_len.to_le_bytes())?;
    file.write_all(&wrapped_key_blob)?;
    
    file.write_all(&vault.sequence_number.to_le_bytes())?;
    file.write_all(&content_nonce)?;
    file.write_all(&content_ciphertext)?;
    file.write_all(&content_tag)?; // Tag at end usually

    Ok(())
}

/// Load the vault from a file.
/// 
/// - `password`: Optional. Required if vault is Portable.
pub fn load_vault<P: AsRef<Path>>(
    path: P, 
    password: Option<&[u8]>
) -> Result<(Vault, SecureBuffer, VaultMode), VaultError> {
    
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    // 1. Basic Header Parsing
    if buffer.len() < 6 + 4 + 1 + 1 + SALT_LEN + NONCE_SIZE + 4 {
        return Err(VaultError::InvalidFormat);
    }
    
    let magic = &buffer[0..6];
    if magic != MAGIC { return Err(VaultError::InvalidMagic); }
    
    let format_version = u32::from_le_bytes(buffer[6..10].try_into().unwrap());
    // Allow V1 (Current) and V2 (Legacy/Pre-release migration source)
    if format_version != FORMAT_VERSION && format_version != 2 { return Err(VaultError::UnsupportedVersion); }
    
    let mode_byte = buffer[10];
    let mode = VaultMode::from_u8(mode_byte).ok_or(VaultError::InvalidMode(mode_byte))?;
    
    let kdf_version_raw = buffer[11];
    if kdf_version_raw != Argon2ParamsVersion::V1_2024 as u8 {
        return Err(VaultError::UnsupportedVersion);
    }
    
    let salt: [u8; SALT_LEN] = buffer[12..44].try_into().unwrap();
    let wrapper_nonce: [u8; NONCE_SIZE] = buffer[44..68].try_into().unwrap();
    let wrapped_key_len = u32::from_le_bytes(buffer[68..72].try_into().unwrap()) as usize;
    
    if buffer.len() < 72 + wrapped_key_len + 8 + NONCE_SIZE + TAG_SIZE {
        return Err(VaultError::InvalidFormat);
    }
    
    let wrapped_key = &buffer[72 .. 72 + wrapped_key_len];
    let offset_after_key = 72 + wrapped_key_len;
    
    // 2. Unwrap Master Key
    let master_key = match mode {
        VaultMode::DeviceBound => {
            // Unseal with TPM to get Encrypted Master Key
            let encrypted_key_blob_mem = sealing::unseal_key(wrapped_key)?;
            let encrypted_key_blob = &encrypted_key_blob_mem[..]; // Access inner slice

            let pass = password.ok_or(VaultError::MissingPassword)?;
            // Derive KEK
            let kek = kdf::derive_key(pass, &salt, Argon2ParamsVersion::V1_2024)
                 .map_err(|_| VaultError::CryptoError(cipher::CryptoError::KeyPrecomputationFailed))?;
            
            // Decrypt Wrapper
            if encrypted_key_blob.len() < TAG_SIZE { return Err(VaultError::InvalidFormat); }
            let tag_start = encrypted_key_blob.len() - TAG_SIZE;
            let ciphertext = &encrypted_key_blob[..tag_start];
            let tag: [u8; TAG_SIZE] = encrypted_key_blob[tag_start..].try_into().unwrap();
            
            let aad = b"PASSX_DEVICE_BOUND_MASTER_KEY";
            let plaintext = cipher::decrypt(&kek, &wrapper_nonce, &tag, ciphertext, aad)?;
            
            SecureBuffer::from_slice(&plaintext).ok_or(VaultError::CryptoError(cipher::CryptoError::DecryptionFailed))?
        },
        VaultMode::Portable => {
             let pass = password.ok_or(VaultError::MissingPassword)?;
             // Derive KEK
             let kek = kdf::derive_key(pass, &salt, Argon2ParamsVersion::V1_2024)
                 .map_err(|_| VaultError::CryptoError(cipher::CryptoError::KeyPrecomputationFailed))?;
            
             // Decrypt Wrapper
             // Wrapped Key is Ciphertext + Tag
             if wrapped_key.len() < TAG_SIZE { return Err(VaultError::InvalidFormat); }
             let tag_start = wrapped_key.len() - TAG_SIZE;
             let ciphertext = &wrapped_key[..tag_start];
             let tag: [u8; TAG_SIZE] = wrapped_key[tag_start..].try_into().unwrap();
             
             let aad = b"PASSX_PORTABLE_MASTER_KEY";
             let plaintext = cipher::decrypt(&kek, &wrapper_nonce, &tag, ciphertext, aad)?;
             
             SecureBuffer::from_slice(&plaintext).ok_or(VaultError::CryptoError(cipher::CryptoError::DecryptionFailed))?
        }
    };
    
    // 3. Decrypt Content
    let seq_num = u64::from_le_bytes(buffer[offset_after_key..offset_after_key+8].try_into().unwrap());
    let content_nonce: [u8; NONCE_SIZE] = buffer[offset_after_key+8 .. offset_after_key+8+NONCE_SIZE].try_into().unwrap();
    
    let content_start = offset_after_key + 8 + NONCE_SIZE;
    let content_tag_start = buffer.len() - TAG_SIZE;
    let content_ciphertext = &buffer[content_start..content_tag_start];
    let content_tag: [u8; TAG_SIZE] = buffer[content_tag_start..].try_into().unwrap();
    
    // Reconstruct AAD
    let mut aad = Vec::new();
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&format_version.to_le_bytes());
    aad.push(mode as u8);
    aad.push(kdf_version_raw);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&seq_num.to_le_bytes());
    
    let content_subkey = cipher::derive_subkey(&master_key[..], b"passx_VAULT_CONTENT")?;
    let plaintext = cipher::decrypt(&content_subkey, &content_nonce, &content_tag, content_ciphertext, &aad)?;
    
    let vault: Vault = bincode::deserialize(&plaintext)?;
    
    // Sanity check mode
    if vault.mode != mode {
        // Warning: Header says one thing, content another? 
        // We trust header for decryption, but maybe warn or error?
        // Let's enforce consistency.
        return Err(VaultError::InvalidFormat);
    }
    
    Ok((vault, master_key, mode))
}
