use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptOpenStorageProvider, NCryptOpenKey, NCryptCreatePersistedKey,
    NCryptFinalizeKey, NCryptEncrypt, NCryptDecrypt, NCryptFreeObject,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_FLAGS,
    BCRYPT_RSA_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_PAD_PKCS1_FLAG, CERT_KEY_SPEC,
};
use crate::memory::guard::SecureBuffer;

#[derive(Debug)]
pub enum TpmError {
    ProviderOpenFailed,
    KeyCreateFailed,
    EncryptionFailed,
    DecryptionFailed,
    TpmUnavailable,
}

const MASTER_KEY_WRAPPER_NAME: &str = "passxMasterKeyWrapper\0";

/// Initialize TPM via Windows CNG.
fn open_tpm_provider() -> Result<NCRYPT_PROV_HANDLE, TpmError> {
    let mut prov_handle = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(
            &mut prov_handle,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0, // flags is u32 here
        ).map_err(|_| TpmError::ProviderOpenFailed)?;
    }
    Ok(prov_handle)
}

/// Get or create a persistent wrapping key within the TPM.
fn get_or_create_wrapping_key(prov: NCRYPT_PROV_HANDLE) -> Result<NCRYPT_KEY_HANDLE, TpmError> {
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let name_u16: Vec<u16> = MASTER_KEY_WRAPPER_NAME.encode_utf16().collect();
    let pcwstr = PCWSTR::from_raw(name_u16.as_ptr());

    unsafe {
        // Try to open existing key first
        if NCryptOpenKey(prov, &mut key_handle, pcwstr, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_ok() {
            return Ok(key_handle);
        }

        // Create new persistent key in TPM if not found
        NCryptCreatePersistedKey(
            prov,
            &mut key_handle,
            BCRYPT_RSA_ALGORITHM,
            pcwstr,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ).map_err(|_| TpmError::KeyCreateFailed)?;

        NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)).map_err(|_| TpmError::KeyCreateFailed)?;
    }
    Ok(key_handle)
}

/// Seal (Wrap) a master key using the TPM-resident key.
pub fn seal_key(key: &SecureBuffer) -> Result<Vec<u8>, TpmError> {
    let prov = open_tpm_provider()?;
    let key_handle = get_or_create_wrapping_key(prov)?;

    let mut output_len = 0;
    unsafe {
        // Get required buffer size
        NCryptEncrypt(
            key_handle,
            Some(&key[..]),
            None,
            None,
            &mut output_len,
            NCRYPT_PAD_PKCS1_FLAG,
        ).map_err(|_| TpmError::EncryptionFailed)?;

        let mut encrypted_data = vec![0u8; output_len as usize];
        NCryptEncrypt(
            key_handle,
            Some(&key[..]),
            None,
            Some(&mut encrypted_data),
            &mut output_len,
            NCRYPT_PAD_PKCS1_FLAG,
        ).map_err(|_| TpmError::EncryptionFailed)?;

        let _ = NCryptFreeObject::<NCRYPT_KEY_HANDLE>(key_handle);
        let _ = NCryptFreeObject::<NCRYPT_PROV_HANDLE>(prov);

        Ok(encrypted_data)
    }
}

/// Unseal (Unwrap) a master key using the TPM-resident key.
pub fn unseal_key(blob: &[u8]) -> Result<SecureBuffer, TpmError> {
    let prov = open_tpm_provider()?;
    let key_handle = get_or_create_wrapping_key(prov)?;

    let mut output_len = 0;
    unsafe {
        // Get required buffer size
        NCryptDecrypt(
            key_handle,
            Some(blob),
            None,
            None,
            &mut output_len,
            NCRYPT_PAD_PKCS1_FLAG,
        ).map_err(|_| TpmError::DecryptionFailed)?;

        let mut decrypted_data = vec![0u8; output_len as usize];
        NCryptDecrypt(
            key_handle,
            Some(blob),
            None,
            Some(&mut decrypted_data),
            &mut output_len,
            NCRYPT_PAD_PKCS1_FLAG,
        ).map_err(|_| TpmError::DecryptionFailed)?;

        let _ = NCryptFreeObject::<NCRYPT_KEY_HANDLE>(key_handle);
        let _ = NCryptFreeObject::<NCRYPT_PROV_HANDLE>(prov);

        SecureBuffer::from_slice(&decrypted_data).ok_or(TpmError::DecryptionFailed)
    }
}

pub fn check_tpm_availability() -> Result<(), TpmError> {
    open_tpm_provider().map(|p| unsafe { 
        let _ = NCryptFreeObject::<NCRYPT_PROV_HANDLE>(p);
    })
}
