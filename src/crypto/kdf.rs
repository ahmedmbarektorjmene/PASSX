use argon2::{
    password_hash::rand_core::OsRng,
    Argon2, Algorithm, Version, Params
};
use crate::memory::guard::SecureBuffer;

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

/// Argon2id parameter set versions.
/// We MUST lock these and version them for future compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2ParamsVersion {
    V1_2024, // current
}

impl Argon2ParamsVersion {
    pub fn get_params(&self) -> Params {
        match self {
            Self::V1_2024 => {
                // Strong parameters: 64MB memory, 3 iterations, 4 parallelism
                Params::new(64 * 1024, 3, 4, Some(KEY_LEN)).unwrap()
            }
        }
    }
}

#[derive(Debug)]
pub enum KdfError {
    DerivationFailed,
    InvalidParams,
}

/// Derive a master key from a password using Argon2id.
/// Returns the derived key in a SecureBuffer.
pub fn derive_key(
    password: &[u8], 
    salt: &[u8], 
    version: Argon2ParamsVersion
) -> Result<SecureBuffer, KdfError> {
    let params = version.get_params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Prepare secure output buffer
    let mut key_buffer = SecureBuffer::new(KEY_LEN)
        .ok_or(KdfError::DerivationFailed)?;

    // Hash password directly into secure buffer
    argon2.hash_password_into(password, salt, &mut key_buffer)
        .map_err(|_| KdfError::DerivationFailed)?;

    Ok(key_buffer)
}

/// Generate a new random salt for KDF
pub fn generate_salt() -> [u8; SALT_LEN] {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_consistency() {
        let password = b"P@$$w0rd";
        let salt = generate_salt();

        let key1 = derive_key(password, &salt, Argon2ParamsVersion::V1_2024).unwrap();
        let key2 = derive_key(password, &salt, Argon2ParamsVersion::V1_2024).unwrap();

        assert_eq!(key1.len(), KEY_LEN);
        assert_eq!(key1.as_slice(), key2.as_slice(), "Same password+salt should yield same key");
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"password123";
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key1 = derive_key(password, &salt1, Argon2ParamsVersion::V1_2024).unwrap();
        let key2 = derive_key(password, &salt2, Argon2ParamsVersion::V1_2024).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice(), "Different salts should yield different keys");
    }
}

