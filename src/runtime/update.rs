use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use std::fs;
use std::path::Path;
use std::convert::TryInto;

#[derive(Debug)]
pub enum UpdateError {
    NetworkError,
    SignatureVerificationFailed,
    InvalidPublicKey,
    InvalidSignatureLength,
}

/// Verify a downloaded update package against a known public key.
/// Returns true if signature is valid.
pub fn verify_signature(
    file_path: &Path,
    signature_bytes: &[u8],
    public_key_bytes: &[u8]
) -> Result<bool, UpdateError> {
    let public_key_array: &[u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| UpdateError::InvalidPublicKey)?;
    
    let public_key = VerifyingKey::from_bytes(public_key_array)
        .map_err(|_| UpdateError::InvalidPublicKey)?;
        
    let signature_array: &[u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| UpdateError::InvalidSignatureLength)?;
        
    let signature = Signature::from_bytes(signature_array);
        
    let file_content = fs::read(file_path)
        .map_err(|_| UpdateError::NetworkError)?;
        
    public_key.verify(&file_content, &signature)
        .map(|_| true)
        .map_err(|_| UpdateError::SignatureVerificationFailed)
}
