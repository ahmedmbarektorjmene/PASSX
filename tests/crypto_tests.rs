use passx::crypto::{cipher, kdf};
use passx::memory::guard::SecureBuffer;

#[test]
fn test_encryption_roundtrip() {
    let key = [0u8; 32]; // Not secure but OK for test vector
    let plaintext = b"Hello, World!";
    let aad = b"test";
    
    // Test XChaCha20-Poly1305 roundtrip
    let (ciphertext_buf, nonce, tag) = cipher::encrypt(&key, plaintext, aad).unwrap();
    let decrypted = cipher::decrypt(&key, &nonce, &tag, &ciphertext_buf, aad).unwrap();
    
    assert_eq!(&decrypted[..], plaintext);
    assert_eq!(nonce.len(), 24); // XNonce size
}

#[test]
fn test_encryption_fail_closed_bitflip() {
    let key = [0u8; 32];
    let plaintext = b"Secret Message";
    let aad = b"context";
    
    let (mut ciphertext_buf, nonce, tag) = cipher::encrypt(&key, plaintext, aad).unwrap();
    
    // Corrupt one bit of ciphertext
    ciphertext_buf[0] ^= 0x01;
    
    let result = cipher::decrypt(&key, &nonce, &tag, &ciphertext_buf, aad);
    match result {
        Err(cipher::CryptoError::DecryptionFailed) => {}, // Functionality correct
        Ok(_) => panic!("Decrypted corrupted ciphertext!"),
        Err(e) => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn test_encryption_fail_closed_tag_mismatch() {
    let key = [0u8; 32];
    let plaintext = b"Secret Message";
    let aad = b"context";
    
    let (ciphertext_buf, nonce, mut tag) = cipher::encrypt(&key, plaintext, aad).unwrap();
    
    // Corrupt tag
    tag[0] ^= 0x01;
    
    let result = cipher::decrypt(&key, &nonce, &tag, &ciphertext_buf, aad);
    match result {
        Err(cipher::CryptoError::DecryptionFailed) => {}, // Functionality correct
        Ok(_) => panic!("Decrypted with wrong tag!"),
        Err(e) => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn test_subkey_derivation_separation() {
    let master_key = [1u8; 32];
    let info_enc = b"encryption_key";
    let info_mac = b"mac_key";
    
    let subkey1 = cipher::derive_subkey(&master_key, info_enc).unwrap();
    let subkey2 = cipher::derive_subkey(&master_key, info_mac).unwrap();
    
    // Different purposes must yield different keys
    assert_ne!(&subkey1[..], &subkey2[..]);
    
    // Different master keys must yield different keys
    let master_key_2 = [2u8; 32];
    let subkey3 = cipher::derive_subkey(&master_key_2, info_enc).unwrap();
    assert_ne!(&subkey1[..], &subkey3[..]);
}

#[test]
fn test_kdf_params_strength() {
    // Verify that we are using strong default parameters
    let version = kdf::Argon2ParamsVersion::V1_2024;
    let params = version.get_params();
    
    // OWASP recommendation: Memory >= 64MB (64 * 1024 KB), Iterations >= 3
    assert!((params.m_cost() as u32) >= 64 * 1024, "Memory cost too low");
    assert!((params.t_cost() as u32) >= 3, "Time cost (iterations) too low");
    assert_eq!(params.p_cost(), 4, "Parallelism should be 4");
}

#[test]
fn test_kdf_salt_uniqueness() {
    let salt1 = kdf::generate_salt();
    let salt2 = kdf::generate_salt();
    assert_ne!(&salt1[..], &salt2[..], "Salts must be random");
}

#[test]
fn test_key_zeroization_after_drop() {
    // This test is tricky in Rust without unsafe, but we can verify the API contract.
    // In a real attack scenario, we'd inspect memory. Here we trust the `zeroize` crate 
    // but ensure our wrapper `SecureBuffer` implements `Drop`.
    
    let buffer = SecureBuffer::from_slice(b"secret").unwrap();
    let _ptr = buffer.as_ptr();
    
    // We can't easily read `ptr` after drop in safe Rust without specific tools or unsafe blocks 
    // that might trigger UB if the OS reclaims memory. 
    // We will rely on `memory_security.rs` for the more invasive test.
    drop(buffer);
}

