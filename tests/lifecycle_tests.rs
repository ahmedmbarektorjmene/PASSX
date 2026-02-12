use passx::vault::{self, Vault, VaultMode, AccountEntry};
use passx::memory::guard::SecureBuffer;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn get_temp_file() -> PathBuf {
    let mut path = env::temp_dir();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    // Add random suffix to avoid collisions if running in parallel or quick succession
    let pid = std::process::id(); 
    path.push(format!("passx_test_{}_{}.vault", pid, nanos));
    path
}

#[test]
fn test_lifecycle_portable_vault() {
    let path = get_temp_file();
    let password = b"strong_password";
    let master_key = SecureBuffer::from_slice(&[1u8; 32]).unwrap(); 
    
    let mut vault = Vault::default();
    vault.mode = VaultMode::Portable;
    
    // Create an account
    let account = AccountEntry::new(
        "Example".to_string(),
        "user".to_string(),
        b"secret",
        Some("https://example.com".to_string())
    ).expect("Failed to create account");
    
    vault.accounts.push(account);

    // 1. Save
    vault::format::save_vault(&path, &vault, &master_key, VaultMode::Portable, Some(password))
        .expect("Failed to save vault");
    
    // 2. Load
    let (loaded_vault, _loaded_key, mode) = vault::format::load_vault(&path, Some(password))
        .expect("Failed to load vault");
    
    assert_eq!(mode, VaultMode::Portable);
    assert_eq!(loaded_vault.accounts.len(), 1);
    assert_eq!(loaded_vault.accounts[0].username, "user");
    assert_eq!(&loaded_vault.accounts[0].password[..], b"secret");
    
    // 3. Load with Wrong Password -> Fail
    let wrong_password = b"wrong_password";
    let result = vault::format::load_vault(&path, Some(wrong_password));
    assert!(result.is_err(), "Should fail with wrong password");
    
    match result {
        Err(passx::vault::VaultError::CryptoError(_)) => {}, // Expected
        _ => panic!("Expected CryptoError for wrong password"),
    }
    
    // 4. Corrupt File -> Fail
    let mut content = fs::read(&path).unwrap();
    // Corrupt the middle of the file (likely ciphertext)
    let len = content.len();
    content[len - 20] ^= 0xFF; 
    fs::write(&path, &content).unwrap();
    
    let result = vault::format::load_vault(&path, Some(password));
    assert!(result.is_err(), "Should fail with corrupted file");

    // Cleanup
    let _ = fs::remove_file(path);
}

#[test]
fn test_lifecycle_empty_vault() {
    let path = get_temp_file();
    let password = b"pass";
    let master_key = SecureBuffer::from_slice(&[2u8; 32]).unwrap();
    
    let mut vault = Vault::default();
    vault.mode = VaultMode::Portable;
    
    // Save empty
    vault::format::save_vault(&path, &vault, &master_key, VaultMode::Portable, Some(password)).unwrap();
    
    // Load
    let (loaded, _, _) = vault::format::load_vault(&path, Some(password)).unwrap();
    assert_eq!(loaded.accounts.len(), 0);
    
    let _ = fs::remove_file(path);
}
