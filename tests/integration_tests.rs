use passx::vault::format::{Vault, VaultMode};
use passx::vault::entry::AccountEntry;
use passx::vault::operations::VaultOps;
use passx::vault::format;
use passx::memory::guard::SecureBuffer;
use std::fs;

#[test]
fn test_end_to_end_flow() {
    let vault_path = "integration_test_vault.dat";
    let _ = fs::remove_file(vault_path); // Ensure clean start
    
    // 1. User sets master password
    let password = b"MasterPassword123!";
    
    // 2. Prepare Vault (Portable mode)
    // Master Key (random in real app)
    let master_key_raw = [0x55u8; 32];
    let master_key = SecureBuffer::from_slice(&master_key_raw).unwrap();

    // 3. Create Vault & Add Entry
    let mut vault = Vault {
        mode: VaultMode::Portable,
        ..Default::default()
    };
    
    let entry = AccountEntry::new(
        "Bank".to_string(),
        "user_bank".to_string(),
        b"super_secret_bank_pw",
        Some("https://bank.com".to_string())
    ).unwrap();

    VaultOps::add_account(&mut vault, entry);
    
    // 4. Save Vault
    // save_vault(path, vault, master_key, mode, password)
    format::save_vault(vault_path, &vault, &master_key, VaultMode::Portable, Some(password)).unwrap();
    
    // 5. Restart Application (Simulated)
    // Load Vault
    let (loaded_vault, loaded_key, loaded_mode) = format::load_vault(vault_path, Some(password)).unwrap();
    
    // Verify Key matches
    assert_eq!(&loaded_key[..], &master_key[..]);
    assert_eq!(loaded_mode, VaultMode::Portable);
    
    // Verify Entry
    let found = VaultOps::find_account(&loaded_vault, &loaded_vault.accounts[0].id);
    assert!(found.is_some());
    let entry = found.unwrap();
    assert_eq!(entry.title, "Bank");
    
    // Verify Password Decrypts
    assert_eq!(&entry.password[..], b"super_secret_bank_pw");
    
    // Cleanup
    let _ = fs::remove_file(vault_path);
}

