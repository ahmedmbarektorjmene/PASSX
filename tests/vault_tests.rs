use passx::vault::{format, format::Vault, format::VaultMode, entry::{AccountEntry, TotpEntry}, operations::VaultOps};
use passx::memory::guard::SecureBuffer;
use std::fs;

#[test]
fn test_vault_entry_management() {
    let mut vault = Vault::default();
    
    // Add Account
    let account = AccountEntry::new(
        "GitHub".to_string(),
        "user1".to_string(),
        b"password123",
        Some("https://github.com".to_string())
    ).unwrap();
    
    VaultOps::add_account(&mut vault, account);
    
    assert_eq!(vault.accounts.len(), 1);
    
    let found = VaultOps::find_account(&vault, &vault.accounts[0].id);
    assert!(found.is_some());
    assert_eq!(found.unwrap().title, "GitHub");

    // Add TOTP
    let totp = TotpEntry::new(
        "Google".to_string(),
        "user2".to_string(),
        b"SECRET123",
        None
    ).unwrap();
    VaultOps::add_totp(&mut vault, totp);
    
    assert_eq!(vault.totps.len(), 1);
    let found_totp = VaultOps::find_totp(&vault, &vault.totps[0].id);
    assert!(found_totp.is_some());
}

#[test]
fn test_vault_persistence() {
    let temp_file = "test_vault_persistence.dat";
    let _ = fs::remove_file(temp_file);

    // Mock Master Key
    let key_raw = [0x42u8; 32];
    let key = SecureBuffer::from_slice(&key_raw).unwrap();
    let password = b"testpassword";

    let mut vault = Vault {
        mode: VaultMode::Portable,
        ..Default::default()
    };
    
    let account = AccountEntry::new(
        "Google".to_string(),
        "user2".to_string(),
        b"secretGoogle",
        Some("https://google.com".to_string())
    ).unwrap();
    VaultOps::add_account(&mut vault, account);
    
    // Save
    format::save_vault(temp_file, &vault, &key, VaultMode::Portable, Some(password)).unwrap();
    
    // Load
    let (loaded_vault, loaded_key, mode) = format::load_vault(temp_file, Some(password)).unwrap();
    
    assert_eq!(&loaded_key[..], &key[..]);
    assert_eq!(mode, VaultMode::Portable);
    assert_eq!(loaded_vault.accounts.len(), 1);
    assert_eq!(loaded_vault.accounts[0].title, "Google");
    
    // Cleanup
    let _ = fs::remove_file(temp_file);
}
