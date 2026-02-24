use crate::vault::format::Vault;
use crate::vault::entry::{AccountEntry, TotpEntry};

/// Operations for managing entries in an unlocked vault.
pub struct VaultOps;

pub enum EntryRef<'a> {
    Account(&'a AccountEntry),
    Totp(&'a TotpEntry),
}

impl VaultOps {
    /// Add a new account to the vault.
    pub fn add_account(vault: &mut Vault, entry: AccountEntry) {
        vault.accounts.push(entry);
    }

    /// Add a new TOTP entry to the vault.
    pub fn add_totp(vault: &mut Vault, entry: TotpEntry) {
        vault.totps.push(entry);
    }

    /// Remove an entry by ID from either accounts or TOTPs.
    pub fn remove_entry(vault: &mut Vault, id: &str) -> bool {
        if let Some(pos) = vault.accounts.iter().position(|e| e.id == id) {
            vault.accounts.remove(pos);
            true
        } else if let Some(pos) = vault.totps.iter().position(|e| e.id == id) {
            vault.totps.remove(pos);
            true
        } else {
            false
        }
    }

    /// Find an account by ID.
    pub fn find_account<'a>(vault: &'a Vault, id: &str) -> Option<&'a AccountEntry> {
        vault.accounts.iter().find(|e| e.id == id)
    }

    /// Find a TOTP entry by ID.
    pub fn find_totp<'a>(vault: &'a Vault, id: &str) -> Option<&'a TotpEntry> {
        vault.totps.iter().find(|e| e.id == id)
    }

    /// Search accounts by title or username (case-insensitive substring).
    pub fn search_accounts<'a>(vault: &'a Vault, query: &str) -> Vec<&'a AccountEntry> {
        let q = query.to_lowercase();
        vault.accounts.iter().filter(|e| {
            e.title.to_lowercase().contains(&q) || e.username.to_lowercase().contains(&q)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::Vault;

    fn create_test_vault() -> Vault {
        Vault {
            format_version: 1,
            mode: crate::vault::format::VaultMode::Portable,
            sequence_number: 0,
            last_updated: chrono::Utc::now(),
            accounts: vec![],
            totps: vec![],
            mirrors: vec![],
            generator_settings: crate::vault::format::GeneratorSettings::default(),
        }
    }

    #[test]
    fn test_add_and_find_account() {
        let mut vault = create_test_vault();
        let account = AccountEntry::new("Test Title".to_string(), "testuser".to_string(), b"pass", None).unwrap();
        let id = account.id.clone();
        
        VaultOps::add_account(&mut vault, account);
        assert_eq!(vault.accounts.len(), 1);
        
        let found = VaultOps::find_account(&vault, &id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().title, "Test Title");
    }

    #[test]
    fn test_remove_entry() {
        let mut vault = create_test_vault();
        let account = AccountEntry::new("A".to_string(), "B".to_string(), b"C", None).unwrap();
        let totp = TotpEntry::new("I".to_string(), "A".to_string(), b"S", None).unwrap();
        
        let acc_id = account.id.clone();
        let totp_id = totp.id.clone();
        
        VaultOps::add_account(&mut vault, account);
        VaultOps::add_totp(&mut vault, totp);
        
        assert_eq!(vault.accounts.len(), 1);
        assert_eq!(vault.totps.len(), 1);
        
        // Remove account
        assert!(VaultOps::remove_entry(&mut vault, &acc_id));
        assert_eq!(vault.accounts.len(), 0);
        
        // Remove TOTP
        assert!(VaultOps::remove_entry(&mut vault, &totp_id));
        assert_eq!(vault.totps.len(), 0);
        
        // Try removing non-existent
        assert!(!VaultOps::remove_entry(&mut vault, "nonexistent"));
    }

    #[test]
    fn test_search_accounts() {
        let mut vault = create_test_vault();
        VaultOps::add_account(&mut vault, AccountEntry::new("Google".to_string(), "user1@gmail.com".to_string(), b"pass", None).unwrap());
        VaultOps::add_account(&mut vault, AccountEntry::new("Github".to_string(), "user1".to_string(), b"pass", None).unwrap());
        
        // Search by title
        let res1 = VaultOps::search_accounts(&vault, "goog");
        assert_eq!(res1.len(), 1);
        assert_eq!(res1[0].title, "Google");
        
        // Search by username
        let res2 = VaultOps::search_accounts(&vault, "user1");
        assert_eq!(res2.len(), 2);
    }
}
