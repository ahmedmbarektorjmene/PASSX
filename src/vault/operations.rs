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
