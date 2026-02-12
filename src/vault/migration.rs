use serde::{Serialize, Deserialize};
use crate::memory::guard::SecureBuffer;
use crate::vault::entry::{AccountEntry, TotpEntry};
use crate::vault::format::{Vault, VaultMode}; // Use V1 vault definition
use chrono::{DateTime, Utc};

// ─── Legacy V2 Structures ───
#[derive(Serialize, Deserialize)]
pub struct VaultV2 {
    pub format_version: u32,
    pub mode: VaultMode,
    pub sequence_number: u64,
    pub last_updated: DateTime<Utc>,
    pub entries: Vec<PasswordEntryV2>,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordEntryV2 {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: SecureBuffer,
    pub url: String,
    pub notes: SecureBuffer,
    pub totp_secret: Option<SecureBuffer>,
    pub deleted: bool,
    pub folder: Option<String>,
    pub icon_data: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    // Note: 'favorite' might have been present in v2? 
    // Wait, I removed 'favorite' in previous step, but 'entry.rs' V2 DID NOT have favorite field in the struct definition I viewed earlier.
    // Let me check 'viewed_code_item' from previous turns.
    // viewed_code_item vault/entry.rs:8: PasswordEntry did NOT have favorite field.
    // It was only in UI model.
    // So this struct should match what was in entry.rs.
}

pub fn migrate_v2_payload(plaintext: &[u8]) -> Result<Vault, bincode::Error> {
    let v2: VaultV2 = bincode::deserialize(plaintext)?;
    
    let mut accounts = Vec::new();
    let mut totps = Vec::new();

    for entry in v2.entries {
        // 1. Create Account Entry
        // Even if it's a TOTP-only entry (empty password), we might create an Account for it acting as a container?
        // Or if password is empty and totp exists, treat as TOTP only?
        // Strategy:
        // - If has password OR (no password and no totp), it's definitely an account.
        // - If has TOTP:
        //   - If has password: Create Account AND separate Linked TOTP.
        //   - If NO password: Create TOTP only (standalone).
        
        let has_password = !entry.password.is_empty();
        let has_totp = entry.totp_secret.is_some();
        
        if has_password || !has_totp {
            // Create Account
            let account = AccountEntry {
                id: entry.id.clone(),
                title: entry.title.clone(),
                username: entry.username.clone(),
                password: entry.password, // Move
                url: entry.url,
                notes: entry.notes,
                deleted: entry.deleted,
                folder: entry.folder.clone(),
                icon_data: entry.icon_data.clone(),
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            };
            accounts.push(account);

            // If it also has TOTP, create a linked TOTP entry
            if let Some(secret) = entry.totp_secret {
                // Generate a new ID for the TOTP entry
                // We don't have SecureRandom here easily without importing logic.
                // Let's us a simple random for migration or deterministic?
                // Deterministic is better for migration stability but random is fine.
                // We'll use a simple deterministic ID based on account ID + suffix to ensure stability if migrated multiple times (though not likely).
                let totp_id = format!("{}-totp", entry.id); 
                
                let totp = TotpEntry {
                    id: totp_id,
                    issuer: entry.username.clone(), // Map username to issuer? Or title? V2 used username as issuer often.
                    account_name: entry.title.clone(),
                    secret,
                    linked_account_id: Some(entry.id.clone()),
                    deleted: entry.deleted,
                    icon_data: entry.icon_data, // Copy icon?
                    created_at: entry.created_at,
                    updated_at: entry.updated_at,
                };
                totps.push(totp);
            }
        } else {
            // TOTP Only (Standalone)
            if let Some(secret) = entry.totp_secret {
                 let totp = TotpEntry {
                    id: entry.id, // Keep original ID
                    issuer: entry.username,
                    account_name: entry.title,
                    secret,
                    linked_account_id: None,
                    deleted: entry.deleted,
                    icon_data: entry.icon_data,
                    created_at: entry.created_at,
                    updated_at: entry.updated_at,
                };
                totps.push(totp);
            }
        }
    }

    Ok(Vault {
        format_version: 1, // Upgrade to stable V1
        mode: v2.mode,
        sequence_number: v2.sequence_number,
        last_updated: v2.last_updated,
        accounts,
        totps,
    })
}
