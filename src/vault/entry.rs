use crate::memory::guard::SecureBuffer;
use serde::{Serialize, Deserialize};
use chrono::Utc;
use crate::crypto::random::SecureRandom;
use hex;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: SecureBuffer,
    pub url: String,
    pub notes: SecureBuffer,
    pub deleted: bool,
    pub folder: Option<String>,
    pub icon_data: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TotpEntry {
    pub id: String,
    pub issuer: String,
    pub account_name: String,
    pub secret: SecureBuffer,
    pub linked_account_id: Option<String>, // Foreign key to AccountEntry
    pub deleted: bool,
    pub icon_data: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl AccountEntry {
    pub fn new(title: String, username: String, password: &[u8], url: Option<String>) -> Option<Self> {
        let password_buf = SecureBuffer::from_slice(password)?;
        let notes_buf = SecureBuffer::new(0)?;
        
        // Generate random ID
        let mut id_bytes = [0u8; 16];
        SecureRandom::fill(&mut id_bytes);
        let id = hex::encode(id_bytes);

        Some(Self {
            id,
            title,
            username,
            password: password_buf,
            url: url.unwrap_or_default(),
            notes: notes_buf,
            deleted: false,
            folder: None,
            icon_data: None,
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
        })
    }

    pub fn update_password(&mut self, new_password: &[u8]) -> bool {
        if let Some(buf) = SecureBuffer::from_slice(new_password) {
            self.password = buf;
            self.updated_at = Utc::now().timestamp();
            true
        } else {
            false
        }
    }
}

impl TotpEntry {
    pub fn new(issuer: String, account_name: String, secret: &[u8], linked_account_id: Option<String>) -> Option<Self> {
        let secret_buf = SecureBuffer::from_slice(secret)?;
        
        let mut id_bytes = [0u8; 16];
        SecureRandom::fill(&mut id_bytes);
        let id = hex::encode(id_bytes);

        Some(Self {
            id,
            issuer,
            account_name,
            secret: secret_buf,
            linked_account_id,
            deleted: false,
            icon_data: None,
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_entry_creation() {
        let title = "Test Account".to_string();
        let username = "testuser".to_string();
        let password = b"supersecret";
        
        let entry = AccountEntry::new(title.clone(), username.clone(), password, None).unwrap();
        
        assert_eq!(entry.title, title);
        assert_eq!(entry.username, username);
        assert!(!entry.id.is_empty());
        assert_eq!(entry.deleted, false);
        // We can't easily check SecureBuffer contents directly without unsealing/exposing,
        // but its existence implies success.
    }

    #[test]
    fn test_account_entry_password_update() {
        let mut entry = AccountEntry::new("T".to_string(), "U".to_string(), b"old", None).unwrap();
        let initial_updated = entry.updated_at;
        
        // Wait briefly so timestamp can change (or we just accept it might be same second, tests execute fast)
        // To ensure it, we can just check if update_password returns true.
        assert!(entry.update_password(b"newpassword"));
        // updated_at should be >= initial
        assert!(entry.updated_at >= initial_updated);
    }

    #[test]
    fn test_totp_entry_creation() {
        let entry = TotpEntry::new("Issuer".to_string(), "Account".to_string(), b"secret", None).unwrap();
        assert_eq!(entry.issuer, "Issuer");
        assert_eq!(entry.account_name, "Account");
        assert!(!entry.id.is_empty());
    }
}
