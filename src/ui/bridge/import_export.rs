// Import/Export module — Separate Accounts and TOTPs
use crate::vault::entry::{AccountEntry, TotpEntry};
use crate::memory::guard::SecureBuffer;
use crate::crypto::random::SecureRandom;
use chrono::Utc;
use serde::{Serialize, Deserialize};
use std::path::Path;

// ─── Account Export ───
// Matches Chrome's "name,url,username,password,note" format
#[derive(Serialize, Deserialize, Debug)]
pub struct AccountExport {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub note: String,
    pub folder: String,
}

// ─── TOTP Export ───
#[derive(Serialize, Deserialize, Debug)]
pub struct TotpExportStruct {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u64,
}

impl AccountExport {
    pub fn from_entry(entry: &AccountEntry) -> Self {
        AccountExport {
            name: entry.title.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            password: String::from_utf8_lossy(&entry.password[..]).to_string(),
            note: String::from_utf8_lossy(&entry.notes[..]).to_string(),
            folder: entry.folder.clone().unwrap_or_default(),
        }
    }

    pub fn to_entry(&self) -> Option<AccountEntry> {
        let password_buf = SecureBuffer::from_slice(self.password.as_bytes())?;
        let notes_buf = if self.note.is_empty() {
            SecureBuffer::new(0)?
        } else {
            SecureBuffer::from_slice(self.note.as_bytes())?
        };

        let mut id_bytes = [0u8; 16];
        SecureRandom::fill(&mut id_bytes);
        let id = hex::encode(id_bytes);

        Some(AccountEntry {
            id,
            title: self.name.clone(),
            username: self.username.clone(),
            password: password_buf,
            url: self.url.clone(),
            notes: notes_buf,
            deleted: false,
            folder: if self.folder.is_empty() { None } else { Some(self.folder.clone()) },
            icon_data: None,
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
        })
    }
}

impl TotpExportStruct {
    pub fn from_entry(entry: &TotpEntry) -> Option<Self> {
        let secret_str = String::from_utf8_lossy(&entry.secret[..]).to_string();
        if secret_str.is_empty() {
            return None;
        }
        Some(TotpExportStruct {
            name: entry.account_name.clone(),
            secret: secret_str,
            issuer: entry.issuer.clone(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        })
    }

    pub fn to_entry(&self) -> Option<TotpEntry> {
        let secret_buf = SecureBuffer::from_slice(self.secret.as_bytes())?;

        let mut id_bytes = [0u8; 16];
        SecureRandom::fill(&mut id_bytes);
        let id = hex::encode(id_bytes);

        Some(TotpEntry {
            id,
            issuer: self.issuer.clone(),
            account_name: self.name.clone(),
            secret: secret_buf,
            linked_account_id: None, // Import doesn't strictly link yet
            deleted: false,
            icon_data: None,
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
        })
    }
}

// ─── Account Export/Import ───

pub fn export_accounts_csv(entries: &[AccountEntry], path: &Path) -> Result<usize, String> {
    let export: Vec<AccountExport> = entries
        .iter()
        .filter(|e| !e.deleted)
        .map(AccountExport::from_entry)
        .collect();

    let count = export.len();
    let mut wtr = csv::Writer::from_path(path)
        .map_err(|e| format!("Failed to create CSV: {}", e))?;
    for entry in &export {
        wtr.serialize(entry).map_err(|e| format!("CSV write error: {}", e))?;
    }
    wtr.flush().map_err(|e| format!("CSV flush error: {}", e))?;

    println!("[IO] Exported {} accounts to CSV: {:?}", count, path);
    Ok(count)
}

pub fn export_accounts_json(entries: &[AccountEntry], path: &Path) -> Result<usize, String> {
    let export: Vec<AccountExport> = entries
        .iter()
        .filter(|e| !e.deleted)
        .map(AccountExport::from_entry)
        .collect();

    let count = export.len();
    let json = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("JSON error: {}", e))?;
    std::fs::write(path, json).map_err(|e| format!("Write error: {}", e))?;

    println!("[IO] Exported {} accounts to JSON: {:?}", count, path);
    Ok(count)
}

pub fn import_accounts_csv(path: &Path) -> Result<Vec<AccountEntry>, String> {
    let mut rdr = csv::Reader::from_path(path)
        .map_err(|e| format!("Failed to open CSV: {}", e))?;

    let mut entries = Vec::new();
    for (i, result) in rdr.deserialize().enumerate() {
        let record: AccountExport = result
            .map_err(|e| format!("CSV row {} error: {}", i + 1, e))?;
        if let Some(entry) = record.to_entry() {
            entries.push(entry);
        }
    }

    println!("[IO] Imported {} accounts from CSV: {:?}", entries.len(), path);
    Ok(entries)
}

pub fn import_accounts_json(path: &Path) -> Result<Vec<AccountEntry>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Read error: {}", e))?;
    let records: Vec<AccountExport> = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let entries: Vec<AccountEntry> = records.iter().filter_map(|r| r.to_entry()).collect();
    println!("[IO] Imported {} accounts from JSON: {:?}", entries.len(), path);
    Ok(entries)
}

// ─── TOTP Export/Import ───

pub fn export_totps_csv(entries: &[TotpEntry], path: &Path) -> Result<usize, String> {
    let export: Vec<TotpExportStruct> = entries
        .iter()
        .filter(|e| !e.deleted)
        .filter_map(TotpExportStruct::from_entry)
        .collect();

    let count = export.len();
    let mut wtr = csv::Writer::from_path(path)
        .map_err(|e| format!("Failed to create CSV: {}", e))?;
    for entry in &export {
        wtr.serialize(entry).map_err(|e| format!("CSV write error: {}", e))?;
    }
    wtr.flush().map_err(|e| format!("CSV flush error: {}", e))?;

    println!("[IO] Exported {} TOTPs to CSV: {:?}", count, path);
    Ok(count)
}

pub fn export_totps_json(entries: &[TotpEntry], path: &Path) -> Result<usize, String> {
    let export: Vec<TotpExportStruct> = entries
        .iter()
        .filter(|e| !e.deleted)
        .filter_map(TotpExportStruct::from_entry)
        .collect();

    let count = export.len();
    let json = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("JSON error: {}", e))?;
    std::fs::write(path, json).map_err(|e| format!("Write error: {}", e))?;

    println!("[IO] Exported {} TOTPs to JSON: {:?}", count, path);
    Ok(count)
}

pub fn import_totps_csv(path: &Path) -> Result<Vec<TotpEntry>, String> {
    let mut rdr = csv::Reader::from_path(path)
        .map_err(|e| format!("Failed to open CSV: {}", e))?;

    let mut entries = Vec::new();
    for (i, result) in rdr.deserialize().enumerate() {
        let record: TotpExportStruct = result
            .map_err(|e| format!("CSV row {} error: {}", i + 1, e))?;
        if let Some(entry) = record.to_entry() {
            entries.push(entry);
        }
    }

    println!("[IO] Imported {} TOTPs from CSV: {:?}", entries.len(), path);
    Ok(entries)
}

pub fn import_totps_json(path: &Path) -> Result<Vec<TotpEntry>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Read error: {}", e))?;
    let records: Vec<TotpExportStruct> = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let entries: Vec<TotpEntry> = records.iter().filter_map(|r| r.to_entry()).collect();
    println!("[IO] Imported {} TOTPs from JSON: {:?}", entries.len(), path);
    Ok(entries)
}
