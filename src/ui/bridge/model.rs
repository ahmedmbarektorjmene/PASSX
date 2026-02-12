use slint::{VecModel, Image, SharedPixelBuffer, Rgba8Pixel};
use std::rc::Rc;
use crate::ui::{MainWindow, VaultEntryData};
use crate::vault::format::Vault;
use base64::{Engine as _, engine::general_purpose};
use totp_rs::{TOTP, Algorithm};

// Intermediate struct that is Send/Sync
pub struct VaultEntryModel {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub icon_text: String,
    pub deleted: bool,
    pub folder: String,
    pub icon_data: Option<(Vec<u8>, u32, u32)>, // rgba bytes, width, height
    pub totp_code: String,
    pub has_totp: bool,
    pub entry_type: String, // "account" or "totp"
    pub linked_id: String,  // If valid, points to linked entity
}

// Generate the model data in a background thread
pub fn generate_vault_entries(vault: &Vault, search: &str, filter: &str) -> Vec<VaultEntryModel> {
    let mut models = Vec::new();
    let q = search.to_lowercase();

    // 1. Process Accounts
    if filter == "accounts" || filter == "all" || filter == "trash" || filter == "favorites" {
        for acc in &vault.accounts {
            if filter == "trash" && !acc.deleted { continue; }
            if filter != "trash" && acc.deleted { continue; }
            
            // Search filter
            if !q.is_empty() && !acc.title.to_lowercase().contains(&q) && !acc.username.to_lowercase().contains(&q) {
                continue;
            }

            // Find linked TOTP
            let linked_totp = vault.totps.iter().find(|t| !t.deleted && t.linked_account_id.as_deref() == Some(&acc.id));
            
            let totp_code = if let Some(t) = linked_totp {
                generate_totp_code(&t.secret, Some(acc.title.clone()), acc.username.clone())
            } else {
                String::new()
            };

            let initial = acc.title.chars().next().unwrap_or('?').to_uppercase().to_string();
            let icon_data = decode_icon_data(&acc.icon_data);

            models.push(VaultEntryModel {
                id: acc.id.clone(),
                title: acc.title.clone(),
                username: acc.username.clone(),
                url: acc.url.clone(),
                icon_text: initial,
                deleted: acc.deleted,
                folder: acc.folder.clone().unwrap_or_default(),
                icon_data,
                totp_code,
                has_totp: linked_totp.is_some(),
                entry_type: "account".to_string(),
                linked_id: linked_totp.map(|t| t.id.clone()).unwrap_or_default(),
            });
        }
    }

    // 2. Process TOTPs (Authenticators)
    if filter == "totp" || filter == "all" || filter== "trash" {
        for t in &vault.totps {
            if filter == "trash" && !t.deleted { continue; }
            if filter != "trash" && t.deleted { continue; }

            // Search filter
            if !q.is_empty() && !t.issuer.to_lowercase().contains(&q) && !t.account_name.to_lowercase().contains(&q) {
                continue;
            }

            let code = generate_totp_code(&t.secret, Some(t.issuer.clone()), t.account_name.clone());
            let initial = t.issuer.chars().next().unwrap_or('?').to_uppercase().to_string();
            let icon_data = decode_icon_data(&t.icon_data);

            models.push(VaultEntryModel {
                id: t.id.clone(),
                title: t.issuer.clone(),      // Map Issuer -> Title
                username: t.account_name.clone(), // Map AccountName -> Username
                url: String::new(),
                icon_text: initial,
                deleted: t.deleted,
                folder: String::new(),
                icon_data,
                totp_code: code,
                has_totp: true,
                entry_type: "totp".to_string(),
                linked_id: t.linked_account_id.clone().unwrap_or_default(),
            });
        }
    }

    models
}

pub fn account_to_data(e: &crate::vault::entry::AccountEntry, linked_totp: Option<&crate::vault::entry::TotpEntry>) -> VaultEntryData {
    let initial = e.title.chars().next().unwrap_or('?').to_uppercase().to_string();
    let icon_data = decode_icon_data(&e.icon_data);
    
    let (icon, has_icon) = if let Some((data, w, h)) = icon_data {
        let buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&data, w, h);
        (Image::from_rgba8(buffer), true)
    } else {
        (Image::default(), false)
    };

    let totp_code = if let Some(t) = linked_totp {
        generate_totp_code(&t.secret, Some(e.title.clone()), e.username.clone())
    } else {
        String::new()
    };

    VaultEntryData {
        id: e.id.clone().into(),
        title: e.title.clone().into(),
        username: e.username.clone().into(),
        url: e.url.clone().into(),
        icon_text: initial.into(),
        deleted: e.deleted,
        folder: e.folder.clone().unwrap_or_default().into(),
        icon,
        has_icon,
        totp_code: totp_code.into(),
        has_totp: linked_totp.is_some(),
        entry_type: "account".into(),
    }
}

pub fn totp_to_data(t: &crate::vault::entry::TotpEntry) -> VaultEntryData {
    let initial = t.issuer.chars().next().unwrap_or('?').to_uppercase().to_string();
    let icon_data = decode_icon_data(&t.icon_data);
    
    let (icon, has_icon) = if let Some((data, w, h)) = icon_data {
        let buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&data, w, h);
        (Image::from_rgba8(buffer), true)
    } else {
        (Image::default(), false)
    };

    let code = generate_totp_code(&t.secret, Some(t.issuer.clone()), t.account_name.clone());

    VaultEntryData {
        id: t.id.clone().into(),
        title: t.issuer.clone().into(),
        username: t.account_name.clone().into(), // Map AccountName -> Username field
        url: "".into(),
        icon_text: initial.into(),
        deleted: t.deleted,
        folder: "".into(),
        icon,
        has_icon,
        totp_code: code.into(),
        has_totp: true,
        entry_type: "totp".into(),
    }
}

// Updates the UI model (lightweight, main thread)
pub fn apply_vault_model(app: &MainWindow, entries: Vec<VaultEntryModel>) {
    let ui_entries: Vec<VaultEntryData> = entries.into_iter().map(|e| {
        let (icon, has_icon) = if let Some((data, w, h)) = e.icon_data {
            let buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&data, w, h);
            (Image::from_rgba8(buffer), true)
        } else {
            (Image::default(), false)
        };

        VaultEntryData {
            id: e.id.into(),
            title: e.title.into(),
            username: e.username.into(),
            url: e.url.into(),
            icon_text: e.icon_text.into(),
            deleted: e.deleted,
            folder: e.folder.into(),
            icon,
            has_icon,
            totp_code: e.totp_code.into(),
            has_totp: e.has_totp,
            entry_type: e.entry_type.into(),
        }
    }).collect();

    let model = Rc::new(VecModel::from(ui_entries));
    app.set_vault_entries(model.into());
}

fn decode_icon_data(b64: &Option<String>) -> Option<(Vec<u8>, u32, u32)> {
    if let Some(b64) = b64 {
         match general_purpose::STANDARD.decode(b64) {
            Ok(bytes) => {
                 let img = image::load_from_memory(&bytes).unwrap_or_else(|_| image::DynamicImage::new_rgba8(1,1));
                 let rgba = img.as_rgba8().unwrap();
                 Some((rgba.as_raw().clone(), img.width(), img.height()))
            }
            Err(_) => None
         }
    } else {
        None
    }
}

fn generate_totp_code(secret: &[u8], issuer: Option<String>, account: String) -> String {
    let secret_str = String::from_utf8_lossy(secret).to_string()
        .replace(" ", "")
        .replace("-", "")
        .to_uppercase();
    
    if let Some(decoded) = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret_str) {
        let mut padded = decoded;
        while padded.len() < 20 { padded.push(0); } // Pad for SHA1 compliance
        
        match TOTP::new(Algorithm::SHA1, 6, 1, 30, padded, issuer, account) {
            Ok(totp) => totp.generate_current().unwrap_or_else(|_| "Error".to_string()),
            Err(_) => "Invalid".to_string()
        }
    } else {
        "Bad Secret".to_string()
    }
}
