
use std::sync::{Arc, Mutex};
use base64::{Engine as _, engine::general_purpose};

use crate::ui::MainWindow;
use crate::ui::bridge::state::AppState;
use crate::ui::bridge::model::{generate_vault_entries, apply_vault_model};
use crate::vault::format;
use crate::memory::guard::SecureBuffer;

pub fn fetch_website_icon(url: String, id: String, app_weak: slint::Weak<MainWindow>, state: Arc<Mutex<AppState>>) {
    let target_url = format!("https://www.google.com/s2/favicons?domain={}&sz=64", url);
    let id_clone = id.clone();
    
    // Note: Request blocking is OK here because we are already in a thread when called from save_entry
    if let Ok(resp) = reqwest::blocking::get(&target_url) {
        if resp.status().is_success() {
             if let Ok(bytes) = resp.bytes() {
                 let b64 = general_purpose::STANDARD.encode(&bytes);
                 
                 // Process update in background thread (mutate + save + generate model)
                 let (entries, success) = {
                     let mut state = state.lock().unwrap();
                     let AppState { vault, key, vault_path, password: state_pass, current_search, current_filter } = &mut *state;
                     
                     if let (Some(vault), Some(key), Some(path)) = (vault, key, vault_path) {
                         if let Some(entry) = vault.accounts.iter_mut().find(|e| e.id == id_clone) {
                              entry.icon_data = Some(b64);
                              entry.updated_at = chrono::Utc::now().timestamp();
                         }
                          vault.sequence_number += 1;
                          
                          let key_copy = SecureBuffer::from_slice(&key[..]);
                          let pass_copy = if let Some(p) = state_pass { SecureBuffer::from_slice(&p[..]) } else { None };
                          
                          // Save
                          if let (Some(key_buf), Some(path)) = (key_copy, Some(path.clone())) {
                              let pass_slice = pass_copy.as_ref().map(|p| &p[..]);
                              let _res = format::save_vault(&path, vault, &key_buf, vault.mode, pass_slice);
                              // We ignore save errors for icon fetch for now to avoid spamming UI?
                              // Or we should log it.
                          }
                          
                          // Generate new model
                          (Some(generate_vault_entries(vault, current_search, current_filter)), true)
                     } else {
                         (None, false)
                     }
                 };

                 if success {
                     let _ = slint::invoke_from_event_loop(move || {
                         if let Some(app) = app_weak.upgrade() {
                             if let Some(e) = entries {
                                 apply_vault_model(&app, e);
                             }
                         }
                     });
                 }
             }
        }
    }
}
