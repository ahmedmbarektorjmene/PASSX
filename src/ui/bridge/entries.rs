use slint::Weak;
use std::sync::{Arc, Mutex};
use std::thread;
use crate::io::clipboard::copy_to_clipboard;

use crate::ui::{MainWindow, VaultEntryData};
use crate::ui::bridge::state::AppState;
use crate::ui::bridge::auth::authenticate_user;
use crate::ui::bridge::icons::fetch_website_icon;
use crate::ui::bridge::model::{generate_vault_entries, apply_vault_model, account_to_data, totp_to_data};
use crate::vault::{format, VaultMode};
use crate::vault::entry::{AccountEntry, TotpEntry};
use crate::memory::guard::SecureBuffer;

pub fn setup(app_weak: Weak<MainWindow>, state: Arc<Mutex<AppState>>) {
    let app = app_weak.upgrade().unwrap();

    // 6. Copy Password
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_copy_password(move |id| {
        println!("[DEBUG] Copy password requested for ID: {}", id);
        let _app = app_ref.upgrade().unwrap();
        let state_thread = state_copy.clone();
        
        thread::spawn(move || {
            println!("[DEBUG] BG Thread: Starting authentication...");
            if !authenticate_user() { 
                println!("[DEBUG] BG Thread: Authentication cancelled or failed");
                return;
            }
            println!("[DEBUG] BG Thread: Authentication successful");

            let pass_str = {
                let state = state_thread.lock().unwrap();
                if let Some(vault) = &state.vault {
                    // Only accounts have passwords
                    if let Some(entry) = vault.accounts.iter().find(|e| e.id == id.as_str()) {
                         println!("[DEBUG] BG Thread: Account found: {}", entry.title);
                         let pass_bytes = &entry.password[..];
                         Some(String::from_utf8_lossy(pass_bytes).to_string())
                    } else { 
                        println!("[DEBUG] BG Thread: Account NOT found for ID: {}", id);
                        None 
                    }
                } else { 
                    println!("[DEBUG] BG Thread: State has no vault");
                    None 
                }
            };

            if let Some(pass) = pass_str {
                println!("[DEBUG] BG Thread: Invoking UI thread for clipboard...");
                let _ = slint::invoke_from_event_loop(move || {
                     println!("[DEBUG] UI Thread: Accessing clipboard...");
                     if let Err(e) = copy_to_clipboard(&pass, 10) {
                         eprintln!("[ERROR] Clipboard error: {}", e);
                     } else {
                         println!("[DEBUG] UI Thread: Password copied to clipboard (10s secure timeout)");
                     }
                });
            }
        });
    });

    // 6b. Copy Username
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_copy_username(move |id| {
        println!("[DEBUG] Copy username requested for ID: {}", id);
        let _app = app_ref.upgrade().unwrap();
        
        let state = state_copy.lock().unwrap();
        if let Some(vault) = &state.vault {
            let text_to_copy = if let Some(entry) = vault.accounts.iter().find(|e| e.id == id.as_str()) {
                println!("[DEBUG] UI Thread: Account found: {}, copying username...", entry.title);
                Some(entry.username.clone())
            } else if let Some(entry) = vault.totps.iter().find(|e| e.id == id.as_str()) {
                println!("[DEBUG] UI Thread: TOTP found: {}, copying account name...", entry.issuer);
                Some(entry.account_name.clone())
            } else {
                println!("[DEBUG] UI Thread: Entry NOT found for ID: {}", id);
                None
            };

            if let Some(text) = text_to_copy {
                 if let Err(e) = copy_to_clipboard(&text, 10) {
                     eprintln!("[ERROR] Clipboard error: {}", e);
                 } else {
                     println!("[DEBUG] UI Thread: Username/Account copied (10s secure timeout)");
                 }
            }
        } else {
            println!("[DEBUG] UI Thread: Vault not available");
        }
    });

    // 6c. Get Entry Details
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_get_entry_details(move |id| {
        let _app = app_ref.upgrade().unwrap();
        let state = state_copy.lock().unwrap();
        
        if let Some(vault) = &state.vault {
            // 1. Try Account
            if let Some(acc) = vault.accounts.iter().find(|e| e.id == id.as_str()) {
                let linked_totp = vault.totps.iter().find(|t| !t.deleted && t.linked_account_id.as_deref() == Some(&acc.id));
                return account_to_data(acc, linked_totp);
            }
            // 2. Try TOTP
            if let Some(totp) = vault.totps.iter().find(|e| e.id == id.as_str()) {
                return totp_to_data(totp);
            }
        }
        
        // Return empty/default
        VaultEntryData {
             id: "".into(),
             title: "".into(),
             username: "".into(),
             url: "".into(),
             icon_text: "".into(),
             deleted: false,
             folder: "".into(),
             icon: slint::Image::default(),
             has_icon: false,
             totp_code: "".into(),
             has_totp: false,
             entry_type: "account".into(),
        }
    });

    // 7. Save Entry (Account)
    let app_ref = app_weak.clone();
    let state_clone = state.clone();
    app.on_save_entry(move |id, title, username, password, url| {
        let _app = app_ref.upgrade().unwrap();
        let app_weak = app_ref.clone();
        let state_thread = state_clone.clone();

        thread::spawn(move || {
             let (path, key_copy, mode, pass_copy, url_str, id_str) = {
                 let mut state = state_thread.lock().unwrap();
                 let AppState { vault, key, vault_path, password: state_pass, .. } = &mut *state;
                 
                 if let (Some(vault), Some(key), Some(path)) = (vault, key, vault_path) {
                    let id_str = id.as_str();
                    
                    if id_str.is_empty() {
                        // Create Account
                        if let Some(entry) = AccountEntry::new(
                            title.into(), 
                            username.into(), 
                            password.as_bytes(), 
                            if url.len() > 0 { Some(url.clone().into()) } else { None }
                        ) {
                            vault.accounts.push(entry);
                        }
                    } else {
                        // Update Account
                        if let Some(entry) = vault.accounts.iter_mut().find(|e| e.id == id_str) {
                            entry.title = title.into();
                            entry.username = username.into();
                            entry.url = url.clone().into();
                            entry.updated_at = chrono::Utc::now().timestamp();
                            if !password.is_empty() {
                                entry.update_password(password.as_bytes()); 
                            }
                        }
                    }
                    
                    vault.sequence_number += 1;
                    vault.last_updated = chrono::Utc::now();

                    let key_copy = SecureBuffer::from_slice(&key[..]);
                    let pass_copy = if let Some(p) = state_pass { SecureBuffer::from_slice(&p[..]) } else { None };
                    
                    (path.clone(), key_copy, vault.mode, pass_copy, url.to_string(), id.to_string())
                 } else {
                     return;
                 }
             };

             if let Some(key_buf) = key_copy {
                 let pass_slice = pass_copy.as_ref().map(|p| &p[..]);
                 let save_result = {
                     let state = state_thread.lock().unwrap();
                     if let Some(vault) = &state.vault {
                         format::save_vault(&path, vault, &key_buf, mode, pass_slice)
                     } else { Ok(()) }
                 };

                 // Generate new model
                 let entries = {
                     let state = state_thread.lock().unwrap();
                     if let Some(vault) = &state.vault {
                         Some(generate_vault_entries(vault, &state.current_search, &state.current_filter))
                     } else { None }
                 };

                 let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak.upgrade() {
                         match save_result {
                             Ok(_) => {
                                 app.set_error_message("".into());
                                 if let Some(e) = entries {
                                     apply_vault_model(&app, e);
                                 }
                                 
                                 if !url_str.is_empty() {
                                     let state_clone_2 = state_thread.clone();
                                     let app_weak_2 = app_weak.clone();
                                     thread::spawn(move || {
                                         fetch_website_icon(url_str, id_str, app_weak_2, state_clone_2);
                                     });
                                 }
                             },
                             Err(e) => {
                                 app.set_error_message(format!("Failed to save: {:?}", e).into());
                             }
                         }
                     }
                 });
             }
        });
    });

    // 10. Delete Entry
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_delete_entry(move |id| {
        let _app = app_ref.upgrade().unwrap();
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();
        
        thread::spawn(move || {
            let (path, key_copy, mode, pass_copy) = {
                let mut state = state_thread.lock().unwrap();
                let AppState { vault, key, vault_path, password: state_pass, current_filter, .. } = &mut *state;
                
                if let (Some(vault), Some(key), Some(path)) = (vault, key, vault_path) {
                    let id_str = id.as_str();
                    let mut linked_ids_to_delete = Vec::new();
                    
                    // Check matches in Accounts
                    if let Some(entry) = vault.accounts.iter_mut().find(|e| e.id == id_str) {
                         if !entry.deleted { 
                             entry.deleted = true;
                             // Identify linked TOTPs for cascading soft-delete
                             // We scan totps for any that link to this account
                             // We capture this ID to avoid borrowing issues
                             let acc_id = entry.id.clone();
                             linked_ids_to_delete.push(acc_id);
                         }
                         entry.updated_at = chrono::Utc::now().timestamp();
                    }
                    
                    // If we found an account, soft-delete its linked TOTPs
                    if !linked_ids_to_delete.is_empty() {
                         let target_id = &linked_ids_to_delete[0];
                         if let Some(totp) = vault.totps.iter_mut().find(|t| t.linked_account_id.as_ref() == Some(target_id)) {
                             if !totp.deleted { totp.deleted = true; }
                             totp.updated_at = chrono::Utc::now().timestamp();
                         }
                    }

                    // Check matches in TOTPs (if user clicked delete on a TOTP row)
                    if let Some(entry) = vault.totps.iter_mut().find(|e| e.id == id_str) {
                         if !entry.deleted { entry.deleted = true; }
                         entry.updated_at = chrono::Utc::now().timestamp();
                    }

                    // Permanent delete from trash (Cascading)
                    if current_filter == "trash" {
                        // 1. If deleting Account, remove it
                        vault.accounts.retain(|e| e.id != id_str);
                        // 2. Also remove any TOTP linked to it? Or just unlink?
                        // If it's in trash, we assume we want to nuke it.
                        vault.totps.retain(|t| t.linked_account_id.as_deref() != Some(id_str));
                        
                        // 3. If deleting a TOTP directly
                        vault.totps.retain(|e| e.id != id_str);
                    }
                    vault.sequence_number += 1;
                    
                    let key_copy = SecureBuffer::from_slice(&key[..]);
                    let pass_copy = if let Some(p) = state_pass { SecureBuffer::from_slice(&p[..]) } else { None };
                    (Some(path.clone()), key_copy, vault.mode, pass_copy)
                } else {
                    (None, None, VaultMode::DeviceBound, None)
                }
            };

            if let (Some(path), Some(key_buf)) = (path, key_copy) {
                let pass_slice = pass_copy.as_ref().map(|p| &p[..]);
                let _ = {
                    let state = state_thread.lock().unwrap();
                    if let Some(vault) = &state.vault {
                        format::save_vault(&path, vault, &key_buf, mode, pass_slice)
                    } else { Ok(()) }
                };

                let entries = {
                    let state = state_thread.lock().unwrap();
                    if let Some(vault) = &state.vault {
                         Some(generate_vault_entries(vault, &state.current_search, &state.current_filter))
                    } else { None }
                };

                let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak.upgrade() {
                         if let Some(e) = entries {
                             apply_vault_model(&app, e);
                         }
                         // Deselect entry after trashing (close detail panel)
                         app.set_selected_entry_id("".into());
                     }
                });
            }
        });
    });

    // 11. Restore Entry
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_restore_entry(move |id| {
        let _app = app_ref.upgrade().unwrap();
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();
        
        thread::spawn(move || {
            let (path, key_copy, mode, pass_copy) = {
                let mut state = state_thread.lock().unwrap();
                let AppState { vault, key, vault_path, password: state_pass, .. } = &mut *state;
                
                if let (Some(vault), Some(key), Some(path)) = (vault, key, vault_path) {
                    if let Some(entry) = vault.accounts.iter_mut().find(|e| e.id == id.as_str()) {
                        entry.deleted = false;
                        entry.updated_at = chrono::Utc::now().timestamp();
                    } else if let Some(entry) = vault.totps.iter_mut().find(|e| e.id == id.as_str()) {
                        entry.deleted = false;
                        entry.updated_at = chrono::Utc::now().timestamp();
                    }
                    vault.sequence_number += 1;
                    let key_copy = SecureBuffer::from_slice(&key[..]);
                    let pass_copy = if let Some(p) = state_pass { SecureBuffer::from_slice(&p[..]) } else { None };
                    (Some(path.clone()), key_copy, vault.mode, pass_copy)
                } else {
                    (None, None, VaultMode::DeviceBound, None)
                }
            };

            if let (Some(path), Some(key_buf)) = (path, key_copy) {
                let pass_slice = pass_copy.as_ref().map(|p| &p[..]);
                let _ = {
                    let state = state_thread.lock().unwrap();
                    if let Some(vault) = &state.vault {
                        format::save_vault(&path, vault, &key_buf, mode, pass_slice)
                    } else { Ok(()) }
                };

                let entries = {
                    let state = state_thread.lock().unwrap();
                    if let Some(vault) = &state.vault {
                         Some(generate_vault_entries(vault, &state.current_search, &state.current_filter))
                    } else { None }
                };

                let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak.upgrade() {
                         if let Some(e) = entries {
                             apply_vault_model(&app, e);
                         }
                     }
                });
            }
        });
    });

    // 13. Reveal Password
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_reveal_password(move |id| {
        println!("[DEBUG] Reveal password requested for ID: {}", id);
        let _app = app_ref.upgrade().unwrap();
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();

        thread::spawn(move || {
            if !authenticate_user() { return; }

            let pass_str = {
                let state = state_thread.lock().unwrap();
                if let Some(vault) = &state.vault {
                    if let Some(entry) = vault.accounts.iter().find(|e| e.id == id.as_str()) {
                         let pass_bytes = &entry.password[..];
                         Some(String::from_utf8_lossy(pass_bytes).to_string())
                    } else { None }
                } else { None }
            };

            if let Some(pass) = pass_str {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = app_weak.upgrade() {
                        app.set_revealed_password(pass.into());
                        app.set_is_password_revealed(true);
                        println!("[DEBUG] UI Thread: Password revealed");
                    }
                });
            }
        });
    });

    // 12. Select Entry
    let app_ref = app_weak.clone();
    app.on_select_entry(move |id| {
        if let Some(app) = app_ref.upgrade() {
            app.set_selected_entry_id(id);
        }
    });

    // 14. Save TOTP
    let app_ref = app_weak.clone();
    let state_clone = state.clone();
    app.on_save_totp(move |id, account, secret, issuer| {
        let app_weak = app_ref.clone();
        let state_thread = state_clone.clone();

        thread::spawn(move || {
             let (path, key_copy, mode, pass_copy, entries) = {
                 let mut state = state_thread.lock().unwrap();
                 
                 // Extract search/filter before pattern matching mutably
                 let search = state.current_search.clone();
                 let filter = state.current_filter.clone();
                 
                 let AppState { vault, key, vault_path, password: state_pass, .. } = &mut *state;
                 
                 if let (Some(vault), Some(key), Some(path)) = (vault, key, vault_path) {
                    let id_str = id.as_str();
                    let sec_clean = secret.as_str().replace(" ", "").replace("-", "").to_uppercase();
                    let account_name: String = account.into();
                    let issuer_name: String = issuer.into();

                    println!("DEBUG: saving TOTP with ID: '{}', Secret: '{}', Clean: '{}'", id_str, secret.as_str(), sec_clean);
                    
                    if id_str.is_empty() {
                        // Create New TOTP
                        println!("DEBUG: creating NEW TOTP entry");
                        
                        // Attempt Automatic Linking: proper relational linking requires a valid Account ID
                        // Strategy: Look for an ACTIVE account where title == issuer AND username == account_name
                        // This allows "Smart Linking" when the user adds a TOTP that matches an account.
                        let linked_id = vault.accounts.iter()
                            .find(|a| !a.deleted && a.title == issuer_name && a.username == account_name)
                            .map(|a| a.id.clone());

                        if let Some(entry) = TotpEntry::new(
                            issuer_name,
                            account_name,
                            sec_clean.as_bytes(),
                            linked_id // Smart Link
                        ) {
                            vault.totps.push(entry);
                        }
                    } else {
                        // Edit Existing TOTP
                        println!("DEBUG: editing EXISTING TOTP entry");
                        if let Some(entry) = vault.totps.iter_mut().find(|e| e.id == id_str) {
                            println!("DEBUG: entry found, updating fields");
                            entry.issuer = issuer_name.clone();
                            entry.account_name = account_name.clone();
                            if let Some(buf) = SecureBuffer::from_slice(sec_clean.as_bytes()) {
                                entry.secret = buf;
                            }
                            
                            // Re-evaluate link if it was broken or if names changed? 
                            // For v1, let's keep existing link if set, OR try to link if None.
                            if entry.linked_account_id.is_none() {
                                 entry.linked_account_id = vault.accounts.iter()
                                    .find(|a| !a.deleted && a.title == issuer_name && a.username == account_name)
                                    .map(|a| a.id.clone());
                            }
                            
                            entry.updated_at = chrono::Utc::now().timestamp();
                        } else {
                             println!("DEBUG: entry NOT found for ID: {}", id_str);
                        }
                    }
                    
                    vault.sequence_number += 1;
                    vault.last_updated = chrono::Utc::now();

                    let key_copy = SecureBuffer::from_slice(&key[..]);
                    let pass_copy = if let Some(p) = state_pass { SecureBuffer::from_slice(&p[..]) } else { None };
                    
                    let entries = generate_vault_entries(vault, &search, &filter);
                    (path.clone(), key_copy, vault.mode, pass_copy, entries)
                 } else { return; }
             };

             // Save to disk
             if let Some(key_buf) = key_copy {
                 let state = state_thread.lock().unwrap();
                 if let Some(vault) = &state.vault {
                     let _ = format::save_vault(&path, vault, &key_buf, mode, pass_copy.as_ref().map(|b| &b[..]));
                 }
             }

             // Refresh UI
             let _ = slint::invoke_from_event_loop(move || {
                  if let Some(app) = app_weak.upgrade() {
                      apply_vault_model(&app, entries);
                      app.set_current_screen(3); // Go back to main
                  }
             });
        });
    });

    // 15. Periodic Refresh (TOTP codes & progress)
    let app_refresh = app_weak.clone();
    let state_refresh = state.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(std::time::Duration::from_millis(1000));
            
            let now = chrono::Utc::now().timestamp();
            let progress = (30.0 - (now % 30) as f32) / 30.0;

            let entries = {
                let state = state_refresh.lock().unwrap();
                if let Some(vault) = &state.vault {
                    Some(generate_vault_entries(vault, &state.current_search, &state.current_filter))
                } else { None }
            };

            let app_weak = app_refresh.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                    app.set_totp_progress(progress);
                    if let Some(e) = entries {
                        apply_vault_model(&app, e);
                    }
                }
            });
        }
    });

    // 16. Generate Password
    app.on_generate_password(move |len, u, l, n, s| {
        use rand::{thread_rng, Rng};

        let mut charset = String::new();
        if u { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
        if l { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
        if n { charset.push_str("0123456789"); }
        if s { charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?"); }

        if charset.is_empty() { charset.push_str("abcdefghijklmnopqrstuvwxyz0123456789"); }

        let mut rng = thread_rng();
        let password: String = (0..len as usize)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset.chars().nth(idx).unwrap()
            })
            .collect();

        password.into()
    });

    // 17. Copy to Clipboard
    app.on_copy_to_clipboard(move |text| {
        // Secure copy for TOTP, Generator, URLs etc.
        if let Err(e) = copy_to_clipboard(text.as_str(), 10) {
            eprintln!("[ERROR] Clipboard error: {}", e);
        }
    });

    // 18. Get Entry Details (Sync)
    let state_copy = state.clone();
    app.on_get_entry_details(move |id| {
        let state = state_copy.lock().unwrap();
        if let Some(vault) = &state.vault {
            let id_str = id.as_str();
             if let Some(entry) = vault.accounts.iter().find(|e| e.id == id_str) {
                 // Find linked TOTP if any
                 let linked = vault.totps.iter().find(|t| t.linked_account_id.as_deref() == Some(id_str));
                 return account_to_data(entry, linked);
             } else if let Some(entry) = vault.totps.iter().find(|e| e.id == id_str) {
                 return totp_to_data(entry);
             }
        }
        VaultEntryData::default() 
    });

    // 19-21. QR Scanning (No changes needed except imports implicitly, logic refers to qr_scanner module)
    // 19. Scan QR from Screen
    let app_ref = app_weak.clone();
    app.on_scan_qr_from_screen(move || {
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            let result = super::qr_scanner::scan_qr_from_screen();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                    match result {
                        Ok(qr) => {
                            app.set_qr_scan_error("".into());
                            app.set_qr_scanned_account(qr.account.into());
                            app.set_qr_scanned_secret(qr.secret.into());
                            app.set_qr_scanned_issuer(qr.issuer.into());
                        }
                        Err(e) => {
                            app.set_qr_scan_error(e.into());
                            app.set_qr_scanned_account("".into());
                            app.set_qr_scanned_secret("".into());
                            app.set_qr_scanned_issuer("".into());
                        }
                    }
                }
            });
        });
    });

    // 20. Scan QR from Clipboard
    let app_ref = app_weak.clone();
    app.on_scan_qr_from_clipboard(move || {
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            let result = super::qr_scanner::scan_qr_from_clipboard();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                    match result {
                        Ok(qr) => {
                            app.set_qr_scan_error("".into());
                            app.set_qr_scanned_account(qr.account.into());
                            app.set_qr_scanned_secret(qr.secret.into());
                            app.set_qr_scanned_issuer(qr.issuer.into());
                        }
                        Err(e) => {
                            app.set_qr_scan_error(e.into());
                            app.set_qr_scanned_account("".into());
                            app.set_qr_scanned_secret("".into());
                            app.set_qr_scanned_issuer("".into());
                        }
                    }
                }
            });
        });
    });

    // 21. Scan QR from File
    let app_ref = app_weak.clone();
    app.on_scan_qr_from_file(move || {
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            let result = super::qr_scanner::scan_qr_from_file();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                    match result {
                        Ok(qr) => {
                            app.set_qr_scan_error("".into());
                            app.set_qr_scanned_account(qr.account.into());
                            app.set_qr_scanned_secret(qr.secret.into());
                            app.set_qr_scanned_issuer(qr.issuer.into());
                        }
                        Err(e) => {
                            app.set_qr_scan_error(e.into());
                            app.set_qr_scanned_account("".into());
                            app.set_qr_scanned_secret("".into());
                            app.set_qr_scanned_issuer("".into());
                        }
                    }
                }
            });
        });
    });

    // ─── Helper: shared import logic ───
    fn do_import_accounts(
        state_thread: Arc<Mutex<AppState>>,
        app_weak: Weak<MainWindow>,
        new_entries: Vec<AccountEntry>,
    ) {
        let (save_data, added_count) = {
            let mut state = state_thread.lock().unwrap();
            let path = state.vault_path.clone().unwrap();
            let key_copy = state.key.as_ref().and_then(|k| SecureBuffer::from_slice(&k[..]));
            let pass_copy = state.password.as_ref().and_then(|p| SecureBuffer::from_slice(&p[..]));

            if let Some(vault) = &mut state.vault {
                let mut added = 0usize;
                for entry in new_entries {
                    let duplicate = vault.accounts.iter().any(|existing| {
                        existing.title == entry.title && existing.username == entry.username && !existing.deleted
                    });
                    if !duplicate {
                        vault.accounts.push(entry);
                        added += 1;
                    }
                }
                let mode = vault.mode;
                vault.sequence_number += 1;
                (Some((path, key_copy, mode, pass_copy)), added)
            } else {
                (None, 0)
            }
        };
        finish_import(state_thread, app_weak, save_data, added_count, "passwords");
    }

    fn do_import_totps(
        state_thread: Arc<Mutex<AppState>>,
        app_weak: Weak<MainWindow>,
        new_entries: Vec<TotpEntry>,
    ) {
        let (save_data, added_count) = {
            let mut state = state_thread.lock().unwrap();
            let path = state.vault_path.clone().unwrap();
            let key_copy = state.key.as_ref().and_then(|k| SecureBuffer::from_slice(&k[..]));
            let pass_copy = state.password.as_ref().and_then(|p| SecureBuffer::from_slice(&p[..]));

            if let Some(vault) = &mut state.vault {
                let mut added = 0usize;
                for entry in new_entries {
                    let duplicate = vault.totps.iter().any(|existing| {
                        existing.issuer == entry.issuer && existing.account_name == entry.account_name && !existing.deleted
                    });
                    if !duplicate {
                        vault.totps.push(entry);
                        added += 1;
                    }
                }
                let mode = vault.mode;
                vault.sequence_number += 1;
                (Some((path, key_copy, mode, pass_copy)), added)
            } else {
                (None, 0)
            }
        };
        finish_import(state_thread, app_weak, save_data, added_count, "authenticators");
    }

    fn finish_import(
        state_thread: Arc<Mutex<AppState>>,
        app_weak: Weak<MainWindow>,
        save_data: Option<(std::path::PathBuf, Option<SecureBuffer>, VaultMode, Option<SecureBuffer>)>,
        added_count: usize,
        label: &'static str,
    ) {
        if let Some((path, key_copy, mode, pass_copy)) = save_data {
            if let Some(key_buf) = key_copy {
                let pass_slice = pass_copy.as_ref().map(|p| &p[..]);
                let save_result = {
                    let state = state_thread.lock().unwrap();
                    if let Some(vault) = &state.vault {
                        format::save_vault(&path, vault, &key_buf, mode, pass_slice)
                    } else { Ok(()) }
                };
                let entries = {
                    let state = state_thread.lock().unwrap();
                    if let Some(vault) = &state.vault {
                        Some(generate_vault_entries(vault, &state.current_search, &state.current_filter))
                    } else { None }
                };

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = app_weak.upgrade() {
                        match save_result {
                            Ok(_) => {
                                if let Some(e) = entries { apply_vault_model(&app, e); }
                                app.set_io_status_message(
                                    format!("Imported {} new {}", added_count, label).into(),
                                );
                            }
                            Err(_) => {
                                app.set_io_status_message("Import OK but failed to save vault".to_string().into());
                            }
                        }
                    }
                });
            }
        }
    }

    // 22. Export Passwords
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_export_passwords(move || {
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            if !authenticate_user() { return; }
            let file = rfd::FileDialog::new()
                .set_title("Export Passwords")
                .add_filter("CSV File", &["csv"])
                .add_filter("JSON File", &["json"])
                .save_file();
            let path = match file { Some(p) => p, None => return };
            let result = {
                let state = state_thread.lock().unwrap();
                if let Some(vault) = &state.vault {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("csv");
                    match ext {
                        "json" => super::import_export::export_accounts_json(&vault.accounts, &path),
                        _ => super::import_export::export_accounts_csv(&vault.accounts, &path),
                    }
                } else { Err("No vault loaded".into()) }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                    match result {
                        Ok(count) => app.set_io_status_message(format!("Exported {} accounts", count).into()),
                        Err(e) => app.set_io_status_message(format!("Export failed: {}", e).into()),
                    }
                }
            });
        });
    });

    // 23. Export TOTPs
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_export_totps(move || {
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            if !authenticate_user() { return; }
            let file = rfd::FileDialog::new()
                .set_title("Export Authenticators")
                .add_filter("CSV File", &["csv"])
                .add_filter("JSON File", &["json"])
                .save_file();
            let path = match file { Some(p) => p, None => return };
            let result = {
                let state = state_thread.lock().unwrap();
                if let Some(vault) = &state.vault {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("csv");
                    match ext {
                        "json" => super::import_export::export_totps_json(&vault.totps, &path),
                        _ => super::import_export::export_totps_csv(&vault.totps, &path),
                    }
                } else { Err("No vault loaded".into()) }
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                    match result {
                        Ok(count) => app.set_io_status_message(format!("Exported {} authenticators", count).into()),
                        Err(e) => app.set_io_status_message(format!("Export failed: {}", e).into()),
                    }
                }
            });
        });
    });

    // 24. Import Passwords
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_import_passwords(move || {
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            let file = rfd::FileDialog::new()
                .set_title("Import Passwords")
                .add_filter("Supported Files", &["csv", "json"])
                .pick_file();
            let path = match file { Some(p) => p, None => return };
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("csv");
            let result = match ext {
                "json" => super::import_export::import_accounts_json(&path),
                _ => super::import_export::import_accounts_csv(&path),
            };
            match result {
                Ok(entries) => do_import_accounts(state_thread, app_weak, entries),
                Err(e) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                            app.set_io_status_message(format!("Import failed: {}", e).into());
                        }
                    });
                }
            }
        });
    });

    // 25. Import TOTPs
    let state_copy = state.clone();
    let app_ref = app_weak.clone();
    app.on_import_totps(move || {
        let state_thread = state_copy.clone();
        let app_weak = app_ref.clone();
        thread::spawn(move || {
            let file = rfd::FileDialog::new()
                .set_title("Import Authenticators")
                .add_filter("Supported Files", &["csv", "json"])
                .pick_file();
            let path = match file { Some(p) => p, None => return };
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("csv");
            let result = match ext {
                "json" => super::import_export::import_totps_json(&path),
                _ => super::import_export::import_totps_csv(&path),
            };
            match result {
                Ok(entries) => do_import_totps(state_thread, app_weak, entries),
                Err(e) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                            app.set_io_status_message(format!("Import failed: {}", e).into());
                        }
                    });
                }
            }
        });
    });
}
