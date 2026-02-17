use slint::Weak;
use std::sync::{Arc, Mutex};
use std::thread;
use rfd::FileDialog;
use rand::{Rng, thread_rng};

use crate::ui::MainWindow;
use crate::ui::bridge::state::AppState;
use crate::ui::prefs::AppPrefs; 
use crate::ui::bridge::model::{generate_vault_entries, apply_vault_model};

use crate::vault::{format::{self, Vault, VaultMode}};
use crate::memory::guard::SecureBuffer;

const VAULT_EXTENSION: &str = "vault";

pub fn setup(app_weak: Weak<MainWindow>, state: Arc<Mutex<AppState>>) {
    let app = app_weak.upgrade().unwrap();

    // 1. Browse for New Vault (Save Dialog)
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_browse_for_new_vault(move || {
        let app = app_ref.upgrade().unwrap();
        if let Some(path) = FileDialog::new()
            .add_filter("passx Vault", &[VAULT_EXTENSION])
            .save_file() 
        {
            let mut state = state_copy.lock().unwrap();
            state.vault_path = Some(path.clone());
            app.set_vault_path(path.to_string_lossy().to_string().into());
        }
    });

    // 2. Browse for Existing Vault (Open Dialog)
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_browse_for_existing_vault(move || {
        let app = app_ref.upgrade().unwrap();
        if let Some(path) = FileDialog::new()
            .add_filter("passx Vault", &[VAULT_EXTENSION])
            .pick_file() 
        {
            let mut state = state_copy.lock().unwrap();
            state.vault_path = Some(path.clone());
            app.set_vault_path(path.to_string_lossy().to_string().into());

            app.set_current_screen(2); // Go to Unlock Screen
        }
    });

    // 3. Create New Vault Confirmed
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_create_new_vault_confirmed(move |password_str, mode_int| {
        let app = app_ref.upgrade().unwrap();
        
        // Map UI int to VaultMode
        let mode = match VaultMode::from_u8(mode_int as u8) {
            Some(m) => m,
            None => {
                app.set_error_message("Invalid vault mode selected.".into());
                return;
            }
        };

        if password_str.is_empty() {
             app.set_error_message("Password is required for all vault modes.".into());
             return;
        }

        let state_clone = state_copy.clone();
        let app_weak = app_ref.clone();
        
        thread::spawn(move || {
            let path = {
                let state = state_clone.lock().unwrap();
                match &state.vault_path {
                    Some(p) => p.clone(),
                    None => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = app_weak.upgrade() {
                                app.set_error_message("Please select a location first.".into());
                            }
                        });
                        return;
                    }
                }
            };

            let mut rng = thread_rng();
            let mut key_bytes = [0u8; 32];
            rng.fill(&mut key_bytes);
            
            let master_key = match SecureBuffer::from_slice(&key_bytes) {
                Some(k) => k,
                None => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                             app.set_error_message("Memory allocation failed.".into());
                        }
                    });
                    return;
                }
            };
            
            let vault = Vault {
                mode,
                last_updated: chrono::Utc::now(),
                ..Default::default()
            };

            let pass_bytes = if !password_str.is_empty() { Some(password_str.as_bytes()) } else { None };
            
            if let Err(e) = format::save_vault(&path, &vault, &master_key, mode, pass_bytes) {
                 let err_msg = format!("Failed to save vault: {:?}", e);
                 let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak.upgrade() {
                         app.set_error_message(err_msg.into());
                     }
                 });
                 return;
            }
            
            let password_buf = if let Some(pb) = pass_bytes {
                SecureBuffer::from_slice(pb)
            } else { None };
            
            // Generate entries (empty)
            let entries = generate_vault_entries(&vault, "", "accounts");

            let _ = slint::invoke_from_event_loop(move || {
                 if let Some(app) = app_weak.upgrade() {
                     let mut state = state_clone.lock().unwrap();
                     state.vault = Some(vault);
                     state.key = Some(master_key);
                     state.password = password_buf;
                     state.current_search = "".into();
                     state.current_filter = "accounts".into();
                     
                     // Update Prefs
                     let mut prefs = AppPrefs::load();
                     prefs.last_vault_path = state.vault_path.clone();
                     prefs.save();
                     
                     app.set_error_message("".into());
                     apply_vault_model(&app, entries);
                     app.set_current_screen(3); 
                 }
            });
        });
    });

    // 4. Attempt Unlock
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_attempt_unlock(move |password_str| {
        let _app = app_ref.upgrade().unwrap();
        let state_clone = state_copy.clone();
        let app_weak = app_ref.clone();

        thread::spawn(move || {
            let path = {
                let state = state_clone.lock().unwrap();
                 match &state.vault_path {
                    Some(p) => p.clone(),
                    None => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = app_weak.upgrade() {
                                app.set_current_screen(0);
                            }
                        });
                        return;
                    }
                }
            };

            if !path.exists() {
                 let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = app_weak.upgrade() {
                        app.set_error_message("Vault file not found.".into());
                    }
                 });
                 return;
            }

            let pass_bytes = if !password_str.is_empty() { Some(password_str.as_bytes()) } else { None };
            
            match format::load_vault(&path, pass_bytes) {
                Ok((vault, master_key, _)) => {
                    let password_buf = if let Some(pb) = pass_bytes {
                        SecureBuffer::from_slice(pb)
                    } else { None };

                    let entries = generate_vault_entries(&vault, "", "accounts");

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                            let mut state = state_clone.lock().unwrap();
                            state.vault = Some(vault);
                            state.key = Some(master_key);
                            state.password = password_buf;
                            state.current_search = "".into();
                            state.current_filter = "accounts".into();
                            
                            // Update Prefs
                            let mut prefs = AppPrefs::load();
                            prefs.last_vault_path = state.vault_path.clone();
                            prefs.save();
                            
                            app.set_error_message("".into());
                            apply_vault_model(&app, entries);
                            app.set_current_screen(3);
                        }
                    });
                },
                Err(e) => {
                    let err_msg = format!("Unlock failed: {:?}", e);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                            app.set_error_message(err_msg.into());
                        }
                    });
                }
            }
        });
    });

    // 5. Lock Vault
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_lock_vault(move || {
        let app = app_ref.upgrade().unwrap();
        let mut state = state_copy.lock().unwrap();
        
        state.key = None;
        state.password = None;
        state.vault = None;
        
        app.set_current_screen(2); 
    });

    // 6. Change Master Password
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_change_master_password(move |old_pass, new_pass| {
        let app = app_ref.upgrade().unwrap();
        let state_clone = state_copy.clone();
        
        // 1. Verify Old Password (Fast check)
        {
             let state = state_clone.lock().unwrap();
             if let Some(current_pass_buf) = &state.password {
                 // Compare bytes
                 let current_pass_str = String::from_utf8_lossy(&current_pass_buf[..]); 
                 if old_pass != current_pass_str {
                      app.set_io_status_message("Incorrect current password.".into());
                      // Clear after 3s
                      let app_weak = app_ref.clone();
                      slint::Timer::single_shot(std::time::Duration::from_secs(3), move || {
                          if let Some(app) = app_weak.upgrade() {
                              app.set_io_status_message("".into());
                          }
                      });
                      return;
                 }
             } else {
                 if !old_pass.is_empty() {
                      app.set_io_status_message("No password set or logic error.".into());
                      return;
                 }
             }
        }
        
        // Prepare data for thread
        let app_weak_for_thread = app_ref.clone();
        let new_pass_owned = new_pass.to_string(); // Own the string

        // 2. Perform Save (Blocking)
        thread::spawn(move || {
            let (path, vault, master_key, mode) = {
                let state = state_clone.lock().unwrap();
                if let (Some(p), Some(v), Some(k)) = (&state.vault_path, &state.vault, &state.key) {
                    (p.clone(), v.clone(), k.clone(), v.mode) // Clone everything to process saving
                } else {
                    return;
                }
            };

            let pass_bytes = if !new_pass_owned.is_empty() { Some(new_pass_owned.as_bytes()) } else { None };

            if let Err(e) = format::save_vault(&path, &vault, &master_key, mode, pass_bytes) {
                 let err_msg = format!("Failed to update password: {:?}", e);
                 let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak_for_thread.upgrade() {
                         app.set_io_status_message(err_msg.into());
                     }
                 });
                 return;
            }
            
            // Re-create bytes for state update
            let password_buf_for_state = if !new_pass_owned.is_empty() { 
                SecureBuffer::from_slice(new_pass_owned.as_bytes())
            } else { 
                None 
            };
            
            // 3. Update State
             let _ = slint::invoke_from_event_loop(move || {
                 if let Some(app) = app_weak_for_thread.upgrade() {
                     let mut state = state_clone.lock().unwrap(); // Use the captured state_clone (Arc)
                     state.password = password_buf_for_state;
                     
                     app.set_io_status_message("Master password updated successfully.".into());
                     
                     // Clear message after 3s
                     let app_weak = app_weak_for_thread.clone();
                     slint::Timer::single_shot(std::time::Duration::from_secs(3), move || {
                          if let Some(app) = app_weak.upgrade() {
                              app.set_io_status_message("".into());
                          }
                     });
                 }
             });
        });
    });
}
