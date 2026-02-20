use slint::Weak;
use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use rfd::FileDialog;
use rand::{Rng, thread_rng};

use crate::ui::MainWindow;
use crate::ui::bridge::state::AppState;
use crate::ui::prefs::AppPrefs; 
use crate::ui::bridge::model::{generate_vault_entries, apply_vault_model};

use crate::vault::{format::{self, Vault, VaultMode}, manager, mirror, file_lock};
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

            // Exclusive Open
            let mut file = match file_lock::open_exclusive(&path) {
                Ok(f) => f,
                Err(e) => {
                     let err_msg = format!("Failed to open vault exclusively (is it open elsewhere?): {}", e);
                     let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                            app.set_error_message(err_msg.into());
                        }
                     });
                     return;
                }
            };

            let pass_bytes = if !password_str.is_empty() { Some(password_str.as_bytes()) } else { None };
            
            match format::load_vault_from_reader(&mut file, pass_bytes) {
                Ok((vault, master_key, _)) => {
                    let password_buf = if let Some(pb) = pass_bytes {
                        SecureBuffer::from_slice(pb)
                    } else { None };

                    let entries = generate_vault_entries(&vault, "", "accounts");

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                            let mut state = state_clone.lock().unwrap();
                            state.vault = Some(vault.clone());
                            state.key = Some(master_key);
                            state.password = password_buf;
                            state.current_search = "".into();
                            state.current_filter = "accounts".into();
                            state.vault_file = Some(file); // Store handle
                            
                            // Update Prefs
                            let mut prefs = AppPrefs::load();
                            prefs.last_vault_path = state.vault_path.clone();
                            prefs.save();
                            
                            app.set_error_message("".into());
                            
                            // Set Mirrors
                            let model = std::rc::Rc::new(slint::VecModel::from(
                                vault.mirrors.iter().map(|s| s.into()).collect::<Vec<slint::SharedString>>()
                            ));
                            app.set_vault_mirrors(model.into());

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
        state.vault_file = None; // Drop handle, releasing lock
        
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
            let (mut file_opt, vault, master_key, mode, path_buf) = {
                let mut state = state_clone.lock().unwrap();
                if state.vault.is_some() && state.key.is_some() {
                     let v = state.vault.clone().unwrap();
                     let k = state.key.clone().unwrap();
                     let mode = v.mode;
                     (state.vault_file.take(), v, k, mode, state.vault_path.clone())
                } else {
                    return;
                }
            };

            let pass_bytes = if !new_pass_owned.is_empty() { Some(new_pass_owned.as_bytes()) } else { None };

            let res: Result<(), String> = if let Some(file) = file_opt.as_mut() {
                 if let Err(e) = file.seek(SeekFrom::Start(0)) {
                     Err(format!("Seek failed: {}", e))
                 } else if let Err(e) = file.set_len(0) {
                      Err(format!("Truncate failed: {}", e))
                 } else {
                      match format::save_vault_to_writer(file, &vault, &master_key, mode, pass_bytes) {
                          Ok(_) => Ok(()),
                          Err(e) => Err(format!("{:?}", e))
                      }
                 }
            } else if let Some(path) = path_buf {
                 match format::save_vault(&path, &vault, &master_key, mode, pass_bytes) {
                     Ok(_) => Ok(()),
                     Err(e) => Err(format!("{:?}", e))
                 }
            } else {
                Err("No file handle or path.".to_string())
            };

            if let Err(e) = res {
                 let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak_for_thread.upgrade() {
                         let mut state = state_clone.lock().unwrap();
                         if let Some(f) = file_opt { state.vault_file = Some(f); } // Return file
                         app.set_io_status_message(format!("Failed to update password: {}", e).into());
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
                     let mut state = state_clone.lock().unwrap(); 
                     // Only restore file if vault is still open
                     if state.vault.is_some() {
                         if let Some(f) = file_opt { state.vault_file = Some(f); } 
                     } else {
                         // Vault locked, drop file (auto-close)
                     }
                     
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

    // ─── Managed Vaults Logic ───
    
    // 7. Refresh Managed Vaults
    let app_ref = app_weak.clone();
    app.on_refresh_managed_vaults(move || {
        let app = app_ref.upgrade().unwrap();
        let vaults = manager::list_managed_vaults();
        let model = std::rc::Rc::new(slint::VecModel::from(
            vaults.into_iter().map(|s| s.into()).collect::<Vec<slint::SharedString>>()
        ));
        app.set_managed_vaults(model.into());
    });

    // 8. Open Managed Vault
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_open_managed_vault(move |name| {
        let app = app_ref.upgrade().unwrap();
        let path = manager::get_vault_path(name.as_str());
        
        let mut state = state_copy.lock().unwrap();
        state.vault_path = Some(path.clone());
        app.set_vault_path(path.to_string_lossy().to_string().into());
        app.set_current_screen(2); // Unlock
    });

    // 9. Delete Managed Vault
    let app_ref = app_weak.clone();
    app.on_delete_managed_vault(move |name| {
        let app = app_ref.upgrade().unwrap();
        if let Err(e) = manager::delete_managed_vault(name.as_str()) {
             // Maybe show error? 
             println!("Failed to delete vault: {:?}", e); // Todo: UI Error
        }
        // Refresh list
        let vaults = manager::list_managed_vaults();
        let model = std::rc::Rc::new(slint::VecModel::from(
            vaults.into_iter().map(|s| s.into()).collect::<Vec<slint::SharedString>>()
        ));
        app.set_managed_vaults(model.into());
    });

    // ─── Mirroring Logic ───

    // 10. Add Mirror
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_add_mirror(move || {
        let _app = app_ref.upgrade().unwrap();
        if let Some(path) = FileDialog::new().pick_folder() {
             let path_str = path.to_string_lossy().to_string();
             
             let state_clone = state_copy.clone();
             let app_weak = app_ref.clone(); // Weak for thread
             
             thread::spawn(move || {
                 // Take resources
                 let (mut vault, mut file_opt, master_key, mode, password_opt, path_buf) = {
                     let mut state = state_clone.lock().unwrap();
                     if state.vault.is_some() && state.key.is_some() {
                         let v = state.vault.clone().unwrap();
                         let k = state.key.clone().unwrap();
                         let mode = v.mode;
                         (
                             v,
                             state.vault_file.take(), // Take file handle
                             k,
                             mode,
                             state.password.clone(),
                             state.vault_path.clone()
                         )
                     } else {
                         return; 
                     }
                 };

                 // Update vault
                 vault.mirrors.push(path_str.clone());
                 let pass_slice = password_opt.as_ref().map(|sb| &sb[..]);

                 let res: Result<(), String> = if let Some(file) = file_opt.as_mut() {
                     // Write to handle
                     if let Err(e) = file.seek(SeekFrom::Start(0)) {
                         Err(format!("Seek failed: {}", e))
                     } else if let Err(e) = file.set_len(0) {
                          Err(format!("Truncate failed: {}", e))
                     } else {
                          // use save_vault_to_writer
                           match format::save_vault_to_writer(file, &vault, &master_key, mode, pass_slice) {
                               Ok(_) => Ok(()),
                               Err(e) => Err(format!("{:?}", e)) // Convert VaultError
                           }
                     }
                 } else if let Some(p) = path_buf {
                     // Fallback to path
                     match format::save_vault(&p, &vault, &master_key, mode, pass_slice) {
                          Ok(_) => Ok(()),
                          Err(e) => Err(format!("{:?}", e))
                     }
                 } else {
                     Err("No file handle or path available.".to_string())
                 };
                 
                 // Return resources and update UI
                 let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak.upgrade() {
                         let mut state = state_clone.lock().unwrap();
                         
                         // Put file back if we took it AND vault is still open
                         if state.vault.is_some() {
                             if let Some(f) = file_opt {
                                 state.vault_file = Some(f);
                             }
                         }
                         
                         if let Err(e) = res {
                             app.set_io_status_message(format!("Failed to add mirror: {}", e).into());
                         } else {
                             // Success, update state vault
                             state.vault = Some(vault.clone());
                             
                             // Refresh mirrors in UI
                             let model = std::rc::Rc::new(slint::VecModel::from(
                                 vault.mirrors.iter().map(|s| s.into()).collect::<Vec<slint::SharedString>>()
                             ));
                             app.set_vault_mirrors(model.into());
                         }
                     }
                 });
             });
        }
    });

    // 11. Remove Mirror
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_remove_mirror(move |index| {
        let app_weak = app_ref.clone();
        let state_clone = state_copy.clone();
        
        thread::spawn(move || {
            // Take resources
             let (mut vault, mut file_opt, master_key, mode, password_opt, path_buf) = {
                 let mut state = state_clone.lock().unwrap();
                 if state.vault.is_some() && state.key.is_some() {
                     let v = state.vault.clone().unwrap();
                     let k = state.key.clone().unwrap();
                     let mode = v.mode;
                     (
                         v,
                         state.vault_file.take(),
                         k,
                         mode,
                         state.password.clone(),
                         state.vault_path.clone()
                     )
                 } else {
                     return; 
                 }
             };

            if index >= 0 && (index as usize) < vault.mirrors.len() {
                vault.mirrors.remove(index as usize);
            } else {
                // Return early, put file back?
                // Actually simpler to just proceed or return. 
                // Let's just return file.
                 let _ = slint::invoke_from_event_loop(move || {
                     let mut state = state_clone.lock().unwrap();
                     if state.vault.is_some() {
                         if let Some(f) = file_opt { state.vault_file = Some(f); }
                     }
                 });
                return;
            }

             let pass_slice = password_opt.as_ref().map(|sb| &sb[..]);

              let res: Result<(), String> = if let Some(file) = file_opt.as_mut() {
                  if let Err(e) = file.seek(SeekFrom::Start(0)) {
                      Err(format!("Seek failed: {}", e))
                  } else if let Err(e) = file.set_len(0) {
                       Err(format!("Truncate failed: {}", e))
                  } else {
                        match format::save_vault_to_writer(file, &vault, &master_key, mode, pass_slice) {
                            Ok(_) => Ok(()),
                            Err(e) => Err(format!("{:?}", e)) 
                        }
                  }
              } else if let Some(p) = path_buf {
                  match format::save_vault(&p, &vault, &master_key, mode, pass_slice) {
                       Ok(_) => Ok(()),
                       Err(e) => Err(format!("{:?}", e))
                  }
              } else {
                  Err("No file handle or path.".to_string())
              };

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak.upgrade() {
                     let mut state = state_clone.lock().unwrap();
                     if state.vault.is_some() {
                         if let Some(f) = file_opt { state.vault_file = Some(f); }
                     }

                     if let Err(e) = res {
                         app.set_io_status_message(format!("Failed to remove mirror: {}", e).into());
                     } else {
                         state.vault = Some(vault.clone());
                         let model = std::rc::Rc::new(slint::VecModel::from(
                             vault.mirrors.iter().map(|s| s.into()).collect::<Vec<slint::SharedString>>()
                         ));
                         app.set_vault_mirrors(model.into());
                     }
                }
            });
        });
    });

    // 12. Sync Mirrors
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_sync_mirrors(move || {
        let app_weak = app_ref.clone();
        let state_clone = state_copy.clone();
        
        thread::spawn(move || {
             // Take file handle
             let (mut file_opt, mirrors, path_buf) = {
                 let mut state = state_clone.lock().unwrap();
                 let mirrors = if let Some(vault) = &state.vault {
                     Some(vault.mirrors.clone())
                 } else {
                     None
                 };

                 if let Some(mirrors) = mirrors {
                     (state.vault_file.take(), mirrors, state.vault_path.clone())
                 } else {
                     return;
                 }
             };
             
             let results = if let Some(mut file) = file_opt.as_mut() {
                 mirror::sync_mirrors_from_file(&mut file, &mirrors)
             } else if let Some(path) = path_buf {
                 mirror::sync_mirrors(&path, &mirrors)
             } else {
                 vec![] // Should not happen
             };
             
             // Restore handle
             let _ = slint::invoke_from_event_loop(move || {
                 if let Some(app) = app_weak.upgrade() {
                     let mut state = state_clone.lock().unwrap();
                     if state.vault.is_some() {
                         if let Some(f) = file_opt { state.vault_file = Some(f); }
                     }

                     // Summarize results
                     let mut success_count = 0;
                     let mut fail_count = 0;
                     for (_, res) in &results {
                         if res.is_ok() { success_count += 1; } else { fail_count += 1; }
                     }
                     
                     let msg = if fail_count == 0 {
                         format!("Synced to {} mirrors.", success_count)
                     } else {
                         format!("Synced: {}, Failed: {}.", success_count, fail_count)
                     };
                     
                     app.set_io_status_message(msg.into());
                     
                     // Clear after 5s
                     let app_weak = app_weak.clone(); // Re-clone for timer
                     slint::Timer::single_shot(std::time::Duration::from_secs(5), move || {
                         if let Some(app) = app_weak.upgrade() {
                            app.set_io_status_message("".into());
                         }
                     });
                 }
             });
        });
    });
    // 13. Create Managed Vault
    let app_ref = app_weak.clone();
    let state_copy = state.clone();
    app.on_create_managed_vault(move |name, password_str, mode_int| {
        let app = app_ref.upgrade().unwrap();
        
        let mode = match VaultMode::from_u8(mode_int as u8) {
            Some(m) => m,
            None => {
                app.set_io_status_message("Invalid vault mode.".into()); // Todo: generic error
                return;
            }
        };

        // Thread handling
        let state_clone = state_copy.clone();
        let app_weak = app_ref.clone();
        let name_owned = name.to_string();
        let password_owned = password_str.to_string();

        thread::spawn(move || {
            // Master Key Gen
            let mut rng = thread_rng();
            let mut key_bytes = [0u8; 32];
            rng.fill(&mut key_bytes);
            let master_key = SecureBuffer::from_slice(&key_bytes).unwrap();
            
            let pass_bytes = if !password_owned.is_empty() { Some(password_owned.as_bytes()) } else { None };

            // Create Managed
            match manager::create_managed_vault(&name_owned, pass_bytes, mode, &master_key) {
                Ok((vault, file, path)) => {
                    // Success!
                    // We have open file handle `file` (exclusive).
                    // We need to keep it open in state.
                    
                    let password_buf = if let Some(pb) = pass_bytes { SecureBuffer::from_slice(pb) } else { None };

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = app_weak.upgrade() {
                             let mut state = state_clone.lock().unwrap();
                             state.vault = Some(vault.clone());
                             state.key = Some(master_key);
                             state.password = password_buf;
                             state.vault_path = Some(path.clone());
                             
                             // Store file handle
                             state.vault_file = Some(file);

                             // Update Prefs
                             let mut prefs = AppPrefs::load();
                             prefs.last_vault_path = Some(path);
                             prefs.save();
                             
                             // Set Mirrors (empty)
                             let model = std::rc::Rc::new(slint::VecModel::from(vec![]));
                             app.set_vault_mirrors(model.into());

                             // Generate entries
                             let entries = generate_vault_entries(&vault, "", "accounts");
                             apply_vault_model(&app, entries);
                             
                             app.set_current_screen(3); // Go to main

                             // Refresh list for next time (or in case we go back)
                             let vaults = manager::list_managed_vaults();
                             let model = std::rc::Rc::new(slint::VecModel::from(
                                 vaults.into_iter().map(|s| s.into()).collect::<Vec<slint::SharedString>>()
                             ));
                             app.set_managed_vaults(model.into());
                        }
                    });
                },
                Err(e) => {
                     let _ = slint::invoke_from_event_loop(move || {
                         if let Some(app) = app_weak.upgrade() {
                             app.set_io_status_message(format!("Creation failed: {}", e).into());
                              // Clear after 3s
                             slint::Timer::single_shot(std::time::Duration::from_secs(3), move || {
                                 app.set_io_status_message("".into());
                             });
                         }
                     });
                }
            }
        });
    });
}
