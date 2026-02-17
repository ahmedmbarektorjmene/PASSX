pub mod state;
pub mod auth;
pub mod model;
pub mod icons;
pub mod vault;
pub mod entries;
pub mod search;
pub mod qr_scanner;
pub mod import_export;

use slint::ComponentHandle;
use std::sync::{Arc, Mutex};
use crate::ui::MainWindow;
use self::state::AppState;
use crate::ui::prefs::AppPrefs; 


pub fn run(tpm_available: bool) -> std::result::Result<(), slint::PlatformError> {
    let app = MainWindow::new()?;
    let app_weak = app.as_weak();

    // Load Preferences
    let prefs = AppPrefs::load();
    
    // Apply Window State (if saved)
    // Note: Slint window positioning/sizing might need to be done after window is shown or via specific API if available (current version has basic support)
    // For now we set the window properties if the backend supports it, or use the slint Window API.
    
    // Since Slint 1.8+ validates window implementation:
    let window = app.window();
    window.set_position(slint::PhysicalPosition::new(prefs.window_x, prefs.window_y));
    window.set_size(slint::PhysicalSize::new(prefs.window_width, prefs.window_height));
    
    // Fullscreen/Maximized
    if prefs.is_maximized {
        window.set_maximized(true);
    }
    
    // Propagate TPM status to UI
    app.set_tpm_available(tpm_available);
    
    let mut state_data = AppState::new();
    
    // Restore Last Vault Path if exists
    if let Some(path) = &prefs.last_vault_path {
        if path.exists() {
            state_data.vault_path = Some(path.clone());
            app.set_vault_path(path.to_string_lossy().to_string().into());
            // Navigate to Unlock Screen
            app.set_current_screen(2);
        }
    }

    let state = Arc::new(Mutex::new(state_data));


    // Setup Feature Callbacks
    vault::setup(app_weak.clone(), state.clone());
    entries::setup(app_weak.clone(), state.clone());
    search::setup(app_weak.clone(), state.clone());

    // Update Check (Async)
    let _app_weak_update = app.as_weak();
    std::thread::spawn(move || {
        // Only run update check in RELEASE mode (or if forced)
        if !cfg!(debug_assertions) {
            match crate::update::check_for_updates() {
                Ok(Some(release)) => {
                    let version = release.version;
                    let body = release.body.unwrap_or_default();
                    
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Ok(update_win) = crate::ui::UpdateWindow::new() {
                            update_win.set_new_version(version.into());
                            update_win.set_release_notes(body.into());
                            
                            let update_win_weak = update_win.as_weak();
                            update_win.on_update_now(move || {
                                // Trigger update in background to avoid freezing UI
                                std::thread::spawn(move || {
                                    if let Err(e) = crate::update::update_to_latest() {
                                        eprintln!("Update failed: {}", e);
                                    } else {
                                        // Update successful, restart/exit
                                        std::process::exit(0);
                                    }
                                });
                                // Hide window immediately or show progress? For now hide.
                                let _ = update_win_weak.upgrade().map(|w| w.hide());
                            });
                            
                            let update_win_weak2 = update_win.as_weak();
                            update_win.on_remind_later(move || {
                                let _ = update_win_weak2.upgrade().map(|w| w.hide());
                            });
                            
                            let _ = update_win.show();
                        }
                    });
                }
                Ok(None) => {
                    println!("App is up to date.");
                }
                Err(e) => {
                    eprintln!("Failed to check for updates: {}", e);
                }
            }
        } else {
            println!("Debug mode detected. Skipping update check.");
        }
    });

    // Save State on Close
    let state_for_close = state.clone();
    app.window().on_close_requested(move || {
        let mut final_prefs = AppPrefs::load(); // Reload to get latest (if modified elsewhere, though single instance guards this)
        
        let app_handle = app_weak.unwrap();
        let win = app_handle.window();
        let pos = win.position();
        let size = win.size();
        
        final_prefs.window_x = pos.x;
        final_prefs.window_y = pos.y;
        final_prefs.window_width = size.width;
        final_prefs.window_height = size.height;
        final_prefs.is_maximized = win.is_maximized();
        
        // Save last vault from state
        if let Ok(s) = state_for_close.lock() {
             final_prefs.last_vault_path = s.vault_path.clone();
        }
        
        final_prefs.save();
        
        slint::CloseRequestResponse::HideWindow
    });

    app.run()

}
