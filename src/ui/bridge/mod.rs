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

pub fn run(tpm_available: bool) -> std::result::Result<(), slint::PlatformError> {
    let app = MainWindow::new()?;
    let app_weak = app.as_weak();
    
    // Propagate TPM status to UI
    app.set_tpm_available(tpm_available);
    
    let state = Arc::new(Mutex::new(AppState::new()));

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

    app.run()
}
