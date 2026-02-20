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
    
    // Apply saved theme mode
    app.set_theme_mode(prefs.theme_mode.clone().into());
    
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

    // SECURITY: Prevent Screen Capture (OBS, Discord, Snipping Tool, etc.)
    // WDA_EXCLUDEFROMCAPTURE (0x00000011) makes the window invisible to capture.
    #[cfg(target_os = "windows")]
    {
        let app_weak_security = app_weak.clone();
        std::thread::spawn(move || {
            // Wait for 500ms to ensure the window is mapped by the backend.
            // "NotSupported" error occurs if we try to get the handle before it's mapped.
            std::thread::sleep(std::time::Duration::from_millis(500));
            
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = app_weak_security.upgrade() {
                    let window = app.window();
                    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
                    
                    println!(">>> [SECURITY] Attempting to secure window (delayed)...");
                    
                    // slint::Window::window_handle() returns slint::WindowHandle struct (not Result)
                    let slint_handle = window.window_handle();
                    // Now calling HasWindowHandle::window_handle() on the struct
                    match slint_handle.window_handle() {
                        Ok(handle) => {
                            if let RawWindowHandle::Win32(handle) = handle.as_raw() {
                                 let hwnd_isize = handle.hwnd.get();
                                 let hwnd = windows::Win32::Foundation::HWND(hwnd_isize as *mut std::ffi::c_void);
                                 println!(">>> [SECURITY] Found HWND: {:?} (isize: {})", hwnd, hwnd_isize);
                                 unsafe {
                                     let result = windows::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity(
                                         hwnd,
                                         windows::Win32::UI::WindowsAndMessaging::WDA_EXCLUDEFROMCAPTURE,
                                     );
                                     if result.is_err() {
                                         eprintln!(">>> [SECURITY] Failed to set window display affinity: {:?}", windows::core::Error::from_win32());
                                     } else {
                                         println!(">>> [SECURITY] Successfully set window display affinity (WDA_EXCLUDEFROMCAPTURE).");
                                     }
                                 };
                            } else {
                                eprintln!(">>> [SECURITY] Application is not running on Win32 (unexpected).");
                            }
                        },
                        Err(e) => {
                            eprintln!(">>> [SECURITY] Failed to get window handle (delayed): {:?}", e);
                        }
                    }
                }
            });
        });
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

    // Wire save-theme callback to persist theme mode to config.json
    app.on_save_theme(move |mode| {
        let mode_str: String = mode.into();
        let mut prefs = AppPrefs::load();
        prefs.theme_mode = mode_str;
        prefs.save();
    });

    // Update Check & Auto-Download (Async)
    std::thread::spawn(move || {
        // Only run update check in RELEASE mode
        if !cfg!(debug_assertions) {
            match crate::update::check_for_updates() {
                Ok(Some(release)) => {
                    let version = release.version.clone();
                    println!("Update available: v{}. Downloading automatically...", version);
                    
                    // Auto-download the update in background
                    match crate::update::update_to_latest() {
                        Ok(()) => {
                            println!("Update v{} downloaded successfully.", version);
                            
                            // Show "Restart Required" dialog
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Ok(update_win) = crate::ui::UpdateWindow::new() {
                                    update_win.set_new_version(version.into());
                                    
                                    // "Restart Now" — exit so the updated binary takes effect
                                    update_win.on_restart_now(move || {
                                        std::process::exit(0);
                                    });
                                    
                                    // "Later" — dismiss; update applies on next natural restart
                                    let update_win_weak = update_win.as_weak();
                                    update_win.on_remind_later(move || {
                                        let _ = update_win_weak.upgrade().map(|w| w.hide());
                                    });
                                    
                                    let _ = update_win.show();
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("Auto-update download failed: {}", e);
                        }
                    }
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

        // Save current theme mode
        final_prefs.theme_mode = app_handle.get_theme_mode().to_string();
        
        final_prefs.save();
        
        slint::CloseRequestResponse::HideWindow
    });

    app.run()

}
