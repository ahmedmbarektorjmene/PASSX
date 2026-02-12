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

    app.run()
}
