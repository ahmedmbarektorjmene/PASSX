use slint::Weak;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::ui::MainWindow;
use crate::ui::bridge::state::AppState;
use crate::ui::bridge::model::{generate_vault_entries, apply_vault_model};

pub fn setup(app_weak: Weak<MainWindow>, state: Arc<Mutex<AppState>>) {
    let app = app_weak.upgrade().unwrap();

    let state_copy = state.clone();
    let app_ref = app_weak.clone();

    app.on_perform_search(move |query, filter| {
        let _app = app_ref.upgrade().unwrap();
        let app_weak = app_ref.clone();
        let state_thread = state_copy.clone();
        
        thread::spawn(move || {
            let entries = {
                let mut state = state_thread.lock().unwrap();
                state.current_search = query.into();
                state.current_filter = filter.into();
                
                if let Some(vault) = &state.vault {
                    Some(generate_vault_entries(vault, &state.current_search, &state.current_filter))
                } else { None }
            };

            if let Some(e) = entries {
                let _ = slint::invoke_from_event_loop(move || {
                     if let Some(app) = app_weak.upgrade() {
                         apply_vault_model(&app, e);
                     }
                });
            }
        });
    });
}
