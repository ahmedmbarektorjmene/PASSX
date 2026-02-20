// use std::path::PathBuf;
use crate::vault::format::Vault;
use crate::memory::guard::SecureBuffer;

// Defined at module level so it's visible to helper functions
#[derive(Default)]
pub struct AppState {
    // Runtime
    pub vault: Option<Vault>,
    pub key: Option<SecureBuffer>,
    pub password: Option<SecureBuffer>, // Kept in memory for re-saving
    pub vault_path: Option<std::path::PathBuf>,
    pub vault_file: Option<std::fs::File>, // Exclusive lock handle
    
    // Search/Filter
    pub current_filter: String,
    pub current_search: String,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            current_filter: "accounts".into(),
            current_search: "".into(),
            ..Default::default()
        }
    }
}
