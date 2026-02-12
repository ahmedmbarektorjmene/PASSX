use std::path::PathBuf;
use crate::vault::format::Vault;
use crate::memory::guard::SecureBuffer;

// Defined at module level so it's visible to helper functions
#[derive(Default)]
pub struct AppState {
    pub vault: Option<Vault>,
    pub key: Option<SecureBuffer>, // The actual Master Key
    pub password: Option<SecureBuffer>, // Cached password for Portable Vaults (needed for re-saving)
    pub vault_path: Option<PathBuf>,
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
