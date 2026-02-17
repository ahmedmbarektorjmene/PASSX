use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use directories::ProjectDirs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppPrefs {
    pub window_x: i32,
    pub window_y: i32,
    pub window_width: u32,
    pub window_height: u32,
    pub is_maximized: bool,
    pub last_vault_path: Option<PathBuf>,
}

impl Default for AppPrefs {
    fn default() -> Self {
        Self {
            window_x: 100,
            window_y: 100,
            window_width: 1050,
            window_height: 720,
            is_maximized: false,
            last_vault_path: None,
        }
    }
}

impl AppPrefs {
    fn get_prefs_path() -> Option<PathBuf> {
        if let Some(proj_dirs) = ProjectDirs::from("com", "passx", "passx") {
            let config_dir = proj_dirs.config_dir(); // Typically LocalAppData on Windows
            if !config_dir.exists() {
                let _ = fs::create_dir_all(config_dir);
            }
            return Some(config_dir.join("prefs.json"));
        }
        None
    }

    pub fn load() -> Self {
        if let Some(path) = Self::get_prefs_path() {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(prefs) = serde_json::from_str(&content) {
                        return prefs;
                    }
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        if let Some(path) = Self::get_prefs_path() {
            if let Ok(content) = serde_json::to_string_pretty(self) {
                let _ = fs::write(path, content);
            }
        }
    }
}
