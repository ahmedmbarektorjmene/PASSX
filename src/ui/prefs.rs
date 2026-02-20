use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppPrefs {
    pub window_x: i32,
    pub window_y: i32,
    pub window_width: u32,
    pub window_height: u32,
    pub is_maximized: bool,
    pub last_vault_path: Option<PathBuf>,
    #[serde(default = "default_theme_mode")]
    pub theme_mode: String,
}

fn default_theme_mode() -> String {
    "system".to_string()
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
            theme_mode: "system".to_string(),
        }
    }
}

impl AppPrefs {
    fn get_prefs_path() -> Option<PathBuf> {
        if let Some(base_dirs) = directories::BaseDirs::new() {
            let config_dir = base_dirs.config_dir().join("passx");
            if !config_dir.exists() {
                let _ = fs::create_dir_all(&config_dir);
            }
            return Some(config_dir.join("config.json"));
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
