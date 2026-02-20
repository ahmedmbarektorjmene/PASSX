use std::path::{Path, PathBuf};
use std::fs;
use crate::vault::file_lock;
use crate::vault::format::{self, Vault, VaultMode};
use crate::memory::guard::SecureBuffer;

// Windows Known Folder ID for LocalAppDataLow
// {A520A1A4-1780-4FF6-BD18-167343C5AF16}
const KAFID_LOCAL_APP_DATA_LOW: windows::core::GUID = windows::core::GUID::from_values(
    0xA520A1A4,
    0x1780,
    0x4FF6,
    [0xBD, 0x18, 0x16, 0x73, 0x43, 0xC5, 0xAF, 0x16]
);

pub fn get_managed_vaults_dir() -> PathBuf {
    use windows::Win32::UI::Shell::SHGetKnownFolderPath;
    use windows::Win32::UI::Shell::KF_FLAG_CREATE;

    unsafe {
        if let Ok(path_ptr) = SHGetKnownFolderPath(&KAFID_LOCAL_APP_DATA_LOW, KF_FLAG_CREATE, None) {
            let path_str = path_ptr.to_string().unwrap();
            windows::Win32::System::Com::CoTaskMemFree(Some(path_ptr.as_ptr() as *mut _));
            
            let mut path = PathBuf::from(path_str);
            path.push("passx");
            return path;
        }
    }
    // Fallback: Current Directory / vaults
    if let Ok(mut cwd) = std::env::current_dir() {
        cwd.push("passx_vaults");
        return cwd;
    }
    PathBuf::from("C:\\passx_vaults") 
}

pub fn init_managed_directory() -> std::io::Result<()> {
    let dir = get_managed_vaults_dir();
    println!("Initializing managed directory at: {:?}", dir);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(())
}

pub fn list_managed_vaults() -> Vec<String> {
    let dir = get_managed_vaults_dir();
    println!("Listing managed vaults in: {:?}", dir);
    let mut vaults = Vec::new();
    
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // println!("Checking entry: {:?}", path);
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "vault" {
                        if let Some(stem) = path.file_stem() {
                            let name = stem.to_string_lossy().to_string();
                            println!("Found vault: {}", name);
                            vaults.push(name);
                        }
                    }
                }
            }
        }
    }
    vaults
}

pub fn is_managed_path(path: &Path) -> bool {
    let managed_dir = get_managed_vaults_dir();
    path.starts_with(managed_dir)
}

pub fn get_vault_path(name: &str) -> PathBuf {
    let mut p = get_managed_vaults_dir();
    p.push(format!("{}.vault", name));
    p
}

/// Creates a new managed vault.
/// Returns (Vault, FileHandle, Path)
/// The FileHandle is exclusively locked.
pub fn create_managed_vault(
    name: &str,
    password: Option<&[u8]>,
    mode: VaultMode,
    master_key: &SecureBuffer
) -> Result<(Vault, std::fs::File, PathBuf), String> {
    // 1. Validate Name
    if name.chars().any(|c| !c.is_alphanumeric() && c != '_' && c != '-') {
        return Err("Invalid vault name. Use alphanumeric, _, - only.".into());
    }
    
    // 2. Init Dir
    init_managed_directory().map_err(|e| e.to_string())?;
    
    let path = get_vault_path(name);
    println!("Creating managed vault at: {:?}", path);
    if path.exists() {
        return Err("Vault with this name already exists.".into());
    }
    
    // 3. Create file (exclusive)
    let mut file = match file_lock::create_exclusive(&path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to create file: {}", e)),
    };
    
    // 4. Initialize Vault Structure
    let vault = Vault {
        mode,
        last_updated: chrono::Utc::now(),
        mirrors: Vec::new(),
        ..Default::default()
    };
    
    // 5. Save Initial Content (while we still have the handle)
    if let Err(e) = format::save_vault_to_writer(&mut file, &vault, master_key, mode, password) {
         drop(file);
         let _ = fs::remove_file(&path);
         return Err(format!("Failed to save initial vault: {:?}", e));
    }
    
    // 6. Close handle so we can apply ACLs by path (SetFileSecurityA needs file not locked)
    drop(file);
    
    // 7. Apply Strict ACLs (by path, file is closed)
    if let Err(e) = file_lock::apply_strict_acls(&path) {
        let _ = fs::remove_file(&path);
        return Err(format!("Failed to apply security/ACLs: {}", e));
    }
    
    // 8. Reopen exclusively (ACLs allow GRGW for current user)
    let file = match file_lock::open_exclusive(&path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to reopen vault after ACL: {}", e)),
    };
    
    Ok((vault, file, path))
}

pub fn delete_managed_vault(name: &str) -> std::io::Result<()> {
    let path = get_vault_path(name);
    if !path.exists() { return Ok(()); }
    
    // 1. Remove Strict ACLs (Unlock for deletion)
    file_lock::remove_strict_acls(&path)?;
    
    // 2. Delete
    fs::remove_file(path)?;
    
    Ok(())
}
