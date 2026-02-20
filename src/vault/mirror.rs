use std::path::{Path, PathBuf};
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};

/// Syncs the source file to all mirror paths.
/// Returns a list of results (Mirror Path, Success/Error).
pub fn sync_mirrors(source_path: &Path, mirrors: &[String]) -> Vec<(String, Result<(), String>)> {
    let mut results = Vec::new();
    
    if !source_path.exists() {
        // Should not happen if source was just saved
        for m in mirrors {
            results.push((m.clone(), Err("Source file not found".into())));
        }
        return results;
    }

    for mirror_str in mirrors {
        let mirror_path = PathBuf::from(mirror_str);
        
        // 1. Check if parent dir exists, try to create if not
        if let Some(parent) = mirror_path.parent() {
             if !parent.exists() {
                 if let Err(e) = fs::create_dir_all(parent) {
                     results.push((mirror_str.clone(), Err(format!("Failed to create parent dir: {}", e))));
                     continue;
                 }
             }
        }
        
        // 2. Perform Copy
        // We use std::fs::copy.
        // Note: Mirrors are NOT strictly locked or ACL protected in the same way (User Requirement: permission explicitness only for LocalLow).
        // So standard copy is fine.
        match fs::copy(source_path, &mirror_path) {
            Ok(_) => results.push((mirror_str.clone(), Ok(()))),
            Err(e) => results.push((mirror_str.clone(), Err(format!("Copy failed: {}", e)))),
        }
    }
    
    results
}

/// Syncs using an open file handle (e.g. exclusively locked file).
/// Reads file into memory and writes to mirrors.
pub fn sync_mirrors_from_file(source_file: &mut fs::File, mirrors: &[String]) -> Vec<(String, Result<(), String>)> {
    let mut results = Vec::new();

    // Rewind source
    if let Err(e) = source_file.seek(SeekFrom::Start(0)) {
        for m in mirrors {
            results.push((m.clone(), Err(format!("Seek failed: {}", e))));
        }
        return results;
    }

    // Read content
    let mut buffer = Vec::new();
    if let Err(e) = source_file.read_to_end(&mut buffer) {
        for m in mirrors {
            results.push((m.clone(), Err(format!("Read failed: {}", e))));
        }
        return results;
    }

    for mirror_str in mirrors {
        let mirror_path = PathBuf::from(mirror_str);
        
        // Parent check
        if let Some(parent) = mirror_path.parent() {
             if !parent.exists() {
                 if let Err(e) = fs::create_dir_all(parent) {
                     results.push((mirror_str.clone(), Err(format!("Parent dir error: {}", e))));
                     continue;
                 }
             }
        }
        
        // Write
        match fs::File::create(&mirror_path) {
            Ok(mut dest) => {
                // Truncate happens on create
                match dest.write_all(&buffer) {
                    Ok(_) => results.push((mirror_str.clone(), Ok(()))),
                    Err(e) => results.push((mirror_str.clone(), Err(format!("Write error: {}", e)))),
                }
            },
            Err(e) => results.push((mirror_str.clone(), Err(format!("Create error: {}", e)))),
        }
    }

    results
}
