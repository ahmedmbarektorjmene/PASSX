use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read};
use std::env;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use reqwest::blocking::Client;
use std::time::Duration;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

/// The production public key used to verify signatures.
const PUBLIC_KEY_BYTES: [u8; 32] = [
    0x3a, 0x1f, 0x5e, 0x7a, 0xbc, 0x12, 0xd4, 0x89, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
];

/// Verifies the digital signature and integrity of the running executable.
pub fn verify_self_integrity() -> Result<bool, Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    let mut file = File::open(&exe_path)?;
    let file_size = file.metadata()?.len();

    // 1. Minimum size: we expect at least 64 bytes for the signature
    if file_size < 64 {
        return Ok(false);
    }

    // 2. Read data (excluding signature)
    let data_len = (file_size - 64) as usize;
    let mut data = vec![0u8; data_len];
    file.read_exact(&mut data)?;

    // 3. Read signature (last 64 bytes)
    let mut sig_bytes = [0u8; 64];
    file.read_exact(&mut sig_bytes)?;

    // 4. Offline Verification
    let public_key = VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES)?;
    let signature = Signature::from_bytes(&sig_bytes);

    if public_key.verify(&data, &signature).is_err() {
        return Ok(false);
    }

    // 5. Online Verification (GitHub Check)
    if let Ok(remote_valid) = check_github_signature(&sig_bytes) {
        if !remote_valid {
            return Ok(false);
        }
    }

    Ok(true)
}

fn check_github_signature(_current_sig: &[u8; 64]) -> Result<bool, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    let url = "https://raw.githubusercontent.com/ahmedmbarektorjmene/PASSX/main/release/signature.txt";
    let response = client.get(url).send();

    match response {
        Ok(res) if res.status().is_success() => {
            let body = res.text()?;
            let remote_sig_hex = body.trim();
            if remote_sig_hex == "REVOKED" {
                return Ok(false);
            }
            Ok(true)
        }
        _ => {
            Ok(true)
        }
    }
}

/// Calculate SHA-256 hash of the .text section in memory.
/// This detects in-memory patching/hollowing.
pub fn verify_memory_integrity(baseline_hash: &[u8; 32]) -> bool {
    unsafe {
        let base = GetModuleHandleW(None).unwrap_or_default();
        if base.is_invalid() { return false; }

        let base_addr = base.0 as *const u8;
        
        // Parse DOS Header
        let dos_header = base_addr as *const windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D { return false; } // MZ

        // Parse NT Headers
        let nt_headers = (base_addr.add((*dos_header).e_lfanew as usize)) as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != 0x00004550 { return false; } // PE\0\0

        // Search for .text section
        let section_header_start = (nt_headers as *const u8).add(std::mem::size_of::<windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64>()) as *const windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
        let section_count = (*nt_headers).FileHeader.NumberOfSections;

        for i in 0..section_count {
            let section = *section_header_start.add(i as usize);
            let name = String::from_utf8_lossy(&section.Name).trim_matches('\0').to_string();
            
            if name == ".text" {
                let start = base_addr.add(section.VirtualAddress as usize);
                let size = section.Misc.VirtualSize as usize;
                
                let mut hasher = Sha256::new();
                hasher.update(std::slice::from_raw_parts(start, size));
                let hash = hasher.finalize();
                
                return hash.as_slice() == baseline_hash;
            }
        }
    }
    false
}

/// Capture the current .text hash to use as baseline.
pub fn get_current_memory_hash() -> Option<[u8; 32]> {
    unsafe {
        let base = GetModuleHandleW(None).ok()?;
        let base_addr = base.0 as *const u8;
        let dos_header = base_addr as *const windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
        let nt_headers = (base_addr.add((*dos_header).e_lfanew as usize)) as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
        let section_header_start = (nt_headers as *const u8).add(std::mem::size_of::<windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64>()) as *const windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
        let section_count = (*nt_headers).FileHeader.NumberOfSections;

        for i in 0..section_count {
            let section = *section_header_start.add(i as usize);
            let name = String::from_utf8_lossy(&section.Name).trim_matches('\0').to_string();
            if name == ".text" {
                let start = base_addr.add(section.VirtualAddress as usize);
                let size = section.Misc.VirtualSize as usize;
                let mut hasher = Sha256::new();
                hasher.update(std::slice::from_raw_parts(start, size));
                let hash = hasher.finalize();
                let mut result = [0u8; 32];
                result.copy_from_slice(&hash);
                return Some(result);
            }
        }
    }
    None
}
