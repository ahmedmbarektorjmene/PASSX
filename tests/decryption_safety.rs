use std::process::{Command, Stdio};
use std::time::Duration;
use std::thread;
use std::io::{BufRead, BufReader};
use windows::Win32::Foundation::{CloseHandle, FALSE};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};

// Re-using common admin privileges logic or assuming executed as admin for this specific test
// (Since admin_forensics.rs has the privilege code, we duplicate or shared it. Duplicating for isolation.)
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::System::Threading::{OpenProcessToken, GetCurrentProcess};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, 
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED
};

#[test]
fn test_secure_buffer_runtime_invisibility() {
    // This test verifies if a SecureBuffer holding a secret is visible to a memory scanner.
    // User expectation: It should NOT be visible (requires advanced protection).
    
    if std::env::var("TEST_MODE").unwrap_or_default() == "VICTIM" {
        victim_behavior();
        std::process::exit(0);
    }

    // --- Attacker Mode ---
    if !unsafe { enable_debug_privilege() } {
        eprintln!("SKIPPING: SeDebugPrivilege could not be acquired. Run as Administrator.");
        // We panic here because the user wants a strict test
        panic!("SKIPPING due to lack of privileges, but user demanded this test!");
    }

    let current_exe = std::env::current_exe().expect("Failed to get current exe path");
    let mut child = Command::new(current_exe)
        .env("TEST_MODE", "VICTIM")
        .arg("test_secure_buffer_runtime_invisibility")
        .arg("--exact")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn victim process");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut secret_bytes = Vec::new();

    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break; 
        }
        if line.starts_with("SECRET_VALUE:") {
            let hex_str = line.trim().strip_prefix("SECRET_VALUE:").unwrap();
            secret_bytes = hex::decode(hex_str).expect("Failed to decode secret");
            break;
        }
    }
    
    assert!(!secret_bytes.is_empty(), "Failed to get secret from victim");
    println!("[*] Attacker received secret target. Scanning victim memory...");

    // Give victim time to stable
    thread::sleep(Duration::from_millis(500));

    let pid = child.id();
    let found = unsafe { scan_process_memory(pid, &secret_bytes) };
    
    let _ = child.kill();

    if found {
        // This is the EXPECTED FAILURE for now
        panic!("SECURITY FAILURE: Secret FOUND in SecureBuffer memory! SecureBuffer is not invisible to scanners.");
    } else {
        println!("[SUCCESS] Secret was NOT found in memory (SecureBuffer is invisible).");
    }
}

fn victim_behavior() {
    use passx::memory::guard::SecureBuffer;
    use passx::crypto::random::SecureRandom;
    
    let mut secret_bytes = [0u8; 32];
    SecureRandom::fill(&mut secret_bytes);
    
    let hex_secret = hex::encode(&secret_bytes);
    println!("SECRET_VALUE:{}", hex_secret);
    
    // Create SecureBuffer
    let secure = SecureBuffer::from_slice(&secret_bytes).expect("Failed to allocate SecureBuffer");
    
    // Zeroize the stack copy immediately
    unsafe {
        std::ptr::write_bytes(secret_bytes.as_mut_ptr(), 0, secret_bytes.len());
    }

    // SEAL THE MEMORY to hide it from scanners
    secure.seal();

    // Hold the secret
    println!("VICTIM_HOLDING_SECRET");
    thread::sleep(Duration::from_secs(60));
}

// --- Helpers (Duplicated to avoid sharing complex test helper modules for now) ---

unsafe fn enable_debug_privilege() -> bool {
    let mut h_token = HANDLE::default();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token).is_err() {
        return false;
    }
    let mut luid = LUID::default();
    let priv_name = "SeDebugPrivilege\0".encode_utf16().collect::<Vec<u16>>();
    if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(priv_name.as_ptr()), &mut luid).is_err() {
        let _ = CloseHandle(h_token);
        return false;
    }
    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        ..Default::default()
    };
    let result = AdjustTokenPrivileges(h_token, FALSE, Some(&mut tp as *mut _ as *const _), 0, None, None);
    let _ = CloseHandle(h_token);
    result.is_ok()
}

unsafe fn scan_process_memory(pid: u32, pattern: &[u8]) -> bool {
    let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if h_process.is_err() { return false; }
    let h_process = h_process.unwrap();
    
    let mut address = 0 as *mut std::ffi::c_void;
    let mut mem_info = MEMORY_BASIC_INFORMATION::default();
    
    while VirtualQueryEx(h_process, Some(address), &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
        if mem_info.State == MEM_COMMIT {
            let mut buffer = vec![0u8; mem_info.RegionSize];
            let mut bytes_read = 0;
            if ReadProcessMemory(h_process, mem_info.BaseAddress, buffer.as_mut_ptr() as *mut _, mem_info.RegionSize, Some(&mut bytes_read)).is_ok() {
                if buffer[..bytes_read].windows(pattern.len()).any(|w| w == pattern) {
                    let _ = CloseHandle(h_process);
                    return true;
                }
            }
        }
        address = (mem_info.BaseAddress as usize + mem_info.RegionSize) as *mut _;
    }
    let _ = CloseHandle(h_process);
    false
}
