use std::process::{Command, Stdio};
use std::time::Duration;
use std::thread;
use std::io::{BufRead, BufReader};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID, FALSE};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, GetCurrentProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, 
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED
};

// REMOVED CONSTANT CANARY to avoid finding it in static memory


#[test]
fn test_memory_forensics_zeroization() {
    // This test acts as the "Attacker" scanning the "Victim" process.
    // However, it first checks if we are running as the Victim subprocess.
    if std::env::var("TEST_MODE").unwrap_or_default() == "VICTIM" {
        victim_behavior();
        std::process::exit(0);
    }

    // --- Attacker Mode ---
    
    // 1. Check/Acquire Admin Privileges (SeDebugPrivilege)
    if !unsafe { enable_debug_privilege() } {
        // If we can't get privileges, we might not be Admin.
        // this is a real CI, we want to fail.
        panic!("SKIPPING: SeDebugPrivilege could not be acquired. Run as Administrator to execute this test.");
    }

    // 2. Spawn Victim Process
    let current_exe = std::env::current_exe().expect("Failed to get current exe path");
    println!("[*] Spawning victim using executable: {:?}", current_exe);
    let mut child = Command::new(&current_exe)
        .env("TEST_MODE", "VICTIM")
        .arg("test_memory_forensics_zeroization")
        .arg("--exact")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn victim process");
    
    println!("[*] Victim process spawned with PID: {}", child.id());

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    let mut secret_bytes = Vec::new();

    // 3. Wait for Victim to initialize and drop the secret
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break; // EOF
        }
        if line.starts_with("SECRET_VALUE:") {
            let hex_str = line.trim().strip_prefix("SECRET_VALUE:").unwrap();
            secret_bytes = hex::decode(hex_str).expect("Failed to decode secret");
        }
        if line.contains("SECRET_DROPPED") {
            break;
        }
    }
    
    assert!(!secret_bytes.is_empty(), "Failed to receive dynamic secret from victim");

    // 4. Forensics Scan
    // The secret should be GONE from the victim's memory now.
    println!("[*] Victim dropped secret. Scanning memory...");
    
    // We need the raw OS Process ID, not the child handle mainly.
    // But `child.id()` returns u32.
    let pid = child.id();
    
    let found = unsafe { scan_process_memory(pid, &secret_bytes) };
    
    // 5. Cleanup
    let _ = child.kill();
    
    assert!(!found, "SECURITY FAILURE: Canary value found in process memory after drop!");
    println!("[SUCCESS] Canary value successfully zeroized and not found in memory.");
}

fn victim_behavior() {
    
    println!("VICTIM_STARTING");
    {
        // Generate a dynamic secret that is NOT in the binary
        // We simulate a user typing a password or generating a key
        // Direct allocation into SecureBuffer prevents standard Vec leaks!
        let mut _secret = passx::memory::guard::SecureBuffer::new(32).unwrap();
        passx::crypto::random::SecureRandom::fill(&mut *_secret);
        
        let mut hex_secret = hex::encode(&*_secret);
        println!("SECRET_VALUE:{}", hex_secret);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        unsafe {
            // To be absolutely certain we zeroize the String's backing buffer, we get its vec representation:
            let vec_repr = hex_secret.as_mut_vec();
            let ptr = vec_repr.as_mut_ptr();
            for i in 0..vec_repr.capacity() {
                std::ptr::write_volatile(ptr.add(i), 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        
        println!("READY_WITH_SECRET");
        // Secret is dropped here at end of scope
    }
    println!("SECRET_DROPPED");
    
    // Keep process alive for scan
    thread::sleep(Duration::from_secs(60));
}

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
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
        ..Default::default()
    };

    let result = AdjustTokenPrivileges(
        h_token, 
        FALSE, 
        Some(&mut tp as *mut _ as *const _), 
        0, 
        None, 
        None
    );

    let _ = CloseHandle(h_token);
    result.is_ok()
}

unsafe fn scan_process_memory(pid: u32, pattern: &[u8]) -> bool {
    let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
        .expect("Failed to open victim process - need Admin?");

    let mut address = 0 as *mut std::ffi::c_void;
    let mut mem_info = MEMORY_BASIC_INFORMATION::default();
    
    while VirtualQueryEx(h_process, Some(address), &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
        if mem_info.State == MEM_COMMIT {
            // Read this region
            let mut buffer = vec![0u8; mem_info.RegionSize];
            let mut bytes_read = 0;
            
            if ReadProcessMemory(
                h_process, 
                mem_info.BaseAddress, 
                buffer.as_mut_ptr() as *mut _, 
                mem_info.RegionSize, 
                Some(&mut bytes_read)
            ).is_ok() {
                // Simple search
                let chunk = &buffer[..bytes_read];
                for (offset, window) in chunk.windows(pattern.len()).enumerate() {
                    if window == pattern {
                        println!("[ATTACKER] Found pattern at Absolute Address: {:p}, Region Base: {:p}, Size: {}, Protect: {:?}, Type: {:?}", 
                            (mem_info.BaseAddress as usize + offset) as *const u8,
                            mem_info.BaseAddress, mem_info.RegionSize, mem_info.Protect, mem_info.Type
                        );
                        let _ = CloseHandle(h_process);
                        return true;
                    }
                }
            }
        }
        
        // Move to next region
        address = (mem_info.BaseAddress as usize + mem_info.RegionSize) as *mut _;
    }

    let _ = CloseHandle(h_process);
    false
}
