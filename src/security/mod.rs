use std::ffi::c_void;
use std::sync::{Once, OnceLock};
#[cfg(not(debug_assertions))]
use std::thread;
#[cfg(not(debug_assertions))]
use std::time::Duration;
use windows::core::PCSTR;
use windows::Win32::Foundation::{GetLastError, BOOL, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::Security::Cryptography::{
    CryptProtectMemory, CryptUnprotectMemory, CRYPTPROTECTMEMORY_SAME_PROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, ProcessChildProcessPolicy, ProcessImageLoadPolicy,
    ProcessStrictHandleCheckPolicy, SetProcessMitigationPolicy,
};

// Import localized security functions
#[cfg(not(debug_assertions))]
use crate::memory::virtualization;
#[cfg(debug_assertions)]
use crate::runtime::integrity;
#[cfg(not(debug_assertions))]
use crate::runtime::{integrity, invariants}; // Still used for BASELINE_HASH check unconditionally in enable_process_mitigation_policies()

pub mod admin;
pub mod anti_injection;
pub mod antivirus;

static INIT: Once = Once::new();
static BASELINE_HASH: OnceLock<[u8; 32]> = OnceLock::new();

#[repr(C)]
struct ProcessMitigationImageLoadPolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessMitigationChildProcessPolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessMitigationHandleCheckPolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessMitigationBinarySignaturePolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessMitigationExtensionPointDisablePolicy {
    flags: u32,
}

/// Apply Windows Process Mitigation policies (Image Load, Child Process, Handle Check).
pub fn enable_process_mitigation_policies() {
    INIT.call_once(|| {
        unsafe {
            // 1. Image Load Policy - NoRemoteImages | NoLowMandatoryLabelImages
            let image_load_policy = ProcessMitigationImageLoadPolicy { flags: 3 };
            let _ = SetProcessMitigationPolicy(
                ProcessImageLoadPolicy,
                &image_load_policy as *const _ as *const c_void,
                std::mem::size_of_val(&image_load_policy),
            );

            // 2. Child Process Policy - NoChildProcess = 1
            let child_process_policy = ProcessMitigationChildProcessPolicy { flags: 1 };
            let _ = SetProcessMitigationPolicy(
                ProcessChildProcessPolicy,
                &child_process_policy as *const _ as *const c_void,
                std::mem::size_of_val(&child_process_policy),
            );

            // 3. Handle Check Policy - RaiseExceptionOnInvalidHandleReference | HandleExceptionsPermanentlyEnabled
            let handle_check_policy = ProcessMitigationHandleCheckPolicy { flags: 3 };
            let _ = SetProcessMitigationPolicy(
                ProcessStrictHandleCheckPolicy,
                &handle_check_policy as *const _ as *const c_void,
                std::mem::size_of_val(&handle_check_policy),
            );

            use windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY;

            // 5. Binary Signature Policy (CIG) - MicrosoftSignedOnly (Stop Unsigned DLLs)
            let signature_policy = ProcessMitigationBinarySignaturePolicy { flags: 1 }; // MicrosoftSignedOnly = 1
            let _ = SetProcessMitigationPolicy(
                PROCESS_MITIGATION_POLICY(8), // ProcessSignaturePolicy
                &signature_policy as *const _ as *const c_void,
                std::mem::size_of_val(&signature_policy),
            );

            // 6. Extension Point Disable Policy - DisableExtensionPoints = 1
            let extension_point_policy = ProcessMitigationExtensionPointDisablePolicy { flags: 1 };
            let _ = SetProcessMitigationPolicy(
                PROCESS_MITIGATION_POLICY(5), // ProcessExtensionPointDisablePolicy
                &extension_point_policy as *const _ as *const c_void,
                std::mem::size_of_val(&extension_point_policy),
            );

            // 4. Capture baseline memory hash for code integrity
            if let Some(hash) = integrity::get_current_memory_hash() {
                let _ = BASELINE_HASH.set(hash);
            }
        }
    });
}

/// Restrict the current process DACL to deny access.
pub fn restrict_process_access() {
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        let advapi = GetModuleHandleA(PCSTR::from_raw("advapi32.dll\0".as_ptr()));
        let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()));

        if let (Ok(h_advapi), Ok(h_kernel32)) = (advapi, kernel32) {
            if !h_advapi.is_invalid() && !h_kernel32.is_invalid() {
                let convert_fn_ptr = GetProcAddress(
                    h_advapi,
                    PCSTR::from_raw(
                        "ConvertStringSecurityDescriptorToSecurityDescriptorA\0".as_ptr(),
                    ),
                );
                let set_fn_ptr = GetProcAddress(
                    h_advapi,
                    PCSTR::from_raw("SetKernelObjectSecurity\0".as_ptr()),
                );
                let free_fn_ptr =
                    GetProcAddress(h_kernel32, PCSTR::from_raw("LocalFree\0".as_ptr()));

                if let (Some(c_ptr), Some(s_ptr), Some(f_ptr)) =
                    (convert_fn_ptr, set_fn_ptr, free_fn_ptr)
                {
                    type ConvertFn =
                        unsafe extern "system" fn(PCSTR, u32, *mut *mut c_void, *mut u32) -> BOOL;
                    type SetFn = unsafe extern "system" fn(HANDLE, u32, *mut c_void) -> BOOL;
                    type FreeFn = unsafe extern "system" fn(*mut c_void) -> *mut c_void;

                    let convert: ConvertFn = std::mem::transmute(c_ptr);
                    let set: SetFn = std::mem::transmute(s_ptr);
                    let free: FreeFn = std::mem::transmute(f_ptr);

                    let mut sd: *mut c_void = std::ptr::null_mut();
                    let mut sd_size: u32 = 0;
                    let sddl = PCSTR::from_raw("D:P\0".as_ptr());

                    if convert(sddl, 1, &mut sd, &mut sd_size).as_bool() {
                        let _ = set(GetCurrentProcess(), 4, sd);
                        free(sd);
                    }
                }
            }
        }
    }
}

/// Hide the main thread from debuggers.
pub fn harden_current_thread() {
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        if let Ok(ntdll) = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr())) {
            if !ntdll.is_invalid() {
                let func_ptr =
                    GetProcAddress(ntdll, PCSTR::from_raw("NtSetInformationThread\0".as_ptr()));

                if let Some(f) = func_ptr {
                    type NtSetInformationThreadFn = unsafe extern "system" fn(
                        thread_handle: HANDLE,
                        thread_information_class: i32,
                        thread_information: *const c_void,
                        thread_information_length: u32,
                    )
                        -> i32;

                    let nt_set_info_thread: NtSetInformationThreadFn = std::mem::transmute(f);
                    let _ = nt_set_info_thread(GetCurrentThread(), 0x11, std::ptr::null(), 0);
                }
            }
        }
    }
}

/// Ensure single instance execution.
pub fn ensure_single_instance() -> bool {
    use windows::Win32::System::Threading::CreateMutexA;

    unsafe {
        let name = "Global\\PASSX_SINGLE_INSTANCE_MUTEX\0";
        let handle = CreateMutexA(None, true, PCSTR::from_raw(name.as_ptr()));

        if let Ok(h) = handle {
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return false;
            }
            let _ = h;
            return true;
        }

        let name_local = "Local\\PASSX_SINGLE_INSTANCE_MUTEX\0";
        let handle = CreateMutexA(None, true, PCSTR::from_raw(name_local.as_ptr()));
        if let Ok(h) = handle {
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return false;
            }
            let _ = h;
            return true;
        }

        true
    }
}

/// Protect memory using DPAPI.
pub fn protect_memory(ptr: *mut u8, len: usize) -> bool {
    unsafe {
        CryptProtectMemory(
            ptr as *mut c_void,
            len as u32,
            CRYPTPROTECTMEMORY_SAME_PROCESS,
        )
        .is_ok()
    }
}

/// Unprotect memory using DPAPI.
pub fn unprotect_memory(ptr: *mut u8, len: usize) -> bool {
    unsafe {
        CryptUnprotectMemory(
            ptr as *mut c_void,
            len as u32,
            CRYPTPROTECTMEMORY_SAME_PROCESS,
        )
        .is_ok()
    }
}

/// Starts a background thread for continuous security monitoring.
pub fn start_security_monitor() {
    #[cfg(debug_assertions)]
    {
        println!("[SECURITY] Debug mode detected. Skipping security monitor watchdog.");
    }

    #[cfg(not(debug_assertions))]
    {
        let watchdog = crate::session::watchdog::Watchdog::new();
        let heartbeat = watchdog.get_heartbeat();

        // Start the watcher thread to monitor THIS thread
        watchdog.start_watcher(3, || {
            // If this panic_action executes, it means our security monitor thread was suspended
            eprintln!("[SECURITY] FATAL: Security monitor thread was suspended. Terminating process to prevent memory extraction or injection!");
            std::process::exit(9);
        });

        thread::spawn(move || {
            loop {
                // Watchdog Heartbeat
                crate::session::watchdog::Watchdog::beat(&heartbeat);

                // 1. Checks for user-mode debuggers
                if virtualization::security_check() {
                    std::process::exit(1);
                }

                // Register DLL Notification Callback (Anti-Injection)
                static REGISTER_ONCE: Once = Once::new();
                REGISTER_ONCE.call_once(|| {
                    anti_injection::register_dll_notification();
                });

                // 2. Check process invariants (Parent validation)
                if !invariants::check_invariants() {
                    std::process::exit(2);
                }

                // 3. Verification of binary signature (On-disk)
                // DISABLED for local development builds (no signature appended)
                // if let Ok(valid) = integrity::verify_self_integrity() {
                //     if !valid {
                //         std::process::exit(3);
                //     }
                // }

                // 4. Anti-Injection: Check for threads starting at LoadLibrary (DLL Injection)
                if anti_injection::check_for_injected_threads() {
                    // Detected remote thread injection attempt
                    println!("[SECURITY] Detected remote thread injection!");
                    std::process::exit(4);
                }

                // 4.5 Anti-Injection: Check for Thread Hijacking via RIP Inspection
                if anti_injection::check_thread_hijacking() {
                    std::process::exit(6);
                }

                // 5. Verification of memory integrity (Hollowing/Patching detection)
                if let Some(baseline) = BASELINE_HASH.get() {
                    if !integrity::verify_memory_integrity(baseline) {
                        // Code segment has been tampered with in RAM
                        std::process::exit(5);
                    }
                }

                thread::sleep(Duration::from_millis(100)); // Reduced racing window
            }
        });
    }
}
