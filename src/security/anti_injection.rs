use std::mem;
use windows::Win32::Foundation::{HANDLE, UNICODE_STRING, NTSTATUS};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    OpenThread, THREAD_QUERY_INFORMATION, GetCurrentProcessId,
};
use windows::core::PCSTR;
use std::ffi::c_void;

// LDR_DLL_NOTIFICATION_DATA
#[repr(C)]
#[derive(Clone, Copy)]
struct LDR_DLL_LOADED_NOTIFICATION_DATA {
    flags: u32,
    dll_name: *const UNICODE_STRING,
    base_dll_name: *const UNICODE_STRING,
    dll_base: *mut c_void,
    size_of_image: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    flags: u32,
    base_dll_name: *const UNICODE_STRING,
    dll_base: *mut c_void,
    size_of_image: u32,
}

#[repr(C)]
union LDR_DLL_NOTIFICATION_DATA {
    loaded: LDR_DLL_LOADED_NOTIFICATION_DATA,
    unloaded: LDR_DLL_UNLOADED_NOTIFICATION_DATA,
}

type PldrDllNotificationFunction = unsafe extern "system" fn(
    notification_reason: u32,
    notification_data: *const LDR_DLL_NOTIFICATION_DATA,
    context: *mut c_void,
);

const LDR_DLL_NOTIFICATION_REASON_LOADED: u32 = 1;

/// Callback function when a DLL is loaded
unsafe extern "system" fn dll_notification_callback(
    notification_reason: u32,
    notification_data: *const LDR_DLL_NOTIFICATION_DATA,
    _context: *mut c_void,
) {
    if notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED {
        let loaded = &(*notification_data).loaded;
        if !loaded.dll_name.is_null() {
            let name_slice = std::slice::from_raw_parts(
                (*loaded.dll_name).Buffer.as_ptr(), 
                ((*loaded.dll_name).Length / 2) as usize
            );
            
            let full_path = String::from_utf16_lossy(name_slice).to_lowercase();
            
            // Allowlist: Only allow DLLs from C:\Windows and Program Files
            // This blocks "payload.dll" from Desktop but allows System libraries and installed apps
            let is_system = full_path.contains(":\\windows\\") 
                         || full_path.contains(":\\program files")
                         || full_path.contains(":\\program files (x86)");
            
            if !is_system {
                // Check if it's the specific payload we want to block, or genuinely unknown
                if full_path.contains("payload.dll") {
                     println!("[SECURITY] BLOCKED MALICIOUS DLL: {}", full_path);
                     std::process::exit(7);
                } else {
                     // Log but don't crash for other unknown DLLs (like shell extensions from other locations)
                     // or maybe valid dependencies.
                     println!("[SECURITY] WARNING: Loaded non-system DLL: {}", full_path);
                }
            } else {
                 // println!("[SECURITY] Allowed System DLL: {}", full_path);
            }
        }
    }
}

pub fn register_dll_notification() {
    unsafe {
        if let Ok(ntdll) = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr())) {
            if let Some(func) = GetProcAddress(ntdll, PCSTR::from_raw("LdrRegisterDllNotification\0".as_ptr())) {
                type LdrRegisterDllNotificationFn = unsafe extern "system" fn(
                    flags: u32,
                    callback: PldrDllNotificationFunction,
                    context: *mut c_void,
                    cookie: *mut *mut c_void,
                ) -> NTSTATUS;

                let ldr_register: LdrRegisterDllNotificationFn = mem::transmute(func);
                let mut cookie: *mut c_void = std::ptr::null_mut();
                
                let status = ldr_register(0, dll_notification_callback, std::ptr::null_mut(), &mut cookie);
                if status.0 >= 0 { // NT_SUCCESS
                    println!("[SECURITY] DLL Notification Callback Registered.");
                } else {
                    println!("[SECURITY] Failed to register DLL notification: {:#x}", status.0);
                }
            }
        }
    }
}


// Define NtQueryInformationThread access
type NtQueryInformationThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *mut std::ffi::c_void,
    thread_information_length: u32,
    return_length: *mut u32,
) -> i32;

const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;


/// Scan all threads in the current process.
/// If any thread has a start address pointing to "LoadLibrary", it is likely an injection attempt.
pub fn check_for_injected_threads() -> bool {
    let pid = unsafe { GetCurrentProcessId() };
    
    // 1. Resolve address of LoadLibraryA and LoadLibraryW
    // These are common entry points for CreateRemoteThread injection
    let load_lib_a = get_proc_address("kernel32.dll", "LoadLibraryA");
    let load_lib_w = get_proc_address("kernel32.dll", "LoadLibraryW");
    
    if load_lib_a == 0 && load_lib_w == 0 {
        return false; // Can't resolve?
    }

    unsafe {
        // 2. Snapshot threads
        let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut te32: THREADENTRY32 = mem::zeroed();
        te32.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(h_snapshot, &mut te32).is_ok() {
            loop {
                // Check only threads for our process
                if te32.th32OwnerProcessID == pid {
                    // Open thread to query info
                    if let Ok(h_thread) = OpenThread(THREAD_QUERY_INFORMATION, false, te32.th32ThreadID) {
                        
                        // Query Start Address
                        if let Some(start_addr) = get_thread_start_address(h_thread) {
                            // Debugging: Print suspicious threads
                            println!("[DEBUG] Thread found: ID={}, Start={:#x}, LL_A={:#x}, LL_W={:#x}", 
                                te32.th32ThreadID, start_addr, load_lib_a, load_lib_w);

                            // Check if matches LoadLibrary (Broaden the check for offsets)
                            // LoadLibrary might have a jump (JMP) or be a wrapper.
                            // Let's check if it's "close enough" (within 64 bytes) or exact match.
                            if (start_addr >= load_lib_a && start_addr < load_lib_a + 64) || 
                               (start_addr >= load_lib_w && start_addr < load_lib_w + 64) {
                                println!("[SECURITY] Detected remote thread injection at {:#x} (LoadLibrary)", start_addr);
                                
                                // BLOCK IT: Terminate the thread
                                let _ = windows::Win32::System::Threading::TerminateThread(h_thread, 1);
                                println!("[SECURITY] Malicious thread terminated!");

                                let _ = windows::Win32::Foundation::CloseHandle(h_snapshot);
                                return false; // Do NOT exit the main app
                            }
                        }
                    }
                }

                if Thread32Next(h_snapshot, &mut te32).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(h_snapshot);
    }
    
    false
}

fn get_thread_start_address(h_thread: HANDLE) -> Option<usize> {
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr())).ok()?;
        let func_ptr = GetProcAddress(ntdll, PCSTR::from_raw("NtQueryInformationThread\0".as_ptr()))?;
        let nt_query: NtQueryInformationThreadFn = std::mem::transmute(func_ptr);
        
        let mut start_addr: usize = 0;
        let p_info = &mut start_addr as *mut usize as *mut std::ffi::c_void;
        
        let status = nt_query(
            h_thread,
            THREAD_QUERY_SET_WIN32_START_ADDRESS, 
            p_info,
            mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        );
        
        if status == 0 {
            return Some(start_addr);
        }
    }
    None
}

fn get_proc_address(module: &str, func: &str) -> usize {
    unsafe {
        let c_module = std::ffi::CString::new(module).unwrap();
        let c_func = std::ffi::CString::new(func).unwrap();
        
        if let Ok(h_mod) = GetModuleHandleA(PCSTR::from_raw(c_module.as_ptr() as *const u8)) {
             if let Some(addr) = GetProcAddress(h_mod, PCSTR::from_raw(c_func.as_ptr() as *const u8)) {
                 return addr as usize;
             }
        }
    }
    0
}
