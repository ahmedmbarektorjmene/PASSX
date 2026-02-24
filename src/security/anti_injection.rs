use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT, CONTEXT_FLAGS};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_IMAGE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread,
    SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
};

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
                ((*loaded.dll_name).Length / 2) as usize,
            );

            let full_path = String::from_utf16_lossy(name_slice).to_lowercase();

            let mut normalized_path = full_path.as_str();
            if normalized_path.starts_with("\\??\\") || normalized_path.starts_with("\\\\?\\") {
                normalized_path = &normalized_path[4..];
            }

            // Allowlist: Only allow DLLs from C:\Windows and Program Files
            // This blocks "payload.dll" from Desktop but allows System libraries and installed apps
            let is_system = normalized_path.starts_with("c:\\windows\\")
                || normalized_path.starts_with("c:\\program files\\")
                || normalized_path.starts_with("c:\\program files (x86)\\");

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
            if let Some(func) = GetProcAddress(
                ntdll,
                PCSTR::from_raw("LdrRegisterDllNotification\0".as_ptr()),
            ) {
                type LdrRegisterDllNotificationFn = unsafe extern "system" fn(
                    flags: u32,
                    callback: PldrDllNotificationFunction,
                    context: *mut c_void,
                    cookie: *mut *mut c_void,
                )
                    -> NTSTATUS;

                let ldr_register: LdrRegisterDllNotificationFn = mem::transmute(func);
                let mut cookie: *mut c_void = std::ptr::null_mut();

                let status = ldr_register(
                    0,
                    dll_notification_callback,
                    std::ptr::null_mut(),
                    &mut cookie,
                );
                if status.0 >= 0 {
                    // NT_SUCCESS
                    println!("[SECURITY] DLL Notification Callback Registered.");
                } else {
                    println!(
                        "[SECURITY] Failed to register DLL notification: {:#x}",
                        status.0
                    );
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
                    if let Ok(h_thread) =
                        OpenThread(THREAD_QUERY_INFORMATION, false, te32.th32ThreadID)
                    {
                        // Query Start Address
                        if let Some(start_addr) = get_thread_start_address(h_thread) {
                            // Debugging: Print suspicious threads
                            println!(
                                "[DEBUG] Thread found: ID={}, Start={:#x}, LL_A={:#x}, LL_W={:#x}",
                                te32.th32ThreadID, start_addr, load_lib_a, load_lib_w
                            );

                            // Query memory protections of the start address
                            let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                            let query_res = VirtualQuery(
                                Some(start_addr as *const c_void),
                                &mut mbi,
                                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            );

                            let mut is_malicious = false;

                            // Check if matches LoadLibrary (Broaden the check for offsets)
                            // LoadLibrary might have a jump (JMP) or be a wrapper.
                            // Let's check if it's "close enough" (within 64 bytes) or exact match.
                            if (start_addr >= load_lib_a && start_addr < load_lib_a + 64)
                                || (start_addr >= load_lib_w && start_addr < load_lib_w + 64)
                            {
                                println!("[SECURITY] Detected remote thread injection at {:#x} (LoadLibrary)", start_addr);
                                is_malicious = true;
                            } else if query_res > 0 {
                                // Checking for unbacked or dynamically allocated executable memory
                                if mbi.Type != MEM_IMAGE {
                                    let protect = mbi.Protect.0;
                                    let base_protect = protect & 0xFF; // Strip modifiers like PAGE_GUARD
                                    let is_executable = base_protect == PAGE_EXECUTE.0
                                        || base_protect == PAGE_EXECUTE_READ.0
                                        || base_protect == PAGE_EXECUTE_READWRITE.0
                                        || base_protect == PAGE_EXECUTE_WRITECOPY.0;

                                    if is_executable {
                                        println!("[SECURITY] Detected thread starting in unbacked/dynamic memory at {:#x}", start_addr);
                                        is_malicious = true;
                                    }
                                }
                            }

                            if is_malicious {
                                // BLOCK IT: Terminate the thread
                                let _ =
                                    windows::Win32::System::Threading::TerminateThread(h_thread, 1);
                                println!("[SECURITY] Malicious thread terminated!");

                                let _ = windows::Win32::Foundation::CloseHandle(h_thread);
                                let _ = windows::Win32::Foundation::CloseHandle(h_snapshot);
                                return false; // Do NOT exit the main app
                            }
                        }
                        let _ = windows::Win32::Foundation::CloseHandle(h_thread);
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
        let func_ptr = GetProcAddress(
            ntdll,
            PCSTR::from_raw("NtQueryInformationThread\0".as_ptr()),
        )?;
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
            if let Some(addr) = GetProcAddress(h_mod, PCSTR::from_raw(c_func.as_ptr() as *const u8))
            {
                return addr as usize;
            }
        }
    }
    0
}

/// Checks all threads for hijacking (e.g. APC Injection, SetThreadContext)
/// by verifying that their current Instruction Pointer (RIP/EIP)
/// is executing inside backed, legitimate memory.
pub fn check_thread_hijacking() -> bool {
    let pid = unsafe { GetCurrentProcessId() };
    let current_tid = unsafe { GetCurrentThreadId() };

    unsafe {
        let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut te32: THREADENTRY32 = mem::zeroed();
        te32.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(h_snapshot, &mut te32).is_ok() {
            loop {
                // Focus on threads belonging to our process, excluding the monitor thread itself.
                if te32.th32OwnerProcessID == pid && te32.th32ThreadID != current_tid {
                    if let Ok(h_thread) = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                        false,
                        te32.th32ThreadID,
                    ) {
                        // Briefly suspend to grab context safely
                        if SuspendThread(h_thread) != u32::MAX {
                            let mut ctx: CONTEXT = mem::zeroed();

                            #[cfg(target_arch = "x86_64")]
                            {
                                ctx.ContextFlags = CONTEXT_FLAGS(0x00100000 | 0x00000001);
                                // CONTEXT_AMD64 | CONTEXT_CONTROL
                            }

                            if GetThreadContext(h_thread, &mut ctx).is_ok() {
                                #[cfg(target_arch = "x86_64")]
                                let rip = ctx.Rip as usize;

                                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                                if VirtualQuery(
                                    Some(rip as *const c_void),
                                    &mut mbi,
                                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                ) > 0
                                {
                                    // If executing in dynamically allocated memory, it is hijacked.
                                    if mbi.Type != MEM_IMAGE {
                                        let protect = mbi.Protect.0;
                                        let base_protect = protect & 0xFF; // Strip modifiers

                                        let is_executable = base_protect == PAGE_EXECUTE.0
                                            || base_protect == PAGE_EXECUTE_READ.0
                                            || base_protect == PAGE_EXECUTE_READWRITE.0
                                            || base_protect == PAGE_EXECUTE_WRITECOPY.0;

                                        if is_executable {
                                            println!("[SECURITY] Detected Thread Hijacking! Thread {} executing at {:#x} in unbacked memory.", te32.th32ThreadID, rip);
                                            let _ =
                                                windows::Win32::System::Threading::TerminateThread(
                                                    h_thread, 1,
                                                );
                                        }
                                    }
                                }
                            }

                            // Resume regardless
                            ResumeThread(h_thread);
                        }
                        let _ = windows::Win32::Foundation::CloseHandle(h_thread);
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

/// Detects Module Stomping by checking the Working Set of the process.
/// It iterates through all threads and for their instruction pointer (RIP/EIP),
/// queries the Working Set to see if a MEM_IMAGE page has been modified
/// (making it private, which means it was Copied-on-Write).
pub fn check_module_stomping() -> bool {
    let pid = unsafe { GetCurrentProcessId() };
    let current_tid = unsafe { GetCurrentThreadId() };
    let h_process = unsafe { GetCurrentProcess() };

    unsafe {
        use windows::Win32::System::ProcessStatus::{
            QueryWorkingSetEx, PSAPI_WORKING_SET_EX_BLOCK, PSAPI_WORKING_SET_EX_INFORMATION,
        };

        let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut te32: THREADENTRY32 = mem::zeroed();
        te32.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(h_snapshot, &mut te32).is_ok() {
            loop {
                // Check threads of this process, skipping our own thread
                if te32.th32OwnerProcessID == pid && te32.th32ThreadID != current_tid {
                    if let Ok(h_thread) = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                        false,
                        te32.th32ThreadID,
                    ) {
                        // Briefly suspend
                        if SuspendThread(h_thread) != u32::MAX {
                            let mut ctx: CONTEXT = mem::zeroed();

                            #[cfg(target_arch = "x86_64")]
                            {
                                ctx.ContextFlags = CONTEXT_FLAGS(0x00100000 | 0x00000001);
                                // CONTEXT_CONTROL
                            }

                            if GetThreadContext(h_thread, &mut ctx).is_ok() {
                                #[cfg(target_arch = "x86_64")]
                                let rip = ctx.Rip as usize;

                                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                                if VirtualQuery(
                                    Some(rip as *const c_void),
                                    &mut mbi,
                                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                ) > 0
                                {
                                    // We only care if the page is MEM_IMAGE (backed by a DLL/EXE file)
                                    if mbi.Type == MEM_IMAGE {
                                        let protect = mbi.Protect.0;
                                        let base_protect = protect & 0xFF;

                                        let is_executable = base_protect == PAGE_EXECUTE.0
                                            || base_protect == PAGE_EXECUTE_READ.0
                                            || base_protect == PAGE_EXECUTE_READWRITE.0
                                            || base_protect == PAGE_EXECUTE_WRITECOPY.0;

                                        if is_executable {
                                            // Query Working Set to see if it's been copied on write
                                            let mut ws_info = PSAPI_WORKING_SET_EX_INFORMATION {
                                                VirtualAddress: rip as *mut c_void,
                                                VirtualAttributes: PSAPI_WORKING_SET_EX_BLOCK {
                                                    Flags: 0,
                                                },
                                            };

                                            let success = QueryWorkingSetEx(
                                                h_process,
                                                &mut ws_info as *mut _ as *mut c_void,
                                                mem::size_of::<PSAPI_WORKING_SET_EX_INFORMATION>()
                                                    as u32,
                                            )
                                            .is_ok();

                                            if success {
                                                let flags = ws_info.VirtualAttributes.Flags;
                                                let valid = (flags & 1) != 0;
                                                let shared = (flags >> 15) & 1;

                                                // If valid and NOT shared, it was written to (Modified MEM_IMAGE)
                                                // which is highly indicative of Module Stomping.
                                                if valid && shared == 0 {
                                                    println!("[SECURITY] Detected Module Stomping! Thread {} executing at {:#x} in modified MEM_IMAGE.", te32.th32ThreadID, rip);
                                                    let _ = windows::Win32::System::Threading::TerminateThread(
                                                        h_thread, 1,
                                                    );
                                                    ResumeThread(h_thread);
                                                    let _ = windows::Win32::Foundation::CloseHandle(
                                                        h_thread,
                                                    );
                                                    let _ = windows::Win32::Foundation::CloseHandle(
                                                        h_snapshot,
                                                    );
                                                    return true; // Malicious activity
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            ResumeThread(h_thread);
                        }
                        let _ = windows::Win32::Foundation::CloseHandle(h_thread);
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

/// Checks the first byte of critical security functions to ensure they haven't been patched.
/// Attackers might attempt to overwrite the start of the function with `ret` (0xC3)
/// or `jmp` (0xE9/0xEB) to bypass security checks from within the process.
pub fn check_functions_integrity() -> bool {
    let funcs: &[*const u8] = &[
        check_for_injected_threads as *const () as *const u8,
        check_thread_hijacking as *const () as *const u8,
        check_module_stomping as *const () as *const u8,
    ];

    for &func in funcs {
        unsafe {
            let first_byte = *func;

            // Common patching hooks:
            // 0xC3 = ret
            // 0xE9 = jmp near
            // 0xEB = jmp short
            // 0xCC = int 3 (debugger breakpoint)
            if first_byte == 0xC3 || first_byte == 0xE9 || first_byte == 0xEB || first_byte == 0xCC
            {
                println!(
                    "[SECURITY] Detected Function Hooking/Patching! First byte: {:#X}",
                    first_byte
                );
                return true;
            }
        }
    }

    false
}
