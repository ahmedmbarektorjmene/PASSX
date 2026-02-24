use std::mem;
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, GetThreadContext, IsDebuggerPresent, CONTEXT, CONTEXT_FLAGS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

/// Check if a debugger is attached to the process.
/// Returns true if a user-mode debugger is present.
pub fn is_debugged() -> bool {
    unsafe {
        if IsDebuggerPresent().as_bool() {
            return true;
        }

        let mut remote_debugger: BOOL = BOOL(0);
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote_debugger).is_ok() {
            if remote_debugger.as_bool() {
                return true;
            }
        }
    }

    // Advanced Checks
    if check_nt_query_info_process() || check_peb() || check_timing_delta() {
        return true;
    }

    // Check hardware breakpoints
    if has_hardware_breakpoints() {
        return true;
    }

    false
}

/// Checks for the presence of hardware breakpoints (DR0-DR3).
/// Returns true if any hardware breakpoint is set.
fn has_hardware_breakpoints() -> bool {
    unsafe {
        let mut ctx: CONTEXT = mem::zeroed();
        // CONTEXT_DEBUG_REGISTERS = 0x00010010 (on x64)
        // Set the ContextFlags to request debug registers
        #[cfg(target_arch = "x86_64")]
        {
            ctx.ContextFlags = CONTEXT_FLAGS(0x00100000 | 0x00000010); // CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS
        }
        #[cfg(target_arch = "x86")]
        {
            ctx.ContextFlags = CONTEXT_FLAGS(0x00010000 | 0x00000010); // CONTEXT_i386 | CONTEXT_DEBUG_REGISTERS
        }

        if GetThreadContext(GetCurrentThread(), &mut ctx).is_ok() {
            // Check if any of the debug registers DR0-DR3 are non-zero
            // and if DR7 (Debug Control Register) has any local/global enable bits set.
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                && (ctx.Dr7 & 0xF) != 0
            {
                return true;
            }
        }
    }
    false
}

/// Check if running inside a hypervisor/VM (basic check via CPUID).
/// Returns true if likely virtualized.
pub fn is_virtualized() -> bool {
    // CPUID Leaf 1, ECX Bit 31 (Hypervisor Present)
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use std::arch::x86_64::__cpuid;
        let result = unsafe { __cpuid(1) };
        // Check ECX bit 31
        if (result.ecx & (1 << 31)) != 0 {
            return true;
        }
    }

    // Additional heuristics could be added (CPUID leaf 0x40000000)
    // but basic check is sufficient for now.
    false
}

/// Quick check that should be run periodically.
/// If returns true, secrets should be wiped immediately.
pub fn security_check() -> bool {
    is_debugged() || is_virtualized()
}

/// Uses NtQueryInformationProcess to call the kernel and ask if a debugger is attached.
/// This defeats user-mode hooks on IsDebuggerPresent.
fn check_nt_query_info_process() -> bool {
    unsafe {
        use std::ffi::c_void;
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        if let Ok(ntdll) = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr())) {
            let func_ptr = GetProcAddress(
                ntdll,
                PCSTR::from_raw("NtQueryInformationProcess\0".as_ptr()),
            );
            if let Some(f) = func_ptr {
                type NtQueryInformationProcessFn = unsafe extern "system" fn(
                    windows::Win32::Foundation::HANDLE,
                    i32,
                    *mut c_void,
                    u32,
                    *mut u32,
                )
                    -> i32;

                let nt_query: NtQueryInformationProcessFn = std::mem::transmute(f);
                let current_process = GetCurrentProcess();

                // ProcessDebugPort (0x7)
                let mut debug_port: usize = 0;
                let status1 = nt_query(
                    current_process,
                    7,
                    &mut debug_port as *mut _ as *mut c_void,
                    std::mem::size_of::<usize>() as u32,
                    std::ptr::null_mut(),
                );
                if status1 >= 0 && debug_port != 0 {
                    return true;
                }

                // ProcessDebugFlags (0x1F) - returns 0 if debugging, 1 if not
                let mut debug_flags: u32 = 0;
                let status2 = nt_query(
                    current_process,
                    0x1F,
                    &mut debug_flags as *mut _ as *mut c_void,
                    std::mem::size_of::<u32>() as u32,
                    std::ptr::null_mut(),
                );
                if status2 >= 0 && debug_flags == 0 {
                    return true;
                }

                // ProcessDebugObjectHandle (0x1E)
                let mut debug_object: usize = 0;
                let status3 = nt_query(
                    current_process,
                    0x1E,
                    &mut debug_object as *mut _ as *mut c_void,
                    std::mem::size_of::<usize>() as u32,
                    std::ptr::null_mut(),
                );
                if status3 >= 0 && debug_object != 0 {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks the PEB NtGlobalFlag directly.
#[cfg(target_arch = "x86_64")]
fn check_peb() -> bool {
    unsafe {
        use std::ffi::c_void;
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        if let Ok(ntdll) = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr())) {
            let func_ptr = GetProcAddress(
                ntdll,
                PCSTR::from_raw("NtQueryInformationProcess\0".as_ptr()),
            );
            if let Some(f) = func_ptr {
                type NtQueryInformationProcessFn = unsafe extern "system" fn(
                    windows::Win32::Foundation::HANDLE,
                    i32,
                    *mut c_void,
                    u32,
                    *mut u32,
                )
                    -> i32;
                let nt_query: NtQueryInformationProcessFn = std::mem::transmute(f);

                #[repr(C)]
                struct PROCESS_BASIC_INFORMATION {
                    exit_status: i32,
                    peb_base_address: *const u8,
                    affinity_mask: usize,
                    base_priority: i32,
                    unique_process_id: usize,
                    inherited_from_unique_process_id: usize,
                }

                let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
                let status = nt_query(
                    GetCurrentProcess(),
                    0, // ProcessBasicInformation
                    &mut pbi as *mut _ as *mut c_void,
                    std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                );

                if status >= 0 && !pbi.peb_base_address.is_null() {
                    let being_debugged = *pbi.peb_base_address.offset(0x2);
                    if being_debugged != 0 {
                        return true;
                    }

                    // NtGlobalFlag is at offset 0xBC in 64-bit PEB
                    // FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS (0x40) == 0x70
                    let nt_global_flag = *(pbi.peb_base_address.offset(0xBC) as *const u32);
                    if (nt_global_flag & 0x70) != 0 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(target_arch = "x86_64"))]
fn check_peb() -> bool {
    false
}

/// RDTSC timing threshold check against single-stepping.
fn check_timing_delta() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use std::arch::x86_64::{__cpuid, _rdtsc};
        unsafe {
            let t1 = _rdtsc();
            // Perform an instruction that forces a VMExit or serialization,
            // a single step in a debugger will pause execution here.
            let _ = __cpuid(1);
            let t2 = _rdtsc();

            // If the time diff is massive (e.g. > 0xFFFFF cycles ~ a few ms), a human is likely stepping.
            if (t2 - t1) > 0xFFFFF {
                return true;
            }
        }
    }
    false
}
