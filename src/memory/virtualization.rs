use windows::Win32::System::Diagnostics::Debug::{IsDebuggerPresent, CheckRemoteDebuggerPresent};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::Foundation::BOOL;

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
    // In production we might want to allow virtualization if user consents (cloud VDI),
    // but strictly speaking a hypervisor can inspect memory.
    // For now, we report true if debugged.
}
