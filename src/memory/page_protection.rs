use std::ffi::c_void;
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_READONLY, PAGE_READWRITE, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS,
};

/// Set memory pages to read-only (RX for code, R for data).
/// Returns true on success.
pub unsafe fn make_readonly(ptr: *mut u8, size: usize) -> bool {
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(ptr as *mut c_void, size, PAGE_READONLY, &mut old_protect).is_ok()
}

/// Set memory pages to read-write (RW).
/// Returns true on success.
pub unsafe fn make_readwrite(ptr: *mut u8, size: usize) -> bool {
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(ptr as *mut c_void, size, PAGE_READWRITE, &mut old_protect).is_ok()
}

/// Set memory pages to no-access (guard pages).
/// Returns true on success.
pub unsafe fn make_noaccess(ptr: *mut u8, size: usize) -> bool {
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(ptr as *mut c_void, size, PAGE_NOACCESS, &mut old_protect).is_ok()
}
