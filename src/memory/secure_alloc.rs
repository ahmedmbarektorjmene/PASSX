use std::alloc::Layout;
use std::ptr::{self, null_mut};
use std::ffi::c_void; // Keep this as c_void is used for casting
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS
};

/// Secure memory allocator that uses VirtualAlloc/VirtualLock
/// to prevent memory from being swapped to disk.
pub struct SecureAllocator;

impl SecureAllocator {
    pub unsafe fn alloc_locked(layout: Layout) -> *mut u8 {
        // VirtualAlloc always returns page-aligned memory
        // We allocate enough pages to cover the size
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }

        // Allocate memory (automatically page aligned)
        let ptr = VirtualAlloc(
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if ptr.is_null() {
            return null_mut();
        }

        // Lock memory to prevent swapping (this might fail if working set quota is exceeded)
        // We attempt to lock, but if it fails we continue with warning (in real app should probably log/panic)
        // For security, strict mode would panic.
        if let Err(_) = VirtualLock(ptr, size) {
            // If locking fails, we should free and return null or panic depending on policy.
            // For this app, strict security:
            let _ = VirtualFree(ptr, 0, MEM_RELEASE);
            return null_mut();
        }

        ptr as *mut u8
    }

    pub unsafe fn dealloc_locked(ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let size = layout.size();
        
        // Zero memory before freeing (Redundant with VirtualFree but good practice secure wipe)
        ptr::write_bytes(ptr, 0, size);
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst); // Compiler fence

        // Unlock memory
        let _ = VirtualUnlock(ptr as *mut c_void, size);

        // Free memory
        let _ = VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE);
    }

    pub unsafe fn seal_locked(ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        let size = layout.size();
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        let _ = VirtualProtect(ptr as *mut c_void, size, PAGE_NOACCESS, &mut old_protect);
    }

    pub unsafe fn unseal_locked(ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        let size = layout.size();
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        let _ = VirtualProtect(ptr as *mut c_void, size, PAGE_READWRITE, &mut old_protect);
    }
}

// Global allocator implementation if we wanted to enforce it globally,
// but for now we expose static methods for dedicated use.
