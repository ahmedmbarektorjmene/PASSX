use std::ptr;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::DataExchange::{
    OpenClipboard, EmptyClipboard, SetClipboardData, CloseClipboard,
};

// Clipboard format constant
const CF_UNICODETEXT: u32 = 13;

/// Copy text to clipboard securely and clear it after timeout.
pub fn copy_to_clipboard(text: &str, timeout_secs: u64) -> Result<(), String> {
    unsafe {
        // Open clipboard
        OpenClipboard(HWND(ptr::null_mut()))
            .map_err(|_| "Failed to open clipboard".to_string())?;
        
        // Clear previous content
        if let Err(e) = EmptyClipboard() {
            let _ = CloseClipboard();
            return Err(format!("Failed to empty clipboard: {:?}", e));
        }

        // Allocate global memory for text (UTF-16)
        let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes_len = utf16.len() * 2;
        
        let h_global = GlobalAlloc(GMEM_MOVEABLE, bytes_len)
            .map_err(|_| {
                let _ = CloseClipboard();
                "GlobalAlloc failed".to_string()
            })?;
        
        // Lock and copy
        let ptr = GlobalLock(h_global);
        if !ptr.is_null() {
            ptr::copy_nonoverlapping(utf16.as_ptr() as *const _, ptr, bytes_len);
            let _ = GlobalUnlock(h_global);
        } else {
             let _ = CloseClipboard();
             return Err("GlobalLock failed".to_string());
        }
        
        // Set data (System takes ownership of h_global)
        // h_global is HGLOBAL, but SetClipboardData wants HANDLE? 
        // HGLOBAL is often castable or identical to HANDLE in Foundation.
        if let Err(e) = SetClipboardData(CF_UNICODETEXT, HANDLE(h_global.0)) {
             let _ = CloseClipboard();
             return Err(format!("SetClipboardData failed: {:?}", e));
        }

    } // End of outer unsafe block

    // Spawn clearer thread safe
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout_secs));
        unsafe {
            if OpenClipboard(HWND(ptr::null_mut())).is_ok() {
                let _ = EmptyClipboard();
                let _ = CloseClipboard();
            }
        }
    });
    
    Ok(())
}

pub fn clear_clipboard() {
    unsafe {
        if OpenClipboard(HWND(ptr::null_mut())).is_ok() {
            let _ = EmptyClipboard();
            let _ = CloseClipboard();
        }
    }
}
