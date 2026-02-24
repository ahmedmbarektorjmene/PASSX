use std::ffi::CString;
use std::fs::File;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use windows::core::PCSTR;
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidA, ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, SetFileSecurityA, TokenUser, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Gets the current user's SID as a string (e.g. "S-1-5-21-...").
fn get_current_user_sid() -> std::io::Result<String> {
    unsafe {
        use windows::Win32::Foundation::HANDLE;

        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        // First call to get required buffer size
        let mut return_length: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut return_length);

        // Allocate buffer and get the actual token info
        let mut buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        let mut sid_string = windows::core::PSTR::null();
        ConvertSidToStringSidA(sid, &mut sid_string)
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        let sid_str = std::ffi::CStr::from_ptr(sid_string.as_ptr() as *const i8)
            .to_string_lossy()
            .to_string();

        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        let _ = LocalFree(HLOCAL(sid_string.as_ptr() as *mut _));

        Ok(sid_str)
    }
}

/// Opens a file with exclusive access (no sharing allowed).
/// This prevents other processes (like Explorer) from reading/copying the file while it's open.
pub fn open_exclusive<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    let path_str = path.as_ref().to_string_lossy().to_string();
    let c_path = CString::new(path_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    unsafe {
        let handle = CreateFileA(
            PCSTR::from_raw(c_path.as_ptr() as *const u8),
            GENERIC_READ.0 | GENERIC_WRITE.0, // Read/Write access
            FILE_SHARE_NONE,                  // Exclusive locking!
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        Ok(File::from_raw_handle(handle.0 as *mut _))
    }
}

/// Creates a new file with exclusive access.
pub fn create_exclusive<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    let path_str = path.as_ref().to_string_lossy().to_string();
    let c_path = CString::new(path_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    unsafe {
        let handle = CreateFileA(
            PCSTR::from_raw(c_path.as_ptr() as *const u8),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        Ok(File::from_raw_handle(handle.0 as *mut _))
    }
}

/// Applies strict ACLs to the file to prevent deletion/renaming by the current user.
/// This persists even when the application is closed.
/// NOTE: The file must NOT be exclusively locked when calling this (close handle first).
pub fn apply_strict_acls<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    // D:P = Protected DACL (blocks inheritance)
    // (A;;GA;;;SY)    = Allow Generic All to SYSTEM
    // (A;;GA;;;BA)    = Allow Generic All to Built-in Administrators
    // By omitting the standard user entirely, they have no access.
    // Because PASSX runs as Administrator, it will match the 'BA' rule.
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_string();
    let c_sddl = CString::new(sddl).unwrap();
    let path_str = path.as_ref().to_string_lossy().to_string();
    let c_path = CString::new(path_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let mut sd_size = 0;

        let res = ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PCSTR::from_raw(c_sddl.as_ptr() as *const u8),
            SDDL_REVISION_1,
            &mut sd,
            Some(&mut sd_size),
        );

        if let Err(e) = res {
            return Err(std::io::Error::from_raw_os_error(e.code().0));
        }

        let res = SetFileSecurityA(
            PCSTR::from_raw(c_path.as_ptr() as *const u8),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        );

        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        let _ = LocalFree(HLOCAL(sd.0));

        if let Err(e) = res {
            return Err(std::io::Error::from_raw_os_error(e.code().0));
        }
    }

    Ok(())
}

/// Removes strict ACLs, essentially resetting permissions so the file can be deleted.
pub fn remove_strict_acls<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let user_sid = get_current_user_sid()?;

    // Grant Generic All to the current user (full access restored)
    let sddl = format!("D:(A;;GA;;;{})", user_sid);
    let c_sddl = CString::new(sddl).unwrap();
    let path_str = path.as_ref().to_string_lossy().to_string();
    let c_path = CString::new(path_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let mut sd_size = 0;

        let res = ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PCSTR::from_raw(c_sddl.as_ptr() as *const u8),
            SDDL_REVISION_1,
            &mut sd,
            Some(&mut sd_size),
        );

        if let Err(e) = res {
            return Err(std::io::Error::from_raw_os_error(e.code().0));
        }

        let res = SetFileSecurityA(
            PCSTR::from_raw(c_path.as_ptr() as *const u8),
            DACL_SECURITY_INFORMATION,
            sd,
        );

        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        let _ = LocalFree(HLOCAL(sd.0));

        if let Err(e) = res {
            return Err(std::io::Error::from_raw_os_error(e.code().0));
        }
    }

    Ok(())
}
