use windows::Win32::System::Threading::{
    OpenProcess, GetCurrentProcessId, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_NAME_FORMAT, QueryFullProcessImageNameW,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::Foundation::{CloseHandle};
use std::path::Path;

/// Validates that the process was launched by a trusted parent.
pub fn check_invariants() -> bool {
    let parent_pid = match get_parent_pid(unsafe { GetCurrentProcessId() }) {
        Some(pid) => pid,
        None => return false,
    };

    let parent_path = match get_process_name(parent_pid) {
        Some(path) => path,
        None => return false,
    };

    let parent_name = Path::new(&parent_path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let allowed_parents = [
        "explorer.exe",
        "cmd.exe",
        "pwsh.exe",
        "powershell.exe",
        "services.exe",
        "taskhostw.exe",
        "svchost.exe",
        "devenv.exe",
        "code.exe",
        "cargo.exe",
    ];

    allowed_parents.iter().any(|&p| parent_name == p)
}

fn get_parent_pid(target_pid: u32) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == target_pid {
                    let ppid = entry.th32ParentProcessID;
                    let _ = CloseHandle(snapshot);
                    return Some(ppid);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    None
}

fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        
        if QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), windows::core::PWSTR::from_raw(buffer.as_mut_ptr()), &mut size).is_ok() {
            let name = String::from_utf16_lossy(&buffer[..size as usize]);
            let _ = CloseHandle(handle);
            return Some(name);
        }
        let _ = CloseHandle(handle);
    }
    None
}

