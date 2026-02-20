use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
use windows::core::PCWSTR;
use std::env;
use std::os::windows::ffi::OsStrExt;

/// Checks if the current process is running with Administrator privileges.
pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Relaunches the current executable requesting Administrator privileges via UAC.
/// Returns true if the relaunch was successfully initiated, false otherwise.
pub fn relaunch_as_admin() -> bool {
    let current_exe = env::current_exe().unwrap_or_default();
    let exe_path = current_exe.to_string_lossy().to_string();

    let exe_wide: Vec<u16> = std::ffi::OsStr::new(&exe_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let runas_wide: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Reconstruct arguments to pass to the new process
    let args: Vec<String> = env::args().skip(1).collect();
    let args_str = args.join(" ");
    let args_wide: Vec<u16> = std::ffi::OsStr::new(&args_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = ShellExecuteW(
            None,
            PCWSTR(runas_wide.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            PCWSTR(if args.is_empty() { std::ptr::null() } else { args_wide.as_ptr() }),
            PCWSTR(std::ptr::null()),
            SW_SHOW,
        );

        // ShellExecute returns a value > 32 on success
        result.0 as usize > 32
    }
}
