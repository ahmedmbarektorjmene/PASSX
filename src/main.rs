#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use passx::runtime::integrity;
use passx::tpm::sealing;
use passx::ui; // Expose seal_key or better a `tpm::check_availability()` function

fn main() {
    // Suppress non-fatal DLL loading warning dialogs (0xc000007b)
    // Must be called before anything else to prevent the error message box
    // that appears when double-clicking the exe (no console to absorb warnings).
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Diagnostics::Debug::SetErrorMode;
        use windows::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS;
        SetErrorMode(SEM_FAILCRITICALERRORS);
    }

    // 0. Anti-Debug Check
    #[cfg(windows)]
    {
        // Enforce Administrator Privileges
        if !passx::security::admin::is_admin() {
            if passx::security::admin::relaunch_as_admin() {
                // Successfully launched UAC prompt and new process
                std::process::exit(0);
            } else {
                eprintln!("Administrator privileges are required to run PASSX.");
                std::process::exit(10);
            }
        }

        // 0. Antivirus Check (Must run before ChildProcess policy blocks PowerShell)
        passx::security::antivirus::check_antivirus_availability();

        // HARDENING
        // 1. Enable Process Mitigation Policies (Refined: ImageLoad, ChildProcess, HandleCheck)
        passx::security::enable_process_mitigation_policies();

        // 2. Single Instance Check
        if !passx::security::ensure_single_instance() {
            eprintln!("Another instance of PASSX is already running.");
            std::process::exit(1);
        }

        // 3. Restrict Process Access (DACL)
        passx::security::restrict_process_access();

        // 4. Harden Main Thread
        passx::security::harden_current_thread();

        // 5. Start Security Monitor (Anti-Debug Loop)
        passx::security::start_security_monitor();

        #[cfg(not(debug_assertions))]
        unsafe {
            use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
            if IsDebuggerPresent().as_bool() {
                eprintln!("Debugger detected. Exiting.");
                std::process::exit(11);
            }
        }
    }

    // 1. Runtime Integrity Check
    match integrity::verify_self_integrity() {
        Ok(true) => {}
        Ok(false) => {
            std::process::exit(12);
        }
        Err(_e) => {
            std::process::exit(13);
        }
    }

    // 2. TPM Requirements Check
    // We try to create a context to verify TPM works, but we don't crash if it fails.
    let tpm_available = match sealing::check_tpm_availability() {
        Ok(_) => true,
        Err(_e) => false,
    };

    // 3. Launch UI
    // We pass tpm_available to the UI
    if let Err(e) = ui::run(tpm_available) {
        eprintln!("Application Error: {}", e);
    }
}
