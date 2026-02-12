#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use passx::runtime::integrity;
use passx::ui;
use passx::tpm::sealing; // Expose seal_key or better a `tpm::check_availability()` function

fn main() {
    // 0. Anti-Debug Check
    #[cfg(windows)]
    unsafe {
        // HARDENING
        // 1. Enable Process Mitigation Policies (Refined: ImageLoad, ChildProcess, HandleCheck)
        passx::security::enable_process_mitigation_policies();
        println!("Process mitigation policies enabled.");
        // 2. Single Instance Check
        if !passx::security::ensure_single_instance() {
            eprintln!("Another instance of PASSX is already running.");
            std::process::exit(1);
        }
        println!("Single instance check passed.");
        
        // 3. Restrict Process Access (DACL)
        passx::security::restrict_process_access();
        println!("Process access restricted.");
        
        // 4. Harden Main Thread
        passx::security::harden_current_thread();
        println!("Main thread hardened.");
        
        // 5. Start Security Monitor (Anti-Debug Loop)
        passx::security::start_security_monitor();
        println!("Security monitor started.");
        
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        if IsDebuggerPresent().as_bool() {
            eprintln!("Debugger detected. Exiting.");
            std::process::exit(1);
        }
        println!("Debugger check passed.");
    }

    // // 1. Runtime Integrity Check
    // match integrity::verify_self_integrity() {
    //     Ok(true) => {},
    //     Ok(false) => {
    //         std::process::exit(1);
    //     },
    //     Err(_e) => {
    //         std::process::exit(1);
    //     }
    // }
    // println!("Runtime integrity check passed.");

    // 2. TPM Requirements Check
    // We try to create a context to verify TPM works, but we don't crash if it fails.
    let tpm_available = match sealing::check_tpm_availability() {
        Ok(_) => {
            true
        },
        Err(_e) => {
            false
        }
    };

    // 3. Launch UI
    // We pass tpm_available to the UI
    if let Err(e) = ui::run(tpm_available) {
        eprintln!("Application Error: {}", e);
    }
}
