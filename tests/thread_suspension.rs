use passx::session::watchdog::Watchdog;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{OpenThread, SuspendThread, THREAD_SUSPEND_RESUME};

#[test]
fn test_watchdog_detects_suspension() {
    // This is the "Attacker" process.
    if std::env::var("TEST_MODE").unwrap_or_default() == "VICTIM" {
        victim_behavior();
        std::process::exit(0);
    }

    let current_exe = std::env::current_exe().expect("Failed to get current exe path");
    let mut child = Command::new(&current_exe)
        .env("TEST_MODE", "VICTIM")
        .arg("test_watchdog_detects_suspension")
        .arg("--exact")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn victim process");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    let mut target_tid = 0;
    // Wait for the victim to announce it has started its monitor thread
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.starts_with("MONITOR_THREAD_STARTED:") {
            let parts: Vec<&str> = line.trim().split(':').collect();
            if parts.len() == 2 {
                target_tid = parts[1].parse().unwrap_or(0);
            }
            break;
        }
    }

    let pid = child.id();
    println!(
        "[*] Victim PID: {}. Attempting to locate and suspend monitor thread (TID: {})...",
        pid, target_tid
    );

    // Give it a moment to stabilize
    thread::sleep(Duration::from_millis(500));

    unsafe {
        suspend_victim_threads(pid, target_tid);
    }

    // Now wait up to 5 seconds. The victim's watchdog should detect the suspended thread
    // and terminate the process with exit code 9.

    // We poll to see if the child exited
    let mut exit_status = None;
    for _ in 0..10 {
        if let Ok(Some(status)) = child.try_wait() {
            exit_status = Some(status);
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }

    // Cleanup in case it didn't
    let _ = child.kill();

    let status = exit_status.expect("Victim process did not terminate! Watchdog failed.");
    assert_eq!(
        status.code(),
        Some(9),
        "Victim terminated, but with wrong exit code. Expected 9 from watchdog."
    );
    println!(
        "[SUCCESS] Watchdog successfully detected thread suspension and terminated the process."
    );
}

fn victim_behavior() {
    let watchdog = Watchdog::new();
    let heartbeat = watchdog.get_heartbeat();

    // Start the watcher thread to monitor the background thread
    // Timeout of 2 seconds
    watchdog.start_watcher(2, || {
        println!("[SECURITY] FATAL: Security monitor thread was suspended. Terminating process!");
        std::process::exit(9);
    });

    // Start the simulated "security monitor" thread
    thread::spawn(move || {
        let tid = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
        println!("MONITOR_THREAD_STARTED:{}", tid);
        loop {
            // Beat
            Watchdog::beat(&heartbeat);
            thread::sleep(Duration::from_millis(500));
        }
    });

    // Main thread just hangs around
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

unsafe fn suspend_victim_threads(pid: u32, target_tid: u32) {
    let h_snapshot =
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).expect("Failed to create thread snapshot");

    let mut te32: THREADENTRY32 = std::mem::zeroed();
    te32.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut suspended_count = 0;
    if Thread32First(h_snapshot, &mut te32).is_ok() {
        loop {
            if te32.th32OwnerProcessID == pid {
                // Only suspend the requested monitor thread
                if te32.th32ThreadID == target_tid {
                    if let Ok(h_thread) =
                        OpenThread(THREAD_SUSPEND_RESUME, false, te32.th32ThreadID)
                    {
                        println!(
                            "[*] Suspending targeted monitor thread: {}",
                            te32.th32ThreadID
                        );
                        SuspendThread(h_thread);
                        let _ = CloseHandle(h_thread);
                        suspended_count += 1;
                    }
                }
            }
            if Thread32Next(h_snapshot, &mut te32).is_err() {
                break;
            }
        }
    }
    let _ = CloseHandle(h_snapshot);
    println!(
        "[*] Suspended {} targeted thread(s) in the victim process.",
        suspended_count
    );
}
