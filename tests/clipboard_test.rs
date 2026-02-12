use arboard::Clipboard;
use std::thread;
use std::time::Duration;

#[test]
fn test_clipboard_thread_safety() {
    // This test simulates the logic we are using in the app:
    // 1. Spawning a thread (simulating background auth)
    // 2. Setting clipboard from that thread? NO, our current logic uses invoke_from_event_loop.
    // However, in a unit test we don't have the slint event loop running.
    // So we can only test if `Clipboard::new().set_text()` works from a fresh thread vs main thread.

    let text_to_copy = "SecretPassword123!";
    
    // Test 1: Main Thread Copy
    let mut cb = Clipboard::new().expect("Failed to init clipboard on main thread");
    cb.set_text(text_to_copy).expect("Failed to set text on main");
    assert_eq!(cb.get_text().expect("Failed to get"), text_to_copy);

    // Test 2: Background Thread Copy (simulating what might have been broken)
    let text_2 = "BackgroundPass";
    let handle = thread::spawn(move || {
         let mut cb = Clipboard::new().expect("Failed to init clipboard on bg thread");
         cb.set_text(text_2).expect("Failed to set text on bg");
         // We need to keep the clipboard handle alive or does arboard persist?
         // On Windows, clipboard data is owned by the window/process.
         thread::sleep(Duration::from_millis(100));
    });
    handle.join().unwrap();
    
    // Check from main thread
    let mut cb = Clipboard::new().unwrap();
    assert_eq!(cb.get_text().unwrap(), text_2);
}
