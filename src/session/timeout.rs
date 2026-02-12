use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use crate::session::state::SessionState;

/// Monitor session activity and trigger lock callback on timeout.
/// This function runs in a background thread.
pub fn monitor_activity<F>(state: Arc<Mutex<SessionState>>, lock_callback: F)
where
    F: FnOnce() + Send + 'static,
{
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            let mut s = state.lock().unwrap();
            
            if s.should_lock() {
                s.lock();
                drop(s); // Unlock mutex before callback
                lock_callback();
                break; // Exit monitoring thread? Or restart?
                // Usually restart monitoring after unlock.
                // But for simplicity, we exit and expect caller to restart on unlock.
            }
        }
    });
}
