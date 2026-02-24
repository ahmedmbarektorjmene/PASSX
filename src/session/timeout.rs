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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_monitor_activity() {
        // Create state with 1 second timeout
        let state = Arc::new(Mutex::new(SessionState::new(1)));
        
        // Unlock it initially
        {
            let mut s = state.lock().unwrap();
            s.unlock();
        }
        
        let callback_fired = Arc::new(AtomicBool::new(false));
        let cf_clone = callback_fired.clone();
        
        monitor_activity(state.clone(), move || {
            cf_clone.store(true, Ordering::SeqCst);
        });
        
        // Wait 2 seconds (1s for timeout + 1s for the monitor loop sleep)
        thread::sleep(Duration::from_millis(2500));
        
        assert!(callback_fired.load(Ordering::SeqCst), "Lock callback was not fired by monitor_activity");
        
        // State should be locked
        {
            let s = state.lock().unwrap();
            assert_eq!(s.lock_state, crate::session::state::LockState::Locked);
        }
    }
}
