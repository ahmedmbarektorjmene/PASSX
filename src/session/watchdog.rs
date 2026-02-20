use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;
use std::time::Duration;

pub struct Watchdog {
    heartbeat: Arc<AtomicU64>,
}

impl Watchdog {
    pub fn new() -> Self {
        Self {
            heartbeat: Arc::new(AtomicU64::new(current_timestamp())),
        }
    }

    /// Get a clone of the heartbeat atomic, to be passed to the monitored thread
    pub fn get_heartbeat(&self) -> Arc<AtomicU64> {
        self.heartbeat.clone()
    }

    /// Update the heartbeat (to be called by the monitored thread continuously)
    pub fn beat(heartbeat: &Arc<AtomicU64>) {
        heartbeat.store(current_timestamp(), Ordering::Release);
    }

    /// Start a watcher thread that checks the heartbeat
    /// If the heartbeat is older than `timeout_secs`, it executes the panic callback.
    pub fn start_watcher(&self, timeout_secs: u64, panic_action: impl Fn() + Send + 'static) {
        let heartbeat_clone = self.heartbeat.clone();
        
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(1));
                
                let last_beat = heartbeat_clone.load(Ordering::Acquire);
                let now = current_timestamp();
                
                if now.saturating_sub(last_beat) > timeout_secs {
                    println!("[SECURITY] WATCHDOG TRIGGERED! Monitor thread suspended/frozen for >{}s. Terminating app to protect memory.", timeout_secs);
                    panic_action();
                    // Fallback exit if action doesn't terminate
                    std::process::exit(7);
                }
            }
        });
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}
