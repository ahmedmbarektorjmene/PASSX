use std::time::{Instant, Duration};

#[derive(Debug, PartialEq)]
pub enum LockState {
    Locked,
    Unlocked,
}

/// Tracks strict application session state.
pub struct SessionState {
    pub lock_state: LockState,
    pub last_activity: Instant,
    pub timeout: Duration,
}

impl SessionState {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            lock_state: LockState::Locked,
            last_activity: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn poke(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn should_lock(&self) -> bool {
        if self.lock_state == LockState::Locked {
            return false;
        }
        self.last_activity.elapsed() >= self.timeout
    }

    pub fn lock(&mut self) {
        self.lock_state = LockState::Locked;
    }

    pub fn unlock(&mut self) {
        self.lock_state = LockState::Unlocked;
        self.poke();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_session_state_lifecycle() {
        let mut state = SessionState::new(2);
        
        // Starts locked
        assert_eq!(state.lock_state, LockState::Locked);
        assert!(!state.should_lock()); // Already locked
        
        // Unlock
        state.unlock();
        assert_eq!(state.lock_state, LockState::Unlocked);
        assert!(!state.should_lock()); // Freshly unlocked, shouldn't lock yet
        
        // Poke
        state.poke();
        assert!(!state.should_lock());
        
        // Wait for timeout (2 seconds)
        thread::sleep(Duration::from_millis(2100));
        assert!(state.should_lock(), "Should lock after timeout");
        
        // Lock
        state.lock();
        assert_eq!(state.lock_state, LockState::Locked);
    }
}
