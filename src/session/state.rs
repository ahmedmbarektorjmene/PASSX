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
