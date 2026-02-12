use rand::RngCore;
use rand::rngs::OsRng;
use crate::memory::guard::SecureBuffer;

/// Cryptographically secure random number generator wrapper.
pub struct SecureRandom;

impl SecureRandom {
    /// Generate a secure buffer with random bytes.
    pub fn bytes(len: usize) -> Option<SecureBuffer> {
        let mut buf = SecureBuffer::new(len)?;
        OsRng.fill_bytes(&mut buf);
        Some(buf)
    }

    /// Fill an existing buffer with random bytes.
    pub fn fill(buf: &mut [u8]) {
        OsRng.fill_bytes(buf);
    }
}
