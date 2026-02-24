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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_bytes() {
        let buf1 = SecureRandom::bytes(32).unwrap();
        let buf2 = SecureRandom::bytes(32).unwrap();
        
        assert_eq!(buf1.len(), 32);
        assert_ne!(buf1.as_slice(), buf2.as_slice(), "Consecutive random generations should differ");
    }
}
