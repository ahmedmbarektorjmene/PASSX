pub mod cipher;
pub mod kdf;
pub mod random;
pub mod recovery;

/// Constant-time equality check for secrets.
/// Uses the `subtle` crate to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
