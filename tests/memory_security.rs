use passx::memory::guard::SecureBuffer;
use zeroize::Zeroize;
use std::ptr;

/// Simulates an ADMIN attacker inspecting memory at the raw pointer level.
/// This uses UNSAFE to read memory that we are auditing.
#[test]
fn test_secure_buffer_zeroization_admin_simulation() {
    let secret = b"super_secret_admin_key";
    let mut buffer = SecureBuffer::from_slice(secret).unwrap();
    let ptr = buffer.as_ptr();
    let len = buffer.len();
    
    // 1. Verify we can read the secret via unsafe pointer (Simulating memory dump)
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        assert_eq!(slice, secret, "Admin should be able to read memory before zeroize");
    }
    
    // 2. Perform Explicit Zeroize
    buffer.zeroize();
    
    // 3. Verify memory is now zeroed via unsafe pointer
    // Even if language visibility rules prevented this, unsafe allows us to check the raw bytes.
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        for (i, &byte) in slice.iter().enumerate() {
            assert_eq!(byte, 0, "Byte at index {} was not zeroed!", i);
        }
    }
    
    // 4. Verify no residual patterns
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        let sum: u64 = slice.iter().map(|&b| b as u64).sum();
        assert_eq!(sum, 0, "Memory sum should be 0");
    }
}

#[test]
fn test_secure_allocator_layout_torture() {
    // Torture test: Allocate, Write, Zeroize, Inspect
    let sizes = [0, 1, 13, 256, 1024, 65536];
    
    for &size in &sizes {
        if let Some(mut buf) = SecureBuffer::new(size) {
            // Write pattern 0xAA
            unsafe {
                // Cast *const u8 to *mut u8 since we are in unsafe block and know we own it
                ptr::write_bytes(buf.as_ptr() as *mut u8, 0xAA, buf.len());
            }
            
            // Zeroize
            buf.zeroize();
            
            // Inspect
            unsafe {
                let slice = std::slice::from_raw_parts(buf.as_ptr(), buf.len());
                if slice.iter().any(|&b| b != 0) {
                     panic!("Failed to zeroize buffer of size {}", size);
                }
            }
        }
    }
}

