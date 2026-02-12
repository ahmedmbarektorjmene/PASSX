use passx::memory::guard::SecureBuffer;

#[test]
fn test_secure_buffer_allocation() {
    let size = 1024;
    let buf = SecureBuffer::new(size);
    assert!(buf.is_some());
    let buf = buf.unwrap();
    assert_eq!(buf.len(), size);
    
    // Check initialized to zero
    for b in buf.iter() {
        assert_eq!(*b, 0);
    }
}

#[test]
fn test_secure_buffer_from_slice() {
    let data = b"Sensitive Data";
    let buf = SecureBuffer::from_slice(data);
    assert!(buf.is_some());
    let buf = buf.unwrap();
    assert_eq!(&buf[..], data);
}

#[test]
fn test_large_allocation() {
    let size = 1024 * 1024 * 10; // 10MB
    let buf = SecureBuffer::new(size);
    // Might fail depending on system limits (VirtualLock quota)
    // But check should be handled gracefully.
    if let Some(b) = buf {
        assert_eq!(b.len(), size);
    } else {
        println!("Large allocation failed (expected on some systems)");
    }
}
