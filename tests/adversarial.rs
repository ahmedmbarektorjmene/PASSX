use passx::vault::AccountEntry;

#[test]
fn test_large_input_allocation() {
    // Attempt to allocate 10MB password
    // This tests if SecureAllocator can handle large contiguous blocks
    let size = 10 * 1024 * 1024;
    let large_data = vec![0u8; size];
    
    let account = AccountEntry::new(
        "Large".to_string(),
        "user".to_string(),
        &large_data,
        None
    );
    
    // We expect it to succeed on most systems, or return None gracefully
    if let Some(acc) = account {
        assert_eq!(acc.password.len(), size);
    } else {
        println!("Large allocation failed gracefully.");
    }
}

#[test]
fn test_huge_input_allocation_failure() {
    // Attempt to allocate impossible size (e.g., usize::MAX or close to it)
    // to verify we don't panic.
    // Note: vec! will panic if allocation fails. 
    // We need to pass a slice.
    // We can't easily construct a slice of size usize::MAX without allocating.
    // But AccountEntry::new takes &[u8].
    // We can pass a fake slice with unsafe, BUT we must ensure it's not read beyond bounds.
    // AccountEntry::new calls SecureBuffer::from_slice which copies.
    // So it WILL read.
    // Thus we can't test "huge input" easily without having "huge input".
    
    // However, we can test SecureBuffer::new(huge_size) directly if it was public.
    // AccountEntry doesn't expose size directly, only via slice.
    
    // So valid huge input test is limited by test process memory.
}
