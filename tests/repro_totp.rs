use totp_rs::{TOTP, Algorithm};

#[test]
fn test_totp_size() {
    let secret_str = "JBSWY3DPEHPK3PXP"; // 16 chars base32 -> 10 bytes
    let decoded = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret_str).unwrap();
    println!("Original secret len: {}", decoded.len()); 

    // Test 1: Original short secret
    let result = TOTP::new(Algorithm::SHA1, 6, 1, 30, decoded.clone(), None, "test".to_string());
    match result {
        Ok(_) => println!("Original: TOTP created successfully"),
        Err(e) => println!("Original: TOTP creation failed: {:?}", e),
    }

    // Test 2: Padded secret
    let mut padded = decoded.clone();
    // Pad to 20 bytes (160 bits) which is standard for SHA1
    while padded.len() < 20 {
        padded.push(0);
    }
    println!("Padded secret len: {}", padded.len());
    
    let result_padded = TOTP::new(Algorithm::SHA1, 6, 1, 30, padded.clone(), None, "test".to_string());
    match result_padded {
        Ok(totp) => {
            println!("Padded: TOTP created successfully");
            let code = totp.generate_current().unwrap();
            println!("Padded Code: {}", code);
            
            // If the original worked, we would compare usage.
            // Since we can't make the original work, we can't strictly compare output here 
            // without a reference tailored for short keys. 
            // But if HMAC logic holds, this is valid.
        },
        Err(e) => println!("Padded: TOTP creation failed: {:?}", e),
    }
}
