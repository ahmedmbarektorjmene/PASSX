use proptest::prelude::*;
use passx::crypto::cipher;

proptest! {
    #[test]
    fn test_encryption_roundtrip_prop(
        key in prop::collection::vec(any::<u8>(), 32), 
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        aad in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let key_arr: [u8; 32] = key.try_into().unwrap();
        let (ciphertext, nonce, tag) = cipher::encrypt(&key_arr, &plaintext, &aad).unwrap();
        let decrypted = cipher::decrypt(&key_arr, &nonce, &tag, &ciphertext, &aad).unwrap();
        prop_assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_encryption_nondeterministic(
        key in prop::collection::vec(any::<u8>(), 32), 
        plaintext in prop::collection::vec(any::<u8>(), 1..1024),
        aad in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let key_arr: [u8; 32] = key.try_into().unwrap();
        // Encrypt twice
        let (c1, n1, t1) = cipher::encrypt(&key_arr, &plaintext, &aad).unwrap();
        let (c2, n2, t2) = cipher::encrypt(&key_arr, &plaintext, &aad).unwrap();
        
        // Ciphertext should differ because nonce differs
        prop_assert_ne!(&c1[..], &c2[..]);
        prop_assert_ne!(n1, n2);
        // Tag differs if nonce differs
        prop_assert_ne!(t1, t2);
    }
}
