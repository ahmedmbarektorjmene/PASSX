use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

/// A simple utility to sign the PASSX binary.
/// Usage: cargo run --example sign_app <path_to_binary>
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: sign_app <binary_path>");
        return Ok(());
    }

    let binary_path = &args[1];
    
    // In a real scenario, you'd load your private key from a secure location.
    // For this demonstration, we'll generate one and PRINT the public key 
    // so you can update integrity.rs.
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    println!("--- SIGNING KEY GENERATED ---");
    println!("Public Key (HEX): {}", hex::encode(public_key.as_bytes()));
    println!("Public Key (Rust Array): {:?}", public_key.as_bytes());
    println!("--- KEEP THE PRIVATE KEY SECRET ---");

    // 1. Read binary
    let mut file = File::open(binary_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    
    // 2. Sign
    let signature = signing_key.sign(&data);
    let sig_bytes = signature.to_bytes();

    // 3. Append to a new file (or overwrite)
    let out_path = format!("{}_signed.exe", binary_path.trim_end_matches(".exe"));
    let mut out_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)?;

    out_file.write_all(&data)?;
    out_file.write_all(&sig_bytes)?;

    println!("Successfully signed binary: {}", out_path);
    println!("Signature length: {} bytes", sig_bytes.len());

    Ok(())
}
