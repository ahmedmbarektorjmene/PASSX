param (
    [string]$TargetExe = "target\release\passx.exe"
)

if (-not $env:ED25519_SIGNING_KEY) {
    Write-Error "ED25519_SIGNING_KEY environment variable is not set"
    exit 1
}

Write-Host "Signing $TargetExe with Ed25519..." -ForegroundColor Yellow

if (-not (Test-Path $TargetExe)) {
    Write-Error "Target executable not found: $TargetExe"
    exit 1
}

$rustScript = @"
use ed25519_dalek::{SigningKey, Signer};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: sign_exe <file_path> <private_key_hex>");
        std::process::exit(1);
    }
    let file_path = &args[1];
    let priv_hex = &args[2];
    let priv_bytes = hex::decode(priv_hex).expect("Invalid hex in private key");
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&priv_bytes);
    
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let data = std::fs::read(file_path).expect("Failed to read file");
    let signature = signing_key.sign(&data);
    
    let mut file = OpenOptions::new()
        .append(true)
        .open(file_path)
        .expect("Failed to open file for append");
    
    file.write_all(&signature.to_bytes()).unwrap();
    println!("Successfully appended Ed25519 signature to {}", file_path);
}
"@

$tempProject = Join-Path $env:TEMP "passx_signer"
if (Test-Path $tempProject) { Remove-Item -Recurse -Force $tempProject }
New-Item -ItemType Directory -Force -Path (Join-Path $tempProject "src") | Out-Null

@"
[package]
name = "passx_signer"
version = "0.1.0"
edition = "2021"

[dependencies]
ed25519-dalek = { version = "2" }
hex = "0.4"
"@ | Out-File -FilePath (Join-Path $tempProject "Cargo.toml") -Encoding utf8

$rustScript | Out-File -FilePath (Join-Path $tempProject "src" "main.rs") -Encoding utf8

Write-Host "  Building and running inline Rust signer..." -ForegroundColor DarkGray
$output = & cargo run --quiet --manifest-path (Join-Path $tempProject "Cargo.toml") -- $TargetExe $env:ED25519_SIGNING_KEY 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to sign executable: $output"
    exit 1
}

Write-Host "  [OK] $TargetExe has been signed with Ed25519." -ForegroundColor Green
Remove-Item -Recurse -Force $tempProject -ErrorAction SilentlyContinue
