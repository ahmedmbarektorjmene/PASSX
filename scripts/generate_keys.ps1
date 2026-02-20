<#
.SYNOPSIS
    Generates both keys needed for PASSX:
    1. SIGNING_CERT  → Base64 PFX for GitHub Secret (MSI code signing)
    2. ED25519 Keypair → PUBLIC_KEY_BYTES for integrity.rs + private key for GitHub Secret

.USAGE
    .\scripts\generate_keys.ps1
#>

$outputDir = Join-Path $PSScriptRoot ".." "keys_output"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PASSX Key Generator" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ──────────────────────────────────────────────
# 1. CODE SIGNING CERTIFICATE (SIGNING_CERT)
# ──────────────────────────────────────────────
Write-Host "[1/2] Generating Code Signing Certificate..." -ForegroundColor Yellow

$certSubject = "CN=PassX Code Signing"

# Generate a strong 32-character random sequence manually using RNGCryptoServiceProvider
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object Byte[] 32
$rng.GetBytes($bytes)
$pfxPassword = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
$pfxPath     = Join-Path $outputDir "signing_cert.pfx"

# Create self-signed code signing cert (valid 5 years)
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $certSubject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(5) `
    -HashAlgorithm SHA256

# Export to PFX
$securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword | Out-Null

# Base64 encode for GitHub Secret
$base64Pfx = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath))
$signingCertFile = Join-Path $outputDir "SIGNING_CERT.txt"
$base64Pfx | Out-File -FilePath $signingCertFile -Encoding utf8 -NoNewline

$passwordFile = Join-Path $outputDir "CERT_PASSWORD.txt"
$pfxPassword | Out-File -FilePath $passwordFile -Encoding utf8 -NoNewline

Write-Host "  [OK] PFX exported to: $pfxPath" -ForegroundColor Green
Write-Host "  [OK] Base64 saved to: $signingCertFile" -ForegroundColor Green
Write-Host "  [OK] Password saved to: $passwordFile" -ForegroundColor Green
Write-Host ""

# ──────────────────────────────────────────────
# 2. ED25519 KEYPAIR (for integrity.rs)
# ──────────────────────────────────────────────
Write-Host "[2/2] Generating Ed25519 Keypair..." -ForegroundColor Yellow

# Use a small inline Rust program to generate the keypair
$rustScript = @"
//! Generates an Ed25519 keypair for PASSX integrity verification.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn main() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Private key (store as GitHub secret: ED25519_SIGNING_KEY)
    println!("PRIVATE_KEY_HEX={}", hex::encode(signing_key.to_bytes()));
    println!("---");

    // Public key for integrity.rs
    let bytes = verifying_key.to_bytes();
    let hex_pairs: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();

    // Format as Rust array
    println!("PUBLIC_KEY_BYTES=[");
    println!("    {},", hex_pairs[0..16].join(", "));
    println!("    {}", hex_pairs[16..32].join(", "));
    println!("];");
}
"@

# Save the Rust keygen as a standalone Cargo project in a temp dir
$tempProject = Join-Path $env:TEMP "passx_keygen"
if (Test-Path $tempProject) { Remove-Item -Recurse -Force $tempProject }

# Create project structure
New-Item -ItemType Directory -Force -Path (Join-Path $tempProject "src") | Out-Null

# Write Cargo.toml
@"
[package]
name = "passx_keygen"
version = "0.1.0"
edition = "2021"

[dependencies]
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
hex = "0.4"
"@ | Out-File -FilePath (Join-Path $tempProject "Cargo.toml") -Encoding utf8

# Write main.rs
$rustScript | Out-File -FilePath (Join-Path $tempProject "src" "main.rs") -Encoding utf8

Write-Host "  Building keygen tool..." -ForegroundColor DarkGray
$output = & cargo run --quiet --manifest-path (Join-Path $tempProject "Cargo.toml") 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to run keygen: $output"
    exit 1
}

# Parse output
$privateKeyLine = ($output | Where-Object { $_ -match "^PRIVATE_KEY_HEX=" }) -replace "PRIVATE_KEY_HEX=", ""
$publicKeyLines = ($output | Where-Object { $_ -notmatch "^PRIVATE_KEY_HEX=" -and $_ -ne "---" }) -join "`n"

# Save private key
$privateKeyFile = Join-Path $outputDir "ED25519_SIGNING_KEY.txt"
$privateKeyLine | Out-File -FilePath $privateKeyFile -Encoding utf8 -NoNewline

# Save public key (Rust format)
$publicKeyFile = Join-Path $outputDir "PUBLIC_KEY_BYTES.txt"
$publicKeyLines | Out-File -FilePath $publicKeyFile -Encoding utf8

Write-Host "  [OK] Private key saved to: $privateKeyFile" -ForegroundColor Green
Write-Host "  [OK] Public key saved to:  $publicKeyFile" -ForegroundColor Green

# Cleanup temp project
Remove-Item -Recurse -Force $tempProject -ErrorAction SilentlyContinue

# ──────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ALL DONE! Next Steps:" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  GitHub Secrets to create:" -ForegroundColor White
Write-Host "    1. SIGNING_CERT        -> paste contents of: $signingCertFile" -ForegroundColor White
Write-Host "    2. CERT_PASSWORD       -> paste contents of: $passwordFile" -ForegroundColor White
Write-Host "    3. ED25519_SIGNING_KEY -> paste contents of: $privateKeyFile" -ForegroundColor White
Write-Host ""
Write-Host "  Code to update:" -ForegroundColor White
Write-Host "    4. Copy PUBLIC_KEY_BYTES from: $publicKeyFile" -ForegroundColor White
Write-Host "       into src\runtime\integrity.rs (replace the placeholder array)" -ForegroundColor White
Write-Host ""
Write-Host "  IMPORTANT: Delete the keys_output folder after you're done!" -ForegroundColor Red
Write-Host "    Remove-Item -Recurse -Force '$outputDir'" -ForegroundColor Red
Write-Host ""
